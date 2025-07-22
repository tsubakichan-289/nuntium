use hex;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::client_info::{save_client_info, ClientInfo};
use crate::path_manager::PathManager;
use nuntium::protocol::{MSG_TYPE_ENCRYPTED_PACKET, MSG_TYPE_KEY_EXCHANGE};

type ClientMap = Arc<Mutex<HashMap<Ipv6Addr, TcpStream>>>;

pub fn run_server(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("Listening for TCP connections on port {}", port);

    let pm = PathManager::new()?;
    let db_path = pm.client_db_path();
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let db_path = db_path.clone();
                let clients = Arc::clone(&clients);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, &db_path, &clients) {
                        eprintln!("❌ Error while handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("❌ Failed to accept connection: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(stream: TcpStream, db_path: &Path, clients: &ClientMap) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    if request_line.starts_with("GET /query?ipv6=") {
        let stream = reader.into_inner();
        handle_query(request_line.trim(), stream, db_path)?
    } else if request_line.starts_with("POST /register") {
        handle_register(&mut reader, db_path, clients)?
    } else if request_line.starts_with("POST /keyexchange") {
        handle_keyexchange(&mut reader, clients)?
    } else if request_line.starts_with("POST /listen") {
        handle_listen(&mut reader, clients)?
    } else if request_line.starts_with("POST /data") {
        handle_data(&mut reader, clients)?
    } else {
        let mut stream = reader.into_inner();
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
    }

    Ok(())
}

fn handle_query(line: &str, mut stream: TcpStream, db_path: &Path) -> io::Result<()> {
    let start = "GET /query?ipv6=".len();
    let end = line[start..].find(' ').unwrap_or(line.len() - start);
    let ipv6_str = &line[start..start + end];

    println!("🔍 Received query: {}", ipv6_str);

    if !db_path.exists() {
        stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")?;
        return Ok(());
    }

    let file = OpenOptions::new().read(true).open(db_path)?;
    let reader = BufReader::new(file);
    let entries: Vec<ClientInfo> = serde_json::from_reader(reader).unwrap_or_default();

    if let Some(entry) = entries.iter().find(|e| e.ipv6 == ipv6_str) {
        match hex::decode(&entry.public_key_hex) {
            Ok(bytes) => {
                let mut response = Vec::new();
                response.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
                response.extend_from_slice(&bytes);
                stream.write_all(&response)?;
                println!("✅ Sent public key: {:02X?}", &bytes[..8]);
            }
            Err(_) => {
                stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")?;
                eprintln!("❌ Public key decode error");
            }
        }
    } else {
        stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")?;
        println!("❌ No entry found: {}", ipv6_str);
    }

    Ok(())
}

fn handle_register(
    reader: &mut BufReader<TcpStream>,
    db_path: &Path,
    _clients: &ClientMap, // ← 使用しなくなるが型は維持
) -> io::Result<()> {
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }
    println!("📄 HTTP headers:\n{}", headers);

    const EXPECTED_BODY_SIZE: usize = 1568 + 16;
    let mut buf = vec![0u8; EXPECTED_BODY_SIZE];
    reader.read_exact(&mut buf)?;

    let public_key_bytes = &buf[..1568];
    let ipv6_bytes = &buf[1568..];
    let ipv6_addr = Ipv6Addr::from(<[u8; 16]>::try_from(ipv6_bytes).unwrap());

    println!(
        "✅ Received public key (first 8 bytes): {:02X?}",
        &public_key_bytes[..8]
    );
    println!("✅ IPv6 address: {}", ipv6_addr);

    let client_info = ClientInfo {
        ipv6: ipv6_addr.to_string(),
        public_key_hex: public_key_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect(),
    };
    save_client_info(client_info, db_path)?;

    let stream = reader.get_mut();
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
    Ok(())
}

fn handle_keyexchange(reader: &mut BufReader<TcpStream>, clients: &ClientMap) -> io::Result<()> {
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }

    const BODY_SIZE: usize = 16 + 1568;
    let mut buf = vec![0u8; BODY_SIZE];
    reader.read_exact(&mut buf)?;

    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
    let ciphertext = &buf[16..];

    println!("📨 Forwarding to {}", dst_addr);

    let mut clients = clients.lock().unwrap();
    if let Some(target_stream) = clients.get_mut(&dst_addr) {
        println!("sending ciphertext to {}", dst_addr);
        target_stream.write_all(&[MSG_TYPE_KEY_EXCHANGE])?;
        target_stream.write_all(&buf)?;
        target_stream.flush()?;
        println!("✅ Forwarded to {}", dst_addr);
    } else {
        println!("❌ No connected client found for {}", dst_addr);
    }

    let stream = reader.get_mut();
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
    Ok(())
}

fn handle_data(reader: &mut BufReader<TcpStream>, clients: &ClientMap) -> io::Result<()> {
    let mut headers = String::new();
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length: ") {
            content_length = rest.trim().parse::<usize>().ok();
        }
        headers.push_str(&line);
    }

    let len = content_length
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing Content-Length"))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    if len < 44 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid body length",
        ));
    }

    let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[16..32]).unwrap());
    let nonce = &buf[32..44];
    let payload = &buf[44..];

    println!("📨 Forwarding from {} to {}", src_addr, dst_addr);

    let mut clients = clients.lock().unwrap();
    if let Some(target_stream) = clients.get_mut(&dst_addr) {
        // message layout: [type] + [src_ipv6] + [nonce] + [payload]
        let mut message = Vec::with_capacity(1 + 16 + 12 + payload.len());
        message.push(MSG_TYPE_ENCRYPTED_PACKET);
        message.extend_from_slice(&src_addr.octets());
        message.extend_from_slice(nonce);
        message.extend_from_slice(payload);
        target_stream.write_all(&message)?;
        println!("✅ Forwarded encrypted packet to {}", dst_addr);
    } else {
        println!("❌ No connected client found for {}", dst_addr);
    }

    let stream = reader.get_mut();
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
    Ok(())
}

fn handle_listen(reader: &mut BufReader<TcpStream>, clients: &ClientMap) -> io::Result<()> {
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }

    let mut ipv6_bytes = [0u8; 16];
    reader.read_exact(&mut ipv6_bytes)?;
    let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
    println!("👂 Listen request from {}", ipv6_addr);

    clients
        .lock()
        .unwrap()
        .insert(ipv6_addr, reader.get_ref().try_clone()?);

    let stream = reader.get_mut();
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
    Ok(())
}
