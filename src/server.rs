use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::client_info::{save_client_info, ClientInfo};
use crate::path_manager::PathManager;
use nuntium::protocol::{
    MSG_TYPE_ENCRYPTED_PACKET, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_LISTEN, MSG_TYPE_QUERY,
    MSG_TYPE_QUERY_RESPONSE, MSG_TYPE_REGISTER,
};

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

fn handle_client(mut stream: TcpStream, db_path: &Path, clients: &ClientMap) -> io::Result<()> {
    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type)?;
    match msg_type[0] {
        MSG_TYPE_REGISTER => handle_register(&mut stream, db_path, clients)?,
        MSG_TYPE_QUERY => handle_query(&mut stream, db_path)?,
        MSG_TYPE_KEY_EXCHANGE => handle_keyexchange(&mut stream, clients)?,
        MSG_TYPE_LISTEN => handle_listen(&mut stream, clients)?,
        MSG_TYPE_ENCRYPTED_PACKET => handle_data(&mut stream, clients)?,
        _ => {
            // Unknown type, just drop the connection
        }
    }

    Ok(())
}

fn handle_query(stream: &mut TcpStream, db_path: &Path) -> io::Result<()> {
    let mut ipv6_bytes = [0u8; 16];
    stream.read_exact(&mut ipv6_bytes)?;
    let ipv6_addr = Ipv6Addr::from(ipv6_bytes);

    println!("🔍 Received query: {}", ipv6_addr);

    if !db_path.exists() {
        stream.write_all(&[MSG_TYPE_QUERY_RESPONSE, 0])?;
        return Ok(());
    }

    let file = OpenOptions::new().read(true).open(db_path)?;
    let reader = std::io::BufReader::new(file);
    let entries: Vec<ClientInfo> = serde_json::from_reader(reader).unwrap_or_default();

    if let Some(entry) = entries.iter().find(|e| e.ipv6 == ipv6_addr.to_string()) {
        match hex::decode(&entry.public_key_hex) {
            Ok(bytes) => {
                let mut response = Vec::with_capacity(2 + bytes.len());
                response.push(MSG_TYPE_QUERY_RESPONSE);
                response.push(1);
                response.extend_from_slice(&bytes);
                stream.write_all(&response)?;
                println!("✅ Sent public key: {:02X?}", &bytes[..8]);
            }
            Err(_) => {
                stream.write_all(&[MSG_TYPE_QUERY_RESPONSE, 0])?;
                eprintln!("❌ Public key decode error");
            }
        }
    } else {
        stream.write_all(&[MSG_TYPE_QUERY_RESPONSE, 0])?;
        println!("❌ No entry found: {}", ipv6_addr);
    }

    Ok(())
}

fn handle_register(stream: &mut TcpStream, db_path: &Path, _clients: &ClientMap) -> io::Result<()> {
    let mut buf = vec![0u8; 1584 + 16];
    stream.read_exact(&mut buf)?;

    let public_key_bytes = &buf[..1584];
    let ipv6_bytes = &buf[1584..];
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

    Ok(())
}

fn handle_keyexchange(stream: &mut TcpStream, clients: &ClientMap) -> io::Result<()> {
    let mut buf = vec![0u8; 16 + 1568];
    stream.read_exact(&mut buf)?;

    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());

    println!("📨 Forwarding to {}", dst_addr);

    let mut clients = clients.lock().unwrap();
    if let Some(target_stream) = clients.get_mut(&dst_addr) {
        target_stream.write_all(&buf)?;
        target_stream.flush()?;
        println!("✅ Forwarded to {}", dst_addr);
    } else {
        println!("❌ No connected client found for {}", dst_addr);
    }

    Ok(())
}

fn handle_data(stream: &mut TcpStream, clients: &ClientMap) -> io::Result<()> {
    let mut header = [0u8; 16 + 16 + 12];
    stream.read_exact(&mut header)?;

    let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&header[..16]).unwrap());
    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&header[16..32]).unwrap());
    let nonce: [u8; 12] = header[32..44].try_into().unwrap();

    let mut payload = Vec::new();
    stream.read_to_end(&mut payload)?;

    println!("📨 Forwarding from {} to {}", src_addr, dst_addr);

    let mut clients = clients.lock().unwrap();
    if let Some(target_stream) = clients.get_mut(&dst_addr) {
        let mut message = Vec::with_capacity(1 + 16 + 16 + 12 + payload.len());
        message.push(MSG_TYPE_ENCRYPTED_PACKET);
        message.extend_from_slice(&src_addr.octets());
        message.extend_from_slice(&dst_addr.octets());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&payload);
        target_stream.write_all(&message)?;
        println!("✅ Forwarded encrypted packet to {}", dst_addr);
    } else {
        println!("❌ No connected client found for {}", dst_addr);
    }

    Ok(())
}

fn handle_listen(stream: &mut TcpStream, clients: &ClientMap) -> io::Result<()> {
    let mut ipv6_bytes = [0u8; 16];
    stream.read_exact(&mut ipv6_bytes)?;
    let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
    println!("👂 Listen request from {}", ipv6_addr);

    clients
        .lock()
        .unwrap()
        .insert(ipv6_addr, stream.try_clone()?);

    Ok(())
}
