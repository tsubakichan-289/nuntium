use std::net::{TcpListener, TcpStream, Ipv6Addr};
use std::io::{self, Read, Write, BufReader, BufWriter, BufRead};
use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use hex;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    ipv6: String,
    public_key_hex: String,
}

fn save_client_info(info: ClientInfo, db_path: &Path) -> io::Result<()> {
    let mut db: Vec<ClientInfo> = if db_path.exists() {
        let reader = BufReader::new(OpenOptions::new().read(true).open(db_path)?);
        serde_json::from_reader(reader).unwrap_or_default()
    } else {
        Vec::new()
    };

    db.retain(|entry| entry.ipv6 != info.ipv6);
    db.push(info);

    let writer = BufWriter::new(OpenOptions::new().write(true).create(true).truncate(true).open(db_path)?);
    serde_json::to_writer_pretty(writer, &db)?;
    Ok(())
}

fn handle_client(stream: TcpStream, db_path: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    if request_line.starts_with("GET /query?ipv6=") {
        let stream = reader.into_inner();
        handle_query(request_line.trim(), stream, db_path)
    } else if request_line.starts_with("POST /register") {
        handle_register(&mut reader, db_path)
    } else {
        let mut stream = reader.into_inner();
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
        Ok(())
    }
}

fn handle_query(line: &str, mut stream: TcpStream, db_path: &Path) -> io::Result<()> {
    let start = "GET /query?ipv6=".len();
    let end = line[start..].find(' ').unwrap_or(line.len() - start);
    let ipv6_str = &line[start..start + end];

    println!("🔍 クエリ受信: {}", ipv6_str);

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
                println!("✅ 公開鍵送信: {:02X?}", &bytes[..8]);
            }
            Err(_) => {
                stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")?;
                eprintln!("❌ 公開鍵デコードエラー");
            }
        }
    } else {
        stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")?;
        println!("❌ 該当なし: {}", ipv6_str);
    }

    Ok(())
}

fn handle_register(reader: &mut BufReader<TcpStream>, db_path: &Path) -> io::Result<()> {
    const EXPECTED_SIZE: usize = 1568 + 16;
    let mut buf = vec![0u8; EXPECTED_SIZE];
    reader.read_exact(&mut buf)?;

    let public_key_bytes = &buf[..1568];
    let ipv6_bytes = &buf[1568..];
    let ipv6_addr = Ipv6Addr::from(<[u8; 16]>::try_from(ipv6_bytes).unwrap());

    println!("✅ 公開鍵を受信しました (先頭8バイト): {:02X?}", &public_key_bytes[..8]);
    println!("✅ IPv6 アドレス: {}", ipv6_addr);

    let client_info = ClientInfo {
        ipv6: ipv6_addr.to_string(),
        public_key_hex: public_key_bytes.iter().map(|b| format!("{:02X}", b)).collect(),
    };
    save_client_info(client_info, db_path)?;

    let mut stream = reader.get_mut();
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
    Ok(())
}

pub fn run_server(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("Listening for TCP connections on port {}", port);

    let db_path = PathBuf::from("/opt/nuntium/clients.json");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, &db_path) {
                    eprintln!("❌ クライアント処理中にエラー: {}", e);
                }
            }
            Err(e) => {
                eprintln!("❌ 接続の受け入れに失敗: {}", e);
            }
        }
    }

    Ok(())
}
