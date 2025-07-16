use std::net::UdpSocket;
use std::io;
use std::net::Ipv6Addr;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::PublicKey;
use serde::{Serialize, Deserialize};
use std::fs::{OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    ipv6: String,       // IPv6 アドレス文字列
    public_key_hex: String, // 公開鍵を16進文字列で保存
}

fn save_client_info(info: ClientInfo, db_path: &Path) -> io::Result<()> {
    let mut db: Vec<ClientInfo> = if db_path.exists() {
        let reader = BufReader::new(OpenOptions::new().read(true).open(db_path)?);
        serde_json::from_reader(reader).unwrap_or_default()
    } else {
        Vec::new()
    };

    // 同じ IPv6 アドレスがあれば上書き
    db.retain(|entry| entry.ipv6 != info.ipv6);
    db.push(info);

    let writer = BufWriter::new(OpenOptions::new().write(true).create(true).truncate(true).open(db_path)?);
    serde_json::to_writer_pretty(writer, &db)?;

    Ok(())
}

const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
const IPV6_ADDR_SIZE: usize = 16;
const EXPECTED_SIZE: usize = KYBER_PUBLIC_KEY_SIZE + IPV6_ADDR_SIZE;

pub fn run_server(port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    println!("Listening for UDP packets on port {}", port);

    let mut buf = [0u8; 1600];
    let db_path = PathBuf::from("/opt/nuntium/clients.json");

    loop {
        let (size, addr) = socket.recv_from(&mut buf)?;
        println!("Received {} bytes from {}", size, addr);

        if size == EXPECTED_SIZE {
            let public_key_bytes = &buf[..KYBER_PUBLIC_KEY_SIZE];
            let ipv6_bytes = &buf[KYBER_PUBLIC_KEY_SIZE..EXPECTED_SIZE];

            let public_key = kyber1024::PublicKey::from_bytes(public_key_bytes);
            let ipv6_addr = Ipv6Addr::from(<[u8; 16]>::try_from(ipv6_bytes).unwrap());

            match public_key {
                Ok(pk) => {
                    println!("✅ 公開鍵を受信しました (先頭8バイト): {:02X?}", &pk.as_bytes()[..8]);
                    println!("✅ IPv6 アドレス: {}", ipv6_addr);

                    let client_info = ClientInfo {
                        ipv6: ipv6_addr.to_string(),
                        public_key_hex: public_key_bytes.iter().map(|b| format!("{:02X}", b)).collect(),
                    };
                    save_client_info(client_info, &db_path)?;
                }
                Err(e) => {
                    eprintln!("❌ 公開鍵の復元に失敗しました: {}", e);
                }
            }
        } else {
            eprintln!("❗ 期待しないサイズのデータを受信: {} バイト", size);
        }
    }
}
