use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};

use crate::client_info::{client_exists, load_from_clients_json};
use crate::client_info::{save_client_info, ClientInfo};
use crate::packet::parse_ipv6_packet;
use crate::path_manager::PathManager;
use crate::tun;

const MTU: usize = 1500;

pub fn run_client(
    ip: IpAddr,
    port: u16,
    public_key: kyber1024::PublicKey,
    ipv6_addr: Ipv6Addr,
) -> io::Result<()> {
    let pm = PathManager::new()?;
    register_to_server(ip, port, &public_key, &ipv6_addr)?;

    let (mut tun_device, tun_device_name) = tun::create_tun(ipv6_addr)?;
    println!("✅ Created TUN device {}", tun_device_name);

    let mut buf = [0u8; MTU];
    loop {
        let n = tun_device.read(&mut buf)?;
        if let Some(ipv6_packet) = parse_ipv6_packet(&buf[..n]) {
            handle_packet(&ipv6_packet.dst, ip, port, &pm)?;
        }
    }
}

fn register_to_server(
    ip: IpAddr,
    port: u16,
    public_key: &kyber1024::PublicKey,
    ipv6_addr: &Ipv6Addr,
) -> io::Result<()> {
    let mut stream = TcpStream::connect(SocketAddr::new(ip, port))?;

    let payload = public_key.as_bytes();
    let ipv6_bytes = ipv6_addr.octets();
    let total_len = payload.len() + ipv6_bytes.len();

    let request = format!(
        "POST /register HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        total_len
    );

    stream.write_all(request.as_bytes())?;
    stream.write_all(payload)?;
    stream.write_all(&ipv6_bytes)?;
    Ok(())
}

fn handle_packet(dst: &Ipv6Addr, ip: IpAddr, port: u16, pm: &PathManager) -> io::Result<()> {
    let db_path = pm.client_db_path();

    if !client_exists(dst, &db_path)? {
        fetch_and_save_peer_key(dst, ip, port, &db_path)?;
    } else {
        perform_key_exchange(dst, &db_path)?;
    }
    Ok(())
}

fn fetch_and_save_peer_key(
    dst: &Ipv6Addr,
    ip: IpAddr,
    port: u16,
    db_path: &std::path::Path,
) -> io::Result<()> {
    match query_server_for_key(*dst, ip, port)? {
        Some(peer_key) => {
            println!("🔑 Retrieved key (first 8 bytes): {:02X?}", &peer_key[..8]);

            let info = ClientInfo {
                ipv6: dst.to_string(),
                public_key_hex: peer_key.iter().map(|b| format!("{:02X}", b)).collect(),
            };

            save_client_info(info, db_path)
                .map(|_| println!("💾 Saved successfully: {}", db_path.display()))
                .map_err(|e| {
                    eprintln!("⚠️ Failed to save key: {}", e);
                    e
                })
        }
        None => {
            println!("❌ No entry found: {}", dst);
            Ok(())
        }
    }
}

fn perform_key_exchange(dst: &Ipv6Addr, db_path: &std::path::Path) -> io::Result<()> {
    if let Some(peer_public_key) = load_from_clients_json(dst, db_path)? {
        println!(
            "🔑 Full public key: {}",
            hex::encode(peer_public_key.as_bytes())
        );

        let (ciphertext, shared_secret) = kyber1024::encapsulate(&peer_public_key);

        println!("📦 Ciphertext: {}", hex::encode(ciphertext.as_bytes()));
        println!(
            "🔐 Shared secret: {}",
            hex::encode(shared_secret.as_bytes())
        );

        // TODO: implement sending ciphertext
    } else {
        println!("⚠️ Public key not found: {}", dst);
    }
    Ok(())
}

fn query_server_for_key(ipv6_addr: Ipv6Addr, ip: IpAddr, port: u16) -> io::Result<Option<Vec<u8>>> {
    let mut stream = TcpStream::connect(SocketAddr::new(ip, port))?;
    let query_request = format!(
        "GET /query?ipv6={} HTTP/1.1\r\nHost: {}\r\n\r\n",
        ipv6_addr, ip
    );
    stream.write_all(query_request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let response_str = String::from_utf8_lossy(&response);
    if response_str.starts_with("HTTP/1.1 200") {
        if let Some(index) = response_str.find("\r\n\r\n") {
            let body = &response[(index + 4)..];
            Ok(Some(body.to_vec()))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Body not found"))
        }
    } else if response_str.contains("404") {
        Ok(None)
    } else if response_str.contains("500") {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Server internal error",
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unknown response",
        ))
    }
}
