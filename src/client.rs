use hex;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream};

use crate::client_info::{client_exists, load_from_clients_json};
use crate::client_info::{save_client_info, ClientInfo};
use crate::packet::parse_ipv6_packet;
use crate::path_manager::PathManager;
use crate::request::Request;
use crate::tun;
use nuntium::crypto::Aes256GcmHelper;

const MTU: usize = 1500;

pub fn run_client(
    ip: IpAddr,
    port: u16,
    public_key: kyber1024::PublicKey,
    secret_key: kyber1024::SecretKey,
    ipv6_addr: Ipv6Addr,
) -> io::Result<()> {
    let pm = PathManager::new()?;
    Request::Register {
        public_key: public_key.clone(),
        ipv6_addr,
    }
    .send(ip, port)?;

    let (mut tun_device, tun_device_name) = tun::create_tun(ipv6_addr)?;
    println!("✅ Created TUN device {}", tun_device_name);

    let mut buf = [0u8; MTU];

    let mut recv_stream = TcpStream::connect((ip, port))?;
    recv_stream.write_all(b"POST /listen HTTP/1.1\r\n\r\n")?;
    recv_stream.write_all(&ipv6_addr.octets())?;
    recv_stream.set_nonblocking(true)?;

    let mut aes: Option<Aes256GcmHelper> = None;

    loop {
        // 送信側
        if let Ok(n) = tun_device.read(&mut buf) {
            if let Some(ipv6_packet) = parse_ipv6_packet(&buf[..n]) {
                handle_packet(
                    &ipv6_packet.dst,
                    ipv6_addr,
                    ip,
                    port,
                    &pm,
                    &buf[..n],
                    &mut aes,
                )?;
            }
        }

        // 受信側
        let mut recv_buf = [0u8; MTU];
        match recv_stream.read(&mut recv_buf) {
            Ok(n) if n > 0 => {
                if n == 1568 + 16 {
                    let dst_bytes = &recv_buf[..16];
                    let ct_bytes = &recv_buf[16..];
                    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(dst_bytes).unwrap());
                    let ciphertext = kyber1024::Ciphertext::from_bytes(ct_bytes).unwrap();

                    let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);
                    println!(
                        "🔐 Shared secret derived for dst {} (first 8 bytes): {:02X?}",
                        dst,
                        &shared_secret.as_bytes()[..8]
                    );

                    let key_bytes: [u8; 32] = Sha256::digest(shared_secret.as_bytes()).into();
                    aes = Some(Aes256GcmHelper::new(&key_bytes));
                } else if let Some(a) = aes.as_mut() {
                    if n > 12 {
                        let nonce: [u8; 12] = recv_buf[..12].try_into().unwrap();
                        if let Some(plain) = a.decrypt(&nonce, &recv_buf[12..n]) {
                            tun_device.write_all(&plain)?;
                        } else {
                            eprintln!("❌ Failed to decrypt packet");
                        }
                    }
                } else {
                    eprintln!(
                        "⚠️ Received {} bytes before AES key established; dropping",
                        n
                    );
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
            _ => {}
        }
    }
}

fn handle_packet(
    dst: &Ipv6Addr,
    local_ipv6: Ipv6Addr,
    ip: IpAddr,
    port: u16,
    pm: &PathManager,
    packet: &[u8],
    aes: &mut Option<Aes256GcmHelper>,
) -> io::Result<()> {
    let db_path = pm.client_db_path();

    if *dst == local_ipv6 {
        return Ok(());
    }

    if dst == &"ff02::2".parse::<Ipv6Addr>().unwrap() {
        return Ok(());
    }

    if let Some(a) = aes.as_mut() {
        let (ciphertext, nonce) = a.encrypt(packet);
        Request::EncryptedPacket {
            dst_ipv6: *dst,
            nonce,
            payload: ciphertext,
        }
        .send(ip, port)?;
    } else if !client_exists(dst, &db_path)? {
        fetch_and_save_peer_key(dst, ip, port, &db_path)?;
    } else {
        perform_key_exchange(dst, &db_path, ip, port)?;
    }
    Ok(())
}

fn fetch_and_save_peer_key(
    dst: &Ipv6Addr,
    ip: IpAddr,
    port: u16,
    db_path: &std::path::Path,
) -> io::Result<()> {
    match (Request::Query { ipv6_addr: *dst }).send(ip, port)? {
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

fn perform_key_exchange(
    dst: &Ipv6Addr,
    db_path: &std::path::Path,
    ip: IpAddr,
    port: u16,
) -> io::Result<()> {
    if let Some(peer_public_key) = load_from_clients_json(dst, db_path)? {
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&peer_public_key);

        Request::KeyExchange {
            dst_ipv6: *dst,
            ciphertext,
        }
        .send(ip, port)?;
    } else {
        println!("⚠️ Public key not found: {}", dst);
    }
    Ok(())
}
