use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::client_info::{client_exists, load_from_clients_json};
use crate::client_info::{save_client_info, ClientInfo};
use crate::packet::parse_ipv6_packet;
use crate::path_manager::PathManager;
use crate::protocol::MSG_TYPE_LISTEN;
use crate::request::Request;
use crate::tun;

use nuntium::crypto::Aes256GcmHelper;
use nuntium::protocol::{MSG_TYPE_ENCRYPTED_PACKET, MSG_TYPE_KEY_EXCHANGE};

const MTU: usize = 1500;
const KEY_EXCHANGE_TOTAL_SIZE: usize = 1 + 16 + 1568;

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

    let (tun_device, tun_device_name) = tun::create_tun(ipv6_addr)?;
    println!("✅ Created TUN device {}", tun_device_name);

    let tun_arc = Arc::new(Mutex::new(tun_device));
    let recv_tun = tun_arc.clone();
    let secret_key_clone = secret_key.clone();
    let ipv6_addr_clone = ipv6_addr;
    let ip_clone = ip;
    let port_clone = port;

    thread::spawn(move || {
        let mut recv_stream = TcpStream::connect((ip_clone, port_clone)).unwrap();
        let mut listen_msg = Vec::with_capacity(1 + 16);
        listen_msg.push(MSG_TYPE_LISTEN);
        listen_msg.extend_from_slice(&ipv6_addr_clone.octets());
        recv_stream.write_all(&listen_msg).unwrap();
        recv_stream.set_nonblocking(true).unwrap();

        let mut recv_buf = [0u8; 2048];
        let mut aes_map: HashMap<Ipv6Addr, Aes256GcmHelper> = HashMap::new();

        loop {
            match recv_stream.read(&mut recv_buf) {
                Ok(n) if n > 0 => {
                    println!("📦 Received {} bytes, first byte = {:#x}", n, recv_buf[0]);

                    match recv_buf[0] {
                        MSG_TYPE_KEY_EXCHANGE => {
                            println!("🔑 Key exchange message received");
                            let dst_bytes = &recv_buf[1..17];
                            let ct_bytes = &recv_buf[17..n];
                            let src = Ipv6Addr::from(<[u8; 16]>::try_from(dst_bytes).unwrap());
                            let ciphertext = kyber1024::Ciphertext::from_bytes(ct_bytes).unwrap();
                            let shared_secret =
                                kyber1024::decapsulate(&ciphertext, &secret_key_clone);
                            let key_bytes: [u8; 32] =
                                Sha256::digest(shared_secret.as_bytes()).into();
                            let aes = Aes256GcmHelper::new(&key_bytes);
                            aes_map.insert(src, aes);
                            println!("🔐 Shared secret established for {}", src);
                        }
                        MSG_TYPE_ENCRYPTED_PACKET => {
                            let src =
                                Ipv6Addr::from(<[u8; 16]>::try_from(&recv_buf[1..17]).unwrap());
                            let dst =
                                Ipv6Addr::from(<[u8; 16]>::try_from(&recv_buf[17..33]).unwrap());
                            let nonce: [u8; 12] = recv_buf[33..45].try_into().unwrap();
                            let payload = &recv_buf[45..];

                            println!("🔒 Received encrypted packet from {} to {}", src, dst);

                            if let Some(aes) = aes_map.get_mut(&src) {
                                if let Some(plain) = aes.decrypt(&nonce, payload) {
                                    let mut tun = recv_tun.lock().unwrap();
                                    tun.write_all(&plain).unwrap();
                                    println!("🔓 Decrypted and wrote to TUN from {}", src);
                                } else {
                                    eprintln!(
                                        "❌ Failed to decrypt packet from {}\nNonce: {}\nPayload: {}",
                                        src,
                                        hex::encode(nonce),
                                        hex::encode(payload)
                                    );
                                }
                            } else {
                                eprintln!("❗ No AES key found for src: {}", src);
                            }
                        }
                        _ => {
                            eprintln!("⚠️ Unknown message type {}", recv_buf[0]);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("❌ Receive thread error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    let mut buf = [0u8; MTU];
    let mut aes_map: HashMap<Ipv6Addr, Aes256GcmHelper> = HashMap::new();

    loop {
        let mut tun = tun_arc.lock().unwrap();
        if let Ok(n) = tun.read(&mut buf) {
            if let Some(ipv6_packet) = parse_ipv6_packet(&buf[..n]) {
                handle_packet(
                    &ipv6_packet.dst,
                    ipv6_addr,
                    ip,
                    port,
                    &pm,
                    &buf[..n],
                    &mut aes_map,
                )?;
            }
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
    aes_map: &mut HashMap<Ipv6Addr, Aes256GcmHelper>,
) -> io::Result<()> {
    let db_path = pm.client_db_path();

    if *dst == local_ipv6 || *dst == "ff02::2".parse::<Ipv6Addr>().unwrap() {
        return Ok(());
    }

    if let Some(aes) = aes_map.get_mut(dst) {
        let (ciphertext, nonce) = aes.encrypt(packet);
        Request::EncryptedPacket {
            src_ipv6: local_ipv6,
            dst_ipv6: *dst,
            nonce,
            payload: ciphertext,
        }
        .send(ip, port)?;
    } else if !client_exists(dst, &db_path)? {
        fetch_and_save_peer_key(dst, ip, port, &db_path)?;
    } else {
        perform_key_exchange(dst, &db_path, ip, port, aes_map)?;
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
            save_client_info(info, db_path)?;
            println!("💾 Saved successfully: {}", db_path.display());
        }
        None => println!("❌ No entry found: {}", dst),
    }
    Ok(())
}

fn perform_key_exchange(
    dst: &Ipv6Addr,
    db_path: &std::path::Path,
    ip: IpAddr,
    port: u16,
    aes_map: &mut HashMap<Ipv6Addr, Aes256GcmHelper>,
) -> io::Result<()> {
    if let Some(peer_public_key) = load_from_clients_json(dst, db_path)? {
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&peer_public_key);
        let key_bytes: [u8; 32] = Sha256::digest(shared_secret.as_bytes()).into();
        aes_map.insert(*dst, Aes256GcmHelper::new(&key_bytes));
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
