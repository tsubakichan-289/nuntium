use crate::aes::{decrypt_packet, encrypt_packet};
use crate::command::Message;
use crate::config::load_config;
use crate::file_io::{find_client, save_client_info, ClientInfo};
use crate::ipv6::{get_kyber_key, ipv6_from_public_key};
use crate::message_io::{receive_message, send_message};
use crate::packet::parse_ipv6_packet;
use crate::tun::{create_tun, MTU};

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

use crossbeam::channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tun::platform::Device as TunDevice;

fn spawn_receive_loop(
    mut stream: TcpStream,
    tx: Sender<Message>,
    tun: Arc<Mutex<TunDevice>>,
    shared_keys: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    my_secret_key: kyber1024::SecretKey,
) {
    std::thread::spawn(move || loop {
        match receive_message(&mut stream) {
            Ok(msg) => match msg {
                Message::ReceiveEncryptedData {
                    source,
                    ciphertext,
                    encrypted_payload,
                } => {
                    println!("🔐 Received encrypted data: {}", source);

                    let ss = match ciphertext {
                        Some(ct_bytes) => {
                            println!(
                                "🧩 Ciphertext provided; decapsulating and caching shared key: {}",
                                source
                            );
                            let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
                                .expect("Invalid ciphertext");
                            let ss = kyber1024::decapsulate(&ct, &my_secret_key);
                            shared_keys.lock().unwrap().insert(source, ss);
                            ss
                        }
                        None => {
                            println!("🔒 No ciphertext; using cached shared key: {}", source);
                            match shared_keys.lock().unwrap().get(&source) {
                                Some(cached) => *cached,
                                None => {
                                    eprintln!("❌ Shared key not cached: {}", source);
                                    continue;
                                }
                            }
                        }
                    };

                    let packet = match decrypt_packet(ss.as_bytes(), &encrypted_payload) {
                        Ok(p) => {
                            println!("✅ Successfully decrypted packet: {}", source);
                            p
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to decrypt: {}", e);
                            continue;
                        }
                    };

                    println!("🔒 Acquiring TUN write lock");
                    let mut tun_guard = tun.lock().unwrap();
                    println!("🔓 Acquired TUN lock");
                    if let Err(e) = tun_guard.write_all(&packet) {
                        eprintln!("❌ Failed to write to TUN: {}", e);
                    } else {
                        println!("📦 Wrote to TUN: {} bytes", packet.len());
                    }
                }

                Message::KeyResponse { .. } | Message::RegisterResponse { .. } => {
                    if let Err(e) = tx.send(msg.clone()) {
                        eprintln!("❌ Failed to forward message: {}", e);
                    }
                }

                _ => {
                    println!("📥 Irrelevant message: {:?}", msg);
                }
            },
            Err(e) => {
                eprintln!("❌ Failed to receive message: {}", e);
                break;
            }
        }
    });
}

fn get_dst_public_key(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    address: Ipv6Addr,
) -> Result<Vec<u8>, String> {
    if let Some(client) =
        find_client(&address).map_err(|e| format!("Failed to retrieve client info: {}", e))?
    {
        return Ok(client.public_key);
    }

    send_message(
        stream,
        &Message::KeyRequest {
            target_address: address,
        },
    )
    .map_err(|e| format!("Failed to send key request: {}", e))?;
    println!("🔑 Sent public key request: {}", address);

    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Message::KeyResponse {
                target_address,
                result,
            }) if target_address == address => {
                let public_key = result.map_err(|e| format!("Key error: {:?}", e))?;
                save_client_info(&ClientInfo {
                    address,
                    public_key: public_key.clone(),
                })
                .map_err(|e| format!("Failed to save: {}", e))?;
                return Ok(public_key);
            }
            Ok(msg) => {
                println!("📥 Irrelevant message: {:?}", msg);
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("Timed out waiting for key response".to_string());
            }
            Err(e) => return Err(format!("Failed to receive from channel: {}", e)),
        }
    }
}

fn register_to_server(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    local_ipv6: Ipv6Addr,
    public_key: &[u8],
) -> Result<(), String> {
    send_message(
        stream,
        &Message::Register {
            address: local_ipv6,
            public_key: public_key.to_vec(),
        },
    )
    .map_err(|e| format!("Failed to send registration: {}", e))?;

    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Message::RegisterResponse { result }) => match result {
                Ok(()) => {
                    println!("✅ Registration successful");
                    return Ok(());
                }
                Err(e) => return Err(format!("Registration failed: {:?}", e)),
            },
            Ok(other) => {
                println!("📥 Other message: {:?}", other);
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("Timed out waiting for registration response".to_string());
            }
            Err(e) => return Err(format!("Failed to receive from channel: {}", e)),
        }
    }
}

fn process_tun_packets(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    tun: Arc<Mutex<TunDevice>>,
    shared_keys: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
) -> Result<(), String> {
    let mut buf = [0u8; MTU];

    loop {
        println!("📥 Reading from TUN");
        let n = tun
            .lock()
            .map_err(|e| format!("Failed to lock TUN: {}", e))?
            .read(&mut buf)
            .map_err(|e| format!("Failed to read from TUN: {}", e))?;
        println!("📥 Read from TUN: {} bytes", n);

        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            if parsed.dst.is_multicast() {
                continue;
            }

            println!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

            let peer_pk = get_dst_public_key(rx, stream, parsed.dst)?;
            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                .map_err(|_| "Invalid public key".to_string())?;

            let (shared_secret, ciphertext, first_time) = {
                let mut cache = shared_keys.lock().unwrap();
                if let Some(ss) = cache.get(&parsed.dst) {
                    println!("🔒 Shared key found in cache: {}", parsed.dst);
                    (*ss, None, false)
                } else {
                    println!("🔒 Caching shared key: {}", parsed.dst);
                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                    cache.insert(parsed.dst, ss);
                    (ss, Some(ct), true)
                }
            };

            let encrypted_payload = encrypt_packet(shared_secret.as_bytes(), &buf[..n]);

            send_message(
                stream,
                &Message::SendEncryptedData {
                    source: parsed.src,
                    destination: parsed.dst,
                    ciphertext: ciphertext.map(|ct| ct.as_bytes().to_vec()),
                    encrypted_payload,
                },
            )
            .map_err(|e| format!("Failed to send: {}", e))?;

            println!(
                "🔐 Sent encrypted_payload: {} (with ciphertext: {})",
                parsed.dst, first_time
            );
        }
    }
}
pub fn run_client() -> Result<(), String> {
    let config = load_config()?;
    let addr = format!("{}:{}", config.ip, config.port);

    let mut stream = TcpStream::connect(addr).map_err(|e| format!("Connection failed: {}", e))?;
    println!("✅ Connected to server");

    let (my_pk, my_sk) = get_kyber_key();
    let shared_keys = Arc::new(Mutex::new(HashMap::new()));

    let public_key = my_pk.as_bytes();
    let local_ipv6 = ipv6_from_public_key(public_key);
    println!("✅ Own IPv6 address: {}", local_ipv6);

    let (tun_device, tun_name) =
        create_tun(local_ipv6).map_err(|e| format!("Failed to create TUN: {}", e))?;
    println!("✅ Created TUN device {}", tun_name);
    let tun = Arc::new(Mutex::new(tun_device));

    let (tx, rx) = unbounded();

    spawn_receive_loop(
        stream.try_clone().unwrap(),
        tx,
        tun.clone(),
        shared_keys.clone(),
        my_sk,
    );

    register_to_server(&rx, &mut stream, local_ipv6, public_key)?;

    process_tun_packets(&rx, &mut stream, tun, shared_keys)
}
