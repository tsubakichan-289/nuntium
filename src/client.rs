use crate::aes::{decrypt_packet, encrypt_packet};
use crate::command::Message;
use crate::config::load_config;
use crate::ipv6::{get_kyber_key, ipv6_from_public_key};
use crate::message_io::{receive_message, send_message};
use crate::packet::parse_ipv6_packet;
use crate::shared_keys::{
    create_cache, get_key as cache_get, insert_key as cache_insert, SharedKeysCache,
};
use crate::tun::{create_tun, TunDevice, MTU};

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

use crossbeam::channel::{unbounded, Receiver, RecvTimeoutError, Sender};
#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{error, info};

fn spawn_receive_loop(
    mut stream: TcpStream,
    tx: Sender<Message>,
    tun: Arc<Mutex<TunDevice>>,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
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
                    info!("🔐 Received encrypted data: {}", source);

                    let ss = match ciphertext {
                        Some(ct_bytes) => {
                            info!(
                                "🧩 Ciphertext provided; decapsulating and caching shared key: {}",
                                source
                            );
                            let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
                                .expect("Invalid ciphertext");
                            let ss = kyber1024::decapsulate(&ct, &my_secret_key);
                            shared_secrets.lock().unwrap().insert(source, ss);
                            ss
                        }
                        None => {
                            info!("🔒 No ciphertext; using cached shared key: {}", source);
                            match shared_secrets.lock().unwrap().get(&source) {
                                Some(cached) => *cached,
                                None => {
                                    error!("❌ Shared key not cached: {}", source);
                                    continue;
                                }
                            }
                        }
                    };

                    let packet = match decrypt_packet(ss.as_bytes(), &encrypted_payload) {
                        Ok(p) => {
                            info!("✅ Successfully decrypted packet: {}", source);
                            p
                        }
                        Err(e) => {
                            error!("❌ Failed to decrypt: {:?}", e);
                            continue;
                        }
                    };

                    info!("🔒 Acquiring TUN write lock");
                    let mut tun_guard = tun.lock().unwrap();
                    info!("🔓 Acquired TUN lock");
                    if let Err(e) = tun_guard.write_all(&packet) {
                        error!("❌ Failed to write to TUN: {}", e);
                    } else {
                        info!("📦 Wrote to TUN: {} bytes", packet.len());
                    }
                }
                Message::KeyResponse {
                    target_address,
                    result,
                } => {
                    if let Ok(ref pk) = result {
                        cache_insert(&public_keys, target_address, pk.clone());
                    }
                    if let Err(e) = tx.send(Message::KeyResponse {
                        target_address,
                        result,
                    }) {
                        error!("❌ Failed to forward message: {}", e);
                    }
                }

                Message::RegisterResponse { .. } => {
                    if let Err(e) = tx.send(msg.clone()) {
                        error!("❌ Failed to forward message: {}", e);
                    }
                }

                _ => {
                    info!("📥 Irrelevant message: {:?}", msg);
                }
            },
            Err(e) => {
                error!("❌ Failed to receive message: {}", e);
                break;
            }
        }
    });
}

#[cfg(unix)]
fn process_tun_packets(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    tun: Arc<Mutex<TunDevice>>,
) -> Result<(), String> {
    let mut buf = [0u8; MTU];
    loop {
        let fd = {
            let tun_guard = tun.lock().unwrap();
            tun_guard.as_raw_fd()
        };
        let mut fds = [PollFd::new(
            unsafe { BorrowedFd::borrow_raw(fd) },
            PollFlags::POLLIN,
        )];
        match poll(&mut fds, 1000u16) {
            Ok(0) => {
                continue;
            }
            Ok(_) => {
                if let Some(revents) = fds[0].revents() {
                    if revents.contains(PollFlags::POLLIN) {
                        let n = tun
                            .lock()
                            .unwrap()
                            .read(&mut buf)
                            .map_err(|e| format!("TUN read failed: {}", e))?;
                        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
                            if parsed.dst.is_multicast() {
                                continue;
                            }

                            info!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

                            let peer_pk = get_dst_public_key(&public_keys, rx, stream, parsed.dst)?;
                            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                                .map_err(|_| "Invalid public key".to_string())?;

                            let (shared_secret, ciphertext, first_time) = {
                                let mut cache = shared_secrets.lock().unwrap();
                                if let Some(ss) = cache.get(&parsed.dst) {
                                    info!("🔒 Shared key found in cache: {}", parsed.dst);
                                    (*ss, None, false)
                                } else {
                                    info!("🔒 Caching shared key: {}", parsed.dst);
                                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                                    cache.insert(parsed.dst, ss);
                                    (ss, Some(ct), true)
                                }
                            };

                            let encrypted_payload =
                                encrypt_packet(shared_secret.as_bytes(), &buf[..n])
                                    .map_err(|e| format!("encryption failed: {:?}", e))?;

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

                            info!(
                                "🔐 Sent encrypted_payload: {} (with ciphertext: {})",
                                parsed.dst, first_time
                            );
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!("poll failed: {}", e));
            }
        }
    }
}

#[cfg(windows)]
fn process_tun_packets(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    tun: Arc<Mutex<TunDevice>>,
) -> Result<(), String> {
    let mut buf = [0u8; MTU];
    loop {
        let n = tun
            .lock()
            .unwrap()
            .read(&mut buf)
            .map_err(|e| format!("TUN read failed: {}", e))?;
        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            if parsed.dst.is_multicast() {
                continue;
            }

            info!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

            let peer_pk = get_dst_public_key(&public_keys, rx, stream, parsed.dst)?;
            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                .map_err(|_| "Invalid public key".to_string())?;

            let (shared_secret, ciphertext, first_time) = {
                let mut cache = shared_secrets.lock().unwrap();
                if let Some(ss) = cache.get(&parsed.dst) {
                    info!("🔒 Shared key found in cache: {}", parsed.dst);
                    (*ss, None, false)
                } else {
                    info!("🔒 Caching shared key: {}", parsed.dst);
                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                    cache.insert(parsed.dst, ss);
                    (ss, Some(ct), true)
                }
            };

            let encrypted_payload = encrypt_packet(shared_secret.as_bytes(), &buf[..n])
                .map_err(|e| format!("encryption failed: {:?}", e))?;

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

            info!(
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
    info!("✅ Connected to server");

    let (my_pk, my_sk) = get_kyber_key();
    let shared_secrets = Arc::new(Mutex::new(HashMap::new()));
    let public_keys = create_cache(config.ttl_seconds, config.max_keys);

    let public_key = my_pk.as_bytes();
    let local_ipv6 = ipv6_from_public_key(public_key);
    info!("✅ Own IPv6 address: {}", local_ipv6);

    let (tun_device, tun_name) =
        create_tun(local_ipv6).map_err(|e| format!("Failed to create TUN: {}", e))?;
    info!("✅ Created TUN device {}", tun_name);
    let tun = Arc::new(Mutex::new(tun_device));

    let (tx, rx) = unbounded();

    spawn_receive_loop(
        stream.try_clone().unwrap(),
        tx,
        tun.clone(),
        public_keys.clone(),
        shared_secrets.clone(),
        my_sk,
    );

    register_to_server(&rx, &mut stream, local_ipv6, public_key)?;

    process_tun_packets(&rx, &mut stream, public_keys, shared_secrets, tun)
}

fn get_dst_public_key(
    cache: &SharedKeysCache,
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    address: Ipv6Addr,
) -> Result<Vec<u8>, String> {
    info!("🔍 Entering get_dst_public_key for address: {}", address);

    // Check LRU cache first
    if let Some(pk) = cache_get(cache, &address) {
        info!("📦 Found cached public key for: {}", address);
        return Ok(pk);
    }

    info!("📭 Sending KeyRequest to server for: {}", address);
    send_message(
        stream,
        &Message::KeyRequest {
            target_address: address,
        },
    )
    .map_err(|e| format!("Failed to send key request: {}", e))?;

    info!("⏳ Waiting for KeyResponse for: {}", address);

    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Message::KeyResponse {
                target_address,
                result,
            }) if target_address == address => {
                info!("📬 Received KeyResponse for: {}", address);
                let public_key = result.map_err(|e| format!("Key error: {:?}", e))?;
                cache_insert(cache, address, public_key.clone());
                info!("✅ Cached public key for: {}", address);
                return Ok(public_key);
            }

            Ok(other) => {
                info!("📥 Received unrelated message while waiting: {:?}", other);
            }

            Err(RecvTimeoutError::Timeout) => {
                info!("⏰ Timeout waiting for KeyResponse: {}", address);
                return Err("Timed out waiting for key response".to_string());
            }

            Err(e) => {
                info!("❌ Error receiving from channel: {}", e);
                return Err(format!("Failed to receive from channel: {}", e));
            }
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
                    info!("✅ Registration successful");
                    return Ok(());
                }
                Err(e) => return Err(format!("Registration failed: {:?}", e)),
            },
            Ok(other) => {
                info!("📥 Other message: {:?}", other);
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("Timed out waiting for registration response".to_string());
            }
            Err(e) => return Err(format!("Failed to receive from channel: {}", e)),
        }
    }
}
