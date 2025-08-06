use crate::command::{Message, ServerError};
use crate::config::{load_config, Config};
use crate::ipv6::ipv6_from_public_key;
use crate::message_io::{receive_message, send_message};
use std::collections::HashMap;
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub type ClientRegistry = Arc<Mutex<HashMap<Ipv6Addr, Vec<u8>>>>;
pub type OnlineClients = Arc<Mutex<HashMap<Ipv6Addr, Arc<Mutex<TcpStream>>>>>;

/// Client registration with synchronization
fn register_client(
    address: Ipv6Addr,
    public_key: Vec<u8>,
    registry: &ClientRegistry,
) -> Result<(), ServerError> {
    let ipv6_addr = ipv6_from_public_key(&public_key);
    if ipv6_addr != address {
        return Err(ServerError::InvalidAddress);
    }

    let mut reg = registry.lock().map_err(|_| ServerError::LockPoisoned)?;
    reg.insert(address, public_key);
    Ok(())
}

pub fn run_server() -> std::io::Result<()> {
    let config: Config = load_config().map_err(std::io::Error::other)?;
    let addr = format!("{}:{}", config.ip, config.port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;

    println!("🚀 Server started: {}", addr);

    let registry: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));
    let online_clients: OnlineClients = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let registry = Arc::clone(&registry);
                let online_clients = Arc::clone(&online_clients);

                std::thread::spawn(move || {
                    let peer_addr = stream.peer_addr().ok();
                    println!("👇 Client connected: {:?}", peer_addr);

                    loop {
                        match receive_message(&mut stream) {
                            Ok(msg) => match msg {
                                Message::Register {
                                    address,
                                    public_key,
                                } => {
                                    println!("📝 Registering client: {:?}", address);

                                    match register_client(address, public_key.clone(), &registry) {
                                        Ok(_) => {
                                            let mut online = online_clients.lock().unwrap();
                                            if let Ok(clone) = stream.try_clone() {
                                                online.insert(address, Arc::new(Mutex::new(clone)));
                                                println!(
                                                    "🟢 Added to online clients: {:?}",
                                                    address
                                                );
                                            }

                                            let response =
                                                Message::RegisterResponse { result: Ok(()) };
                                            if let Err(e) = send_message(&mut stream, &response) {
                                                eprintln!("❌ Failed to send response: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            let response = Message::RegisterResponse {
                                                result: Err(e.clone()),
                                            };
                                            if let Err(e) = send_message(&mut stream, &response) {
                                                eprintln!("❌ Failed to send response: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }

                                Message::KeyRequest { target_address } => {
                                    println!("🔑 Public key request: {:?}", target_address);
                                    let reg = registry.lock().unwrap();
                                    let response = match reg.get(&target_address) {
                                        Some(public_key) => {
                                            println!("✅ Found public key: {:?}", target_address);
                                            Message::KeyResponse {
                                                target_address,
                                                result: Ok(public_key.clone()),
                                            }
                                        }
                                        None => {
                                            println!(
                                                "❗ Public key not found: {:?}",
                                                target_address
                                            );
                                            Message::KeyResponse {
                                                target_address,
                                                result: Err(ServerError::KeyNotFound(
                                                    target_address,
                                                )),
                                            }
                                        }
                                    };
                                    if let Err(e) = send_message(&mut stream, &response) {
                                        eprintln!("❌ Failed to send public key response: {}", e);
                                        break;
                                    }
                                }
                                Message::SendEncryptedData {
                                    source,
                                    destination,
                                    ciphertext,
                                    encrypted_payload,
                                } => {
                                    println!("📦 encrypted_payload received: {:?}", destination);
                                    let online = online_clients.lock().unwrap();
                                    if let Some(dest_stream_arc) = online.get(&destination) {
                                        let mut guard = dest_stream_arc.lock().unwrap();
                                        let dest_stream: &mut TcpStream = &mut guard;
                                        let response = Message::ReceiveEncryptedData {
                                            source,
                                            ciphertext,
                                            encrypted_payload,
                                        };
                                        if let Err(e) = send_message(dest_stream, &response) {
                                            eprintln!(
                                                "❌ Failed to forward encrypted_payload: {}",
                                                e
                                            );
                                        } else {
                                            println!(
                                                "📤 encrypted_payload forwarded: {:?}",
                                                destination
                                            );
                                        }
                                    } else {
                                        eprintln!("❗ Online client not found: {:?}", destination);
                                        let response = Message::Error(
                                            ServerError::DestinationUnavailable(destination),
                                        );

                                        if let Err(e) = send_message(&mut stream, &response) {
                                            eprintln!("❌ Failed to send error message: {}", e);
                                        }
                                    }
                                }
                                other => {
                                    eprintln!("❗ Unimplemented message type: {:?}", other);
                                }
                            },
                            Err(e) => {
                                eprintln!("📬 Failed to receive message: {}", e);
                                break;
                            }
                        }
                    }

                    println!("🔌 Closing connection with client");
                    if let Some(addr) = peer_addr {
                        let mut online = online_clients.lock().unwrap();
                        online.retain(|_, s| {
                            s.lock().ok().and_then(|tcp| tcp.peer_addr().ok()) != Some(addr)
                        });
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    Ok(())
}
