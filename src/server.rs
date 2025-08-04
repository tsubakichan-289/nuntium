use crate::command::{Message, ServerError};
use crate::config::{load_config, Config};
use crate::file_io::{save_client_info, ClientInfo};
use crate::ipv6::ipv6_from_public_key;
use crate::message_io::{receive_message, send_message};
use std::collections::HashMap;
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub type ClientRegistry = Arc<Mutex<HashMap<Ipv6Addr, Vec<u8>>>>;
pub type OnlineClients = Arc<Mutex<HashMap<Ipv6Addr, Arc<Mutex<TcpStream>>>>>;

/// クライアント登録処理（排他制御付き）
fn register_client(
    address: Ipv6Addr,
    public_key: Vec<u8>,
    registry: &ClientRegistry,
) -> Result<(), ServerError> {
    let ipv6_addr = ipv6_from_public_key(&public_key);
    if ipv6_addr != address {
        return Err(ServerError::InvalidAddress);
    }

    let client_info = ClientInfo {
        address,
        public_key,
    };

    {
        let mut reg = registry.lock().map_err(|_| ServerError::LockPoisoned)?;
        reg.insert(client_info.address, client_info.public_key.clone());
    }

    save_client_info(&client_info).map_err(|_| ServerError::StorageFailure)?;
    Ok(())
}

pub fn run_server() -> std::io::Result<()> {
    let config: Config = load_config().map_err(std::io::Error::other)?;
    let addr = format!("{}:{}", config.ip, config.port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;

    println!("🚀 サーバー起動: {}", addr);

    let registry: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));
    let online_clients: OnlineClients = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let registry = Arc::clone(&registry);
                let online_clients = Arc::clone(&online_clients);

                std::thread::spawn(move || {
                    let peer_addr = stream.peer_addr().ok();
                    println!("👇 クライアント接続: {:?}", peer_addr);

                    loop {
                        match receive_message(&mut stream) {
                            Ok(msg) => match msg {
                                Message::Register {
                                    address,
                                    public_key,
                                } => {
                                    println!("📝 クライアント登録: {:?}", address);

                                    match register_client(address, public_key.clone(), &registry) {
                                        Ok(_) => {
                                            let mut online = online_clients.lock().unwrap();
                                            if let Ok(clone) = stream.try_clone() {
                                                online.insert(address, Arc::new(Mutex::new(clone)));
                                                println!(
                                                    "🟢 オンラインクライアントに追加: {:?}",
                                                    address
                                                );
                                            }

                                            let response =
                                                Message::RegisterResponse { result: Ok(()) };
                                            if let Err(e) = send_message(&mut stream, &response) {
                                                eprintln!("❌ 応答送信に失敗: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            let response = Message::RegisterResponse {
                                                result: Err(e.clone()),
                                            };
                                            if let Err(e) = send_message(&mut stream, &response) {
                                                eprintln!("❌ 応答送信に失敗: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }

                                Message::KeyRequest { target_address } => {
                                    println!("🔑 公開鍵要求: {:?}", target_address);
                                    let reg = registry.lock().unwrap();
                                    let response = match reg.get(&target_address) {
                                        Some(public_key) => {
                                            println!("✅ 公開鍵を見つけた: {:?}", target_address);
                                            Message::KeyResponse {
                                                target_address,
                                                result: Ok(public_key.clone()),
                                            }
                                        }
                                        None => {
                                            println!(
                                                "❗ 公開鍵が見つからない: {:?}",
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
                                        eprintln!("❌ 公開鍵応答送信失敗: {}", e);
                                        break;
                                    }
                                }
                                Message::SendEncryptedData {
                                    source,
                                    destination,
                                    ciphertext,
                                    encrypted_payload,
                                } => {
                                    println!("📦 encrypted_payload 受信: {:?}", destination);
                                    let online = online_clients.lock().unwrap();
                                    if let Some(dest_stream_arc) = online.get(&destination) {
                                        let mut guard = dest_stream_arc.lock().unwrap();
                                        let dest_stream: &mut TcpStream = &mut *guard;
                                        let response = Message::ReceiveEncryptedData {
                                            source,
                                            ciphertext,
                                            encrypted_payload,
                                        };
                                        if let Err(e) = send_message(dest_stream, &response) {
                                            eprintln!("❌ encrypted_payload 転送失敗: {}", e);
                                        } else {
                                            println!("📤 encrypted_payload 転送完了: {:?}", destination);
                                        }
                                    } else {
                                        eprintln!(
                                            "❗ オンラインクライアントが見つからない: {:?}",
                                            destination
                                        );
                                        let response = Message::Error(
                                            ServerError::DestinationUnavailable(destination),
                                        );

                                        if let Err(e) = send_message(&mut stream, &response) {
                                            eprintln!("❌ エラーメッセージ送信失敗: {}", e);
                                        }
                                    }
                                }
                                other => {
                                    eprintln!("❗ 未実装のメッセージ種別: {:?}", other);
                                }
                            },
                            Err(e) => {
                                eprintln!("📬 メッセージ受信失敗: {}", e);
                                break;
                            }
                        }
                    }

                    println!("🔌 クライアントとの接続を終了");
                    if let Some(addr) = peer_addr {
                        let mut online = online_clients.lock().unwrap();
                        online.retain(|_, s| {
                            s.lock()
                                .ok()
                                .and_then(|tcp| tcp.peer_addr().ok())
                                .map_or(true, |tcp_addr| tcp_addr != addr)
                        });
                    }
                });
            }
            Err(e) => eprintln!("接続失敗: {}", e),
        }
    }

    Ok(())
}
