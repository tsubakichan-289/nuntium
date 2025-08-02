use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::command::Message;
use crate::message_io::{receive_message};

type ClientRegistry = Arc<Mutex<HashMap<std::net::Ipv6Addr, Vec<u8>>>>;

pub fn run_server(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("🚀 サーバー起動: {}", addr);

    let registry: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let registry = Arc::clone(&registry);

                std::thread::spawn(move || {
                    println!("👂 クライアント接続: {:?}", stream.peer_addr());

                    match receive_message(&mut stream) {
                        Ok(msg) => match msg {
                            Message::Register { address, public_key } => {
								println!("📝 クライアント登録: {:?}, {:?}", address, public_key);
                            }
                            other => {
                                eprintln!("❗ 未実装のメッセージ種別: {:?}", other);
                                // 必要に応じてエラーを返してもOK
                            }
                        }
                        Err(e) => {
                            eprintln!("📭 メッセージ受信失敗: {}", e);
                        }
                    }
                });
            }
            Err(e) => eprintln!("接続失敗: {}", e),
        }
    }

    Ok(())
}
