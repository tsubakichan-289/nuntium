use std::net::{TcpStream, Ipv6Addr};
use std::io::{Write, Read};
use crate::config::load_config;
use crate::config::Config;
use serde::{Serialize, Deserialize};
use crate::ipv6::ipv6_from_public_key;
use crate::command::{Message, ServerError};
use crate::message_io::{send_message, receive_message};

pub fn register_client(
    stream: &mut TcpStream,
    address: Ipv6Addr,
    public_key: Vec<u8>,
) -> Result<(), String> {
    // 登録メッセージを作成
    let register_msg = Message::Register {
        address,
        public_key,
    };

    // メッセージ送信
    send_message(stream, &register_msg)
        .map_err(|e| format!("メッセージ送信失敗: {}", e))?;

    println!("✅ クライアント登録要求を送信しました");

    // 応答メッセージを受信
    let response = receive_message(stream)
        .map_err(|e| format!("メッセージ受信失敗: {}", e))?;

    // 応答の検査
    match response {
        Message::RegisterResponse { result } => {
            match result {
                Ok(()) => {
                    println!("🆗 登録成功");
                    Ok(())
                }
                Err(err) => {
                    eprintln!("❌ 登録失敗: {:?}", err);
                    Err(format!("登録失敗: {:?}", err))
                }
            }
        }
        other => {
            Err(format!("予期しない応答: {:?}", other))
        }
    }
}

// == クライアント実行 ==
pub fn run_client() -> Result<(), String> {
    let config = load_config()?; // 設定ファイル読み込み
    let addr = format!("{}:{}", config.ip, config.port);

    // == TCP接続 ==
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| format!("サーバー接続失敗: {}", e))?;
    println!("✅ サーバーに接続しました");

	// == 仮の公開鍵生成 ==
	let public_key = vec![0u8; 800]; // 例として800バイトのダミー公開鍵
    // == 自分のIPv6アドレス取得 ==
	let local_ipv6 = ipv6_from_public_key(&public_key);

	println!("✅ 自分のIPv6アドレス: {}", local_ipv6);
	// == クライアント登録要求 ==
	register_client(&mut stream, local_ipv6, public_key)?;
	

    Ok(())
}