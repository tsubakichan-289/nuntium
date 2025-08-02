use crate::command::Message;
use crate::config::load_config;
use crate::ipv6::{get_kyber_key, ipv6_from_public_key};
use crate::message_io::{receive_message, send_message};
use crate::tun::{create_tun, MTU};

use pqcrypto_traits::kem::PublicKey as _;
use std::io::{self, Write};
use std::net::{Ipv6Addr, TcpStream};

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::Ciphertext as _;
use pqcrypto_traits::kem::SharedSecret;

use tun::Device;

use std::sync::{Arc, Mutex};

use crate::file_io::find_client;
use crate::packet::{parse_ipv6_packet, UpperLayerPacket};

pub fn register_client(
    stream: &mut TcpStream,
    address: Ipv6Addr,
    public_key: Vec<u8>,
) -> Result<(), String> {
    let register_msg = Message::Register {
        address,
        public_key,
    };
    send_message(stream, &register_msg).map_err(|e| format!("メッセージ送信失敗: {}", e))?;
    println!("✅ クライアント登録要求を送信しました");

    let response = receive_message(stream).map_err(|e| format!("メッセージ受信失敗: {}", e))?;

    match response {
        Message::RegisterResponse { result } => match result {
            Ok(()) => {
                println!("🆗 登録成功");
                Ok(())
            }
            Err(err) => {
                eprintln!("❌ 登録失敗: {:?}", err);
                Err(format!("登録失敗: {:?}", err))
            }
        },
        other => Err(format!("予期しない応答: {:?}", other)),
    }
}

fn get_dst_public_key(stream: &mut TcpStream, address: Ipv6Addr) -> Result<Vec<u8>, String> {
    let client_opt =
        find_client(&address).map_err(|e| format!("クライアント情報の取得失敗: {}", e))?;

    if let Some(client) = client_opt {
        Ok(client.public_key)
    } else {
        let key_request = Message::KeyRequest {
            target_address: address,
        };
        send_message(stream, &key_request).map_err(|e| format!("公開鍵要求の送信失敗: {}", e))?;
        println!("🔑 公開鍵要求を送信しました: {}", address);

        let response =
            receive_message(stream).map_err(|e| format!("公開鍵応答の受信失敗: {}", e))?;
        match response {
            Message::KeyResponse { result, .. } => match result {
                Ok(public_key) => {
                    println!("✅ 公開鍵を受信しました: {}", address);
                    let client_info = crate::file_io::ClientInfo {
                        address,
                        public_key: public_key.clone(),
                    };
                    crate::file_io::save_client_info(&client_info)
                        .map_err(|e| format!("クライアント情報の保存失敗: {}", e))?;
                    Ok(public_key)
                }
                Err(err) => {
                    eprintln!("❌ 公開鍵要求失敗: {:?}", err);
                    Err(format!("公開鍵要求失敗: {:?}", err))
                }
            },
            other => Err(format!("予期しない応答: {:?}", other)),
        }
    }
}

pub fn read_loop(
    stream: &mut TcpStream,
    dev: Arc<Mutex<dyn Device<Queue = tun::platform::Queue> + Send>>,
) -> io::Result<()> {
    let mut buf = [0u8; MTU];
    loop {
        let n = dev.lock().unwrap().read(&mut buf)?;
        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            if parsed.dst == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2) {
                continue;
            }
            println!(
                "📦 IPv6: {} → {}, next_header: {}, hop_limit: {}, payload_length: {}",
                parsed.src, parsed.dst, parsed.next_header, parsed.hop_limit, parsed.payload_length
            );

            let peer_public_key_bytes =
                get_dst_public_key(stream, parsed.dst).map_err(io::Error::other)?;
            let peer_public_key = kyber1024::PublicKey::from_bytes(&peer_public_key_bytes)
                .map_err(|_| io::Error::other("公開鍵形式不正"))?;

            let (ciphertext, _shared_secret) = kyber1024::encapsulate(&peer_public_key);

            let send_msg = Message::SendCiphertext {
                source: parsed.src,
                destination: parsed.dst,
                ciphertext: ciphertext.as_bytes().to_vec(),
            };
            send_message(stream, &send_msg)
                .map_err(|e| io::Error::other(format!("ciphertext 送信失敗: {}", e)))?;
            println!("🔐 ciphertext を送信しました: {}", parsed.dst);

            match parsed.upper_layer {
                UpperLayerPacket::Tcp(ref tcp) => {
                    println!(
                        "    TCP: {} → {}, flags: {:#x}, seq={}, ack={}",
                        tcp.source_port,
                        tcp.destination_port,
                        tcp.flags,
                        tcp.sequence_number,
                        tcp.acknowledgement_number
                    );
                }
                UpperLayerPacket::Icmpv6(ref icmp) => {
                    println!(
                        "    ICMPv6: type={}, code={}, checksum=0x{:04x}",
                        icmp.icmp_type, icmp.code, icmp.checksum
                    );
                }
                UpperLayerPacket::Unknown(proto, ref raw) => {
                    println!(
                        "    Unsupported upper-layer protocol: {}, raw_length={}",
                        proto,
                        raw.len()
                    );
                }
            }
        } else {
            println!("⚠️ Invalid IPv6 packet ({} bytes)", n);
        }
    }
}

pub fn run_client() -> Result<(), String> {
    let config = load_config()?;
    let addr = format!("{}:{}", config.ip, config.port);

    let mut stream = TcpStream::connect(addr).map_err(|e| format!("サーバー接続失敗: {}", e))?;
    println!("✅ サーバーに接続しました");

    let public_key = get_kyber_key().0.as_bytes().to_vec();
    let local_ipv6 = ipv6_from_public_key(&public_key);
    println!("✅ 自分のIPv6アドレス: {}", local_ipv6);
    register_client(&mut stream, local_ipv6, public_key)?;

    let (tun_device, tun_name) =
        create_tun(local_ipv6).map_err(|e| format!("TUNデバイス作成失敗: {}", e))?;
    println!("✅ TUNデバイス {} を作成しました", tun_name);

    let mut stream_clone = stream.try_clone().expect("TCP stream clone failed");
    let tun_device = Arc::new(Mutex::new(tun_device));
    let tun_clone = Arc::clone(&tun_device);

    std::thread::spawn(move || loop {
        match receive_message(&mut stream_clone) {
            Ok(Message::ReceiveCiphertext { source, ciphertext }) => {
                println!("📥 ciphertext 受信: {}", source);

                let (_, secret_key) = get_kyber_key();
                let ct = match kyber1024::Ciphertext::from_bytes(&ciphertext) {
                    Ok(c) => c,
                    Err(_) => {
                        eprintln!("❌ Ciphertext parse error");
                        continue;
                    }
                };

                let shared_secret = kyber1024::decapsulate(&ct, &secret_key);
                let _key = shared_secret.as_bytes(); // ここで将来 AES 鍵などに使う

                if let Err(e) = tun_clone.lock().unwrap().write_all(&ciphertext) {
                    eprintln!("❌ TUN 書き込み失敗: {}", e);
                }
            }
            Ok(msg) => {
                eprintln!("❗ 未知のメッセージ種別: {:?}", msg);
            }
            Err(e) => {
                eprintln!("❌ メッセージ受信エラー: {}", e);
                break;
            }
        }
    });

    println!("🔄 パケット読み取りループを開始します...");
    read_loop(&mut stream, tun_device).map_err(|e| format!("パケット読み取り失敗: {}", e))?;

    println!("✅ パケット読み取りループを終了しました");
    Ok(())
}
