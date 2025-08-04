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

use crossbeam::channel::{unbounded, Receiver, Sender};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::{Arc, Mutex};
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
                    println!("🔐 暗号化データ受信: {}", source);

                    let ss = match ciphertext {
                        Some(ct_bytes) => {
                            println!("🧩 ciphertext あり、復号して共有鍵キャッシュ: {}", source);
                            let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
                                .expect("無効なCiphertext");
                            let ss = kyber1024::decapsulate(&ct, &my_secret_key);
                            shared_keys.lock().unwrap().insert(source, ss.clone());
                            ss
                        }
                        None => {
                            println!("🔒 ciphertext なし、キャッシュ参照: {}", source);
                            match shared_keys.lock().unwrap().get(&source) {
                                Some(cached) => cached.clone(),
                                None => {
                                    eprintln!("❌ 共有鍵がキャッシュされていません: {}", source);
                                    continue;
                                }
                            }
                        }
                    };

                    let packet = match decrypt_packet(ss.as_bytes(), &encrypted_payload) {
                        Ok(p) => {
                            println!("✅ パケット復号成功: {}", source);
                            p
                        }
                        Err(e) => {
                            eprintln!("❌ 復号失敗: {}", e);
                            continue;
                        }
                    };
                    
                    println!("🔒 TUN 書き込み前ロック取得開始");
                    let mut tun_guard = tun.lock().unwrap();
                    println!("🔓 TUN ロック取得成功");
                    if let Err(e) = tun_guard.write_all(&packet) {
                        eprintln!("❌ TUN 書き込み失敗: {}", e);
                    } else {
                        println!("📦 TUN 書き込み成功: {} バイト", packet.len());
                    }
                }

                Message::KeyResponse { .. } | Message::RegisterResponse { .. } => {
                    if let Err(e) = tx.send(msg.clone()) {
                        eprintln!("❌ メッセージ転送失敗: {}", e);
                    }
                }

                _ => {
                    println!("📥 関係ないメッセージ: {:?}", msg);
                }
            },
            Err(e) => {
                eprintln!("❌ メッセージ受信失敗: {}", e);
                break;
            }
        }
    });
}

fn get_dst_public_key(
    tx: &Sender<Message>,
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    address: Ipv6Addr,
) -> Result<Vec<u8>, String> {
    if let Some(client) =
        find_client(&address).map_err(|e| format!("クライアント情報取得失敗: {}", e))?
    {
        return Ok(client.public_key);
    }

    send_message(
        stream,
        &Message::KeyRequest {
            target_address: address,
        },
    )
    .map_err(|e| format!("公開鍵要求送信失敗: {}", e))?;
    println!("🔑 公開鍵要求を送信しました: {}", address);

    loop {
        match rx.recv() {
            Ok(Message::KeyResponse {
                target_address,
                result,
            }) if target_address == address => {
                let public_key = result.map_err(|e| format!("鍵エラー: {:?}", e))?;
                save_client_info(&ClientInfo {
                    address,
                    public_key: public_key.clone(),
                })
                .map_err(|e| format!("保存失敗: {}", e))?;
                return Ok(public_key);
            }
            Ok(msg) => {
                println!("📥 関係ないメッセージ: {:?}", msg);
            }
            Err(e) => return Err(format!("チャンネル受信失敗: {}", e)),
        }
    }
}
pub fn run_client() -> Result<(), String> {
    let config = load_config()?;
    let addr = format!("{}:{}", config.ip, config.port);

    let mut stream = TcpStream::connect(addr).map_err(|e| format!("接続失敗: {}", e))?;
    println!("✅ サーバーに接続しました");

    let (my_pk, my_sk) = get_kyber_key();
    let shared_keys = Arc::new(Mutex::new(HashMap::new()));

    let public_key = my_pk.as_bytes();
    let local_ipv6 = ipv6_from_public_key(&public_key);
    println!("✅ 自分のIPv6アドレス: {}", local_ipv6);

    let (tun_device, tun_name) =
        create_tun(local_ipv6).map_err(|e| format!("TUN作成失敗: {}", e))?;
    println!("✅ TUNデバイス {} を作成しました", tun_name);
    let tun = Arc::new(Mutex::new(tun_device));

    let (tx, rx) = unbounded();

    spawn_receive_loop(
        stream.try_clone().unwrap(),
        tx.clone(),
        tun.clone(),
        shared_keys.clone(),
        my_sk.clone(),
    );

    // 🔐 公開鍵登録
    send_message(
        &mut stream,
        &Message::Register {
            address: local_ipv6,
            public_key: public_key.to_vec(),
        },
    )
    .map_err(|e| format!("登録送信失敗: {}", e))?;

    // 🔐 RegisterResponse 待機
    loop {
        match rx.recv() {
            Ok(Message::RegisterResponse { result }) => {
                match result {
                    Ok(()) => {
                        println!("✅ 登録成功");
                        break;
                    }
                    Err(e) => return Err(format!("登録失敗: {:?}", e)),
                }
            }
            Ok(other) => {
                println!("📥 他のメッセージ: {:?}", other);
            }
            Err(e) => return Err(format!("チャンネル受信失敗: {}", e)),
        }
    }

    let mut buf = [0u8; MTU];

    loop {
        println!("📥 TUN 読み込み前");
        let n = tun
            .lock()
            .map_err(|e| format!("TUNロック失敗: {}", e))?
            .read(&mut buf)
            .map_err(|e| format!("TUN読み込み失敗: {}", e))?;
        println!("📥 TUN 読み込み完了: {} bytes", n);

        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            if parsed.dst.is_multicast() {
                continue;
            }

            println!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

            // 🔐 受信者の公開鍵取得
            let peer_pk =
                get_dst_public_key(&tx, &rx, &mut stream, parsed.dst).map_err(|e| e.to_string())?;
            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                .map_err(|_| "公開鍵不正".to_string())?;

            // 🔐 キャッシュ確認と必要に応じて鍵交換
            let (shared_secret, ciphertext, first_time) = {
                let mut cache = shared_keys.lock().unwrap();
                if let Some(ss) = cache.get(&parsed.dst) {
                    println!("🔒 共有鍵がキャッシュに存在: {}", parsed.dst);
                    (ss.clone(), None, false)
                } else {
                    println!("🔒 共有鍵をキャッシュに登録: {}", parsed.dst);
                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                    cache.insert(parsed.dst, ss.clone());
                    (ss, Some(ct), true)
                }
            };

            let encrypted_payload = encrypt_packet(shared_secret.as_bytes(), &buf[..n]);

            // 🔐 送信（必要に応じて ciphertext を含める）
            send_message(
                &mut stream,
                &Message::SendEncryptedData {
                    source: parsed.src,
                    destination: parsed.dst,
                    ciphertext: ciphertext.map(|ct| ct.as_bytes().to_vec()),
                    encrypted_payload,
                },
            )
            .map_err(|e| format!("送信失敗: {}", e))?;

            println!(
                "🔐 encrypted_payload 送信: {} （ciphertext付き: {}）",
                parsed.dst,
                first_time
            );
        }
    }
}
