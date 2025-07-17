use std::net::{IpAddr, SocketAddr, TcpStream, Ipv6Addr};
use std::io::{self, Read, Write};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::PublicKey;

use crate::tun;
use crate::packet::parse_ipv6_packet;

const MTU: usize = 1500;

pub fn run_client(
    ip: IpAddr,
    port: u16,
    public_key: kyber1024::PublicKey,
    ipv6_addr: Ipv6Addr,
) -> io::Result<()> {
    // 公開鍵登録
    let remote = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(remote)?;

    let payload = public_key.as_bytes();
    let register_request = format!(
        "POST /register HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        payload.len() + 16
    );
    stream.write_all(register_request.as_bytes())?;
    stream.write_all(payload)?;
    stream.write_all(&ipv6_addr.octets())?;

    println!("📤 公開鍵を送信しました ({} bytes)", payload.len() + 16);

    let (tun_device, tun_device_name) = tun::create_tun(ipv6_addr)?;
    println!("✅ TUN デバイス {} を作成", tun_device_name);

    let mut dev = tun_device;
    let mut buf = [0u8; MTU];
    loop {
        let n = dev.read(&mut buf)?;
        if let Some(ipv6_packet) = parse_ipv6_packet(&buf[..n]) {
            let dst = ipv6_packet.dst;
            println!("🔍 宛先アドレス: {}", dst);

            match query_server_for_key(dst, ip, port)? {
                Some(peer_key) => {
                    println!("🔑 鍵取得成功 (先頭8バイト): {:02X?}", &peer_key[..8]);
                }
                None => {
                    println!("❌ 該当なし: {}", dst);
                }
            }
        }
    }
}

fn query_server_for_key(ipv6_addr: Ipv6Addr, ip: IpAddr, port: u16) -> io::Result<Option<Vec<u8>>> {
    let mut stream = TcpStream::connect(SocketAddr::new(ip, port))?;
    let query_request = format!(
        "GET /query?ipv6={} HTTP/1.1\r\nHost: {}\r\n\r\n",
        ipv6_addr, ip
    );
    stream.write_all(query_request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let response_str = String::from_utf8_lossy(&response);
    if response_str.starts_with("HTTP/1.1 200") {
        if let Some(index) = response_str.find("\r\n\r\n") {
            let body = &response[(index + 4)..];
            Ok(Some(body.to_vec()))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "ボディが見つかりません"))
        }
    } else if response_str.contains("404") {
        Ok(None)
    } else if response_str.contains("500") {
        Err(io::Error::new(io::ErrorKind::Other, "サーバー内部エラー"))
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "不明なレスポンス"))
    }
}
