use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use pqcrypto_traits::kem::{PublicKey, Ciphertext};
use pqcrypto_kyber::kyber1024;

/// リクエストの種類
pub enum Request {
    Register {
        public_key: kyber1024::PublicKey,
        ipv6_addr: Ipv6Addr,
    },
    Query {
        ipv6_addr: Ipv6Addr,
    },
    KeyExchange {
        dst_ipv6: Ipv6Addr,
        ciphertext: kyber1024::Ciphertext,
    },
}

impl Request {
    /// リクエストを送信する。`Query` のみレスポンスの内容（公開鍵バイト列）を返す。
    pub fn send(&self, ip: IpAddr, port: u16) -> io::Result<Option<Vec<u8>>> {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr)?;

        match self {
            Request::Register { public_key, ipv6_addr } => {
                let payload = public_key.as_bytes();
                let ipv6_bytes = ipv6_addr.octets();
                let total_len = payload.len() + ipv6_bytes.len();

                let header = format!(
                    "POST /register HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                    total_len
                );

                stream.write_all(header.as_bytes())?;
                stream.write_all(payload)?;
                stream.write_all(&ipv6_bytes)?;

                Ok(None)
            }

            Request::Query { ipv6_addr } => {
                let request = format!(
                    "GET /query?ipv6={} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    ipv6_addr, ip
                );
                stream.write_all(request.as_bytes())?;

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

            Request::KeyExchange { dst_ipv6, ciphertext } => {
                let dst_bytes = dst_ipv6.octets();
                let ct_bytes = ciphertext.as_bytes();
                let total_len = dst_bytes.len() + ct_bytes.len();

                let header = format!(
                    "POST /keyexchange HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                    total_len
                );

                stream.write_all(header.as_bytes())?;
                stream.write_all(&dst_bytes)?;
                stream.write_all(ct_bytes)?;
                Ok(None)
            }
        }
    }
}
