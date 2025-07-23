use nuntium::protocol::{
    MSG_TYPE_ENCRYPTED_PACKET, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_LISTEN, MSG_TYPE_QUERY,
    MSG_TYPE_QUERY_RESPONSE, MSG_TYPE_REGISTER,
};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};

/// リクエストの種類
pub enum Request {
    Register {
        public_key: kyber1024::PublicKey,
        ipv6_addr: Ipv6Addr,
    },
    Query {
        ipv6_addr: Ipv6Addr,
    },
    Listen {
        ipv6_addr: Ipv6Addr,
    },
    KeyExchange {
        dst_ipv6: Ipv6Addr,
        ciphertext: kyber1024::Ciphertext,
    },
    EncryptedPacket {
        src_ipv6: Ipv6Addr,
        dst_ipv6: Ipv6Addr,
        nonce: [u8; 12],
        payload: Vec<u8>,
    },
}

impl Request {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Request::Register {
                public_key,
                ipv6_addr,
            } => {
                let mut buf = Vec::with_capacity(1 + public_key.as_bytes().len() + 16);
                buf.push(MSG_TYPE_REGISTER);
                buf.extend_from_slice(public_key.as_bytes());
                buf.extend_from_slice(&ipv6_addr.octets());
                buf
            }
            Request::Query { ipv6_addr } => {
                let mut buf = Vec::with_capacity(1 + 16);
                buf.push(MSG_TYPE_QUERY);
                buf.extend_from_slice(&ipv6_addr.octets());
                buf
            }
            Request::Listen { ipv6_addr } => {
                let mut buf = Vec::with_capacity(1 + 16);
                buf.push(MSG_TYPE_LISTEN);
                buf.extend_from_slice(&ipv6_addr.octets());
                buf
            }
            Request::KeyExchange {
                dst_ipv6,
                ciphertext,
            } => {
                let ct = ciphertext.as_bytes();
                let mut buf = Vec::with_capacity(1 + 16 + ct.len());
                buf.push(MSG_TYPE_KEY_EXCHANGE);
                buf.extend_from_slice(&dst_ipv6.octets());
                buf.extend_from_slice(ct);
                buf
            }
            Request::EncryptedPacket {
                src_ipv6,
                dst_ipv6,
                nonce,
                payload,
            } => {
                let mut buf = Vec::with_capacity(1 + 16 + 16 + 12 + payload.len());
                buf.push(MSG_TYPE_ENCRYPTED_PACKET);
                buf.extend_from_slice(&src_ipv6.octets());
                buf.extend_from_slice(&dst_ipv6.octets());
                buf.extend_from_slice(nonce);
                buf.extend_from_slice(payload);
                buf
            }
        }
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty frame"));
        }
        match buf[0] {
            MSG_TYPE_REGISTER => {
                if buf.len() < 1 + 1584 + 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid register",
                    ));
                }
                let pk = kyber1024::PublicKey::from_bytes(&buf[1..1 + 1584]).map_err(|e| {
                    io::Error::new(ErrorKind::InvalidData, format!("Invalid public key: {e}"))
                })?;
                let ipv6 =
                    Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1 + 1584..1 + 1584 + 16]).unwrap());
                Ok(Request::Register {
                    public_key: pk,
                    ipv6_addr: ipv6,
                })
            }
            MSG_TYPE_QUERY => {
                if buf.len() < 1 + 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid query",
                    ));
                }
                let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
                Ok(Request::Query { ipv6_addr: ipv6 })
            }
            MSG_TYPE_LISTEN => {
                if buf.len() < 1 + 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid listen",
                    ));
                }
                let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
                Ok(Request::Listen { ipv6_addr: ipv6 })
            }
            MSG_TYPE_KEY_EXCHANGE => {
                if buf.len() < 1 + 16 + 1568 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid keyexchange",
                    ));
                }
                let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
                let ct = kyber1024::Ciphertext::from_bytes(&buf[17..]).map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("Invalid Kyber ciphertext: {e}"),
                    )
                })?;
                Ok(Request::KeyExchange {
                    dst_ipv6: dst,
                    ciphertext: ct,
                })
            }
            MSG_TYPE_ENCRYPTED_PACKET => {
                if buf.len() < 1 + 16 + 16 + 12 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "invalid packet",
                    ));
                }
                let src = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
                let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[17..33]).unwrap());
                let nonce: [u8; 12] = buf[33..45].try_into().unwrap();
                let payload = buf[45..].to_vec();
                Ok(Request::EncryptedPacket {
                    src_ipv6: src,
                    dst_ipv6: dst,
                    nonce,
                    payload,
                })
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown type")),
        }
    }

    /// リクエストを送信する。`Query` のみレスポンスの内容（公開鍵バイト列）を返す。
    pub fn send(&self, ip: IpAddr, port: u16) -> io::Result<Option<Vec<u8>>> {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr)?;
        stream.write_all(&self.to_bytes())?;

        if matches!(self, Request::Query { .. }) {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            if buf.first() == Some(&MSG_TYPE_QUERY_RESPONSE) {
                if buf.get(1) == Some(&1) {
                    Ok(Some(buf[2..].to_vec()))
                } else {
                    Ok(None)
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid response",
                ))
            }
        } else {
            Ok(None)
        }
    }
}
