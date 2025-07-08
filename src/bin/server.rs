use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::net::UdpSocket;
use tun::AbstractDevice;
use std::convert::TryInto;

// Type alias for HMAC-SHA1
type HmacSha1 = Hmac<Sha1>;

const KEY: &[u8] = b"sharedsecret";
const SERVER_ADDR: &str = "0.0.0.0:5072";

#[tokio::main]
async fn main() -> Result<()> {
    // Create TUN device (tun0 by default)
    let mut config = tun::Configuration::default();
    config.up();
    config.name("tun0");

    let mut dev = tun::create_as_async(&config)?;
    let mtu = dev.mtu()? as usize;
    let mut buf = vec![0u8; mtu + tun::PACKET_INFORMATION_LENGTH];

    let socket = UdpSocket::bind(SERVER_ADDR).await?;
    println!("Server listening on {}", SERVER_ADDR);

    loop {
        let (len, _addr) = socket.recv_from(&mut buf).await?;
        let packet = &buf[..len];
        if let Ok(payload) = parse_and_verify(packet) {
            dev.send(&payload).await?;
        }
    }
}

fn parse_and_verify(packet: &[u8]) -> Result<Vec<u8>> {
    let mut idx = 0usize;
    if packet.len() < 1 + 1 + 1 + 4 + 1 {
        return Err(anyhow!("packet too short"));
    }

    let identity_type = packet[idx];
    idx += 1;
    if identity_type != 0x01 { return Err(anyhow!("unsupported identity type")); }

    let id_len = packet[idx] as usize;
    idx += 1;
    if idx + id_len > packet.len() { return Err(anyhow!("bad identity length")); }
    let _identity = &packet[idx..idx+id_len];
    idx += id_len;

    if idx >= packet.len() { return Err(anyhow!("missing hmac_len")); }
    let hmac_len = packet[idx] as usize;
    idx += 1;
    if idx + hmac_len > packet.len() { return Err(anyhow!("bad hmac length")); }
    let hmac_bytes = &packet[idx..idx+hmac_len];
    idx += hmac_len;

    if idx + 4 + 1 > packet.len() { return Err(anyhow!("missing epoch or header")); }
    let epoch_bytes: [u8;4] = packet[idx..idx+4].try_into().unwrap();
    idx += 4;
    let next_header = packet[idx];
    idx += 1;
    if next_header != 0x29 { return Err(anyhow!("unsupported header")); }

    let payload = &packet[idx..];

    let mut mac = HmacSha1::new_from_slice(KEY).expect("HMAC can take key of any size");
    mac.update(&epoch_bytes);
    mac.update(payload);
    mac.verify_slice(hmac_bytes).map_err(|_| anyhow!("hmac mismatch"))?;

    Ok(payload.to_vec())
}
