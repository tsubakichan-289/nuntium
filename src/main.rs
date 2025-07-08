use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tun::AbstractDevice;

// Type alias for HMAC-SHA1
type HmacSha1 = Hmac<Sha1>;

const IDENTITY: &str = "demo";
const KEY: &[u8] = b"sharedsecret";
const SERVER_ADDR: &str = "127.0.0.1:5072";

#[tokio::main]
async fn main() -> Result<()> {
    // Create TUN device
    let mut config = tun::Configuration::default();
    config.up();

    let dev = tun::create_as_async(&config)?;
    let mtu = dev.mtu()? as usize;
    let mut buf = vec![0u8; mtu + tun::PACKET_INFORMATION_LENGTH];

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(SERVER_ADDR).await?;

    loop {
        let n = dev.recv(&mut buf).await?;
        let payload = &buf[..n];
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as u32;
        let epoch_bytes = epoch.to_be_bytes();

        let mut mac = HmacSha1::new_from_slice(KEY).expect("HMAC can take key of any size");
        mac.update(&epoch_bytes);
        mac.update(payload);
        let hmac_bytes = mac.finalize().into_bytes();

        let mut packet = Vec::with_capacity(1 + 1 + IDENTITY.len() + 1 + hmac_bytes.len() + 4 + 1 + payload.len());
        packet.push(0x01); // identity_type
        packet.push(IDENTITY.len() as u8); // identity_len
        packet.extend_from_slice(IDENTITY.as_bytes());
        packet.push(hmac_bytes.len() as u8); // hmac_len
        packet.extend_from_slice(&hmac_bytes); // hmac
        packet.extend_from_slice(&epoch_bytes); // epoch
        packet.push(0x29); // next_header: IPv6
        packet.extend_from_slice(payload); // payload

        socket.send(&packet).await?;
    }
}
