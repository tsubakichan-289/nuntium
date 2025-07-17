use std::io::{self, Read};
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;
use tun::{Configuration, Device};

use crate::packet::{parse_ipv6_packet, UpperLayerPacket};

const MTU: usize = 1500;

/// TUN デバイスを作成し、IPv6 アドレスを割り当てる
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(impl Device, String)> {
    let mut config = Configuration::default();
    config
        .mtu(MTU as i32)
        .up();

    // エラーを io::Error に変換
    let dev = tun::create(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let name = dev
        .name()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .to_string();

    let status = Command::new("ip")
        .args(["-6", "addr", "add", &format!("{}/7", ipv6_addr), "dev", &name])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "IPv6 アドレスの設定に失敗しました"));
    }

    Ok((dev, name))
}

/// TUN デバイスから読み取ったパケットを逐次パースして表示する
pub fn read_loop(mut dev: impl Device) -> io::Result<()> {
    let mut buf = [0u8; MTU];
    loop {
        let n = dev.read(&mut buf)?;
        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            println!(
                "📦 IPv6: {} → {}, next_header: {}, hop_limit: {}, payload_length: {}",
                parsed.src, parsed.dst, parsed.next_header, parsed.hop_limit, parsed.payload_length
            );
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
                        "    未対応の上位プロトコル: {}, raw_length={}",
                        proto,
                        raw.len()
                    );
                }
            }
        } else {
            println!("⚠️ 無効な IPv6 パケット ({} bytes)", n);
        }
    }
}