use std::io::{self};
use std::net::Ipv6Addr;
use std::process::Command;
use tun::{Configuration, Device};

use crate::packet::{parse_ipv6_packet, UpperLayerPacket};
use crate::protocol::MTU;

/// Create a TUN device and assign an IPv6 address
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(impl Device, String)> {
    let mut config = Configuration::default();
    config.mtu(MTU as i32).up();

    // Convert errors into io::Error
    let dev = tun::create(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let name = dev
        .name()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .to_string();

    let status = Command::new("ip")
        .args([
            "-6",
            "addr",
            "add",
            &format!("{}/7", ipv6_addr),
            "dev",
            &name,
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to configure IPv6 address",
        ));
    }

    Ok((dev, name))
}

/// Sequentially parse and display packets read from the TUN device
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
