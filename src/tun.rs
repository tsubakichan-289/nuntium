use std::io::{self, Error};
use std::net::Ipv6Addr;
use std::process::Command;
use tun::{Configuration, Device};

pub const MTU: usize = 1500;

/// Create a TUN device and assign an IPv6 address
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(tun::platform::Device, String)> {
    let mut config = Configuration::default();
    config.mtu(MTU as i32).up();

    let dev = tun::create(&config)
        .map_err(|e| Error::other(format!("TUN device creation failed: {}", e)))?;

    let name = dev.name().to_string();

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
        return Err(Error::other("Failed to configure IPv6 address"));
    }

    Ok((dev, name))
}
