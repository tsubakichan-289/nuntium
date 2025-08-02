use std::io::{self, Error, ErrorKind};
use std::net::Ipv6Addr;
use std::process::Command;
use tun::{Configuration, Device};

pub const MTU: usize = 1500;

/// Create a TUN device and assign an IPv6 address
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(impl Device, String)> {
    let mut config = Configuration::default();
    config.mtu(MTU as i32).up();

    let dev = tun::create(&config).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("TUN device creation failed: {}", e),
        )
    })?;

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
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to configure IPv6 address",
        ));
    }

    Ok((dev, name))
}
