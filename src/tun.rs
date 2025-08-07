use std::io::{self, Error, Read, Write};
#[cfg(target_os = "windows")]
use std::net::IpAddr;
use std::net::Ipv6Addr;

pub const MTU: usize = 53049;

#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tun::{Configuration, Device};

/// Platform agnostic wrapper around a TUN device
#[cfg(target_os = "linux")]
pub type TunDevice = tun::platform::Device;

#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
pub struct WintunDevice {
    session: Arc<wintun::Session>,
}

#[cfg(target_os = "windows")]
pub type TunDevice = WintunDevice;

/// Create a TUN device and assign an IPv6 address
#[cfg(target_os = "linux")]
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(TunDevice, String)> {
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

/// Read a single packet from the TUN device into the provided MTU-sized buffer.
///
/// Allocating the buffer once and reusing it avoids repeated heap allocations
/// for every read call and helps keep throughput high.
#[inline]
#[allow(dead_code)]
pub fn read_packet(dev: &mut TunDevice, buf: &mut [u8; MTU]) -> io::Result<usize> {
    dev.read(buf)
}

/// Write a packet to the TUN device.
#[inline]
#[allow(dead_code)]
pub fn write_packet(dev: &mut TunDevice, packet: &[u8]) -> io::Result<usize> {
    dev.write(packet)
}

#[cfg(target_os = "windows")]
impl Read for WintunDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .session
            .receive_blocking()
            .map_err(|e| Error::other(format!("{}", e)))?;
        let bytes = packet.bytes();
        let len = bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}

#[cfg(target_os = "windows")]
impl Write for WintunDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut packet = self
            .session
            .allocate_send_packet(buf.len() as u16)
            .map_err(|e| Error::other(format!("{}", e)))?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn create_tun(ipv6_addr: Ipv6Addr) -> io::Result<(TunDevice, String)> {
    use std::env;
    use std::path::PathBuf;
    use wintun::Adapter;

    let dll_path = env::var_os("WINTUN_DLL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
            path.set_file_name("wintun.dll");
            path
        });
    let wintun = unsafe { wintun::load_from_path(&dll_path) }
        .map_err(|e| Error::other(format!("Failed to load wintun: {}", e)))?;

    let adapter = match Adapter::open(&wintun, "Nuntium") {
        Ok(a) => a,
        Err(_) => Adapter::create(&wintun, "Nuntium", "Nuntium", None)
            .map_err(|e| Error::other(format!("Adapter creation failed: {}", e)))?,
    };

    adapter
        .set_mtu(MTU)
        .map_err(|e| Error::other(format!("Failed to set MTU: {}", e)))?;

    let mask = wintun::util::ipv6_netmask_for_prefix(7)
        .map_err(|e| Error::other(format!("Failed to derive netmask: {}", e)))?;
    adapter
        .set_network_addresses_tuple(IpAddr::V6(ipv6_addr), IpAddr::V6(mask), None)
        .map_err(|e| Error::other(format!("Failed to set address: {}", e)))?;

    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| Error::other(format!("Failed to start session: {}", e)))?,
    );

    let name = adapter
        .get_name()
        .map_err(|e| Error::other(format!("Failed to get adapter name: {}", e)))?;

    Ok((WintunDevice { session }, name))
}
