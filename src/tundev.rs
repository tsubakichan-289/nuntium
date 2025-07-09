use std::io::{Read, Write};
use std::process::Command;
use tun::{Configuration, Layer, Device};

pub struct TunDevice {
    dev: tun::platform::Device,
}

impl TunDevice {
    pub fn create(name: &str) -> tun::Result<Self> {
        let mut config = Configuration::default();
        config
            .name(name)
            .layer(Layer::L3)
            .up();
        config.platform(|p| {
            #[cfg(target_os = "linux")]
            p.packet_information(false);
        });
        let dev = tun::create(&config)?;
        Ok(Self { dev })
    }

    pub fn name(&self) -> Result<String, tun::Error> {
        self.dev.name()
    }

    pub fn assign_ipv6(&self, addr: std::net::Ipv6Addr) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let name = self
                .dev
                .name()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let status = Command::new("ip")
                .args(["-6", "addr", "add", &format!("{}/64", addr), "dev", &name])
                .status()?;
            if !status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "ip addr add failed",
                ));
            }
        }
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.write(buf)
    }
}
