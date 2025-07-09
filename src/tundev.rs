use std::io::{Read, Write};
use std::process::Command;
use std::net::Ipv6Addr;
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

    pub fn assign_ipv6(&self, addr: Ipv6Addr) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let name = self
                .dev
                .name()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let args = Self::ip_args(addr, &name);
            let status = Command::new("ip")
                .args(&args)
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

    #[cfg(target_os = "linux")]
    pub fn ip_args(addr: Ipv6Addr, name: &str) -> Vec<String> {
        vec![
            "-6".into(),
            "addr".into(),
            "add".into(),
            format!("{}/7", addr),
            "dev".into(),
            name.into(),
        ]
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.write(buf)
    }
}
