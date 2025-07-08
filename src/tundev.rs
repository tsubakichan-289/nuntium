use std::io::{Read, Write};
use tun::{Configuration, Layer};

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

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.write(buf)
    }
}
