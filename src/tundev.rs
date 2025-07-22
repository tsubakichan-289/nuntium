use std::net::Ipv6Addr;

pub struct TunDevice;

impl TunDevice {
    pub fn ip_args(addr: Ipv6Addr, name: &str) -> Vec<String> {
        vec![
            "-6".to_string(),
            "addr".to_string(),
            "add".to_string(),
            format!("{}/7", addr),
            "dev".to_string(),
            name.to_string(),
        ]
    }
}
