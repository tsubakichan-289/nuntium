use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub ip: IpAddr,
    pub port: u16,
}
