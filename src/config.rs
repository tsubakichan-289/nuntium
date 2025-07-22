use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub ip: IpAddr,
    pub port: u16,
}
use std::env;
use std::fs;
use std::io;

/// Read the server configuration file and return the deserialized structure.
fn read_config() -> io::Result<ServerConfig> {
    let path = env::var("NUNTIUM_CONF").unwrap_or_else(|_| "/etc/nuntium.conf".into());
    let contents = fs::read_to_string(path)?;
    let cfg: ServerConfig = serde_json::from_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(cfg)
}

/// Return the server IP address from configuration if available.
pub fn read_server_ip() -> Option<String> {
    read_config().ok().map(|c| c.ip.to_string())
}

/// Return the server port from configuration if available.
pub fn read_server_port() -> Option<u16> {
    read_config().ok().map(|c| c.port)
}
