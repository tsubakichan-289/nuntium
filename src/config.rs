use crate::path_manager::CONFIG_FILE;
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub ttl_seconds: u64,
    pub max_keys: usize,
}

/// Determine configuration file path, optionally using the `NUNTIUM_CONF` environment variable
fn config_path() -> PathBuf {
    env::var("NUNTIUM_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(CONFIG_FILE))
}

/// Load the JSON configuration file
pub fn load_config() -> Result<Config, String> {
    let path = config_path();
    let text =
        fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;

    serde_json::from_str::<Config>(&text).map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Read the server IP from the configuration file
#[allow(dead_code)]
pub fn read_server_ip() -> Option<String> {
    load_config().ok().map(|c| c.ip.to_string())
}

/// Read the server port from the configuration file
#[allow(dead_code)]
pub fn read_server_port() -> Option<u16> {
    load_config().ok().map(|c| c.port)
}
