use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct Config {
    ip: Option<String>,
    port: Option<u16>,
    idle_timeout: Option<u64>,
}

fn read_config() -> Option<Config> {
    let path = std::env::var("NUNTIUM_CONF").unwrap_or_else(|_| "/etc/nuntium.conf".to_string());
    let content = fs::read_to_string(Path::new(&path)).ok()?;
    serde_json::from_str(&content).ok()
}

/// Read the server IP address from `/etc/nuntium.conf`.
///
/// The configuration file is expected to contain a JSON object with an `ip`
/// field. Returns `None` if the file does not exist or if parsing fails.
pub fn read_server_ip() -> Option<String> {
    read_config()?.ip
}

/// Read the server port from `/etc/nuntium.conf`.
///
/// The configuration file is expected to contain a JSON object with a `port`
/// field. Returns `None` if the file does not exist or if parsing fails.
pub fn read_server_port() -> Option<u16> {
    read_config()?.port
}

/// Read the idle timeout (in seconds) from `/etc/nuntium.conf`.
/// Returns `None` if the file or field is missing or invalid.
pub fn read_idle_timeout() -> Option<u64> {
    read_config()?.idle_timeout
}
