use std::fs;
use std::path::Path;

/// Read the server IP address from `/etc/nuntium.conf`.
///
/// The file is expected to contain the IP address on the first line.
/// Returns `None` if the file does not exist or is empty.
pub fn read_server_ip() -> Option<String> {
    let path = std::env::var("NUNTIUM_CONF").unwrap_or_else(|_| "/etc/nuntium.conf".to_string());
    let content = fs::read_to_string(Path::new(&path)).ok()?;
    content
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// Read the server port from `/etc/nuntium.conf`.
///
/// The port is expected to be specified on the second line of the file.
/// Returns `None` if the file does not exist, the second line is missing, or
/// parsing fails.
pub fn read_server_port() -> Option<u16> {
    let path = std::env::var("NUNTIUM_CONF").unwrap_or_else(|_| "/etc/nuntium.conf".to_string());
    let content = fs::read_to_string(Path::new(&path)).ok()?;
    content
        .lines()
        .nth(1)
        .and_then(|l| l.trim().parse::<u16>().ok())
}
