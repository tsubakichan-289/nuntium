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
