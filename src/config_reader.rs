use std::fs;
use std::io;
use crate::path_manager::PathManager;
use crate::config::ServerConfig;

pub fn read_server_config(pm: &PathManager) -> io::Result<ServerConfig> {
    let path = pm.nuntium_config_path();
    let contents = fs::read_to_string(path)?;
    let config: ServerConfig = serde_json::from_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(config)
}
