use crate::path_manager::CONFIG_FILE;
use serde::Deserialize;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// JSON 設定ファイルを読み込む
pub fn load_config() -> Result<Config, String> {
    let path = Path::new(CONFIG_FILE);
    let text = fs::read_to_string(path).map_err(|e| format!("設定ファイル読み込み失敗: {}", e))?;

    serde_json::from_str::<Config>(&text).map_err(|e| format!("JSON パース失敗: {}", e))
}
