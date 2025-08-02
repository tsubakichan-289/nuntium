use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::path::Path;

use crate::path_manager::DATA_CLIENTS;

// file_io.rs または別ファイルでも可
mod hex_format {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex string has odd length"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInfo {
    pub address: Ipv6Addr,

    #[serde(with = "hex_format")]
    pub public_key: Vec<u8>,
}

/// クライアント情報を保存（clients.json に追記・更新）
pub fn save_client_info(client: &ClientInfo) -> std::io::Result<()> {
    // 親ディレクトリを作成（存在しない場合）
    if let Some(parent) = Path::new(DATA_CLIENTS).parent() {
        create_dir_all(parent)?;
    }

    // 既存のデータを読み込む（存在しなければ空配列）
    let mut clients = load_all_clients().unwrap_or_else(|_| Vec::new());

    // アドレスが一致するクライアントがいれば更新、なければ追加
    if let Some(pos) = clients.iter().position(|c| c.address == client.address) {
        clients[pos] = client.clone();
    } else {
        clients.push(client.clone());
    }

    // JSON にシリアライズして書き込み
    let json = serde_json::to_string_pretty(&clients)?;
    let mut file = File::create(DATA_CLIENTS)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

/// clients.json からすべてのクライアント情報を読み込む
pub fn load_all_clients() -> std::io::Result<Vec<ClientInfo>> {
    match File::open(DATA_CLIENTS) {
        Ok(mut file) => {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let clients = serde_json::from_str(&contents)?;
            Ok(clients)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// 指定された IPv6 アドレスのクライアント情報を探す
pub fn find_client(address: &Ipv6Addr) -> std::io::Result<Option<ClientInfo>> {
    let clients = load_all_clients()?;
    Ok(clients.into_iter().find(|c| &c.address == address))
}

/// バイナリデータを 16進文字列に変換してファイルに保存
pub fn save_hex_to_file<P: AsRef<Path>>(path: P, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        create_dir_all(parent)?;
    }

    let hex_string = data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    let mut file = File::create(path)?;
    file.write_all(hex_string.as_bytes())?;

    Ok(())
}

/// 16進文字列ファイルをバイナリに変換して読み込み
pub fn load_hex_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let hex_string = std::fs::read_to_string(path)?;
    let bytes = (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16).unwrap())
        .collect();
    Ok(bytes)
}
