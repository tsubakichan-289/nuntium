use std::fs::OpenOptions;
use std::io::{self, BufReader, BufWriter};
use std::path::Path;
use std::net::Ipv6Addr;
use serde::{Serialize, Deserialize};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub ipv6: String,
    pub public_key_hex: String,
}

pub fn save_client_info(info: ClientInfo, db_path: &Path) -> io::Result<()> {
	println!("Saving client info for {}", info.ipv6);
    let mut db: Vec<ClientInfo> = if db_path.exists() {
        let reader = BufReader::new(OpenOptions::new().read(true).open(db_path)?);
        serde_json::from_reader(reader).unwrap_or_default()
    } else {
        Vec::new()
    };

    db.retain(|entry| entry.ipv6 != info.ipv6);
    db.push(info);

    let writer = BufWriter::new(OpenOptions::new().write(true).create(true).truncate(true).open(db_path)?);
    serde_json::to_writer_pretty(writer, &db)?;
    Ok(())
}

pub fn client_exists(ipv6: &Ipv6Addr, db_path: &Path) -> io::Result<bool> {
    if !db_path.exists() {
        return Ok(false);
    }
    let reader = BufReader::new(OpenOptions::new().read(true).open(db_path)?);
    let entries: Vec<ClientInfo> = serde_json::from_reader(reader).unwrap_or_default();
    Ok(entries.iter().any(|entry| entry.ipv6 == ipv6.to_string()))
}

pub fn load_from_clients_json(ipv6: &Ipv6Addr, db_path: &Path) -> io::Result<Option<kyber1024::PublicKey>> {
    let reader = BufReader::new(OpenOptions::new().read(true).open(db_path)?);
    let entries: Vec<crate::client_info::ClientInfo> = serde_json::from_reader(reader).unwrap_or_default();

    if let Some(entry) = entries.iter().find(|e| e.ipv6 == ipv6.to_string()) {
        let bytes = hex::decode(&entry.public_key_hex)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hex decode failed"))?;
        let pk = kyber1024::PublicKey::from_bytes(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Kyber public key"))?;
        Ok(Some(pk))
    } else {
        Ok(None)
    }
}