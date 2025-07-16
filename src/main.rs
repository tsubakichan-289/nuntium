mod path_manager;
mod debug;
mod config;
mod config_reader;
mod server;
mod client;
mod tun;

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

use std::fs::File;
use std::io::Write;
use std::path::Path;
use sha2::{Sha256, Digest};
use std::net::Ipv6Addr;

fn save_hex_to_file<P: AsRef<Path>>(path: P, data: &[u8]) -> std::io::Result<()> {
    let hex_string = data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    let mut file = File::create(path)?;
    file.write_all(hex_string.as_bytes())?;
    Ok(())
}

fn load_hex_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let hex_string = std::fs::read_to_string(path)?;
    let bytes = (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16).unwrap())
        .collect();
    Ok(bytes)
}

fn make_kyber_key(pm: &path_manager::PathManager) -> (kyber1024::PublicKey, kyber1024::SecretKey) {
    let (public_key, secret_key) = kyber1024::keypair();
    save_hex_to_file(pm.kyber_public_key_path(), public_key.as_bytes()).unwrap();
    save_hex_to_file(pm.kyber_secret_key_path(), secret_key.as_bytes()).unwrap();
    (public_key, secret_key)
}

fn get_kyber_key(pm: &path_manager::PathManager) -> (kyber1024::PublicKey, kyber1024::SecretKey) {
    if !pm.kyber_public_key_path().exists() || !pm.kyber_secret_key_path().exists() {
        return make_kyber_key(pm);
    }

    let public_key_bytes = load_hex_from_file(pm.kyber_public_key_path()).unwrap();
    let secret_key_bytes = load_hex_from_file(pm.kyber_secret_key_path()).unwrap();

    let public_key = kyber1024::PublicKey::from_bytes(&public_key_bytes).unwrap();
    let secret_key = kyber1024::SecretKey::from_bytes(&secret_key_bytes).unwrap();

    (public_key, secret_key)
}

fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    let mut hasher = Sha256::new();
    hasher.update(pk);
    let digest = hasher.finalize();

    let mut addr_bytes = [0u8; 16];

    addr_bytes[..15].copy_from_slice(&digest[..15]);

    addr_bytes[15] = digest[15] & 0b1000_0000;

    addr_bytes[0] &= 0b0111_1111;
    addr_bytes[0] |= 0b0100_0000;

    Ipv6Addr::from(addr_bytes)
}

fn main() -> std::io::Result<()> {
    debug::debug_print("Starting Nuntium...");

    let path_manager = path_manager::PathManager::new()?;
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            debug::debug_print("Debug mode: Generating Kyber keys");

            let config = config_reader::read_server_config(&path_manager)?;
            debug::debug_print(&format!("Server IP: {}, Port: {}", config.ip, config.port));

            // サーバー起動
            server::run_server(config.port)?;
        }

        Some("client") => {
            debug::debug_print("Starting in client mode...");

            let (public_key, _secret_key) = get_kyber_key(&path_manager);
            let ipv6_addr = ipv6_from_public_key(public_key.as_bytes());

            // key を表示
            println!("Public Key (first 8 bytes): {:02X?}", &public_key.as_bytes()[..8]);
            println!("IPv6 Address: {}", ipv6_addr);

            let config = config_reader::read_server_config(&path_manager)?;

            // クライアント処理
            client::run_client(config.ip, config.port, public_key, ipv6_addr)?;
        }

        _ => {
            let name = args.get(0).map(String::as_str).unwrap_or("nuntium");
            eprintln!("Usage: {} [server|client]", name);
            std::process::exit(1);
        }
    }

    Ok(())
}
