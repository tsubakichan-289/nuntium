mod client;
mod client_info;
mod config;
mod config_reader;
mod debug;
mod packet;
mod path_manager;
mod server;
mod tun;

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::net::Ipv6Addr;
use std::path::Path;

fn save_hex_to_file<P: AsRef<Path>>(path: P, data: &[u8]) -> std::io::Result<()> {
    let hex_string = data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
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

pub fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    let digest = Sha256::digest(pk); // 256bit = 32byte

    let mut addr = [0u8; 16];

    // First byte: upper 7 bits fixed (e.g. 0b10000000 = 0x80), lowest bit comes from the digest
    addr[0] = 0b10000000 | ((digest[0] & 0b10000000) >> 7); // fixed prefix + top bit of the hash

    // addr[1..16] uses the remaining 7 bits of digest[0] and the upper 121 bits of digest[1..15]
    let mut bit_cursor = 1; // already consumed the highest bit of the digest

    for i in 1..16 {
        let byte = match bit_cursor {
            1..=7 => {
                // Combine the tail of the previous byte with the head of the next byte
                let prev = digest[i - 1] << bit_cursor;
                let next = digest[i] >> (8 - bit_cursor);
                prev | next
            }
            _ => digest[i], // Fallback (should not happen)
        };
        addr[i] = byte;
    }

    Ipv6Addr::from(addr)
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

            // Start server
            server::run_server(config.port)?;
        }

        Some("client") => {
            debug::debug_print("Starting in client mode...");

            let (public_key, _secret_key) = get_kyber_key(&path_manager);
            let ipv6_addr = ipv6_from_public_key(public_key.as_bytes());

            // Display key
            println!(
                "Public Key (first 8 bytes): {:02X?}",
                &public_key.as_bytes()[..8]
            );
            println!("IPv6 Address: {}", ipv6_addr);

            let config = config_reader::read_server_config(&path_manager)?;

            // Client processing
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
