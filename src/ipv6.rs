use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::Ipv6Addr;
use std::path::Path;

use crate::path_manager::{DATA_PUBLIC_KEY, DATA_SECRET_KEY};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

fn save_hex_to_file<P: AsRef<Path>>(path: P, data: &[u8]) -> std::io::Result<()> {
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

fn load_hex_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let hex_string = std::fs::read_to_string(path)?;
    let bytes = (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16).unwrap())
        .collect();
    Ok(bytes)
}

fn make_kyber_key() -> (kyber1024::PublicKey, kyber1024::SecretKey) {
    let (public_key, secret_key) = kyber1024::keypair();
    save_hex_to_file(DATA_PUBLIC_KEY, public_key.as_bytes()).unwrap();
    save_hex_to_file(DATA_SECRET_KEY, secret_key.as_bytes()).unwrap();
    (public_key, secret_key)
}

pub fn get_kyber_key() -> (kyber1024::PublicKey, kyber1024::SecretKey) {
    if !std::path::Path::new(DATA_PUBLIC_KEY).exists() {
        return make_kyber_key();
    }

    let public_key_bytes = load_hex_from_file(DATA_PUBLIC_KEY).unwrap();
    let secret_key_bytes = load_hex_from_file(DATA_SECRET_KEY).unwrap();

    let public_key = kyber1024::PublicKey::from_bytes(&public_key_bytes).unwrap();
    let secret_key = kyber1024::SecretKey::from_bytes(&secret_key_bytes).unwrap();

    (public_key, secret_key)
}

pub fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    let mut bits = [0u8; 121];
    let mut bit_idx = 0;

    'outer: for &byte in pk {
        let inv = !byte;
        for i in (0..8).rev() {
            let bit = (inv >> i) & 1;
            if bit_idx < 121 {
                bits[bit_idx] = bit;
                bit_idx += 1;
            } else {
                break 'outer;
            }
        }
    }

    let start = bits.iter().position(|&b| b == 1).unwrap_or(120);
    let suffix = &bits[start..];
    let mut trimmed = [0u8; 121];
    trimmed[..suffix.len()].copy_from_slice(suffix);

    let mut addr = [0u8; 16];
    addr[0] = 0b0100_0000 | trimmed[0];

    let mut idx = 1;
    for byte in &mut addr[1..] {
        let mut b = 0u8;
        for _ in 0..8 {
            b = (b << 1) | trimmed.get(idx).copied().unwrap_or(0);
            idx += 1;
        }
        *byte = b;
    }

    Ipv6Addr::from(addr)
}
