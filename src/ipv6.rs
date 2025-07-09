use sha2::{Sha256, Digest};
use std::net::Ipv6Addr;

/// Derive an IPv6 address from a public key by hashing it with SHA-256 and
/// truncating the result to 128 bits.
pub fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    let hash = Sha256::digest(pk);
    let bytes: [u8; 16] = hash[0..16].try_into().unwrap();
    Ipv6Addr::from(bytes)
}
