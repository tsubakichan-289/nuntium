use sha2::{Sha256, Digest};
use std::net::Ipv6Addr;

pub fn make_ipv6_from_pubkey(pk: &[u8]) -> Ipv6Addr {
    let hash = Sha256::digest(pk);
    let bytes: [u8; 16] = hash[0..16].try_into().unwrap();
    Ipv6Addr::from(bytes)
}
