#![allow(dead_code)]
pub const MSG_TYPE_KEY_EXCHANGE: u8 = 1;
pub const MSG_TYPE_ENCRYPTED_PACKET: u8 = 2;

pub const MSG_TYPE_REGISTER: u8 = 0x10;
pub const MSG_TYPE_QUERY: u8 = 0x11;
pub const MSG_TYPE_QUERY_RESPONSE: u8 = 0x12;
pub const MSG_TYPE_LISTEN: u8 = 0x13;

// === Size constants ===
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1584;
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
pub const IPV6_ADDR_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

// === Computed frame lengths ===
pub const REGISTER_MSG_SIZE: usize = 1 + KYBER_PUBLIC_KEY_SIZE + IPV6_ADDR_SIZE;
pub const KEY_EXCHANGE_MSG_SIZE: usize = 1 + IPV6_ADDR_SIZE + KYBER_CIPHERTEXT_SIZE;
pub const ENCRYPTED_PACKET_HEADER_SIZE: usize = 1 + IPV6_ADDR_SIZE * 2 + NONCE_SIZE;
pub const QUERY_MSG_SIZE: usize = 1 + IPV6_ADDR_SIZE;
pub const LISTEN_MSG_SIZE: usize = 1 + IPV6_ADDR_SIZE;
pub const MTU: usize = 1500;
