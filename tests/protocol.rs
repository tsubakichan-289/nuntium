use nuntium::{
    aes::{decrypt_packet, encrypt_packet},
    ipv6::ipv6_from_public_key,
};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::SharedSecret as _;
use std::net::Ipv6Addr;

#[test]
fn ipv6_derivation_from_known_key() {
    // deterministic 32-byte public key 0..31
    let pk: Vec<u8> = (0u8..32).collect();
    let addr = ipv6_from_public_key(&pk);
    let expected_bytes = [
        0x41, 0xff, 0xfd, 0xfb, 0xf9, 0xf7, 0xf5, 0xf3, 0xf1, 0xef, 0xed, 0xeb, 0xe9, 0xe7, 0xe5,
        0xe3,
    ];
    let expected = Ipv6Addr::from(expected_bytes);
    assert_eq!(addr, expected);
}

#[test]
fn kyber512_handshake_shared_secret() {
    let (server_pk, server_sk) = kyber1024::keypair();
    let (client_ss, ct) = kyber1024::encapsulate(&server_pk);
    let server_ss = kyber1024::decapsulate(&ct, &server_sk);
    assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
}

#[test]
fn aes256gcm_round_trip() {
    let key = [0u8; 32];
    let msg = b"hello";
    let ct = encrypt_packet(&key, msg);
    let dec = decrypt_packet(&key, &ct).expect("decrypt");
    assert_eq!(dec, msg);
}
