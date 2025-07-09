use std::net::Ipv6Addr;
use nuntium::{ipv6::ipv6_from_public_key, pqc, crypto::Aes256GcmHelper};

#[test]
fn ipv6_derivation_from_known_key() {
    // deterministic 32-byte public key 0..31
    let pk: Vec<u8> = (0u8..32).collect();
    let addr = ipv6_from_public_key(&pk);
    let expected_bytes = [
        0x41, 0xff, 0xfd, 0xfb, 0xf9, 0xf7, 0xf5, 0xf3,
        0xf1, 0xef, 0xed, 0xeb, 0xe9, 0xe7, 0xe5, 0xe3,
    ];
    let expected = Ipv6Addr::from(expected_bytes);
    assert_eq!(addr, expected);
}

#[test]
fn kyber512_handshake_shared_secret() {
    let (server_pk, server_sk) = pqc::generate_keypair();
    let (ct, client_ss) = pqc::encapsulate(&server_pk);
    let server_ss = pqc::decapsulate(&ct, &server_sk);
    assert_eq!(client_ss, server_ss);
}

#[test]
fn aes256gcm_round_trip_unique_nonces() {
    let key = [0u8; 32];
    let mut aes = Aes256GcmHelper::new(&key);

    let msg1 = b"hello";
    let (ct1, nonce1) = aes.encrypt(msg1);
    let msg2 = b"world";
    let (ct2, nonce2) = aes.encrypt(msg2);

    assert_ne!(nonce1, nonce2);

    let dec1 = aes.decrypt(&nonce1, &ct1).expect("decrypt1");
    let dec2 = aes.decrypt(&nonce2, &ct2).expect("decrypt2");
    assert_eq!(dec1, msg1);
    assert_eq!(dec2, msg2);
}
