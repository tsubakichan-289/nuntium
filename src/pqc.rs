use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Wrapper functions around pqcrypto-kyber for easier testing
pub fn generate_keypair() -> (PublicKey, SecretKey) {
    kyber1024::keypair()
}

pub fn encapsulate(pk: &PublicKey) -> (Ciphertext, SharedSecret) {
    let (ss, ct) = kyber1024::encapsulate(pk);
    (ct, ss)
}

pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    kyber1024::decapsulate(ct, sk)
}
