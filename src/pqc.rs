use pqcrypto_traits::kem::{PublicKey as _, Ciphertext as _, SharedSecret as _};
use pqcrypto_kyber::kyber512;
use pqcrypto_kyber::kyber512::{PublicKey, SecretKey, Ciphertext};

pub const PUBLIC_KEY_LEN: usize = kyber512::public_key_bytes();
pub const SECRET_KEY_LEN: usize = kyber512::secret_key_bytes();
pub const CIPHERTEXT_LEN: usize = kyber512::ciphertext_bytes();

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    kyber512::keypair()
}

pub fn encapsulate(pk: &PublicKey) -> (Vec<u8>, Vec<u8>) {
    let (ct, ss) = kyber512::encapsulate(pk);
    (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
}

pub fn decapsulate(ciphertext: &[u8], sk: &SecretKey) -> Vec<u8> {
    let ct = Ciphertext::from_bytes(ciphertext).expect("invalid ciphertext");
    let ss = kyber512::decapsulate(&ct, sk);
    ss.as_bytes().to_vec()
}

pub fn public_key_from_bytes(bytes: &[u8]) -> PublicKey {
    PublicKey::from_bytes(bytes).expect("invalid public key")
}
