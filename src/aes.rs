use aes_gcm::aead::{Aead, Error, KeyInit, OsRng}; // Runtime traits and helpers
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // Cipher implementation and helper types

/// Encrypt a packet using AES-256-GCM.
///
/// A random nonce is generated for every packet and prepended to the
/// resulting ciphertext. The provided `key` must be at least 32 bytes.
pub fn encrypt_packet(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() < 32 {
        return Err(Error);
    }

    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut ciphertext = cipher.encrypt(&nonce, plaintext)?;

    let mut result = nonce.to_vec();
    result.append(&mut ciphertext);
    Ok(result)
}

/// Decrypt a packet using AES-256-GCM.
///
/// Expects the nonce to be prepended to the ciphertext. The provided
/// `key` must be at least 32 bytes long.
pub fn decrypt_packet(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() < 32 {
        return Err(Error);
    }
    if ciphertext.len() < 12 {
        return Err(Error);
    }

    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(key);

    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct)
}
