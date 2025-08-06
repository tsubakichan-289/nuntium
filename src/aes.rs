use aes_gcm::aead::Aead; // For runtime use
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Cipher implementation and helper types

pub fn encrypt_packet(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key[..32]);

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&[0u8; 12]); // Using a fixed nonce is insecure but fine for initial testing
    cipher.encrypt(nonce, plaintext).expect("encryption failed")
}

pub fn decrypt_packet(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<aes_gcm::aes::Aes256>::from_slice(&key[..32]);

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {:?}", e))
}
