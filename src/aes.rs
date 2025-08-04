use aes_gcm::aead::Aead; // ✅ 実行用
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // ✅ 暗号本体 // ✅ .new() を使うために必要

pub fn encrypt_packet(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key[..32]);

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&[0u8; 12]); // ← 固定値は安全性低いが、まず動作確認用
    cipher.encrypt(nonce, plaintext).expect("暗号化失敗")
}

pub fn decrypt_packet(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<aes_gcm::aes::Aes256>::from_slice(&key[..32]);

    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("復号失敗: {:?}", e))
}
