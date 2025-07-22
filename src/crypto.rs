use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// Helper wrapper around AES-256-GCM providing simple encrypt/decrypt methods
/// with monotonically increasing nonces.
pub struct Aes256GcmHelper {
    cipher: Aes256Gcm,
    counter: u128,
}

impl Aes256GcmHelper {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher, counter: 0 }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let nonce_bytes = self.counter.to_be_bytes();
        let nonce_arr: [u8; 12] = nonce_bytes[4..].try_into().unwrap();
        let nonce = Nonce::from_slice(&nonce_arr);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("encryption failure");
        self.counter += 1;
        (ciphertext, nonce_arr)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, ciphertext).ok()
    }
}
