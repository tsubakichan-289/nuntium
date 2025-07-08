use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

pub struct Aes256GcmHelper {
    cipher: Aes256Gcm,
    counter: u64,
}

impl Aes256GcmHelper {
    pub fn new(key: &[u8]) -> Self {
        let k = Key::<Aes256Gcm>::from_slice(key);
        Self { cipher: Aes256Gcm::new(k), counter: 0 }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        nonce
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self.cipher.encrypt(nonce, plaintext).expect("encryption failure");
        (ct, nonce_bytes)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, ciphertext).ok()
    }
}
