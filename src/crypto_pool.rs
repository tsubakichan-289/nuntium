use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use crossbeam_channel::{bounded, Sender};
use std::thread;

pub enum CryptoJob {
    Encrypt {
        packet_id: u64,
        nonce: [u8; 12],
        key: [u8; 32],
        payload: Vec<u8>,
        respond_to: Sender<(u64, Vec<u8>)>,
    },
    Decrypt {
        packet_id: u64,
        nonce: [u8; 12],
        key: [u8; 32],
        ciphertext: Vec<u8>,
        respond_to: Sender<(u64, Result<Vec<u8>, String>)>,
    },
}

#[derive(Clone)]
pub struct CryptoPool {
    req_tx: Sender<CryptoJob>,
}

impl CryptoPool {
    pub fn new(workers: usize) -> Self {
        let workers = std::env::var("NUNTIUM_CRYPTO_WORKERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(workers)
            .max(2);
        let (tx, rx) = bounded::<CryptoJob>(256);
        for _ in 0..workers {
            let rx = rx.clone();
            thread::spawn(move || {
                while let Ok(job) = rx.recv() {
                    match job {
                        CryptoJob::Encrypt {
                            packet_id,
                            nonce,
                            key,
                            payload,
                            respond_to,
                        } => {
                            let key = Key::<Aes256Gcm>::from_slice(&key);
                            let cipher = Aes256Gcm::new(key);
                            match cipher.encrypt(Nonce::from_slice(&nonce), payload.as_ref()) {
                                Ok(ct) => {
                                    let _ = respond_to.send((packet_id, ct));
                                }
                                Err(e) => {
                                    log::error!("❌ Encrypt error: {}", e);
                                    let _ = respond_to.send((packet_id, Vec::new()));
                                }
                            }
                        }
                        CryptoJob::Decrypt {
                            packet_id,
                            nonce,
                            key,
                            ciphertext,
                            respond_to,
                        } => {
                            let key = Key::<Aes256Gcm>::from_slice(&key);
                            let cipher = Aes256Gcm::new(key);
                            let res = cipher
                                .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                                .map_err(|e| e.to_string());
                            let _ = respond_to.send((packet_id, res));
                        }
                    }
                }
            });
        }
        Self { req_tx: tx }
    }

    pub fn submit(&self, job: CryptoJob) {
        let _ = self.req_tx.send(job);
    }
}
