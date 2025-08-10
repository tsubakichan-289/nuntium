use crate::aes::{decrypt_packet, encrypt_packet};
use aes_gcm::aead::Error;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::thread;

pub enum CryptoJob {
    Encrypt {
        packet_id: u64,
        key: Vec<u8>,
        data: Vec<u8>,
        resp: Sender<(u64, Result<Vec<u8>, Error>)>,
    },
    Decrypt {
        packet_id: u64,
        key: Vec<u8>,
        data: Vec<u8>,
        resp: Sender<(u64, Result<Vec<u8>, Error>)>,
    },
}

#[derive(Clone)]
pub struct CryptoPool {
    tx: Sender<CryptoJob>,
}

impl CryptoPool {
    pub fn new() -> Self {
        let workers = std::env::var("NUNTIUM_CRYPTO_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(num_cpus::get)
            .max(2);
        let (tx, rx): (Sender<CryptoJob>, Receiver<CryptoJob>) = bounded(256);
        for _ in 0..workers {
            let rx = rx.clone();
            thread::spawn(move || {
                while let Ok(job) = rx.recv() {
                    match job {
                        CryptoJob::Encrypt {
                            packet_id,
                            key,
                            data,
                            resp,
                        } => {
                            let res = encrypt_packet(&key, &data);
                            let _ = resp.send((packet_id, res));
                        }
                        CryptoJob::Decrypt {
                            packet_id,
                            key,
                            data,
                            resp,
                        } => {
                            let res = decrypt_packet(&key, &data);
                            let _ = resp.send((packet_id, res));
                        }
                    }
                }
            });
        }
        Self { tx }
    }

    pub fn submit(&self, job: CryptoJob) -> Result<(), crossbeam_channel::SendError<CryptoJob>> {
        self.tx.send(job)
    }
}

impl Default for CryptoPool {
    fn default() -> Self {
        Self::new()
    }
}
