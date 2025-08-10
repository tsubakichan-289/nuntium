use crate::tun::TunDevice;
use crossbeam_channel::{bounded, Sender};
use std::io::{self, Write};
use std::thread;

/// Dedicated writer thread for TUN device.
#[derive(Clone)]
pub struct TunWriter {
    tx: Sender<Vec<u8>>,
}

impl TunWriter {
    /// Spawn the writer thread and return a handle for sending packets.
    pub fn spawn(mut device: TunDevice) -> Self {
        let capacity = std::env::var("NUNTIUM_TUN_QUEUE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        let (tx, rx) = bounded::<Vec<u8>>(capacity);

        thread::Builder::new()
            .name("tun-writer".into())
            .spawn(move || {
                while let Ok(pkt) = rx.recv() {
                    let mut offset = 0;
                    while offset < pkt.len() {
                        match device.write(&pkt[offset..]) {
                            Ok(0) => break,
                            Ok(n) => offset += n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(std::time::Duration::from_millis(1));
                            }
                            Err(e) => {
                                log::error!("❌ Failed to write to TUN: {}", e);
                                break;
                            }
                        }
                    }
                    if offset == pkt.len() {
                        log::info!("📦 Wrote to TUN: {} bytes", offset);
                    }
                }
            })
            .expect("failed to spawn tun-writer thread");

        Self { tx }
    }

    /// Queue a packet for writing to the TUN device.
    pub fn send(&self, packet: Vec<u8>) -> Result<(), crossbeam_channel::SendError<Vec<u8>>> {
        self.tx.send(packet)
    }
}
