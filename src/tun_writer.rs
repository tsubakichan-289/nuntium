use crate::tun::TunDevice;
use crossbeam_channel::{bounded, Sender};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// Asynchronous writer for TUN device using a bounded channel.
#[derive(Clone)]
pub struct TunWriter {
    sender: Sender<Vec<u8>>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl TunWriter {
    /// Create a new `TunWriter` and spawn the background writer thread.
    pub fn new(mut dev: TunDevice) -> Self {
        let queue_size = std::env::var("NUNTIUM_TUN_QUEUE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        let (tx, rx) = bounded::<Vec<u8>>(queue_size);

        let handle = thread::Builder::new()
            .name("tun-writer".into())
            .spawn(move || {
                while let Ok(packet) = rx.recv() {
                    if let Err(e) = dev.write_all(&packet) {
                        log::error!("❌ Failed to write to TUN: {}", e);
                    }
                }
            })
            .expect("failed to spawn tun-writer thread");

        Self {
            sender: tx,
            handle: Arc::new(Mutex::new(Some(handle))),
        }
    }

    /// Send a packet to the TUN writer thread.
    pub fn send(&self, packet: Vec<u8>) -> Result<(), crossbeam_channel::SendError<Vec<u8>>> {
        self.sender.send(packet)
    }

    /// Shutdown the writer thread, waiting for it to finish.
    pub fn shutdown(self) {
        drop(self.sender);
        if let Ok(mut guard) = self.handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}
