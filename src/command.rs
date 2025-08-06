use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ServerError {
    /// Public key not found
    KeyNotFound(Ipv6Addr),

    /// Client is not registered
    UnregisteredClient,

    /// Destination client is offline
    DestinationUnavailable(Ipv6Addr),

    /// Invalid request
    InvalidRequest(String),

    /// Internal server error
    InternalError(String),

    /// Client address is invalid
    InvalidAddress,

    /// Mutex lock was poisoned
    LockPoisoned,

    /// Failed to save to storage
    StorageFailure,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    /// Client registration request (c -> s)
    Register {
        address: Ipv6Addr,
        public_key: Vec<u8>,
    },

    /// Client registration response (s -> c)
    RegisterResponse { result: Result<(), ServerError> },

    /// Public key request (c -> s)
    KeyRequest { target_address: Ipv6Addr },

    /// Public key response (s -> c)
    KeyResponse {
        target_address: Ipv6Addr,
        result: Result<Vec<u8>, ServerError>, // OK
    },

    /// Send encrypted_payload (c -> s)
    SendEncryptedData {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        ciphertext: Option<Vec<u8>>,
        encrypted_payload: Vec<u8>,
    },

    /// Receive encrypted_payload (s -> c)
    ReceiveEncryptedData {
        source: Ipv6Addr,
        ciphertext: Option<Vec<u8>>,
        encrypted_payload: Vec<u8>,
    },

    /// Forwarded encrypted communication (s -> c2)
    ForwardedData {
        source: Ipv6Addr,
        encrypted_payload: Vec<u8>,
    },

    /// Error message (s -> c)
    Error(ServerError),
}
