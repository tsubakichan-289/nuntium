# Nuntium Protocol Overview

Nuntium is an experimental messaging protocol that combines post-quantum key exchange with symmetric transport encryption.

## Key Exchange

Peers negotiate a session key using the [Kyber](https://pq-crystals.org/kyber/) key encapsulation mechanism via the `pqcrypto-kyber` crate. This provides resistance against quantum adversaries. Both sides generate Kyber key pairs, exchange the public keys and derive a shared secret.

## Transport Encryption

Once a shared secret is established, all messages are encrypted with AES-256-GCM from the `aes-gcm` crate. Nonces should never repeat and each packet is authenticated to prevent tampering.

## IPv6 Address Derivation

The shared secret also deterministically maps to an IPv6 address. Derive a 128-bit value from the secret (e.g. using a cryptographic hash) and use it as the host portion of an IPv6 address. This allows peers to discover each other based solely on the key exchange.

## Building and Usage

This repository currently contains only documentation, but future server and client implementations will be written in Rust. Ensure you have the Rust toolchain installed (`rustup` recommended).

To build future components:

```bash
cargo build --release
```

## Prerequisites

- Rust stable toolchain
- [`pqcrypto-kyber`](https://crates.io/crates/pqcrypto-kyber) for post-quantum key exchange
- [`aes-gcm`](https://crates.io/crates/aes-gcm) for AES-256-GCM transport encryption

