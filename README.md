# Nuntium

Nuntium is an experimental tool for secure packet forwarding over IPv6. It combines the post-quantum Kyber key exchange with AES-256-GCM encryption and uses a relay server to distribute public keys and forward encrypted payloads between clients.

## Features

- Derives IPv6 addresses from Kyber public keys
- Forwards packets through a TUN device
- Encrypts payloads using AES-256-GCM
- Shares public keys and relays encrypted data via a server

## Building and Testing

This project targets **Rust edition 2021** and supports both Unix-like systems and Windows.
On Windows, the client looks for the `wintun.dll` library using the `WINTUN_DLL_PATH`
environment variable. If unset, it falls back to the executable's directory. Ensure the
library is available so that the Wintun adapter can be loaded at runtime.

Before committing changes, format and verify the code:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Running

Start the server:

```bash
cargo run -- server
```

Start a client:

```bash
cargo run -- client
```

## Configuration

Settings are read from `nuntium.conf`. By default, the file is located at
`/etc/nuntium/nuntium.conf` on Unix systems and at
`C:/ProgramData/nuntium/nuntium.conf` on Windows. Set the `NUNTIUM_CONF`
environment variable to override the path:

```json
{
  "ip": "172.30.0.2",
  "port": 5072,
  "ttl_seconds": 3600,
  "max_keys": 1000
}
```

`ttl_seconds` defines how long cached public keys remain valid, and `max_keys` sets the maximum number of cached keys.

## IPv6 Address Derivation

1. Invert each byte of the Kyber public key and read bits from most to least significant.
2. Collect the first 121 bits and remove leading zeros.
3. Set the first byte of the IPv6 address to `0b0100_0000` ORed with the first remaining bit.
4. Pack the rest of the bits into the remaining 15 bytes.
5. The resulting 128-bit value becomes the client's logical IPv6 address.

## Transport Encryption

After exchanging keys, clients encrypt IPv6 payloads with **AES-256-GCM**. Each packet uses a randomly generated 12-byte nonce, which is prepended to the ciphertext to ensure confidentiality.

## Disclaimer

Nuntium is a research project and is not intended for production environments.
