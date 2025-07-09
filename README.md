# Nuntium Protocol Overview

Nuntium is an experimental messaging protocol that combines post-quantum key exchange with symmetric transport encryption.

## Key Exchange

Peers negotiate a session key using the [Kyber](https://pq-crystals.org/kyber/) key encapsulation mechanism via the `pqcrypto-kyber` crate. This provides resistance against quantum adversaries. Both sides generate Kyber key pairs, exchange the public keys and derive a shared secret.

## Transport Encryption

Once a shared secret is established, all messages are encrypted with AES-256-GCM from the `aes-gcm` crate. Nonces should never repeat and each packet is authenticated to prevent tampering.

## IPv6 Address Derivation

Each public key deterministically maps to an IPv6 address in the `4000::/7`
range. First the public key bytes are bitwise inverted. Leading zero bits of
this inverted value are discarded until the first `1` bit. The next 121 bits are
used as the suffix below the `4000::/7` prefix (padding with zeros if necessary).
This stable mapping lets peers identify each other without additional
configuration.

## Building

Nuntium is written in Rust. Make sure the stable toolchain is available
(`rustup` is recommended) and build the binaries with:

```bash
cargo build --release
```

## Command-Line Interface

The build produces three small executables. `nuntium` is a dispatcher that
selects a mode via `--mode`:

```bash
nuntium --mode client       # connect to the server and exchange ping/pong
nuntium --mode server       # run the TCP handshake server
nuntium --mode client-tun   # start the TUN-based client
nuntium --mode server-tun   # run the UDP relay for tunneling
```

Minimal `client` and `server` binaries provide the same functionality as the
corresponding modes without argument parsing:

```bash
cargo run --bin client
cargo run --bin server
```

### Configuration

Client modes read the server address from `/etc/nuntium.conf` or the path given
in the `NUNTIUM_CONF` environment variable. The file must contain a JSON object
with `ip` and `port` fields:

```json
{ "ip": "127.0.0.1", "port": 9000 }
```

## Prerequisites

- Rust stable toolchain
- [`pqcrypto-kyber`](https://crates.io/crates/pqcrypto-kyber) for post-quantum key exchange
- [`aes-gcm`](https://crates.io/crates/aes-gcm) for AES-256-GCM transport encryption

## Running Tests

Unit tests ensure the cryptographic routines behave correctly. Run them with:

```bash
cargo test
```

## Tunneling and Virtual Networking

Nuntium also supports a virtual IPv6 overlay built on TUN devices. Each
client creates its own TUN interface and assigns the IPv6 address
derived from its public key. The address is configured automatically on
the interface with a `/64` prefix using the host's networking tools
(e.g. `ip`). If the assignment fails, a warning is printed. Packets read
from this interface are
encrypted and sent over UDP to a relay server. The server merely
forwards packets between clients and does not require its own address.

All peers share the `4000::/7` prefix, enabling isolated communication
without affecting the host network stack. Incoming encrypted packets are
decrypted and written back to the TUN interface, allowing transparent
use of standard IPv6 networking tools over the secure tunnel.

