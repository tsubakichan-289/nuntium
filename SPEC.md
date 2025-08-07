# Nuntium Specification

## Overview
Nuntium is an experimental tool for secure packet forwarding over IPv6. It combines Kyber key exchange with AES‑256‑GCM encryption and uses a relay server to distribute public keys and forward encrypted payloads between clients.

## Components

### Cryptography
- Kyber1024 is used for post‑quantum key exchange. Each client generates a key pair, stores it on disk, and derives its IPv6 address from the public key.
- Payloads are protected with AES‑256‑GCM. A fixed 12‑byte nonce is used for initial testing and is not secure for production use.

### IPv6 Address Derivation
- The public key is bitwise inverted and the first 121 bits are taken.
- Leading zeros are trimmed, and the remaining bits are packed into a 128‑bit address whose first byte is `0b01000000` ORed with the first trimmed bit.
- The resulting address becomes the client's logical IPv6 identifier.

### Configuration
- Settings are read from a JSON file (`nuntium.conf`) with fields `ip`, `port`, `ttl_seconds`, and `max_keys`.
- `ttl_seconds` and `max_keys` configure the shared key cache on clients.

### Message Protocol
Messages are serialized with bincode and preceded by a 4‑byte big‑endian length prefix. The protocol supports:
- `Register { address, public_key }`
- `RegisterResponse { result }`
- `KeyRequest { target_address }`
- `KeyResponse { target_address, result }`
- `SendEncryptedData { source, destination, ciphertext, encrypted_payload }`
- `ReceiveEncryptedData { source, ciphertext, encrypted_payload }`
- `ForwardedData { source, encrypted_payload }`
- `Error(ServerError)`

### Client Behavior
1. Load configuration and connect to the server.
2. Generate or load a Kyber key pair and derive its IPv6 address.
3. Create a TUN interface and register the address and public key with the server.
4. Maintain an LRU cache of peer public keys and derived shared secrets. Cached entries expire after `ttl_seconds`.
5. For outgoing packets from the TUN device:
   - Parse the IPv6 header to determine the destination.
   - Obtain the destination's public key from cache or via `KeyRequest`.
   - Encapsulate to derive a shared secret and optionally send the ciphertext for first contact.
   - Encrypt the original packet with AES‑256‑GCM and send `SendEncryptedData` to the server.
6. For incoming `ReceiveEncryptedData`, decapsulate if needed, decrypt the payload, and write it to the TUN device.

### Server Behavior
1. Load configuration and listen for TCP clients.
2. Handle `Register` by verifying that the provided public key derives to the advertised IPv6 address before storing it.
3. Respond to `KeyRequest` with a cached public key or an error if not found.
4. For `SendEncryptedData`, forward the packet to the destination if online or respond with `Error(DestinationUnavailable)`.

### TUN Device
- Clients create a TUN device with MTU 1500 and assign their derived IPv6 address using `ip -6 addr add {addr}/7 dev {name}`.

## Storage Paths
On Linux, public and secret Kyber keys are stored under `/var/lib/nuntium/` and the configuration file defaults to `/etc/nuntium/nuntium.conf`. On Windows, the keys and configuration file reside under `C:\\ProgramData\\nuntium\\`.

