# Contributor Guidelines

## Style conventions

- The project uses **Rust edition 2021**. Keep all code compatible with this edition.
- Format Rust sources with `rustfmt` using `cargo fmt` before committing.

## Testing

- Run `cargo test` to execute unit tests.
- Run `cargo clippy` and ensure there are no warnings.

## Protocol Maintenance

- IPv6 address derivation logic lives in `src/ipv6.rs`. Changes must remain consistent with the description in [README.md#ipv6-address-derivation](README.md#ipv6-address-derivation).
- Encryption routines are in `src/crypto.rs`. Follow the practices outlined in [README.md#transport-encryption](README.md#transport-encryption). Maintain AES-256-GCM and unique nonces.
