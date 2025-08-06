use aes_gcm::aead::{AeadInPlace, Error, KeyInit, OsRng}; // Runtime traits and helpers
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // Cipher implementation and helper types
use cpufeatures::new; // For runtime CPU feature detection

// Detect availability of AES instructions at runtime. The `aes-gcm` crate will
// transparently use hardware acceleration when this feature is present.
new!(aes_intrinsics, "aes");

/// Encrypt a packet using AES-256-GCM.
///
/// A random nonce is generated for every packet and prepended to the
/// resulting ciphertext. The provided `key` must be at least 32 bytes.
pub fn encrypt_packet(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() < 32 {
        return Err(Error);
    }

    // Construct cipher once per call. The `aes-gcm` crate internally uses
    // `cpufeatures` to take advantage of AES-NI or similar SIMD extensions at
    // runtime, so simply constructing the cipher here will leverage hardware
    // acceleration when available. We assert here so that in debug builds we
    // notice when the binary is running without AES acceleration.
    debug_assert!(aes_intrinsics::get(), "CPU lacks AES acceleration");
    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt in place into a temporary buffer and then prepend the nonce. This
    // avoids an extra allocation for the ciphertext compared to the previous
    // approach and keeps the output layout identical (nonce || ciphertext).
    let mut buf = plaintext.to_vec();
    cipher.encrypt_in_place(&nonce, b"", &mut buf)?;
    let mut result = Vec::with_capacity(nonce.len() + buf.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&buf);
    Ok(result)
}

/// Decrypt a packet using AES-256-GCM.
///
/// Expects the nonce to be prepended to the ciphertext. The provided
/// `key` must be at least 32 bytes long.
pub fn decrypt_packet(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() < 32 {
        return Err(Error);
    }
    if ciphertext.len() < 12 {
        return Err(Error);
    }

    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(key);

    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt in-place to avoid an additional allocation.
    let mut buffer = ct.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut buffer)?;
    Ok(buffer)
}
