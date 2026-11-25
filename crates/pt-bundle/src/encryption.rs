//! Bundle encryption helpers (optional).
//!
//! Bundles can be encrypted at rest with a passphrase-derived key.
//! This is an outer envelope over the ZIP payload.

use crate::{BundleError, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const MAGIC: &[u8; 8] = b"PTBENC01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const KDF_ITERS: u32 = 100_000;
/// Maximum iterations accepted during decryption to prevent DoS via crafted bundles.
const MAX_KDF_ITERS: u32 = 10_000_000;
const HEADER_LEN: usize = 8 + 4 + SALT_LEN + NONCE_LEN;

fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

fn parse_header(bytes: &[u8]) -> Result<(u32, [u8; SALT_LEN], [u8; NONCE_LEN])> {
    if bytes.len() < HEADER_LEN {
        return Err(BundleError::InvalidEncryptionHeader);
    }

    if !is_encrypted(bytes) {
        return Err(BundleError::NotEncrypted);
    }

    let mut offset = MAGIC.len();
    let mut iter_bytes = [0u8; 4];
    iter_bytes.copy_from_slice(&bytes[offset..offset + 4]);
    let iterations = u32::from_be_bytes(iter_bytes);
    offset += 4;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[offset..offset + SALT_LEN]);
    offset += SALT_LEN;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[offset..offset + NONCE_LEN]);

    if iterations == 0 || iterations > MAX_KDF_ITERS {
        return Err(BundleError::InvalidEncryptionHeader);
    }

    Ok((iterations, salt, nonce))
}

/// Return true if the buffer appears to be an encrypted bundle.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

/// Return true if the prefix contains the encrypted magic header.
pub fn is_encrypted_prefix(prefix: &[u8]) -> bool {
    prefix.len() == MAGIC.len() && prefix == MAGIC
}

/// Encrypt bundle bytes using a passphrase-derived key.
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(BundleError::MissingPassphrase);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| BundleError::EncryptionFailed)?;
    getrandom::fill(&mut nonce).map_err(|_| BundleError::EncryptionFailed)?;

    let key = derive_key(passphrase, &salt, KDF_ITERS);
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| BundleError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&KDF_ITERS.to_be_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt bundle bytes using a passphrase-derived key.
pub fn decrypt_bytes(bytes: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(BundleError::MissingPassphrase);
    }

    let (iterations, salt, nonce) = parse_header(bytes)?;
    let ciphertext = &bytes[HEADER_LEN..];
    if ciphertext.is_empty() {
        return Err(BundleError::InvalidEncryptionHeader);
    }

    let key = derive_key(passphrase, &salt, iterations);
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|_| BundleError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"pt-bundle roundtrip";
        let encrypted = encrypt_bytes(plaintext, "secret").unwrap();
        assert!(is_encrypted(&encrypted));

        let decrypted = decrypt_bytes(&encrypted, "secret").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_fails() {
        let plaintext = b"pt-bundle wrong key";
        let encrypted = encrypt_bytes(plaintext, "secret").unwrap();

        let result = decrypt_bytes(&encrypted, "bad");
        assert!(matches!(result, Err(BundleError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypts_independently_produced_envelope() {
        // Bundles written by earlier releases must keep decrypting. This
        // envelope was built outside pt (Python hashlib PBKDF2-HMAC-SHA256 and
        // the `cryptography` ChaCha20-Poly1305) with the documented layout:
        // magic, iterations (u32 BE, 1000 here), salt 00..0f, nonce 64..6f,
        // ciphertext with tag.
        let envelope = hex::decode(
            "505442454e433031000003e8000102030405060708090a0b0c0d0e0f\
             6465666768696a6b6c6d6e6fe29aea9d9ddc80517e3f7b72e6d07e7e\
             92478b69371352c832434edc1d2d2f8d731e8c39b4687be94370df0c39fa",
        )
        .unwrap();
        let decrypted = decrypt_bytes(&envelope, "correct horse battery staple").unwrap();
        assert_eq!(decrypted, b"pt-bundle known-answer payload");
        assert!(matches!(
            decrypt_bytes(&envelope, "wrong passphrase"),
            Err(BundleError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_parse_header_rejects_short_input() {
        let result = decrypt_bytes(b"short", "secret");
        assert!(matches!(result, Err(BundleError::InvalidEncryptionHeader)));
    }
}
