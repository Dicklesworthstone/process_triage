//! ECDSA P-256 signature verification for release binaries.
//!
//! Verifies detached `.sig` signatures (DER-encoded) using NIST P-256 / ECDSA.
//! Supports multiple public keys for key rotation.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::path::Path;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from signature operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("no public keys configured")]
    NoKeys,
    #[error("invalid public key: {0}")]
    InvalidKey(String),
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),
    #[error("signature verification failed (tried {tried} key(s))")]
    VerificationFailed { tried: usize },
    #[error("signature file not found: {0}")]
    SignatureFileNotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Key format helpers
// ---------------------------------------------------------------------------

/// Parse a verifying key from SEC1-encoded bytes (uncompressed or compressed).
pub fn parse_sec1_key(bytes: &[u8]) -> Result<VerifyingKey, SignatureError> {
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| SignatureError::InvalidKey(format!("SEC1 decode: {e}")))
}

/// Parse a verifying key from base64-encoded SEC1 bytes.
pub fn parse_base64_key(b64: &str) -> Result<VerifyingKey, SignatureError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| SignatureError::InvalidKey(format!("base64 decode: {e}")))?;
    parse_sec1_key(&bytes)
}

/// Parse a verifying key from a PEM-encoded SPKI block.
///
/// Accepts the standard `-----BEGIN PUBLIC KEY-----` PEM wrapper around
/// a DER-encoded SubjectPublicKeyInfo.
pub fn parse_pem_key(pem: &str) -> Result<VerifyingKey, SignatureError> {
    let trimmed = pem.trim();

    // Strip PEM header/footer and decode base64 payload
    let b64_payload: String = trimmed
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let der_bytes = BASE64
        .decode(&b64_payload)
        .map_err(|e| SignatureError::InvalidKey(format!("PEM base64 decode: {e}")))?;

    // SPKI for P-256: 26-byte header + 65-byte uncompressed point (or 33 compressed)
    // The last 65 (or 33) bytes are the SEC1 encoded point.
    // For P-256 uncompressed SPKI, total is 91 bytes. Header is 26.
    // For compressed SPKI, total is 59 bytes. Header is 26.
    const SPKI_HEADER_LEN: usize = 26;

    if der_bytes.len() > SPKI_HEADER_LEN {
        let point_bytes = &der_bytes[SPKI_HEADER_LEN..];
        if let Ok(key) = VerifyingKey::from_sec1_bytes(point_bytes) {
            return Ok(key);
        }
    }

    // Fallback: try parsing raw bytes as SEC1 (in case it's not really SPKI)
    parse_sec1_key(&der_bytes)
}

/// Compute the SHA-256 fingerprint of a verifying key (hex-encoded).
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let sec1 = key.to_sec1_bytes();
    let hash = Sha256::digest(&sec1);
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Signature parsing
// ---------------------------------------------------------------------------

/// Parse a DER-encoded signature from raw bytes.
pub fn parse_der_signature(bytes: &[u8]) -> Result<Signature, SignatureError> {
    Signature::from_der(bytes)
        .map_err(|e| SignatureError::InvalidSignature(format!("DER decode: {e}")))
}

/// Parse a base64-encoded DER signature (as stored in `.sig` files).
pub fn parse_base64_signature(b64: &str) -> Result<Signature, SignatureError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| SignatureError::InvalidSignature(format!("base64 decode: {e}")))?;
    parse_der_signature(&bytes)
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// ECDSA signature verifier with multiple-key support for key rotation.
#[derive(Debug, Clone)]
pub struct SignatureVerifier {
    /// Trusted public keys (newest first). Verification tries each in order.
    keys: Vec<VerifyingKey>,
}

impl SignatureVerifier {
    /// Create a verifier with no keys. Keys must be added via [`add_key`].
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Create a verifier from a single base64-encoded SEC1 public key.
    pub fn from_base64(b64: &str) -> Result<Self, SignatureError> {
        let key = parse_base64_key(b64)?;
        Ok(Self { keys: vec![key] })
    }

    /// Create a verifier from a PEM public key.
    pub fn from_pem(pem: &str) -> Result<Self, SignatureError> {
        let key = parse_pem_key(pem)?;
        Ok(Self { keys: vec![key] })
    }

    /// Add a trusted public key (tried during verification in FIFO order).
    pub fn add_key(&mut self, key: VerifyingKey) {
        self.keys.push(key);
    }

    /// Add a base64-encoded SEC1 public key.
    pub fn add_base64_key(&mut self, b64: &str) -> Result<(), SignatureError> {
        let key = parse_base64_key(b64)?;
        self.keys.push(key);
        Ok(())
    }

    /// Number of trusted keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Fingerprints of all trusted keys.
    pub fn fingerprints(&self) -> Vec<String> {
        self.keys.iter().map(key_fingerprint).collect()
    }

    /// Verify `data` against a `signature`.
    ///
    /// Tries each trusted key in order and returns `Ok(fingerprint)` for the
    /// first key that validates, or [`SignatureError::VerificationFailed`] if
    /// none match.
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<String, SignatureError> {
        if self.keys.is_empty() {
            return Err(SignatureError::NoKeys);
        }

        for key in &self.keys {
            if key.verify(data, signature).is_ok() {
                return Ok(key_fingerprint(key));
            }
        }

        Err(SignatureError::VerificationFailed {
            tried: self.keys.len(),
        })
    }

    /// Verify `data` against a DER-encoded signature.
    pub fn verify_der(&self, data: &[u8], sig_der: &[u8]) -> Result<String, SignatureError> {
        let sig = parse_der_signature(sig_der)?;
        self.verify(data, &sig)
    }

    /// Verify `data` against a base64-encoded DER signature.
    pub fn verify_base64(
        &self,
        data: &[u8],
        sig_base64: &str,
    ) -> Result<String, SignatureError> {
        let sig = parse_base64_signature(sig_base64)?;
        self.verify(data, &sig)
    }

    /// Verify a file against its detached `.sig` sidecar.
    ///
    /// Reads `file_path` into memory and reads `file_path.sig` as a raw
    /// DER-encoded signature.
    pub fn verify_file(&self, file_path: &Path) -> Result<VerifyResult, SignatureError> {
        let sig_path = signature_path_for(file_path);

        if !sig_path.exists() {
            return Err(SignatureError::SignatureFileNotFound(
                sig_path.display().to_string(),
            ));
        }

        let data = std::fs::read(file_path)?;
        let sig_bytes = std::fs::read(&sig_path)?;
        let fingerprint = self.verify_der(&data, &sig_bytes)?;

        Ok(VerifyResult {
            file: file_path.display().to_string(),
            key_fingerprint: fingerprint,
            sig_path: sig_path.display().to_string(),
        })
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Successful verification result.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Path of the verified file.
    pub file: String,
    /// SHA-256 fingerprint of the key that validated.
    pub key_fingerprint: String,
    /// Path of the `.sig` file used.
    pub sig_path: String,
}

/// Return the conventional `.sig` sidecar path for a binary.
pub fn signature_path_for(binary_path: &Path) -> std::path::PathBuf {
    let mut sig = binary_path.as_os_str().to_owned();
    sig.push(".sig");
    std::path::PathBuf::from(sig)
}

// ---------------------------------------------------------------------------
// Signing (for tests and CI tooling)
// ---------------------------------------------------------------------------

/// Sign `data` with a secret key and return the DER-encoded signature.
///
/// This is exposed for test helpers and the release signing script.
/// It is NOT used in the normal verification path.
pub fn sign_bytes(data: &[u8], signing_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let sig: Signature = signing_key.sign(data);
    sig.to_der().as_bytes().to_vec()
}

/// Generate a new random ECDSA P-256 key pair.
///
/// Returns `(signing_key_sec1_bytes, verifying_key_sec1_bytes)`.
/// Useful for test fixtures and initial key generation.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    (sk.to_bytes().to_vec(), vk.to_sec1_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use tempfile::TempDir;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    // -- Key parsing -------------------------------------------------------

    #[test]
    fn test_parse_sec1_key_roundtrip() {
        let (_sk, vk) = test_keypair();
        let bytes = vk.to_sec1_bytes();
        let parsed = parse_sec1_key(&bytes).unwrap();
        assert_eq!(parsed, vk);
    }

    #[test]
    fn test_parse_base64_key_roundtrip() {
        let (_sk, vk) = test_keypair();
        let b64 = BASE64.encode(vk.to_sec1_bytes());
        let parsed = parse_base64_key(&b64).unwrap();
        assert_eq!(parsed, vk);
    }

    #[test]
    fn test_parse_base64_key_with_whitespace() {
        let (_sk, vk) = test_keypair();
        let b64 = format!("  {}  \n", BASE64.encode(vk.to_sec1_bytes()));
        let parsed = parse_base64_key(&b64).unwrap();
        assert_eq!(parsed, vk);
    }

    #[test]
    fn test_parse_invalid_base64_key() {
        assert!(parse_base64_key("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_parse_wrong_length_key() {
        let b64 = BASE64.encode([0u8; 10]);
        assert!(parse_base64_key(&b64).is_err());
    }

    #[test]
    fn test_key_fingerprint_deterministic() {
        let (_sk, vk) = test_keypair();
        let fp1 = key_fingerprint(&vk);
        let fp2 = key_fingerprint(&vk);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_key_fingerprint_different_keys() {
        let (_, vk1) = test_keypair();
        let (_, vk2) = test_keypair();
        assert_ne!(key_fingerprint(&vk1), key_fingerprint(&vk2));
    }

    // -- Signature parsing -------------------------------------------------

    #[test]
    fn test_parse_der_signature_roundtrip() {
        let (sk, _vk) = test_keypair();
        let sig_der = sign_bytes(b"test", &sk);
        let sig = parse_der_signature(&sig_der).unwrap();
        // Verify the round-tripped signature still works
        let sig_der2 = sig.to_der();
        assert!(!sig_der2.as_bytes().is_empty());
    }

    #[test]
    fn test_parse_base64_signature_roundtrip() {
        let (sk, _vk) = test_keypair();
        let sig_der = sign_bytes(b"data", &sk);
        let b64 = BASE64.encode(&sig_der);
        let sig = parse_base64_signature(&b64).unwrap();
        assert!(!sig.to_der().as_bytes().is_empty());
    }

    #[test]
    fn test_parse_invalid_der_signature() {
        assert!(parse_der_signature(&[0xff; 10]).is_err());
    }

    #[test]
    fn test_parse_empty_signature() {
        assert!(parse_der_signature(&[]).is_err());
    }

    // -- Verifier ----------------------------------------------------------

    #[test]
    fn test_verify_valid_signature() {
        let (sk, vk) = test_keypair();
        let data = b"release binary contents";
        let sig_der = sign_bytes(data, &sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify(data, &sig);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key_fingerprint(&vk));
    }

    #[test]
    fn test_verify_wrong_data_fails() {
        let (sk, vk) = test_keypair();
        let sig_der = sign_bytes(b"original", &sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify(b"tampered", &sig);
        assert!(matches!(
            result,
            Err(SignatureError::VerificationFailed { tried: 1 })
        ));
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (sk, _vk) = test_keypair();
        let (_, wrong_vk) = test_keypair();
        let data = b"data";
        let sig_der = sign_bytes(data, &sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(wrong_vk);

        let result = verifier.verify(data, &sig);
        assert!(matches!(
            result,
            Err(SignatureError::VerificationFailed { tried: 1 })
        ));
    }

    #[test]
    fn test_verify_no_keys_error() {
        let verifier = SignatureVerifier::new();
        let (sk, _) = test_keypair();
        let sig_der = sign_bytes(b"data", &sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let result = verifier.verify(b"data", &sig);
        assert!(matches!(result, Err(SignatureError::NoKeys)));
    }

    #[test]
    fn test_verify_der_convenience() {
        let (sk, vk) = test_keypair();
        let data = b"binary data";
        let sig_der = sign_bytes(data, &sk);

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        assert!(verifier.verify_der(data, &sig_der).is_ok());
    }

    #[test]
    fn test_verify_base64_convenience() {
        let (sk, vk) = test_keypair();
        let data = b"binary data";
        let sig_der = sign_bytes(data, &sk);
        let sig_b64 = BASE64.encode(&sig_der);

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        assert!(verifier.verify_base64(data, &sig_b64).is_ok());
    }

    // -- Key rotation (multiple keys) --------------------------------------

    #[test]
    fn test_key_rotation_old_key_still_works() {
        let (old_sk, old_vk) = test_keypair();
        let (_new_sk, new_vk) = test_keypair();

        let data = b"signed with old key";
        let sig_der = sign_bytes(data, &old_sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        // Verifier has new key first, old key second
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(new_vk);
        verifier.add_key(old_vk);

        let result = verifier.verify(data, &sig).unwrap();
        assert_eq!(result, key_fingerprint(&old_vk));
    }

    #[test]
    fn test_key_rotation_new_key_tried_first() {
        let (_old_sk, old_vk) = test_keypair();
        let (new_sk, new_vk) = test_keypair();

        let data = b"signed with new key";
        let sig_der = sign_bytes(data, &new_sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(new_vk);
        verifier.add_key(old_vk);

        let result = verifier.verify(data, &sig).unwrap();
        assert_eq!(result, key_fingerprint(&new_vk));
        assert_eq!(verifier.key_count(), 2);
    }

    #[test]
    fn test_key_rotation_both_wrong_fails() {
        let (signing_sk, _) = test_keypair();
        let (_, wrong_vk1) = test_keypair();
        let (_, wrong_vk2) = test_keypair();

        let data = b"data";
        let sig_der = sign_bytes(data, &signing_sk);
        let sig = parse_der_signature(&sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(wrong_vk1);
        verifier.add_key(wrong_vk2);

        let result = verifier.verify(data, &sig);
        assert!(matches!(
            result,
            Err(SignatureError::VerificationFailed { tried: 2 })
        ));
    }

    // -- File verification -------------------------------------------------

    #[test]
    fn test_verify_file_valid() {
        let (sk, vk) = test_keypair();
        let dir = TempDir::new().unwrap();

        let binary_path = dir.path().join("pt-core");
        let sig_path = dir.path().join("pt-core.sig");

        let contents = b"fake binary contents for test";
        std::fs::write(&binary_path, contents).unwrap();

        let sig_der = sign_bytes(contents, &sk);
        std::fs::write(&sig_path, &sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify_file(&binary_path).unwrap();
        assert_eq!(result.key_fingerprint, key_fingerprint(&vk));
        assert!(result.sig_path.ends_with("pt-core.sig"));
    }

    #[test]
    fn test_verify_file_tampered() {
        let (sk, vk) = test_keypair();
        let dir = TempDir::new().unwrap();

        let binary_path = dir.path().join("pt-core");
        let sig_path = dir.path().join("pt-core.sig");

        let original = b"original binary";
        std::fs::write(&binary_path, b"TAMPERED binary").unwrap();

        let sig_der = sign_bytes(original, &sk);
        std::fs::write(&sig_path, &sig_der).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify_file(&binary_path);
        assert!(matches!(
            result,
            Err(SignatureError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_file_missing_signature() {
        let (_, vk) = test_keypair();
        let dir = TempDir::new().unwrap();

        let binary_path = dir.path().join("pt-core");
        std::fs::write(&binary_path, b"contents").unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify_file(&binary_path);
        assert!(matches!(result, Err(SignatureError::SignatureFileNotFound(_))));
    }

    #[test]
    fn test_verify_file_corrupted_signature() {
        let (_, vk) = test_keypair();
        let dir = TempDir::new().unwrap();

        let binary_path = dir.path().join("pt-core");
        let sig_path = dir.path().join("pt-core.sig");

        std::fs::write(&binary_path, b"contents").unwrap();
        std::fs::write(&sig_path, b"not a valid DER signature").unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let result = verifier.verify_file(&binary_path);
        assert!(matches!(result, Err(SignatureError::InvalidSignature(_))));
    }

    // -- Constructor helpers -----------------------------------------------

    #[test]
    fn test_from_base64_constructor() {
        let (_, vk) = test_keypair();
        let b64 = BASE64.encode(vk.to_sec1_bytes());
        let verifier = SignatureVerifier::from_base64(&b64).unwrap();
        assert_eq!(verifier.key_count(), 1);
    }

    #[test]
    fn test_add_base64_key() {
        let (_, vk1) = test_keypair();
        let (_, vk2) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_base64_key(&BASE64.encode(vk1.to_sec1_bytes())).unwrap();
        verifier.add_base64_key(&BASE64.encode(vk2.to_sec1_bytes())).unwrap();
        assert_eq!(verifier.key_count(), 2);
    }

    #[test]
    fn test_fingerprints() {
        let (_, vk1) = test_keypair();
        let (_, vk2) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk1);
        verifier.add_key(vk2);
        let fps = verifier.fingerprints();
        assert_eq!(fps.len(), 2);
        assert_ne!(fps[0], fps[1]);
    }

    // -- generate_keypair --------------------------------------------------

    #[test]
    fn test_generate_keypair() {
        let (sk_bytes, vk_bytes) = generate_keypair();
        assert_eq!(sk_bytes.len(), 32); // P-256 scalar = 32 bytes
        assert_eq!(vk_bytes.len(), 65); // Uncompressed SEC1 point = 65 bytes
        assert_eq!(vk_bytes[0], 0x04); // Uncompressed point prefix

        // Verify the pair is consistent
        let sk = SigningKey::from_bytes(sk_bytes.as_slice().into()).unwrap();
        let vk = parse_sec1_key(&vk_bytes).unwrap();
        let data = b"roundtrip test";
        let sig_der = sign_bytes(data, &sk);
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);
        assert!(verifier.verify_der(data, &sig_der).is_ok());
    }

    // -- signature_path_for ------------------------------------------------

    #[test]
    fn test_signature_path_for() {
        let path = Path::new("/usr/local/bin/pt-core");
        let sig = signature_path_for(path);
        assert_eq!(sig.to_str().unwrap(), "/usr/local/bin/pt-core.sig");
    }

    // -- PEM key parsing ---------------------------------------------------

    #[test]
    fn test_parse_pem_key_roundtrip() {
        let (_, vk) = test_keypair();
        // Build a minimal PEM block from the SEC1 bytes wrapped in SPKI DER
        let pem = build_test_pem(&vk);
        let parsed = parse_pem_key(&pem).unwrap();
        assert_eq!(parsed, vk);
    }

    /// Build a PEM public key block for testing.
    /// Constructs the SPKI DER wrapper around the SEC1 encoded point.
    fn build_test_pem(vk: &VerifyingKey) -> String {
        // SPKI header for P-256 uncompressed point (AlgorithmIdentifier + BIT STRING wrapper)
        let sec1 = vk.to_sec1_bytes();
        let mut spki = Vec::new();

        // SEQUENCE (outer)
        spki.push(0x30);
        // Total length = algorithm_id(19) + BIT STRING header(4) + point(65) = 88 for uncompressed
        let inner_len = 19 + 2 + 1 + sec1.len(); // algid + tag+len + unused_bits + point
        push_der_length(&mut spki, inner_len);

        // AlgorithmIdentifier SEQUENCE
        spki.push(0x30);
        spki.push(0x13); // length 19
        // OID 1.2.840.10045.2.1 (ecPublicKey)
        spki.extend_from_slice(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
        spki.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

        // BIT STRING containing the SEC1 point
        spki.push(0x03);
        push_der_length(&mut spki, 1 + sec1.len()); // +1 for unused bits byte
        spki.push(0x00); // unused bits = 0
        spki.extend_from_slice(&sec1);

        let b64 = BASE64.encode(&spki);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            b64
        )
    }

    fn push_der_length(buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    // -- Edge cases --------------------------------------------------------

    #[test]
    fn test_verify_empty_data() {
        let (sk, vk) = test_keypair();
        let data: &[u8] = b"";
        let sig_der = sign_bytes(data, &sk);

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);
        assert!(verifier.verify_der(data, &sig_der).is_ok());
    }

    #[test]
    fn test_verify_large_data() {
        let (sk, vk) = test_keypair();
        let data = vec![0xAB_u8; 10_000_000]; // 10 MB
        let sig_der = sign_bytes(&data, &sk);

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);
        assert!(verifier.verify_der(&data, &sig_der).is_ok());
    }

    #[test]
    fn test_default_verifier_is_empty() {
        let verifier = SignatureVerifier::default();
        assert_eq!(verifier.key_count(), 0);
    }
}
