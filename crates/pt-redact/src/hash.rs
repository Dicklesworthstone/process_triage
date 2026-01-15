//! Keyed cryptographic hashing for redaction.
//!
//! Uses HMAC-SHA256 with truncated output to provide stable, non-reversible
//! hashes that enable pattern matching across sessions.

use crate::error::{RedactionError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

/// Default number of bytes to keep from HMAC output (16 hex chars).
pub const DEFAULT_TRUNCATION_BYTES: usize = 8;

/// Key material for HMAC-SHA256.
#[derive(Clone)]
pub struct KeyMaterial {
    /// The raw key bytes (32 bytes for HMAC-SHA256).
    key: [u8; 32],
    /// Key identifier for output format.
    pub key_id: String,
}

impl KeyMaterial {
    /// Create new key material with a random key.
    pub fn generate(key_id: &str) -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| {
            RedactionError::KeyError(format!("failed to generate random key: {}", e))
        })?;
        Ok(Self {
            key,
            key_id: key_id.to_string(),
        })
    }

    /// Create key material from raw bytes.
    pub fn from_bytes(key: [u8; 32], key_id: &str) -> Self {
        Self {
            key,
            key_id: key_id.to_string(),
        }
    }

    /// Create key material from base64-encoded string.
    pub fn from_base64(encoded: &str, key_id: &str) -> Result<Self> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| RedactionError::KeyError(format!("invalid base64: {}", e)))?;

        if decoded.len() != 32 {
            return Err(RedactionError::KeyError(format!(
                "key must be 32 bytes, got {}",
                decoded.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(Self {
            key,
            key_id: key_id.to_string(),
        })
    }

    /// Export key material as base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.key)
    }

    /// Compute HMAC-SHA256 of the input and return truncated hex output.
    pub fn hash(&self, input: &str, truncation_bytes: usize) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(input.as_bytes());
        let result = mac.finalize().into_bytes();

        // Truncate to specified bytes (clamped to valid range)
        let trunc = truncation_bytes.min(32).max(4);
        let hex = hex::encode(&result[..trunc]);

        format!("[HASH:{}:{}]", self.key_id, hex)
    }
}

/// Key manager for loading and storing redaction keys.
#[derive(Serialize, Deserialize)]
pub struct KeyManager {
    /// Schema version for the key file.
    pub schema_version: String,
    /// Map of key IDs to key entries.
    pub keys: std::collections::HashMap<String, KeyEntry>,
    /// Currently active key ID.
    pub active_key_id: String,
}

/// Entry in the key file.
#[derive(Serialize, Deserialize)]
pub struct KeyEntry {
    /// When this key was created.
    pub created_at: String,
    /// Algorithm (always hmac-sha256).
    pub algorithm: String,
    /// Base64-encoded key material.
    pub key_material: String,
    /// Key status (active, deprecated, revoked).
    pub status: String,
}

impl KeyManager {
    /// Create a new key manager with a fresh key.
    pub fn new() -> Result<Self> {
        let key = KeyMaterial::generate("k1")?;
        let now = chrono::Utc::now().to_rfc3339();

        let mut keys = std::collections::HashMap::new();
        keys.insert(
            "k1".to_string(),
            KeyEntry {
                created_at: now,
                algorithm: "hmac-sha256".to_string(),
                key_material: key.to_base64(),
                status: "active".to_string(),
            },
        );

        Ok(Self {
            schema_version: "1.0.0".to_string(),
            keys,
            active_key_id: "k1".to_string(),
        })
    }

    /// Load key manager from a file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let manager: KeyManager = serde_json::from_str(&content)?;
        Ok(manager)
    }

    /// Save key manager to a file with restricted permissions.
    ///
    /// On Unix, creates file with 0600 permissions atomically to prevent
    /// race conditions where the file might be readable before permissions are set.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            // Create file with restricted permissions atomically
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, fall back to basic write
            std::fs::write(&path, &content)?;
        }

        Ok(())
    }

    /// Get the active key material.
    pub fn active_key(&self) -> Result<KeyMaterial> {
        let entry = self.keys.get(&self.active_key_id).ok_or_else(|| {
            RedactionError::KeyError(format!("active key '{}' not found", self.active_key_id))
        })?;

        KeyMaterial::from_base64(&entry.key_material, &self.active_key_id)
    }

    /// Rotate to a new key.
    pub fn rotate(&mut self) -> Result<()> {
        // Mark current key as deprecated
        if let Some(entry) = self.keys.get_mut(&self.active_key_id) {
            entry.status = "deprecated".to_string();
        }

        // Generate new key ID
        let new_id = format!("k{}", self.keys.len() + 1);
        let key = KeyMaterial::generate(&new_id)?;
        let now = chrono::Utc::now().to_rfc3339();

        self.keys.insert(
            new_id.clone(),
            KeyEntry {
                created_at: now,
                algorithm: "hmac-sha256".to_string(),
                key_material: key.to_base64(),
                status: "active".to_string(),
            },
        );
        self.active_key_id = new_id;

        Ok(())
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new().expect("failed to generate default key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = KeyMaterial::generate("test").unwrap();
        assert_eq!(key.key_id, "test");
    }

    #[test]
    fn test_hash_stability() {
        let key = KeyMaterial::from_bytes([0u8; 32], "test");
        let hash1 = key.hash("hello world", 8);
        let hash2 = key.hash("hello world", 8);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_format() {
        let key = KeyMaterial::from_bytes([0u8; 32], "k1");
        let hash = key.hash("test", 8);
        assert!(hash.starts_with("[HASH:k1:"));
        assert!(hash.ends_with("]"));
        // 8 bytes = 16 hex chars
        assert_eq!(hash.len(), "[HASH:k1:]".len() + 16);
    }

    #[test]
    fn test_different_keys_different_hashes() {
        let key1 = KeyMaterial::from_bytes([0u8; 32], "k1");
        let key2 = KeyMaterial::from_bytes([1u8; 32], "k2");
        let hash1 = key1.hash("test", 8);
        let hash2 = key2.hash("test", 8);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = KeyMaterial::generate("test").unwrap();
        let encoded = original.to_base64();
        let restored = KeyMaterial::from_base64(&encoded, "test").unwrap();
        assert_eq!(original.hash("test", 8), restored.hash("test", 8));
    }
}
