//! Error types for bundle operations.

use thiserror::Error;

/// Errors that can occur during bundle operations.
#[derive(Error, Debug)]
pub enum BundleError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// ZIP archive error
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Checksum verification failed
    #[error("checksum mismatch for '{path}': expected {expected}, got {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    /// Missing required file in bundle
    #[error("missing required file: {0}")]
    MissingFile(String),

    /// Unknown or unsupported bundle version
    #[error("unsupported bundle version: {version} (supported: {supported})")]
    UnsupportedVersion { version: String, supported: String },

    /// Schema version mismatch
    #[error("schema version mismatch for {component}: expected {expected}, got {actual}")]
    SchemaMismatch {
        component: String,
        expected: String,
        actual: String,
    },

    /// Corrupted manifest
    #[error("corrupted manifest: {0}")]
    CorruptedManifest(String),

    /// File not found in bundle
    #[error("file not found in bundle: {0}")]
    FileNotFound(String),

    /// Invalid export profile
    #[error("invalid export profile: {0}")]
    InvalidProfile(String),

    /// Bundle is empty
    #[error("bundle has no content to write")]
    EmptyBundle,

    /// Manifest integrity check failed
    #[error("manifest integrity check failed")]
    ManifestIntegrityFailed,

    /// Bundle is encrypted; passphrase required
    #[error("bundle is encrypted; passphrase required")]
    EncryptedBundleRequiresPassphrase,

    /// Passphrase required but missing or empty
    #[error("missing passphrase for bundle encryption/decryption")]
    MissingPassphrase,

    /// Encryption header is missing or invalid
    #[error("invalid bundle encryption header")]
    InvalidEncryptionHeader,

    /// Bundle is not encrypted
    #[error("bundle is not encrypted")]
    NotEncrypted,

    /// Encryption failed
    #[error("bundle encryption failed")]
    EncryptionFailed,

    /// Decryption failed (bad key or tampered data)
    #[error("bundle decryption failed")]
    DecryptionFailed,
}

/// Result type alias for bundle operations.
pub type Result<T> = std::result::Result<T, BundleError>;
