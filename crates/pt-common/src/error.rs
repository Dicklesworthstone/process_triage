//! Error types for Process Triage.

use thiserror::Error;

/// Result type alias for Process Triage operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Unified error type for Process Triage.
#[derive(Error, Debug)]
pub enum Error {
    // Configuration errors (10-19)
    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid priors file: {0}")]
    InvalidPriors(String),

    #[error("invalid policy file: {0}")]
    InvalidPolicy(String),

    #[error("schema validation failed: {0}")]
    SchemaValidation(String),

    // Collection errors (20-29)
    #[error("process collection failed: {0}")]
    Collection(String),

    #[error("process {pid} not found")]
    ProcessNotFound { pid: u32 },

    #[error("process identity mismatch: expected start_id={expected}, got {actual}")]
    IdentityMismatch { expected: String, actual: String },

    #[error("permission denied accessing process {pid}")]
    PermissionDenied { pid: u32 },

    // Inference errors (30-39)
    #[error("inference failed: {0}")]
    Inference(String),

    #[error("numerical instability detected: {0}")]
    NumericalInstability(String),

    // Action errors (40-49)
    #[error("action execution failed: {0}")]
    ActionFailed(String),

    #[error("action blocked by policy: {0}")]
    PolicyBlocked(String),

    #[error("action timeout after {seconds}s")]
    ActionTimeout { seconds: u64 },

    // Session errors (50-59)
    #[error("session not found: {session_id}")]
    SessionNotFound { session_id: String },

    #[error("session expired: {session_id}")]
    SessionExpired { session_id: String },

    #[error("session corrupted: {0}")]
    SessionCorrupted(String),

    // I/O errors (60-69)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    // Platform errors (70-79)
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("capability not available: {0}")]
    CapabilityMissing(String),
}

impl Error {
    /// Returns the error code for this error type.
    /// Used for detailed error reporting in JSON output.
    pub fn code(&self) -> u32 {
        match self {
            Error::Config(_) => 10,
            Error::InvalidPriors(_) => 11,
            Error::InvalidPolicy(_) => 12,
            Error::SchemaValidation(_) => 13,
            Error::Collection(_) => 20,
            Error::ProcessNotFound { .. } => 21,
            Error::IdentityMismatch { .. } => 22,
            Error::PermissionDenied { .. } => 23,
            Error::Inference(_) => 30,
            Error::NumericalInstability(_) => 31,
            Error::ActionFailed(_) => 40,
            Error::PolicyBlocked(_) => 41,
            Error::ActionTimeout { .. } => 42,
            Error::SessionNotFound { .. } => 50,
            Error::SessionExpired { .. } => 51,
            Error::SessionCorrupted(_) => 52,
            Error::Io(_) => 60,
            Error::Json(_) => 61,
            Error::UnsupportedPlatform(_) => 70,
            Error::CapabilityMissing(_) => 71,
        }
    }
}
