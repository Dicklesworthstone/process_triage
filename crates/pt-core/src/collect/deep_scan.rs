//! Deep scan implementation via /proc filesystem (Linux-only).
//!
//! This module provides detailed process inspection using the /proc filesystem,
//! which is only available on Linux systems.
//!
//! TODO: Full implementation pending.

use thiserror::Error;

/// Options for deep scan operation.
#[derive(Debug, Clone, Default)]
pub struct DeepScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,
}

/// Errors that can occur during deep scan.
#[derive(Debug, Error)]
pub enum DeepScanError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Not implemented")]
    NotImplemented,
}

/// Extended process record from deep scan.
#[derive(Debug, Clone)]
pub struct DeepScanRecord {
    /// Process ID.
    pub pid: u32,
    // TODO: Add more fields when implementing
}

/// Perform a deep scan of running processes.
///
/// TODO: Full implementation pending.
pub fn deep_scan(_options: &DeepScanOptions) -> Result<Vec<DeepScanRecord>, DeepScanError> {
    Err(DeepScanError::NotImplemented)
}
