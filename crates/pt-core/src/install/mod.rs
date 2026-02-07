//! Installation, update, and rollback management.
//!
//! This module provides functionality for:
//! - Creating backups before updates
//! - Atomic binary replacement
//! - Post-update verification
//! - Automatic rollback on failure
//! - Manual rollback commands

mod backup;
mod rollback;
mod verification;

pub use backup::{Backup, BackupManager, BackupMetadata};
pub use rollback::{RollbackManager, RollbackResult, UpdateResult};
pub use verification::{verify_binary, VerificationResult};

use std::path::PathBuf;

/// Default number of backup versions to retain
pub const DEFAULT_BACKUP_RETENTION: usize = 3;

/// Default verification timeout in seconds
pub const DEFAULT_VERIFICATION_TIMEOUT_SECS: u64 = 5;

/// Get the default rollback directory path
pub fn default_rollback_dir() -> PathBuf {
    
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("process_triage")
        .join("rollback")
}
