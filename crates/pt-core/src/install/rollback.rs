//! Rollback management for self-updates.
//!
//! Provides atomic update with automatic rollback on failure.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

use super::backup::{Backup, BackupManager};
use super::verification::{verify_binary, VerificationResult};

/// Result of a rollback operation
#[derive(Debug)]
pub struct RollbackResult {
    /// Whether the rollback succeeded
    pub success: bool,
    /// The version rolled back to (if successful)
    pub restored_version: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Path of the restored binary
    pub restored_path: Option<PathBuf>,
}

impl RollbackResult {
    fn success(version: String, path: PathBuf) -> Self {
        Self {
            success: true,
            restored_version: Some(version),
            error: None,
            restored_path: Some(path),
        }
    }

    fn failure(error: String) -> Self {
        Self {
            success: false,
            restored_version: None,
            error: Some(error),
            restored_path: None,
        }
    }
}

/// Manages rollback operations for binary updates
pub struct RollbackManager {
    backup_manager: BackupManager,
    target_path: PathBuf,
}

impl RollbackManager {
    /// Create a new rollback manager for the given target binary
    pub fn new(target_path: PathBuf, binary_name: &str) -> Self {
        Self {
            backup_manager: BackupManager::new(binary_name),
            target_path,
        }
    }

    /// Create with custom backup directory
    pub fn with_backup_dir(target_path: PathBuf, binary_name: &str, backup_dir: PathBuf) -> Self {
        Self {
            backup_manager: BackupManager::with_config(backup_dir, binary_name, 3),
            target_path,
        }
    }

    /// Get the backup manager
    pub fn backup_manager(&self) -> &BackupManager {
        &self.backup_manager
    }

    /// Get the target path
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// Create a backup of the current binary before updating
    pub fn backup_current(&self, current_version: &str) -> io::Result<Backup> {
        info!(
            target: "update.backup_start",
            current_version = %current_version,
            backup_path = ?self.backup_manager.backup_dir(),
            "Creating backup before update"
        );

        if !self.target_path.exists() {
            error!(
                target: "update.backup_start",
                path = ?self.target_path,
                "Target binary does not exist"
            );
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Target binary does not exist: {:?}", self.target_path),
            ));
        }

        let backup = self
            .backup_manager
            .create_backup(&self.target_path, current_version)?;

        info!(
            target: "update.backup_complete",
            version = %backup.metadata.version,
            backup_path = ?backup.binary_path,
            size_bytes = backup.metadata.size_bytes,
            "Backup created successfully"
        );

        Ok(backup)
    }

    /// Perform atomic update with verification and automatic rollback
    ///
    /// Steps:
    /// 1. Create backup of current binary
    /// 2. Download/copy new binary to temp location
    /// 3. Atomically replace current with new
    /// 4. Verify new binary works
    /// 5. If verification fails, automatically rollback
    pub fn atomic_update(
        &self,
        new_binary_path: &Path,
        current_version: &str,
        expected_new_version: Option<&str>,
    ) -> io::Result<UpdateResult> {
        info!(
            target: "update.verify_start",
            current_version = %current_version,
            expected_version = ?expected_new_version,
            new_binary = ?new_binary_path,
            "Starting atomic update"
        );

        // Step 1: Create backup
        let backup = self.backup_current(current_version)?;

        // Step 2: Atomic replacement
        debug!(
            target: "update.verify_start",
            "Performing atomic binary replacement"
        );

        if let Err(e) = self.atomic_replace(new_binary_path) {
            error!(
                target: "update.verify_fail",
                reason = %e,
                "Atomic replacement failed"
            );
            // Restore backup on replace failure
            let _ = self.restore_backup(&backup);
            return Err(e);
        }

        // Step 3: Verify new binary
        info!(
            target: "update.verify_start",
            checks = "version,health",
            "Verifying new binary"
        );

        let verification = verify_binary(&self.target_path, expected_new_version)?;

        if !verification.passed {
            // Step 4: Automatic rollback on verification failure
            warn!(
                target: "update.verify_fail",
                reason = ?verification.error,
                expected = ?expected_new_version,
                actual = ?verification.version,
                "Verification failed, initiating rollback"
            );

            let rollback = self.restore_backup(&backup)?;
            return Ok(UpdateResult::VerificationFailed {
                verification,
                rollback,
                backup,
            });
        }

        info!(
            target: "update.verify_pass",
            version = ?verification.version,
            "Update verified successfully"
        );

        Ok(UpdateResult::Success {
            verification,
            backup,
        })
    }

    /// Atomically replace the target binary with a new one
    fn atomic_replace(&self, new_binary_path: &Path) -> io::Result<()> {
        let target_dir = self.target_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target path has no parent directory",
            )
        })?;

        // Copy to temp file in same directory (for atomic rename)
        let temp_path = target_dir.join(format!(
            ".{}.new.{}",
            self.target_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            std::process::id()
        ));

        // Copy new binary to temp location
        fs::copy(new_binary_path, &temp_path)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&temp_path, perms)?;
        }

        // Atomic rename
        let result = fs::rename(&temp_path, &self.target_path);

        // Clean up temp file if rename failed
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }

        result
    }

    /// Restore a backup to the target path
    pub fn restore_backup(&self, backup: &Backup) -> io::Result<RollbackResult> {
        info!(
            target: "update.rollback_start",
            reason = "restore_backup",
            target_version = %backup.metadata.version,
            "Initiating rollback to restore backup"
        );

        // Verify backup integrity first
        debug!(
            target: "update.rollback_start",
            "Verifying backup integrity"
        );

        if !self.backup_manager.verify_backup(backup)? {
            error!(
                target: "update.rollback_start",
                expected_checksum = %backup.metadata.checksum,
                "Backup verification failed - checksum mismatch"
            );
            return Ok(RollbackResult::failure(
                "Backup verification failed - checksum mismatch".to_string(),
            ));
        }

        // Atomic restore
        if let Err(e) = self.atomic_replace(&backup.binary_path) {
            error!(
                target: "update.rollback_start",
                reason = %e,
                "Failed to restore backup"
            );
            return Ok(RollbackResult::failure(format!(
                "Failed to restore backup: {}",
                e
            )));
        }

        info!(
            target: "update.rollback_complete",
            restored_version = %backup.metadata.version,
            "Rollback completed successfully"
        );

        Ok(RollbackResult::success(
            backup.metadata.version.clone(),
            self.target_path.clone(),
        ))
    }

    /// Rollback to the most recent backup
    pub fn rollback_to_latest(&self) -> io::Result<RollbackResult> {
        let backup = self.backup_manager.get_latest_backup()?;

        match backup {
            Some(b) => self.restore_backup(&b),
            None => Ok(RollbackResult::failure(
                "No backup available for rollback".to_string(),
            )),
        }
    }

    /// Rollback to a specific version
    pub fn rollback_to_version(&self, version: &str) -> io::Result<RollbackResult> {
        let backup = self.backup_manager.get_backup_by_version(version)?;

        match backup {
            Some(b) => self.restore_backup(&b),
            None => Ok(RollbackResult::failure(format!(
                "No backup found for version: {}",
                version
            ))),
        }
    }

    /// List all available backups
    pub fn list_backups(&self) -> io::Result<Vec<Backup>> {
        self.backup_manager.list_backups()
    }
}

/// Result of an update operation
#[derive(Debug)]
pub enum UpdateResult {
    /// Update succeeded, verification passed
    Success {
        verification: VerificationResult,
        backup: Backup,
    },
    /// Update failed verification, rolled back automatically
    VerificationFailed {
        verification: VerificationResult,
        rollback: RollbackResult,
        backup: Backup,
    },
}

impl UpdateResult {
    /// Check if the update was successful
    pub fn is_success(&self) -> bool {
        matches!(self, UpdateResult::Success { .. })
    }

    /// Get the verification result
    pub fn verification(&self) -> &VerificationResult {
        match self {
            UpdateResult::Success { verification, .. } => verification,
            UpdateResult::VerificationFailed { verification, .. } => verification,
        }
    }
}

/// Write manual recovery instructions to a file
#[allow(dead_code)]
pub fn write_recovery_instructions(path: &Path, details: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "# Process Triage Recovery Instructions")?;
    writeln!(file)?;
    writeln!(
        file,
        "The automatic update/rollback failed. Follow these steps to recover:"
    )?;
    writeln!(file)?;
    writeln!(file, "## Details")?;
    writeln!(file, "{}", details)?;
    writeln!(file)?;
    writeln!(file, "## Manual Recovery Steps")?;
    writeln!(file)?;
    writeln!(
        file,
        "1. Download a known good version from GitHub releases:"
    )?;
    writeln!(
        file,
        "   https://github.com/Dicklesworthstone/process_triage/releases"
    )?;
    writeln!(file)?;
    writeln!(file, "2. Replace the binary manually:")?;
    writeln!(file, "   cp pt-core ~/.local/bin/pt-core")?;
    writeln!(file)?;
    writeln!(file, "3. Make it executable:")?;
    writeln!(file, "   chmod +x ~/.local/bin/pt-core")?;
    writeln!(file)?;
    writeln!(file, "4. Verify the installation:")?;
    writeln!(file, "   pt-core --version")?;
    writeln!(file)?;
    writeln!(
        file,
        "If you continue to experience issues, please report at:"
    )?;
    writeln!(
        file,
        "https://github.com/Dicklesworthstone/process_triage/issues"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_mock_binary(dir: &Path, name: &str, version: &str) -> PathBuf {
        let path = dir.join(name);
        let content = format!(
            r#"#!/bin/bash
case "$1" in
    --version) echo "{} {}" ;;
    health) echo "OK" ;;
    *) echo "Unknown command" ;;
esac
"#,
            name, version
        );
        fs::write(&path, content).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }

        path
    }

    #[test]
    fn test_backup_and_list() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");

        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);

        // Create backup
        let backup = manager.backup_current("1.0.0").unwrap();
        assert_eq!(backup.version(), "1.0.0");

        // List backups
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_rollback_to_latest() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");

        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);

        // Create backup
        let _ = manager.backup_current("1.0.0").unwrap();

        // Modify the binary (simulating update)
        fs::write(&binary, "corrupted content").unwrap();

        // Rollback
        let result = manager.rollback_to_latest().unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version.unwrap(), "1.0.0");
    }

    #[test]
    fn test_rollback_no_backup() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");

        let manager = RollbackManager::with_backup_dir(binary, "pt-core", backup_dir);

        // Try rollback without any backup
        let result = manager.rollback_to_latest().unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("No backup available"));
    }

    #[test]
    fn test_rollback_to_specific_version() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");

        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);

        // Create multiple backups
        let _ = manager.backup_current("1.0.0").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Simulate update to 1.0.1
        fs::write(&binary, "version 1.0.1").unwrap();
        let _ = manager.backup_current("1.0.1").unwrap();

        // Rollback to 1.0.0
        let result = manager.rollback_to_version("1.0.0").unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version.unwrap(), "1.0.0");
    }

    #[test]
    fn test_recovery_instructions() {
        let temp = TempDir::new().unwrap();
        let instructions_path = temp.path().join("RECOVERY.md");

        write_recovery_instructions(&instructions_path, "Update failed with error X").unwrap();

        let content = fs::read_to_string(&instructions_path).unwrap();
        assert!(content.contains("Recovery Instructions"));
        assert!(content.contains("Update failed with error X"));
        assert!(content.contains("GitHub releases"));
    }

    // --- RollbackResult constructors ---

    #[test]
    fn rollback_result_success_constructor() {
        let result = RollbackResult::success("1.2.3".to_string(), PathBuf::from("/usr/bin/pt"));
        assert!(result.success);
        assert_eq!(result.restored_version.as_deref(), Some("1.2.3"));
        assert!(result.error.is_none());
        assert_eq!(result.restored_path, Some(PathBuf::from("/usr/bin/pt")));
    }

    #[test]
    fn rollback_result_failure_constructor() {
        let result = RollbackResult::failure("checksum mismatch".to_string());
        assert!(!result.success);
        assert!(result.restored_version.is_none());
        assert_eq!(result.error.as_deref(), Some("checksum mismatch"));
        assert!(result.restored_path.is_none());
    }

    #[test]
    fn rollback_result_debug() {
        let result = RollbackResult::success("1.0.0".to_string(), PathBuf::from("/bin/pt"));
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("RollbackResult"));
        assert!(dbg.contains("1.0.0"));
    }

    // --- UpdateResult methods ---

    #[test]
    fn update_result_debug() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");

        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);
        let backup = manager.backup_current("1.0.0").unwrap();
        let vr = verify_binary(&binary, None).unwrap();

        let ur = UpdateResult::Success {
            verification: vr,
            backup,
        };
        let dbg = format!("{:?}", ur);
        assert!(dbg.contains("Success"));
    }

    #[test]
    fn update_result_is_success_true() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);
        let backup = manager.backup_current("1.0.0").unwrap();
        let vr = verify_binary(&binary, None).unwrap();

        let ur = UpdateResult::Success {
            verification: vr,
            backup,
        };
        assert!(ur.is_success());
    }

    #[test]
    fn update_result_verification_accessor() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);
        let backup = manager.backup_current("1.0.0").unwrap();
        let vr = verify_binary(&binary, None).unwrap();

        let ur = UpdateResult::Success {
            verification: vr,
            backup,
        };
        let _v = ur.verification();
        // Just verify it doesn't panic and returns a reference
    }

    // --- RollbackManager accessors ---

    #[test]
    fn rollback_manager_target_path() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let manager = RollbackManager::new(binary.clone(), "pt-core");
        assert_eq!(manager.target_path(), binary.as_path());
    }

    #[test]
    fn rollback_manager_backup_manager_accessor() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary, "pt-core", backup_dir.clone());
        let bm = manager.backup_manager();
        assert_eq!(bm.backup_dir(), backup_dir);
    }

    // --- backup_current error cases ---

    #[test]
    fn backup_current_missing_target() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("nonexistent");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(missing, "pt-core", backup_dir);
        let result = manager.backup_current("1.0.0");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // --- rollback_to_version not found ---

    #[test]
    fn rollback_to_version_not_found() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary, "pt-core", backup_dir);

        let result = manager.rollback_to_version("99.99.99").unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("99.99.99"));
    }

    // --- list_backups empty ---

    #[test]
    fn list_backups_empty() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary, "pt-core", backup_dir);

        let backups = manager.list_backups().unwrap();
        assert!(backups.is_empty());
    }

    // --- recovery instructions content structure ---

    #[test]
    fn recovery_instructions_content_structure() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("RECOVERY.md");
        write_recovery_instructions(&path, "test details").unwrap();
        let content = fs::read_to_string(&path).unwrap();

        // Verify structural elements
        assert!(content.contains("# Process Triage Recovery Instructions"));
        assert!(content.contains("## Details"));
        assert!(content.contains("test details"));
        assert!(content.contains("## Manual Recovery Steps"));
        assert!(content.contains("chmod +x"));
        assert!(content.contains("pt-core --version"));
        assert!(content.contains("issues"));
    }

    // --- multiple backups and ordering ---

    #[test]
    fn multiple_backups_listed() {
        let temp = TempDir::new().unwrap();
        let binary = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("backups");
        let manager = RollbackManager::with_backup_dir(binary.clone(), "pt-core", backup_dir);

        let _ = manager.backup_current("1.0.0").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&binary, "v2 content").unwrap();
        let _ = manager.backup_current("2.0.0").unwrap();

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 2);
    }

    #[test]
    fn rollback_manager_new_default_backup_dir() {
        let manager = RollbackManager::new(PathBuf::from("/tmp/pt-core"), "pt-core");
        assert_eq!(manager.target_path(), Path::new("/tmp/pt-core"));
        // backup_manager should have been created with default dir
        let _bm = manager.backup_manager();
    }
}
