//! Backup creation and management for rollback support.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::{default_rollback_dir, DEFAULT_BACKUP_RETENTION};

/// Metadata stored alongside each backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Version string of the backed-up binary
    pub version: String,
    /// Timestamp when backup was created (RFC3339)
    pub created_at: String,
    /// SHA256 checksum of the backed-up binary
    pub checksum: String,
    /// Original path of the binary
    pub original_path: String,
    /// Size in bytes
    pub size_bytes: u64,
}

impl BackupMetadata {
    /// Create new metadata for a backup
    pub fn new(version: &str, original_path: &Path, checksum: &str, size_bytes: u64) -> Self {
        let created_at = chrono::Utc::now().to_rfc3339();
        Self {
            version: version.to_string(),
            created_at,
            checksum: checksum.to_string(),
            original_path: original_path.to_string_lossy().to_string(),
            size_bytes,
        }
    }

    /// Load metadata from a JSON file
    pub fn load(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Save metadata to a JSON file
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

/// A backup entry with its metadata and paths
#[derive(Debug, Clone)]
pub struct Backup {
    /// The backup metadata
    pub metadata: BackupMetadata,
    /// Path to the backed-up binary
    pub binary_path: PathBuf,
    /// Path to the metadata file
    pub metadata_path: PathBuf,
}

impl Backup {
    /// Get the version of this backup
    pub fn version(&self) -> &str {
        &self.metadata.version
    }

    /// Get the creation timestamp
    pub fn created_at(&self) -> &str {
        &self.metadata.created_at
    }
}

/// Manager for creating and managing backups
pub struct BackupManager {
    /// Directory where backups are stored
    backup_dir: PathBuf,
    /// Binary name (e.g., "pt-core")
    binary_name: String,
    /// Maximum number of backups to retain
    retention_count: usize,
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new(binary_name: &str) -> Self {
        Self {
            backup_dir: default_rollback_dir(),
            binary_name: binary_name.to_string(),
            retention_count: DEFAULT_BACKUP_RETENTION,
        }
    }

    /// Create a backup manager with custom settings
    pub fn with_config(backup_dir: PathBuf, binary_name: &str, retention_count: usize) -> Self {
        Self {
            backup_dir,
            binary_name: binary_name.to_string(),
            retention_count,
        }
    }

    /// Set the backup directory
    pub fn set_backup_dir(&mut self, dir: PathBuf) {
        self.backup_dir = dir;
    }

    /// Set the retention count
    pub fn set_retention_count(&mut self, count: usize) {
        self.retention_count = count;
    }

    /// Get the backup directory
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Ensure the backup directory exists
    pub fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.backup_dir)
    }

    /// Compute SHA256 checksum of a file
    pub fn compute_checksum(path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Create a backup of the current binary
    ///
    /// Returns the backup entry if successful
    pub fn create_backup(&self, source_path: &Path, version: &str) -> io::Result<Backup> {
        self.ensure_dir()?;

        // Compute checksum
        let checksum = Self::compute_checksum(source_path)?;
        let size_bytes = fs::metadata(source_path)?.len();

        // Generate backup filename: pt-core-<version>-<timestamp>
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let backup_name = format!("{}-{}-{}", self.binary_name, version, timestamp);

        let binary_path = self.backup_dir.join(&backup_name);
        let metadata_path = self.backup_dir.join(format!("{}.json", backup_name));

        // Copy binary
        fs::copy(source_path, &binary_path)?;

        // Create and save metadata
        let metadata = BackupMetadata::new(version, source_path, &checksum, size_bytes);
        metadata.save(&metadata_path)?;

        // Prune old backups
        self.prune_old_backups()?;

        Ok(Backup {
            metadata,
            binary_path,
            metadata_path,
        })
    }

    /// List all available backups, sorted by creation time (newest first)
    pub fn list_backups(&self) -> io::Result<Vec<Backup>> {
        if !self.backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups = Vec::new();
        let prefix = format!("{}-", self.binary_name);

        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Look for metadata files
            if path.extension().is_some_and(|e| e == "json") {
                let filename = path.file_stem().unwrap_or_default().to_string_lossy();
                if filename.starts_with(&prefix) {
                    if let Ok(metadata) = BackupMetadata::load(&path) {
                        let binary_path = self.backup_dir.join(filename.as_ref());
                        if binary_path.exists() {
                            backups.push(Backup {
                                metadata,
                                binary_path,
                                metadata_path: path,
                            });
                        }
                    }
                }
            }
        }

        // Sort by creation time, newest first
        backups.sort_by(|a, b| b.metadata.created_at.cmp(&a.metadata.created_at));

        Ok(backups)
    }

    /// Get the most recent backup
    pub fn get_latest_backup(&self) -> io::Result<Option<Backup>> {
        let backups = self.list_backups()?;
        Ok(backups.into_iter().next())
    }

    /// Get a backup by version
    pub fn get_backup_by_version(&self, version: &str) -> io::Result<Option<Backup>> {
        let backups = self.list_backups()?;
        Ok(backups.into_iter().find(|b| b.metadata.version == version))
    }

    /// Remove old backups keeping only the most recent N
    fn prune_old_backups(&self) -> io::Result<()> {
        let backups = self.list_backups()?;

        // Keep only retention_count backups
        for backup in backups.into_iter().skip(self.retention_count) {
            // Remove binary and metadata
            let _ = fs::remove_file(&backup.binary_path);
            let _ = fs::remove_file(&backup.metadata_path);
        }

        Ok(())
    }

    /// Verify a backup's integrity by checking its checksum
    pub fn verify_backup(&self, backup: &Backup) -> io::Result<bool> {
        if !backup.binary_path.exists() {
            return Ok(false);
        }

        let current_checksum = Self::compute_checksum(&backup.binary_path)?;
        Ok(current_checksum == backup.metadata.checksum)
    }

    /// Remove a specific backup
    pub fn remove_backup(&self, backup: &Backup) -> io::Result<()> {
        if backup.binary_path.exists() {
            fs::remove_file(&backup.binary_path)?;
        }
        if backup.metadata_path.exists() {
            fs::remove_file(&backup.metadata_path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_binary(dir: &Path, content: &[u8]) -> PathBuf {
        let path = dir.join("test-binary");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_backup_metadata_roundtrip() {
        let temp = TempDir::new().unwrap();
        let meta = BackupMetadata::new("1.0.0", Path::new("/usr/bin/pt-core"), "abc123", 1024);

        let meta_path = temp.path().join("meta.json");
        meta.save(&meta_path).unwrap();

        let loaded = BackupMetadata::load(&meta_path).unwrap();
        assert_eq!(loaded.version, "1.0.0");
        assert_eq!(loaded.checksum, "abc123");
        assert_eq!(loaded.size_bytes, 1024);
    }

    #[test]
    fn test_compute_checksum() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_test_binary(temp.path(), b"test content");

        let checksum = BackupManager::compute_checksum(&binary_path).unwrap();
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA256 hex length
    }

    #[test]
    fn test_create_and_list_backups() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_test_binary(temp.path(), b"binary content");

        let manager = BackupManager::with_config(temp.path().join("rollback"), "pt-core", 3);

        // Create a backup
        let backup = manager.create_backup(&binary_path, "1.0.0").unwrap();
        assert_eq!(backup.version(), "1.0.0");

        // List backups
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].version(), "1.0.0");
    }

    #[test]
    fn test_backup_retention() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_test_binary(temp.path(), b"binary content");

        let manager = BackupManager::with_config(
            temp.path().join("rollback"),
            "pt-core",
            2, // Keep only 2
        );

        // Create 4 backups
        for i in 1..=4 {
            let _ = manager
                .create_backup(&binary_path, &format!("1.0.{}", i))
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure different timestamps
        }

        // Should only have 2 backups
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 2);

        // Should be the newest ones (1.0.4 and 1.0.3)
        assert_eq!(backups[0].version(), "1.0.4");
        assert_eq!(backups[1].version(), "1.0.3");
    }

    #[test]
    fn test_verify_backup() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_test_binary(temp.path(), b"binary content");

        let manager = BackupManager::with_config(temp.path().join("rollback"), "pt-core", 3);

        let backup = manager.create_backup(&binary_path, "1.0.0").unwrap();

        // Verify should pass
        assert!(manager.verify_backup(&backup).unwrap());

        // Corrupt the backup
        fs::write(&backup.binary_path, b"corrupted").unwrap();

        // Verify should fail
        assert!(!manager.verify_backup(&backup).unwrap());
    }

    #[test]
    fn test_get_backup_by_version() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_test_binary(temp.path(), b"binary content");

        let manager = BackupManager::with_config(temp.path().join("rollback"), "pt-core", 5);

        let _ = manager.create_backup(&binary_path, "1.0.0").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = manager.create_backup(&binary_path, "1.0.1").unwrap();

        let found = manager.get_backup_by_version("1.0.0").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().version(), "1.0.0");

        let not_found = manager.get_backup_by_version("2.0.0").unwrap();
        assert!(not_found.is_none());
    }
}
