//! Bundle reader for opening and verifying .ptb files.
//!
//! Reads ZIP archives with integrity verification.

use crate::encryption;
use crate::{BundleError, BundleManifest, FileEntry, Result, BUNDLE_SCHEMA_VERSION};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use tracing::{debug, info, warn};
use zip::ZipArchive;

/// Maximum allowed file size to read into memory (100 MB).
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Reader for .ptb session bundles with verification.
pub struct BundleReader<R: Read + std::io::Seek> {
    manifest: BundleManifest,
    archive: ZipArchive<R>,
    verified: HashMap<String, bool>,
}

impl BundleReader<File> {
    /// Open a bundle from a file path.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 8];
        let bytes_read = file.read(&mut magic)?;

        if bytes_read == magic.len() && encryption::is_encrypted_prefix(&magic) {
            return Err(BundleError::EncryptedBundleRequiresPassphrase);
        }

        file.seek(SeekFrom::Start(0))?;
        Self::from_reader(file)
    }
}

impl BundleReader<Cursor<Vec<u8>>> {
    /// Open a bundle from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let cursor = Cursor::new(bytes);
        Self::from_reader(cursor)
    }

    /// Open a bundle from a file path, optionally using a passphrase.
    pub fn open_with_passphrase(path: &Path, passphrase: Option<&str>) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 8];
        let bytes_read = file.read(&mut magic)?;

        file.seek(SeekFrom::Start(0))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        if bytes_read == magic.len() && encryption::is_encrypted_prefix(&magic) {
            let passphrase = passphrase.ok_or(BundleError::EncryptedBundleRequiresPassphrase)?;
            let decrypted = encryption::decrypt_bytes(&data, passphrase)?;
            return Self::from_bytes(decrypted);
        }

        Self::from_bytes(data)
    }
}

impl<R: Read + std::io::Seek> BundleReader<R> {
    /// Create a reader from any Read + Seek source.
    pub fn from_reader(reader: R) -> Result<Self> {
        let mut archive = ZipArchive::new(reader)?;

        // Read and parse manifest
        let manifest = Self::read_manifest(&mut archive)?;

        // Validate manifest structure
        manifest.validate()?;

        info!(
            session_id = %manifest.session_id,
            files = manifest.file_count(),
            profile = %manifest.export_profile,
            "Bundle opened"
        );

        Ok(Self {
            manifest,
            archive,
            verified: HashMap::new(),
        })
    }

    /// Read and parse the manifest from the archive.
    fn read_manifest(archive: &mut ZipArchive<R>) -> Result<BundleManifest> {
        let mut manifest_file = archive
            .by_name("manifest.json")
            .map_err(|_| BundleError::MissingFile("manifest.json".to_string()))?;

        if manifest_file.size() > MAX_FILE_SIZE {
            return Err(BundleError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "manifest.json too large",
            )));
        }

        let mut json = String::new();
        manifest_file.read_to_string(&mut json)?;

        let manifest = BundleManifest::from_json(&json)?;

        // Check bundle version compatibility
        if manifest.bundle_version != BUNDLE_SCHEMA_VERSION {
            warn!(
                bundle_version = %manifest.bundle_version,
                supported = %BUNDLE_SCHEMA_VERSION,
                "Bundle version mismatch"
            );
        }

        Ok(manifest)
    }

    /// Get the manifest.
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Get the export profile.
    pub fn export_profile(&self) -> pt_redact::ExportProfile {
        self.manifest.export_profile
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.manifest.session_id
    }

    /// List all files in the bundle.
    pub fn files(&self) -> &[FileEntry] {
        &self.manifest.files
    }

    /// Check if a file exists in the bundle.
    pub fn has_file(&self, path: &str) -> bool {
        self.manifest.find_file(path).is_some()
    }

    /// Read a file from the bundle without verification.
    ///
    /// Use `read_verified` for integrity-checked reads.
    pub fn read_raw(&mut self, path: &str) -> Result<Vec<u8>> {
        let mut file = self
            .archive
            .by_name(path)
            .map_err(|_| BundleError::FileNotFound(path.to_string()))?;

        if file.size() > MAX_FILE_SIZE {
            return Err(BundleError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("file {} too large ({} bytes)", path, file.size()),
            )));
        }

        let mut data = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut data)?;

        debug!(
            path,
            bytes = data.len(),
            "Read file from bundle (unverified)"
        );

        Ok(data)
    }

    /// Read a file with checksum verification.
    ///
    /// Returns error if checksum doesn't match manifest.
    pub fn read_verified(&mut self, path: &str) -> Result<Vec<u8>> {
        // Check if we have a manifest entry
        let entry = self
            .manifest
            .find_file(path)
            .ok_or_else(|| BundleError::FileNotFound(path.to_string()))?
            .clone();

        // Read the file
        let data = self.read_raw(path)?;

        // Verify checksum
        let actual_checksum = FileEntry::compute_checksum(&data);
        if actual_checksum != entry.sha256 {
            return Err(BundleError::ChecksumMismatch {
                path: path.to_string(),
                expected: entry.sha256.clone(),
                actual: actual_checksum,
            });
        }

        // Mark as verified
        self.verified.insert(path.to_string(), true);

        debug!(path, "File verified");

        Ok(data)
    }

    /// Check if a file has been verified.
    pub fn is_verified(&self, path: &str) -> bool {
        self.verified.get(path).copied().unwrap_or(false)
    }

    /// Verify all files in the bundle.
    ///
    /// Returns list of paths that failed verification.
    pub fn verify_all(&mut self) -> Vec<String> {
        let mut failures = Vec::new();

        let paths: Vec<String> = self.manifest.files.iter().map(|f| f.path.clone()).collect();

        for path in paths {
            if let Err(e) = self.read_verified(&path) {
                warn!(path = %path, error = %e, "Verification failed");
                failures.push(path);
            }
        }

        if failures.is_empty() {
            info!("All files verified");
        } else {
            warn!(failures = ?failures, "Some files failed verification");
        }

        failures
    }

    /// Read and parse a JSON file.
    pub fn read_json<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T> {
        let data = self.read_verified(path)?;
        let json = String::from_utf8_lossy(&data);
        let value: T = serde_json::from_str(&json)?;
        Ok(value)
    }

    /// Read the summary file.
    pub fn read_summary<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        self.read_json("summary.json")
    }

    /// Read the plan file (if present).
    pub fn read_plan<T: serde::de::DeserializeOwned>(&mut self) -> Result<Option<T>> {
        if self.has_file("plan.json") {
            Ok(Some(self.read_json("plan.json")?))
        } else {
            Ok(None)
        }
    }

    /// Read the report HTML (if present).
    pub fn read_report(&mut self) -> Result<Option<Vec<u8>>> {
        if self.has_file("report.html") {
            Ok(Some(self.read_verified("report.html")?))
        } else {
            Ok(None)
        }
    }

    /// List telemetry files in the bundle.
    pub fn telemetry_files(&self) -> Vec<&FileEntry> {
        self.manifest
            .files
            .iter()
            .filter(|f| f.path.starts_with("telemetry/") && f.path.ends_with(".parquet"))
            .collect()
    }

    /// Read a telemetry file.
    pub fn read_telemetry(&mut self, table_name: &str) -> Result<Vec<u8>> {
        let path = format!("telemetry/{}.parquet", table_name);
        self.read_verified(&path)
    }

    /// List log files in the bundle.
    pub fn log_files(&self) -> Vec<&FileEntry> {
        self.manifest
            .files
            .iter()
            .filter(|f| f.path.starts_with("logs/") && f.path.ends_with(".jsonl"))
            .collect()
    }

    /// Read a log file.
    pub fn read_log(&mut self, name: &str) -> Result<Vec<u8>> {
        let path = format!("logs/{}.jsonl", name);
        self.read_verified(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{decrypt_bytes, encrypt_bytes};
    use crate::BundleError;
    use crate::BundleWriter;
    use pt_redact::ExportProfile;

    fn create_test_bundle() -> Vec<u8> {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();
        writer.add_file("data.txt", b"test data".to_vec(), None);

        let (bytes, _) = writer.write_to_vec().unwrap();
        bytes
    }

    #[test]
    fn test_bundle_reader_from_bytes() {
        let bytes = create_test_bundle();
        let reader = BundleReader::from_bytes(bytes).unwrap();

        assert_eq!(reader.session_id(), "session-123");
        assert_eq!(reader.manifest().file_count(), 2);
    }

    #[test]
    fn test_bundle_reader_manifest() {
        let bytes = create_test_bundle();
        let reader = BundleReader::from_bytes(bytes).unwrap();

        let manifest = reader.manifest();
        assert_eq!(manifest.session_id, "session-123");
        assert_eq!(manifest.host_id, "host-abc");
        assert_eq!(manifest.export_profile, ExportProfile::Safe);
    }

    #[test]
    fn test_bundle_reader_has_file() {
        let bytes = create_test_bundle();
        let reader = BundleReader::from_bytes(bytes).unwrap();

        assert!(reader.has_file("summary.json"));
        assert!(reader.has_file("data.txt"));
        assert!(!reader.has_file("missing.txt"));
    }

    #[test]
    fn test_bundle_reader_read_verified() {
        let bytes = create_test_bundle();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let data = reader.read_verified("data.txt").unwrap();
        assert_eq!(data, b"test data");
        assert!(reader.is_verified("data.txt"));
    }

    #[test]
    fn test_bundle_reader_read_summary() {
        let bytes = create_test_bundle();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let summary: serde_json::Value = reader.read_summary().unwrap();
        assert_eq!(summary["total"], 42);
    }

    #[test]
    fn test_bundle_reader_verify_all() {
        let bytes = create_test_bundle();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let failures = reader.verify_all();
        assert!(failures.is_empty());
    }

    #[test]
    fn test_bundle_reader_missing_file() {
        let bytes = create_test_bundle();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let result = reader.read_verified("missing.txt");
        assert!(matches!(result, Err(BundleError::FileNotFound(_))));
    }

    #[test]
    fn test_bundle_reader_telemetry_files() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        writer.add_telemetry("proc_samples", vec![1, 2, 3]);
        writer.add_telemetry("audit", vec![4, 5, 6]);
        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();

        let (bytes, _) = writer.write_to_vec().unwrap();
        let reader = BundleReader::from_bytes(bytes).unwrap();

        let telemetry = reader.telemetry_files();
        assert_eq!(telemetry.len(), 2);
    }

    #[test]
    fn test_bundle_reader_log_files() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        writer.add_log("events", b"{}\n".to_vec());
        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();

        let (bytes, _) = writer.write_to_vec().unwrap();
        let reader = BundleReader::from_bytes(bytes).unwrap();

        let logs = reader.log_files();
        assert_eq!(logs.len(), 1);
        assert!(logs[0].path.contains("events"));
    }

    #[test]
    fn test_bundle_reader_read_plan_missing() {
        let bytes = create_test_bundle();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let plan: Option<serde_json::Value> = reader.read_plan().unwrap();
        assert!(plan.is_none());
    }

    #[test]
    fn test_bundle_reader_read_plan_present() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();
        writer
            .add_plan(&serde_json::json!({"action": "kill"}))
            .unwrap();

        let (bytes, _) = writer.write_to_vec().unwrap();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let plan: Option<serde_json::Value> = reader.read_plan().unwrap();
        assert!(plan.is_some());
        assert_eq!(plan.unwrap()["action"], "kill");
    }

    #[test]
    fn test_bundle_reader_read_report() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();
        writer.add_report(b"<html></html>".to_vec());

        let (bytes, _) = writer.write_to_vec().unwrap();
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        let report = reader.read_report().unwrap();
        assert!(report.is_some());
        assert_eq!(report.unwrap(), b"<html></html>");
    }

    #[test]
    fn test_bundle_roundtrip_integrity() {
        let mut writer = BundleWriter::new("session-test", "host-test", ExportProfile::Forensic)
            .with_pt_version("0.1.0")
            .with_description("Test bundle");

        writer
            .add_summary(&serde_json::json!({
                "total_processes": 100,
                "candidates": 5,
            }))
            .unwrap();

        writer
            .add_plan(&serde_json::json!({
                "recommendations": ["kill", "spare"],
            }))
            .unwrap();

        writer.add_telemetry("proc_samples", vec![1, 2, 3, 4, 5]);
        writer.add_log("audit", b"{\"event\":\"test\"}\n".to_vec());

        let (bytes, orig_manifest) = writer.write_to_vec().unwrap();

        // Read it back
        let mut reader = BundleReader::from_bytes(bytes).unwrap();

        // Verify manifest matches
        assert_eq!(reader.manifest().session_id, orig_manifest.session_id);
        assert_eq!(reader.manifest().file_count(), orig_manifest.file_count());

        // Verify all files
        let failures = reader.verify_all();
        assert!(failures.is_empty(), "Verification failed: {:?}", failures);
    }

    #[test]
    fn test_bundle_reader_open_encrypted() {
        let bytes = create_test_bundle();
        let encrypted = encrypt_bytes(&bytes, "secret").unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("session.ptb");
        std::fs::write(&bundle_path, encrypted).unwrap();

        let reader = BundleReader::open_with_passphrase(&bundle_path, Some("secret")).unwrap();
        assert_eq!(reader.session_id(), "session-123");
    }

    #[test]
    fn test_bundle_reader_open_encrypted_requires_passphrase() {
        let bytes = create_test_bundle();
        let encrypted = encrypt_bytes(&bytes, "secret").unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("session.ptb");
        std::fs::write(&bundle_path, encrypted).unwrap();

        let result = BundleReader::open(&bundle_path);
        assert!(matches!(
            result,
            Err(BundleError::EncryptedBundleRequiresPassphrase)
        ));
    }

    #[test]
    fn test_bundle_reader_open_encrypted_wrong_passphrase() {
        let bytes = create_test_bundle();
        let encrypted = encrypt_bytes(&bytes, "secret").unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("session.ptb");
        std::fs::write(&bundle_path, encrypted).unwrap();

        let result = BundleReader::open_with_passphrase(&bundle_path, Some("bad"));
        assert!(matches!(result, Err(BundleError::DecryptionFailed)));
    }

    #[test]
    fn test_bundle_reader_decrypt_roundtrip() {
        let bytes = create_test_bundle();
        let encrypted = encrypt_bytes(&bytes, "secret").unwrap();
        let decrypted = decrypt_bytes(&encrypted, "secret").unwrap();
        assert_eq!(decrypted, bytes);
    }
}
