//! Bundle writer for creating .ptb files.
//!
//! Creates ZIP archives with manifest and checksums.

use crate::{BundleError, BundleManifest, FileEntry, Result};
use crate::encryption;
use pt_redact::ExportProfile;
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::Path;
use tracing::{debug, info};
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;

/// File type hints for MIME type assignment.
#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Json,
    Parquet,
    Html,
    Log,
    Binary,
}

impl FileType {
    fn mime_type(&self) -> &'static str {
        match self {
            FileType::Json => "application/json",
            FileType::Parquet => "application/vnd.apache.parquet",
            FileType::Html => "text/html",
            FileType::Log => "application/x-ndjson",
            FileType::Binary => "application/octet-stream",
        }
    }

    fn from_path(path: &str) -> Self {
        if path.ends_with(".json") || path.ends_with(".jsonl") {
            if path.ends_with(".jsonl") {
                FileType::Log
            } else {
                FileType::Json
            }
        } else if path.ends_with(".parquet") {
            FileType::Parquet
        } else if path.ends_with(".html") {
            FileType::Html
        } else {
            FileType::Binary
        }
    }
}

/// Builder for creating .ptb session bundles.
pub struct BundleWriter {
    manifest: BundleManifest,
    files: Vec<(String, Vec<u8>)>,
}

impl BundleWriter {
    /// Create a new bundle writer.
    pub fn new(
        session_id: impl Into<String>,
        host_id: impl Into<String>,
        export_profile: ExportProfile,
    ) -> Self {
        let manifest = BundleManifest::new(session_id, host_id, export_profile);
        Self {
            manifest,
            files: Vec::new(),
        }
    }

    /// Set the redaction policy version and hash.
    pub fn with_redaction_policy(
        mut self,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        self.manifest = self.manifest.with_redaction_policy(version, hash);
        self
    }

    /// Set the pt version.
    pub fn with_pt_version(mut self, version: impl Into<String>) -> Self {
        self.manifest = self.manifest.with_pt_version(version);
        self
    }

    /// Set the bundle description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.manifest = self.manifest.with_description(description);
        self
    }

    /// Add a file to the bundle with automatic checksum.
    pub fn add_file(
        &mut self,
        path: impl Into<String>,
        data: Vec<u8>,
        file_type: Option<FileType>,
    ) {
        let path = path.into();
        let checksum = FileEntry::compute_checksum(&data);
        let bytes = data.len() as u64;

        let file_type = file_type.unwrap_or_else(|| FileType::from_path(&path));

        let mut entry = FileEntry::new(&path, checksum, bytes);
        entry.mime_type = Some(file_type.mime_type().to_string());

        self.manifest.add_file(entry);
        self.files.push((path, data));

        debug!(path = %self.files.last().unwrap().0, bytes, "Added file to bundle");
    }

    /// Add a JSON-serializable value as a file.
    pub fn add_json<T: serde::Serialize>(
        &mut self,
        path: impl Into<String>,
        value: &T,
    ) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        self.add_file(path, json.into_bytes(), Some(FileType::Json));
        Ok(())
    }

    /// Add the session summary.
    pub fn add_summary<T: serde::Serialize>(&mut self, summary: &T) -> Result<()> {
        self.add_json("summary.json", summary)
    }

    /// Add the agent plan.
    pub fn add_plan<T: serde::Serialize>(&mut self, plan: &T) -> Result<()> {
        self.add_json("plan.json", plan)
    }

    /// Add raw bytes with a specific file type.
    pub fn add_bytes(&mut self, path: impl Into<String>, data: Vec<u8>, file_type: FileType) {
        self.add_file(path, data, Some(file_type));
    }

    /// Add a telemetry file (Parquet).
    pub fn add_telemetry(&mut self, table_name: &str, data: Vec<u8>) {
        let path = format!("telemetry/{}.parquet", table_name);
        self.add_file(path, data, Some(FileType::Parquet));
    }

    /// Add a log file.
    pub fn add_log(&mut self, name: &str, data: Vec<u8>) {
        let path = format!("logs/{}.jsonl", name);
        self.add_file(path, data, Some(FileType::Log));
    }

    /// Add an HTML report.
    pub fn add_report(&mut self, data: Vec<u8>) {
        self.add_file("report.html", data, Some(FileType::Html));
    }

    /// Get the current manifest (for inspection before writing).
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Get the export profile.
    pub fn export_profile(&self) -> ExportProfile {
        self.manifest.export_profile
    }

    /// Get total size in bytes before compression.
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|(_, data)| data.len() as u64).sum()
    }

    /// Get file count (not including manifest).
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Write the bundle to a file.
    pub fn write(mut self, path: &Path) -> Result<BundleManifest> {
        if self.files.is_empty() {
            return Err(BundleError::EmptyBundle);
        }

        // Sort files for deterministic ordering
        self.manifest.sort_files();
        self.files.sort_by(|a, b| a.0.cmp(&b.0));

        // Prepare manifest JSON
        let manifest_json = self.manifest.to_json()?;
        let manifest_bytes = manifest_json.as_bytes();

        // Create the ZIP file
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);

        let options: FileOptions<'_, ()> = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);

        // Write manifest first
        zip.start_file("manifest.json", options)?;
        zip.write_all(manifest_bytes)?;

        // Write all content files
        for (file_path, data) in &self.files {
            zip.start_file(file_path.as_str(), options)?;
            zip.write_all(data)?;
        }

        // Finalize the ZIP
        zip.finish()?;

        info!(
            path = %path.display(),
            files = self.files.len(),
            bytes = self.total_bytes(),
            profile = %self.manifest.export_profile,
            "Bundle written"
        );

        Ok(self.manifest)
    }

    /// Write the bundle to a file, encrypted with a passphrase.
    pub fn write_encrypted(self, path: &Path, passphrase: &str) -> Result<BundleManifest> {
        let (bytes, manifest) = self.write_to_vec()?;
        let encrypted = encryption::encrypt_bytes(&bytes, passphrase)?;
        std::fs::write(path, encrypted)?;
        Ok(manifest)
    }

    /// Write the bundle to a byte vector (for in-memory use).
    pub fn write_to_vec(mut self) -> Result<(Vec<u8>, BundleManifest)> {
        if self.files.is_empty() {
            return Err(BundleError::EmptyBundle);
        }

        // Sort files for deterministic ordering
        self.manifest.sort_files();
        self.files.sort_by(|a, b| a.0.cmp(&b.0));

        // Prepare manifest JSON
        let manifest_json = self.manifest.to_json()?;
        let manifest_bytes = manifest_json.as_bytes();

        // Create the ZIP in memory
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);

            let options: FileOptions<'_, ()> = FileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);

            // Write manifest first
            zip.start_file("manifest.json", options)?;
            zip.write_all(manifest_bytes)?;

            // Write all content files
            for (file_path, data) in &self.files {
                zip.start_file(file_path.as_str(), options)?;
                zip.write_all(data)?;
            }

            zip.finish()?;
        }

        let bytes = buffer.into_inner();

        info!(
            files = self.files.len(),
            compressed_bytes = bytes.len(),
            uncompressed_bytes = self.total_bytes(),
            "Bundle written to memory"
        );

        Ok((bytes, self.manifest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_bundle_writer_new() {
        let writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        assert_eq!(writer.manifest().session_id, "session-123");
        assert_eq!(writer.export_profile(), ExportProfile::Safe);
        assert_eq!(writer.file_count(), 0);
    }

    #[test]
    fn test_bundle_writer_add_file() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        writer.add_file("test.json", b"{}".to_vec(), None);

        assert_eq!(writer.file_count(), 1);
        assert_eq!(writer.total_bytes(), 2);
    }

    #[test]
    fn test_bundle_writer_add_json() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        let data = serde_json::json!({"key": "value"});
        writer.add_json("data.json", &data).unwrap();

        assert_eq!(writer.file_count(), 1);
        assert!(writer.manifest().find_file("data.json").is_some());
    }

    #[test]
    fn test_bundle_writer_add_summary() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        let summary = serde_json::json!({"total": 42});
        writer.add_summary(&summary).unwrap();

        assert!(writer.manifest().find_file("summary.json").is_some());
    }

    #[test]
    fn test_bundle_writer_add_telemetry() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        writer.add_telemetry("proc_samples", vec![0, 1, 2, 3]);

        let entry = writer
            .manifest()
            .find_file("telemetry/proc_samples.parquet");
        assert!(entry.is_some());
        assert_eq!(
            entry.unwrap().mime_type,
            Some("application/vnd.apache.parquet".to_string())
        );
    }

    #[test]
    fn test_bundle_writer_add_log() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        writer.add_log("events", b"{}\n{}\n".to_vec());

        assert!(writer.manifest().find_file("logs/events.jsonl").is_some());
    }

    #[test]
    fn test_bundle_writer_write_empty_fails() {
        let writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);
        let result = writer.write_to_vec();

        assert!(matches!(result, Err(BundleError::EmptyBundle)));
    }

    #[test]
    fn test_bundle_writer_write_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test.ptb");

        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe)
            .with_pt_version("0.1.0");

        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();
        writer.add_file("data.txt", b"test data".to_vec(), None);

        let manifest = writer.write(&bundle_path).unwrap();

        assert!(bundle_path.exists());
        assert_eq!(manifest.file_count(), 2);
        assert_eq!(manifest.session_id, "session-123");
    }

    #[test]
    fn test_bundle_writer_write_to_vec() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();

        let (bytes, manifest) = writer.write_to_vec().unwrap();

        assert!(!bytes.is_empty());
        assert_eq!(manifest.file_count(), 1);

        // Verify it's a valid ZIP (magic bytes)
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_bundle_writer_deterministic_order() {
        // Create two writers with files added in different orders
        let mut writer1 = BundleWriter::new("session", "host", ExportProfile::Safe);
        writer1.add_file("z.txt", b"z".to_vec(), None);
        writer1.add_file("a.txt", b"a".to_vec(), None);
        writer1.add_file("m.txt", b"m".to_vec(), None);

        let mut writer2 = BundleWriter::new("session", "host", ExportProfile::Safe);
        writer2.add_file("a.txt", b"a".to_vec(), None);
        writer2.add_file("m.txt", b"m".to_vec(), None);
        writer2.add_file("z.txt", b"z".to_vec(), None);

        let (bytes1, manifest1) = writer1.write_to_vec().unwrap();
        let (bytes2, manifest2) = writer2.write_to_vec().unwrap();

        // Verify both bundles are valid ZIPs
        assert_eq!(&bytes1[0..2], b"PK");
        assert_eq!(&bytes2[0..2], b"PK");

        // File order in manifest should be identical (sorted)
        let paths1: Vec<_> = manifest1.files.iter().map(|f| &f.path).collect();
        let paths2: Vec<_> = manifest2.files.iter().map(|f| &f.path).collect();
        assert_eq!(paths1, paths2);
        assert_eq!(paths1, vec!["a.txt", "m.txt", "z.txt"]);

        // Checksums should match (same content)
        for (f1, f2) in manifest1.files.iter().zip(manifest2.files.iter()) {
            assert_eq!(f1.sha256, f2.sha256);
        }
    }

    #[test]
    fn test_file_type_from_path() {
        assert!(matches!(FileType::from_path("test.json"), FileType::Json));
        assert!(matches!(FileType::from_path("test.jsonl"), FileType::Log));
        assert!(matches!(
            FileType::from_path("test.parquet"),
            FileType::Parquet
        ));
        assert!(matches!(FileType::from_path("test.html"), FileType::Html));
        assert!(matches!(FileType::from_path("test.bin"), FileType::Binary));
    }

    #[test]
    fn test_bundle_writer_with_options() {
        let writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Forensic)
            .with_redaction_policy("1.0.0", "abc123")
            .with_pt_version("0.1.0")
            .with_description("Test bundle");

        let manifest = writer.manifest();
        assert_eq!(manifest.redaction_policy_version, "1.0.0");
        assert_eq!(manifest.redaction_policy_hash, "abc123");
        assert_eq!(manifest.pt_version, Some("0.1.0".to_string()));
        assert_eq!(manifest.description, Some("Test bundle".to_string()));
    }
}
