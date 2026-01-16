//! Bundle manifest types and serialization.
//!
//! The manifest is the source of truth for a bundle's contents, providing:
//! - Bundle metadata (version, timestamps, identifiers)
//! - File listing with SHA-256 checksums
//! - Redaction policy version used
//! - Export profile applied

use chrono::{DateTime, Utc};
use pt_redact::ExportProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current bundle schema version.
pub const BUNDLE_SCHEMA_VERSION: &str = "1.0.0";

/// Manifest file name within the bundle.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

/// Bundle manifest containing metadata and file checksums.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle format version.
    pub bundle_version: String,

    /// Schema version for data structures.
    pub schema_version: String,

    /// When the bundle was created.
    pub created_at: DateTime<Utc>,

    /// Host ID (hashed for privacy).
    pub host_id: String,

    /// Session ID this bundle is for.
    pub session_id: String,

    /// Export profile used (minimal/safe/forensic).
    pub export_profile: ExportProfile,

    /// Redaction policy version applied.
    pub redaction_policy_version: String,

    /// SHA-256 hash of the redaction policy file.
    pub redaction_policy_hash: String,

    /// Files included in the bundle with checksums.
    pub files: Vec<FileEntry>,

    /// Optional description or notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// pt version that created this bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pt_version: Option<String>,
}

impl BundleManifest {
    /// Create a new manifest with required fields.
    pub fn new(
        session_id: impl Into<String>,
        host_id: impl Into<String>,
        export_profile: ExportProfile,
    ) -> Self {
        Self {
            bundle_version: BUNDLE_SCHEMA_VERSION.to_string(),
            schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
            created_at: Utc::now(),
            host_id: host_id.into(),
            session_id: session_id.into(),
            export_profile,
            redaction_policy_version: "1.0.0".to_string(),
            redaction_policy_hash: String::new(),
            files: Vec::new(),
            description: None,
            pt_version: None,
        }
    }

    /// Set the redaction policy version and hash.
    pub fn with_redaction_policy(
        mut self,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        self.redaction_policy_version = version.into();
        self.redaction_policy_hash = hash.into();
        self
    }

    /// Set the pt version.
    pub fn with_pt_version(mut self, version: impl Into<String>) -> Self {
        self.pt_version = Some(version.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a file entry to the manifest.
    pub fn add_file(&mut self, entry: FileEntry) {
        self.files.push(entry);
    }

    /// Get total size of all files in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.bytes).sum()
    }

    /// Get file count.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Find a file by path.
    pub fn find_file(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Compute the checksum of the manifest content itself (excluding this field).
    pub fn compute_self_checksum(&self) -> String {
        // Create a version without files for checksum (to avoid chicken-egg)
        let canonical = serde_json::json!({
            "bundle_version": self.bundle_version,
            "schema_version": self.schema_version,
            "created_at": self.created_at.to_rfc3339(),
            "host_id": self.host_id,
            "session_id": self.session_id,
            "export_profile": self.export_profile.to_string(),
            "redaction_policy_version": self.redaction_policy_version,
            "redaction_policy_hash": self.redaction_policy_hash,
        });

        let json = serde_json::to_string(&canonical).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validate the manifest structure.
    pub fn validate(&self) -> crate::Result<()> {
        if self.bundle_version != BUNDLE_SCHEMA_VERSION {
            return Err(crate::BundleError::UnsupportedVersion {
                version: self.bundle_version.clone(),
                supported: BUNDLE_SCHEMA_VERSION.to_string(),
            });
        }

        if self.session_id.is_empty() {
            return Err(crate::BundleError::CorruptedManifest(
                "session_id is empty".to_string(),
            ));
        }

        if self.host_id.is_empty() {
            return Err(crate::BundleError::CorruptedManifest(
                "host_id is empty".to_string(),
            ));
        }

        // Validate file entries
        for file in &self.files {
            if file.path.is_empty() {
                return Err(crate::BundleError::CorruptedManifest(
                    "file entry has empty path".to_string(),
                ));
            }

            // Security: reject absolute paths
            if file.path.starts_with('/') || file.path.starts_with('\\') {
                return Err(crate::BundleError::CorruptedManifest(format!(
                    "file '{}' has absolute path (security violation)",
                    file.path
                )));
            }

            // Security: reject path traversal attempts
            if file.path.contains("..") {
                return Err(crate::BundleError::CorruptedManifest(format!(
                    "file '{}' contains path traversal sequence (security violation)",
                    file.path
                )));
            }

            if file.sha256.len() != 64 {
                return Err(crate::BundleError::CorruptedManifest(format!(
                    "file '{}' has invalid checksum length",
                    file.path
                )));
            }
        }

        Ok(())
    }

    /// Sort files for deterministic ordering.
    pub fn sort_files(&mut self) {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// Serialize to JSON with consistent formatting.
    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// File entry in the manifest with checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path within the bundle (relative).
    pub path: String,

    /// SHA-256 checksum (64 hex characters).
    pub sha256: String,

    /// Size in bytes.
    pub bytes: u64,

    /// MIME type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl FileEntry {
    /// Create a new file entry.
    pub fn new(path: impl Into<String>, sha256: impl Into<String>, bytes: u64) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
            bytes,
            mime_type: None,
        }
    }

    /// Set the MIME type.
    pub fn with_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    /// Compute SHA-256 checksum of data.
    pub fn compute_checksum(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Verify the checksum against data.
    pub fn verify(&self, data: &[u8]) -> bool {
        Self::compute_checksum(data) == self.sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_new() {
        let manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);

        assert_eq!(manifest.session_id, "session-123");
        assert_eq!(manifest.host_id, "host-abc");
        assert_eq!(manifest.export_profile, ExportProfile::Safe);
        assert_eq!(manifest.bundle_version, BUNDLE_SCHEMA_VERSION);
    }

    #[test]
    fn test_manifest_builder() {
        let manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Forensic)
            .with_pt_version("0.1.0")
            .with_description("Test bundle");

        assert_eq!(manifest.pt_version, Some("0.1.0".to_string()));
        assert_eq!(manifest.description, Some("Test bundle".to_string()));
    }

    #[test]
    fn test_manifest_add_file() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);

        manifest.add_file(FileEntry::new("summary.json", "a".repeat(64), 100));
        manifest.add_file(FileEntry::new("plan.json", "b".repeat(64), 200));

        assert_eq!(manifest.file_count(), 2);
        assert_eq!(manifest.total_bytes(), 300);
    }

    #[test]
    fn test_manifest_find_file() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);
        manifest.add_file(FileEntry::new("summary.json", "a".repeat(64), 100));

        assert!(manifest.find_file("summary.json").is_some());
        assert!(manifest.find_file("missing.json").is_none());
    }

    #[test]
    fn test_manifest_sort_files() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);
        manifest.add_file(FileEntry::new("z.json", "a".repeat(64), 100));
        manifest.add_file(FileEntry::new("a.json", "b".repeat(64), 100));
        manifest.add_file(FileEntry::new("m.json", "c".repeat(64), 100));

        manifest.sort_files();

        assert_eq!(manifest.files[0].path, "a.json");
        assert_eq!(manifest.files[1].path, "m.json");
        assert_eq!(manifest.files[2].path, "z.json");
    }

    #[test]
    fn test_manifest_validate_success() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);
        manifest.add_file(FileEntry::new("test.json", "a".repeat(64), 100));

        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_validate_empty_session() {
        let manifest = BundleManifest::new("", "host-abc", ExportProfile::Safe);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_manifest_validate_invalid_checksum() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);
        manifest.add_file(FileEntry::new("test.json", "invalid", 100));

        let result = manifest.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_json_roundtrip() {
        let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe)
            .with_pt_version("0.1.0");
        manifest.add_file(FileEntry::new("test.json", "a".repeat(64), 100));

        let json = manifest.to_json().unwrap();
        let parsed = BundleManifest::from_json(&json).unwrap();

        assert_eq!(parsed.session_id, manifest.session_id);
        assert_eq!(parsed.host_id, manifest.host_id);
        assert_eq!(parsed.file_count(), manifest.file_count());
    }

    #[test]
    fn test_file_entry_checksum() {
        let data = b"hello world";
        let checksum = FileEntry::compute_checksum(data);

        // Known SHA-256 for "hello world"
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_file_entry_verify() {
        let data = b"test data";
        let checksum = FileEntry::compute_checksum(data);
        let entry = FileEntry::new("test.txt", checksum, data.len() as u64);

        assert!(entry.verify(data));
        assert!(!entry.verify(b"different data"));
    }

    #[test]
    fn test_file_entry_with_mime() {
        let entry =
            FileEntry::new("test.json", "a".repeat(64), 100).with_mime_type("application/json");

        assert_eq!(entry.mime_type, Some("application/json".to_string()));
    }
}
