//! Bundle writer for creating .ptb files.
//!
//! Creates ZIP archives with manifest and checksums.

use crate::encryption;
use crate::{BundleError, BundleManifest, BundleProvenanceSummary, FileEntry, Result};
use pt_redact::{ExportProfile, RedactionEngine, RedactionPolicy};
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
    redaction: Option<RedactionEngine>,
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
            redaction: None,
        }
    }

    /// Use an explicit policy/key, including field allowlists for forensic data.
    pub fn with_redaction_engine(mut self, engine: RedactionEngine) -> Self {
        self.redaction = Some(engine);
        self
    }

    /// Sanitize all payloads before opening any output or computing final hashes.
    fn prepare_export(&mut self) -> Result<()> {
        let engine = match self.redaction.take() {
            Some(engine) => engine,
            None => RedactionEngine::new(RedactionPolicy::default())?,
        };
        let profile = self.manifest.export_profile;
        let policy_bytes = serde_json::to_vec(&serde_json::to_value(engine.policy())?)?;
        self.manifest.redaction_policy_version = engine.policy_version().to_string();
        self.manifest.redaction_policy_hash = FileEntry::compute_checksum(&policy_bytes);
        if profile != ExportProfile::Forensic {
            let metadata = engine.redact_json_for_export(
                &serde_json::json!({
                    "session_id": self.manifest.session_id,
                    "host_id": self.manifest.host_id,
                    "description": self.manifest.description,
                    "pt_version": self.manifest.pt_version,
                    "policy_version": self.manifest.redaction_policy_version,
                }),
                profile,
            );
            self.manifest.session_id = metadata["session_id"].as_str().unwrap().to_string();
            self.manifest.host_id = metadata["host_id"].as_str().unwrap().to_string();
            self.manifest.description = metadata["description"].as_str().map(str::to_string);
            self.manifest.pt_version = metadata["pt_version"].as_str().map(str::to_string);
            self.manifest.redaction_policy_version =
                metadata["policy_version"].as_str().unwrap().to_string();
        }

        if profile == ExportProfile::Minimal {
            let mut summary = serde_json::Map::new();
            let aggregate_file = ["summary.json", "plan.json", "session/manifest.json"]
                .iter()
                .find_map(|name| self.files.iter().find(|(path, _)| path == name));
            if let Some((_, bytes)) = aggregate_file {
                let value: serde_json::Value = serde_json::from_slice(bytes)?;
                let aggregate = value.get("summary").unwrap_or(&value);
                if let Some(fields) = aggregate.as_object() {
                    for (key, value) in fields {
                        if is_aggregate_field(key) && value.is_number() {
                            summary.insert(key.clone(), value.clone());
                        }
                    }
                }
            }
            self.files = vec![(
                "summary.json".to_string(),
                serde_json::to_vec_pretty(&summary)?,
            )];
            self.manifest.provenance = None;
        } else {
            for (path, bytes) in &mut self.files {
                let file_type = self
                    .manifest
                    .find_file(path)
                    .and_then(|entry| entry.mime_type.as_deref());
                match file_type {
                    Some("application/json") => {
                        let value = serde_json::from_slice(bytes)?;
                        let mut sanitized = engine.redact_json_for_export(&value, profile);
                        refresh_payload_integrity(&mut sanitized)?;
                        *bytes = serde_json::to_vec_pretty(&sanitized)?;
                    }
                    Some("application/x-ndjson") => {
                        let mut sanitized = Vec::new();
                        for line in bytes.split(|byte| *byte == b'\n') {
                            if line.iter().all(u8::is_ascii_whitespace) {
                                continue;
                            }
                            let value = serde_json::from_slice(line)?;
                            serde_json::to_writer(
                                &mut sanitized,
                                &engine.redact_json_for_export(&value, profile),
                            )?;
                            sanitized.push(b'\n');
                        }
                        *bytes = sanitized;
                    }
                    _ if profile == ExportProfile::Forensic => {}
                    _ => {
                        return Err(BundleError::UnsanitizedPayload {
                            path: path.clone(),
                            profile: profile.to_string(),
                        })
                    }
                }
            }
            if let Some(provenance) = &mut self.manifest.provenance {
                // The saved audit described pre-export bytes and cannot attest
                // to the newly redacted graph. Keep actual counts, clear that hash.
                provenance.integrity_sha256 = None;
                provenance
                    .redacted_sections
                    .push("bundle payload strings".to_string());
                provenance.compatibility_notes = vec![
                    "Bundle payloads were redacted during export; source audit hashes describe the original session.".to_string(),
                ];
                if profile == ExportProfile::Safe {
                    let versions = engine.redact_json_for_export(
                        &serde_json::json!({
                            "schema_version": provenance.provenance_schema_version,
                            "policy_version": provenance.privacy_version,
                        }),
                        profile,
                    );
                    provenance.provenance_schema_version =
                        versions["schema_version"].as_str().map(str::to_string);
                    provenance.privacy_version =
                        versions["policy_version"].as_str().map(str::to_string);
                    provenance.snapshot_path =
                        export_artifact_path(&engine, &provenance.snapshot_path);
                    provenance.audit_path = provenance
                        .audit_path
                        .as_ref()
                        .map(|path| export_artifact_path(&engine, path));
                    for section in provenance
                        .persisted_sections
                        .iter_mut()
                        .chain(provenance.redacted_sections.iter_mut())
                        .chain(provenance.omitted_sections.iter_mut())
                    {
                        let value = engine.redact_json_for_export(
                            &serde_json::json!({"description": section}),
                            profile,
                        );
                        *section = value["description"].as_str().unwrap().to_string();
                    }
                }
            }
            if profile == ExportProfile::Safe {
                for ((path, _), entry) in self.files.iter_mut().zip(&mut self.manifest.files) {
                    let exported_path = export_artifact_path(&engine, path);
                    *path = exported_path.clone();
                    entry.path = exported_path;
                }
            }
        }

        for entry in &mut self.manifest.files {
            if let Some((_, bytes)) = self.files.iter().find(|(path, _)| path == &entry.path) {
                entry.sha256 = FileEntry::compute_checksum(bytes);
                entry.bytes = bytes.len() as u64;
            }
        }
        self.manifest
            .files
            .retain(|entry| self.files.iter().any(|(path, _)| path == &entry.path));
        if profile == ExportProfile::Minimal {
            let bytes = &self.files[0].1;
            let mut entry = FileEntry::new(
                "summary.json",
                FileEntry::compute_checksum(bytes),
                bytes.len() as u64,
            );
            entry.mime_type = Some(FileType::Json.mime_type().to_string());
            self.manifest.files = vec![entry];
        }
        Ok(())
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

    /// Set bundle-level provenance metadata.
    pub fn with_provenance(mut self, provenance: BundleProvenanceSummary) -> Self {
        self.manifest = self.manifest.with_provenance(provenance);
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

    /// Add the canonical provenance snapshot.
    pub fn add_provenance_snapshot<T: serde::Serialize>(&mut self, snapshot: &T) -> Result<()> {
        self.add_json("scan/provenance.json", snapshot)
    }

    /// Add the provenance audit sidecar.
    pub fn add_provenance_audit<T: serde::Serialize>(&mut self, audit: &T) -> Result<()> {
        self.add_json("scan/provenance_audit.json", audit)
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

        self.prepare_export()?;

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

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("ptb.tmp");
        std::fs::write(&tmp_path, encrypted)?;
        std::fs::rename(&tmp_path, path)?;

        Ok(manifest)
    }

    /// Write the bundle to a byte vector (for in-memory use).
    pub fn write_to_vec(mut self) -> Result<(Vec<u8>, BundleManifest)> {
        if self.files.is_empty() {
            return Err(BundleError::EmptyBundle);
        }

        self.prepare_export()?;

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

fn is_aggregate_field(field: &str) -> bool {
    matches!(
        field,
        "total"
            | "count"
            | "total_processes"
            | "total_processes_scanned"
            | "candidates_evaluated"
            | "candidates_returned"
            | "kill_recommendations"
            | "review_recommendations"
            | "policy_blocked"
            | "protected_by_rule"
            | "total_system_processes"
            | "protected_filtered"
            | "record_count"
            | "candidate_count"
            | "action_count"
            | "kill_count"
            | "review_count"
            | "spare_count"
            | "scanned"
            | "evaluated"
            | "above_threshold"
            | "protected_count"
            | "total_candidates"
            | "total_actions"
            | "successful"
            | "failed"
            | "skipped"
            | "candidates"
            | "kills"
            | "spares"
    )
}

fn refresh_payload_integrity(value: &mut serde_json::Value) -> Result<()> {
    if value.get("integrity_sha256").is_some() {
        if let Some(payload) = value.get("payload") {
            let digest = FileEntry::compute_checksum(&serde_json::to_vec(payload)?);
            value["integrity_sha256"] = serde_json::Value::String(digest);
        }
    }
    Ok(())
}

fn export_artifact_path(engine: &RedactionEngine, path: &str) -> String {
    if matches!(
        path,
        "summary.json"
            | "plan.json"
            | "snapshot.json"
            | "data.json"
            | "test.json"
            | "session/context.json"
            | "session/manifest.json"
            | "scan/inventory.json"
            | "scan/provenance.json"
            | "scan/provenance_audit.json"
            | "inference/results.json"
            | "inference/posteriors.json"
            | "logs/events.jsonl"
            | "logs/outcomes.jsonl"
            | "logs/session.jsonl"
            | "signatures/user_signatures.json"
    ) {
        return path.to_string();
    }
    let redacted =
        engine.redact_json_for_export(&serde_json::json!({"path": path}), ExportProfile::Safe);
    let pseudonym: String = redacted["path"]
        .as_str()
        .unwrap()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let extension = match FileType::from_path(path) {
        FileType::Json => "json",
        FileType::Log => "jsonl",
        FileType::Parquet => "parquet",
        FileType::Html => "html",
        FileType::Binary => "bin",
    };
    format!("artifact-{pseudonym}.{extension}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn canary_writer(profile: ExportProfile) -> BundleWriter {
        let engine = RedactionEngine::with_key(
            RedactionPolicy::default(),
            pt_redact::KeyMaterial::from_bytes([9; 32], "export-test"),
        );
        let mut writer =
            BundleWriter::new("private-customer-session", "private-customer-host", profile)
                .with_description("private-customer-description")
                .with_redaction_engine(engine)
                .with_provenance(BundleProvenanceSummary {
                    snapshot_path: "private-customer/provenance.json".to_string(),
                    audit_path: Some("private-customer/audit.json".to_string()),
                    provenance_schema_version: Some("private-customer-version".to_string()),
                    privacy_version: Some("private-customer-policy".to_string()),
                    integrity_sha256: Some("a".repeat(64)),
                    node_count: Some(1),
                    edge_count: Some(0),
                    evidence_count: Some(1),
                    redacted_evidence_count: Some(0),
                    missing_or_conflicted_evidence_count: Some(0),
                    warning_count: Some(0),
                    persisted_sections: vec!["private-customer-section".to_string()],
                    redacted_sections: Vec::new(),
                    omitted_sections: Vec::new(),
                    compatibility_notes: vec!["private-customer-note".to_string()],
                });
        writer
            .add_summary(&serde_json::json!({"candidate_count": 1, "total": 42}))
            .unwrap();
        writer.add_plan(&serde_json::json!({
            "candidates": [{
                "pid": 1234, "score": 87, "recommended_action": "KILL",
                "posterior": {"useful": 0.1, "useful_bad": 0.03, "abandoned": 0.8, "zombie": 0.07},
                "cmd": "python /home/private-customer/job.py",
                "hostname": "private-customer-host",
                "cwd": "/home/private-customer/work",
                "environment": {"TOKEN": "AKIAIOSFODNN7EXAMPLE"}
            }]
        })).unwrap();
        writer.add_log("outcomes", b"{\"pid\":1234,\"action\":\"kill\",\"cmd\":\"python /home/private-customer/job.py\",\"success\":true}\n".to_vec());
        writer
            .add_json("private-customer.json", &serde_json::json!({"score": 87}))
            .unwrap();
        for path in [
            "private-customer/provenance.json",
            "private-customer/audit.json",
        ] {
            writer
                .add_json(path, &serde_json::json!({"node_count": 1}))
                .unwrap();
        }
        writer
    }

    #[test]
    fn safe_export_sanitizes_actual_zip_and_preserves_evidence() {
        let (bytes, manifest) = canary_writer(ExportProfile::Safe).write_to_vec().unwrap();
        let mut reader = crate::BundleReader::from_bytes(bytes).unwrap();
        assert!(reader.verify_all().is_empty());
        let mut exported = manifest.to_json().unwrap();
        for entry in &manifest.files {
            let bytes = reader.read_verified(&entry.path).unwrap();
            assert_eq!(entry.sha256, FileEntry::compute_checksum(&bytes));
            assert_eq!(entry.bytes, bytes.len() as u64);
            exported.push_str(std::str::from_utf8(&bytes).unwrap());
        }
        for canary in ["private-customer", "AKIAIOSFODNN7EXAMPLE"] {
            assert!(!exported.contains(canary), "ZIP leaked {canary}");
        }
        let plan: serde_json::Value = reader.read_json("plan.json").unwrap();
        assert_eq!(plan["candidates"][0]["pid"], 1234);
        assert_eq!(plan["candidates"][0]["score"], 87);
        assert_eq!(plan["candidates"][0]["posterior"]["useful_bad"], 0.03);
        assert_eq!(plan["candidates"][0]["recommended_action"], "KILL");
        let log = reader.read_raw("logs/outcomes.jsonl").unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(&log).unwrap();
        assert_eq!(outcome["cmd"], plan["candidates"][0]["cmd"]);
        assert_eq!(outcome["success"], true);
    }

    #[test]
    fn minimal_export_omits_process_data_and_keeps_actual_aggregate_counts() {
        let (bytes, manifest) = canary_writer(ExportProfile::Minimal)
            .write_to_vec()
            .unwrap();
        assert_eq!(manifest.file_count(), 1);
        assert_eq!(manifest.files[0].path, "summary.json");
        let mut reader = crate::BundleReader::from_bytes(bytes).unwrap();
        let summary: serde_json::Value = reader.read_summary().unwrap();
        assert_eq!(
            summary,
            serde_json::json!({"candidate_count": 1, "total": 42})
        );
        assert!(!reader.has_file("plan.json"));
        assert!(!reader.has_file("logs/outcomes.jsonl"));
        assert!(reader.verify_all().is_empty());
    }

    #[test]
    fn memory_file_and_encrypted_exports_use_the_same_sanitized_payloads() {
        let dir = TempDir::new().unwrap().keep();
        let file_path = dir.join("safe.ptb");
        let encrypted_path = dir.join("encrypted.ptb");
        let (bytes, manifest) = canary_writer(ExportProfile::Safe).write_to_vec().unwrap();
        canary_writer(ExportProfile::Safe)
            .write(&file_path)
            .unwrap();
        canary_writer(ExportProfile::Safe)
            .write_encrypted(&encrypted_path, "export-test-passphrase")
            .unwrap();
        let mut memory = crate::BundleReader::from_bytes(bytes).unwrap();
        let mut disk = crate::BundleReader::open(&file_path).unwrap();
        let mut encrypted = crate::BundleReader::open_with_passphrase(
            &encrypted_path,
            Some("export-test-passphrase"),
        )
        .unwrap();
        for entry in manifest.files {
            let expected = memory.read_verified(&entry.path).unwrap();
            assert_eq!(disk.read_verified(&entry.path).unwrap(), expected);
            assert_eq!(encrypted.read_verified(&entry.path).unwrap(), expected);
        }
    }

    #[test]
    fn sharing_refuses_opaque_or_malformed_data_before_creating_output() {
        let dir = TempDir::new().unwrap().keep();
        let path = dir.join("must-not-exist.ptb");
        let mut writer = BundleWriter::new("session", "host", ExportProfile::Safe);
        writer.add_telemetry("audit", b"PAR1private-customer".to_vec());
        assert!(matches!(
            writer.write(&path),
            Err(BundleError::UnsanitizedPayload { .. })
        ));
        assert!(!path.exists());
        let mut writer = BundleWriter::new("session", "host", ExportProfile::Safe);
        writer.add_log("outcomes", b"not-json private-customer".to_vec());
        assert!(matches!(
            writer.write_encrypted(&path, "test"),
            Err(BundleError::Json(_))
        ));
        assert!(!path.exists());
        let mut forensic = BundleWriter::new("session", "host", ExportProfile::Forensic);
        forensic.add_telemetry("audit", b"PAR1private-customer".to_vec());
        let (bytes, _) = forensic.write_to_vec().unwrap();
        let mut reader = crate::BundleReader::from_bytes(bytes).unwrap();
        assert_eq!(
            reader.read_telemetry("audit").unwrap(),
            b"PAR1private-customer"
        );
    }

    #[test]
    fn export_recomputes_saved_envelope_integrity_after_redaction() {
        let mut writer = BundleWriter::new("session", "host", ExportProfile::Safe);
        writer
            .add_json(
                "inference/results.json",
                &serde_json::json!({
                    "integrity_sha256": "a".repeat(64),
                    "payload": {"pid": 1234, "cmd": "private-customer-command", "score": 87}
                }),
            )
            .unwrap();
        let (bytes, _) = writer.write_to_vec().unwrap();
        let mut reader = crate::BundleReader::from_bytes(bytes).unwrap();
        let envelope: serde_json::Value = reader.read_json("inference/results.json").unwrap();
        assert_eq!(
            envelope["integrity_sha256"],
            FileEntry::compute_checksum(&serde_json::to_vec(&envelope["payload"]).unwrap())
        );
        assert_eq!(envelope["payload"]["score"], 87);
        assert!(!envelope.to_string().contains("private-customer"));
    }

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
    fn test_bundle_writer_add_provenance_files() {
        let mut writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Safe);

        writer
            .add_provenance_snapshot(&serde_json::json!({"schema_version": "1.0.0"}))
            .unwrap();
        writer
            .add_provenance_audit(&serde_json::json!({"artifact_path": "scan/provenance.json"}))
            .unwrap();

        assert!(writer
            .manifest()
            .find_file("scan/provenance.json")
            .is_some());
        assert!(writer
            .manifest()
            .find_file("scan/provenance_audit.json")
            .is_some());
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
        let temp_dir = TempDir::new().unwrap().keep();
        let bundle_path = temp_dir.join("test.ptb");

        let mut writer =
            BundleWriter::new("pt-20261004-120000-abcd", "host-abc", ExportProfile::Safe)
                .with_pt_version("0.1.0");

        writer
            .add_summary(&serde_json::json!({"total": 42}))
            .unwrap();
        writer
            .add_json("data.json", &serde_json::json!({"count": 7}))
            .unwrap();

        let manifest = writer.write(&bundle_path).unwrap();

        assert!(bundle_path.exists());
        assert_eq!(manifest.file_count(), 2);
        assert_eq!(manifest.session_id, "pt-20261004-120000-abcd");
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
        let mut writer1 = BundleWriter::new("session", "host", ExportProfile::Forensic);
        writer1.add_file("z.txt", b"z".to_vec(), None);
        writer1.add_file("a.txt", b"a".to_vec(), None);
        writer1.add_file("m.txt", b"m".to_vec(), None);

        let mut writer2 = BundleWriter::new("session", "host", ExportProfile::Forensic);
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

    #[test]
    fn test_bundle_writer_with_provenance_metadata() {
        let writer = BundleWriter::new("session-123", "host-abc", ExportProfile::Forensic)
            .with_provenance(BundleProvenanceSummary {
                snapshot_path: "scan/provenance.json".to_string(),
                audit_path: Some("scan/provenance_audit.json".to_string()),
                provenance_schema_version: Some("1.0.0".to_string()),
                privacy_version: Some("1.0.0".to_string()),
                integrity_sha256: Some("a".repeat(64)),
                node_count: Some(10),
                edge_count: Some(9),
                evidence_count: Some(11),
                redacted_evidence_count: Some(2),
                missing_or_conflicted_evidence_count: Some(1),
                warning_count: Some(0),
                persisted_sections: vec!["graph.nodes".to_string()],
                redacted_sections: vec!["graph.evidence".to_string()],
                omitted_sections: vec![],
                compatibility_notes: vec!["redacted export".to_string()],
            });

        assert!(writer.manifest().provenance.is_some());
    }
}
