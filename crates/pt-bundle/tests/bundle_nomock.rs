//! No-mock bundle integration tests for bd-yaps.
//!
//! Exercises real bundle creation, verification, and profile handling:
//! - All 3 export profiles (Minimal, Safe, Forensic)
//! - Multi-file bundles with mixed content types
//! - Manifest checksums verify on read-back
//! - Encrypted bundle roundtrip
//! - JSONL log schema validation
//! - Bundle schema version presence

use chrono::Utc;
use pt_bundle::{BundleError, BundleReader, BundleWriter, BUNDLE_SCHEMA_VERSION};
use pt_redact::{ExportProfile, RedactionPolicy};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Build structured content, with opaque archive payloads only under Forensic.
fn build_full_bundle(
    profile: ExportProfile,
    include_opaque_telemetry: bool,
) -> (Vec<u8>, pt_bundle::BundleManifest) {
    let mut writer = BundleWriter::new("pt-20260115-143022-abcd", "host-test", profile)
        .with_pt_version("2.0.0-test")
        .with_redaction_policy("1.0.0", "sha256-test-hash")
        .with_description("No-mock integration test bundle");

    writer
        .add_summary(&json!({
            "total_processes": 200,
            "candidates": 8,
            "kills": 3,
            "spares": 5,
            "schema_version": "1.0.0"
        }))
        .expect("add summary");

    writer
        .add_plan(&json!({
            "recommendations": [
                {"pid": 1234, "action": "kill", "confidence": 0.97},
                {"pid": 5678, "action": "spare", "confidence": 0.85}
            ]
        }))
        .expect("add plan");

    // Opaque bytes exercise ZIP packaging, not Parquet validity or sanitization.
    let artifacts = if include_opaque_telemetry {
        assert_eq!(profile, ExportProfile::Forensic);
        writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31]);
        writer.add_telemetry("proc_samples", vec![0x50, 0x41, 0x52, 0x31, 0x00, 0x01]);
        json!([
            {"path": "telemetry/audit.parquet", "kind": "parquet"},
            {"path": "telemetry/proc_samples.parquet", "kind": "parquet"}
        ])
    } else {
        json!([
            {"path": "summary.json", "kind": "json"},
            {"path": "plan.json", "kind": "json"}
        ])
    };

    let log_entry = json!({
        "event": "bundle_test",
        "timestamp": Utc::now().to_rfc3339(),
        "phase": "bundle",
        "case_id": "nomock-1",
        "command": "pt bundle create",
        "exit_code": 0,
        "duration_ms": 42,
        "artifacts": artifacts
    });
    let log_jsonl = format!("{}\n", log_entry);
    writer.add_log("events", log_jsonl.into_bytes());

    writer.write_to_vec().expect("write bundle")
}

/// Validate JSONL log schema (same schema as bundle_pipeline_nomock).
fn validate_jsonl_schema(line: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "expected json object".to_string())?;

    let required = [
        "event",
        "timestamp",
        "phase",
        "case_id",
        "command",
        "exit_code",
        "duration_ms",
        "artifacts",
    ];

    for field in required {
        if !obj.contains_key(field) {
            return Err(format!("missing field: {field}"));
        }
    }

    // Validate artifacts is an array of objects with path + kind
    if let Some(artifacts) = obj.get("artifacts").and_then(|v| v.as_array()) {
        for (i, artifact) in artifacts.iter().enumerate() {
            let a = artifact
                .as_object()
                .ok_or_else(|| format!("artifact[{}] not an object", i))?;
            if !a.contains_key("path") {
                return Err(format!("artifact[{}] missing 'path'", i));
            }
            if !a.contains_key("kind") {
                return Err(format!("artifact[{}] missing 'kind'", i));
            }
        }
    }

    Ok(())
}

// ============================================================================
// Export Profile Tests
// ============================================================================

#[test]
fn test_bundle_all_profiles_create_and_verify() {
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let (bytes, manifest) = build_full_bundle(profile, false);

        // Verify bundle is a valid ZIP
        assert_eq!(&bytes[0..2], b"PK", "Profile {:?}: not a ZIP", profile);

        // Verify manifest metadata
        assert_eq!(manifest.export_profile, profile);
        assert_eq!(manifest.session_id, "pt-20260115-143022-abcd");
        if profile == ExportProfile::Forensic {
            assert_eq!(manifest.host_id, "host-test");
            assert_eq!(
                manifest.description,
                Some("No-mock integration test bundle".to_string())
            );
        } else {
            assert_ne!(manifest.host_id, "host-test");
            assert!(!manifest.host_id.is_empty());
            let description = manifest.description.as_deref().expect("description");
            assert!(!description.is_empty());
            assert!(!description.contains("No-mock integration test bundle"));
        }
        assert_eq!(manifest.bundle_version, BUNDLE_SCHEMA_VERSION);
        assert_eq!(manifest.pt_version, Some("2.0.0-test".to_string()));

        // Read back and verify all files
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");
        assert_eq!(reader.export_profile(), profile);
        let summary: serde_json::Value = reader.read_summary().expect("read summary");
        assert_eq!(summary["total_processes"], 200);
        assert_eq!(summary["candidates"], 8);
        if profile == ExportProfile::Minimal {
            assert_eq!(manifest.file_count(), 1);
            assert_eq!(
                summary,
                json!({"total_processes": 200, "candidates": 8, "kills": 3, "spares": 5})
            );
            assert!(!reader.has_file("plan.json"));
            assert!(!reader.has_file("logs/events.jsonl"));
        } else {
            assert_eq!(manifest.file_count(), 3);
            assert_eq!(summary["schema_version"], "1.0.0");
            let plan: serde_json::Value = reader.read_plan().expect("read plan").expect("plan");
            assert_eq!(plan["recommendations"][0]["pid"], 1234);
            assert_eq!(plan["recommendations"][0]["action"], "kill");
            assert!(reader.has_file("logs/events.jsonl"));
        }

        let failures = reader.verify_all();
        assert!(
            failures.is_empty(),
            "Profile {:?}: verification failures: {:?}",
            profile,
            failures
        );

        eprintln!(
            "[INFO] Profile {:?}: {} files verified",
            profile,
            manifest.file_count()
        );
    }
}

#[test]
fn test_bundle_manifest_checksums_match() {
    let (bytes, manifest) = build_full_bundle(ExportProfile::Forensic, true);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    // Verify each file individually
    for entry in manifest.files.iter() {
        let data = reader
            .read_verified(&entry.path)
            .unwrap_or_else(|e| panic!("Checksum mismatch for {}: {}", entry.path, e));

        assert_eq!(
            data.len() as u64,
            entry.bytes,
            "Size mismatch for {}",
            entry.path
        );

        eprintln!(
            "[INFO] Verified {}: {} bytes, sha256={}...",
            entry.path,
            entry.bytes,
            &entry.sha256[..16]
        );
    }
}

#[test]
fn test_bundle_schema_version_present() {
    let (bytes, manifest) = build_full_bundle(ExportProfile::Safe, false);

    // Bundle version must be present and match constant
    assert_eq!(manifest.bundle_version, BUNDLE_SCHEMA_VERSION);
    assert!(!manifest.bundle_version.is_empty());
    assert!(
        manifest.bundle_version.contains('.'),
        "schema version should be semver: {}",
        manifest.bundle_version
    );

    // Read back and verify it persists
    let reader = BundleReader::from_bytes(bytes).expect("open bundle");
    assert_eq!(reader.manifest().bundle_version, BUNDLE_SCHEMA_VERSION);
}

// ============================================================================
// Multi-File Bundle Tests
// ============================================================================

#[test]
fn test_bundle_multi_file_content_types() {
    let (bytes, manifest) = build_full_bundle(ExportProfile::Forensic, true);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    // Verify expected files are present
    assert!(reader.has_file("summary.json"), "missing summary.json");
    assert!(reader.has_file("plan.json"), "missing plan.json");
    assert!(
        reader.has_file("telemetry/audit.parquet"),
        "missing audit parquet"
    );
    assert!(
        reader.has_file("telemetry/proc_samples.parquet"),
        "missing proc_samples parquet"
    );
    assert!(reader.has_file("logs/events.jsonl"), "missing events log");

    // Total file count
    assert_eq!(manifest.file_count(), 5, "expected 5 files in bundle");

    // Read summary as JSON
    let summary: serde_json::Value = reader.read_summary().expect("read summary");
    assert_eq!(summary["total_processes"], 200);
    assert_eq!(summary["candidates"], 8);

    // Read plan
    let plan: Option<serde_json::Value> = reader.read_plan().expect("read plan");
    assert!(plan.is_some());
    let plan = plan.unwrap();
    assert!(plan["recommendations"].is_array());

    // Telemetry files
    let telemetry = reader.telemetry_files();
    assert_eq!(telemetry.len(), 2, "expected 2 telemetry files");

    // Log files
    let logs = reader.log_files();
    assert_eq!(logs.len(), 1, "expected 1 log file");
}

#[test]
fn test_bundle_jsonl_log_schema_valid() {
    let (bytes, _) = build_full_bundle(ExportProfile::Safe, false);
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    let log_bytes = reader.read_verified("logs/events.jsonl").expect("read log");
    let log_text = String::from_utf8(log_bytes).expect("log utf8");

    let mut line_count = 0;
    for (line_num, line) in log_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        validate_jsonl_schema(line)
            .unwrap_or_else(|err| panic!("JSONL schema error line {}: {}", line_num + 1, err));
        line_count += 1;
    }

    assert!(line_count > 0, "log file should have at least one entry");
    eprintln!("[INFO] Validated {} JSONL log lines", line_count);
}

// ============================================================================
// Encryption Roundtrip Tests
// ============================================================================

#[test]
fn test_bundle_encrypted_roundtrip_all_profiles() {
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let temp_dir = TempDir::new().expect("temp dir");
        let bundle_path = temp_dir.path().join("encrypted.ptb");
        let passphrase = "test-passphrase-for-nomock";

        // Build and encrypt
        let mut writer = BundleWriter::new("pt-20261004-120000-abcd", "host-enc", profile)
            .with_pt_version("2.0.0");
        writer
            .add_summary(&json!({"total_processes": 12, "candidates": 2}))
            .expect("add summary");
        writer
            .add_plan(&json!({"recommendations": [{"pid": 1234, "action": "spare"}]}))
            .expect("add plan");
        writer.add_log(
            "events",
            b"{\"event\":\"encryption_test\",\"exit_code\":0}\n".to_vec(),
        );

        let manifest = writer
            .write_encrypted(&bundle_path, passphrase)
            .expect("write encrypted");

        // Verify file exists and is encrypted (not a ZIP)
        let raw_bytes = std::fs::read(&bundle_path).expect("read raw");
        assert_ne!(
            &raw_bytes[0..2],
            b"PK",
            "Encrypted file should not look like a ZIP"
        );

        // Open with passphrase
        let mut reader =
            BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
        assert_eq!(reader.session_id(), "pt-20261004-120000-abcd");
        assert_eq!(reader.export_profile(), profile);
        let summary: serde_json::Value = reader.read_summary().expect("read summary");
        assert_eq!(summary, json!({"total_processes": 12, "candidates": 2}));
        if profile == ExportProfile::Minimal {
            assert_eq!(manifest.file_count(), 1);
            assert!(!reader.has_file("plan.json"));
            assert!(!reader.has_file("logs/events.jsonl"));
        } else {
            assert_eq!(manifest.file_count(), 3);
            let plan: serde_json::Value = reader.read_plan().expect("read plan").expect("plan");
            assert_eq!(plan["recommendations"][0]["action"], "spare");
            assert!(reader.has_file("logs/events.jsonl"));
        }

        let failures = reader.verify_all();
        assert!(
            failures.is_empty(),
            "Profile {:?} encrypted: verification failures: {:?}",
            profile,
            failures
        );

        // Wrong passphrase should fail
        let err = BundleReader::open_with_passphrase(&bundle_path, Some("wrong"));
        assert!(err.is_err(), "Wrong passphrase should fail");

        // No passphrase should fail
        let err = BundleReader::open(&bundle_path);
        assert!(
            err.is_err(),
            "Opening encrypted without passphrase should fail"
        );

        eprintln!(
            "[INFO] Encrypted roundtrip {:?}: {} files, {} bytes",
            profile,
            manifest.file_count(),
            raw_bytes.len()
        );
    }
}

// ============================================================================
// Artifact Manifest Tests
// ============================================================================

#[test]
fn test_bundle_artifact_manifest_completeness() {
    let (_, manifest) = build_full_bundle(ExportProfile::Forensic, true);

    // Every file must have non-empty sha256, non-zero bytes, and valid path
    for entry in manifest.files.iter() {
        assert!(!entry.path.is_empty(), "path should not be empty");
        assert!(
            !entry.sha256.is_empty(),
            "sha256 should not be empty for {}",
            entry.path
        );
        assert!(entry.bytes > 0, "bytes should be > 0 for {}", entry.path);
        assert!(
            !entry.path.starts_with('/'),
            "path should be relative: {}",
            entry.path
        );
        assert!(
            !entry.path.contains(".."),
            "path should not traverse: {}",
            entry.path
        );

        // MIME type should be present
        assert!(
            entry.mime_type.is_some(),
            "mime_type should be set for {}",
            entry.path
        );
    }

    // Metadata describes the policy actually applied, overriding caller claims.
    let policy = RedactionPolicy::default();
    let canonical_policy = serde_json::to_value(&policy).expect("policy value");
    let policy_bytes = serde_json::to_vec(&canonical_policy).expect("policy bytes");
    assert_eq!(manifest.redaction_policy_version, policy.schema_version);
    assert_eq!(
        manifest.redaction_policy_hash,
        format!("{:x}", Sha256::digest(&policy_bytes))
    );
    assert_ne!(manifest.redaction_policy_hash, "sha256-test-hash");

    eprintln!(
        "[INFO] Artifact manifest: {} entries, all valid",
        manifest.file_count()
    );
}

#[test]
fn test_bundle_file_on_disk_verify_all() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("on-disk.ptb");

    // Write to disk
    let mut writer = BundleWriter::new("session-disk", "host-disk", ExportProfile::Forensic)
        .with_pt_version("2.0.0");
    writer
        .add_summary(&json!({"disk_test": true}))
        .expect("add summary");
    writer.add_telemetry("audit", vec![10, 20, 30, 40]);
    writer.add_log("events", b"{\"event\":\"disk_test\"}\n".to_vec());

    let manifest = writer.write(&bundle_path).expect("write to disk");
    assert!(bundle_path.exists());

    // Read from disk and verify
    let mut reader = BundleReader::open(&bundle_path).expect("open from disk");
    assert_eq!(reader.session_id(), "session-disk");

    let failures = reader.verify_all();
    assert!(
        failures.is_empty(),
        "On-disk verification failures: {:?}",
        failures
    );

    eprintln!(
        "[INFO] On-disk bundle: {} files, {} bytes on disk",
        manifest.file_count(),
        std::fs::metadata(&bundle_path).unwrap().len()
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_bundle_empty_bundle_rejected() {
    let writer = BundleWriter::new("session-empty", "host-empty", ExportProfile::Safe);
    let result = writer.write_to_vec();
    assert!(result.is_err(), "Empty bundle should be rejected");
}

#[test]
fn test_bundle_single_file_minimal() {
    let mut writer = BundleWriter::new("session-min", "host-min", ExportProfile::Minimal);
    writer
        .add_summary(&json!({
            "total_processes": 5,
            "candidates": 1,
            "kills": "private nonnumeric count",
            "pid": 1234,
            "command": "private-worker --token=canary",
            "records": [{"pid": 1234}]
        }))
        .expect("add summary");
    writer
        .add_plan(&json!({"recommendations": [{"pid": 1234, "action": "kill"}]}))
        .expect("add plan");
    writer.add_telemetry("audit", b"opaque private telemetry".to_vec());
    writer.add_log("events", b"private unstructured log".to_vec());

    let (bytes, manifest) = writer.write_to_vec().expect("write");

    assert_eq!(manifest.file_count(), 1);
    assert_eq!(manifest.export_profile, ExportProfile::Minimal);

    let mut reader = BundleReader::from_bytes(bytes).expect("open");
    let summary: serde_json::Value = reader.read_summary().expect("read summary");
    assert_eq!(summary, json!({"total_processes": 5, "candidates": 1}));
    assert!(!reader.has_file("plan.json"));
    assert!(reader.telemetry_files().is_empty());
    assert!(reader.log_files().is_empty());
    assert!(reader.verify_all().is_empty());
}

#[test]
fn test_bundle_large_telemetry_data() {
    let mut writer = BundleWriter::new("session-large", "host-large", ExportProfile::Forensic);

    // 1MB of telemetry data
    let large_data = vec![0xABu8; 1024 * 1024];
    writer.add_telemetry("proc_samples", large_data.clone());
    writer
        .add_summary(&json!({"large": true}))
        .expect("add summary");

    let (bytes, _) = writer.write_to_vec().expect("write");

    // Should compress significantly
    assert!(
        bytes.len() < large_data.len(),
        "Compressed bundle ({}) should be smaller than raw data ({})",
        bytes.len(),
        large_data.len()
    );

    // Verify roundtrip
    let mut reader = BundleReader::from_bytes(bytes).expect("open");
    let read_data = reader
        .read_verified("telemetry/proc_samples.parquet")
        .expect("read telemetry");
    assert_eq!(read_data, large_data);
}

#[test]
fn test_safe_opaque_payload_refused_before_destination_creation() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("refused.ptb");
    let mut writer = BundleWriter::new("session-refused", "host-refused", ExportProfile::Safe);
    writer
        .add_summary(&json!({"total_processes": 1}))
        .expect("add summary");
    writer.add_telemetry("audit", b"opaque private telemetry".to_vec());

    let result = writer.write(&bundle_path);
    assert!(matches!(
        result,
        Err(BundleError::UnsanitizedPayload { path, profile })
            if path == "telemetry/audit.parquet" && profile == "safe"
    ));
    assert!(!bundle_path.exists(), "refusal must not create an output");
}
