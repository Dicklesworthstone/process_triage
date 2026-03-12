//! E2E tests for bundle creation → report generation pipeline.
//!
//! Validates:
//! - Pipeline produces bundle + report deterministically per profile
//! - Artifact manifest includes .ptb, report HTML
//! - JSONL schema validation passes for pipeline events
//! - Report HTML includes required sections
//! - Redaction integrity through full pipeline
//! - Checksum verification at each stage
//!
//! See: bd-v1y1

use arrow::array::{Int32Array, StringArray, TimestampMicrosecondArray};
use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use chrono::Utc;
use pt_bundle::{BundleReader, BundleWriter, BUNDLE_SCHEMA_VERSION};
use pt_redact::{ExportProfile, FieldClass, KeyMaterial, RedactionEngine, RedactionPolicy};
use pt_report::{ReportConfig, ReportGenerator, ReportTheme};
use pt_telemetry::schema::{audit_schema, TableName};
use pt_telemetry::writer::{BatchedWriter, WriterConfig};
use serde_json::json;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Create a realistic audit batch for pipeline testing.
fn create_audit_batch(schema: &Schema, session_id: &str) -> RecordBatch {
    let audit_ts =
        TimestampMicrosecondArray::from(vec![Utc::now().timestamp_micros()]).with_timezone("UTC");
    let sess = StringArray::from(vec![session_id]);
    let event_type = StringArray::from(vec!["pipeline_e2e"]);
    let severity = StringArray::from(vec!["info"]);
    let actor = StringArray::from(vec!["system"]);
    let target_pid: Int32Array = Int32Array::from(vec![None::<i32>]);
    let target_start_id: StringArray = StringArray::from(vec![None::<&str>]);
    let message = StringArray::from(vec!["E2E pipeline test entry"]);
    let details_json: StringArray = StringArray::from(vec![None::<&str>]);
    let host_id = StringArray::from(vec!["e2e-test-host"]);

    RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(audit_ts),
            Arc::new(sess),
            Arc::new(event_type),
            Arc::new(severity),
            Arc::new(actor),
            Arc::new(target_pid),
            Arc::new(target_start_id),
            Arc::new(message),
            Arc::new(details_json),
            Arc::new(host_id),
        ],
    )
    .expect("audit batch")
}

/// Validate JSONL pipeline log schema.
fn validate_pipeline_jsonl(line: &str) -> Result<(), String> {
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

    // Validate artifacts array structure
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

/// Run a full pipeline: write telemetry → redact → bundle → verify → report.
/// Returns (bundle_bytes, manifest, report_html).
fn run_full_pipeline(
    profile: ExportProfile,
    temp_dir: &TempDir,
    case_id: &str,
) -> (Vec<u8>, pt_bundle::BundleManifest, String) {
    let session_id = format!("pt-20260205-e2e-{}", case_id);
    let host_id = "e2e-pipeline-host";

    // Step 1: Write real telemetry (audit table)
    let schema = audit_schema();
    let telemetry_dir = temp_dir.path().join(format!("telemetry-{}", case_id));
    let writer_config = WriterConfig::new(telemetry_dir, session_id.clone(), host_id.to_string())
        .with_batch_size(1);
    let mut writer = BatchedWriter::new(TableName::Audit, Arc::new(schema.clone()), writer_config);
    writer
        .write(create_audit_batch(&schema, &session_id))
        .expect("write audit batch");
    let parquet_path = writer.close().expect("close parquet writer");
    let parquet_bytes = fs::read(&parquet_path).expect("read parquet bytes");

    // Step 2: Redact secrets
    let secret = "ghp_SuperSecretGitHubToken12345678901234";
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([42u8; 32], "pipeline-e2e");
    let engine = RedactionEngine::with_key(policy, key);
    let redacted = engine.redact_with_profile(secret, FieldClass::FreeText, profile);

    // Step 3: Build pipeline JSONL log entries
    let log_entries = [
        json!({
            "event": "bundle_create",
            "timestamp": Utc::now().to_rfc3339(),
            "phase": "bundle",
            "case_id": case_id,
            "command": "pt bundle create",
            "exit_code": 0,
            "duration_ms": 42,
            "artifacts": [
                {"path": "telemetry/audit.parquet", "kind": "parquet"},
                {"path": "summary.json", "kind": "json"}
            ]
        }),
        json!({
            "event": "report_generate",
            "timestamp": Utc::now().to_rfc3339(),
            "phase": "report",
            "case_id": case_id,
            "command": "pt agent report",
            "exit_code": 0,
            "duration_ms": 15,
            "artifacts": [
                {"path": "report.html", "kind": "html"}
            ]
        }),
    ];
    let log_jsonl: String = log_entries.iter().map(|e| format!("{}\n", e)).collect();

    // Step 4: Create bundle
    let summary = json!({
        "total_processes": 250,
        "candidates": 10,
        "kills": 4,
        "spares": 6,
        "note": redacted.output,
        "profile": format!("{:?}", profile),
        "session_id": &session_id,
        "schema_version": "1.0.0"
    });

    let plan = json!({
        "recommendations": [
            {"pid": 1001, "action": "kill", "confidence": 0.98, "evidence": ["zombie", "orphan"]},
            {"pid": 1002, "action": "spare", "confidence": 0.72, "evidence": ["active_io"]},
            {"pid": 1003, "action": "kill", "confidence": 0.95, "evidence": ["abandoned_build"]},
        ],
        "schema_version": "1.0.0"
    });

    let mut bundle_writer = BundleWriter::new(&session_id, host_id, profile)
        .with_pt_version("2.0.0-e2e-test")
        .with_redaction_policy("1.0.0", "sha256-e2e-test-hash")
        .with_description(format!("E2E pipeline test: {}", case_id));
    bundle_writer.add_summary(&summary).expect("add summary");
    bundle_writer.add_plan(&plan).expect("add plan");
    bundle_writer.add_telemetry("audit", parquet_bytes);
    bundle_writer.add_log("events", log_jsonl.into_bytes());

    let (bundle_bytes, manifest) = bundle_writer.write_to_vec().expect("write bundle");

    // Step 5: Verify bundle and generate report
    let mut reader = BundleReader::from_bytes(bundle_bytes.clone()).expect("open bundle");
    let failures = reader.verify_all();
    assert!(
        failures.is_empty(),
        "Bundle verification failed for {}: {:?}",
        case_id,
        failures
    );

    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    (bundle_bytes, manifest, html)
}

// ============================================================================
// Full Pipeline Per Profile
// ============================================================================

#[test]
fn test_pipeline_all_profiles_produce_bundle_and_report() {
    let profiles = [
        (ExportProfile::Minimal, "minimal"),
        (ExportProfile::Safe, "safe"),
        (ExportProfile::Forensic, "forensic"),
    ];

    for (profile, name) in profiles {
        let temp_dir = TempDir::new().expect("tempdir");
        let (bundle_bytes, manifest, html) =
            run_full_pipeline(profile, &temp_dir, &format!("profile-{}", name));

        // Bundle is valid ZIP
        assert_eq!(
            &bundle_bytes[0..2],
            b"PK",
            "Profile {:?}: bundle should be a ZIP",
            profile
        );

        // Manifest metadata correct
        assert_eq!(manifest.export_profile, profile);
        assert_eq!(manifest.bundle_version, BUNDLE_SCHEMA_VERSION);
        assert_eq!(manifest.pt_version, Some("2.0.0-e2e-test".to_string()));

        // Report is valid HTML
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Profile {:?}: report should start with DOCTYPE",
            profile
        );
        assert!(
            html.contains("</html>"),
            "Profile {:?}: report should be complete HTML",
            profile
        );

        eprintln!(
            "[INFO] Profile {:?}: bundle={} bytes, manifest={} files, report={} bytes",
            profile,
            bundle_bytes.len(),
            manifest.file_count(),
            html.len()
        );
    }
}

// ============================================================================
// JSONL Schema Validation Through Pipeline
// ============================================================================

#[test]
fn test_pipeline_jsonl_logs_pass_schema_validation() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (bundle_bytes, _, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "jsonl-schema");

    let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");
    let log_bytes = reader.read_verified("logs/events.jsonl").expect("read log");
    let log_text = String::from_utf8(log_bytes).expect("log utf8");

    let mut line_count = 0;
    for (line_num, line) in log_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        validate_pipeline_jsonl(line).unwrap_or_else(|err| {
            panic!(
                "JSONL schema validation failed line {}: {}\n  line: {}",
                line_num + 1,
                err,
                line
            )
        });
        line_count += 1;
    }

    assert_eq!(
        line_count, 2,
        "pipeline should produce 2 log entries (bundle_create + report_generate)"
    );

    // Verify log entries have expected events
    let log_text = {
        let mut reader = BundleReader::from_bytes(
            run_full_pipeline(ExportProfile::Safe, &temp_dir, "jsonl-events").0,
        )
        .expect("open");
        String::from_utf8(reader.read_verified("logs/events.jsonl").unwrap()).unwrap()
    };
    assert!(
        log_text.contains("bundle_create"),
        "log should contain bundle_create event"
    );
    assert!(
        log_text.contains("report_generate"),
        "log should contain report_generate event"
    );

    eprintln!("[INFO] JSONL schema: {} lines validated", line_count);
}

#[test]
fn test_pipeline_jsonl_artifact_paths_match_bundle() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (bundle_bytes, manifest, _) =
        run_full_pipeline(ExportProfile::Safe, &temp_dir, "artifact-match");

    let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");
    let log_bytes = reader.read_verified("logs/events.jsonl").expect("read log");
    let log_text = String::from_utf8(log_bytes).expect("log utf8");

    // Collect all artifact paths from JSONL
    let mut jsonl_artifact_paths: Vec<String> = Vec::new();
    for line in log_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: serde_json::Value = serde_json::from_str(line).expect("parse log entry");
        if let Some(artifacts) = entry["artifacts"].as_array() {
            for artifact in artifacts {
                if let Some(path) = artifact["path"].as_str() {
                    jsonl_artifact_paths.push(path.to_string());
                }
            }
        }
    }

    // Verify referenced artifacts exist in the bundle manifest
    let manifest_paths: Vec<String> = manifest.files.iter().map(|f| f.path.clone()).collect();

    for artifact_path in &jsonl_artifact_paths {
        // report.html is generated after bundle, so it's not in the bundle itself
        if artifact_path == "report.html" {
            continue;
        }
        assert!(
            manifest_paths.contains(artifact_path),
            "JSONL artifact path '{}' should exist in bundle manifest. Manifest paths: {:?}",
            artifact_path,
            manifest_paths
        );
    }

    eprintln!(
        "[INFO] JSONL artifact paths: {} referenced, {} in manifest",
        jsonl_artifact_paths.len(),
        manifest_paths.len()
    );
}

// ============================================================================
// Report HTML Validation
// ============================================================================

#[test]
fn test_pipeline_report_includes_required_sections() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (_, _, html) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "html-sections");

    // Required HTML structure
    assert!(html.contains("<head>"), "report needs <head>");
    assert!(html.contains("<body"), "report needs <body>");
    assert!(
        html.contains("<meta charset=\"UTF-8\">"),
        "report needs UTF-8 charset"
    );
    assert!(html.contains("viewport"), "report needs viewport meta");

    // Required report sections
    assert!(
        html.contains("id=\"tab-overview\""),
        "report needs overview tab"
    );

    // Generator identity
    assert!(
        html.contains("pt-report"),
        "report should contain generator name"
    );
}

#[test]
fn test_pipeline_report_contains_session_data() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (_, _, html) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "session-data");

    // Session ID should appear in report
    assert!(
        html.contains("pt-20260205-e2e-session-data"),
        "report should contain session ID"
    );

    // Profile name should appear (lowercase via Display trait)
    assert!(
        html.contains("safe"),
        "report should contain profile name 'safe'"
    );
}

#[test]
fn test_pipeline_report_theme_variants() {
    let themes = [
        (ReportTheme::Light, "light"),
        (ReportTheme::Dark, "dark"),
        (ReportTheme::Auto, ""),
    ];

    for (theme, expected_class) in themes {
        let session_id = format!("pt-20260205-theme-{:?}", theme);

        // Build a minimal bundle
        let mut bundle_writer = BundleWriter::new(&session_id, "theme-host", ExportProfile::Safe)
            .with_pt_version("2.0.0");
        bundle_writer
            .add_summary(&json!({"total_processes": 10, "candidates": 1}))
            .expect("add summary");
        bundle_writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31]);

        let (bytes, _) = bundle_writer.write_to_vec().expect("write bundle");
        let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

        let config = ReportConfig::new().with_theme(theme);
        let generator = ReportGenerator::new(config);
        let html = generator
            .generate_from_bundle(&mut reader)
            .expect("generate report");

        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "Theme {:?}: report should start with DOCTYPE",
            theme
        );

        if !expected_class.is_empty() {
            assert!(
                html.contains(&format!("class=\"{}\"", expected_class)),
                "Theme {:?}: report should have class '{}'",
                theme,
                expected_class
            );
        }
    }
}

#[test]
fn test_pipeline_report_galaxy_brain_mode() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (bundle_bytes, _, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "galaxy-brain");

    let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");

    let config = ReportConfig::new().with_galaxy_brain(true);
    let generator = ReportGenerator::new(config);
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    assert!(
        html.starts_with("<!DOCTYPE html>"),
        "galaxy-brain report should be valid HTML"
    );
    assert!(
        html.contains("katex"),
        "galaxy-brain report should include KaTeX reference"
    );
}

// ============================================================================
// Redaction Integrity Through Pipeline
// ============================================================================

#[test]
fn test_pipeline_secrets_never_leak_through_report() {
    let secret = "ghp_SuperSecretGitHubToken12345678901234";

    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];

    for profile in profiles {
        let temp_dir = TempDir::new().expect("tempdir");
        let case_id = format!("secret-leak-{:?}", profile);
        let (bundle_bytes, _, html) = run_full_pipeline(profile, &temp_dir, &case_id);

        // Secret should not appear in bundle summary
        let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");
        let summary_bytes = reader.read_verified("summary.json").expect("read summary");
        let summary_text = String::from_utf8(summary_bytes).expect("summary utf8");
        assert!(
            !summary_text.contains(secret),
            "Profile {:?}: secret leaked in bundle summary",
            profile
        );

        // Secret should not appear in report HTML
        assert!(
            !html.contains(secret),
            "Profile {:?}: secret leaked in report HTML",
            profile
        );
    }
}

// ============================================================================
// Bundle Manifest and Checksum Validation
// ============================================================================

#[test]
fn test_pipeline_manifest_completeness() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (_, manifest, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "manifest-check");

    // Expected files in bundle
    assert!(
        manifest.files.iter().any(|f| f.path == "summary.json"),
        "manifest should contain summary.json"
    );
    assert!(
        manifest.files.iter().any(|f| f.path == "plan.json"),
        "manifest should contain plan.json"
    );
    assert!(
        manifest
            .files
            .iter()
            .any(|f| f.path == "telemetry/audit.parquet"),
        "manifest should contain telemetry/audit.parquet"
    );
    assert!(
        manifest.files.iter().any(|f| f.path == "logs/events.jsonl"),
        "manifest should contain logs/events.jsonl"
    );

    // All entries should have valid checksums and sizes
    for entry in manifest.files.iter() {
        assert!(!entry.path.is_empty(), "path should not be empty");
        assert!(
            !entry.sha256.is_empty(),
            "sha256 should not be empty for {}",
            entry.path
        );
        assert!(entry.bytes > 0, "bytes should be > 0 for {}", entry.path);
        assert!(
            entry.mime_type.is_some(),
            "mime_type should be set for {}",
            entry.path
        );
    }

    // Redaction policy metadata
    assert_eq!(manifest.redaction_policy_version, "1.0.0");
    assert_eq!(manifest.redaction_policy_hash, "sha256-e2e-test-hash");

    eprintln!(
        "[INFO] Manifest: {} files, all valid",
        manifest.file_count()
    );
}

#[test]
fn test_pipeline_checksums_verify_on_readback() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (bundle_bytes, manifest, _) =
        run_full_pipeline(ExportProfile::Safe, &temp_dir, "checksum-verify");

    let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");

    // Verify each file individually
    for entry in manifest.files.iter() {
        let data = reader
            .read_verified(&entry.path)
            .unwrap_or_else(|e| panic!("Checksum failed for {}: {}", entry.path, e));

        assert_eq!(
            data.len() as u64,
            entry.bytes,
            "Size mismatch for {}",
            entry.path
        );
    }

    // Full verification should also pass
    let mut reader2 = BundleReader::from_bytes(
        run_full_pipeline(ExportProfile::Safe, &temp_dir, "checksum-verify2").0,
    )
    .expect("open bundle");
    let failures = reader2.verify_all();
    assert!(
        failures.is_empty(),
        "Full verification should pass: {:?}",
        failures
    );
}

// ============================================================================
// Encrypted Pipeline
// ============================================================================

#[test]
fn test_pipeline_encrypted_bundle_produces_valid_report() {
    let temp_dir = TempDir::new().expect("tempdir");
    let session_id = "pt-20260205-encrypted-pipeline";
    let passphrase = "e2e-pipeline-passphrase";

    // Build bundle
    let schema = audit_schema();
    let telemetry_dir = temp_dir.path().join("telemetry-enc");
    let writer_config = WriterConfig::new(
        telemetry_dir,
        session_id.to_string(),
        "enc-host".to_string(),
    )
    .with_batch_size(1);
    let mut writer = BatchedWriter::new(TableName::Audit, Arc::new(schema.clone()), writer_config);
    writer
        .write(create_audit_batch(&schema, session_id))
        .expect("write batch");
    let parquet_path = writer.close().expect("close writer");
    let parquet_bytes = fs::read(&parquet_path).expect("read parquet");

    let mut bundle_writer =
        BundleWriter::new(session_id, "enc-host", ExportProfile::Safe).with_pt_version("2.0.0");
    bundle_writer
        .add_summary(&json!({"encrypted_pipeline": true, "candidates": 3}))
        .expect("add summary");
    bundle_writer.add_telemetry("audit", parquet_bytes);

    let bundle_path = temp_dir.path().join("encrypted.ptb");
    let manifest = bundle_writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted bundle");

    // Verify encrypted file is NOT a plain ZIP
    let raw = fs::read(&bundle_path).expect("read raw");
    assert_ne!(
        &raw[0..2],
        b"PK",
        "encrypted bundle should not look like plain ZIP"
    );

    // Open with correct passphrase and generate report
    let mut reader =
        BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
    assert_eq!(reader.session_id(), session_id);
    assert_eq!(reader.export_profile(), ExportProfile::Safe);

    let failures = reader.verify_all();
    assert!(
        failures.is_empty(),
        "encrypted bundle verification failed: {:?}",
        failures
    );

    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report from encrypted bundle");
    assert!(
        html.starts_with("<!DOCTYPE html>"),
        "report from encrypted bundle should be valid HTML"
    );
    assert!(
        html.contains("pt-20260205-encrypted-pipeline"),
        "report should contain session ID from encrypted bundle"
    );

    eprintln!(
        "[INFO] Encrypted pipeline: manifest={} files, report={} bytes",
        manifest.file_count(),
        html.len()
    );
}

// ============================================================================
// Multi-Telemetry Pipeline
// ============================================================================

#[test]
fn test_pipeline_multiple_telemetry_tables_in_bundle() {
    let temp_dir = TempDir::new().expect("tempdir");
    let session_id = "pt-20260205-multi-telemetry";
    let host_id = "multi-host";

    // Write audit telemetry
    let audit_s = audit_schema();
    let audit_dir = temp_dir.path().join("telemetry-audit");
    let audit_config = WriterConfig::new(audit_dir, session_id.to_string(), host_id.to_string())
        .with_batch_size(1);
    let mut audit_writer =
        BatchedWriter::new(TableName::Audit, Arc::new(audit_s.clone()), audit_config);
    audit_writer
        .write(create_audit_batch(&audit_s, session_id))
        .expect("write audit");
    let audit_path = audit_writer.close().expect("close audit");
    let audit_bytes = fs::read(&audit_path).expect("read audit");

    // Build bundle with multiple telemetry files
    let mut bundle_writer = BundleWriter::new(session_id, host_id, ExportProfile::Safe)
        .with_pt_version("2.0.0")
        .with_redaction_policy("1.0.0", "sha256-multi-test");
    bundle_writer
        .add_summary(&json!({
            "total_processes": 500,
            "candidates": 15,
            "schema_version": "1.0.0"
        }))
        .expect("add summary");
    bundle_writer.add_telemetry("audit", audit_bytes);
    // Add fake proc_samples telemetry
    bundle_writer.add_telemetry("proc_samples", vec![0x50, 0x41, 0x52, 0x31, 0x00]);
    // Add JSONL log
    let log = json!({
        "event": "multi_telemetry_pipeline",
        "timestamp": Utc::now().to_rfc3339(),
        "phase": "bundle",
        "case_id": "multi-telemetry",
        "command": "pt bundle create",
        "exit_code": 0,
        "duration_ms": 100,
        "artifacts": [
            {"path": "telemetry/audit.parquet", "kind": "parquet"},
            {"path": "telemetry/proc_samples.parquet", "kind": "parquet"},
            {"path": "summary.json", "kind": "json"}
        ]
    });
    bundle_writer.add_log("events", format!("{}\n", log).into_bytes());

    let (bytes, manifest) = bundle_writer.write_to_vec().expect("write bundle");

    // Verify multiple telemetry files present
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");
    let telemetry_count = reader.telemetry_files().len();
    assert_eq!(
        telemetry_count, 2,
        "bundle should contain 2 telemetry files"
    );

    // Verify full bundle integrity
    let failures = reader.verify_all();
    assert!(
        failures.is_empty(),
        "multi-telemetry bundle verification failed: {:?}",
        failures
    );

    // Generate report
    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains(session_id));

    eprintln!(
        "[INFO] Multi-telemetry pipeline: {} files in bundle, {} telemetry tables",
        manifest.file_count(),
        telemetry_count
    );
}

// ============================================================================
// Pipeline Determinism
// ============================================================================

#[test]
fn test_pipeline_produces_deterministic_manifest() {
    let temp_dir = TempDir::new().expect("tempdir");

    // Run pipeline twice with same parameters
    let (_, manifest_1, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "determinism-1");
    let (_, manifest_2, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "determinism-2");

    // Same file count
    assert_eq!(
        manifest_1.file_count(),
        manifest_2.file_count(),
        "pipeline should produce consistent file count"
    );

    // Same file paths (sorted)
    let mut paths_1: Vec<_> = manifest_1.files.iter().map(|f| &f.path).collect();
    let mut paths_2: Vec<_> = manifest_2.files.iter().map(|f| &f.path).collect();
    paths_1.sort();
    paths_2.sort();
    assert_eq!(
        paths_1, paths_2,
        "pipeline should produce consistent file paths"
    );

    // Same export profile
    assert_eq!(manifest_1.export_profile, manifest_2.export_profile);

    // Same bundle schema version
    assert_eq!(manifest_1.bundle_version, manifest_2.bundle_version);
}

// ============================================================================
// Custom Report Title Through Pipeline
// ============================================================================

#[test]
fn test_pipeline_custom_report_title() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (bundle_bytes, _, _) = run_full_pipeline(ExportProfile::Safe, &temp_dir, "custom-title");

    let mut reader = BundleReader::from_bytes(bundle_bytes).expect("open bundle");

    let config = ReportConfig::new().with_title("My Custom E2E Report");
    let generator = ReportGenerator::new(config);
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");

    assert!(
        html.contains("My Custom E2E Report"),
        "report should use custom title"
    );
}
