//! No-mock bundle/report/redaction/telemetry integration test.
//!
//! Exercises a real pipeline:
//! - Write telemetry parquet (audit table)
//! - Redact a secret into summary.json
//! - Bundle artifacts with checksums
//! - Verify bundle reads + JSONL log schema
//! - Generate HTML report from bundle

use arrow::array::{Int32Array, StringArray, TimestampMicrosecondArray};
use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use chrono::Utc;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use pt_bundle::{BundleError, BundleReader, BundleWriter};
use pt_redact::{ExportProfile, FieldClass, KeyMaterial, RedactionEngine, RedactionPolicy};
use pt_report::ReportGenerator;
use pt_telemetry::schema::{audit_schema, TableName};
use pt_telemetry::writer::{BatchedWriter, WriterConfig};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn create_audit_batch(schema: &Schema) -> RecordBatch {
    let audit_ts =
        TimestampMicrosecondArray::from(vec![Utc::now().timestamp_micros()]).with_timezone("UTC");
    let session_id = StringArray::from(vec!["pt-20260115-143022-test"]);
    let event_type = StringArray::from(vec!["bundle_test"]);
    let severity = StringArray::from(vec!["info"]);
    let actor = StringArray::from(vec!["system"]);
    let target_pid: Int32Array = Int32Array::from(vec![None::<i32>]);
    let target_start_id: StringArray = StringArray::from(vec![None::<&str>]);
    let message = StringArray::from(vec!["bundle pipeline test"]);
    let details_json: StringArray = StringArray::from(vec![None::<&str>]);
    let host_id = StringArray::from(vec!["test-host"]);

    RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(audit_ts),
            Arc::new(session_id),
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

    Ok(())
}

#[test]
fn test_bundle_report_redaction_telemetry_nomock() {
    let temp_dir = TempDir::new().expect("temp dir");
    let session_id = "pt-20260115-143022-test";
    let host_id = "host-test";

    // Telemetry parquet (audit table)
    let schema = audit_schema();
    let telemetry_dir = temp_dir.path().join("telemetry");
    let config = WriterConfig::new(telemetry_dir, session_id.to_string(), host_id.to_string())
        .with_batch_size(1);
    let mut writer = BatchedWriter::new(TableName::Audit, Arc::new(schema.clone()), config);
    writer
        .write(create_audit_batch(&schema))
        .expect("write audit batch");
    let parquet_path = writer.close().expect("close parquet writer");
    let parquet_bytes = fs::read(&parquet_path).expect("read parquet bytes");

    // Redaction (ensure secret does not leak into bundle summary)
    let secret = "sk-test-secret-123";
    let policy = RedactionPolicy::default();
    let key = KeyMaterial::from_bytes([7u8; 32], "bundle-test");
    let engine = RedactionEngine::with_key(policy, key);
    let redacted = engine.redact_with_profile(secret, FieldClass::FreeText, ExportProfile::Safe);
    assert!(
        !redacted.output.contains(secret),
        "redaction output leaked secret"
    );

    let summary = serde_json::json!({
        "note": secret,
        "total_processes": 1,
        "state": "completed",
        "session_id": session_id,
    });

    let log_entry = serde_json::json!({
        "event": "bundle_pipeline",
        "timestamp": Utc::now().to_rfc3339(),
        "phase": "bundle",
        "case_id": "case-1",
        "command": "pt bundle create",
        "exit_code": 0,
        "duration_ms": 10,
        "artifacts": [
            {"path": "telemetry/audit.parquet", "kind": "parquet"}
        ]
    });
    let log_jsonl = format!("{}\n", log_entry);

    // Safe refuses even valid Parquet until a format-specific sanitizer exists.
    let refused_path = temp_dir.path().join("safe-refused.ptb");
    let mut safe_bundle = BundleWriter::new(session_id, host_id, ExportProfile::Safe);
    safe_bundle.add_summary(&summary).expect("add Safe summary");
    safe_bundle.add_telemetry("audit", parquet_bytes.clone());
    assert!(matches!(
        safe_bundle.write(&refused_path),
        Err(BundleError::UnsanitizedPayload { path, profile })
            if path == "telemetry/audit.parquet" && profile == "safe"
    ));
    assert!(
        !refused_path.exists(),
        "Safe refusal must not create output"
    );

    // Preserve the real Parquet archive under explicit Forensic export.
    let bundle_path = temp_dir.path().join("session.ptb");
    let mut bundle = BundleWriter::new(session_id, host_id, ExportProfile::Forensic)
        .with_pt_version("0.1.0-test")
        .with_redaction_policy("test", "hash")
        .with_redaction_engine(engine);
    bundle.add_summary(&summary).expect("add summary");
    bundle.add_telemetry("audit", parquet_bytes.clone());
    bundle.add_log("events", log_jsonl.into_bytes());
    let manifest = bundle.write(&bundle_path).expect("write bundle");
    assert_eq!(manifest.export_profile, ExportProfile::Forensic);

    // Verify bundle reads + checksum validation
    let mut reader = BundleReader::open(&bundle_path).expect("open bundle");
    assert!(
        reader.verify_all().is_empty(),
        "archive checksums must verify"
    );
    let summary_bytes = reader.read_verified("summary.json").expect("read summary");
    let summary_text = String::from_utf8(summary_bytes).expect("summary utf8");
    assert!(
        !summary_text.contains(secret),
        "bundle summary leaked secret"
    );

    let log_bytes = reader
        .read_verified("logs/events.jsonl")
        .expect("read log jsonl");
    let log_text = String::from_utf8(log_bytes).expect("log utf8");
    let mut log_lines = 0;
    for (line_num, line) in log_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        validate_jsonl_schema(line)
            .unwrap_or_else(|err| panic!("log schema failed line {}: {}", line_num + 1, err));
        log_lines += 1;
    }
    assert_eq!(log_lines, 1, "must validate the emitted JSONL record");

    // Telemetry schema validation (read parquet schema)
    let telemetry_bytes = reader
        .read_verified("telemetry/audit.parquet")
        .expect("read telemetry parquet");
    assert_eq!(
        telemetry_bytes, parquet_bytes,
        "archive must preserve real Parquet bytes"
    );
    let parquet_file = fs::File::open(&parquet_path).expect("open parquet file");
    let builder = ParquetRecordBatchReaderBuilder::try_new(parquet_file).expect("parquet reader");
    let parquet_schema = builder.schema();
    assert_eq!(parquet_schema.as_ref(), &schema);

    // Report generation from bundle
    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains(r#"id="tab-overview""#));
    assert!(!html.contains(secret), "report must not expose the secret");
}

#[test]
fn test_structured_bundle_report_all_export_profiles() {
    let private_command = "private-worker --secret=report-canary";
    for profile in [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ] {
        let policy = RedactionPolicy::default();
        let key = KeyMaterial::from_bytes([11u8; 32], "structured-report-test");
        let engine = RedactionEngine::with_key(policy, key);
        let mut writer = BundleWriter::new("pt-20261004-120500-abcd", "private-host", profile)
            .with_description("private report description")
            .with_redaction_engine(engine);
        writer
            .add_summary(&serde_json::json!({
                "total_processes": 4,
                "candidates": 1,
                "state": "completed",
                "command": private_command,
                "records": [{"pid": 1234, "command": private_command}]
            }))
            .expect("add structured summary");
        writer
            .add_plan(&serde_json::json!({
                "recommendations": [{"pid": 1234, "action": "spare"}]
            }))
            .expect("add structured plan");
        let log_entry = serde_json::json!({
            "event": "structured_report",
            "timestamp": Utc::now().to_rfc3339(),
            "phase": "bundle",
            "case_id": "report-profile",
            "command": private_command,
            "exit_code": 0,
            "duration_ms": 10,
            "artifacts": [{"path": "summary.json", "kind": "json"}]
        });
        writer.add_log("events", format!("{log_entry}\n").into_bytes());

        let (bytes, manifest) = writer.write_to_vec().expect("write structured bundle");
        assert_eq!(manifest.export_profile, profile);
        let mut reader = BundleReader::from_bytes(bytes).expect("read structured bundle");
        assert_eq!(reader.session_id(), "pt-20261004-120500-abcd");
        assert!(
            reader.verify_all().is_empty(),
            "structured checksums must verify"
        );
        let summary: serde_json::Value = reader.read_summary().expect("read summary");
        assert_eq!(summary["total_processes"], 4);
        assert_eq!(summary["candidates"], 1);
        assert!(!summary.to_string().contains(private_command));

        if profile == ExportProfile::Minimal {
            assert_eq!(
                summary,
                serde_json::json!({"total_processes": 4, "candidates": 1})
            );
            assert_eq!(manifest.file_count(), 1);
            assert!(!reader.has_file("plan.json"));
            assert!(reader.log_files().is_empty());
        } else {
            assert_eq!(manifest.file_count(), 3);
            assert_eq!(summary["state"], "completed");
            let plan: serde_json::Value = reader.read_plan().expect("read plan").expect("plan");
            assert_eq!(plan["recommendations"][0]["pid"], 1234);
            assert_eq!(plan["recommendations"][0]["action"], "spare");
            let logs = reader.read_verified("logs/events.jsonl").expect("read log");
            let log_text = String::from_utf8(logs).expect("log UTF-8");
            assert!(!log_text.contains(private_command));
            assert_eq!(log_text.lines().count(), 1);
            validate_jsonl_schema(log_text.trim()).expect("structured log schema");
        }
        if profile != ExportProfile::Forensic {
            assert_ne!(manifest.host_id, "private-host");
            assert_ne!(
                manifest.description.as_deref(),
                Some("private report description")
            );
        }

        let html = ReportGenerator::default_config()
            .generate_from_bundle(&mut reader)
            .expect("generate structured report");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains(r#"id="tab-overview""#));
        assert!(!html.contains(private_command));
    }
}
