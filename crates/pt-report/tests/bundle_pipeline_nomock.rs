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
use pt_bundle::{BundleReader, BundleWriter};
use pt_redact::{ExportProfile, FieldClass, KeyMaterial, RedactionEngine, RedactionPolicy};
use pt_report::ReportGenerator;
use pt_telemetry::schema::{audit_schema, TableName};
use pt_telemetry::writer::{BatchedWriter, WriterConfig};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn create_audit_batch(schema: &Schema) -> RecordBatch {
    let audit_ts = TimestampMicrosecondArray::from(vec![Utc::now().timestamp_micros()])
        .with_timezone("UTC");
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
        "note": redacted.output,
        "profile": "safe",
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

    // Bundle artifacts
    let bundle_path = temp_dir.path().join("session.ptb");
    let mut bundle = BundleWriter::new(session_id, host_id, ExportProfile::Safe)
        .with_pt_version("0.1.0-test")
        .with_redaction_policy("test", "hash");
    bundle.add_summary(&summary).expect("add summary");
    bundle.add_telemetry("audit", parquet_bytes);
    bundle.add_log("events", log_jsonl.into_bytes());
    let manifest = bundle.write(&bundle_path).expect("write bundle");
    assert_eq!(manifest.export_profile, ExportProfile::Safe);

    // Verify bundle reads + checksum validation
    let mut reader = BundleReader::open(&bundle_path).expect("open bundle");
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
    for (line_num, line) in log_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        validate_jsonl_schema(line)
            .unwrap_or_else(|err| panic!("log schema failed line {}: {}", line_num + 1, err));
    }

    // Telemetry schema validation (read parquet schema)
    let _telemetry_bytes = reader
        .read_verified("telemetry/audit.parquet")
        .expect("read telemetry parquet");
    let parquet_file = fs::File::open(&parquet_path).expect("open parquet file");
    let builder =
        ParquetRecordBatchReaderBuilder::try_new(parquet_file).expect("parquet reader");
    let parquet_schema = builder.schema();
    assert_eq!(parquet_schema.as_ref(), &schema);

    // Report generation from bundle
    let generator = ReportGenerator::default_config();
    let html = generator
        .generate_from_bundle(&mut reader)
        .expect("generate report");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains(r#"id="tab-overview""#));
}
