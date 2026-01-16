//! No-mock integration tests for logging and telemetry JSONL output.
//!
//! These tests validate:
//! - JSONL schema for retention events (required/optional fields)
//! - Retention event log files are valid JSONL
//! - Event serialization roundtrips correctly
//! - Log volume respects configured caps
//!
//! See: process_triage-aii.7.6

use chrono::{DateTime, Utc};
use pt_telemetry::retention::{
    RetentionConfig, RetentionEnforcer, RetentionEvent, RetentionReason,
};
use pt_telemetry::schema::TableName;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{Duration as StdDuration, SystemTime};
use tempfile::tempdir;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a fake parquet file with specific modification time for testing.
fn create_fake_parquet(path: &Path, size_bytes: usize, age_days: u64) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(path)?;
    let content = vec![0u8; size_bytes];
    file.write_all(&content)?;
    file.sync_all()?;

    let mtime = SystemTime::now() - StdDuration::from_secs(age_days * 86400);
    let atime = filetime::FileTime::from_system_time(mtime);
    filetime::set_file_times(path, atime, atime)?;

    Ok(())
}

/// Validate that a JSON string contains all required fields for RetentionEvent.
fn validate_retention_event_schema(json: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("Invalid JSON: {}", e))?;

    let obj = value
        .as_object()
        .ok_or_else(|| "Expected JSON object".to_string())?;

    // Required fields for RetentionEvent
    let required_fields = [
        "timestamp",
        "file_path",
        "table",
        "size_bytes",
        "age_days",
        "reason",
        "dry_run",
        "host_id",
    ];

    for field in required_fields {
        if !obj.contains_key(field) {
            return Err(format!("Missing required field: {}", field));
        }
    }

    // Validate timestamp is ISO-8601
    if let Some(ts) = obj.get("timestamp").and_then(|v| v.as_str()) {
        DateTime::parse_from_rfc3339(ts)
            .map_err(|e| format!("Invalid timestamp format: {}", e))?;
    }

    // Validate table is a known value
    if let Some(table) = obj.get("table").and_then(|v| v.as_str()) {
        let valid_tables = [
            "runs",
            "proc_samples",
            "proc_features",
            "proc_inference",
            "outcomes",
            "audit",
        ];
        if !valid_tables.contains(&table) {
            return Err(format!("Unknown table: {}", table));
        }
    }

    // Validate reason is an object with known variant
    if let Some(reason) = obj.get("reason").and_then(|v| v.as_object()) {
        let valid_reasons = [
            "ttl_expired",
            "disk_budget_exceeded",
            "table_budget_exceeded",
            "manual_prune",
            "compacted",
        ];
        if !valid_reasons.iter().any(|r| reason.contains_key(*r)) {
            return Err("Unknown retention reason variant".to_string());
        }
    }

    Ok(())
}

/// Read and validate all events in a JSONL file.
fn validate_jsonl_file(path: &Path) -> Result<Vec<RetentionEvent>, String> {
    let file = fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| format!("Read error at line {}: {}", line_num + 1, e))?;

        if line.trim().is_empty() {
            continue;
        }

        // First validate schema
        validate_retention_event_schema(&line)
            .map_err(|e| format!("Schema validation failed at line {}: {}", line_num + 1, e))?;

        // Then parse into struct
        let event: RetentionEvent = serde_json::from_str(&line)
            .map_err(|e| format!("Parse error at line {}: {}", line_num + 1, e))?;

        events.push(event);
    }

    Ok(events)
}

// ============================================================================
// JSONL Schema Validation Tests
// ============================================================================

#[test]
fn test_retention_event_jsonl_required_fields() {
    let event = RetentionEvent {
        timestamp: Utc::now(),
        file_path: "proc_samples/year=2025/file.parquet".to_string(),
        table: "proc_samples".to_string(),
        size_bytes: 1024 * 1024,
        age_days: 45,
        reason: RetentionReason::TtlExpired {
            ttl_days: 30,
            age_days: 45,
        },
        dry_run: false,
        host_id: "test-host-abc".to_string(),
        session_ids: Vec::new(),
    };

    let json = serde_json::to_string(&event).expect("serialize");

    // Validate schema
    validate_retention_event_schema(&json).expect("schema validation");

    // Verify required fields are present
    assert!(json.contains("\"timestamp\""));
    assert!(json.contains("\"file_path\""));
    assert!(json.contains("\"table\""));
    assert!(json.contains("\"size_bytes\""));
    assert!(json.contains("\"age_days\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"dry_run\""));
    assert!(json.contains("\"host_id\""));

    eprintln!("[INFO] retention_event_jsonl_required_fields passed");
}

#[test]
fn test_retention_event_jsonl_all_reason_variants() {
    let reasons = vec![
        RetentionReason::TtlExpired {
            ttl_days: 30,
            age_days: 45,
        },
        RetentionReason::DiskBudgetExceeded {
            budget_bytes: 10 * 1024 * 1024 * 1024,
            used_bytes: 12 * 1024 * 1024 * 1024,
            freed_bytes: 2 * 1024 * 1024,
        },
        RetentionReason::TableBudgetExceeded {
            table: "proc_samples".to_string(),
            budget_bytes: 1024 * 1024 * 1024,
            used_bytes: 2 * 1024 * 1024 * 1024,
            freed_bytes: 512 * 1024 * 1024,
        },
        RetentionReason::ManualPrune {
            reason: "User requested cleanup".to_string(),
        },
        RetentionReason::Compacted {
            new_file: "proc_samples/compacted.parquet".to_string(),
        },
    ];

    for reason in reasons {
        let reason_debug = format!("{:?}", reason);
        let event = RetentionEvent {
            timestamp: Utc::now(),
            file_path: "test/file.parquet".to_string(),
            table: "proc_samples".to_string(),
            size_bytes: 1024,
            age_days: 10,
            reason,
            dry_run: false,
            host_id: "test-host".to_string(),
            session_ids: Vec::new(),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        validate_retention_event_schema(&json)
            .unwrap_or_else(|e| panic!("Schema validation failed for {}: {}", reason_debug, e));

        // Verify roundtrip
        let parsed: RetentionEvent =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.table, "proc_samples");

        eprintln!("[INFO] Reason variant {} serializes correctly", reason_debug);
    }
}

#[test]
fn test_retention_event_jsonl_roundtrip_fidelity() {
    let original = RetentionEvent {
        timestamp: Utc::now(),
        file_path: "proc_samples/year=2025/month=01/day=15/host_id=abc123/data.parquet".to_string(),
        table: "proc_samples".to_string(),
        size_bytes: 1234567890,
        age_days: 45,
        reason: RetentionReason::TtlExpired {
            ttl_days: 30,
            age_days: 45,
        },
        dry_run: true,
        host_id: "host-xyz-789".to_string(),
        session_ids: vec!["sess-1".to_string(), "sess-2".to_string()],
    };

    let json = serde_json::to_string(&original).expect("serialize");
    let roundtrip: RetentionEvent = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(roundtrip.file_path, original.file_path);
    assert_eq!(roundtrip.table, original.table);
    assert_eq!(roundtrip.size_bytes, original.size_bytes);
    assert_eq!(roundtrip.age_days, original.age_days);
    assert_eq!(roundtrip.dry_run, original.dry_run);
    assert_eq!(roundtrip.host_id, original.host_id);
    assert_eq!(roundtrip.session_ids, original.session_ids);

    // Timestamp should be within 1 second (chrono precision)
    let time_diff = (roundtrip.timestamp - original.timestamp).num_seconds().abs();
    assert!(time_diff <= 1, "Timestamp drift: {} seconds", time_diff);

    eprintln!("[INFO] retention_event_jsonl_roundtrip_fidelity passed");
}

#[test]
fn test_retention_event_jsonl_empty_session_ids_omitted() {
    let event = RetentionEvent {
        timestamp: Utc::now(),
        file_path: "test.parquet".to_string(),
        table: "runs".to_string(),
        size_bytes: 1024,
        age_days: 100,
        reason: RetentionReason::TtlExpired {
            ttl_days: 90,
            age_days: 100,
        },
        dry_run: false,
        host_id: "host".to_string(),
        session_ids: Vec::new(), // Empty
    };

    let json = serde_json::to_string(&event).expect("serialize");

    // Empty session_ids should be omitted (skip_serializing_if)
    assert!(
        !json.contains("\"session_ids\":[]"),
        "Empty session_ids should be omitted from JSON"
    );

    eprintln!("[INFO] Empty session_ids correctly omitted from JSONL");
}

// ============================================================================
// Retention Event Log File Tests
// ============================================================================

#[test]
fn test_retention_jsonl_log_file_format() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create a file that exceeds TTL
    let old_file =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
    create_fake_parquet(&old_file, 2048, 45).expect("create fake parquet");

    let event_log_dir = root.join("retention_logs");
    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };

    let mut enforcer = RetentionEnforcer::with_host_id(
        root.to_path_buf(),
        config,
        "test-host-nomock".to_string(),
    );

    // Run enforcement
    let events = enforcer.enforce().expect("enforce");
    assert_eq!(events.len(), 1, "Should have pruned 1 file");

    // Find and read the log file
    let log_files: Vec<_> = fs::read_dir(&event_log_dir)
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();

    assert_eq!(log_files.len(), 1, "Should have 1 JSONL log file");

    let log_path = log_files[0].path();
    let validated_events =
        validate_jsonl_file(&log_path).expect("JSONL file should be valid");

    assert_eq!(validated_events.len(), 1, "Log file should contain 1 event");

    let logged_event = &validated_events[0];
    assert_eq!(logged_event.table, "proc_samples");
    assert_eq!(logged_event.host_id, "test-host-nomock");
    assert!(!logged_event.dry_run);
    assert!(logged_event.file_path.contains("old.parquet"));

    eprintln!("[INFO] JSONL log file format validated successfully");
    eprintln!("  Log file: {}", log_path.display());
    eprintln!("  Events: {}", validated_events.len());
}

#[test]
fn test_retention_dry_run_jsonl_log() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files to trigger pruning
    let old_file =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
    create_fake_parquet(&old_file, 4096, 40).expect("create fake parquet");

    let event_log_dir = root.join("retention_logs");
    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };

    let mut enforcer = RetentionEnforcer::with_host_id(
        root.to_path_buf(),
        config,
        "dry-run-host".to_string(),
    );

    // Run dry-run
    let events = enforcer.dry_run().expect("dry_run");
    assert_eq!(events.len(), 1, "Should report 1 file would be pruned");
    assert!(events[0].dry_run, "Events should be marked as dry_run");

    // File should still exist
    assert!(
        old_file.exists(),
        "File should NOT be deleted in dry-run mode"
    );

    // Validate log file
    let log_files: Vec<_> = fs::read_dir(&event_log_dir)
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();

    assert_eq!(log_files.len(), 1, "Should have 1 JSONL log file");

    let validated_events =
        validate_jsonl_file(&log_files[0].path()).expect("JSONL file should be valid");

    for event in &validated_events {
        assert!(event.dry_run, "All logged events should have dry_run=true");
    }

    eprintln!("[INFO] Dry-run JSONL log validated: {} events", validated_events.len());
}

#[test]
fn test_retention_multiple_files_jsonl_log() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create multiple files that exceed TTL
    let files = [
        ("proc_samples", "file1.parquet", 1024, 35),
        ("proc_samples", "file2.parquet", 2048, 40),
        ("proc_features", "file3.parquet", 4096, 60), // proc_features TTL=30
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=01/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create fake parquet");
    }

    let event_log_dir = root.join("retention_logs");
    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };

    let mut enforcer = RetentionEnforcer::with_host_id(
        root.to_path_buf(),
        config,
        "multi-file-host".to_string(),
    );

    let events = enforcer.enforce().expect("enforce");
    assert!(events.len() >= 2, "Should prune at least 2 files");

    // Validate log file contains all events
    let log_files: Vec<_> = fs::read_dir(&event_log_dir)
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();

    let validated_events =
        validate_jsonl_file(&log_files[0].path()).expect("JSONL file should be valid");

    assert_eq!(
        validated_events.len(),
        events.len(),
        "Log should contain all events"
    );

    // Verify each line is valid JSONL (no trailing comma issues, proper newlines)
    let content = fs::read_to_string(log_files[0].path()).expect("read log");
    for (i, line) in content.lines().enumerate() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("Line {} is not valid JSON: {} - content: {}", i + 1, e, line)
            });
        assert!(
            parsed.is_object(),
            "Line {} should be a JSON object",
            i + 1
        );
    }

    eprintln!("[INFO] Multiple file JSONL log validated: {} events", validated_events.len());
}

// ============================================================================
// Log Volume / Caps Tests
// ============================================================================

#[test]
fn test_retention_respects_keep_everything_mode() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files that would normally be pruned
    let old_file =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
    create_fake_parquet(&old_file, 1024, 100).expect("create fake parquet");

    let config = RetentionConfig {
        keep_everything: true,
        event_log_dir: Some(root.join("retention_logs")),
        ..Default::default()
    };

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "keep-all-host".to_string());

    // Preview should show no files to prune
    let preview = enforcer.preview().expect("preview");
    assert_eq!(
        preview.files_to_prune, 0,
        "keep_everything mode should prevent all pruning"
    );

    // Enforce should also prune nothing
    let events = enforcer.enforce().expect("enforce");
    assert!(events.is_empty(), "No events should be generated");

    // File should still exist
    assert!(old_file.exists(), "File should be preserved");

    eprintln!("[INFO] keep_everything mode correctly prevents pruning");
}

#[test]
fn test_retention_disk_budget_limits_pruning() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files totaling 6MB
    let files = [
        ("proc_samples", "a.parquet", 2 * 1024 * 1024, 5),
        ("proc_samples", "b.parquet", 2 * 1024 * 1024, 10),
        ("outcomes", "c.parquet", 2 * 1024 * 1024, 5),
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=15/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create fake parquet");
    }

    // Set budget to 4MB
    let config = RetentionConfig {
        disk_budget_bytes: 4 * 1024 * 1024,
        event_log_dir: Some(root.join("retention_logs")),
        ..Default::default()
    };

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "budget-host".to_string());

    let preview = enforcer.preview().expect("preview");

    // Should prune 1 file (2MB) to get to 4MB
    assert_eq!(
        preview.files_to_prune, 1,
        "Should prune exactly 1 file to meet budget"
    );
    assert!(
        preview.projected_usage_bytes <= 4 * 1024 * 1024,
        "Projected usage should be within budget"
    );

    let events = enforcer.enforce().expect("enforce");
    assert_eq!(events.len(), 1, "Should generate 1 pruning event");

    // Verify log
    let log_files: Vec<_> = fs::read_dir(root.join("retention_logs"))
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();

    let validated_events =
        validate_jsonl_file(&log_files[0].path()).expect("JSONL file should be valid");

    // Verify the reason is disk budget
    match &validated_events[0].reason {
        RetentionReason::DiskBudgetExceeded { budget_bytes, .. } => {
            assert_eq!(*budget_bytes, 4 * 1024 * 1024);
        }
        other => panic!("Expected DiskBudgetExceeded, got {:?}", other),
    }

    eprintln!("[INFO] Disk budget correctly limits pruning");
}

#[test]
fn test_retention_ttl_override_respected() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create a file 50 days old (default proc_samples TTL=30, but we'll override to 60)
    let file =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/data.parquet");
    create_fake_parquet(&file, 1024, 50).expect("create fake parquet");

    let mut config = RetentionConfig::default();
    config.ttl_days.insert("proc_samples".to_string(), 60); // Override to 60 days
    config.event_log_dir = Some(root.join("retention_logs"));

    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "ttl-override-host".to_string());

    let preview = enforcer.preview().expect("preview");

    // File is 50 days old, TTL is 60 days, so should NOT be pruned
    assert_eq!(
        preview.files_to_prune, 0,
        "File should not be pruned with TTL override"
    );

    eprintln!("[INFO] TTL override correctly extends retention");
}

// ============================================================================
// CI Artifact Tests
// ============================================================================

#[test]
fn test_retention_log_artifacts_ci_compatible() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create test data
    let file =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/data.parquet");
    create_fake_parquet(&file, 1024, 45).expect("create fake parquet");

    let artifacts_dir = root.join("ci_artifacts");
    let config = RetentionConfig {
        event_log_dir: Some(artifacts_dir.clone()),
        ..Default::default()
    };

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "ci-test-host".to_string());

    let _ = enforcer.enforce().expect("enforce");

    // Verify artifacts directory exists and contains valid files
    assert!(
        artifacts_dir.exists(),
        "CI artifacts directory should exist"
    );

    let log_files: Vec<_> = fs::read_dir(&artifacts_dir)
        .expect("read artifacts dir")
        .filter_map(|e| e.ok())
        .collect();

    assert!(
        !log_files.is_empty(),
        "CI artifacts should contain at least one log file"
    );

    // Verify log file naming convention (retention_events_YYYYMMDD_HHMMSS.jsonl)
    for entry in &log_files {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        assert!(
            name_str.starts_with("retention_events_"),
            "Log file should follow naming convention: {}",
            name_str
        );
        assert!(
            name_str.ends_with(".jsonl"),
            "Log file should have .jsonl extension: {}",
            name_str
        );
    }

    // Verify file is readable and valid
    let validated_events =
        validate_jsonl_file(&log_files[0].path()).expect("JSONL file should be valid");

    // Output artifact summary for CI systems
    eprintln!("\n=== CI ARTIFACT SUMMARY ===");
    eprintln!("Artifacts directory: {}", artifacts_dir.display());
    eprintln!("Log files generated: {}", log_files.len());
    eprintln!("Events recorded: {}", validated_events.len());
    for entry in &log_files {
        let metadata = entry.metadata().expect("metadata");
        eprintln!(
            "  - {} ({} bytes)",
            entry.file_name().to_string_lossy(),
            metadata.len()
        );
    }
    eprintln!("=== END ARTIFACT SUMMARY ===\n");
}

// ============================================================================
// Table Name Schema Tests
// ============================================================================

#[test]
fn test_table_name_retention_days() {
    // Verify default TTL values for each table
    assert_eq!(TableName::Runs.retention_days(), 90);
    assert_eq!(TableName::ProcSamples.retention_days(), 30);
    assert_eq!(TableName::ProcFeatures.retention_days(), 30);
    assert_eq!(TableName::ProcInference.retention_days(), 90);
    assert_eq!(TableName::Outcomes.retention_days(), 365);
    assert_eq!(TableName::Audit.retention_days(), 365);

    eprintln!("[INFO] Table retention days validated");
}

#[test]
fn test_retention_config_validation() {
    // Valid config
    let mut config = RetentionConfig::default();
    assert!(config.validate().is_ok());

    // Invalid table name in ttl_days
    config.ttl_days.insert("invalid_table".to_string(), 30);
    assert!(config.validate().is_err());

    // Reset and test table_budget_bytes
    config.ttl_days.clear();
    config
        .table_budget_bytes
        .insert("another_invalid".to_string(), 1024);
    assert!(config.validate().is_err());

    eprintln!("[INFO] Retention config validation works correctly");
}

#[test]
fn test_retention_status_jsonl_serializable() {
    let dir = tempdir().expect("tempdir");
    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(dir.path().to_path_buf(), config, "status-host".to_string());

    let status = enforcer.status().expect("status");

    // Status should be JSON serializable
    let json = serde_json::to_string(&status).expect("serialize status");
    assert!(json.contains("\"root_dir\""));
    assert!(json.contains("\"total_bytes\""));
    assert!(json.contains("\"total_files\""));
    assert!(json.contains("\"by_table\""));

    eprintln!("[INFO] Retention status is JSONL serializable");
}

#[test]
fn test_retention_preview_jsonl_serializable() {
    let dir = tempdir().expect("tempdir");
    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(dir.path().to_path_buf(), config, "preview-host".to_string());

    let preview = enforcer.preview().expect("preview");

    // Preview should be JSON serializable
    let json = serde_json::to_string(&preview).expect("serialize preview");
    assert!(json.contains("\"files_to_prune\""));
    assert!(json.contains("\"bytes_to_free\""));
    assert!(json.contains("\"by_table\""));
    assert!(json.contains("\"current_usage_bytes\""));
    assert!(json.contains("\"projected_usage_bytes\""));

    eprintln!("[INFO] Retention preview is JSONL serializable");
}
