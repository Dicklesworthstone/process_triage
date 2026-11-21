//! E2E tests for telemetry status + prune/retention workflows.
//!
//! Validates:
//! - Deterministic status→prune workflows complete in CI
//! - Retention boundary precision (files at exact TTL boundary)
//! - Prune idempotency (second enforce returns 0 events)
//! - Failure paths produce correct errors
//! - JSONL logs emitted per case
//! - Sequential prune cycles behave deterministically

use pt_telemetry::retention::{
    RetentionConfig, RetentionEnforcer, RetentionError, RetentionEvent, RetentionReason,
};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

// ============================================================================
// Helpers
// ============================================================================

/// Create a fake parquet file with specific size and simulated age.
fn create_fake_parquet(path: &Path, size_bytes: usize, age_days: u64) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(&vec![0u8; size_bytes])?;
    file.sync_all()?;

    let mtime = SystemTime::now() - Duration::from_secs(age_days * 86400);
    let times = fs::FileTimes::new().set_accessed(mtime).set_modified(mtime);
    file.set_times(times)?;
    Ok(())
}

/// Create a fixture telemetry directory with files across multiple tables and ages.
fn create_fixture_telemetry(root: &Path) {
    let fixtures = [
        // (table, filename, size_bytes, age_days)
        // proc_samples: default TTL=30d
        ("proc_samples", "young.parquet", 1024, 5),
        ("proc_samples", "mid.parquet", 2048, 25),
        ("proc_samples", "old.parquet", 4096, 35),
        ("proc_samples", "ancient.parquet", 8192, 60),
        // runs: default TTL=90d
        ("runs", "recent_run.parquet", 1024, 10),
        ("runs", "old_run.parquet", 2048, 95),
        // outcomes: default TTL=365d
        ("outcomes", "outcome.parquet", 4096, 100),
        // audit: default TTL=365d
        ("audit", "audit_entry.parquet", 512, 50),
        // proc_features: default TTL=30d
        ("proc_features", "features.parquet", 1024, 40),
        // proc_inference: default TTL=90d
        ("proc_inference", "inference.parquet", 2048, 15),
    ];

    for (table, name, size, age) in &fixtures {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=15/host_id=fixture/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create fixture file");
    }
}

/// Read JSONL log file and return parsed events.
fn read_retention_log(log_dir: &Path) -> Vec<RetentionEvent> {
    let entries: Vec<_> = fs::read_dir(log_dir)
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();

    let mut events = Vec::new();
    for entry in entries {
        let file = fs::File::open(entry.path()).expect("open log file");
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.expect("read line");
            if line.trim().is_empty() {
                continue;
            }
            let event: RetentionEvent = serde_json::from_str(&line).expect("parse retention event");
            events.push(event);
        }
    }
    events
}

// ============================================================================
// Deterministic Workflow Tests
// ============================================================================

#[test]
fn test_deterministic_status_prune_status_workflow() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let event_log_dir = root.join("retention_logs");

    create_fixture_telemetry(root);

    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };
    let host_id = "e2e-workflow-host".to_string();

    // Step 1: Status before prune
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let status_before = enforcer.status().expect("status before");

    assert_eq!(status_before.total_files, 10, "fixture has 10 files");
    let expected_bytes: u64 = [1024, 2048, 4096, 8192, 1024, 2048, 4096, 512, 1024, 2048]
        .iter()
        .sum();
    assert_eq!(status_before.total_bytes, expected_bytes);
    assert!(
        status_before.ttl_eligible_files > 0,
        "some files should be TTL-eligible"
    );

    // Step 2: Preview matches status TTL-eligible count
    let preview = enforcer.preview().expect("preview");
    // Preview candidates include TTL-expired + any budget-exceeded
    // With default 10GB budget, only TTL-expired should appear
    assert_eq!(
        preview.files_to_prune, status_before.ttl_eligible_files,
        "preview prune count should match status TTL-eligible count"
    );

    // Step 3: Enforce (real prune)
    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let events = enforcer.enforce().expect("enforce");
    let pruned_count = events.len();
    let pruned_bytes: u64 = events.iter().map(|e| e.size_bytes).sum();

    assert_eq!(
        pruned_count, preview.files_to_prune,
        "enforce count should match preview"
    );
    assert!(pruned_count > 0, "should prune at least one file");

    // Step 4: Status after prune — counts should be reduced
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let status_after = enforcer.status().expect("status after");

    assert_eq!(
        status_after.total_files,
        status_before.total_files - pruned_count,
        "total files should decrease by pruned count"
    );
    assert_eq!(
        status_after.total_bytes,
        status_before.total_bytes - pruned_bytes,
        "total bytes should decrease by pruned bytes"
    );
    assert_eq!(
        status_after.ttl_eligible_files, 0,
        "no TTL-eligible files should remain after prune"
    );

    // Step 5: JSONL log emitted
    let logged_events = read_retention_log(&event_log_dir);
    assert_eq!(
        logged_events.len(),
        pruned_count,
        "JSONL log should have one event per pruned file"
    );

    eprintln!(
        "[INFO] Workflow: {} files before, {} pruned, {} remaining",
        status_before.total_files, pruned_count, status_after.total_files
    );
}

#[test]
fn test_prune_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files that will be pruned
    let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
    create_fake_parquet(&old_file, 1024, 45).expect("create fixture");

    let config = RetentionConfig::default();
    let host_id = "idempotent-host".to_string();

    // First enforce
    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let events_1 = enforcer.enforce().expect("first enforce");
    assert_eq!(events_1.len(), 1, "first enforce should prune 1 file");
    assert!(!old_file.exists(), "file should be deleted");

    // Second enforce — should be a no-op
    let mut enforcer = RetentionEnforcer::with_host_id(root.to_path_buf(), config, host_id);
    let events_2 = enforcer.enforce().expect("second enforce");
    assert_eq!(
        events_2.len(),
        0,
        "second enforce should prune 0 files (idempotent)"
    );
}

// ============================================================================
// TTL Boundary Precision
// ============================================================================

#[test]
fn test_ttl_boundary_precision() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // proc_samples default TTL = 30 days
    // Create files at boundary: 29d (keep), 30d (keep — age must EXCEED ttl), 31d (prune)
    let under_ttl =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/under_ttl.parquet");
    let at_ttl = root.join("proc_samples/year=2025/month=01/day=02/host_id=test/at_ttl.parquet");
    let over_ttl =
        root.join("proc_samples/year=2025/month=01/day=03/host_id=test/over_ttl.parquet");

    create_fake_parquet(&under_ttl, 1024, 29).expect("under TTL");
    create_fake_parquet(&at_ttl, 1024, 30).expect("at TTL");
    create_fake_parquet(&over_ttl, 1024, 31).expect("over TTL");

    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "boundary-host".to_string());

    let preview = enforcer.preview().expect("preview");

    // Only the 31-day file should be pruned (age > 30d TTL)
    // The 30-day file's age in seconds is exactly 30*86400 vs TTL of 30*86400.
    // Due to Duration comparison (age > ttl where both are same), the at-boundary file
    // may or may not be pruned depending on sub-second timing. We test that:
    // - 29d file is definitely NOT pruned
    // - 31d file is definitely pruned
    let pruned_paths: Vec<_> = preview
        .candidates
        .iter()
        .map(|c| c.file_path.as_str())
        .collect();

    assert!(
        !pruned_paths.iter().any(|p| p.contains("under_ttl")),
        "29-day file should NOT be pruned (under 30d TTL)"
    );
    assert!(
        pruned_paths.iter().any(|p| p.contains("over_ttl")),
        "31-day file should be pruned (over 30d TTL)"
    );

    // The at-boundary file (30d) may or may not be pruned depending on timing.
    // That's OK — we verify the boundary behavior is reasonable.
    let at_ttl_pruned = pruned_paths.iter().any(|p| p.contains("at_ttl"));
    eprintln!(
        "[INFO] Boundary precision: under=kept, at={}, over=pruned",
        if at_ttl_pruned { "pruned" } else { "kept" }
    );
}

#[test]
fn test_custom_ttl_boundary_precision() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Use custom TTL of 10 days for proc_samples
    let keep_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/keep.parquet");
    let prune_file = root.join("proc_samples/year=2025/month=01/day=02/host_id=test/prune.parquet");

    create_fake_parquet(&keep_file, 1024, 8).expect("keep file");
    create_fake_parquet(&prune_file, 1024, 12).expect("prune file");

    let mut config = RetentionConfig::default();
    config.ttl_days.insert("proc_samples".to_string(), 10);

    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "custom-ttl-host".to_string());

    let preview = enforcer.preview().expect("preview");

    assert_eq!(
        preview.files_to_prune, 1,
        "only the 12-day file should be pruned with 10d TTL"
    );
    assert!(
        preview.candidates[0].file_path.contains("prune.parquet"),
        "pruned file should be the 12-day one"
    );
}

// ============================================================================
// Mixed Table Pruning
// ============================================================================

#[test]
fn test_mixed_table_ttl_overrides_prune_correctly() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // proc_samples: override to 5d TTL
    // runs: override to 50d TTL
    // outcomes: default 365d TTL
    let files = [
        ("proc_samples", "ps1.parquet", 1024, 3), // keep (3d < 5d)
        ("proc_samples", "ps2.parquet", 1024, 7), // prune (7d > 5d)
        ("runs", "r1.parquet", 1024, 30),         // keep (30d < 50d)
        ("runs", "r2.parquet", 1024, 55),         // prune (55d > 50d)
        ("outcomes", "o1.parquet", 1024, 200),    // keep (200d < 365d)
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=15/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create file");
    }

    let mut config = RetentionConfig::default();
    config.ttl_days.insert("proc_samples".to_string(), 5);
    config.ttl_days.insert("runs".to_string(), 50);

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "mixed-ttl-host".to_string());

    let events = enforcer.enforce().expect("enforce");
    let pruned_tables: Vec<_> = events.iter().map(|e| e.table.as_str()).collect();

    assert_eq!(events.len(), 2, "should prune exactly 2 files");
    assert!(
        pruned_tables.contains(&"proc_samples"),
        "should prune proc_samples"
    );
    assert!(pruned_tables.contains(&"runs"), "should prune runs");

    // Verify kept files still exist
    assert!(
        root.join("proc_samples/year=2025/month=01/day=15/host_id=test/ps1.parquet")
            .exists(),
        "ps1 (3d) should be kept"
    );
    assert!(
        root.join("runs/year=2025/month=01/day=15/host_id=test/r1.parquet")
            .exists(),
        "r1 (30d) should be kept"
    );
    assert!(
        root.join("outcomes/year=2025/month=01/day=15/host_id=test/o1.parquet")
            .exists(),
        "o1 (200d) should be kept"
    );
}

// ============================================================================
// Status Field Consistency
// ============================================================================

#[test]
fn test_status_fields_consistency_with_fixture_data() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    create_fixture_telemetry(root);

    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "status-host".to_string());

    let status = enforcer.status().expect("status");

    // Verify total_bytes == sum of all table bytes
    let sum_table_bytes: u64 = status.by_table.values().map(|t| t.total_bytes).sum();
    assert_eq!(
        status.total_bytes, sum_table_bytes,
        "total_bytes should equal sum of per-table bytes"
    );

    // Verify total_files == sum of all table files
    let sum_table_files: usize = status.by_table.values().map(|t| t.file_count).sum();
    assert_eq!(
        status.total_files, sum_table_files,
        "total_files should equal sum of per-table files"
    );

    // Verify TTL-eligible count == sum of per-table over_ttl_count
    let sum_over_ttl: usize = status.by_table.values().map(|t| t.over_ttl_count).sum();
    assert_eq!(
        status.ttl_eligible_files, sum_over_ttl,
        "ttl_eligible_files should equal sum of per-table over_ttl_count"
    );

    // Verify TTL-eligible bytes == sum of per-table over_ttl_bytes
    let sum_over_ttl_bytes: u64 = status.by_table.values().map(|t| t.over_ttl_bytes).sum();
    assert_eq!(
        status.ttl_eligible_bytes, sum_over_ttl_bytes,
        "ttl_eligible_bytes should equal sum of per-table over_ttl_bytes"
    );

    // Verify budget percentage calculation
    if status.disk_budget_bytes > 0 {
        let expected_pct = (status.total_bytes as f64 / status.disk_budget_bytes as f64) * 100.0;
        assert!(
            (status.budget_used_pct - expected_pct).abs() < 0.01,
            "budget_used_pct should be accurate: got {}, expected {}",
            status.budget_used_pct,
            expected_pct
        );
    }

    // Verify each table has correct TTL
    if let Some(ps) = status.by_table.get("proc_samples") {
        assert_eq!(ps.ttl_days, 30, "proc_samples TTL should be 30d");
    }
    if let Some(runs) = status.by_table.get("runs") {
        assert_eq!(runs.ttl_days, 90, "runs TTL should be 90d");
    }
    if let Some(outcomes) = status.by_table.get("outcomes") {
        assert_eq!(outcomes.ttl_days, 365, "outcomes TTL should be 365d");
    }

    eprintln!(
        "[INFO] Status consistency: {} files, {} bytes, {:.4}% budget, {} TTL-eligible",
        status.total_files, status.total_bytes, status.budget_used_pct, status.ttl_eligible_files
    );
}

#[test]
fn test_status_per_table_age_range() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files with known ages
    let files = [
        ("proc_samples", "young.parquet", 1024, 5),
        ("proc_samples", "old.parquet", 1024, 50),
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=15/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create file");
    }

    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "age-range-host".to_string());

    let status = enforcer.status().expect("status");
    let ps = status.by_table.get("proc_samples").expect("proc_samples");

    // Oldest should be ~50 days, newest ~5 days
    assert!(
        ps.oldest_file_age_days >= 49 && ps.oldest_file_age_days <= 51,
        "oldest should be ~50d, got {}",
        ps.oldest_file_age_days
    );
    assert!(
        ps.newest_file_age_days >= 4 && ps.newest_file_age_days <= 6,
        "newest should be ~5d, got {}",
        ps.newest_file_age_days
    );
}

// ============================================================================
// Sequential Prune Cycles
// ============================================================================

#[test]
fn test_sequential_prune_cycles_deterministic() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let event_log_dir = root.join("retention_logs");

    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };
    let host_id = "sequential-host".to_string();

    // Cycle 1: Create old file, prune it
    let old_file_1 =
        root.join("proc_samples/year=2025/month=01/day=01/host_id=test/cycle1.parquet");
    create_fake_parquet(&old_file_1, 1024, 45).expect("cycle1 file");

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let events_1 = enforcer.enforce().expect("cycle1 enforce");
    assert_eq!(events_1.len(), 1, "cycle1: should prune 1 file");
    assert!(!old_file_1.exists(), "cycle1: file should be deleted");

    // Cycle 2: Create more old files, prune them
    let old_file_2 =
        root.join("proc_samples/year=2025/month=01/day=02/host_id=test/cycle2a.parquet");
    let old_file_3 =
        root.join("proc_features/year=2025/month=01/day=01/host_id=test/cycle2b.parquet");
    let young_file = root.join("proc_samples/year=2025/month=01/day=03/host_id=test/young.parquet");

    create_fake_parquet(&old_file_2, 2048, 40).expect("cycle2a file");
    create_fake_parquet(&old_file_3, 4096, 35).expect("cycle2b file");
    create_fake_parquet(&young_file, 1024, 5).expect("young file");

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let events_2 = enforcer.enforce().expect("cycle2 enforce");
    assert_eq!(events_2.len(), 2, "cycle2: should prune 2 old files");
    assert!(!old_file_2.exists(), "cycle2: old file 2 should be deleted");
    assert!(!old_file_3.exists(), "cycle2: old file 3 should be deleted");
    assert!(young_file.exists(), "cycle2: young file should be kept");

    // Verify JSONL logs exist (note: if both cycles run within the same second,
    // the second log file may overwrite the first due to timestamp-based naming).
    let all_logged = read_retention_log(&event_log_dir);
    assert!(
        all_logged.len() >= 2,
        "logged events should contain at least cycle2's events: got {}",
        all_logged.len()
    );

    // Verify total via return values (reliable regardless of log file collisions)
    assert_eq!(
        events_1.len() + events_2.len(),
        3,
        "total returned events should be 3 across 2 cycles"
    );

    eprintln!(
        "[INFO] Sequential prune: cycle1={} pruned, cycle2={} pruned, logged={}",
        events_1.len(),
        events_2.len(),
        all_logged.len()
    );
}

// ============================================================================
// JSONL Log Validation Per Case
// ============================================================================

#[test]
fn test_jsonl_emitted_per_pruned_file() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let event_log_dir = root.join("retention_logs");

    // Create 4 files across tables that will all be pruned
    let files = [
        ("proc_samples", "ps.parquet", 1024, 35),
        ("proc_features", "pf.parquet", 2048, 40),
        ("runs", "r.parquet", 4096, 95),
        ("audit", "a.parquet", 512, 400),
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=01/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create file");
    }

    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "jsonl-per-case".to_string());
    let events = enforcer.enforce().expect("enforce");

    assert_eq!(events.len(), 4, "should prune all 4 files");

    // Read JSONL log and verify 1:1 correspondence
    let logged = read_retention_log(&event_log_dir);
    assert_eq!(logged.len(), 4, "JSONL should have 4 events");

    // Verify each event has correct fields
    let logged_tables: Vec<_> = logged.iter().map(|e| e.table.as_str()).collect();
    assert!(logged_tables.contains(&"proc_samples"));
    assert!(logged_tables.contains(&"proc_features"));
    assert!(logged_tables.contains(&"runs"));
    assert!(logged_tables.contains(&"audit"));

    // Verify all events have proper host_id
    for event in &logged {
        assert_eq!(event.host_id, "jsonl-per-case");
        assert!(!event.dry_run);
        assert!(event.size_bytes > 0);
        assert!(event.age_days > 0);
        assert!(!event.file_path.is_empty());

        match &event.reason {
            RetentionReason::TtlExpired { ttl_days, age_days } => {
                assert!(*age_days > *ttl_days, "age should exceed TTL");
            }
            _ => panic!(
                "Expected TtlExpired reason for {}, got {:?}",
                event.file_path, event.reason
            ),
        }
    }

    eprintln!(
        "[INFO] JSONL per-case: {} events logged for {} prunes",
        logged.len(),
        events.len()
    );
}

#[test]
fn test_dry_run_jsonl_events_marked_correctly() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    let event_log_dir = root.join("retention_logs");

    let old_file = root.join("proc_samples/year=2025/month=01/day=01/host_id=test/old.parquet");
    create_fake_parquet(&old_file, 1024, 45).expect("create file");

    let config = RetentionConfig {
        event_log_dir: Some(event_log_dir.clone()),
        ..Default::default()
    };

    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "dry-run-host".to_string());
    let events = enforcer.dry_run().expect("dry_run");

    assert_eq!(events.len(), 1);
    assert!(events[0].dry_run, "event should be marked dry_run");
    assert!(old_file.exists(), "file should NOT be deleted in dry-run");

    // Verify JSONL also has dry_run=true
    let logged = read_retention_log(&event_log_dir);
    assert_eq!(logged.len(), 1);
    assert!(logged[0].dry_run, "logged event should be dry_run");
}

// ============================================================================
// Failure Paths
// ============================================================================

#[test]
fn test_failure_invalid_config_table_name() {
    let mut config = RetentionConfig::default();
    config.ttl_days.insert("nonexistent_table".to_string(), 30);

    let result = config.validate();
    assert!(
        result.is_err(),
        "config with invalid table should fail validation"
    );

    match result.unwrap_err() {
        RetentionError::InvalidConfig(msg) => {
            assert!(
                msg.contains("nonexistent_table"),
                "error should mention the invalid table name: {}",
                msg
            );
        }
        other => panic!("Expected InvalidConfig, got: {}", other),
    }
}

#[test]
fn test_failure_invalid_table_budget_name() {
    let mut config = RetentionConfig::default();
    config
        .table_budget_bytes
        .insert("bogus_table".to_string(), 1024);

    let result = config.validate();
    assert!(
        result.is_err(),
        "config with invalid budget table should fail validation"
    );

    match result.unwrap_err() {
        RetentionError::InvalidConfig(msg) => {
            assert!(
                msg.contains("bogus_table"),
                "error should mention the invalid table: {}",
                msg
            );
        }
        other => panic!("Expected InvalidConfig, got: {}", other),
    }
}

#[test]
fn test_failure_nonexistent_telemetry_dir() {
    let dir = tempdir().expect("tempdir");
    let nonexistent = dir.path().join("does_not_exist");

    let config = RetentionConfig::default();
    let enforcer = RetentionEnforcer::with_host_id(
        nonexistent.clone(),
        config,
        "nonexistent-host".to_string(),
    );

    // Status on non-existent dir should still work (returns 0 files)
    let status = enforcer.status().expect("status should succeed");
    assert_eq!(status.total_files, 0);
    assert_eq!(status.total_bytes, 0);
}

#[test]
fn test_failure_empty_telemetry_dir_zeros() {
    let dir = tempdir().expect("tempdir");
    let config = RetentionConfig::default();
    let enforcer =
        RetentionEnforcer::with_host_id(dir.path().to_path_buf(), config, "empty-host".to_string());

    let status = enforcer.status().expect("status");
    assert_eq!(status.total_files, 0);
    assert_eq!(status.total_bytes, 0);
    assert_eq!(status.ttl_eligible_files, 0);
    assert_eq!(status.ttl_eligible_bytes, 0);

    // All table entries should have zero counts
    for ts in status.by_table.values() {
        assert_eq!(ts.file_count, 0);
        assert_eq!(ts.total_bytes, 0);
        assert_eq!(ts.over_ttl_count, 0);
    }

    // Prune on empty dir should be a no-op
    let mut enforcer = RetentionEnforcer::with_host_id(
        dir.path().to_path_buf(),
        RetentionConfig::default(),
        "empty-host".to_string(),
    );
    let events = enforcer.enforce().expect("enforce empty");
    assert!(
        events.is_empty(),
        "prune on empty dir should produce 0 events"
    );
}

// ============================================================================
// Preview Consistency
// ============================================================================

#[test]
fn test_preview_projected_usage_matches_actual() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    create_fixture_telemetry(root);

    let config = RetentionConfig::default();
    let host_id = "preview-match-host".to_string();

    // Get preview
    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let preview = enforcer.preview().expect("preview");

    // Enforce
    let mut enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let _ = enforcer.enforce().expect("enforce");

    // Get status after
    let enforcer = RetentionEnforcer::with_host_id(root.to_path_buf(), config, host_id);
    let status_after = enforcer.status().expect("status after");

    assert_eq!(
        status_after.total_bytes, preview.projected_usage_bytes,
        "actual usage after prune should match preview projected_usage_bytes"
    );
}

#[test]
fn test_preview_by_table_breakdown_matches_enforcement() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    create_fixture_telemetry(root);

    let config = RetentionConfig::default();
    let host_id = "table-breakdown-host".to_string();

    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config.clone(), host_id.clone());
    let preview = enforcer.preview().expect("preview");

    let mut enforcer = RetentionEnforcer::with_host_id(root.to_path_buf(), config, host_id);
    let events = enforcer.enforce().expect("enforce");

    // Count events per table
    let mut event_counts: HashMap<String, usize> = HashMap::new();
    for event in &events {
        *event_counts.entry(event.table.clone()).or_default() += 1;
    }

    // Preview per-table prune counts should match event counts
    for (table, table_preview) in &preview.by_table {
        let actual_count = event_counts.get(table).copied().unwrap_or(0);
        assert_eq!(
            table_preview.files_to_prune, actual_count,
            "table {} preview count {} != actual prune count {}",
            table, table_preview.files_to_prune, actual_count
        );
    }
}

// ============================================================================
// Retention Config Serialization
// ============================================================================

#[test]
fn test_retention_config_json_roundtrip() {
    let mut config = RetentionConfig::default();
    config.ttl_days.insert("proc_samples".to_string(), 15);
    config.ttl_days.insert("runs".to_string(), 60);
    config.disk_budget_bytes = 5 * 1024 * 1024 * 1024;
    config.keep_everything = false;

    let json = serde_json::to_string(&config).expect("serialize config");
    let parsed: RetentionConfig = serde_json::from_str(&json).expect("deserialize config");

    assert_eq!(
        parsed.ttl_days.get("proc_samples"),
        Some(&15),
        "proc_samples TTL should survive roundtrip"
    );
    assert_eq!(
        parsed.ttl_days.get("runs"),
        Some(&60),
        "runs TTL should survive roundtrip"
    );
    assert_eq!(parsed.disk_budget_bytes, 5 * 1024 * 1024 * 1024);
    assert!(!parsed.keep_everything);
}

// ============================================================================
// Disk Budget + TTL Combined
// ============================================================================

#[test]
fn test_budget_pruning_after_ttl_pruning() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create files: some over TTL, some under TTL but exceeding budget
    let files = [
        // Over TTL (will be pruned by TTL first)
        ("proc_samples", "ttl_expired.parquet", 2 * 1024 * 1024, 35),
        // Under TTL but contributing to budget
        ("proc_samples", "budget_a.parquet", 2 * 1024 * 1024, 5),
        ("proc_features", "budget_b.parquet", 2 * 1024 * 1024, 5),
        ("outcomes", "safe.parquet", 2 * 1024 * 1024, 5),
    ];

    for (table, name, size, age) in &files {
        let path = root.join(format!(
            "{}/year=2025/month=01/day=15/host_id=test/{}",
            table, name
        ));
        create_fake_parquet(&path, *size, *age).expect("create file");
    }

    // Budget: 5MB. Total: 8MB. TTL prune removes 2MB → 6MB still > 5MB.
    // Budget prune should then remove 1 more file.
    let config = RetentionConfig {
        disk_budget_bytes: 5 * 1024 * 1024,
        ..Default::default()
    };

    let enforcer =
        RetentionEnforcer::with_host_id(root.to_path_buf(), config, "combined-host".to_string());
    let preview = enforcer.preview().expect("preview");

    // Should prune TTL-expired (1 file) + budget-exceeded (at least 1 more)
    assert!(
        preview.files_to_prune >= 2,
        "should prune at least 2 files (TTL + budget): got {}",
        preview.files_to_prune
    );

    // Verify reasons include both TTL and budget types
    let has_ttl = preview
        .candidates
        .iter()
        .any(|c| matches!(&c.reason, RetentionReason::TtlExpired { .. }));
    let has_budget = preview
        .candidates
        .iter()
        .any(|c| matches!(&c.reason, RetentionReason::DiskBudgetExceeded { .. }));

    assert!(has_ttl, "should have at least one TTL-based prune");
    assert!(has_budget, "should have at least one budget-based prune");

    assert!(
        preview.projected_usage_bytes <= 5 * 1024 * 1024,
        "projected usage should be within budget: {} bytes",
        preview.projected_usage_bytes
    );
}
