//! CLI E2E tests for `pt-core shadow` subcommands.
//!
//! Validates:
//! - `pt-core shadow status` JSON schema and exit codes
//! - `pt-core shadow stop` when not running (clean exit)
//! - `pt-core shadow export` with empty and populated stores
//! - `pt-core shadow export --export-format jsonl` variant
//! - `pt-core shadow report` with empty and populated stores
//! - `pt-core shadow start --iterations 1` foreground lifecycle
//! - Fixture-based export/report round-trip (write observations, export, report)
//! - Error paths: invalid export path, missing data dir
//! - Exit codes for all success and error paths
//!
//! See: bd-2663

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

// ============================================================================
// Helpers
// ============================================================================

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(60));
    cmd
}

/// Parse any JSON values embedded in stdout by scanning for `{` / `[` and
/// attempting JSON deserialization from that byte offset.
///
/// Some `pt-core` subcommands may emit progress JSONL or other informational
/// lines alongside structured JSON output; this keeps tests resilient by
/// extracting the structured payload(s) from mixed stdout.
fn parse_embedded_json_values(stdout: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(stdout);
    let bytes = text.as_bytes();
    let mut values = Vec::new();

    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'{' || b == b'[' {
            let sub = &text[i..];
            let mut stream = serde_json::Deserializer::from_str(sub).into_iter::<Value>();
            if let Some(Ok(v)) = stream.next() {
                let consumed = stream.byte_offset();
                values.push(v);
                i += consumed.max(1);
                continue;
            }
        }
        i += 1;
    }

    values
}

/// Parse the last structured JSON object from stdout.
fn parse_last_json_object(stdout: &[u8]) -> Value {
    parse_embedded_json_values(stdout)
        .into_iter()
        .rev()
        .find(|v| v.is_object())
        .expect("expected at least one JSON object in stdout")
}

/// Parse the last structured JSON object that matches `{"command": <value>}`.
fn parse_last_json_object_with_command(stdout: &[u8], command: &str) -> Value {
    let values = parse_embedded_json_values(stdout);
    for v in values.into_iter().rev() {
        if v.get("command").and_then(|c| c.as_str()) == Some(command) {
            return v;
        }
    }

    // Fallback: accept any JSON object so tests fail with more context later.
    parse_last_json_object(stdout)
}

/// Create a minimal observation JSON file in a shadow storage dir.
/// Returns the path to the created file.
fn write_fixture_observations(base_dir: &std::path::Path, count: usize) -> std::path::PathBuf {
    let obs_dir = base_dir.join("observations");
    fs::create_dir_all(&obs_dir).expect("create observations dir");

    let mut observations = Vec::new();
    for i in 0..count {
        observations.push(serde_json::json!({
            "timestamp": format!("2026-01-15T10:{:02}:00Z", i % 60),
            "pid": 1000 + i as u32,
            "identity_hash": format!("hash_{}", i),
            "state": {
                "cpu_percent": 5.0 + (i as f32),
                "memory_bytes": 1024 * 1024 * (i + 1),
                "rss_bytes": 512 * 1024 * (i + 1),
                "fd_count": 10 + i as u32,
                "thread_count": 1,
                "state_char": "S",
                "io_read_bytes": 0,
                "io_write_bytes": 0,
                "has_tty": false,
                "child_count": 0
            },
            "events": [],
            "belief": {
                "p_abandoned": 0.6 + (i as f32 * 0.01),
                "p_legitimate": 0.2,
                "p_zombie": 0.1,
                "p_useful_but_bad": 0.1,
                "confidence": 0.8,
                "score": 60.0 + (i as f32),
                "recommendation": "review"
            }
        }));
    }

    let obs_path = obs_dir.join("fixture.json");
    let content = serde_json::to_string_pretty(&observations).expect("serialize observations");
    let mut f = fs::File::create(&obs_path).expect("create fixture file");
    f.write_all(content.as_bytes()).expect("write fixture");
    obs_path
}

// ============================================================================
// Shadow Status
// ============================================================================

#[test]
fn test_shadow_status_success() {
    let dir = tempdir().expect("tempdir");

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_shadow_status_json_schema() {
    let dir = tempdir().expect("tempdir");

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(json["command"], "shadow status");
    assert!(
        json.get("running").is_some(),
        "status should have 'running' field"
    );
    assert!(
        json.get("pid").is_some(),
        "status should have 'pid' field"
    );
    assert!(
        json.get("stale_pid_file").is_some(),
        "status should have 'stale_pid_file' field"
    );
    assert!(
        json.get("base_dir").is_some(),
        "status should have 'base_dir' field"
    );
    assert!(
        json.get("stats").is_some(),
        "status should have 'stats' field"
    );
}

#[test]
fn test_shadow_status_not_running() {
    let dir = tempdir().expect("tempdir");

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(json["running"], false, "should not be running");
    assert!(json["pid"].is_null(), "pid should be null when not running");
    assert_eq!(
        json["stale_pid_file"], false,
        "no stale pid file in fresh dir"
    );
}

#[test]
fn test_shadow_status_stale_pid_detection() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    fs::create_dir_all(&shadow_dir).expect("create shadow dir");

    // Write a PID file for a process that doesn't exist (PID 999999)
    let pid_path = shadow_dir.join("shadow.pid");
    fs::write(&pid_path, "999999").expect("write fake pid");

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(json["running"], false, "stale process should not show as running");
    assert_eq!(
        json["stale_pid_file"], true,
        "should detect stale pid file"
    );
}

// ============================================================================
// Shadow Stop
// ============================================================================

#[test]
fn test_shadow_stop_not_running_success() {
    let dir = tempdir().expect("tempdir");

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "stop"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_shadow_stop_not_running_json_schema() {
    let dir = tempdir().expect("tempdir");

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "stop"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(json["command"], "shadow stop");
    assert_eq!(json["running"], false);
    assert!(
        json.get("message").is_some(),
        "should have message when not running"
    );
}

// ============================================================================
// Shadow Export
// ============================================================================

#[test]
fn test_shadow_export_empty_store_success() {
    let dir = tempdir().expect("tempdir");

    // Export from empty store should produce empty array
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert!(json.is_array(), "empty export should produce JSON array");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "empty export should have 0 observations"
    );
}

#[test]
fn test_shadow_export_with_fixtures() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 3);

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert!(json.is_array(), "export should produce JSON array");

    let observations = json.as_array().unwrap();
    assert_eq!(observations.len(), 3, "should export 3 observations");

    // Verify observation structure
    for (i, obs) in observations.iter().enumerate() {
        assert!(
            obs.get("timestamp").is_some(),
            "observation[{}] should have timestamp",
            i
        );
        assert!(
            obs.get("pid").is_some(),
            "observation[{}] should have pid",
            i
        );
        assert!(
            obs.get("identity_hash").is_some(),
            "observation[{}] should have identity_hash",
            i
        );
        assert!(
            obs.get("state").is_some(),
            "observation[{}] should have state",
            i
        );
        assert!(
            obs.get("belief").is_some(),
            "observation[{}] should have belief",
            i
        );
    }
}

#[test]
fn test_shadow_export_observation_fields() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 1);

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let obs = &json[0];

    // Verify state snapshot fields
    let state = &obs["state"];
    assert!(
        state.get("cpu_percent").is_some(),
        "state should have cpu_percent"
    );
    assert!(
        state.get("memory_bytes").is_some(),
        "state should have memory_bytes"
    );
    assert!(
        state.get("rss_bytes").is_some(),
        "state should have rss_bytes"
    );
    assert!(
        state.get("fd_count").is_some(),
        "state should have fd_count"
    );
    assert!(
        state.get("thread_count").is_some(),
        "state should have thread_count"
    );

    // Verify belief state fields
    let belief = &obs["belief"];
    assert!(
        belief.get("p_abandoned").is_some(),
        "belief should have p_abandoned"
    );
    assert!(
        belief.get("p_legitimate").is_some(),
        "belief should have p_legitimate"
    );
    assert!(
        belief.get("confidence").is_some(),
        "belief should have confidence"
    );
    assert!(
        belief.get("score").is_some(),
        "belief should have score"
    );
    assert!(
        belief.get("recommendation").is_some(),
        "belief should have recommendation"
    );
}

#[test]
fn test_shadow_export_with_limit() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export", "--limit", "2"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let observations = json.as_array().unwrap();
    assert_eq!(
        observations.len(),
        2,
        "should export at most 2 observations with --limit 2"
    );
}

#[test]
fn test_shadow_export_to_file() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 3);

    let output_path = dir.path().join("exported.json");

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "export",
            "-o", output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    // File should exist with valid JSON
    assert!(output_path.exists(), "exported file should exist");
    let content = fs::read_to_string(&output_path).expect("read exported file");
    let file_json: Value = serde_json::from_str(&content).expect("file should be valid JSON");
    assert!(file_json.is_array(), "file should contain JSON array");
    assert_eq!(
        file_json.as_array().unwrap().len(),
        3,
        "file should have 3 observations"
    );

    // Stdout should have metadata response
    let meta: Value = serde_json::from_slice(&output).expect("parse metadata JSON");
    assert_eq!(meta["command"], "shadow export");
    assert_eq!(meta["count"], 3);
}

#[test]
fn test_shadow_export_jsonl_format() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 3);

    let output_path = dir.path().join("exported.jsonl");

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "export",
            "--export-format", "jsonl",
            "-o", output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0);

    let content = fs::read_to_string(&output_path).expect("read JSONL file");
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "JSONL should have 3 lines");

    // Each line should be valid JSON
    for (i, line) in lines.iter().enumerate() {
        let _: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("JSONL line {} should be valid JSON: {}", i, e));
    }
}

#[test]
fn test_shadow_export_chronological_order() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let observations = json.as_array().unwrap();

    // Verify chronological order (earliest first)
    for i in 1..observations.len() {
        let prev_ts = observations[i - 1]["timestamp"].as_str().unwrap();
        let curr_ts = observations[i]["timestamp"].as_str().unwrap();
        assert!(
            prev_ts <= curr_ts,
            "observations should be in chronological order: {} <= {}",
            prev_ts,
            curr_ts
        );
    }
}

// ============================================================================
// Shadow Report
// ============================================================================

#[test]
fn test_shadow_report_empty_store_success() {
    let dir = tempdir().expect("tempdir");

    // Report with no data should succeed (prints message to stderr)
    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "report"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_shadow_report_with_fixtures_structured() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "report"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    // Structured report should be valid JSON
    if !output.is_empty() {
        let json: Value = serde_json::from_slice(&output).expect("parse JSON");
        assert!(json.is_object(), "structured report should be JSON object");
    }
}

#[test]
fn test_shadow_report_to_file() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    let output_path = dir.path().join("report.json");

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "report",
            "-o", output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0);

    // If file was created, it should be valid JSON
    if output_path.exists() {
        let content = fs::read_to_string(&output_path).expect("read report file");
        let _: Value = serde_json::from_str(&content).expect("report file should be valid JSON");
    }
}

#[test]
fn test_shadow_report_with_threshold() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "report",
            "--threshold", "0.9",
        ])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_shadow_report_with_limit() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 10);

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "report",
            "--limit", "3",
        ])
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Shadow Start (foreground, limited iterations)
// ============================================================================

#[test]
fn test_shadow_start_foreground_one_iteration() {
    let dir = tempdir().expect("tempdir");

    // Run 1 iteration in foreground with a short interval and small sample
    // to keep inference fast in CI.
    let mut cmd = pt_core();
    cmd.timeout(Duration::from_secs(300));

    let output = cmd
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "start",
            "--iterations", "1",
            "--interval", "1",
            "--sample-size", "5",
        ])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    // Shadow run inherits stdout from iteration subprocess, so parse the last JSON object
    let json = parse_last_json_object_with_command(&output, "shadow run");
    assert_eq!(json["command"], "shadow run");
    assert_eq!(json["iterations"], 1, "should have completed 1 iteration");
    assert!(
        json.get("base_dir").is_some(),
        "should have base_dir"
    );
}

// ============================================================================
// Shadow Start Background (Lock Detection)
// ============================================================================

#[test]
fn test_shadow_start_background_lock_detection() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    fs::create_dir_all(&shadow_dir).expect("create shadow dir");

    // Write a PID file for this process (which IS running)
    let pid_path = shadow_dir.join("shadow.pid");
    fs::write(&pid_path, std::process::id().to_string()).expect("write pid");

    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "start",
            "--background",
        ])
        .assert()
        .failure()
        .code(14); // LockError
}

#[test]
fn test_shadow_start_background_clears_stale_pid() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    fs::create_dir_all(&shadow_dir).expect("create shadow dir");

    // Write a PID file for a non-existent process
    let pid_path = shadow_dir.join("shadow.pid");
    fs::write(&pid_path, "999999").expect("write stale pid");

    // Starting with a stale PID should succeed (clears stale file + spawns)
    // We use start without --background to avoid actually spawning a daemon
    // and instead test just the foreground path with small sample for speed.
    let mut cmd = pt_core();
    cmd.timeout(Duration::from_secs(300));

    cmd.env("PROCESS_TRIAGE_DATA", dir.path())
        .args([
            "--format", "json",
            "shadow", "start",
            "--iterations", "1",
            "--interval", "1",
            "--sample-size", "5",
        ])
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Export → Report Round-Trip
// ============================================================================

#[test]
fn test_shadow_export_report_round_trip() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 5);

    // Step 1: Export observations
    let export_output = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let exported: Value = serde_json::from_slice(&export_output).expect("parse export JSON");
    let obs_count = exported.as_array().unwrap().len();
    assert!(obs_count > 0, "should have exported observations");

    // Step 2: Generate report
    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "report"])
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Status → Start → Status → Stop → Status Workflow
// ============================================================================

#[test]
fn test_shadow_lifecycle_foreground_workflow() {
    let dir = tempdir().expect("tempdir");
    let dir_str = dir.path().to_str().unwrap();

    // Step 1: Status before start (should not be running)
    let status_before = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir_str)
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_before: Value = serde_json::from_slice(&status_before).expect("parse");
    assert_eq!(json_before["running"], false);

    // Step 2: Run 1 iteration in foreground with small sample for speed
    let mut run_cmd = pt_core();
    run_cmd.timeout(Duration::from_secs(300));

    let run_output = run_cmd
        .env("PROCESS_TRIAGE_DATA", dir_str)
        .args([
            "--format", "json",
            "shadow", "start",
            "--iterations", "1",
            "--interval", "1",
            "--sample-size", "5",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Shadow run inherits stdout from iteration subprocess
    let run_json = parse_last_json_object_with_command(&run_output, "shadow run");
    assert_eq!(run_json["command"], "shadow run");
    assert_eq!(run_json["iterations"], 1);

    // Step 3: Status after run (should not be running since foreground exited)
    let status_after = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir_str)
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_after: Value = serde_json::from_slice(&status_after).expect("parse");
    assert_eq!(json_after["running"], false);

    // Step 4: Stop should be clean (nothing to stop)
    pt_core()
        .env("PROCESS_TRIAGE_DATA", dir_str)
        .args(["--format", "json", "shadow", "stop"])
        .assert()
        .success()
        .code(0);

    eprintln!(
        "[INFO] shadow lifecycle: status(not running) → start(1 iter) → status(not running) → stop(clean)"
    );
}

// ============================================================================
// Output Format Compatibility
// ============================================================================

#[test]
fn test_shadow_commands_work_with_all_formats() {
    let dir = tempdir().expect("tempdir");

    for format in &["json", "toon", "summary"] {
        pt_core()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", format, "shadow", "status"])
            .assert()
            .success();

        pt_core()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", format, "shadow", "stop"])
            .assert()
            .success();

        eprintln!("[INFO] Shadow commands work with format '{}'", format);
    }
}

// ============================================================================
// Determinism
// ============================================================================

#[test]
fn test_shadow_status_deterministic() {
    let dir = tempdir().expect("tempdir");

    let output1 = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output2 = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json1: Value = serde_json::from_slice(&output1).expect("parse 1");
    let json2: Value = serde_json::from_slice(&output2).expect("parse 2");

    assert_eq!(json1["running"], json2["running"]);
    assert_eq!(json1["stale_pid_file"], json2["stale_pid_file"]);
    assert_eq!(json1["command"], json2["command"]);
}

#[test]
fn test_shadow_export_deterministic_with_fixtures() {
    let dir = tempdir().expect("tempdir");
    let shadow_dir = dir.path().join("shadow");
    write_fixture_observations(&shadow_dir, 3);

    let output1 = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output2 = pt_core()
        .env("PROCESS_TRIAGE_DATA", dir.path())
        .args(["--format", "json", "shadow", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json1: Value = serde_json::from_slice(&output1).expect("parse 1");
    let json2: Value = serde_json::from_slice(&output2).expect("parse 2");

    assert_eq!(json1, json2, "export should be deterministic with same fixtures");
}
