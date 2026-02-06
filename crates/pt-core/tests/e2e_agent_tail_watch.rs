//! E2E tests for `agent tail` and `agent watch --once` commands.
//!
//! Tests these streaming subcommands end-to-end through the CLI binary.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::SessionId;
use pt_core::exit_codes::ExitCode;
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::env;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_temp_data_dir<T>(f: impl FnOnce(&TempDir) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let old = env::var("PROCESS_TRIAGE_DATA").ok();
    let dir = TempDir::new().expect("create temp data dir");
    env::set_var("PROCESS_TRIAGE_DATA", dir.path());

    let result = f(&dir);

    match old {
        Some(val) => env::set_var("PROCESS_TRIAGE_DATA", val),
        None => env::remove_var("PROCESS_TRIAGE_DATA"),
    }

    result
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Create a basic session (no plan needed for tail).
fn create_session(_dir: &TempDir) -> SessionId {
    let store = SessionStore::from_env().expect("session store from env");
    let session_id = SessionId::new();
    let manifest = SessionManifest::new(&session_id, None, SessionMode::RobotPlan, None);
    let handle = store.create(&manifest).expect("create session");
    let ctx = SessionContext::new(
        &session_id,
        "host-test".to_string(),
        "run-test".to_string(),
        None,
    );
    handle.write_context(&ctx).expect("write context");
    session_id
}

// ============================================================================
// agent tail tests
// ============================================================================

#[test]
fn tail_requires_session_flag() {
    pt_core_fast().args(["agent", "tail"]).assert().failure();
}

#[test]
fn tail_invalid_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "tail", "--session", "not-valid"])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn tail_missing_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "tail", "--session", "pt-20260101-000000-zzzz"])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn tail_no_log_file_returns_args_error() {
    with_temp_data_dir(|dir| {
        let session_id = create_session(dir);

        // Session exists but has no logs/session.jsonl
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "tail", "--session", &session_id.0])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn tail_reads_existing_log() {
    with_temp_data_dir(|dir| {
        let session_id = create_session(dir);

        // Create a log file with sample events
        let session_dir = dir.path().join("sessions").join(&session_id.0);
        let logs_dir = session_dir.join("logs");
        fs::create_dir_all(&logs_dir).expect("create logs dir");

        let events = vec![
            r#"{"event":"scan_started","timestamp":"2026-01-01T00:00:00Z","count":10}"#,
            r#"{"event":"inference_complete","timestamp":"2026-01-01T00:00:01Z","candidates":3}"#,
        ];
        fs::write(logs_dir.join("session.jsonl"), events.join("\n") + "\n").expect("write log");

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "tail", "--session", &session_id.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "Expected 2 log lines");

        // Each line should be valid JSONL
        for line in &lines {
            let _: Value = serde_json::from_str(line).expect("valid JSON line");
        }
    });
}

#[test]
fn tail_stops_on_session_ended_event() {
    with_temp_data_dir(|dir| {
        let session_id = create_session(dir);

        let session_dir = dir.path().join("sessions").join(&session_id.0);
        let logs_dir = session_dir.join("logs");
        fs::create_dir_all(&logs_dir).expect("create logs dir");

        // Include a session_ended event — tail should stop after it
        let events = vec![
            r#"{"event":"scan_started","timestamp":"2026-01-01T00:00:00Z"}"#,
            r#"{"event":"session_ended","timestamp":"2026-01-01T00:00:01Z"}"#,
            r#"{"event":"should_not_appear","timestamp":"2026-01-01T00:00:02Z"}"#,
        ];
        fs::write(logs_dir.join("session.jsonl"), events.join("\n") + "\n").expect("write log");

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "tail", "--session", &session_id.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
        // Should have stopped after session_ended (line 2), not printing line 3
        assert_eq!(lines.len(), 2, "Expected tail to stop after session_ended");
    });
}

// ============================================================================
// agent watch tests
// ============================================================================

#[test]
fn watch_requires_jsonl_format() {
    // watch without --format jsonl should fail
    pt_core_fast()
        .args(["--format", "json", "agent", "watch", "--once"])
        .assert()
        .code(ExitCode::ArgsError.as_i32());
}

#[test]
fn watch_once_produces_jsonl() {
    let output = pt_core_fast()
        .args([
            "--format",
            "jsonl",
            "agent",
            "watch",
            "--once",
            "--threshold",
            "low",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    // watch --once should produce at least some output (candidate_detected events)
    // on a real system, though it might be empty if nothing matches threshold
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let json: Value = serde_json::from_str(line).expect("each line should be valid JSON");
        assert!(
            json.get("event").is_some(),
            "Each watch event should have an 'event' field",
        );
        assert!(
            json.get("timestamp").is_some(),
            "Each watch event should have a 'timestamp' field",
        );
    }
}

#[test]
fn watch_invalid_threshold_returns_error() {
    pt_core_fast()
        .args([
            "--format",
            "jsonl",
            "agent",
            "watch",
            "--once",
            "--threshold",
            "invalid_threshold",
        ])
        .assert()
        .code(ExitCode::ArgsError.as_i32());
}

#[test]
fn watch_once_with_high_threshold() {
    // With a high threshold, fewer candidates should match
    let output = pt_core_fast()
        .args([
            "--format",
            "jsonl",
            "agent",
            "watch",
            "--once",
            "--threshold",
            "critical",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    // Valid output (may be empty with critical threshold)
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let json: Value = serde_json::from_str(line).expect("valid JSON line");
        assert!(json.get("event").is_some());
    }
}

#[test]
fn watch_once_with_min_age() {
    // --min-age should filter out young processes
    let output = pt_core_fast()
        .args([
            "--format",
            "jsonl",
            "agent",
            "watch",
            "--once",
            "--threshold",
            "low",
            "--min-age",
            "86400", // Only processes older than 1 day
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let _: Value = serde_json::from_str(line).expect("valid JSON line");
    }
}
