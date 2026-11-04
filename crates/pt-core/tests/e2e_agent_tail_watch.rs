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

        let events = [
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
        let events = [
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

#[cfg(unix)]
struct OwnedWatchChild(std::process::Child);

#[cfg(unix)]
impl Drop for OwnedWatchChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn write_watch_review_config(config: &TempDir) {
    let mut policy = pt_core::config::Policy::default();
    // Test explicit review independently of host placement, user identity, or
    // the test runner's own agent ancestry. Watch never executes these actions.
    policy.guardrails.builtin_protection = false;
    policy.guardrails.protected_users.clear();
    policy.guardrails.protected_categories.clear();
    policy.guardrails.never_kill_ppid.clear();
    policy.guardrails.min_process_age_seconds = 0;
    policy.robot_mode.enabled = true;
    let mut pattern = policy.guardrails.protected_patterns[0].clone();
    pattern.pattern = r"\bsleep\b".to_string();
    policy.guardrails.force_review_patterns.push(pattern);
    for row in [
        &mut policy.loss_matrix.useful,
        &mut policy.loss_matrix.useful_bad,
        &mut policy.loss_matrix.abandoned,
        &mut policy.loss_matrix.zombie,
    ] {
        row.keep = 10.0;
        row.kill = 0.0;
        row.pause = Some(10.0);
        row.throttle = Some(10.0);
        row.restart = Some(10.0);
        row.renice = Some(10.0);
    }
    fs::write(
        config.path().join("policy.json"),
        serde_json::to_vec(&policy).expect("serialize policy"),
    )
    .expect("write policy");

    // Equal likelihoods make the owned process cross the watch threshold without
    // relying on sampled CPU, runtime, or the host's process population.
    let mut priors = pt_core::config::Priors::default();
    let mut class = priors.classes.abandoned.clone();
    class.prior_prob = 1e-12;
    class.runtime_gamma = None;
    priors.classes.useful = class.clone();
    priors.classes.useful_bad = class.clone();
    priors.classes.zombie = class.clone();
    class.prior_prob = 1.0 - 3e-12;
    priors.classes.abandoned = class;
    priors.state_flags = None;
    priors.command_categories = None;
    fs::write(
        config.path().join("priors.json"),
        serde_json::to_vec(&priors).expect("serialize priors"),
    )
    .expect("write priors");
}

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

#[test]
fn watch_rejects_invalid_force_review_rule() {
    let config = TempDir::new().expect("config directory");
    let data = TempDir::new().expect("data directory");
    let mut policy = pt_core::config::Policy::default();
    let mut pattern = policy.guardrails.protected_patterns[0].clone();
    pattern.pattern = "[".to_string();
    policy.guardrails.force_review_patterns.push(pattern);
    fs::write(
        config.path().join("policy.json"),
        serde_json::to_vec(&policy).expect("serialize policy"),
    )
    .expect("write policy");

    pt_core_fast()
        .env("PROCESS_TRIAGE_DATA", data.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(config.path())
        .args(["--format", "jsonl", "agent", "watch", "--once"])
        .assert()
        .code(ExitCode::InternalError.as_i32())
        .stderr(predicates::str::contains(
            "agent watch: policy enforcer error",
        ))
        .stderr(predicates::str::contains(
            "guardrails.force_review_patterns",
        ));
}

#[cfg(unix)]
#[test]
fn watch_reports_policy_review_instead_of_raw_kill_decision() {
    let child = OwnedWatchChild(
        std::process::Command::new("sleep")
            .arg("300")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn owned process"),
    );
    let config = TempDir::new().expect("config directory");
    let data = TempDir::new().expect("data directory");
    write_watch_review_config(&config);

    let output = pt_core_fast()
        .env("PROCESS_TRIAGE_DATA", data.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .arg("--config")
        .arg(config.path())
        .args([
            "--robot",
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
    let events: Vec<Value> = String::from_utf8_lossy(&output)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("watch event JSON"))
        .collect();
    let event = events
        .iter()
        .find(|event| {
            event["event"] == "candidate_detected"
                && event["pid"].as_u64() == Some(u64::from(child.0.id()))
        })
        .unwrap_or_else(|| panic!("owned process must produce a watch event: {events:?}"));
    assert_eq!(event["classification"], "review", "{event}");
    assert!(
        event["action_rationale"]
            .as_str()
            .expect("policy rationale")
            .contains("force_review pattern"),
        "{event}"
    );
    assert!(event["confidence"].as_f64().expect("confidence") >= 0.5);
}

#[cfg(unix)]
#[test]
fn watch_clears_owned_process_after_exit_with_the_original_identity() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Instant;

    let config = TempDir::new().expect("config directory");
    let data = TempDir::new().expect("data directory");
    write_watch_review_config(&config);
    let mut workload = OwnedWatchChild(
        std::process::Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owned workload"),
    );
    let workload_pid = workload.0.id();
    let stderr_path = data.path().join("watch.stderr");
    let mut watch = OwnedWatchChild(
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("pt-core"))
            .env("PROCESS_TRIAGE_DATA", data.path())
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .env("PT_SKIP_GLOBAL_LOCK", "1")
            .arg("--config")
            .arg(config.path())
            .args([
                "--robot",
                "--format",
                "jsonl",
                "agent",
                "watch",
                "--threshold",
                "low",
                "--interval",
                "1",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(
                fs::File::create(&stderr_path).expect("watch stderr"),
            ))
            .spawn()
            .expect("start real watch CLI"),
    );
    let output = watch.0.stdout.take().expect("watch stdout");
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut detected_identity = None;
    let cleared = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = receiver
            .recv_timeout(remaining)
            .unwrap_or_else(|error| {
                panic!(
                    "watch did not complete lifecycle: {error}; stderr: {}",
                    fs::read_to_string(&stderr_path).unwrap_or_default()
                )
            })
            .expect("read watch JSONL");
        let event: Value = serde_json::from_str(&line).expect("watch event JSON");
        if event["pid"].as_u64() != Some(u64::from(workload_pid)) {
            continue;
        }
        match event["event"].as_str() {
            Some("candidate_detected") => {
                assert!(detected_identity.is_none(), "duplicate detection: {event}");
                assert_eq!(event["recommended_action"], "review");
                assert!(event["action_target"].is_null());
                let identity: pt_common::ProcessIdentity =
                    serde_json::from_value(event["source_identity"].clone())
                        .expect("complete source identity");
                assert_eq!(identity.pid.0, workload_pid);
                detected_identity = Some(identity);
                // Only the child created by this test is terminated. Watch is
                // read-only and must publish a later clear without executing it.
                workload.0.kill().expect("stop owned workload");
                workload.0.wait().expect("reap owned workload");
            }
            Some("candidate_cleared") => break event,
            _ => {}
        }
    };
    assert_eq!(
        cleared["source_identity"],
        serde_json::to_value(detected_identity.expect("detection must precede clearing")).unwrap()
    );
    assert_eq!(cleared["reason"], "not_observed");
    assert!(cleared["recommended_action"].is_null());
    assert!(cleared["action_target"].is_null());
    assert_eq!(cleared["prior_recommended_action"], "review");
    watch.0.kill().expect("stop owned watcher");
    watch.0.wait().expect("reap owned watcher");
    reader.join().expect("watch output reader");
}
