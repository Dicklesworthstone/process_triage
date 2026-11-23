//! Session persistence tests (t6lf).
//!
//! These tests validate that session artifacts are written to disk and that
//! commands can reuse an existing session id via `--session`.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn unique_data_dir() -> PathBuf {
    let id = uuid::Uuid::new_v4().simple().to_string();
    PathBuf::from("/tmp").join(format!("pt-core-session-test-{}", id))
}

fn pt_core_with_data_dir(data_dir: &PathBuf) -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    // Allow enough time for full plan runs on busy CI hosts.
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PROCESS_TRIAGE_DATA", data_dir);
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

#[test]
fn snapshot_creates_session_directory_with_manifest_and_context() {
    let data_dir = unique_data_dir();

    let output = pt_core_with_data_dir(&data_dir)
        .args(["--format", "json", "agent", "snapshot"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("valid JSON");
    let session_id = json
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id");

    let session_root = data_dir.join("sessions").join(session_id);
    let manifest_path = session_root.join("manifest.json");
    let context_path = session_root.join("context.json");

    assert!(
        manifest_path.exists(),
        "manifest.json should exist at {}",
        manifest_path.display()
    );
    assert!(
        context_path.exists(),
        "context.json should exist at {}",
        context_path.display()
    );

    let manifest_raw = fs::read_to_string(&manifest_path).expect("read manifest");
    let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest JSON");
    assert_eq!(
        manifest.get("session_id").and_then(|v| v.as_str()),
        Some(session_id)
    );
}

#[test]
fn plan_with_session_reuses_session_id_and_writes_plan_artifact() {
    let data_dir = unique_data_dir();

    // Create snapshot session.
    let snapshot_output = pt_core_with_data_dir(&data_dir)
        .args(["--format", "json", "agent", "snapshot"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot: Value = serde_json::from_slice(&snapshot_output).unwrap();
    let session_id = snapshot
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id")
        .to_string();

    // Run plan against the same session.
    // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
    let plan_output = pt_core_with_data_dir(&data_dir)
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--sample-size",
            "50",
            "--session",
            &session_id,
        ])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    assert_eq!(
        plan.get("session_id").and_then(|v| v.as_str()),
        Some(session_id.as_str())
    );

    // Verify plan artifact exists.
    let plan_path = data_dir
        .join("sessions")
        .join(&session_id)
        .join("decision")
        .join("plan.json");
    assert!(
        plan_path.exists(),
        "plan.json should exist at {}",
        plan_path.display()
    );
}

#[test]
fn plan_writes_session_event_log() {
    let data_dir = unique_data_dir();

    let plan_output = pt_core_with_data_dir(&data_dir)
        .args(["--format", "json", "agent", "plan", "--sample-size", "50"])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .stdout
        .clone();

    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let session_id = plan
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id");

    let log_path = data_dir
        .join("sessions")
        .join(session_id)
        .join("logs")
        .join("session.jsonl");

    assert!(
        log_path.exists(),
        "session.jsonl should exist at {}",
        log_path.display()
    );

    let content = fs::read_to_string(&log_path).expect("read session log");
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "session log should not be empty");

    let first: Value = serde_json::from_str(lines[0]).expect("event JSON");
    assert!(first.get("event").is_some(), "event field missing");
    assert_eq!(
        first.get("session_id").and_then(|v| v.as_str()),
        Some(session_id)
    );
}

#[test]
fn agent_tail_reads_session_log() {
    let data_dir = unique_data_dir();

    let plan_output = pt_core_with_data_dir(&data_dir)
        .args(["--format", "json", "agent", "plan", "--sample-size", "50"])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .stdout
        .clone();

    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let session_id = plan
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id");

    let tail_output = pt_core_with_data_dir(&data_dir)
        .args(["agent", "tail", "--session", session_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(tail_output).expect("utf8");
    let mut events = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let value: Value = serde_json::from_str(line).expect("valid JSONL line");
        events.push(value);
    }

    assert!(!events.is_empty(), "tail output should not be empty");

    let mut has_session_started = false;
    let mut has_session_ended = false;
    let mut has_plan_ready = false;
    let mut has_inference_started = false;
    let mut has_decision_started = false;

    for event in &events {
        let name = event.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let evt_session = event.get("session_id").and_then(|v| v.as_str());
        assert_eq!(evt_session, Some(session_id));
        match name {
            "session_started" => has_session_started = true,
            "session_ended" => has_session_ended = true,
            "plan_ready" => has_plan_ready = true,
            "inference_started" => has_inference_started = true,
            "decision_started" => has_decision_started = true,
            _ => {}
        }
    }

    assert!(has_session_started, "missing session_started event");
    assert!(has_session_ended, "missing session_ended event");
    assert!(has_plan_ready, "missing plan_ready event");
    assert!(has_inference_started, "missing inference_started event");
    assert!(has_decision_started, "missing decision_started event");
}

#[cfg(target_os = "linux")]
#[test]
fn session_creation_advances_bounded_retention_across_processes() {
    use chrono::Utc;
    use pt_common::SessionId;
    use pt_core::session::{SessionManifest, SessionMode, SessionState};

    let data_dir = unique_data_dir();
    let sessions = data_dir.join("sessions");
    let make_session = |suffix: &str, old: bool, state: SessionState| {
        let id = SessionId(format!("pt-20260101-000000-{suffix}"));
        assert!(SessionId::parse(&id.0).is_some());
        let path = sessions.join(&id.0);
        fs::create_dir_all(path.join("action")).unwrap();
        let mut manifest = SessionManifest::new(&id, None, SessionMode::RobotPlan, None);
        manifest.state = state;
        if old {
            manifest.timing.created_at = (Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        }
        fs::write(
            path.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        path
    };
    // More preserved entries than a single automatic pass may enumerate. The
    // cursor must cross this prefix on later real invocations, without parsing
    // plan/inference payloads or hiding unfinished work behind the hourly marker.
    let fresh: Vec<_> = (0..140u8)
        .map(|index| {
            let suffix = format!(
                "aa{}{}",
                char::from(b'a' + index / 26),
                char::from(b'a' + index % 26)
            );
            make_session(&suffix, false, SessionState::Planned)
        })
        .collect();
    let executing = make_session("exec", true, SessionState::Executing);
    let reversible = make_session("undo", true, SessionState::Completed);
    fs::create_dir(reversible.join("action/reversals")).unwrap();
    let malformed = make_session("badx", true, SessionState::Completed);
    fs::write(malformed.join("manifest.json"), b"incomplete").unwrap();
    let old = make_session("oldx", true, SessionState::Completed);
    let tree = make_session("tree", true, SessionState::Scanning);
    let probes = tree.join("scan/probes");
    fs::create_dir_all(&probes).unwrap();
    for index in 0..400 {
        fs::write(probes.join(index.to_string()), b"expired probe").unwrap();
    }
    let mut observed_partial = false;
    let mut completed = false;
    // A busy host may consume a whole production GC slice before it gets CPU
    // time to enumerate anything. Bound the overall test, not the number of
    // legitimate partial passes, and keep every child inside that same deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
        if remaining.is_zero() {
            break;
        }
        pt_core_with_data_dir(&data_dir)
            .timeout(remaining)
            .env("PROCESS_TRIAGE_RETENTION", "7")
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success();
        let progress: Value =
            serde_json::from_slice(&fs::read(sessions.join(".retention-progress.json")).unwrap())
                .unwrap();
        if progress["in_progress"] == true {
            observed_partial = true;
            assert!(!sessions.join(".last_gc").exists());
            if tree.exists() {
                assert!(tree.join("manifest.json").exists());
            }
        } else {
            completed = true;
            break;
        }
    }
    assert!(
        observed_partial,
        "backlog must require multiple bounded invocations"
    );
    assert!(
        completed,
        "independent processes must resume rather than restart GC within the 60-second deadline"
    );
    assert!(!old.exists());
    assert!(!tree.exists());
    assert!(fresh
        .iter()
        .all(|path| path.join("manifest.json").is_file()));
    assert!(executing.join("manifest.json").is_file());
    assert!(reversible.join("action/reversals").is_dir());
    assert_eq!(
        fs::read(malformed.join("manifest.json")).unwrap(),
        b"incomplete"
    );
    let report: Value =
        serde_json::from_slice(&fs::read(sessions.join(".last_gc")).unwrap()).unwrap();
    assert_eq!(report["complete"], true);
    assert!(report["entries"].as_u64().unwrap() <= 128);
    assert!(report["sessions"].as_u64().unwrap() <= 32);
    assert!(report["tree_nodes"].as_u64().unwrap() <= 256);
}
