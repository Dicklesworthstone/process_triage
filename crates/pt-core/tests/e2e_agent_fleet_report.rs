//! E2E tests for `agent fleet report`.
//!
//! Verifies deterministic report sections, profile-based redaction, and --out output writing.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::SessionId;
use pt_core::session::fleet::{create_fleet_session, CandidateInfo, HostInput};
use pt_core::session::{SessionManifest, SessionMode, SessionStore};
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

    let old_data = env::var("PROCESS_TRIAGE_DATA").ok();
    let data_dir = TempDir::new().expect("create temp data dir");
    env::set_var("PROCESS_TRIAGE_DATA", data_dir.path());

    let result = f(&data_dir);

    match old_data {
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

fn kill_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "zombie".to_string(),
        recommended_action: "kill".to_string(),
        score,
        e_value: None,
    }
}

fn review_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "abandoned".to_string(),
        recommended_action: "review".to_string(),
        score,
        e_value: None,
    }
}

fn spare_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "useful".to_string(),
        recommended_action: "spare".to_string(),
        score,
        e_value: None,
    }
}

fn host_input(id: &str, candidates: Vec<CandidateInfo>) -> HostInput {
    HostInput {
        host_id: id.to_string(),
        session_id: format!("session-{}", id),
        scanned_at: "2026-02-08T12:00:00Z".to_string(),
        total_processes: 250 + candidates.len() as u32,
        candidates,
    }
}

fn create_fixture_fleet_session() -> String {
    let session_id = SessionId::new();
    let store = SessionStore::from_env().expect("session store");
    let manifest = SessionManifest::new(
        &session_id,
        None,
        SessionMode::RobotPlan,
        Some("fleet-report-fixture".to_string()),
    );
    let handle = store.create(&manifest).expect("create session");

    let inputs = vec![
        host_input(
            "alpha.internal",
            vec![
                kill_candidate(1001, "orphaned_node_dev_server", 0.99),
                kill_candidate(1002, "orphaned_node_dev_server", 0.97),
                review_candidate(1003, "stale_pytest_worker", 0.78),
            ],
        ),
        host_input(
            "beta.internal",
            vec![
                kill_candidate(2001, "orphaned_node_dev_server", 0.98),
                kill_candidate(2002, "hung_vite_hot_reload", 0.95),
                spare_candidate(2003, "shell_idle", 0.11),
            ],
        ),
        host_input(
            "gamma.internal",
            vec![
                review_candidate(3001, "stale_pytest_worker", 0.82),
                review_candidate(3002, "stale_pytest_worker", 0.81),
                kill_candidate(3003, "hung_vite_hot_reload", 0.91),
            ],
        ),
    ];

    let fleet = create_fleet_session(&session_id.0, Some("fixture"), &inputs, 0.05);
    let fleet_path = handle.dir.join("fleet.json");
    let payload = serde_json::to_string_pretty(&fleet).expect("serialize fleet");
    fs::write(&fleet_path, payload).expect("write fleet session");

    session_id.0
}

/// Fleet apply executes nothing remotely yet: it lists the plan but must not exit 0,
/// so no script mistakes it for an apply that ran.
#[test]
fn fleet_apply_reports_not_implemented_and_exits_nonzero() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "apply",
                "--fleet-session",
                &fleet_session_id,
            ])
            .assert()
            .code(11)
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).expect("valid json");
        assert_eq!(json["status"], "not_implemented");
        assert_eq!(json["planned_actions"]["total_kill_candidates"], 5);
    });
}

#[test]
fn fleet_report_json_contains_expected_sections() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "report",
                "--fleet-session",
                &fleet_session_id,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid json");
        let report = json.get("report").expect("report section");

        assert_eq!(
            report.get("profile").and_then(|v| v.as_str()),
            Some("safe"),
            "default profile should be safe"
        );
        assert!(
            report
                .get("top_offenders")
                .and_then(|v| v.as_array())
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            "top_offenders should be non-empty for recurring signatures"
        );
        assert!(
            report
                .get("host_comparison")
                .and_then(|v| v.as_array())
                .map(|v| v.iter().all(|host| host.get("rank").is_some()))
                .unwrap_or(false),
            "host_comparison should include deterministic rank ordering"
        );
        assert!(
            report
                .get("cross_host_anomalies")
                .and_then(|v| v.get("pattern_hotspots"))
                .and_then(|v| v.as_array())
                .is_some(),
            "cross_host_anomalies should include pattern_hotspots"
        );
    });
}

#[test]
fn fleet_report_minimal_profile_redacts_hosts_and_signatures() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "report",
                "--fleet-session",
                &fleet_session_id,
                "--profile",
                "minimal",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let rendered = String::from_utf8(output.clone()).expect("utf8");
        assert!(
            !rendered.contains("alpha.internal")
                && !rendered.contains("beta.internal")
                && !rendered.contains("gamma.internal"),
            "minimal profile should redact host IDs"
        );
        assert!(
            !rendered.contains("orphaned_node_dev_server")
                && !rendered.contains("stale_pytest_worker")
                && !rendered.contains("hung_vite_hot_reload"),
            "minimal profile should redact signatures"
        );

        let json: Value = serde_json::from_slice(&output).expect("valid json");
        let first_host = json["report"]["host_comparison"][0]["host_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let first_signature = json["report"]["top_offenders"][0]["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(first_host.starts_with("host_"));
        assert!(first_signature.starts_with("sig_"));
    });
}

#[test]
fn fleet_report_writes_json_output_file() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let out_path = data_dir.path().join("reports").join("fleet_report.json");

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "report",
                "--fleet-session",
                &fleet_session_id,
                "--out",
                out_path.to_str().expect("utf8 path"),
            ])
            .assert()
            .success();

        assert!(out_path.exists(), "--out should create report file");
        let content = fs::read_to_string(&out_path).expect("read output file");
        let json: Value = serde_json::from_str(&content).expect("file should contain valid json");
        assert_eq!(
            json.get("fleet_session_id").and_then(|v| v.as_str()),
            Some(fleet_session_id.as_str())
        );
        assert!(
            json.get("report")
                .and_then(|v| v.get("top_offenders"))
                .is_some(),
            "written report should include computed sections"
        );
    });
}
