//! E2E tests for saved fleet reports and local execution approval.
//!
//! Verifies deterministic report sections, profile-based redaction, and --out output writing.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{ProcessIdentity, SessionId, StartId};
use pt_core::fleet::apply::{bind_fleet_execution, plan_document_sha256};
use pt_core::fleet::ssh_scan::{
    parse_remote_plan, scan_result_to_host_input, FleetScanResult, HostScanResult, SshScanConfig,
};
use pt_core::plan::ActionTimeouts;
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

fn executable_document(host_id: &str, session_id: &str, pids: &[u32]) -> Value {
    let identities: Vec<_> = pids
        .iter()
        .map(|&pid| ProcessIdentity::new(pid, StartId::from_linux("fixture-boot", 42, pid), 1000))
        .collect();
    serde_json::json!({
        "command": "agent plan",
        "host_id": host_id,
        "session_id": session_id,
        "plan_id": "fixture-plan",
        "generated_at": "2026-11-05T12:00:00Z",
        "policy_id": null,
        "policy_version": "1.0.0",
        "pre_toggled": [],
        "gates_summary": {"total_candidates": pids.len(), "blocked_candidates": 0, "pre_toggled_actions": 0},
        "summary": {"total_processes_scanned": pids.len()},
        "policy_snapshot": pt_core::config::Policy::default(),
        "actions": identities.iter().enumerate().map(|(order, identity)| serde_json::json!({
            "action_id": format!("kill-{}", identity.pid.0),
            "target": identity,
            "action": "kill",
            "order": order,
            "stage": 0,
            "timeouts": ActionTimeouts::default(),
            "pre_checks": [],
            "rationale": {},
            "on_success": [],
            "on_failure": [],
            "blocked": false,
        })).collect::<Vec<_>>(),
        "candidates": identities.iter().enumerate().map(|(order, identity)| serde_json::json!({
            "pid": identity.pid.0,
            "start_id": identity.start_id,
            "uid": identity.uid,
            "action_target": identity,
            "recommended_action": "kill",
            "recommendation": "KILL",
            "command_short": "fixture-worker",
            "classification": "abandoned",
            "posterior": {"abandoned": if order == 0 {0.999} else {0.4}, "zombie": 0.0},
        })).collect::<Vec<_>>(),
    })
}

fn create_bound_fleet_fixture() -> String {
    let document = executable_document("machine-alpha", &SessionId::new().0, &[1001, 1002]);
    let scan = FleetScanResult {
        total_hosts: 1,
        successful: 1,
        failed: 0,
        duration_ms: 1,
        provenance_aggregate: None,
        results: vec![HostScanResult {
            host: "fixture.invalid".into(),
            success: true,
            plan: Some(parse_remote_plan(&document.to_string()).unwrap()),
            error: None,
            duration_ms: 1,
            provenance: None,
        }],
    };
    let id = SessionId::new();
    let store = SessionStore::from_env().unwrap();
    let handle = store
        .create(&SessionManifest::new(
            &id,
            None,
            SessionMode::RobotPlan,
            None,
        ))
        .unwrap();
    let inputs: Vec<_> = scan.results.iter().map(scan_result_to_host_input).collect();
    let mut fleet = create_fleet_session(&id.0, None, &inputs, 0.05);
    fleet.execution = Some(bind_fleet_execution(
        &fleet,
        &scan,
        &SshScanConfig::default(),
    ));
    fs::write(
        handle.dir.join("fleet.json"),
        serde_json::to_vec(&fleet).unwrap(),
    )
    .unwrap();
    id.0
}

/// Old summaries contain no executable identity or retained plan evidence.
#[test]
fn fleet_apply_refuses_summary_only_sessions() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PATH", data_dir.path())
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
            .code(10)
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).expect("valid json");
        assert_eq!(json["status"], "error");
        assert!(json["error"].as_str().unwrap().contains("summaries only"));
    });
}

#[test]
fn fleet_apply_preview_and_dry_run_keep_exact_pooled_selection_without_dispatch() {
    with_temp_data_dir(|data_dir| {
        let session_id = create_bound_fleet_fixture();
        for flags in [
            vec![],
            vec!["--confirm", "--dry-run"],
            vec!["--confirm", "--shadow"],
        ] {
            let output = pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", data_dir.path())
                .env("PATH", data_dir.path())
                .args([
                    "--format",
                    "json",
                    "agent",
                    "fleet",
                    "apply",
                    "--session",
                    &session_id,
                ])
                .args(flags)
                .assert()
                .code(1)
                .get_output()
                .stdout
                .clone();
            let response: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(response["status"], "preview");
            assert_eq!(response["planning_only"], true);
            assert_eq!(response["summary"]["attempted_hosts"], 0);
            assert!(response["receipt_path"].is_null());
            let host = &response["hosts"][0];
            assert_eq!(host["status"], "preview");
            assert_eq!(host["attempted"], false);
            assert_eq!(host["selected_targets"].as_array().unwrap().len(), 1);
            assert_eq!(host["selected_targets"][0]["pid"], 1001);
            assert_eq!(host["binding"]["host_id"], "machine-alpha");
        }
    });
}

#[test]
fn fleet_confirmed_cap_refusal_persists_intent_and_zero_attempt_receipts() {
    with_temp_data_dir(|data_dir| {
        let session_id = create_bound_fleet_fixture();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PATH", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "apply",
                "--session",
                &session_id,
                "--confirm",
                "--max-kills-per-host",
                "0",
            ])
            .assert()
            .code(4)
            .get_output()
            .stdout
            .clone();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["summary"]["attempted_hosts"], 0);
        assert_eq!(response["hosts"][0]["attempted"], false);
        assert_eq!(
            response["fdr_approval"]["scope"],
            "complete_planned_kill_set"
        );
        assert_eq!(
            response["fdr_approval"]["applies_to_partial_or_unknown_execution"],
            false
        );
        let content = fs::read_to_string(response["receipt_path"].as_str().unwrap()).unwrap();
        let records: Vec<Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            records
                .iter()
                .map(|record| record["event"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["intent", "host_result", "finished"]
        );
        assert_eq!(records[0]["completion_without_receipt"], "unknown");
        assert_eq!(records[0]["fdr_approval"], response["fdr_approval"]);
        assert_eq!(records[0]["hosts"][0]["request"]["targets"][0]["pid"], 1001);
        assert_eq!(records[1]["result"]["status"], "blocked");
        assert_eq!(records[1]["result"]["kill_signals_delivered"], 0);
    });
}

#[test]
fn remote_apply_checks_host_and_document_before_resume_or_no_actions() {
    with_temp_data_dir(|data_dir| {
        let config_dir = TempDir::new().unwrap();
        let session_id = SessionId::new();
        let store = SessionStore::from_env().unwrap();
        let handle = store
            .create(&SessionManifest::new(
                &session_id,
                None,
                SessionMode::RobotPlan,
                None,
            ))
            .unwrap();
        let host_id = pt_core::logging::get_host_id();
        let document = executable_document(&host_id, &session_id.0, &[]);
        let digest = plan_document_sha256(&document).unwrap();
        fs::create_dir_all(handle.dir.join("decision")).unwrap();
        fs::write(
            handle.dir.join("decision/plan.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let run = |expected_host: &str, expected_digest: &str, exit_code: i32| {
            let output = pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", data_dir.path())
                .env("PT_CONFIG_DIR", config_dir.path())
                .env("PATH", data_dir.path())
                .args([
                    "--format",
                    "json",
                    "agent",
                    "apply",
                    "--session",
                    &session_id.0,
                    "--recommended",
                    "--resume",
                    "--yes",
                    "--expected-host-id",
                    expected_host,
                    "--expected-plan-sha256",
                    expected_digest,
                ])
                .assert()
                .code(exit_code)
                .get_output()
                .stdout
                .clone();
            serde_json::from_slice::<Value>(&output).unwrap()
        };
        let response = run(&host_id, &digest, 0);
        assert_eq!(response["note"], "nothing_to_do");
        assert_eq!(response["execution_binding"]["host_id"], host_id);
        assert_eq!(response["execution_binding"]["plan_sha256"], digest);
        fs::create_dir_all(handle.dir.join("action")).unwrap();
        fs::write(
            handle.dir.join("action/outcomes.jsonl"),
            "invalid saved outcome\n",
        )
        .unwrap();
        for (expected_host, expected_digest) in [
            ("wrong-host", digest.as_str()),
            (
                host_id.as_str(),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let response = run(expected_host, expected_digest, 4);
            assert_eq!(response["error"], "fleet_binding_mismatch");
            assert_eq!(
                response["expected_execution_binding"]["host_id"],
                expected_host
            );
            assert!(response["outcomes"].as_array().unwrap().is_empty());
        }
    });
}

/// The documented `--session` spelling works for fleet commands.
#[test]
fn fleet_status_accepts_documented_session_flag() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                "status",
                "--session",
                &fleet_session_id,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).expect("valid json");
        assert!(json.to_string().contains(&fleet_session_id), "{json}");
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
