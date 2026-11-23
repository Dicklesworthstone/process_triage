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

const HEALTH_SAMPLE_MS: u64 = 1_770_552_000_000;
const PRIVATE_HEALTH_MARKERS: [&str; 5] = [
    "private-health-host-metadata",
    "private-health-system-context",
    "private-health-source-path",
    "private-health-sensor-error",
    "private-health-regime-explanation",
];

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
        host: None,
        system_state: None,
        health: Default::default(),
    }
}

fn add_fixture_health(input: &mut HostInput, index: usize) {
    let cpu = if index == 0 { 45.0 } else { 0.0 };
    let mut document = serde_json::json!({
        "generated_at": input.scanned_at,
        "session_id": input.session_id,
        "host": {"hostname": PRIVATE_HEALTH_MARKERS[0]},
        "summary": {"total_processes_scanned": input.total_processes},
        "candidates": [],
        "system_state": {
            "operator_context": PRIVATE_HEALTH_MARKERS[1],
            "census": {"zombies": 0, "dstate": 0},
            "pressure": {
                "sampled_at_ms": HEALTH_SAMPLE_MS + index as u64 * 1000,
                "cpus": 8,
                "cpu": {"some": {"avg10": cpu, "avg60": cpu, "avg300": cpu, "total_us": 100}},
                "memory": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                "io": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                "load": {"one": 1.0, "five": 1.0, "fifteen": 1.0},
                "meminfo": {"total": 16_u64 << 30, "available": 8_u64 << 30, "swap_total": 0, "swap_free": 0},
                "file_handles": {"allocated": 10, "max": 10000},
                "unavailable": []
            }
        }
    });
    if index == 2 {
        document["system_state"]["pressure"]["io"] = Value::Null;
        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": PRIVATE_HEALTH_MARKERS[2], "reason": PRIVATE_HEALTH_MARKERS[3]}
        ]);
    }
    let observation = scan_result_to_host_input(&HostScanResult {
        host: input.host_id.clone(),
        success: true,
        plan: Some(parse_remote_plan(&document.to_string()).expect("parse health fixture")),
        error: None,
        duration_ms: 1,
        provenance: None,
    });
    input.host = observation.host;
    input.system_state = observation.system_state;
    input.health = observation.health;
    if let Some(regime) = input
        .health
        .assessment
        .as_mut()
        .and_then(|assessment| assessment.regimes.first_mut())
    {
        // Free-form explanations are not a safe public-report surface either.
        regime.explanation = PRIVATE_HEALTH_MARKERS[4].to_string();
    }
}

fn assert_fixture_health_counts(health: &Value) {
    assert_eq!(health["healthy_hosts"], 1);
    assert_eq!(health["critical_hosts"], 1);
    assert_eq!(health["warning_hosts"], 0);
    assert_eq!(health["unknown_hosts"], 1);
    assert_eq!(health["partial_hosts"], 1);
    assert_eq!(health["unavailable_hosts"], 0);
    assert_eq!(health["worst_observed"], "crit");
}

fn assert_compact_host_health(health: &Value, index: usize) {
    let mut keys: Vec<_> = health
        .as_object()
        .expect("compact health object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "coverage",
            "observed_regimes",
            "sampled_at_ms",
            "status",
            "unavailable_sources"
        ]
    );
    assert_eq!(
        health["sampled_at_ms"],
        HEALTH_SAMPLE_MS + index as u64 * 1000
    );
    assert_eq!(health["status"], ["crit", "ok", "unknown"][index]);
    assert_eq!(
        health["coverage"],
        if index == 2 { "partial" } else { "complete" }
    );
    assert_eq!(
        health["observed_regimes"],
        if index == 0 {
            serde_json::json!(["cpu_contention"])
        } else {
            serde_json::json!([])
        }
    );
    let unavailable = health["unavailable_sources"]
        .as_u64()
        .expect("unavailable source count");
    if index == 2 {
        assert!(unavailable > 0);
    } else {
        assert_eq!(unavailable, 0);
    }
}

fn assert_health_details_private(rendered: &str) {
    for marker in PRIVATE_HEALTH_MARKERS {
        assert!(
            !rendered.contains(marker),
            "raw health detail leaked: {marker}"
        );
    }
}

fn assert_report_host_health(report: &Value) {
    assert_fixture_health_counts(&report["aggregate"]["health"]);
    let rows = report["host_comparison"]
        .as_array()
        .expect("comparison rows");
    assert_eq!(rows.len(), 3);
    for index in 0..3 {
        let timestamp = HEALTH_SAMPLE_MS + index as u64 * 1000;
        let host = rows
            .iter()
            .find(|row| row["health"]["sampled_at_ms"].as_u64() == Some(timestamp))
            .expect("host health remains associated with its own sample");
        assert_compact_host_health(&host["health"], index);
        assert!(host["host_id"].as_str().unwrap().starts_with("host_"));
    }
    assert_eq!(report["hosts"], report["host_comparison"]);
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

    let mut inputs = vec![
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
    for (index, input) in inputs.iter_mut().enumerate() {
        add_fixture_health(input, index);
    }

    let fleet = create_fleet_session(&session_id.0, Some("fixture"), &inputs, 0.05);
    let fleet_path = handle.dir.join("fleet.json");
    let payload = serde_json::to_string_pretty(&fleet).expect("serialize fleet");
    for marker in PRIVATE_HEALTH_MARKERS {
        assert!(
            payload.contains(marker),
            "redaction fixture lost private marker: {marker}"
        );
    }
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
            "rationale": {"posterior": {
                "useful": if order == 0 {0.001} else {0.6},
                "useful_bad": 0.0,
                "abandoned": if order == 0 {0.999} else {0.4},
                "zombie": 0.0,
            }},
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
            "posterior": {
                "useful": if order == 0 {0.001} else {0.6},
                "useful_bad": 0.0,
                "abandoned": if order == 0 {0.999} else {0.4},
                "zombie": 0.0,
            },
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
            "any_subset_of_approved_direct_kill_targets"
        );
        assert_eq!(
            response["fdr_approval"]["applies_to_partial_or_unknown_execution"],
            true
        );
        assert_eq!(response["fdr_approval"]["model_based"], true);
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
        assert_fixture_health_counts(&json["aggregate"]["health"]);
        let hosts = json["host_health"]
            .as_array()
            .expect("host health metadata");
        assert_eq!(hosts.len(), 3);
        for (index, host_id) in ["alpha.internal", "beta.internal", "gamma.internal"]
            .iter()
            .enumerate()
        {
            let host = hosts
                .iter()
                .find(|host| host["host_id"].as_str() == Some(*host_id))
                .expect("each host is present");
            assert_compact_host_health(&host["health"], index);
        }
        assert_health_details_private(&String::from_utf8(output).unwrap());
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
        assert_report_host_health(report);
        assert_health_details_private(&String::from_utf8(output).unwrap());

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
        assert_health_details_private(&rendered);
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
        assert_report_host_health(&json["report"]);
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
        assert_report_host_health(&json["report"]);
        assert_health_details_private(&content);
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

#[test]
fn fleet_status_and_report_prose_distinguish_partial_pressure_from_healthy() {
    with_temp_data_dir(|data_dir| {
        let fleet_session_id = create_fixture_fleet_session();
        for command in ["status", "report"] {
            let output = pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", data_dir.path())
                .args([
                    "--format",
                    "prose",
                    "agent",
                    "fleet",
                    command,
                    "--session",
                    &fleet_session_id,
                ])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            let rendered = String::from_utf8(output).expect("readable pressure summary");
            assert!(
                rendered.contains("1 healthy, 0 warning, 1 critical, 1 unknown"),
                "{rendered}"
            );
            assert!(rendered.contains("1 partial, 0 unavailable"), "{rendered}");
            assert!(rendered.contains("partial coverage"), "{rendered}");
            assert!(rendered.contains("complete coverage"), "{rendered}");
            assert_health_details_private(&rendered);
        }
    });
}

#[cfg(unix)]
mod live_inspection {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn install_ssh_fixture(directory: &Path) -> PathBuf {
        let bin = directory.join("bin");
        fs::create_dir(&bin).unwrap();
        let script = bin.join("ssh");
        let root_escaped = directory.to_str().unwrap().replace('\'', "'\\''");
        let log_escaped = directory
            .join("calls.log")
            .to_str()
            .unwrap()
            .replace('\'', "'\\''");
        fs::write(
            &script,
            format!(
                r#"#!/bin/sh
set -eu
ROOT='{root_escaped}'
LOG='{log_escaped}'
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ "$#" -eq 3 ] || exit 98
shift
host=$1
command=$2
printf '%s\t%s\n' "$host" "$command" >> "$LOG"
case "$host" in
  bad*) printf 'connection refused by fixture\n' >&2; exit 255 ;;
  slow) sleep 10 ;;
esac
case "$command" in
  *' --format json agent snapshot --minimal') cat "$ROOT/$host.health.json"; exit 0 ;;
  *' --format json doctor') cat "$ROOT/$host.doctor.json"; exit "$(cat "$ROOT/$host.exit")" ;;
  *) printf 'unexpected remote command\n' >&2; exit 99 ;;
esac
"#
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    fn command(directory: &Path, bin: &Path, mode: &str, hosts: &str) -> Command {
        let path = env::join_paths(
            std::iter::once(bin.to_path_buf())
                .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
        )
        .unwrap();
        let mut cmd = pt_core_fast();
        cmd.env("PROCESS_TRIAGE_DATA", directory.join("data"))
            .env("PT_FLEET_TEST_ROOT", directory)
            .env("PT_FLEET_TEST_LOG", directory.join("calls.log"))
            .env("PATH", path)
            .args([
                "--format",
                "json",
                "agent",
                "fleet",
                mode,
                "--hosts",
                hosts,
                "--parallel",
                "1",
                "--remote-binary",
                "/opt/pt tools/pt-core",
            ]);
        cmd
    }

    fn snapshot(cpu: f64) -> Value {
        serde_json::json!({
            "schema_version": pt_common::SCHEMA_VERSION,
            "command": "agent snapshot", "status": "ok",
            "pt_version": env!("CARGO_PKG_VERSION"),
            "host_id": "remote-host", "generated_at": "2026-02-08T12:00:00Z",
            "minimal": true,
            "system_state": {
                "process_count": 100,
                "census": {"zombies": 0, "dstate": 0},
                "pressure": {
                    "sampled_at_ms": HEALTH_SAMPLE_MS, "cpus": 8,
                    "cpu": {"some": {"avg10": cpu, "avg60": cpu, "avg300": cpu, "total_us": 100}},
                    "memory": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                    "io": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                    "load": {"one": 1.0, "five": 1.0, "fifteen": 1.0},
                    "meminfo": {"total": 16_u64 << 30, "available": 8_u64 << 30, "swap_total": 0, "swap_free": 0},
                    "file_handles": {"allocated": 10, "max": 10000}, "unavailable": []
                }
            },
            "responsible_units": {"units": [{"id": "compile", "label": "compiler scope", "member_count": 3, "usage": {"cpu_cores": {"value": 3.0}}}]},
            "memory_limits": {"warning_threshold_percent": 90, "complete": true,
                "total_units": 1, "observed_units": 1, "complete_units": 1, "hard_limit_count": 0,
                "warning_count": 0, "omitted_warnings": 0, "warnings": []}
        })
    }

    fn save(directory: &Path, host: &str, kind: &str, document: &Value) {
        fs::write(
            directory.join(format!("{host}.{kind}.json")),
            serde_json::to_vec(document).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn fleet_health_runs_only_minimal_snapshots_and_preserves_unknown_and_failed_hosts() {
        let dir = TempDir::new().unwrap();
        let bin = install_ssh_fixture(dir.path());
        save(dir.path(), "quiet", "health", &snapshot(0.0));
        save(dir.path(), "busy", "health", &snapshot(45.0));
        let mut partial = snapshot(0.0);
        partial["system_state"]["pressure"]["memory"] = Value::Null;
        partial["pt_version"] = serde_json::json!("older-release");
        save(dir.path(), "partial", "health", &partial);
        let bytes = command(dir.path(), &bin, "health", "quiet,bad-ssh,busy,partial")
            .assert()
            .code(3)
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["command"], "agent fleet health");
        assert_eq!(report["read_only"], true);
        assert_eq!(report["status"], "partial");
        assert_eq!(report["summary"]["completed"], 3);
        assert_eq!(report["summary"]["failed"], 1);
        assert_eq!(report["summary"]["critical_hosts"], 1);
        assert_eq!(report["summary"]["unknown_hosts"], 2);
        assert_eq!(report["summary"]["version_mismatches"], 1);
        let hosts = report["hosts"].as_array().unwrap();
        assert_eq!(hosts[0]["host"], "busy");
        assert_eq!(
            hosts[0]["responsible_units"]["units"][0]["label"],
            "compiler scope"
        );
        let failed = hosts.iter().find(|host| host["host"] == "bad-ssh").unwrap();
        assert_eq!(failed["exit_code"], 255);
        assert!(failed["stderr"]
            .as_str()
            .unwrap()
            .contains("connection refused"));
        assert_eq!(failed["observed_status"], "unknown");
        let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 4);
        assert!(calls
            .lines()
            .all(|line| line
                .ends_with("'/opt/pt tools/pt-core' --format json agent snapshot --minimal")));
        assert!(report.get("fleet_session_id").is_none());
    }

    #[test]
    fn fleet_health_surfaces_ancestor_limit_with_quiet_host_pressure() {
        let dir = TempDir::new().unwrap();
        let bin = install_ssh_fixture(dir.path());
        let mut constrained = snapshot(0.0);
        constrained["memory_limits"] = serde_json::json!({
            "warning_threshold_percent": 90, "complete": false,
            "total_units": 1, "observed_units": 1, "complete_units": 0, "hard_limit_count": 1,
            "warning_count": 1, "omitted_warnings": 0,
            "warnings": [{
                "scope_id": "boot:1:2:3:4:5:6:memory.max",
                "path": "/user.slice/user-1000.slice", "directory_device": 5,
                "directory_inode": 6, "control": "memory.max",
                "current_bytes": 100, "limit_bytes": 100, "headroom_bytes": 0,
                "at_or_above_limit": true, "hierarchy_complete": false,
            }],
        });
        save(dir.path(), "constrained", "health", &constrained);
        save(dir.path(), "quiet", "health", &snapshot(0.0));
        let bytes = command(dir.path(), &bin, "health", "quiet,constrained")
            .assert()
            .code(1)
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["summary"]["critical_hosts"], 1);
        assert_eq!(report["hosts"][0]["host"], "constrained");
        assert_eq!(
            report["hosts"][0]["memory_limits"]["warnings"][0]["path"],
            "/user.slice/user-1000.slice"
        );
        let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 2);
        assert!(calls
            .lines()
            .all(|line| line.ends_with("agent snapshot --minimal")));
    }

    #[test]
    fn fleet_doctor_accepts_findings_exit_and_never_runs_reported_remedies() {
        let dir = TempDir::new().unwrap();
        let bin = install_ssh_fixture(dir.path());
        let forbidden = dir.path().join("remedy-must-not-run");
        let remedy = format!("touch {}", forbidden.display());
        let document = serde_json::json!({
            "schema_version": pt_common::SCHEMA_VERSION,
            "command": "doctor", "status": "ok",
            "pt_version": env!("CARGO_PKG_VERSION"),
            "host_id": "doctor-host", "generated_at": "2026-02-08T12:00:00Z",
            "worst": "crit", "facts": {"memory_high": "infinity"},
            "pressure": {"worst": "ok", "regimes": [], "severity": {"cpu": 0.0, "memory": 0.0, "io": 0.0, "fd": 0.0}},
            "findings": [{"id": "oomd.limit", "level": "crit", "summary": "Memory limit overridden", "observed": "infinity", "recommended": "Review the drop-in", "rationale": "Effective static configuration", "commands": [remedy]}]
        });
        save(dir.path(), "worker", "doctor", &document);
        fs::write(dir.path().join("worker.exit"), "1\n").unwrap();
        let bytes = command(dir.path(), &bin, "doctor", "worker")
            .assert()
            .code(1)
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["status"], "ok");
        assert_eq!(report["summary"]["completed"], 1);
        assert_eq!(report["summary"]["critical_hosts"], 1);
        assert_eq!(report["hosts"][0]["exit_code"], 1);
        assert_eq!(
            report["hosts"][0]["doctor"]["findings"][0]["commands"][0],
            remedy
        );
        assert!(!forbidden.exists());
        let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 1);
        assert!(calls.ends_with("--format json doctor\n"));
    }

    #[test]
    fn fleet_inspection_rejects_incompatible_schema_and_stops_after_repeated_failures() {
        let dir = TempDir::new().unwrap();
        let bin = install_ssh_fixture(dir.path());
        let mut wrong = snapshot(0.0);
        wrong["schema_version"] = serde_json::json!("99.0.0");
        save(dir.path(), "wrong", "health", &wrong);
        let bytes = command(dir.path(), &bin, "health", "wrong,bad-ssh,never-started")
            .args(["--max-consecutive-failures", "2"])
            .assert()
            .code(21)
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["summary"]["failed"], 2);
        assert_eq!(report["summary"]["skipped"], 1);
        assert_eq!(report["summary"]["circuit_open"], true);
        let hosts = report["hosts"].as_array().unwrap();
        let wrong = hosts.iter().find(|host| host["host"] == "wrong").unwrap();
        assert!(wrong["error"].as_str().unwrap().contains("schema_version"));
        let skipped = hosts
            .iter()
            .find(|host| host["host"] == "never-started")
            .unwrap();
        assert_eq!(skipped["status"], "skipped");
        assert!(skipped["exit_code"].is_null());
        assert_eq!(
            fs::read_to_string(dir.path().join("calls.log"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn fleet_inspection_deadline_keeps_timeout_distinct_from_a_quiet_host() {
        let dir = TempDir::new().unwrap();
        let bin = install_ssh_fixture(dir.path());
        let bytes = command(dir.path(), &bin, "health", "slow")
            .args(["--timeout", "1", "--connect-timeout", "1"])
            .assert()
            .code(21)
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["summary"]["failed"], 1);
        assert_eq!(report["hosts"][0]["timed_out"], true);
        assert_eq!(report["hosts"][0]["observed_status"], "unknown");
        assert!(report["hosts"][0]["health"].is_null());
    }
}
