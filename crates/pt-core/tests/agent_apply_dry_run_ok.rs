//! Agent apply dry-run success tests.
//!
//! Ensures agent apply returns ActionsOk when constraints and prechecks allow the action.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, ProcessRecord, ProcessState, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::exit_codes::ExitCode;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand};
use std::time::{Duration, Instant};
use tempfile::TempDir;

// The target is an owned, null-stdio child of a foreign-session shell reaper,
// not a session leader or a member of pt's protected connection.
struct OwnedSleep {
    leader: Child,
    pid: u32,
    record: Option<ProcessRecord>,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

impl OwnedSleep {
    fn spawn() -> Self {
        use std::os::unix::process::CommandExt;
        let mut command = ProcessCommand::new("sh");
        command
            .args(["-c", "sleep 900 </dev/null >/dev/null 2>&1 & echo $!; wait"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // SAFETY: setsid only configures our new child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut leader = command.spawn().expect("spawn owned reaper");
        let mut line = String::new();
        std::io::BufReader::new(leader.stdout.take().expect("reaper stdout"))
            .read_line(&mut line)
            .expect("read owned target PID");
        let pid = line.trim().parse::<u32>().expect("owned target PID");
        #[cfg(target_os = "linux")]
        let pidfd = {
            use std::os::fd::FromRawFd;
            // SAFETY: this descriptor binds the original owned sleep incarnation.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
            unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
        };
        let mut target = Self {
            leader,
            pid,
            record: None,
            #[cfg(target_os = "linux")]
            pidfd,
        };
        let started = Instant::now();
        loop {
            let record = target.scan();
            if record.comm.rsplit('/').next() == Some("sleep")
                && record.state == ProcessState::Sleeping
            {
                assert_eq!(record.ppid.0, target.leader.id());
                assert_ne!(record.sid, Some(pid));
                // SAFETY: geteuid observes the test's owner without side effects.
                assert_eq!(record.uid, unsafe { libc::geteuid() });
                target.record = Some(record);
                return target;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "sleep not ready: {record:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn scan(&self) -> ProcessRecord {
        let scan = quick_scan(&QuickScanOptions {
            pids: vec![self.pid],
            timeout: Some(Duration::from_secs(30)),
            ..QuickScanOptions::default()
        })
        .expect("scan owned sleep");
        assert!(
            scan.metadata.warnings.is_empty(),
            "{:?}",
            scan.metadata.warnings
        );
        assert_eq!(scan.processes.len(), 1);
        scan.processes
            .into_iter()
            .next()
            .expect("owned sleep record")
    }

    fn identity(&self) -> ProcessIdentity {
        let record = self.record.as_ref().expect("ready sleep");
        ProcessIdentity {
            pid: record.pid,
            start_id: record.start_id.clone(),
            uid: record.uid,
            pgid: record.pgid,
            sid: record.sid,
            quality: IdentityQuality::Full,
        }
    }

    fn assert_unchanged(&self) {
        let before = self.record.as_ref().expect("ready sleep");
        let after = self.scan();
        assert_eq!(after.pid, before.pid);
        assert_eq!(after.start_id, before.start_id);
        assert_eq!(after.uid, before.uid);
        assert_eq!(after.ppid, before.ppid);
        assert_eq!(after.pgid, before.pgid);
        assert_eq!(after.sid, before.sid);
        assert_eq!(after.cmd, before.cmd);
        assert_eq!(after.state, ProcessState::Sleeping);
    }
}

impl Drop for OwnedSleep {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the pidfd can signal only our original disposable target.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        #[cfg(target_os = "macos")]
        if self.record.is_some() {
            use pt_core::action::{IdentityProvider, LiveIdentityProvider};
            if matches!(
                LiveIdentityProvider::new().revalidate(&self.identity()),
                Ok(true)
            ) {
                // SAFETY: exact incarnation revalidation immediately precedes cleanup.
                unsafe {
                    libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
        let _ = self.leader.wait();
    }
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

#[test]
fn agent_apply_dry_run_returns_actions_ok() {
    let data_dir = TempDir::new().expect("create temp data dir").keep();
    let config_dir = TempDir::new().expect("create temp config dir").keep();
    let target = OwnedSleep::spawn();
    let mut policy = Policy::default();
    policy.robot_mode.enabled = true;
    policy.robot_mode.min_posterior = 0.0;
    policy.robot_mode.require_human_for_supervised = false;
    // This existing fixture permits fresh children; keep every production
    // policy and the original observation windows unchanged.
    policy.guardrails.min_process_age_seconds = 0;

    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_string_pretty(&policy).expect("serialize policy"),
    )
    .expect("write policy.json");

    let store = SessionStore::at_data_dir(&data_dir);
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

    let pid = target.pid;
    let identity = target.identity();

    let plan = Plan {
        plan_id: "plan-test".to_string(),
        session_id: session_id.0.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        actions: vec![PlanAction {
            action_id: "action-1".to_string(),
            target: identity,
            action: Action::Kill,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: Vec::<ActionHook>::new(),
            on_failure: Vec::<ActionHook>::new(),
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
            memory_cap: None,
            supervisor_restart: None,
        }],
        pre_toggled: Vec::new(),
        gates_summary: GatesSummary {
            total_candidates: 1,
            blocked_candidates: 0,
            pre_toggled_actions: 0,
        },
    };

    let decision_dir = handle.dir.join("decision");
    fs::create_dir_all(&decision_dir).expect("create decision dir");
    let plan_path = decision_dir.join("plan.json");
    fs::write(
        &plan_path,
        serde_json::to_string_pretty(&plan).expect("serialize plan"),
    )
    .expect("write plan");

    let budget_path = data_dir.join("rate_limit.json");
    let budget_before = optional_file(&budget_path);
    let args = vec![
        "--format".to_string(),
        "json".to_string(),
        "--dry-run".to_string(),
        "agent".to_string(),
        "apply".to_string(),
        "--session".to_string(),
        session_id.0.clone(),
        "--pids".to_string(),
        pid.to_string(),
        // The existing command timeout is shorter than this requested window.
        // Dry-run must skip resource sampling and the settle wait completely.
        "--settle".to_string(),
        "300".to_string(),
    ];
    let output = apply_logged(
        &data_dir,
        &config_dir,
        &session_id,
        &target,
        "dry_run_positive",
        &args,
        ExitCode::ActionsOk,
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("Output should be valid JSON");
    let summary = json
        .get("summary")
        .expect("Missing summary in agent apply output");
    assert_eq!(
        summary.get("skipped").and_then(|v| v.as_u64()),
        Some(1),
        "Expected skipped to be 1 in dry-run"
    );
    assert_eq!(
        summary
            .get("blocked_by_constraints")
            .and_then(|v| v.as_u64()),
        Some(0),
        "Expected blocked_by_constraints to be 0"
    );
    assert_eq!(
        summary.get("blocked_by_prechecks").and_then(|v| v.as_u64()),
        Some(0),
        "Expected blocked_by_prechecks to be 0"
    );

    let goal_progress = json
        .get("goal_progress")
        .expect("Missing goal_progress section");
    let metrics = goal_progress
        .get("metrics")
        .expect("Missing goal_progress.metrics");
    assert_eq!(goal_progress["planning_only"], true);
    assert_eq!(json.get("resource_delta"), Some(&Value::Null));
    assert_eq!(json.get("resource_observation"), Some(&Value::Null));
    for phase in ["before", "after"] {
        for metric in [
            "available_memory_bytes",
            "total_cpu_frac",
            "occupied_ports",
            "total_fds",
        ] {
            assert_eq!(goal_progress[phase].get(metric), Some(&Value::Null));
        }
    }
    // This plan has no memory forecast. Lifetime process CPU and socket counts
    // cannot become host-capacity or exclusive-port predictions in dry-run.
    for metric in ["memory", "cpu", "ports"] {
        assert_eq!(metrics[metric].get("expected_progress"), Some(&Value::Null));
        assert_eq!(
            metrics[metric]["action_outcomes"][0].get("expected_contribution"),
            Some(&Value::Null)
        );
    }
    #[cfg(target_os = "linux")]
    assert!(metrics["file_descriptors"]["expected_progress"]
        .as_f64()
        .is_some_and(|value| value > 0.0));
    #[cfg(target_os = "macos")]
    assert_eq!(
        metrics["file_descriptors"].get("expected_progress"),
        Some(&Value::Null)
    );
    for metric in ["memory", "cpu", "ports", "file_descriptors"] {
        let report = metrics.get(metric).expect("recorded metric");
        assert_eq!(report.get("observed_progress"), Some(&Value::Null));
        assert_eq!(report.get("discrepancy"), Some(&Value::Null));
        assert_eq!(report.get("discrepancy_fraction"), Some(&Value::Null));
        assert_eq!(report["classification"], "not_executed");
        assert_eq!(report["planning_only"], true);
        assert_eq!(report["suspected_causes"], serde_json::json!([]));
    }

    let outcomes = json
        .get("outcomes")
        .and_then(|v| v.as_array())
        .expect("Missing outcomes array");
    assert_eq!(outcomes.len(), 1, "Expected exactly one outcome");
    assert_eq!(
        outcomes[0].get("status").and_then(|v| v.as_str()),
        Some("dry_run"),
        "Expected dry_run status"
    );
    assert!(
        outcomes[0].get("goal_progress").is_some(),
        "Expected per-outcome goal_progress discrepancy fields"
    );
    assert_eq!(summary["attempted"], 1);
    assert_eq!(summary["succeeded"], 0);
    assert_eq!(summary["failed"], 0);
    assert_eq!(outcomes[0]["pid"], pid);
    assert!(outcomes[0]["executed_at"].is_null());
    assert!(outcomes[0]["resource_run_id"].is_null());
    for metric in ["memory", "cpu", "ports", "file_descriptors"] {
        let report = &outcomes[0]["goal_progress"][metric];
        assert_eq!(report.get("observed"), Some(&Value::Null));
        assert_eq!(report.get("discrepancy"), Some(&Value::Null));
        assert_eq!(report.get("discrepancy_fraction"), Some(&Value::Null));
        assert_eq!(report["classification"], "not_executed");
        assert_eq!(report["planning_only"], true);
    }
    let saved_path = handle.dir.join("action/outcomes.jsonl");
    assert!(!handle.dir.join("action/resource_samples.jsonl").exists());
    assert!(fs::read_dir(handle.dir.join("action"))
        .unwrap()
        .all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("resource_delta-")
        }));
    let saved_before = fs::read(&saved_path).expect("saved dry-run outcomes");
    let saved: Vec<Value> = String::from_utf8(saved_before.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    // The journal is persisted once before any settle wait. Enrichment belongs
    // to the returned response and goal_progress.json, not a rewritten outcome.
    let mut expected_execution = outcomes[0].clone();
    let expected_execution_fields = expected_execution.as_object_mut().unwrap();
    expected_execution_fields.remove("goal_progress");
    expected_execution_fields.remove("respawn_detected");
    assert_eq!(saved, vec![expected_execution]);
    let saved_goal: Value = serde_json::from_slice(
        &fs::read(handle.dir.join("action/goal_progress.json")).expect("saved goal report"),
    )
    .expect("goal report JSON");
    assert_eq!(saved_goal, *goal_progress);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["status"], "dry_run");
    assert_eq!(
        optional_file(&budget_path),
        budget_before,
        "dry run spent budget"
    );
    target.assert_unchanged();

    // A neighboring selection with the same live PID but an unplanned birth
    // must fail before it can add an outcome, even in dry-run mode.
    let stale_target = format!("{}:{}-unplanned", pid, target.identity().start_id.0);
    let stale_args = vec![
        "--format".to_string(),
        "json".to_string(),
        "--dry-run".to_string(),
        "agent".to_string(),
        "apply".to_string(),
        "--session".to_string(),
        session_id.0.clone(),
        "--targets".to_string(),
        stale_target,
    ];
    let stale_output = apply_logged(
        &data_dir,
        &config_dir,
        &session_id,
        &target,
        "unplanned_birth_negative",
        &stale_args,
        ExitCode::ArgsError,
    );
    assert!(String::from_utf8_lossy(&stale_output.stderr).contains("does not match a saved action"));
    assert_eq!(fs::read(&saved_path).unwrap(), saved_before);
    assert_eq!(optional_file(&budget_path), budget_before);
    target.assert_unchanged();
}

fn apply_logged(
    data_dir: &Path,
    config_dir: &Path,
    session: &SessionId,
    target: &OwnedSleep,
    label: &str,
    args: &[String],
    expected_exit: ExitCode,
) -> std::process::Output {
    let started = Instant::now();
    let mut command = pt_core_fast();
    command
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .args(args);
    let executable = command.get_program().to_os_string();
    let output = command.output().expect("run actual agent apply");
    let log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-logs/e2e/agent_apply")
        .join(&session.0)
        .join(label);
    fs::create_dir_all(&log_dir).expect("apply artifacts");
    fs::write(log_dir.join("stdout.json"), &output.stdout).expect("retain stdout");
    fs::write(log_dir.join("stderr.jsonl"), &output.stderr).expect("retain stderr");
    fs::write(
        log_dir.join("step.jsonl"),
        format!(
            "{}\n",
            serde_json::json!({
                "command": executable.to_string_lossy(), "args": args,
                "data_dir": data_dir, "config_dir": config_dir,
                "target_identity": target.identity(), "target_before": target.record,
                "exit_code": output.status.code(), "elapsed_ms": started.elapsed().as_millis(),
                "stdout_sha256": pt_bundle::FileEntry::compute_checksum(&output.stdout),
                "stderr_sha256": pt_bundle::FileEntry::compute_checksum(&output.stderr),
            })
        ),
    )
    .expect("retain CLI step");
    assert_eq!(
        output.status.code(),
        Some(expected_exit.as_i32()),
        "{label}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn optional_file(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}
