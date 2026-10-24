//! Agent apply constraints-blocked tests.
//!
//! Ensures agent apply returns PolicyBlocked when robot constraints block actions.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, ProcessRecord, ProcessState, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::exit_codes::ExitCode;
use pt_core::inference::ClassScores;
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

// A foreign session's nonleader avoids pt's own-session protection. The shell
// reaps only the sleep child we created; every target descriptor is /dev/null.
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

fn retained_dirs() -> (std::path::PathBuf, std::path::PathBuf) {
    let data_dir = TempDir::new().expect("create temp data dir").keep();
    let config_dir = TempDir::new().expect("create temp config dir").keep();
    let mut policy = Policy::default();
    // Enable this isolated robot oracle; retain the default .95 posterior and
    // human-supervision protection. Only its fresh-process age floor is zero.
    policy.robot_mode.enabled = true;
    policy.guardrails.min_process_age_seconds = 0;
    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .expect("write isolated policy");
    (data_dir, config_dir)
}

#[test]
fn agent_apply_uses_abandoned_plus_zombie_posterior_for_kill_constraints() {
    let (data_dir, config_dir) = retained_dirs();
    let target = OwnedSleep::spawn();
    for (label, posterior, expected_status, expected_exit) in [
        (
            "union_positive",
            ClassScores {
                useful: 0.01,
                useful_bad: 0.01,
                abandoned: 0.49,
                zombie: 0.49,
            },
            "dry_run",
            ExitCode::ActionsOk,
        ),
        (
            "high_useful_negative",
            ClassScores {
                useful: 0.99,
                useful_bad: 0.0,
                abandoned: 0.005,
                zombie: 0.005,
            },
            "blocked_by_constraints",
            ExitCode::PolicyBlocked,
        ),
        (
            "original_below_threshold",
            ClassScores {
                useful: 0.01,
                useful_bad: 0.49,
                abandoned: 0.49,
                zombie: 0.01,
            },
            "blocked_by_constraints",
            ExitCode::PolicyBlocked,
        ),
    ] {
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
                    posterior: Some(posterior),
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

        let json = apply_logged(
            &data_dir,
            &config_dir,
            &session_id,
            &target,
            label,
            &["--min-posterior", "0.9"],
            expected_exit,
        );
        let summary = json
            .get("summary")
            .expect("Missing summary in agent apply output");
        assert_eq!(
            summary
                .get("blocked_by_constraints")
                .and_then(|v| v.as_u64()),
            Some(u64::from(expected_status == "blocked_by_constraints")),
            "Wrong constraint count for {label}"
        );

        let outcomes = json
            .get("outcomes")
            .and_then(|v| v.as_array())
            .expect("Missing outcomes array");
        assert_eq!(outcomes.len(), 1, "Expected exactly one outcome");
        assert_eq!(
            outcomes[0].get("status").and_then(|v| v.as_str()),
            Some(expected_status),
            "Wrong outcome for {label}"
        );
        assert_eq!(summary["attempted"], 1);
        assert_eq!(summary["succeeded"], 0);
        assert_eq!(summary["failed"], 0);
        assert_eq!(summary["blocked_by_prechecks"], 0);
        assert_eq!(summary["skipped"], u64::from(expected_status == "dry_run"));
        assert_eq!(outcomes[0]["pid"], target.pid);
        if expected_status == "blocked_by_constraints" {
            let violations = outcomes[0]["violations"].as_array().expect("violations");
            assert_eq!(
                violations.len(),
                1,
                "unexpected gate for {label}: {violations:?}"
            );
            assert_eq!(violations[0]["constraint"], "min_posterior");
        }
        target.assert_unchanged();
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
fn agent_apply_returns_policy_blocked_for_constraints() {
    let (data_dir, config_dir) = retained_dirs();
    let target = OwnedSleep::spawn();
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

    let json = apply_logged(
        &data_dir,
        &config_dir,
        &session_id,
        &target,
        "missing_posterior",
        &[],
        ExitCode::PolicyBlocked,
    );
    let summary = json
        .get("summary")
        .expect("Missing summary in agent apply output");
    assert_eq!(
        summary
            .get("blocked_by_constraints")
            .and_then(|v| v.as_u64()),
        Some(1),
        "Expected blocked_by_constraints to be 1"
    );

    let outcomes = json
        .get("outcomes")
        .and_then(|v| v.as_array())
        .expect("Missing outcomes array");
    assert_eq!(outcomes.len(), 1, "Expected exactly one outcome");
    assert_eq!(
        outcomes[0].get("status").and_then(|v| v.as_str()),
        Some("blocked_by_constraints"),
        "Expected blocked_by_constraints status"
    );
    assert_eq!(summary["attempted"], 1);
    assert_eq!(summary["succeeded"], 0);
    assert_eq!(summary["failed"], 0);
    assert_eq!(summary["skipped"], 0);
    assert_eq!(summary["blocked_by_prechecks"], 0);
    assert_eq!(outcomes[0]["pid"], target.pid);
    let violations = outcomes[0]["violations"].as_array().expect("violations");
    assert_eq!(violations.len(), 1, "unexpected gate: {violations:?}");
    assert_eq!(violations[0]["constraint"], "min_posterior");
    assert_eq!(violations[0]["actual"], "missing or invalid");
    target.assert_unchanged();
}

fn apply_logged(
    data_dir: &Path,
    config_dir: &Path,
    session: &SessionId,
    target: &OwnedSleep,
    label: &str,
    extra: &[&str],
    expected_exit: ExitCode,
) -> Value {
    let budget_path = data_dir.join("rate_limit.json");
    let budget_before = optional_file(&budget_path);
    let mut args = vec![
        "--format".to_string(),
        "json".to_string(),
        "--dry-run".to_string(),
        "agent".to_string(),
        "apply".to_string(),
        "--session".to_string(),
        session.0.clone(),
        "--pids".to_string(),
        target.pid.to_string(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_string()));
    let started = Instant::now();
    let mut command = pt_core_fast();
    command
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .args(&args);
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
    let json: Value = serde_json::from_slice(&output.stdout).expect("actual apply JSON");
    let saved = fs::read_to_string(
        data_dir
            .join("sessions")
            .join(&session.0)
            .join("action/outcomes.jsonl"),
    )
    .expect("saved outcomes");
    let saved: Vec<Value> = saved
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        saved.as_slice(),
        json["outcomes"].as_array().expect("outcomes")
    );
    assert!(saved.iter().all(|outcome| outcome["status"] != "success"));
    assert_eq!(
        optional_file(&budget_path),
        budget_before,
        "dry run spent budget"
    );
    json
}

fn optional_file(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}
