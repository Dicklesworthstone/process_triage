//! `agent apply` really executes non-signal actions.
//!
//! Before 2026-09-24 `agent apply` only had a signal runner: kill/pause/resume could
//! run, and every other planned action (renice, freeze, throttle, quarantine) failed.
//! This test applies a real renice and then a real kill to a spawned child process
//! with its live identity (no dry-run) and checks each effect on the live process.
//! Runs on Linux and macOS (the macOS executor landed with bd-o3cd).

#![cfg(any(target_os = "linux", target_os = "macos"))]

use assert_cmd::cargo::cargo_bin_cmd;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand};
use std::time::Duration;
use tempfile::TempDir;

/// How apply delivers signals to a single verified process: a pidfd bound to it on
/// Linux; kill(2) right after an exact start-time recheck on macOS (no pidfds).
#[cfg(target_os = "linux")]
const SIGNAL_PATH: &str = "pidfd";
#[cfg(target_os = "macos")]
const SIGNAL_PATH: &str = "kill";

/// A target process in a foreign session and not its leader: how a process left
/// behind by a terminal looks. (pt's own session and session leaders are protected by
/// the session-safety pre-check, which apply always runs.) `sh` leads the new session,
/// starts `script` in the background, reports its pid and reaps it.
struct ForeignTarget {
    leader: Child,
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "macos")]
    identity: ProcessIdentity,
}

impl ForeignTarget {
    fn spawn(script: &str) -> Self {
        use std::io::BufRead;
        use std::os::unix::process::CommandExt;
        let mut cmd = ProcessCommand::new("sh");
        // stdio on /dev/null: an inherited log file open for writing would (rightly)
        // trip the data-loss gate.
        cmd.args([
            "-c",
            &format!("{script} </dev/null >/dev/null 2>&1 & echo $!; wait"),
        ])
        .stdout(std::process::Stdio::piped())
        // From another login: session safety protects whatever shares pt's own SSH
        // connection (the test may itself run over ssh).
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_CLIENT")
        .env_remove("SSH_TTY");
        // SAFETY: setsid is async-signal-safe and only affects the child.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut leader = cmd.spawn().expect("spawn session leader");
        let mut line = String::new();
        std::io::BufReader::new(leader.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read target pid");
        let pid: u32 = line.trim().parse().expect("target pid");
        #[cfg(target_os = "linux")]
        let pidfd = {
            use std::os::fd::FromRawFd;
            // SAFETY: pidfd_open observes the test target; OwnedFd takes sole
            // ownership of the successful descriptor.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
            unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
        };
        Self {
            leader,
            pid,
            #[cfg(target_os = "linux")]
            pidfd,
            #[cfg(target_os = "macos")]
            identity: live_identity(pid),
        }
    }

    fn alive(&self) -> bool {
        // The leader reaps the target, so a dead target disappears from ps.
        state_of(self.pid).is_some_and(|s| s != 'Z')
    }
}

impl Drop for ForeignTarget {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        // SAFETY: the pidfd still refers only to the original test target,
        // including after it exits and the numeric PID becomes reusable.
        unsafe {
            use std::os::fd::AsRawFd;
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        #[cfg(target_os = "macos")]
        {
            use pt_core::action::{IdentityProvider, LiveIdentityProvider};
            if matches!(
                LiveIdentityProvider::new().revalidate(&self.identity),
                Ok(true)
            ) {
                // SAFETY: macOS lacks pidfds; repeat the exact live identity
                // check immediately before signaling the captured target.
                unsafe {
                    libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
        let _ = self.leader.kill();
        let _ = self.leader.wait();
    }
}

/// Nice value of a live process (from ps: portable across Linux and macOS).
fn nice_of(pid: u32) -> Option<i64> {
    let out = ProcessCommand::new("ps")
        .args(["-o", "nice=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Live identity of `pid` exactly as a plan records it (via the real quick_scan).
fn live_identity(pid: u32) -> ProcessIdentity {
    let scan = quick_scan(&QuickScanOptions {
        pids: vec![pid],
        include_kernel_threads: false,
        timeout: Some(Duration::from_secs(30)),
        progress: None,
    })
    .expect("quick_scan child");
    let rec = scan
        .processes
        .iter()
        .find(|p| p.pid.0 == pid)
        .expect("child in scan");
    ProcessIdentity {
        pid: ProcessId(pid),
        start_id: rec.start_id.clone(),
        uid: rec.uid,
        pgid: rec.pgid,
        sid: rec.sid,
        quality: IdentityQuality::Full,
    }
}

/// Policy that lets `agent apply` run in a test (robot mode, no posterior gate).
fn write_test_policy(config_dir: &Path) {
    let mut policy = Policy::default();
    policy.robot_mode.enabled = true;
    policy.robot_mode.min_posterior = 0.0;
    policy.robot_mode.require_human_for_supervised = false;
    // These fixtures deliberately act on freshly spawned targets. Production
    // apply now correctly enforces the policy age floor even without --min-age.
    policy.guardrails.min_process_age_seconds = 0;
    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_string_pretty(&policy).expect("serialize policy"),
    )
    .expect("write policy");
}

fn plan_action(action: Action, identity: &ProcessIdentity) -> PlanAction {
    PlanAction {
        action_id: format!("a-{action:?}").to_lowercase(),
        target: identity.clone(),
        action,
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: Vec::new(),
        rationale: ActionRationale {
            expected_loss: None,
            expected_recovery: None,
            expected_recovery_stddev: None,
            posterior_odds_abandoned_vs_useful: None,
            sprt_boundary: None,
            posterior: None,
            memory_mb: Some(1.0),
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
    }
}

/// Create a session holding a one-action plan; return the session id.
fn session_with_plan(data_dir: &Path, action: PlanAction) -> String {
    session_with_actions(data_dir, vec![action])
}

/// Create a session holding a plan with `actions`; return the session id.
fn session_with_actions(data_dir: &Path, actions: Vec<PlanAction>) -> String {
    let store = SessionStore::at_data_dir(data_dir);
    let session_id = SessionId::new();
    let handle = store
        .create(&SessionManifest::new(
            &session_id,
            None,
            SessionMode::RobotPlan,
            None,
        ))
        .expect("create session");
    handle
        .write_context(&SessionContext::new(
            &session_id,
            "host-test".to_string(),
            "run-test".to_string(),
            None,
        ))
        .expect("write context");
    let plan = Plan {
        plan_id: format!("plan-{}", actions[0].action_id),
        session_id: session_id.0.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        gates_summary: GatesSummary {
            total_candidates: actions.len(),
            blocked_candidates: 0,
            pre_toggled_actions: 0,
        },
        actions,
        pre_toggled: Vec::new(),
    };
    let decision_dir = handle.dir.join("decision");
    fs::create_dir_all(&decision_dir).expect("decision dir");
    fs::write(
        decision_dir.join("plan.json"),
        serde_json::to_string_pretty(&plan).expect("serialize plan"),
    )
    .expect("write plan");
    session_id.0
}

/// Run a real (non-dry-run) `agent apply` and return the single outcome status.
fn apply(data_dir: &Path, config_dir: &Path, session: &str, target: &str) -> (String, Value) {
    apply_with_args(data_dir, config_dir, session, target, &[])
}

/// [`apply`] with extra `agent apply` arguments.
fn apply_with_args(
    data_dir: &Path,
    config_dir: &Path,
    session: &str,
    target: &str,
    extra: &[&str],
) -> (String, Value) {
    let started = std::time::Instant::now();
    let out = cargo_bin_cmd!("pt-core")
        .timeout(Duration::from_secs(240))
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            session,
            "--targets",
            target,
            "--yes",
        ])
        .args(extra)
        .output()
        .expect("run agent apply");
    let log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-logs/e2e/agent_apply")
        .join(session)
        .join(SessionId::new().0);
    fs::create_dir_all(&log_dir).expect("apply artifacts");
    fs::write(log_dir.join("stdout.json"), &out.stdout).expect("save apply stdout");
    fs::write(log_dir.join("stderr.jsonl"), &out.stderr).expect("save apply stderr");
    fs::write(
        log_dir.join("step.jsonl"),
        format!(
            "{}\n",
            serde_json::json!({
                "command": "pt-core", "session_id": session,
                "args": ["--format", "json", "agent", "apply", "--session", session,
                         "--targets", target, "--yes"], "extra_args": extra,
                "exit_code": out.status.code(), "elapsed_ms": started.elapsed().as_millis(),
                "stdout_sha256": pt_bundle::FileEntry::compute_checksum(&out.stdout),
                "stderr_sha256": pt_bundle::FileEntry::compute_checksum(&out.stderr),
            })
        ),
    )
    .expect("save apply step");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "apply output not JSON ({e}): {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let status = json["outcomes"][0]["status"]
        .as_str()
        .unwrap_or("missing")
        .to_string();
    (status, json)
}

#[test]
fn agent_apply_persists_the_kill_budget_across_runs() {
    use std::io::Write;
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());
    let policy_path = config_dir.path().join("policy.json");
    let mut policy: Policy = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy.guardrails.max_kills_per_minute = Some(2);
    // A full one-second I/O window keeps this minute-budget probe inside its
    // declared window. The separate writer regressions exercise the data gate.
    policy.data_loss_gates.block_if_recent_io_seconds = Some(1);
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    let first = ForeignTarget::spawn("sleep 351");
    let second = ForeignTarget::spawn("sleep 352");
    let third = ForeignTarget::spawn("sleep 353");
    let mut first_action = plan_action(Action::Kill, &live_identity(first.pid));
    first_action.action_id = "first-kill".to_string();
    let mut second_action = plan_action(Action::Kill, &live_identity(second.pid));
    second_action.action_id = "second-kill".to_string();
    let first_session = session_with_actions(data_dir.path(), vec![first_action, second_action]);
    let third_session = session_with_plan(
        data_dir.path(),
        plan_action(Action::Kill, &live_identity(third.pid)),
    );
    let log_dir = Path::new("target/test-logs/e2e/rate_limit").join(format!(
        "{}-{}",
        std::process::id(),
        SessionId::new().0
    ));
    fs::create_dir_all(&log_dir).unwrap();
    let mut steps = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(log_dir.join("steps.jsonl"))
        .unwrap();
    let started = std::time::Instant::now();
    for (index, session) in [&first_session, &third_session].into_iter().enumerate() {
        let output = cargo_bin_cmd!("pt-core")
            .timeout(Duration::from_secs(120))
            .env("PT_SKIP_GLOBAL_LOCK", "1")
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .args([
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                session,
                "--recommended",
                "--yes",
            ])
            .output()
            .unwrap();
        fs::write(log_dir.join(format!("{index}.stdout.json")), &output.stdout).unwrap();
        fs::write(
            log_dir.join(format!("{index}.stderr.jsonl")),
            &output.stderr,
        )
        .unwrap();
        writeln!(
            steps,
            "{}",
            serde_json::json!({
                "step": index, "session_id": session, "exit_code": output.status.code(),
                "elapsed_ms": started.elapsed().as_millis(),
                "stdout_sha256": pt_bundle::FileEntry::compute_checksum(&output.stdout),
                "stderr_sha256": pt_bundle::FileEntry::compute_checksum(&output.stderr),
            })
        )
        .unwrap();
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        if index == 0 {
            assert_eq!(output.status.code(), Some(2), "{result}");
            let outcomes = result["outcomes"].as_array().unwrap();
            assert_eq!(outcomes.len(), 2, "{result}");
            assert!(
                outcomes
                    .iter()
                    .all(|outcome| outcome["status"] == "success"),
                "{result}"
            );
            assert!(!first.alive());
            assert!(!second.alive());
        } else {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "minute-window probe ran too slowly"
            );
            assert_eq!(
                result["outcomes"][0]["status"], "blocked_by_policy",
                "{result}"
            );
            assert_eq!(result["outcomes"][0]["reason"], "rate_limit", "{result}");
            assert_ne!(output.status.code(), Some(2), "{result}");
            assert!(third.alive(), "rate-limited target was signaled");
        }
        let budget: Value =
            serde_json::from_slice(&fs::read(data_dir.path().join("rate_limit.json")).unwrap())
                .unwrap();
        assert_eq!(budget["kill_timestamps"].as_array().unwrap().len(), 2);
    }
}

/// Exercise the actual planner-to-apply contract, not a hand-authored action.
/// The isolated policy selects kill to make routing deterministic; this tests
/// execution and saved identities, not inference calibration or FDR quality.
#[cfg(target_os = "linux")]
#[test]
fn actual_agent_plan_applies_and_verifies_its_saved_live_identity() {
    use std::io::{BufRead, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Stdio;

    fn run_step(
        log_dir: &Path,
        step: &str,
        args: &[&str],
        data_dir: &Path,
        config_dir: &Path,
        timeout_seconds: u64,
    ) -> std::process::Output {
        let started = std::time::Instant::now();
        let output = cargo_bin_cmd!("pt-core")
            .timeout(Duration::from_secs(timeout_seconds))
            .env("PT_SKIP_GLOBAL_LOCK", "1")
            .env("PROCESS_TRIAGE_DATA", data_dir)
            .env("PROCESS_TRIAGE_CONFIG", config_dir)
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .args(args)
            .output()
            .expect("run actual agent step");
        static STEP_NUMBER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let index = STEP_NUMBER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stdout_path = format!("{index}-{step}.stdout.json");
        let stderr_path = format!("{index}-{step}.stderr.jsonl");
        fs::write(log_dir.join(&stdout_path), &output.stdout).expect("save actual stdout");
        fs::write(log_dir.join(&stderr_path), &output.stderr).expect("save actual stderr");
        let record = serde_json::json!({
            "step": step, "command": "pt-core", "args": args,
            "exit_code": output.status.code(), "success": output.status.success(),
            "elapsed_ms": started.elapsed().as_millis(),
            "stdout_sha256": pt_bundle::FileEntry::compute_checksum(&output.stdout),
            "stderr_sha256": pt_bundle::FileEntry::compute_checksum(&output.stderr),
            "stdout_path": stdout_path, "stderr_path": stderr_path,
        });
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("steps.jsonl"))
            .expect("open step log");
        writeln!(log, "{record}").expect("record actual step");
        eprintln!("{record}");
        output
    }

    struct BoundTarget(OwnedFd);
    impl Drop for BoundTarget {
        fn drop(&mut self) {
            // SAFETY: the pidfd binds only the process spawned by this test;
            // unlike a numeric PID it cannot signal a replacement process.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }

    // Keep artifacts for inspection and never remove files as test cleanup.
    let data_dir = TempDir::new().expect("data dir").keep();
    let config_dir = TempDir::new().expect("config dir").keep();
    let log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-logs/e2e/agent_loop")
        .join(format!(
            "{}-{}",
            chrono::Utc::now().timestamp_millis(),
            std::process::id()
        ));
    fs::create_dir_all(&log_dir).expect("step log directory");
    let mut policy = Policy::default();
    policy.robot_mode.enabled = true;
    policy.robot_mode.min_posterior = 0.0;
    policy.guardrails.min_process_age_seconds = 0;
    policy.fdr_control.enabled = false;
    for row in [
        &mut policy.loss_matrix.useful,
        &mut policy.loss_matrix.useful_bad,
        &mut policy.loss_matrix.abandoned,
        &mut policy.loss_matrix.zombie,
    ] {
        row.keep = 1000.0;
        row.kill = 0.0;
        row.pause = Some(1000.0);
        row.throttle = Some(1000.0);
        row.restart = Some(1000.0);
        row.renice = Some(1000.0);
    }
    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize isolated policy"),
    )
    .expect("write isolated policy");

    // Detach the reaping shell from the test/agent ancestor chain. The target
    // itself is neither a session leader nor attached to a terminal or log FD.
    let unique_seconds = format!("900.{}", std::process::id());
    let script = format!(
        "sleep {unique_seconds} </dev/null >/dev/null 2>&1 & target=$!; printf '%s\\n' \"$target\"; exec >/dev/null; wait \"$target\""
    );
    let mut launcher = ProcessCommand::new("setsid")
        .args(["--fork", "sh", "-c", &script])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn detached target");
    let mut line = String::new();
    std::io::BufReader::new(launcher.stdout.take().expect("target PID pipe"))
        .read_line(&mut line)
        .expect("read detached PID");
    let pid: u32 = line.trim().parse().expect("detached target PID");
    assert!(launcher.wait().expect("wait for launcher").success());
    // SAFETY: pidfd_open does not modify the process. Ownership of the returned
    // descriptor transfers once to OwnedFd and lasts through all assertions.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    let _target = BoundTarget(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    let identity = live_identity(pid);

    let planned = run_step(
        &log_dir,
        "plan",
        &[
            "--format",
            "json",
            "agent",
            "plan",
            "--min-posterior",
            "0",
            "--min-age",
            "0",
            "--max-candidates",
            "20",
            "--pids",
            &pid.to_string(),
        ],
        &data_dir,
        &config_dir,
        180,
    );
    assert!(
        planned.status.code() == Some(1),
        "planner stderr: {}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let document: Value = serde_json::from_slice(&planned.stdout).expect("actual plan JSON");
    let pressure: pt_core::collect::pressure::PressureSnapshot =
        serde_json::from_value(document["system_state"]["pressure"].clone())
            .expect("actual typed kernel-pressure reading is persisted");
    assert!(pressure.sampled_at_ms > 0);
    assert!(pressure.cpus > 0);
    let meminfo = fs::read_to_string("/proc/meminfo").expect("kernel memory inventory");
    let total_kib: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(pressure.meminfo.unwrap().total, Some(total_kib * 1024));
    assert_eq!(document["args"]["pids"], serde_json::json!([pid]));
    assert_eq!(document["candidates"].as_array().unwrap().len(), 1);
    let session = document["session_id"].as_str().expect("actual session ID");
    let store = SessionStore::at_data_dir(&data_dir);
    let handle = store
        .open(&SessionId::parse(session).expect("canonical session ID"))
        .expect("open planned session");
    let persisted = fs::read(handle.dir.join("decision/plan.json")).expect("saved actual plan");
    let plan: Plan = serde_json::from_slice(&persisted).expect("planner output is executable Plan");
    let action = plan
        .actions
        .iter()
        .find(|action| action.target.pid.0 == pid)
        .unwrap_or_else(|| panic!("spawned target absent from actual plan: {document}"));
    assert_eq!(action.action, Action::Kill);
    assert_eq!(action.target.start_id, identity.start_id);
    assert!(
        !action.pre_checks.is_empty(),
        "planner must retain required checks"
    );
    assert!(action.rationale.posterior.is_some());

    // Export the actual producer document, including its full executable schema.
    // A sharing profile pseudonymizes identities but must preserve typed checks,
    // timeouts, actions, and numerical evidence for inspection.
    let bundle_path = data_dir.join("actual-plan-safe.ptb");
    let bundled = run_step(
        &log_dir,
        "bundle_actual_plan",
        &[
            "--format",
            "json",
            "bundle",
            "create",
            "--session",
            session,
            "--output",
            bundle_path.to_str().unwrap(),
        ],
        &data_dir,
        &config_dir,
        60,
    );
    assert!(
        bundled.status.success(),
        "actual plan export: {}",
        String::from_utf8_lossy(&bundled.stderr)
    );
    let mut reader = pt_bundle::BundleReader::open(&bundle_path).unwrap();
    assert!(reader.verify_all().is_empty());
    let exported: Plan = reader.read_plan().unwrap().expect("typed exported Plan");
    assert_eq!(exported.actions.len(), plan.actions.len());
    for (exported, original) in exported.actions.iter().zip(&plan.actions) {
        assert_eq!(exported.target.pid, original.target.pid);
        assert_eq!(exported.target.uid, original.target.uid);
        assert_eq!(exported.target.pgid, original.target.pgid);
        assert_eq!(exported.target.sid, original.target.sid);
        assert_eq!(exported.target.quality, original.target.quality);
        assert_eq!(exported.action, original.action);
        assert_eq!(exported.order, original.order);
        assert_eq!(exported.stage, original.stage);
        assert_eq!(exported.pre_checks, original.pre_checks);
        assert_eq!(exported.blocked, original.blocked);
        assert_eq!(exported.routing, original.routing);
        assert_eq!(exported.confidence, original.confidence);
        assert_eq!(
            serde_json::to_value(&exported.timeouts).unwrap(),
            serde_json::to_value(&original.timeouts).unwrap()
        );
        assert_eq!(exported.rationale.posterior, original.rationale.posterior);
        assert_eq!(
            exported.rationale.expected_loss,
            original.rationale.expected_loss
        );
        assert_eq!(
            exported.rationale.expected_recovery,
            original.rationale.expected_recovery
        );
        assert_eq!(exported.rationale.memory_mb, original.rationale.memory_mb);
    }
    assert_eq!(
        serde_json::to_value(&exported.gates_summary).unwrap(),
        serde_json::to_value(&plan.gates_summary).unwrap()
    );
    assert!(
        !String::from_utf8(reader.read_verified("plan.json").unwrap())
            .unwrap()
            .contains(&unique_seconds)
    );

    // A supplied stale identity must refuse before runtime work, even when the
    // saved plan contains a valid action for this same live PID.
    for invalid_target in [format!("{pid}:stale-start-id"), pid.to_string()] {
        let refused = run_step(
            &log_dir,
            "apply_invalid_identity",
            &[
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                session,
                "--targets",
                &invalid_target,
                "--yes",
            ],
            &data_dir,
            &config_dir,
            30,
        );
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("agent apply:"),
            "identity refusal must come from apply: {refused:?}"
        );
        assert!(state_of(pid).is_some_and(|state| state != 'Z'));
        assert!(!handle.dir.join("action/outcomes.jsonl").exists());
    }

    // Scope the real apply to our one exact identity, regardless of what the
    // planner observes on the worker. The normal runtime safety checks run.
    let target = format!("{pid}:{}", identity.start_id.0);
    policy.robot_mode.require_policy_snapshot = Some(true);
    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    for (step, snapshot) in [
        ("apply_missing_snapshot", None),
        (
            "apply_incomplete_snapshot",
            Some(serde_json::json!({"min_process_age_seconds": 0})),
        ),
    ] {
        let mut without_snapshot: Value = serde_json::from_slice(&persisted).unwrap();
        if let Some(snapshot) = snapshot {
            without_snapshot["policy_snapshot"] = snapshot;
        } else {
            without_snapshot
                .as_object_mut()
                .unwrap()
                .remove("policy_snapshot");
        }
        fs::write(
            handle.dir.join("decision/plan.json"),
            serde_json::to_vec(&without_snapshot).unwrap(),
        )
        .unwrap();
        let refused = run_step(
            &log_dir,
            step,
            &[
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                session,
                "--targets",
                &target,
                "--yes",
            ],
            &data_dir,
            &config_dir,
            30,
        );
        assert_eq!(refused.status.code(), Some(4));
        assert!(String::from_utf8_lossy(&refused.stderr)
            .contains("requires a valid recorded policy snapshot"));
        assert!(state_of(pid).is_some_and(|state| state != 'Z'));
        assert!(!handle.dir.join("action/outcomes.jsonl").exists());
    }
    let mut tampered: Value = serde_json::from_slice(&persisted).unwrap();
    for saved_action in tampered["actions"].as_array_mut().unwrap() {
        saved_action["pre_checks"] = serde_json::json!([]);
        saved_action["target"]["uid"] = serde_json::json!(identity.uid.wrapping_add(1));
    }
    fs::write(
        handle.dir.join("decision/plan.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    let refused = run_step(
        &log_dir,
        "apply_tampered_plan",
        &[
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            session,
            "--targets",
            &target,
            "--yes",
        ],
        &data_dir,
        &config_dir,
        240,
    );
    let refusal: Value = serde_json::from_slice(&refused.stdout).unwrap_or_else(|error| {
        panic!(
            "tampered-plan JSON {error}: {}",
            String::from_utf8_lossy(&refused.stderr)
        )
    });
    assert_eq!(refusal["outcomes"][0]["status"], "identity_mismatch");
    assert!(state_of(pid).is_some_and(|state| state != 'Z'));
    fs::write(handle.dir.join("decision/plan.json"), &persisted).unwrap();

    let applied = run_step(
        &log_dir,
        "apply",
        &[
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            session,
            "--targets",
            &target,
            "--yes",
        ],
        &data_dir,
        &config_dir,
        240,
    );
    let applied: Value = serde_json::from_slice(&applied.stdout).expect("actual apply JSON");
    assert_eq!(
        applied["outcomes"][0]["status"], "success",
        "actual planned action: {applied}"
    );
    assert_eq!(applied["outcomes"].as_array().unwrap().len(), 1);
    assert_eq!(applied["outcomes"][0]["pid"], pid);
    assert_eq!(applied["outcomes"][0]["action_id"], action.action_id);
    assert!(state_of(pid).is_none_or(|state| state == 'Z'));

    let verified = run_step(
        &log_dir,
        "verify",
        &["--format", "json", "agent", "verify", "--session", session],
        &data_dir,
        &config_dir,
        60,
    );
    let verification: Value = serde_json::from_slice(&verified.stdout).unwrap_or_else(|error| {
        panic!(
            "verify JSON {error}: {}",
            String::from_utf8_lossy(&verified.stderr)
        )
    });
    let outcome = verification["action_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|outcome| outcome["target"]["pid"] == pid)
        .expect("verified target");
    assert_eq!(outcome["outcome"], "confirmed_dead", "{verification}");
    assert!(outcome["target"]["cmd_full"]
        .as_str()
        .unwrap()
        .contains(&unique_seconds));
}

#[test]
fn agent_apply_enforces_policy_age_floor_when_plan_snapshot_is_missing() {
    let data_dir = TempDir::new().expect("data dir").keep();
    let config_dir = TempDir::new().expect("config dir").keep();
    write_test_policy(&config_dir);
    let policy_path = config_dir.join("policy.json");
    let mut policy: Policy = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy.guardrails.min_process_age_seconds = 60;
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let victim = ForeignTarget::spawn("sleep 903");
    let identity = live_identity(victim.pid);
    let session = session_with_plan(&data_dir, plan_action(Action::Kill, &identity));
    let target = format!("{}:{}", victim.pid, identity.start_id.0);
    let plan_path = SessionStore::at_data_dir(&data_dir)
        .open(&SessionId::parse(&session).unwrap())
        .unwrap()
        .dir
        .join("decision/plan.json");
    for saved_floor in [None, Some(0)] {
        if let Some(floor) = saved_floor {
            let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
            plan["policy_snapshot"] = serde_json::json!({"min_process_age_seconds": floor});
            fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        }
        let (status, json) = apply_with_args(
            &data_dir,
            &config_dir,
            &session,
            &target,
            &["--min-age", "0"],
        );
        assert_ne!(
            status, "success",
            "CLI or old snapshot must not lower the current policy floor: {json}"
        );
        assert!(json["outcomes"].as_array().unwrap().is_empty());
        assert_eq!(json["summary"]["attempted"], 0);
        assert!(victim.alive());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn agent_apply_subset_and_failed_child_do_not_kill_a_live_parent() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    struct ChildGuard(OwnedFd);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // SAFETY: this descriptor is bound to the child spawned below.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }
    let data_dir = TempDir::new().unwrap().keep();
    let config_dir = TempDir::new().unwrap().keep();
    write_test_policy(&config_dir);
    let writer_path = data_dir.join("child-pending-data.log");
    let parent = ForeignTarget::spawn(&format!(
        "sh -c 'sleep 904 3>>\"{}\" & wait'",
        writer_path.display()
    ));
    let children_path = format!("/proc/{0}/task/{0}/children", parent.pid);
    let mut child_pid = None;
    for _ in 0..100 {
        child_pid = fs::read_to_string(&children_path)
            .unwrap()
            .split_whitespace()
            .next()
            .and_then(|pid| pid.parse::<u32>().ok());
        if child_pid.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let child_pid = child_pid.expect("spawned writer child");
    // SAFETY: pidfd_open only acquires an identity-bound descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
    assert!(fd >= 0);
    let _child = ChildGuard(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    let parent_identity = live_identity(parent.pid);
    let child_identity = live_identity(child_pid);
    let mut parent_action = plan_action(Action::Kill, &parent_identity);
    parent_action.action_id = "kill-parent".to_string();
    let mut child_action = plan_action(Action::Kill, &child_identity);
    child_action.action_id = "kill-child".to_string();
    let session = session_with_actions(&data_dir, vec![parent_action, child_action]);
    let parent_target = format!("{}:{}", parent.pid, parent_identity.start_id.0);
    let child_target = format!("{}:{}", child_pid, child_identity.start_id.0);
    for targets in [
        parent_target.clone(),
        format!("{parent_target},{child_target}"),
    ] {
        let (_, document) = apply(&data_dir, &config_dir, &session, &targets);
        let outcomes = document["outcomes"].as_array().unwrap();
        assert_eq!(
            outcomes.len(),
            if targets == parent_target { 1 } else { 2 },
            "every selected action must have an outcome: {document}"
        );
        let parent_outcome = outcomes
            .iter()
            .find(|outcome| outcome["pid"] == parent.pid)
            .unwrap();
        assert_eq!(parent_outcome["status"], "precheck_blocked", "{document}");
        assert_eq!(parent_outcome["check"], "process_tree", "{document}");
        assert!(parent.alive());
        assert!(state_of(child_pid).is_some_and(|state| state != 'Z'));
        if outcomes.len() == 2 {
            let child_outcome = outcomes
                .iter()
                .find(|outcome| outcome["pid"] == child_pid)
                .unwrap();
            assert_eq!(child_outcome["status"], "precheck_blocked", "{document}");
            assert_eq!(child_outcome["check"], "check_data_loss_gate", "{document}");
            assert_eq!(outcomes[0]["pid"], child_pid, "child must precede parent");
        }
    }
}

#[test]
fn agent_apply_executes_renice_then_kill_on_live_process() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());

    let victim = ForeignTarget::spawn("sleep 300");
    let pid = victim.pid;
    let nice_before = nice_of(pid).expect("read nice");

    // Real identity of the live child, exactly as a plan records it.
    let identity = live_identity(pid);
    let target = format!("{}:{}", pid, identity.start_id.0);

    // 1) Renice: previously failed in apply ("requires ... support").
    let s1 = session_with_plan(data_dir.path(), plan_action(Action::Renice, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s1, &target);
    assert_eq!(status, "success", "renice outcome: {json}");
    // Renice only lowers priority: target nice is the default (10); a child that
    // already runs at nice >= 10 (the test was launched under `nice`) is left alone.
    let nice_after = nice_of(pid).expect("child alive after renice");
    let target_nice = i64::from(pt_core::action::renice::DEFAULT_NICE_VALUE);
    assert_eq!(
        nice_after,
        nice_before.max(target_nice),
        "unexpected nice after renice (before {nice_before})"
    );

    assert!(
        json["outcomes"][0]["signal_path"].is_null(),
        "renice sends no signal"
    );

    // 2) Kill.
    let s2 = session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s2, &target);
    assert_eq!(status, "success", "kill outcome: {json}");
    assert_eq!(json["outcomes"][0]["signal_path"], SIGNAL_PATH, "{json}");
    let exited = (0..50).any(|_| {
        if !victim.alive() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        false
    });
    assert!(exited, "target {pid} still running after apply kill");
}

/// First letter of the process state from ps ('T' = stopped).
fn state_of(pid: u32) -> Option<char> {
    let out = ProcessCommand::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().chars().next()
}

#[test]
fn agent_apply_pauses_resumes_and_refuses_stale_or_protected_targets() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());

    let victim = ForeignTarget::spawn("sleep 301");
    let pid = victim.pid;
    let identity = live_identity(pid);
    let target = format!("{}:{}", pid, identity.start_id.0);

    // Pause (SIGSTOP) then resume (SIGCONT), each checked on the live process.
    let s = session_with_plan(data_dir.path(), plan_action(Action::Pause, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_eq!(status, "success", "pause outcome: {json}");
    assert_eq!(json["outcomes"][0]["signal_path"], SIGNAL_PATH, "{json}");
    assert_eq!(state_of(pid), Some('T'), "child should be stopped");
    let s = session_with_plan(data_dir.path(), plan_action(Action::Resume, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_eq!(status, "success", "resume outcome: {json}");
    assert_eq!(json["outcomes"][0]["signal_path"], SIGNAL_PATH, "{json}");
    assert_ne!(state_of(pid), Some('T'), "child should run again");

    // A plan whose identity no longer matches the live process (PID reuse) must not
    // signal it.
    let mut stale = identity.clone();
    let (head, _) = stale.start_id.0.rsplit_once(':').expect("start id has pid");
    let (boot, start) = head.rsplit_once(':').expect("start id has start");
    let start: u64 = start.parse().expect("numeric start");
    stale.start_id.0 = format!("{boot}:{}:{pid}", start + 7);
    let stale_target = format!("{}:{}", pid, stale.start_id.0);
    let s = session_with_plan(data_dir.path(), plan_action(Action::Kill, &stale));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &stale_target);
    assert_ne!(status, "success", "stale identity must be refused: {json}");
    assert!(victim.alive(), "target must survive a stale-identity kill");

    // A built-in-protected process (argv0 of a tmux server) is blocked by the live
    // prechecks at apply time, even if a plan names it. Foreign session and not a
    // leader, so only the built-in protection (not session safety) can block it.
    let mux = ForeignTarget::spawn("bash -c \"exec -a 'tmux: server' sleep 302\"");
    let mux_pid = mux.pid;
    std::thread::sleep(Duration::from_millis(300));
    let mux_identity = live_identity(mux_pid);
    let mux_target = format!("{}:{}", mux_pid, mux_identity.start_id.0);
    let s = session_with_plan(data_dir.path(), plan_action(Action::Kill, &mux_identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &mux_target);
    assert_eq!(status, "precheck_blocked", "protected target: {json}");
    assert!(mux.alive(), "protected process must survive");
}

/// Pid of `parent`'s zombie child, once it has one.
fn zombie_child_of(parent: u32) -> u32 {
    for _ in 0..50 {
        let out = ProcessCommand::new("ps")
            .args(["-A", "-o", "pid=,ppid=,stat="])
            .output()
            .expect("ps");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let found = text.lines().find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3 && f[1] == parent.to_string() && f[2].starts_with('Z'))
                .then(|| f[0].parse().ok())
                .flatten()
        });
        if let Some(pid) = found {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("no zombie child of {parent}");
}

/// A zombie-to-parent route: Restart on the parent carrying the zombie's identity.
fn zombie_route(parent: &ProcessIdentity, zombie: &ProcessIdentity) -> PlanAction {
    let mut action = plan_action(Action::Restart, parent);
    action.routing = ActionRouting::ZombieToParent;
    action.original_zombie_target = Some(zombie.clone());
    action
}

/// Applying a zombie route nudges the parent with SIGCHLD and reports honestly when
/// the parent does not reap: the zombie persists, the parent is not harmed.
#[test]
fn agent_apply_zombie_route_reports_non_reaping_parent() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());

    // The target sh forks `sleep 0`, then execs `sleep 307`, which never reaps it.
    let parent = ForeignTarget::spawn("sh -c 'sleep 0 & exec sleep 307'");
    let zombie_pid = zombie_child_of(parent.pid);
    let parent_identity = live_identity(parent.pid);
    let zombie_identity = live_identity(zombie_pid);
    let target = format!("{}:{}", parent.pid, parent_identity.start_id.0);

    let s = session_with_plan(
        data_dir.path(),
        zombie_route(&parent_identity, &zombie_identity),
    );
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_ne!(status, "success", "non-reaping parent: {json}");
    assert!(json.to_string().contains("persists"), "{json}");
    assert!(parent.alive(), "the parent must not be harmed");
    assert_eq!(state_of(zombie_pid), Some('Z'), "zombie still there");
}

/// A parent that reaps on SIGCHLD clears its zombie when pt applies the route.
#[cfg(target_os = "linux")]
#[test]
fn agent_apply_zombie_route_reaps_via_sigchld() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());

    // Child exits first (zombie); only then does the parent install a SIGCHLD
    // handler that reaps, so the zombie waits for pt's nudge.
    let script = "import os, signal, time\n\
                  if os.fork() == 0: os._exit(0)\n\
                  time.sleep(1)\n\
                  signal.signal(signal.SIGCHLD, lambda s, f: os.waitpid(-1, os.WNOHANG))\n\
                  time.sleep(300)\n";
    let script_dir = TempDir::new().expect("script dir");
    let script_path = script_dir.path().join("reaper.py");
    fs::write(&script_path, script).expect("write script");
    let parent = ForeignTarget::spawn(&format!("python3 '{}'", script_path.display()));
    let zombie_pid = zombie_child_of(parent.pid);
    std::thread::sleep(Duration::from_millis(1500)); // handler installed
    let parent_identity = live_identity(parent.pid);
    let zombie_identity = live_identity(zombie_pid);
    let target = format!("{}:{}", parent.pid, parent_identity.start_id.0);

    let s = session_with_plan(
        data_dir.path(),
        zombie_route(&parent_identity, &zombie_identity),
    );
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_eq!(status, "success", "reaping parent: {json}");
    assert_ne!(state_of(zombie_pid), Some('Z'), "zombie reaped");
    assert!(parent.alive(), "the parent must not be harmed");
}

/// The recent-I/O data-loss probe runs once for all targets (it slept the full
/// 60 s window per target), and still blocks a process that writes periodically.
#[cfg(target_os = "linux")]
#[test]
fn agent_apply_probes_recent_io_once_for_all_targets() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());
    let file_dir = TempDir::new().expect("file dir");
    let log = file_dir.path().join("heartbeat.log");

    let a = ForeignTarget::spawn("sleep 308");
    let b = ForeignTarget::spawn("sleep 309");
    // Opens, appends and closes every 5 s: no fd held open, only recent I/O shows it.
    let w = ForeignTarget::spawn(&format!(
        "sh -c 'while :; do echo x >> \"{}\"; sleep 5; done'",
        log.display()
    ));
    std::thread::sleep(Duration::from_millis(300));

    let mut actions = Vec::new();
    let mut targets = Vec::new();
    for (i, pid) in [a.pid, b.pid, w.pid].into_iter().enumerate() {
        let identity = live_identity(pid);
        targets.push(format!("{}:{}", pid, identity.start_id.0));
        let mut action = plan_action(Action::Kill, &identity);
        action.action_id = format!("a-kill-{i}");
        actions.push(action);
    }
    let s = session_with_actions(data_dir.path(), actions);

    let started = std::time::Instant::now();
    let (_, json) = apply(data_dir.path(), config_dir.path(), &s, &targets.join(","));
    let elapsed = started.elapsed();

    let status_of = |pid: u32| {
        json["outcomes"]
            .as_array()
            .expect("outcomes")
            .iter()
            .find(|o| o["pid"].as_u64() == Some(u64::from(pid)))
            .cloned()
            .unwrap_or_else(|| panic!("no outcome for {pid}: {json}"))
    };
    assert_eq!(status_of(a.pid)["status"], "success", "{json}");
    assert_eq!(status_of(b.pid)["status"], "success", "{json}");
    let wo = status_of(w.pid);
    assert_eq!(wo["status"], "precheck_blocked", "{json}");
    assert!(
        wo["reason"].as_str().unwrap_or("").contains("recent I/O"),
        "{wo}"
    );
    assert!(w.alive(), "periodic writer must survive");
    // Three gated targets: one shared 60 s window, not three (>= 180 s).
    assert!(
        elapsed < Duration::from_secs(110),
        "apply took {elapsed:?}: the probe window is not shared"
    );
}

/// The data-loss gate blocks a kill of a process holding a regular file open for
/// writing (the other tests' targets, with stdio on /dev/null, are killable).
#[test]
fn agent_apply_data_loss_gate_blocks_kill_of_open_writer() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());
    let file_dir = TempDir::new().expect("file dir");
    let log = file_dir.path().join("journal.log");

    let writer = ForeignTarget::spawn(&format!("sleep 304 3>>'{}'", log.display()));
    let pid = writer.pid;
    std::thread::sleep(Duration::from_millis(300));
    let identity = live_identity(pid);
    let target = format!("{}:{}", pid, identity.start_id.0);

    let s = session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_eq!(status, "precheck_blocked", "open writer: {json}");
    assert!(
        json.to_string().contains("open write fds"),
        "blocked by the data-loss gate: {json}"
    );
    assert!(writer.alive(), "open writer must survive");
}

/// --max-total-blast-radius accumulates the memory of each kill (bd-qr40.7): apply
/// originally recorded 0 bytes, then trusted saved estimates. Allocate actual
/// resident memory while recording zero estimates: two measured footprints fit
/// the budget, while a third is refused and remains alive.
#[cfg(target_os = "linux")]
#[test]
fn agent_apply_total_blast_radius_budget_refuses_kills_past_the_cap() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());

    let policy_path = config_dir.path().join("policy.json");
    let mut policy: Policy = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy.data_loss_gates.block_if_recent_io_seconds = Some(1);
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    let victims = std::array::from_fn::<_, 3, _>(|_| {
        ForeignTarget::spawn(
            "python3 -c 'import time; memory=bytearray(b\"x\"*(16*1024*1024)); time.sleep(600)'",
        )
    });
    let pids: Vec<u32> = victims.iter().map(|victim| victim.pid).collect();
    let started = std::time::Instant::now();
    let resident_bytes = loop {
        let scan = quick_scan(&QuickScanOptions {
            pids: pids.clone(),
            ..QuickScanOptions::default()
        })
        .unwrap();
        let resident: Vec<u64> = pids
            .iter()
            .map(|pid| {
                scan.processes
                    .iter()
                    .find(|process| process.pid.0 == *pid)
                    .map_or(0, |process| process.rss_bytes)
            })
            .collect();
        if resident.iter().all(|bytes| *bytes >= 16 * 1024 * 1024) {
            break resident;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "real resident memory: {resident:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let budget_mb =
        (resident_bytes[0] + resident_bytes[1] + resident_bytes[2] / 2) as f64 / (1024.0 * 1024.0);
    let mut actions = Vec::new();
    let mut targets = Vec::new();
    for (i, victim) in victims.iter().enumerate() {
        let identity = live_identity(victim.pid);
        targets.push(format!("{}:{}", victim.pid, identity.start_id.0));
        let mut action = plan_action(Action::Kill, &identity);
        action.action_id = format!("a-kill-{i}");
        action.order = i as u32;
        action.rationale.memory_mb = Some(0.0);
        actions.push(action);
    }
    let s = session_with_actions(data_dir.path(), actions);

    let (_, json) = apply_with_args(
        data_dir.path(),
        config_dir.path(),
        &s,
        &targets.join(","),
        &["--max-total-blast-radius", &budget_mb.to_string()],
    );
    let outcomes = json["outcomes"].as_array().expect("outcomes");
    let statuses: Vec<(u64, &str)> = outcomes
        .iter()
        .map(|o| {
            (
                o["pid"].as_u64().expect("pid"),
                o["status"].as_str().expect("status"),
            )
        })
        .collect();
    let succeeded: Vec<u64> = statuses
        .iter()
        .filter(|(_, st)| *st == "success")
        .map(|(pid, _)| *pid)
        .collect();
    let refused: Vec<u64> = statuses
        .iter()
        .filter(|(_, st)| *st == "blocked_by_constraints")
        .map(|(pid, _)| *pid)
        .collect();
    assert_eq!(
        succeeded.len(),
        2,
        "two measured kills fit in {budget_mb} MB: {json}"
    );
    assert_eq!(
        refused.len(),
        1,
        "the third measured kill exceeds {budget_mb} MB: {json}"
    );
    let refused_outcome = outcomes
        .iter()
        .find(|outcome| outcome["status"] == "blocked_by_constraints")
        .unwrap();
    assert!(refused_outcome["current_rss_bytes"].as_u64().unwrap() >= 16 * 1024 * 1024);
    assert!(refused_outcome["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| { violation["constraint"] == "max_total_blast_radius" }));
    let survivor = victims
        .iter()
        .find(|v| u64::from(v.pid) == refused[0])
        .expect("refused pid is one of ours");
    assert!(survivor.alive(), "a refused target must survive");
}
