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
    _tty_master: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "macos")]
    identity: ProcessIdentity,
}

impl ForeignTarget {
    fn spawn(script: &str) -> Self {
        Self::spawn_in_session(script, None)
    }

    fn spawn_with_tty(script: &str) -> Self {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes both descriptors; default terminal settings
        // and size are requested by null input pointers.
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(result, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: the two successful descriptors are distinct and uniquely owned.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        for descriptor in [&master, &slave] {
            // SAFETY: set close-on-exec on this fixture's live descriptors. The
            // slave remains available during pre_exec to acquire the terminal.
            assert_ne!(
                unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                -1,
                "terminal close-on-exec: {}",
                std::io::Error::last_os_error()
            );
        }
        Self::spawn_in_session(script, Some((master, slave)))
    }

    fn spawn_in_session(
        script: &str,
        terminal: Option<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)>,
    ) -> Self {
        use std::io::BufRead;
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let tty_slave = terminal.as_ref().map(|(_, slave)| slave.as_raw_fd());
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
        // SAFETY: these calls only configure the child before exec. The borrowed
        // slave stays alive in the parent until spawn has completed.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(slave) = tty_slave {
                    if libc::ioctl(slave, libc::TIOCSCTTY, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
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
            // Keep the master alive so closing it cannot send SIGHUP to the
            // target before the identity-bound teardown has finished.
            _tty_master: terminal.map(|(master, _)| master),
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
fn nice_of(pid: u32) -> Result<i64, String> {
    let out = ProcessCommand::new("ps")
        .args(["-o", "nice=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("ps nice for {pid}: {error}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!(
            "ps nice for {pid}: status={}, stdout={stdout:?}, stderr={stderr:?}",
            out.status
        ));
    }
    stdout.trim().parse().map_err(|error| {
        format!(
            "ps nice for {pid}: {error}, status={}, stdout={stdout:?}, stderr={stderr:?}",
            out.status
        )
    })
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
fn agent_apply_refuses_the_live_protected_group_without_spending_budget() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    write_test_policy(config_dir.path());
    let victim = ForeignTarget::spawn("sleep 354");
    let identity = live_identity(victim.pid);
    let target = format!("{}:{}", victim.pid, identity.start_id.0);
    let group = ProcessCommand::new("ps")
        .args(["-o", "group=", "-p", &victim.pid.to_string()])
        .output()
        .expect("collect the actual target group");
    assert!(group.status.success(), "group observation: {group:?}");
    let group = String::from_utf8(group.stdout).expect("group UTF-8");
    assert!(!group.trim().is_empty(), "group must be known");
    let policy_path = config_dir.path().join("policy.json");
    let mut policy: Policy = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy.guardrails.protected_groups = vec![group.trim().to_string()];
    policy.data_loss_gates.block_if_recent_io_seconds = Some(1);
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    let blocked_session = session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(
        data_dir.path(),
        config_dir.path(),
        &blocked_session,
        &target,
    );
    assert_eq!(status, "blocked_by_policy", "{json}");
    assert_eq!(
        json["outcomes"][0]["violation"]["rule"], "guardrails.protected_groups",
        "{json}"
    );
    assert!(victim.alive(), "the protected exact target must survive");
    assert_eq!(live_identity(victim.pid), identity);
    assert!(
        !data_dir.path().join("rate_limit.json").exists(),
        "a refused action must not prepare or spend kill budget"
    );

    // Removing only this group restriction permits the same live target, with
    // every other identity, session, writer and built-in check retained.
    policy.guardrails.protected_groups.clear();
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    let permitted_session =
        session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(
        data_dir.path(),
        config_dir.path(),
        &permitted_session,
        &target,
    );
    assert_eq!(status, "success", "{json}");
    assert!(!victim.alive(), "the actually permitted target must exit");
    let budget: Value =
        serde_json::from_slice(&fs::read(data_dir.path().join("rate_limit.json")).unwrap())
            .unwrap();
    assert_eq!(budget["kill_timestamps"].as_array().unwrap().len(), 1);
    assert_eq!(budget["pending_kill_intent"], false);
}

#[test]
fn default_robot_policy_preserves_the_actual_useful_spare_target() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    let policy = Policy::default();
    assert!(!policy.robot_mode.enabled);
    fs::write(
        config_dir.path().join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    let victim = ForeignTarget::spawn_with_tty("sleep 355");
    let identity = live_identity(victim.pid);
    let observation = quick_scan(&QuickScanOptions {
        pids: vec![victim.pid],
        ..QuickScanOptions::default()
    })
    .expect("observe the useful target's actual controlling terminal");
    assert!(observation
        .processes
        .iter()
        .find(|process| process.pid.0 == victim.pid)
        .expect("owned terminal target is present")
        .has_tty());
    // Fresh owned targets need explicit age/selection/threshold options. The
    // robot policy itself remains default, and no action is executed.
    let output = cargo_bin_cmd!("pt-core")
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .timeout(Duration::from_secs(60))
        .args([
            "--format",
            "json",
            "--robot",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--pids",
            &victim.pid.to_string(),
        ])
        .output()
        .expect("run the actual default-policy robot planner");
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "plan status={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).expect("actual plan JSON");
    assert_eq!(plan["candidates"].as_array().unwrap().len(), 1, "{plan}");
    assert_eq!(plan["candidates"][0]["pid"], victim.pid);
    assert_eq!(
        plan["candidates"][0]["recommended_action"], "keep",
        "{plan}"
    );
    assert_eq!(
        plan["recommendations"]["spare_set"],
        serde_json::json!([victim.pid]),
        "{plan}"
    );
    assert!(plan["actions"].as_array().unwrap().is_empty(), "{plan}");
    assert!(victim.alive());
    assert_eq!(live_identity(victim.pid), identity);
    assert!(!data_dir.path().join("rate_limit.json").exists());
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
/// An explicit four-class test signature supplies the prior for our owned orphan;
/// default loss, FDR, posterior thresholds and runtime checks remain intact.
/// This tests controlled execution and identities, not calibration or FDR quality.
#[cfg(target_os = "linux")]
#[test]
fn actual_agent_plan_applies_and_verifies_its_saved_live_identity() {
    use pt_core::supervision::signature::{
        BetaParams, SignaturePriors, SignatureSchema, SupervisorSignature,
    };
    use pt_core::supervision::SupervisorCategory;
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

    struct OwnedSubreaper(Child);
    impl Drop for OwnedSubreaper {
        fn drop(&mut self) {
            // EOF asks this dedicated helper to use its original pidfd and reap
            // its own child, including when an assertion unwinds the test.
            drop(self.0.stdin.take());
            if let Err(error) = self.0.wait() {
                eprintln!("owned subreaper wait failed: {error}");
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
    let defaults = serde_json::to_value(&policy).unwrap();
    policy.robot_mode.enabled = true;
    policy.guardrails.min_process_age_seconds = 0;
    let configured = serde_json::to_value(&policy).unwrap();
    let mut unchanged_defaults = configured.clone();
    unchanged_defaults["robot_mode"]["enabled"] = defaults["robot_mode"]["enabled"].clone();
    unchanged_defaults["guardrails"]["min_process_age_seconds"] =
        defaults["guardrails"]["min_process_age_seconds"].clone();
    assert_eq!(unchanged_defaults, defaults);
    assert_eq!(configured["loss_matrix"], defaults["loss_matrix"]);
    assert_eq!(configured["fdr_control"], defaults["fdr_control"]);
    assert_eq!(configured["fdr_control"]["enabled"], true);
    assert_eq!(
        configured["robot_mode"]["min_posterior"],
        defaults["robot_mode"]["min_posterior"]
    );
    assert_eq!(configured["guardrails"]["builtin_protection"], true);
    assert_eq!(
        configured["guardrails"]["never_kill_ppid"],
        defaults["guardrails"]["never_kill_ppid"]
    );
    fs::write(
        config_dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize isolated policy"),
    )
    .expect("write isolated policy");

    // The dedicated helper is a kernel child subreaper; do not change the test
    // process's adoption behavior. Its setsid intermediate exits after the
    // helper binds a pidfd, genuinely orphaning and adopting the sleep child.
    let unique_seconds = format!("1000.{}", std::process::id());
    let script = r#"
import ctypes, json, os, signal, sys, time
from pathlib import Path
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
pid_read, pid_write = os.pipe()
ack_read, ack_write = os.pipe()
intermediate = os.fork()
if intermediate == 0:
    os.close(pid_read)
    os.close(ack_write)
    os.setsid()
    target = os.fork()
    if target == 0:
        null = os.open('/dev/null', os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        for fd in [int(name) for name in os.listdir('/proc/self/fd') if int(name) > 2]:
            try:
                os.close(fd)
            except OSError:
                pass
        os.execve('/usr/bin/sleep', ['sleep', sys.argv[1]], {'PATH': '/usr/bin:/bin'})
    os.write(pid_write, str(target).encode() + b'\n')
    os.close(pid_write)
    if os.read(ack_read, 1) != b'1':
        # Before adoption this is our unreaped direct child: its PID cannot be
        # reused. Bootstrap refusal must kill/reap it without a scanner PID.
        try:
            os.kill(target, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(target, 0)
    os._exit(0)
os.close(pid_write)
os.close(ack_read)
with os.fdopen(pid_read) as pipe:
    target = int(pipe.readline())
try:
    pidfd = os.pidfd_open(target)
except BaseException:
    os.close(ack_write)
    assert os.waitpid(intermediate, 0) == (intermediate, 0)
    raise
try:
    os.write(ack_write, b'1')
    os.close(ack_write)
    assert os.waitpid(intermediate, 0) == (intermediate, 0)
    deadline = time.monotonic() + 5
    while Path('/proc/' + str(target) + '/comm').read_text().strip() != 'sleep':
        assert time.monotonic() < deadline
        time.sleep(0.01)
    print(json.dumps({'pid': target, 'former_parent': intermediate,
                      'adoptive_parent': os.getpid()}), flush=True)
    sys.stdin.readline()
finally:
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
    except ProcessLookupError:
        pass
    os.waitpid(target, 0)
    os.close(pidfd)
    print('Owned pidfd target reaped; files retained', file=sys.stderr, flush=True)
"#;
    let spawn_owned_orphan = |target_log: &Path, seconds: &str, data: &Path, config: &Path| {
        let mut reaper = OwnedSubreaper(
            ProcessCommand::new("python3")
                .args(["-u", "-c", script, seconds])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(fs::File::create(target_log.join("target-launch.stderr")).unwrap())
                .spawn()
                .expect("spawn owned subreaper"),
        );
        let mut line = String::new();
        std::io::BufReader::new(reaper.0.stdout.take().expect("adoption evidence pipe"))
            .read_line(&mut line)
            .expect("read adopted target evidence");
        let adoption: Value = serde_json::from_str(&line).expect("actual kernel adoption evidence");
        let pid: u32 = adoption["pid"].as_u64().unwrap().try_into().unwrap();
        assert_eq!(adoption["adoptive_parent"], reaper.0.id());
        // SAFETY: pidfd_open observes our owned process. Ownership transfers
        // once to OwnedFd and lasts through all assertions and cleanup.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        let target = BoundTarget(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        let identity = live_identity(pid);
        let raw_stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let fields: Vec<_> = raw_stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(fields[1].parse::<u32>().unwrap(), reaper.0.id());
        assert_eq!(
            fields[3].parse::<u32>().unwrap(),
            adoption["former_parent"].as_u64().unwrap() as u32
        );
        assert_ne!(adoption["former_parent"], adoption["adoptive_parent"]);
        assert_ne!(identity.sid, Some(pid));
        assert_eq!(fields[4], "0", "orphan must have no controlling terminal");
        assert_ne!(fields[0], "Z");
        // SAFETY: getuid has no pointer arguments and only observes this process.
        assert_eq!(identity.uid, unsafe { libc::getuid() });
        assert_eq!(
            fs::read(format!("/proc/{pid}/environ")).unwrap(),
            b"PATH=/usr/bin:/bin\0"
        );
        let mut descriptors = Vec::new();
        for path in fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
            let path = path.unwrap().path();
            let fd: u32 = path.file_name().unwrap().to_str().unwrap().parse().unwrap();
            let destination = fs::read_link(&path).unwrap();
            assert_eq!(destination, Path::new("/dev/null"));
            let raw_fdinfo = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).unwrap();
            descriptors.push(
                serde_json::json!({"fd":fd, "destination":destination, "raw_fdinfo":raw_fdinfo}),
            );
        }
        descriptors.sort_by_key(|descriptor| descriptor["fd"].as_u64().unwrap());
        assert_eq!(
            descriptors
                .iter()
                .map(|descriptor| descriptor["fd"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        fs::write(
            target_log.join("owned-target-before.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "adoption":adoption, "identity":identity, "raw_stat":raw_stat,
                "raw_status":fs::read_to_string(format!("/proc/{pid}/status")).unwrap(),
                "descriptors":descriptors, "data_dir":data, "config_dir":config,
            }))
            .unwrap(),
        )
        .unwrap();
        (reaper, target, identity)
    };
    let (mut reaper, _target, identity) =
        spawn_owned_orphan(&log_dir, &unique_seconds, &data_dir, &config_dir);
    let pid = identity.pid.0;

    // This intentionally strong typed prior is input to the real Bayesian path,
    // not a claim that the prior is calibrated for production processes.
    let argument_pattern = format!(r"(^|\s){}$", regex::escape(&unique_seconds));
    let mut signatures = SignatureSchema::new();
    signatures.add(
        SupervisorSignature::new("literal-owned-sleep", SupervisorCategory::Other)
            .with_process_patterns(vec!["^sleep$"])
            .with_arg_patterns(vec![&argument_pattern])
            .with_priors(SignaturePriors {
                useful: Some(BetaParams::new(1.0, 999.0)),
                useful_bad: Some(BetaParams::new(1.0, 999.0)),
                abandoned: Some(BetaParams::new(999.0, 1.0)),
                zombie: Some(BetaParams::new(1.0, 999.0)),
            }),
    );
    signatures.validate_for_activation().unwrap();
    fs::write(
        config_dir.join("signatures.json"),
        signatures.to_json().unwrap(),
    )
    .unwrap();
    let validated = run_step(
        &log_dir,
        "signature_validate",
        &["--format", "json", "signature", "validate"],
        &data_dir,
        &config_dir,
        30,
    );
    assert_eq!(validated.status.code(), Some(0), "{validated:?}");

    let planned = run_step(
        &log_dir,
        "plan",
        &[
            "--format",
            "json",
            "agent",
            "plan",
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
    assert_eq!(
        serde_json::from_slice::<Value>(&persisted).unwrap(),
        document
    );
    let plan: Plan = serde_json::from_slice(&persisted).expect("planner output is executable Plan");
    let action = plan
        .actions
        .iter()
        .find(|action| action.target.pid.0 == pid)
        .unwrap_or_else(|| panic!("spawned target absent from actual plan: {document}"));
    assert_eq!(action.action, Action::Kill);
    assert_eq!(action.target.start_id, identity.start_id);
    assert_eq!(action.target.uid, identity.uid);
    assert_eq!(action.target.sid, identity.sid);
    assert_eq!(document["candidates"][0]["ppid"], reaper.0.id());
    assert_eq!(
        document["candidates"][0]["inference"]["prior_source"],
        "signature"
    );
    assert_eq!(document["candidates"][0]["inference"]["mode"], "bayesian");
    assert_eq!(
        document["candidates"][0]["signature"]["name"],
        "literal-owned-sleep"
    );
    assert_eq!(
        document["candidates"][0]["inference"]["fast_path"]["used"],
        false
    );
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
    let mut malformed_age_snapshot = serde_json::to_value(&policy).unwrap();
    malformed_age_snapshot["min_process_age_seconds"] = serde_json::json!("invalid");
    for (step, snapshot) in [
        ("apply_missing_snapshot", None),
        (
            "apply_incomplete_snapshot",
            Some(serde_json::json!({"min_process_age_seconds": 0})),
        ),
        (
            "apply_malformed_snapshot",
            Some(serde_json::json!("invalid")),
        ),
        ("apply_malformed_snapshot_age", Some(malformed_age_snapshot)),
    ] {
        let mut without_snapshot: Value = serde_json::from_slice(&persisted).unwrap();
        let has_snapshot = snapshot.is_some();
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
        if has_snapshot {
            let response: Value = serde_json::from_slice(&refused.stdout).unwrap();
            assert_eq!(response["error"], "invalid_policy_snapshot");
            assert_eq!(response["session_id"], session);
        }
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
    assert_eq!(applied.status.code(), Some(2), "{applied:?}");
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
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
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
    drop(reaper.0.stdin.take());
    assert!(reaper.0.wait().expect("reap owned subreaper").success());
    eprint!(
        "{}",
        fs::read_to_string(log_dir.join("target-launch.stderr")).unwrap()
    );

    // A separate real producer phase exercises saved/current policy drift.
    // The default 60s I/O check outlasts a minute-cap probe, so declare an hourly
    // cap of one. Leave the minute, loss, FDR, posterior and I/O defaults intact.
    let drift_log = log_dir.join("policy-drift");
    fs::create_dir_all(&drift_log).unwrap();
    let drift_data = TempDir::new().expect("drift data dir").keep();
    let drift_config = TempDir::new().expect("drift config dir").keep();
    let mut saved_policy = Policy::default();
    saved_policy.robot_mode.enabled = true;
    saved_policy.guardrails.min_process_age_seconds = 0;
    saved_policy.guardrails.max_kills_per_hour = Some(1);
    let original_defaults = serde_json::to_value(Policy::default()).unwrap();
    let mut otherwise_default = serde_json::to_value(&saved_policy).unwrap();
    for (section, field) in [
        ("robot_mode", "enabled"),
        ("guardrails", "min_process_age_seconds"),
        ("guardrails", "max_kills_per_hour"),
    ] {
        otherwise_default[section][field] = original_defaults[section][field].clone();
    }
    assert_eq!(otherwise_default, original_defaults);
    fs::write(
        drift_config.join("policy.json"),
        serde_json::to_vec_pretty(&saved_policy).unwrap(),
    )
    .unwrap();
    let durations = [
        format!("1001.{}", std::process::id()),
        format!("1002.{}", std::process::id()),
    ];
    let mut drift_signatures = signatures.clone();
    drift_signatures.signatures[0].patterns.arg_patterns = vec![format!(
        r"(^|\s)({}|{})$",
        regex::escape(&durations[0]),
        regex::escape(&durations[1])
    )];
    drift_signatures.signatures[0].patterns.min_matches = 2;
    drift_signatures.validate_for_activation().unwrap();
    fs::write(
        drift_config.join("signatures.json"),
        drift_signatures.to_json().unwrap(),
    )
    .unwrap();
    let validated = run_step(
        &drift_log,
        "signature_validate",
        &["--format", "json", "signature", "validate"],
        &drift_data,
        &drift_config,
        30,
    );
    assert_eq!(validated.status.code(), Some(0), "{validated:?}");
    let first_log = drift_log.join("first-target");
    let second_log = drift_log.join("second-target");
    fs::create_dir_all(&first_log).unwrap();
    fs::create_dir_all(&second_log).unwrap();
    let (mut first_reaper, _first_target, first_identity) =
        spawn_owned_orphan(&first_log, &durations[0], &drift_data, &drift_config);
    let (mut second_reaper, _second_target, second_identity) =
        spawn_owned_orphan(&second_log, &durations[1], &drift_data, &drift_config);
    let identities = [&first_identity, &second_identity];
    let mut sessions = Vec::new();
    let mut produced = Vec::new();
    // Produce both executable sessions before recording any successful kill.
    for (index, identity) in identities.iter().enumerate() {
        let planned = run_step(
            &drift_log,
            &format!("plan-{index}"),
            &[
                "--format",
                "json",
                "agent",
                "plan",
                "--min-age",
                "0",
                "--pids",
                &identity.pid.0.to_string(),
            ],
            &drift_data,
            &drift_config,
            180,
        );
        assert_eq!(planned.status.code(), Some(1), "{planned:?}");
        let actual: Value = serde_json::from_slice(&planned.stdout).unwrap();
        assert_eq!(actual["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(
            actual["candidates"][0]["inference"]["prior_source"],
            "signature"
        );
        assert_eq!(
            actual["candidates"][0]["signature"]["match_level"],
            "command_plus_args"
        );
        assert_eq!(
            actual["policy_snapshot"]["guardrails"]["max_kills_per_hour"],
            1
        );
        let session = actual["session_id"].as_str().unwrap().to_string();
        let handle = SessionStore::at_data_dir(&drift_data)
            .open(&SessionId::parse(&session).unwrap())
            .unwrap();
        let recorded = fs::read(handle.dir.join("decision/plan.json")).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&recorded).unwrap(), actual);
        let canonical: Plan = serde_json::from_slice(&recorded).unwrap();
        assert_eq!(canonical.actions.len(), 1);
        assert_eq!(canonical.actions[0].target, **identity);
        assert_eq!(canonical.actions[0].action, Action::Kill);
        assert!(!canonical.actions[0].blocked);
        assert!(!canonical.actions[0].pre_checks.is_empty());
        assert!(state_of(identity.pid.0).is_some_and(|state| state != 'Z'));
        sessions.push(session);
        produced.push(canonical);
    }
    assert!(!drift_data.join("rate_limit.json").exists());
    let first_target = format!("{}:{}", first_identity.pid.0, first_identity.start_id.0);
    let applied = run_step(
        &drift_log,
        "apply-first",
        &[
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            &sessions[0],
            "--targets",
            &first_target,
            "--yes",
        ],
        &drift_data,
        &drift_config,
        240,
    );
    assert_eq!(applied.status.code(), Some(2), "{applied:?}");
    let first: Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(first["outcomes"].as_array().unwrap().len(), 1);
    assert_eq!(first["outcomes"][0]["status"], "success");
    assert_eq!(first["outcomes"][0]["pid"], first_identity.pid.0);
    assert_eq!(
        first["outcomes"][0]["action_id"],
        produced[0].actions[0].action_id
    );
    assert!(state_of(first_identity.pid.0).is_none_or(|state| state == 'Z'));
    let delivered_at = std::time::Instant::now();
    let verified = run_step(
        &drift_log,
        "verify-first",
        &[
            "--format",
            "json",
            "agent",
            "verify",
            "--session",
            &sessions[0],
        ],
        &drift_data,
        &drift_config,
        60,
    );
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    let verification: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert!(verification["action_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|outcome| outcome["target"]["pid"] == first_identity.pid.0
            && outcome["outcome"] == "confirmed_dead"));
    let before_budget: Value =
        serde_json::from_slice(&fs::read(drift_data.join("rate_limit.json")).unwrap()).unwrap();
    assert_eq!(
        before_budget["kill_timestamps"].as_array().unwrap().len(),
        1
    );
    assert_eq!(before_budget["pending_kill_intent"], false);
    let mut current_policy = saved_policy.clone();
    current_policy.guardrails.max_kills_per_run = 100;
    current_policy.guardrails.max_kills_per_minute = Some(100);
    current_policy.guardrails.max_kills_per_hour = Some(100);
    current_policy.guardrails.max_kills_per_day = Some(1000);
    fs::write(
        drift_config.join("policy.json"),
        serde_json::to_vec_pretty(&current_policy).unwrap(),
    )
    .unwrap();
    let second_target = format!("{}:{}", second_identity.pid.0, second_identity.start_id.0);
    let refused = run_step(
        &drift_log,
        "apply-second-after-current-caps-raised",
        &[
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            &sessions[1],
            "--targets",
            &second_target,
            "--yes",
        ],
        &drift_data,
        &drift_config,
        240,
    );
    assert_ne!(refused.status.code(), Some(2), "{refused:?}");
    let refusal: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refusal["outcomes"].as_array().unwrap().len(), 1);
    assert_eq!(refusal["outcomes"][0]["pid"], second_identity.pid.0);
    assert_eq!(
        refusal["outcomes"][0]["action_id"],
        produced[1].actions[0].action_id
    );
    assert_eq!(refusal["outcomes"][0]["status"], "blocked_by_policy");
    assert_eq!(refusal["outcomes"][0]["reason"], "rate_limit");
    assert!(
        refusal["outcomes"][0]["violation"]["message"]
            .as_str()
            .unwrap()
            .contains("1 kills already performed this hour (max 1)"),
        "{refusal}"
    );
    assert!(
        delivered_at.elapsed() < Duration::from_secs(3600),
        "hour-cap probe exceeded its actual window"
    );
    assert!(state_of(second_identity.pid.0).is_some_and(|state| state != 'Z'));
    assert_eq!(live_identity(second_identity.pid.0), second_identity);
    let after_budget: Value =
        serde_json::from_slice(&fs::read(drift_data.join("rate_limit.json")).unwrap()).unwrap();
    assert_eq!(
        after_budget["kill_timestamps"],
        before_budget["kill_timestamps"]
    );
    assert_eq!(after_budget["pending_kill_intent"], false);
    eprintln!("saved hourly cap1/current caps100/100/100/1000; actual post-delivery elapsed={}ms; retained={}", delivered_at.elapsed().as_millis(), drift_log.display());
    for (reaper, target_log) in [
        (&mut first_reaper, &first_log),
        (&mut second_reaper, &second_log),
    ] {
        drop(reaper.0.stdin.take());
        assert!(reaper.0.wait().unwrap().success());
        eprint!(
            "{}",
            fs::read_to_string(target_log.join("target-launch.stderr")).unwrap()
        );
    }
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

    let mut victim = ForeignTarget::spawn("sleep 300");
    let pid = victim.pid;
    let nice_before = nice_of(pid).unwrap_or_else(|error| {
        panic!(
            "read initial nice: {error}; leader={:?}; target_alive={}",
            victim.leader.try_wait(),
            victim.alive()
        )
    });

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

/// Live WS11.2 acceptance. These Linux fixtures exercise the real planner,
/// persisted execution evidence and CLI verifier, not inference calibration.
#[cfg(target_os = "linux")]
mod live_agent_verify {
    use super::*;
    use pt_core::action::{IdentityProvider, LiveIdentityProvider};
    use pt_core::collect::ProcessRecord;
    use pt_core::session::SessionState;
    use std::io::{BufRead, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::{Output, Stdio};

    struct BoundProcess {
        identity: ProcessIdentity,
        fd: OwnedFd,
    }

    impl BoundProcess {
        fn bind(identity: ProcessIdentity) -> Option<Self> {
            // SAFETY: opening a pidfd observes the process without signaling it.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid.0, 0) };
            if fd < 0 {
                return None;
            }
            // SAFETY: the successful syscall returns a uniquely owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            if !matches!(LiveIdentityProvider::new().revalidate(&identity), Ok(true)) {
                return None;
            }
            Some(Self { identity, fd })
        }

        fn signal(&self, signal: i32) -> libc::c_long {
            // SAFETY: this descriptor can signal only the captured process,
            // including after its numeric PID becomes reusable.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            }
        }
    }

    impl Drop for BoundProcess {
        fn drop(&mut self) {
            self.signal(libc::SIGKILL);
        }
    }

    struct Respawner {
        parent: BoundProcess,
        _initial_child: BoundProcess,
    }

    impl Drop for Respawner {
        fn drop(&mut self) {
            // Stop the bound spawner before collecting its current children so
            // killing a replacement cannot cause another replacement to escape.
            if self.parent.signal(libc::SIGSTOP) == 0 {
                let parent_pid = self.parent.identity.pid.0;
                for _ in 0..50 {
                    if state_of(parent_pid) == Some('T') {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if state_of(parent_pid) == Some('T')
                    && matches!(
                        LiveIdentityProvider::new().revalidate(&self.parent.identity),
                        Ok(true)
                    )
                {
                    if let Ok(children) =
                        fs::read_to_string(format!("/proc/{parent_pid}/task/{parent_pid}/children"))
                    {
                        let pids: Vec<u32> = children
                            .split_whitespace()
                            .filter_map(|pid| pid.parse().ok())
                            .collect();
                        if pids.is_empty() {
                            return;
                        }
                        if let Ok(scan) = quick_scan(&QuickScanOptions {
                            pids,
                            include_kernel_threads: false,
                            timeout: Some(Duration::from_secs(5)),
                            progress: None,
                        }) {
                            for child in scan.processes {
                                if child.ppid.0 == parent_pid
                                    && child.uid == self.parent.identity.uid
                                {
                                    let identity = ProcessIdentity {
                                        pid: child.pid,
                                        start_id: child.start_id,
                                        uid: child.uid,
                                        pgid: child.pgid,
                                        sid: child.sid,
                                        quality: IdentityQuality::Full,
                                    };
                                    if let Some(owned_child) = BoundProcess::bind(identity) {
                                        owned_child.signal(libc::SIGKILL);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            self.parent.signal(libc::SIGKILL);
        }
    }

    fn detached_child(script: &str) -> (u32, u32) {
        let mut launcher = ProcessCommand::new("setsid")
            .args(["--fork", "sh", "-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn test-owned detached shell");
        let mut line = String::new();
        std::io::BufReader::new(launcher.stdout.take().expect("PID pipe"))
            .read_line(&mut line)
            .expect("read owned parent and child");
        assert!(launcher.wait().expect("wait for setsid launcher").success());
        let mut pids = line.split_whitespace();
        let parent = pids.next().expect("parent PID").parse().unwrap();
        let child = pids.next().expect("child PID").parse().unwrap();
        assert!(pids.next().is_none(), "unexpected PID record: {line}");
        (parent, child)
    }

    fn current_process(pid: u32) -> ProcessRecord {
        quick_scan(&QuickScanOptions {
            pids: vec![pid],
            include_kernel_threads: false,
            timeout: Some(Duration::from_secs(30)),
            progress: None,
        })
        .expect("scan test-owned process")
        .processes
        .into_iter()
        .find(|process| process.pid.0 == pid)
        .expect("test-owned process is present")
    }

    fn orphan(script: &str) -> (BoundProcess, ProcessRecord) {
        let (former_parent, pid) = detached_child(script);
        let target = BoundProcess::bind(live_identity(pid)).expect("bind owned orphan");
        let started = std::time::Instant::now();
        loop {
            let process = current_process(pid);
            if process.ppid.0 != former_parent {
                assert_ne!(process.sid, Some(pid), "orphan is not a session leader");
                return (target, process);
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "shell did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn run_step(
        log_dir: &Path,
        step: &str,
        args: &[&str],
        data_dir: &Path,
        config_dir: &Path,
        path_override: Option<&std::ffi::OsStr>,
    ) -> Output {
        let started = std::time::Instant::now();
        let mut command = cargo_bin_cmd!("pt-core");
        command
            .timeout(Duration::from_secs(240))
            .env("PT_SKIP_GLOBAL_LOCK", "1")
            .env("PROCESS_TRIAGE_DATA", data_dir)
            .env("PROCESS_TRIAGE_CONFIG", config_dir)
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .args(args);
        if let Some(path) = path_override {
            command.env("PATH", path);
        }
        let output = command.output().expect("run actual verify acceptance step");
        let stdout_path = format!("{step}.stdout.json");
        let stderr_path = format!("{step}.stderr.jsonl");
        fs::write(log_dir.join(&stdout_path), &output.stdout).expect("retain stdout");
        fs::write(log_dir.join(&stderr_path), &output.stderr).expect("retain stderr");
        let record = serde_json::json!({
            "step": step, "command": "pt-core", "args": args,
            "path_override": path_override.map(|path| path.to_string_lossy()),
            "exit_code": output.status.code(), "elapsed_ms": started.elapsed().as_millis(),
            "stdout_sha256": pt_bundle::FileEntry::compute_checksum(&output.stdout),
            "stderr_sha256": pt_bundle::FileEntry::compute_checksum(&output.stderr),
            "stdout_path": stdout_path, "stderr_path": stderr_path,
        });
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("steps.jsonl"))
            .expect("open retained steps");
        writeln!(log, "{record}").expect("record actual command");
        eprintln!("{record}");
        output
    }

    fn plan_owned(
        log_dir: &Path,
        step: &str,
        pid: u32,
        expected_recommendation: &str,
        data_dir: &Path,
        config_dir: &Path,
    ) -> (Value, Plan) {
        let output = run_step(
            log_dir,
            step,
            &[
                "--format",
                "json",
                "--robot",
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
            data_dir,
            config_dir,
            None,
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let document: Value = serde_json::from_slice(&output.stdout).expect("actual plan JSON");
        assert_eq!(document["args"]["pids"], serde_json::json!([pid]));
        assert_eq!(
            document["candidates"].as_array().unwrap().len(),
            1,
            "{document}"
        );
        let candidate = &document["candidates"][0];
        let identity = live_identity(pid);
        assert_eq!(candidate["pid"], pid);
        assert_eq!(candidate["uid"], identity.uid);
        assert_eq!(candidate["start_id"], identity.start_id.0);
        assert_eq!(
            candidate["recommended_action"], expected_recommendation,
            "{document}"
        );
        let session = SessionId::parse(document["session_id"].as_str().unwrap()).unwrap();
        let handle = SessionStore::at_data_dir(data_dir).open(&session).unwrap();
        let saved = fs::read(handle.dir.join("decision/plan.json")).expect("actual saved plan");
        fs::write(log_dir.join(format!("{step}.saved-plan.json")), &saved).unwrap();
        let plan: Plan = serde_json::from_slice(&saved).expect("canonical executable Plan");
        match expected_recommendation {
            "kill" => {
                assert_eq!(plan.actions.len(), 1);
                let action = &plan.actions[0];
                assert_eq!(action.action, Action::Kill);
                assert!(action.target.matches(&identity));
                assert!(
                    !action.pre_checks.is_empty(),
                    "actual safety checks remain present"
                );
                assert!(action.rationale.posterior.is_some());
            }
            "review" => assert!(
                plan.actions.is_empty(),
                "review-only candidates must not produce executable actions"
            ),
            other => panic!("unsupported expected recommendation {other}"),
        }
        (document, plan)
    }

    fn verify(
        log_dir: &Path,
        step: &str,
        session: &str,
        data_dir: &Path,
        config_dir: &Path,
    ) -> (Output, Value) {
        let output = run_step(
            log_dir,
            step,
            &[
                "--format",
                "json",
                "agent",
                "verify",
                "--session",
                session,
                "--check-respawn",
            ],
            data_dir,
            config_dir,
            None,
        );
        let document = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("verify JSON {error}: {output:?}"));
        (output, document)
    }

    fn apply_owned(
        log_dir: &Path,
        step: &str,
        plan: &Plan,
        data_dir: &Path,
        config_dir: &Path,
    ) -> pt_core::verify::SavedActionOutcome {
        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.action, Action::Kill);
        assert!(
            !action.blocked,
            "the real planner must permit our exact target"
        );
        let target = format!("{}:{}", action.target.pid.0, action.target.start_id.0);
        let output = run_step(
            log_dir,
            step,
            &[
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                &plan.session_id,
                "--targets",
                &target,
                "--yes",
            ],
            data_dir,
            config_dir,
            None,
        );
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let document: Value = serde_json::from_slice(&output.stdout).expect("actual apply JSON");
        let outcomes = document["outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 1, "{document}");
        assert_eq!(outcomes[0]["action_id"], action.action_id);
        assert_eq!(outcomes[0]["pid"], action.target.pid.0);
        assert_eq!(outcomes[0]["status"], "success", "{document}");
        let session = SessionId::parse(&plan.session_id).unwrap();
        let handle = SessionStore::at_data_dir(data_dir).open(&session).unwrap();
        let saved =
            fs::read(handle.dir.join("action/outcomes.jsonl")).expect("actual saved outcomes");
        fs::write(log_dir.join(format!("{step}.saved-outcomes.jsonl")), &saved).unwrap();
        let executions =
            pt_core::verify::parse_action_outcomes(std::str::from_utf8(&saved).unwrap())
                .expect("typed successful execution evidence");
        assert_eq!(executions.len(), 1);
        let executed = executions.into_iter().next().unwrap();
        assert_eq!(executed.status, "success");
        assert!(executed.target.as_ref().unwrap().matches(&action.target));
        assert_eq!(executed.command.as_deref(), Some("sleep 1000"));
        assert!(executed.parent_pid.is_some_and(|pid| pid > 0));
        assert!(executed.executed_at.is_some());
        assert!(executed
            .execution_clock
            .as_ref()
            .is_some_and(|clock| !clock.boot_id.is_empty() && clock.ticks > 0));
        executed
    }

    fn assert_born_after_execution(
        process: &ProcessRecord,
        executed: &pt_core::verify::SavedActionOutcome,
    ) {
        let clock = executed.execution_clock.as_ref().unwrap();
        let mut parts = process.start_id.0.rsplitn(3, ':');
        assert_eq!(parts.next().unwrap().parse::<u32>().unwrap(), process.pid.0);
        let birth_ticks = parts.next().unwrap().parse::<u64>().unwrap();
        assert_eq!(parts.next().unwrap(), clock.boot_id);
        assert!(
            birth_ticks > clock.ticks,
            "challenge must pass the post-execution birth-time predicate"
        );
    }

    fn recorded_state(log_dir: &Path, step: &str, data_dir: &Path, session: &str) -> SessionState {
        let session = SessionId::parse(session).unwrap();
        let handle = SessionStore::at_data_dir(data_dir).open(&session).unwrap();
        let saved = fs::read(handle.manifest_path()).unwrap();
        fs::write(log_dir.join(format!("{step}.saved-manifest.json")), &saved).unwrap();
        serde_json::from_slice::<SessionManifest>(&saved)
            .unwrap()
            .state
    }

    #[test]
    fn actual_agent_verify_attributes_respawns_and_ignores_unexecuted_candidates() {
        let data_dir = TempDir::new().unwrap().keep();
        let config_dir = TempDir::new().unwrap().keep();
        let log_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-logs/e2e/agent_verify")
            .join(format!("{}-{}", std::process::id(), SessionId::new().0));
        fs::create_dir_all(&log_dir).unwrap();
        write_test_policy(&config_dir);
        let policy_path = config_dir.join("policy.json");
        let mut policy: Policy = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
        // This explicit policy permits the PID-scoped disposable fixtures.
        // The probe checks execution plumbing, not default-policy decisions,
        // inference quality or FDR calibration; built-in protection stays enabled.
        policy.guardrails.protected_users.clear();
        policy.guardrails.never_kill_ppid.clear();
        policy.fdr_control.enabled = false;
        policy.data_loss_gates.block_if_recent_io_seconds = Some(1);
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
        fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();

        let (parent_pid, original_pid) = detached_child(
            "first=1; while :; do sleep 1000 </dev/null >/dev/null 2>&1 & child=$!; \
             if [ \"$first\" = 1 ]; then printf '%s %s\\n' \"$$\" \"$child\"; first=0; exec >/dev/null; fi; \
             wait \"$child\"; sleep 0.2; done",
        );
        let respawner = Respawner {
            parent: BoundProcess::bind(live_identity(parent_pid)).expect("bind owned spawner"),
            _initial_child: BoundProcess::bind(live_identity(original_pid))
                .expect("bind owned child"),
        };
        let original = current_process(original_pid);
        assert_eq!(original.ppid.0, parent_pid);
        assert_eq!(original.cmd, "sleep 1000");
        let (_, respawn_plan) = plan_owned(
            &log_dir,
            "respawn_plan",
            original_pid,
            "kill",
            &data_dir,
            &config_dir,
        );
        assert_eq!(
            recorded_state(
                &log_dir,
                "unexecuted_before",
                &data_dir,
                &respawn_plan.session_id
            ),
            SessionState::Planned
        );
        let (unexecuted_output, unexecuted) = verify(
            &log_dir,
            "unexecuted_verify",
            &respawn_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(unexecuted_output.status.code(), Some(0), "{unexecuted}");
        assert!(unexecuted["action_outcomes"].as_array().unwrap().is_empty());
        assert_eq!(unexecuted["verification"]["overall_status"], "success");
        assert_eq!(unexecuted["respawn_check"]["respawned_count"], 0);
        assert_eq!(unexecuted["respawn_check"]["unknown_count"], 0);
        assert!(state_of(original_pid).is_some_and(|state| state != 'Z'));
        assert_eq!(
            recorded_state(
                &log_dir,
                "unexecuted_after",
                &data_dir,
                &respawn_plan.session_id
            ),
            SessionState::Planned
        );

        // Plant a prior failure in the real unexecuted session. A clean verify
        // must not revive it; the positive apply below uses a fresh real plan.
        SessionStore::at_data_dir(&data_dir)
            .open(&SessionId::parse(&respawn_plan.session_id).unwrap())
            .unwrap()
            .update_state(SessionState::Failed)
            .unwrap();
        assert_eq!(
            recorded_state(
                &log_dir,
                "unexecuted_failed_before",
                &data_dir,
                &respawn_plan.session_id
            ),
            SessionState::Failed
        );
        let (failed_unexecuted_output, failed_unexecuted) = verify(
            &log_dir,
            "unexecuted_prior_failed_verify",
            &respawn_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(
            failed_unexecuted_output.status.code(),
            Some(0),
            "{failed_unexecuted}"
        );
        assert!(failed_unexecuted["action_outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(failed_unexecuted["respawn_check"]["respawned_count"], 0);
        assert_eq!(failed_unexecuted["respawn_check"]["unknown_count"], 0);
        assert_eq!(
            recorded_state(
                &log_dir,
                "unexecuted_failed_after",
                &data_dir,
                &respawn_plan.session_id
            ),
            SessionState::Failed
        );
        assert!(state_of(original_pid).is_some_and(|state| state != 'Z'));
        let (_, respawn_plan) = plan_owned(
            &log_dir,
            "respawn_execution_plan",
            original_pid,
            "kill",
            &data_dir,
            &config_dir,
        );

        let respawn_execution = apply_owned(
            &log_dir,
            "respawn_apply",
            &respawn_plan,
            &data_dir,
            &config_dir,
        );
        let started = std::time::Instant::now();
        let replacement = loop {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "owned shell did not respawn child"
            );
            let children =
                fs::read_to_string(format!("/proc/{parent_pid}/task/{parent_pid}/children"))
                    .unwrap();
            let pids: Vec<u32> = children
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect();
            if pids.is_empty() {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let scan = quick_scan(&QuickScanOptions {
                pids,
                include_kernel_threads: false,
                timeout: Some(Duration::from_secs(30)),
                progress: None,
            })
            .unwrap();
            if let Some(process) = scan.processes.into_iter().find(|process| {
                process.ppid.0 == parent_pid
                    && process.pid.0 != original_pid
                    && process.cmd == "sleep 1000"
                    && !process.state.is_zombie()
            }) {
                break process;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _replacement = BoundProcess::bind(live_identity(replacement.pid.0)).unwrap();
        assert_eq!(replacement.uid, original.uid);
        assert_ne!(replacement.start_id, original.start_id);
        assert_born_after_execution(&replacement, &respawn_execution);
        assert_eq!(respawn_execution.parent_pid, Some(parent_pid));
        assert!(respawn_execution
            .parent_identity
            .as_ref()
            .unwrap()
            .matches(&respawner.parent.identity));
        let (respawn_output, respawned) = verify(
            &log_dir,
            "respawn_verify",
            &respawn_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(respawn_output.status.code(), Some(3), "{respawned}");
        assert_eq!(
            respawned["respawn_check"]["respawned_count"], 1,
            "{respawned}"
        );
        assert_eq!(
            respawned["respawn_check"]["unknown_count"], 0,
            "{respawned}"
        );
        assert_eq!(
            recorded_state(
                &log_dir,
                "respawn_verified",
                &data_dir,
                &respawn_plan.session_id
            ),
            SessionState::Failed
        );
        let outcomes = respawned["action_outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["target"]["pid"], original_pid);
        assert_eq!(outcomes[0]["outcome"], "respawned", "{respawned}");
        assert_eq!(outcomes[0]["verified"], false);
        assert_eq!(outcomes[0]["respawn_detected"]["pid"], replacement.pid.0);
        assert_eq!(outcomes[0]["respawn_detected"]["parent_pid"], parent_pid);
        assert_eq!(
            outcomes[0]["respawn_detected"]["parent_start_id"],
            respawner.parent.identity.start_id.0
        );

        let (_orphan, original_orphan) = orphan(
            "sleep 1000 </dev/null >/dev/null 2>&1 & child=$!; printf '%s %s\\n' \"$$\" \"$child\"",
        );
        let (_, orphan_plan) = plan_owned(
            &log_dir,
            "orphan_plan",
            original_orphan.pid.0,
            "kill",
            &data_dir,
            &config_dir,
        );
        let orphan_execution = apply_owned(
            &log_dir,
            "orphan_apply",
            &orphan_plan,
            &data_dir,
            &config_dir,
        );
        assert!(state_of(original_orphan.pid.0).is_none_or(|state| state == 'Z'));
        assert_eq!(orphan_execution.parent_pid, Some(original_orphan.ppid.0));

        let started = std::time::Instant::now();
        let execution_clock = orphan_execution.execution_clock.as_ref().unwrap();
        loop {
            let now = pt_core::verify::capture_execution_clock().unwrap();
            assert_eq!(now.boot_id, execution_clock.boot_id);
            if now.ticks > execution_clock.ticks {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(20));
        }

        // Both challenges are born after the real kill. One has the exact
        // command but another parent; the other shares the adopter but only
        // contains the killed command as a substring.
        let same_command = ForeignTarget::spawn("sleep 1000");
        let same_command_record = current_process(same_command.pid);
        assert_eq!(same_command_record.cmd, original_orphan.cmd);
        assert_eq!(same_command_record.uid, original_orphan.uid);
        assert_ne!(same_command_record.ppid, original_orphan.ppid);
        assert_born_after_execution(&same_command_record, &orphan_execution);
        let (_collision, collision) = orphan(
            "sleep 10000 </dev/null >/dev/null 2>&1 & child=$!; printf '%s %s\\n' \"$$\" \"$child\"",
        );
        assert_eq!(collision.ppid, original_orphan.ppid);
        assert_eq!(collision.uid, original_orphan.uid);
        assert!(collision.cmd.contains(&original_orphan.cmd));
        assert_ne!(collision.cmd, original_orphan.cmd);
        assert_born_after_execution(&collision, &orphan_execution);
        fs::write(
            log_dir.join("live-respawn-and-challenges.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "original": original,
                "replacement": replacement,
                "original_orphan": original_orphan,
                "same_command_other_parent": same_command_record,
                "substring_collision_same_parent": collision,
            }))
            .unwrap(),
        )
        .unwrap();
        let (orphan_output, orphan_report) = verify(
            &log_dir,
            "orphan_verify_with_collisions",
            &orphan_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(orphan_output.status.code(), Some(0), "{orphan_report}");
        assert_eq!(
            orphan_report["respawn_check"]["respawned_count"], 0,
            "{orphan_report}"
        );
        assert_eq!(orphan_report["respawn_check"]["unknown_count"], 0);
        let outcomes = orphan_report["action_outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["target"]["pid"], original_orphan.pid.0);
        assert_eq!(outcomes[0]["outcome"], "confirmed_dead", "{orphan_report}");
        assert_eq!(outcomes[0]["verified"], true);
        assert!(outcomes[0].get("respawn_detected").is_none());
        assert!(orphan_report["resource_summary"]
            .get("expected_freed_mb")
            .is_some());
        assert!(orphan_report["resource_summary"]
            .get("memory_freed_mb")
            .is_none());
        assert!(same_command.alive());
        assert!(!current_process(collision.pid.0).state.is_zombie());

        // Corrupt observations must not replace the real successful report.
        // These are explicit subprocess fault injections, not live process proof.
        let handle = SessionStore::at_data_dir(&data_dir)
            .open(&SessionId::parse(&orphan_plan.session_id).unwrap())
            .unwrap();
        let plan_path = handle.dir.join("decision/plan.json");
        let original_plan = fs::read(&plan_path).unwrap();
        let verification_path = handle.dir.join("action/verifications.json");
        let original_verification = fs::read(&verification_path).unwrap();
        let original_manifest = fs::read(handle.manifest_path()).unwrap();
        let mut wrong_session: Value = serde_json::from_slice(&original_plan).unwrap();
        wrong_session["session_id"] = Value::String(respawn_plan.session_id.clone());
        fs::write(&plan_path, serde_json::to_vec(&wrong_session).unwrap()).unwrap();
        let refused = run_step(
            &log_dir,
            "wrong_session_verify",
            &["agent", "verify", "--session", &orphan_plan.session_id],
            &data_dir,
            &config_dir,
            None,
        );
        assert_eq!(refused.status.code(), Some(20), "{refused:?}");
        assert!(String::from_utf8_lossy(&refused.stderr).contains("does not match"));
        assert!(refused.stdout.is_empty());
        assert_eq!(fs::read(&verification_path).unwrap(), original_verification);
        assert_eq!(fs::read(handle.manifest_path()).unwrap(), original_manifest);
        fs::write(&plan_path, &original_plan).unwrap();

        use std::os::unix::fs::PermissionsExt;
        for (step, script, message) in [
            (
                "failed_ps_verify",
                "#!/bin/sh\nexit 7\n",
                "full process snapshot exited",
            ),
            (
                "malformed_ps_verify",
                "#!/bin/sh\nprintf '%s\\n' 'malformed process row'\n",
                "incomplete process snapshot",
            ),
            (
                "empty_ps_verify",
                "#!/bin/sh\nexit 0\n",
                "full process snapshot contains no processes",
            ),
        ] {
            let probe_dir = log_dir.join(step);
            fs::create_dir(&probe_dir).unwrap();
            let ps_path = probe_dir.join("ps");
            fs::write(&ps_path, script).unwrap();
            fs::set_permissions(&ps_path, fs::Permissions::from_mode(0o700)).unwrap();
            let path =
                std::env::join_paths(std::iter::once(probe_dir).chain(std::env::split_paths(
                    &std::env::var_os("PATH").expect("actual executable search path"),
                )))
                .unwrap();
            let refused = run_step(
                &log_dir,
                step,
                &["agent", "verify", "--session", &orphan_plan.session_id],
                &data_dir,
                &config_dir,
                Some(&path),
            );
            assert_eq!(refused.status.code(), Some(20), "{refused:?}");
            assert!(String::from_utf8_lossy(&refused.stderr).contains(message));
            assert!(refused.stdout.is_empty());
            assert_eq!(fs::read(&verification_path).unwrap(), original_verification);
            assert_eq!(fs::read(handle.manifest_path()).unwrap(), original_manifest);
        }
        let (restored_output, restored) = verify(
            &log_dir,
            "restored_valid_observation_verify",
            &orphan_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(restored_output.status.code(), Some(0), "{restored}");
        assert_eq!(restored["action_outcomes"][0]["verified"], true);

        policy
            .guardrails
            .force_review_patterns
            .push(pt_core::config::policy::PatternEntry {
                pattern: "^sleep 1000$".into(),
                kind: pt_core::config::policy::PatternKind::Regex,
                case_insensitive: false,
                notes: Some("test-owned target requires review".into()),
            });
        fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
        let (review_document, review_plan) = plan_owned(
            &log_dir,
            "review_plan",
            same_command.pid,
            "review",
            &data_dir,
            &config_dir,
        );
        assert_eq!(
            review_document["candidates"][0]["recommended_action"], "review",
            "{review_document}"
        );
        assert!(review_plan.actions.is_empty());
        assert_eq!(
            recorded_state(
                &log_dir,
                "review_before",
                &data_dir,
                &review_plan.session_id
            ),
            SessionState::Planned
        );
        let (review_output, review_report) = verify(
            &log_dir,
            "review_verify",
            &review_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(review_output.status.code(), Some(0), "{review_report}");
        assert!(review_report["action_outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(review_report["verification"]["overall_status"], "success");
        assert_eq!(review_report["respawn_check"]["respawned_count"], 0);
        assert_eq!(review_report["respawn_check"]["unknown_count"], 0);
        assert_eq!(
            recorded_state(&log_dir, "review_after", &data_dir, &review_plan.session_id),
            SessionState::Planned
        );
        assert!(same_command.alive(), "review-only target must remain alive");

        SessionStore::at_data_dir(&data_dir)
            .open(&SessionId::parse(&review_plan.session_id).unwrap())
            .unwrap()
            .update_state(SessionState::Failed)
            .unwrap();
        assert_eq!(
            recorded_state(
                &log_dir,
                "review_failed_before",
                &data_dir,
                &review_plan.session_id
            ),
            SessionState::Failed
        );
        let (failed_review_output, failed_review) = verify(
            &log_dir,
            "review_prior_failed_verify",
            &review_plan.session_id,
            &data_dir,
            &config_dir,
        );
        assert_eq!(
            failed_review_output.status.code(),
            Some(0),
            "{failed_review}"
        );
        assert!(failed_review["action_outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(failed_review["respawn_check"]["respawned_count"], 0);
        assert_eq!(failed_review["respawn_check"]["unknown_count"], 0);
        assert_eq!(
            recorded_state(
                &log_dir,
                "review_failed_after",
                &data_dir,
                &review_plan.session_id
            ),
            SessionState::Failed
        );
        assert!(
            same_command.alive(),
            "prior failure must not turn review into execution"
        );
    }
}
