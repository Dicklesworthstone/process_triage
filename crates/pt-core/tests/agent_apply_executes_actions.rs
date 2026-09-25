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

/// A target process in a foreign session and not its leader: how a process left
/// behind by a terminal looks. (pt's own session and session leaders are protected by
/// the session-safety pre-check, which apply always runs.) `sh` leads the new session,
/// starts `script` in the background, reports its pid and reaps it.
struct ForeignTarget {
    leader: Child,
    pid: u32,
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
        let pid = line.trim().parse().expect("target pid");
        Self { leader, pid }
    }

    fn alive(&self) -> bool {
        // The leader reaps the target, so a dead target disappears from ps.
        state_of(self.pid).is_some_and(|s| s != 'Z')
    }
}

impl Drop for ForeignTarget {
    fn drop(&mut self) {
        // SAFETY: plain kill(2) on pids this test created.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
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
        plan_id: format!("plan-{}", action.action_id),
        session_id: session_id.0.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        actions: vec![action],
        pre_toggled: Vec::new(),
        gates_summary: GatesSummary {
            total_candidates: 1,
            blocked_candidates: 0,
            pre_toggled_actions: 0,
        },
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
    let out = cargo_bin_cmd!("pt-core")
        .timeout(Duration::from_secs(120))
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
        .output()
        .expect("run agent apply");
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

    // 2) Kill.
    let s2 = session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s2, &target);
    assert_eq!(status, "success", "kill outcome: {json}");
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
    assert_eq!(state_of(pid), Some('T'), "child should be stopped");
    let s = session_with_plan(data_dir.path(), plan_action(Action::Resume, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s, &target);
    assert_eq!(status, "success", "resume outcome: {json}");
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
