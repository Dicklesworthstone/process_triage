//! Composite action runner that dispatches to specialized runners.

use super::executor::{ActionError, ActionRunner};
use crate::decision::Action;
use crate::plan::{ActionRouting, PlanAction};

use super::renice::ReniceActionRunner;
use super::signal::SignalActionRunner;

#[cfg(target_os = "linux")]
use super::cgroup_throttle::CpuThrottleActionRunner;
#[cfg(target_os = "linux")]
use super::cpuset_quarantine::CpusetQuarantineActionRunner;
#[cfg(target_os = "linux")]
use super::freeze::FreezeActionRunner;

/// Dispatches actions to the appropriate runner implementation.
#[derive(Debug)]
pub struct CompositeActionRunner {
    signal: SignalActionRunner,
    renice: ReniceActionRunner,
    #[cfg(target_os = "linux")]
    freeze: FreezeActionRunner,
    #[cfg(target_os = "linux")]
    throttle: CpuThrottleActionRunner,
    #[cfg(target_os = "linux")]
    quarantine: CpusetQuarantineActionRunner,
}

impl CompositeActionRunner {
    /// Construct a runner using default configurations.
    pub fn with_defaults() -> Self {
        Self {
            signal: SignalActionRunner::with_defaults(),
            renice: ReniceActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            freeze: FreezeActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            throttle: CpuThrottleActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            quarantine: CpusetQuarantineActionRunner::with_defaults(),
        }
    }
}

impl CompositeActionRunner {
    /// How the most recent signal was delivered ("pidfd", "kill", "kill_group"),
    /// clearing it; `None` when the last action sent no signal.
    pub fn take_signal_path(&self) -> Option<&'static str> {
        self.signal.take_signal_path()
    }

    /// Whether a destructive signal actually reached a target since the last call.
    pub fn take_kill_signal_delivered(&self) -> bool {
        self.signal.take_kill_signal_delivered()
    }
}

impl Default for CompositeActionRunner {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Refuse cgroup-wide actions unless the target is the only process in its cgroup.
///
/// Freeze/throttle/quarantine write to the target's *existing* cgroup
/// (`cgroup.freeze`, `cpu.max`, `cpuset.cpus`). In a shared cgroup (a login
/// session scope, a tmux spawn scope, a container) that would freeze/throttle every
/// member, possibly including the user's shell, other agents, or pt itself. Until
/// pt moves the target into a dedicated leaf cgroup, it only acts when the cgroup
/// holds the target alone.
#[cfg(target_os = "linux")]
pub(super) fn read_cgroup_identity(pid: u32) -> Option<pt_common::ProcessIdentity> {
    let stat = crate::collect::proc_parsers::parse_proc_stat(pid)?;
    if stat.pid != pid || stat.starttime == 0 {
        return None;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    uuid::Uuid::parse_str(boot_id.trim()).ok()?;
    Some(pt_common::ProcessIdentity {
        pid: pt_common::ProcessId(pid),
        start_id: pt_common::StartId::from_linux(boot_id.trim(), stat.starttime, pid),
        uid,
        pgid: u32::try_from(stat.pgrp).ok(),
        sid: u32::try_from(stat.session).ok(),
        quality: pt_common::IdentityQuality::Full,
    })
}

/// Revalidate the planned incarnation and built-in protections for direct callers.
#[cfg(target_os = "linux")]
pub(super) fn ensure_cgroup_target(
    target: &pt_common::ProcessIdentity,
) -> Result<String, ActionError> {
    let pid = target.pid.0;
    if pid <= 1 || crate::collect::protected::live_invoker_chain_pids().contains(&pid) {
        return Err(ActionError::Failed(format!(
            "refusing cgroup mutation for protected PID {pid}"
        )));
    }
    if target.quality != pt_common::IdentityQuality::Full {
        return Err(ActionError::IdentityMismatch);
    }
    let current = read_cgroup_identity(pid).ok_or(ActionError::IdentityMismatch)?;
    if !target.matches(&current) {
        return Err(ActionError::IdentityMismatch);
    }
    // SAFETY: geteuid has no preconditions and only reads the caller's credentials.
    if current.uid != unsafe { libc::geteuid() } {
        return Err(ActionError::PermissionDenied);
    }
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map_err(|error| ActionError::Failed(format!("cannot read target name: {error}")))?;
    let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|error| ActionError::Failed(format!("cannot read target command: {error}")))?;
    let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
    if crate::collect::protected::builtin_protection_match(comm.trim(), &cmd).is_some()
        || crate::collect::protected::live_service_ancestor(pid).is_some()
        || crate::collect::read_cgroup_role(pid).is_supervised_service()
    {
        return Err(ActionError::Failed(
            "refusing cgroup mutation for protected infrastructure".to_string(),
        ));
    }
    ensure_exclusive_cgroup(pid)
}

#[cfg(target_os = "linux")]
pub(super) fn ensure_exclusive_cgroup(pid: u32) -> Result<String, ActionError> {
    if pid <= 1 {
        return Err(ActionError::Failed(format!(
            "refusing cgroup mutation for protected PID {pid}"
        )));
    }
    let path = crate::collect::collect_cgroup_details(pid)
        .and_then(|d| d.unified_path)
        .ok_or_else(|| ActionError::Failed(format!("cannot resolve cgroup of pid {pid}")))?;
    ensure_exclusive_cgroup_path(pid, std::path::Path::new(&format!("/sys/fs/cgroup{path}")))?;
    Ok(path)
}

/// Check the actual controller directory, including a hybrid v1 fallback.
#[cfg(target_os = "linux")]
pub(super) fn ensure_exclusive_cgroup_path(
    pid: u32,
    directory: &std::path::Path,
) -> Result<(), ActionError> {
    if pid <= 1 {
        return Err(ActionError::Failed(format!(
            "refusing cgroup mutation for protected PID {pid}"
        )));
    }
    let path = directory.display();
    let procs_file = directory.join("cgroup.procs");
    let content = std::fs::read_to_string(&procs_file)
        .map_err(|e| ActionError::Failed(format!("cannot read {}: {e}", procs_file.display())))?;
    let others = shared_cgroup_members(&content, pid)?;
    if others > 0 {
        return Err(ActionError::Failed(format!(
            "refusing: cgroup {path} is shared with {others} other process(es) and would \
             affect them all (leaf-cgroup isolation not implemented)"
        )));
    }
    // Resource limits and freeze state affect descendants too. Require a leaf
    // rather than inferring isolation from only this directory's process list.
    for entry in std::fs::read_dir(directory)
        .map_err(|error| ActionError::Failed(format!("cannot inspect cgroup {path}: {error}")))?
    {
        let entry = entry.map_err(|error| {
            ActionError::Failed(format!("cannot inspect cgroup entry in {path}: {error}"))
        })?;
        if entry
            .file_type()
            .map_err(|error| {
                ActionError::Failed(format!("cannot inspect cgroup entry in {path}: {error}"))
            })?
            .is_dir()
        {
            return Err(ActionError::Failed(format!(
                "refusing: cgroup {path} has descendants; an exclusive leaf is required"
            )));
        }
    }
    Ok(())
}

/// Number of processes other than `pid` listed in `cgroup.procs` content.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn shared_cgroup_members(procs_content: &str, pid: u32) -> Result<usize, ActionError> {
    let mut target_present = false;
    let mut others = 0;
    for line in procs_content.lines() {
        let member = line.trim().parse::<u32>().map_err(|_| {
            ActionError::Failed(
                "cannot establish cgroup isolation: invalid process list".to_string(),
            )
        })?;
        if member == 0 {
            return Err(ActionError::Failed(
                "cannot establish cgroup isolation: invalid zero PID".to_string(),
            ));
        }
        if member == pid {
            target_present = true;
        } else {
            others += 1;
        }
    }
    if !target_present {
        return Err(ActionError::Failed(format!(
            "cannot establish cgroup isolation: target PID {pid} is absent"
        )));
    }
    Ok(others)
}

impl ActionRunner for CompositeActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        // Each specialized cgroup runner checks isolation at its own write entry,
        // including callers that use the runner without this dispatcher.
        match action.action {
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill => self.signal.execute(action),
            Action::Renice => self.renice.execute(action),
            #[cfg(target_os = "linux")]
            Action::Freeze | Action::Unfreeze => self.freeze.execute(action),
            #[cfg(target_os = "linux")]
            Action::Throttle => self.throttle.execute(action),
            #[cfg(target_os = "linux")]
            Action::Quarantine | Action::Unquarantine => self.quarantine.execute(action),
            // A zombie's remedy targets its parent: nudge it to reap. (A real
            // restart of the parent needs supervisor support, bd-qr40.6.)
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::Restart if action.routing == ActionRouting::ZombieToParent => {
                self.signal.nudge_parent_to_reap(action)
            }
            Action::Restart => Err(ActionError::Failed(
                "restart requires supervisor support".to_string(),
            )),
            #[cfg(not(target_os = "linux"))]
            Action::Freeze
            | Action::Unfreeze
            | Action::Throttle
            | Action::Quarantine
            | Action::Unquarantine => Err(ActionError::Failed(
                "action not supported on this platform".to_string(),
            )),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill => self.signal.verify(action),
            Action::Renice => self.renice.verify(action),
            #[cfg(target_os = "linux")]
            Action::Freeze | Action::Unfreeze => self.freeze.verify(action),
            #[cfg(target_os = "linux")]
            Action::Throttle => self.throttle.verify(action),
            #[cfg(target_os = "linux")]
            Action::Quarantine | Action::Unquarantine => self.quarantine.verify(action),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::Restart if action.routing == ActionRouting::ZombieToParent => {
                self.signal.verify_zombie_reaped(action)
            }
            Action::Restart => Ok(()),
            #[cfg(not(target_os = "linux"))]
            Action::Freeze
            | Action::Unfreeze
            | Action::Throttle
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;
    use crate::decision::{Action, DecisionOutcome, ExpectedLoss};
    use crate::plan::{generate_plan, DecisionBundle, DecisionCandidate, PlanAction};
    use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};

    fn make_action() -> PlanAction {
        let identity = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        let decision = DecisionOutcome {
            expected_loss: vec![ExpectedLoss {
                action: Action::Pause,
                loss: 1.0,
            }],
            optimal_action: Action::Pause,
            sprt_boundary: None,
            posterior_odds_abandoned_vs_useful: None,
            recovery_expectations: None,
            rationale: crate::decision::DecisionRationale {
                chosen_action: Action::Pause,
                tie_break: false,
                disabled_actions: vec![],
                used_recovery_preference: false,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            risk_sensitive: None,
            dro: None,
        };
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            candidates: vec![DecisionCandidate {
                identity,
                ppid: None,
                decision,
                blocked_reasons: vec![],
                stage_pause_before_kill: false,
                process_state: None,
                parent_identity: None,
                d_state_diagnostics: None,
            }],
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
        };
        let plan = generate_plan(&bundle);
        plan.actions[0].clone()
    }

    #[test]
    fn shared_cgroup_members_counts_others() {
        assert_eq!(shared_cgroup_members("123\n", 123).unwrap(), 0);
        assert_eq!(shared_cgroup_members("123\n456\n789\n", 123).unwrap(), 2);
        assert_eq!(shared_cgroup_members("123\n123\n", 123).unwrap(), 0);
        for invalid in ["", "456\n", "123\ninvalid\n", "123\n0\n"] {
            assert!(shared_cgroup_members(invalid, 123).is_err());
        }
    }

    #[test]
    fn composite_runner_keep_is_ok() {
        let mut action = make_action();
        action.action = Action::Keep;
        let runner = CompositeActionRunner::with_defaults();
        assert!(runner.execute(&action).is_ok());
        assert!(runner.verify(&action).is_ok());
    }

    #[test]
    fn composite_runner_restart_requires_supervisor() {
        let mut action = make_action();
        action.action = Action::Restart;
        let runner = CompositeActionRunner::with_defaults();
        let err = runner.execute(&action).expect_err("expected error");
        assert!(format!("{:?}", err).contains("restart requires supervisor support"));
    }

    #[test]
    fn composite_runner_default_trait() {
        let runner = CompositeActionRunner::default();
        let mut action = make_action();
        action.action = Action::Keep;
        assert!(runner.execute(&action).is_ok());
    }

    #[test]
    fn composite_runner_verify_keep() {
        let runner = CompositeActionRunner::with_defaults();
        let mut action = make_action();
        action.action = Action::Keep;
        assert!(runner.verify(&action).is_ok());
    }

    #[test]
    fn composite_runner_verify_restart() {
        let runner = CompositeActionRunner::with_defaults();
        let mut action = make_action();
        action.action = Action::Restart;
        // verify for restart is Ok (no verification needed)
        assert!(runner.verify(&action).is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn composite_runner_freeze_not_supported_non_linux() {
        let runner = CompositeActionRunner::with_defaults();
        let mut action = make_action();
        action.action = Action::Freeze;
        let err = runner.execute(&action).expect_err("expected error");
        assert!(format!("{:?}", err).contains("not supported"));
    }

    #[test]
    fn composite_runner_debug_impl() {
        let runner = CompositeActionRunner::with_defaults();
        let dbg = format!("{:?}", runner);
        assert!(dbg.contains("CompositeActionRunner"));
    }
}
