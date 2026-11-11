//! Composite action runner that dispatches to specialized runners.

use super::executor::{ActionError, ActionRunner};
use crate::collect::ProcessState;
use crate::decision::{Action, ActionFeasibility, DisabledAction};
use crate::plan::{ActionRouting, PlanAction};
use pt_common::ProcessIdentity;
use std::{path::PathBuf, sync::Arc};

use super::renice::ReniceActionRunner;
use super::reversal::ReversalJournal;
use super::signal::SignalActionRunner;

#[cfg(target_os = "linux")]
use super::cgroup_throttle::CpuThrottleActionRunner;
#[cfg(target_os = "linux")]
use super::cpuset_quarantine::CpusetQuarantineActionRunner;
#[cfg(target_os = "linux")]
use super::freeze::FreezeActionRunner;
#[cfg(target_os = "linux")]
use super::memory_cap::MemoryCapActionRunner;

/// Dispatches actions to the appropriate runner implementation.
#[derive(Debug)]
pub struct CompositeActionRunner {
    signal: SignalActionRunner,
    renice: ReniceActionRunner,
    #[cfg(target_os = "linux")]
    supervisor_restart_attempted: std::cell::Cell<bool>,
    #[cfg(target_os = "linux")]
    freeze: FreezeActionRunner,
    #[cfg(target_os = "linux")]
    throttle: CpuThrottleActionRunner,
    #[cfg(target_os = "linux")]
    memory_cap: MemoryCapActionRunner,
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
            supervisor_restart_attempted: std::cell::Cell::new(false),
            #[cfg(target_os = "linux")]
            freeze: FreezeActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            throttle: CpuThrottleActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            memory_cap: MemoryCapActionRunner::with_defaults(),
            #[cfg(target_os = "linux")]
            quarantine: CpusetQuarantineActionRunner::with_defaults(),
        }
    }

    /// Capture durable restoration receipts at the actual control writes.
    /// The journal binds renice, freeze, throttle and quarantine to the saved plan.
    pub fn with_reversal_journal(self, journal: Arc<ReversalJournal>) -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut runner = self;
            runner.renice = runner.renice.with_reversal_journal(Arc::clone(&journal));
            runner.freeze = runner.freeze.with_reversal_journal(Arc::clone(&journal));
            runner.throttle = runner.throttle.with_reversal_journal(Arc::clone(&journal));
            runner.memory_cap = runner
                .memory_cap
                .with_reversal_journal(Arc::clone(&journal));
            runner.quarantine = runner.quarantine.with_reversal_journal(journal);
            runner
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = journal;
            self
        }
    }

    /// Keep unjournaled writers from superseding an unresolved durable undo.
    /// This guard reads ownership evidence but does not create reversal receipts.
    pub fn with_reversal_ownership_guard(self, sessions_root: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut runner = self;
            runner.renice = runner
                .renice
                .with_reversal_ownership_guard(sessions_root.clone());
            runner.freeze = runner
                .freeze
                .with_reversal_ownership_guard(sessions_root.clone());
            runner.throttle = runner
                .throttle
                .with_reversal_ownership_guard(sessions_root.clone());
            runner.quarantine = runner
                .quarantine
                .with_reversal_ownership_guard(sessions_root);
            runner
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = sessions_root;
            self
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

    /// A manager-changing command may outlive a timed-out systemctl client.
    /// Charge such attempts conservatively without claiming a signal was sent.
    pub fn take_supervisor_restart_attempted(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.supervisor_restart_attempted.replace(false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Default for CompositeActionRunner {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// State and runtime capabilities used before expected-loss minimization.
///
/// A capability is an observation, not authorization: execution still repeats
/// identity, ownership, isolation and controller checks. Probing never writes
/// controller values, creates a cgroup, or moves a process.
pub fn planning_action_feasibility(
    target: &ProcessIdentity,
    state: ProcessState,
) -> ActionFeasibility {
    planning_action_feasibility_with_restart(target, state, None)
}

/// Reuse the binding already observed for this exact scan incarnation. No
/// implicit supervisor probing or service operation happens in this function.
pub fn planning_action_feasibility_with_restart(
    target: &ProcessIdentity,
    state: ProcessState,
    supervisor_restart: Option<&super::supervisor::SystemdUserServiceBinding>,
) -> ActionFeasibility {
    let mut feasibility =
        ActionFeasibility::from_process_state(state.is_zombie(), state.is_disksleep(), None);
    let bound_user_restart = !state.is_zombie()
        && supervisor_restart.is_some_and(|binding| binding.matches_target(target));
    if bound_user_restart {
        // A supervised service is eligible only for its reviewed manager route.
        // Do not let minimization select an unavailable cheaper raw intervention
        // and hide a supported restart behind a later policy refusal.
        for action in [
            Action::Kill,
            Action::Renice,
            Action::Pause,
            Action::Resume,
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::CapMemory,
            Action::Quarantine,
            Action::Unquarantine,
        ] {
            feasibility.disabled.push(DisabledAction {
                action,
                reason: "supervised service requires its verified manager restart route"
                    .to_string(),
            });
        }
        return feasibility;
    }
    if !state.is_zombie() {
        feasibility.disabled.push(DisabledAction {
            action: Action::Restart,
            reason:
                "restart requires a verified current-user service binding or zombie-parent reaping"
                    .to_string(),
        });
    }
    feasibility.disabled.push(DisabledAction {
        action: Action::Unquarantine,
        reason: "unquarantine requires the recorded previous cpuset; use reversal metadata"
            .to_string(),
    });
    #[cfg(target_os = "linux")]
    {
        // Preserve the zombie-parent reaping route without probing controllers
        // for a dead child. Its direct interventions are already excluded.
        if !state.is_zombie() {
            feasibility = feasibility.merge(&cgroup_action_feasibility(target));
            if feasibility.is_allowed(Action::CapMemory) {
                if let Err(error) = super::memory_cap::plan_memory_cap(target) {
                    feasibility.disabled.push(DisabledAction {
                        action: Action::CapMemory,
                        reason: error.to_string(),
                    });
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        feasibility = feasibility.merge(&unavailable_cgroup_actions(
            "cgroup actions require the Linux cgroup runner".to_string(),
        ));
    }
    feasibility
}

fn unavailable_cgroup_actions(reason: String) -> ActionFeasibility {
    ActionFeasibility {
        disabled: [
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::CapMemory,
            Action::Quarantine,
            Action::Unquarantine,
        ]
        .into_iter()
        .map(|action| DisabledAction {
            action,
            reason: reason.clone(),
        })
        .collect(),
    }
}

/// Reuse one identity/membership inspection for all cgroup capabilities. The
/// public availability helpers use these same facts rather than mode-bit guesses.
#[cfg(target_os = "linux")]
pub(super) fn cgroup_action_feasibility(target: &ProcessIdentity) -> ActionFeasibility {
    let inspect = || -> Result<ActionFeasibility, ActionError> {
        let comm = ensure_cgroup_identity(target)?;
        let pid = target.pid.0;
        let details = crate::collect::collect_cgroup_details(pid)
            .ok_or_else(|| ActionError::Failed(format!("cannot read cgroup of pid {pid}")))?;
        let path = details.unified_path.as_deref().ok_or_else(|| {
            ActionError::Failed("an isolated unified cgroup is required by the runner".to_string())
        })?;
        let directory = std::path::PathBuf::from(format!("/sys/fs/cgroup{path}"));
        let cpu_v1 = details
            .v1_paths
            .get("cpu")
            .map(|path| std::path::PathBuf::from(format!("/sys/fs/cgroup/cpu{path}")));
        let cpuset_v1 = details
            .v1_paths
            .get("cpuset")
            .map(|path| std::path::PathBuf::from(format!("/sys/fs/cgroup/cpuset{path}")));
        let feasibility = cgroup_action_feasibility_at(
            pid,
            &comm,
            &directory,
            cpu_v1.as_deref(),
            cpuset_v1.as_deref(),
        );

        // Do not combine controller facts from different incarnations or
        // memberships. Parse membership alone instead of walking limits again.
        let source = format!("/proc/{pid}/cgroup");
        let content = std::fs::read_to_string(&source)
            .map_err(|error| ActionError::Failed(format!("cannot recheck {source}: {error}")))?;
        let observed = crate::collect::collect_cgroup_from_content(&content, &source, None)
            .ok_or_else(|| ActionError::Failed("cannot recheck cgroup membership".to_string()))?;
        if observed.unified_path != details.unified_path || observed.v1_paths != details.v1_paths {
            return Err(ActionError::Failed(
                "cgroup membership changed during capability inspection".to_string(),
            ));
        }
        let current = read_cgroup_identity(pid).ok_or(ActionError::IdentityMismatch)?;
        if !target.matches(&current) {
            return Err(ActionError::IdentityMismatch);
        }
        Ok(feasibility)
    };
    inspect().unwrap_or_else(|error| unavailable_cgroup_actions(error.to_string()))
}

#[cfg(target_os = "linux")]
fn cgroup_action_feasibility_at(
    pid: u32,
    comm: &str,
    directory: &std::path::Path,
    cpu_v1: Option<&std::path::Path>,
    cpuset_v1: Option<&std::path::Path>,
) -> ActionFeasibility {
    if let Err(error) = ensure_exclusive_cgroup_path(pid, directory) {
        return unavailable_cgroup_actions(error.to_string());
    }
    let mut disabled = Vec::new();
    if let Err(error) = super::freeze::check_freeze_capability(directory) {
        for action in [Action::Freeze, Action::Unfreeze] {
            disabled.push(DisabledAction {
                action,
                reason: error.to_string(),
            });
        }
    }
    for (action, observation) in [
        (
            Action::Throttle,
            super::cgroup_throttle::check_throttle_capability(pid, directory, cpu_v1),
        ),
        (
            Action::Quarantine,
            super::cpuset_quarantine::check_quarantine_capability(pid, comm, directory, cpuset_v1),
        ),
    ] {
        if let Err(error) = observation {
            disabled.push(DisabledAction {
                action,
                reason: error.to_string(),
            });
        }
    }
    ActionFeasibility { disabled }
}

/// Ask the kernel about effective read/write access, including ACLs and read-only
/// mounts. Open without create, truncate, or a write; callers separately parse
/// the observed controller contents. Metadata write bits alone do not establish
/// that this caller can operate another owner's controller.
#[cfg(target_os = "linux")]
pub(super) fn check_controller_access(path: &std::path::Path) -> Result<(), ActionError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            ActionError::Failed(format!(
                "controller {} requires read/write access: {error}",
                path.display()
            ))
        })?;
    if !file
        .metadata()
        .map_err(|error| {
            ActionError::Failed(format!("cannot inspect {}: {error}", path.display()))
        })?
        .is_file()
    {
        return Err(ActionError::Failed(format!(
            "controller {} is not a regular control file",
            path.display()
        )));
    }
    Ok(())
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
    ensure_cgroup_identity(target)?;
    ensure_exclusive_cgroup(target.pid.0)
}

/// Common identity/ownership/infrastructure checks; return the observed command
/// name for runner-specific protection checks during capability inspection.
#[cfg(target_os = "linux")]
fn ensure_cgroup_identity(target: &pt_common::ProcessIdentity) -> Result<String, ActionError> {
    super::signal::ensure_action_pid_namespace()?;
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
    Ok(comm.trim().to_string())
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
        if action.action != Action::Keep {
            super::signal::ensure_action_pid_namespace()?;
        }
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
            Action::CapMemory => self.memory_cap.execute(action),
            #[cfg(target_os = "linux")]
            Action::Quarantine | Action::Unquarantine => self.quarantine.execute(action),
            // A zombie's remedy targets its parent: nudge it to reap. (A real
            // restart of the parent needs supervisor support, bd-qr40.6.)
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::Restart if action.routing == ActionRouting::ZombieToParent => {
                self.signal.nudge_parent_to_reap(action)
            }
            #[cfg(target_os = "linux")]
            Action::Restart if action.routing == ActionRouting::Supervisor => {
                super::supervisor::execute_systemd_user_restart(action, || {
                    self.supervisor_restart_attempted.set(true)
                })
            }
            Action::Restart => Err(ActionError::Failed(
                "restart requires supervisor support".to_string(),
            )),
            #[cfg(not(target_os = "linux"))]
            Action::Freeze
            | Action::Unfreeze
            | Action::Throttle
            | Action::CapMemory
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
            Action::CapMemory => self.memory_cap.verify(action),
            #[cfg(target_os = "linux")]
            Action::Quarantine | Action::Unquarantine => self.quarantine.verify(action),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::Restart if action.routing == ActionRouting::ZombieToParent => {
                self.signal.verify_zombie_reaped(action)
            }
            #[cfg(target_os = "linux")]
            Action::Restart if action.routing == ActionRouting::Supervisor => {
                super::supervisor::verify_systemd_user_restart(action)
            }
            Action::Restart => Err(ActionError::Failed(
                "restart verification requires a supported supervisor or zombie-parent route"
                    .to_string(),
            )),
            #[cfg(not(target_os = "linux"))]
            Action::Freeze
            | Action::Unfreeze
            | Action::Throttle
            | Action::CapMemory
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
                supervisor_restart: None,
                memory_cap: None,
            }],
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
        };
        let plan = generate_plan(&bundle);
        plan.actions[0].clone()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervised_feasibility_offers_only_keep_or_the_bound_restart() {
        let mut target = make_action().target;
        // SAFETY: geteuid only reads the test process's credentials.
        target.uid = unsafe { libc::geteuid() };
        let uid = target.uid;
        let binding = super::super::supervisor::SystemdUserServiceBinding {
            target: target.clone(),
            unit: "worker-proof.service".into(),
            control_group: format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/worker-proof.service"
            ),
            invocation_id: "1234567890abcdef1234567890abcdef".into(),
        };
        let feasible = planning_action_feasibility_with_restart(
            &target,
            ProcessState::Running,
            Some(&binding),
        );
        assert!(feasible.is_allowed(Action::Keep));
        assert!(feasible.is_allowed(Action::Restart));
        for action in [
            Action::Kill,
            Action::Renice,
            Action::Pause,
            Action::Resume,
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::Quarantine,
            Action::Unquarantine,
        ] {
            assert!(!feasible.is_allowed(action), "{action:?}");
        }
        let mut replaced = target;
        replaced.pid = ProcessId(u32::MAX);
        let feasible = planning_action_feasibility_with_restart(
            &replaced,
            ProcessState::Running,
            Some(&binding),
        );
        assert!(!feasible.is_allowed(Action::Restart));
    }

    #[test]
    fn planning_feasibility_preserves_zombie_routing_and_state_constraints() {
        let mut target = make_action().target;
        target.pid = ProcessId(u32::MAX);
        let live = planning_action_feasibility(&target, ProcessState::Running);
        assert!(!live.is_allowed(Action::Restart));
        assert!(live.is_allowed(Action::Keep));
        for action in [Action::Freeze, Action::Throttle, Action::Quarantine] {
            assert!(!live.is_allowed(action));
            assert!(live
                .disabled
                .iter()
                .any(|disabled| disabled.action == action && !disabled.reason.is_empty()));
        }
        let zombie = planning_action_feasibility(&target, ProcessState::Zombie);
        assert!(zombie.is_allowed(Action::Restart));
        assert!(zombie.is_allowed(Action::Keep));
        for action in [
            Action::Kill,
            Action::Pause,
            Action::Renice,
            Action::Freeze,
            Action::Throttle,
            Action::Quarantine,
            Action::Unquarantine,
        ] {
            assert!(!zombie.is_allowed(action));
        }
        assert!(
            !planning_action_feasibility(&target, ProcessState::DiskSleep).is_allowed(Action::Kill)
        );
    }

    #[test]
    fn planning_reoptimizes_without_unavailable_actions_even_under_pressure() {
        use crate::decision::load_aware::{
            prepare_pressure_decision, PressureContext, ResourceShares,
        };
        use crate::decision::pressure_regime::ResourceSeverity;
        use crate::inference::ClassScores;

        let mut target = make_action().target;
        target.pid = ProcessId(u32::MAX);
        let feasibility = planning_action_feasibility(&target, ProcessState::Running);
        let mut policy = Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.pressure.kappa = 1.0;
        for row in [
            &mut policy.loss_matrix.useful,
            &mut policy.loss_matrix.useful_bad,
            &mut policy.loss_matrix.abandoned,
            &mut policy.loss_matrix.zombie,
        ] {
            row.keep = 10.0;
            row.pause = Some(6.0);
            row.throttle = Some(0.0);
            row.restart = Some(0.0);
            row.renice = Some(5.0);
            row.kill = 100.0;
        }
        let posterior = ClassScores {
            useful: 0.0,
            useful_bad: 1.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        assert_eq!(
            crate::decision::decide_action(&posterior, &policy, &ActionFeasibility::allow_all())
                .unwrap()
                .optimal_action,
            Action::Throttle
        );
        for cpu_pressure in [0.0, 1.0] {
            let context = PressureContext {
                severity: ResourceSeverity {
                    cpu: cpu_pressure,
                    ..ResourceSeverity::default()
                },
                shares: ResourceShares {
                    cpu: Some(1.0),
                    ..ResourceShares::default()
                },
                unavailable: Vec::new(),
            };
            let prepared =
                prepare_pressure_decision(&posterior, &policy, &feasibility, &context).unwrap();
            assert_eq!(prepared.decision.optimal_action, Action::Renice);
            for action in [
                Action::Freeze,
                Action::Throttle,
                Action::Quarantine,
                Action::Restart,
            ] {
                assert!(!prepared.feasibility.is_allowed(action));
                assert!(!prepared
                    .decision
                    .expected_loss
                    .iter()
                    .any(|loss| loss.action == action));
                assert!(prepared
                    .decision
                    .rationale
                    .disabled_actions
                    .iter()
                    .any(|disabled| disabled.action == action && !disabled.reason.is_empty()));
            }
        }
    }

    #[cfg(target_os = "linux")]
    const CAPABILITY_FILES: [(&str, &str); 6] = [
        ("cgroup.procs", "123\n"),
        ("cgroup.freeze", "0\n"),
        ("cgroup.events", "populated 1\nfrozen 0\n"),
        ("cpu.max", "max 100000\n"),
        ("cpuset.cpus", "\n"),
        ("cpuset.cpus.effective", "2-3,8\n"),
    ];

    #[cfg(target_os = "linux")]
    fn capability_leaf(omit: &[&str]) -> std::path::PathBuf {
        let directory = tempfile::tempdir().unwrap().keep();
        for (name, content) in CAPABILITY_FILES {
            if !omit.contains(&name) {
                std::fs::write(directory.join(name), content).unwrap();
            }
        }
        directory
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_probe_is_read_only_and_respects_runner_protections() {
        let directory = capability_leaf(&[]);
        let observed = cgroup_action_feasibility_at(123, "worker", &directory, None, None);
        for action in [
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::Quarantine,
        ] {
            assert!(
                observed.is_allowed(action),
                "{action:?}: {:?}",
                observed.disabled
            );
        }
        for (name, content) in CAPABILITY_FILES {
            assert_eq!(
                std::fs::read_to_string(directory.join(name)).unwrap(),
                content
            );
        }
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            CAPABILITY_FILES.len()
        );
        let protected = cgroup_action_feasibility_at(123, "dockerd", &directory, None, None);
        assert!(!protected.is_allowed(Action::Quarantine));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_probe_requires_complete_exclusive_leaf_membership() {
        for members in ["123\n456\n", "456\n", "", "123\ninvalid\n"] {
            let directory = capability_leaf(&[]);
            std::fs::write(directory.join("cgroup.procs"), members).unwrap();
            let observed = cgroup_action_feasibility_at(123, "worker", &directory, None, None);
            for action in [Action::Freeze, Action::Throttle, Action::Quarantine] {
                assert!(!observed.is_allowed(action), "{members:?}: {action:?}");
            }
        }
        let directory = capability_leaf(&[]);
        std::fs::create_dir(directory.join("descendant")).unwrap();
        let observed = cgroup_action_feasibility_at(123, "worker", &directory, None, None);
        assert!(observed
            .disabled
            .iter()
            .all(|disabled| disabled.reason.contains("descendants")));
        let absent = capability_leaf(&["cgroup.procs"]);
        let observed = cgroup_action_feasibility_at(123, "worker", &absent, None, None);
        assert!(!observed.is_allowed(Action::Throttle));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_or_malformed_controller_disables_only_its_actions() {
        for (name, action) in [
            ("cgroup.freeze", Action::Freeze),
            ("cgroup.events", Action::Freeze),
            ("cpu.max", Action::Throttle),
            ("cpuset.cpus", Action::Quarantine),
            ("cpuset.cpus.effective", Action::Quarantine),
        ] {
            let directory = capability_leaf(&[name]);
            let observed = cgroup_action_feasibility_at(123, "worker", &directory, None, None);
            for checked in [Action::Freeze, Action::Throttle, Action::Quarantine] {
                assert_eq!(
                    observed.is_allowed(checked),
                    checked != action,
                    "{name}: {checked:?}"
                );
            }
            assert!(
                !directory.join(name).exists(),
                "capability probe created {name}"
            );
        }
        for (name, value, action) in [
            ("cgroup.events", "populated 1\n", Action::Freeze),
            ("cpu.max", "invalid quota\n", Action::Throttle),
            ("cpuset.cpus.effective", "\n", Action::Quarantine),
        ] {
            let directory = capability_leaf(&[]);
            std::fs::write(directory.join(name), value).unwrap();
            let observed = cgroup_action_feasibility_at(123, "worker", &directory, None, None);
            for checked in [Action::Freeze, Action::Throttle, Action::Quarantine] {
                assert_eq!(
                    observed.is_allowed(checked),
                    checked != action,
                    "{name}: {checked:?}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hybrid_capabilities_check_the_selected_hierarchy_and_do_not_hide_v2_failures() {
        let unified = capability_leaf(&["cpu.max", "cpuset.cpus"]);
        let cpu_v1 = capability_leaf(&[]);
        let cpuset_v1 = capability_leaf(&[]);
        std::fs::write(cpu_v1.join("cpu.cfs_quota_us"), "-1\n").unwrap();
        std::fs::write(cpu_v1.join("cpu.cfs_period_us"), "100000\n").unwrap();
        std::fs::write(cpuset_v1.join("cpuset.effective_cpus"), "4-5\n").unwrap();
        let observe = || {
            cgroup_action_feasibility_at(123, "worker", &unified, Some(&cpu_v1), Some(&cpuset_v1))
        };
        let available = observe();
        assert!(available.is_allowed(Action::Throttle));
        assert!(available.is_allowed(Action::Quarantine));

        std::fs::write(cpu_v1.join("cgroup.procs"), "123\n456\n").unwrap();
        std::fs::write(cpuset_v1.join("cgroup.procs"), "456\n").unwrap();
        let unsafe_fallback = observe();
        assert!(!unsafe_fallback.is_allowed(Action::Throttle));
        assert!(!unsafe_fallback.is_allowed(Action::Quarantine));
        assert!(unsafe_fallback.is_allowed(Action::Freeze));

        std::fs::write(cpu_v1.join("cgroup.procs"), "123\n").unwrap();
        std::fs::write(cpuset_v1.join("cgroup.procs"), "123\n").unwrap();
        std::fs::write(unified.join("cpu.max"), "invalid quota\n").unwrap();
        std::fs::write(unified.join("cpuset.cpus"), "invalid CPUs\n").unwrap();
        let broken_v2 = observe();
        assert!(!broken_v2.is_allowed(Action::Throttle));
        assert!(!broken_v2.is_allowed(Action::Quarantine));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn controller_capability_uses_effective_access() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;

        const CHILD_FLAG: &str = "PT_CAPABILITY_ACCESS_CHILD";
        if let Some(path) = std::env::var_os(CHILD_FLAG) {
            assert!(check_controller_access(std::path::Path::new(&path)).is_err());
            eprintln!("effective-controller-access-refused");
            return;
        }
        let directory = capability_leaf(&[]);
        let path = directory.join("cpu.max");
        assert!(check_controller_access(&path).is_ok());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Writable mode bits exist, but the owning user has no read/write access.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o020)).unwrap();
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
        // SAFETY: geteuid only reads the current effective user ID.
        if unsafe { libc::geteuid() } == 0 {
            // Drop privileges in a child, never in the shared test process.
            let output = std::process::Command::new("/proc/self/exe")
                .args([
                    "--exact",
                    "action::dispatch::tests::controller_capability_uses_effective_access",
                    "--nocapture",
                ])
                .env(CHILD_FLAG, &path)
                .gid(65534)
                .uid(65534)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("effective-controller-access-refused"));
        } else {
            assert!(check_controller_access(&path).is_err());
        }
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
