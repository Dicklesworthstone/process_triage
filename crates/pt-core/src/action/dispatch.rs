//! Composite action runner that dispatches to specialized runners.

use super::executor::{ActionError, ActionRunner};
use crate::decision::Action;
use crate::plan::PlanAction;

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
fn ensure_exclusive_cgroup(pid: u32) -> Result<(), ActionError> {
    let path = crate::collect::collect_cgroup_details(pid)
        .and_then(|d| d.unified_path)
        .ok_or_else(|| ActionError::Failed(format!("cannot resolve cgroup of pid {pid}")))?;
    let procs_file = format!("/sys/fs/cgroup{path}/cgroup.procs");
    let content = std::fs::read_to_string(&procs_file)
        .map_err(|e| ActionError::Failed(format!("cannot read {procs_file}: {e}")))?;
    let others = shared_cgroup_members(&content, pid);
    if others > 0 {
        return Err(ActionError::Failed(format!(
            "refusing: cgroup {path} is shared with {others} other process(es) and would \
             affect them all (leaf-cgroup isolation not implemented)"
        )));
    }
    Ok(())
}

/// Number of processes other than `pid` listed in `cgroup.procs` content.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn shared_cgroup_members(procs_content: &str, pid: u32) -> usize {
    procs_content
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .filter(|p| *p != pid)
        .count()
}

impl ActionRunner for CompositeActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        #[cfg(target_os = "linux")]
        if matches!(
            action.action,
            Action::Freeze | Action::Throttle | Action::Quarantine
        ) {
            ensure_exclusive_cgroup(action.target.pid.0)?;
        }
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
        assert_eq!(shared_cgroup_members("123\n", 123), 0);
        assert_eq!(shared_cgroup_members("123\n456\n789\n", 123), 2);
        assert_eq!(shared_cgroup_members("", 123), 0);
        assert_eq!(shared_cgroup_members("456\n", 123), 1);
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
