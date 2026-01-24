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

impl ActionRunner for CompositeActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
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
}
