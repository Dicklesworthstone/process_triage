//! Expected loss decisioning and SPRT-style boundary computation.

use crate::config::policy::{LossMatrix, LossRow, Policy};
use crate::config::priors::Priors;
use crate::decision::causal_interventions::{expected_recovery_by_action, RecoveryExpectation};
use crate::inference::ClassScores;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported actions for early decisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Keep,
    Renice,
    Pause,
    /// Resume a previously paused process (follow-up to Pause, not a decision action).
    Resume,
    /// Freeze process via cgroup v2 freezer (more robust than SIGSTOP).
    Freeze,
    /// Unfreeze a previously frozen process (follow-up to Freeze, not a decision action).
    Unfreeze,
    Throttle,
    Restart,
    Kill,
}

impl Action {
    /// Actions available for decision-making (excludes Resume/Unfreeze, which are follow-up actions).
    const ALL: [Action; 7] = [
        Action::Keep,
        Action::Renice,
        Action::Pause,
        Action::Freeze,
        Action::Throttle,
        Action::Restart,
        Action::Kill,
    ];

    fn tie_break_rank(&self) -> u8 {
        match self {
            Action::Keep => 0,
            Action::Renice => 1,
            Action::Pause => 2,
            Action::Resume => 2,    // Same rank as Pause (both reversible)
            Action::Freeze => 2,    // Same rank as Pause (cgroup-level pause)
            Action::Unfreeze => 2,  // Same rank as Freeze (both reversible)
            Action::Throttle => 3,
            Action::Restart => 4,
            Action::Kill => 5,
        }
    }

    /// Returns true if this is an action that can be reversed.
    pub fn is_reversible(&self) -> bool {
        matches!(
            self,
            Action::Pause
                | Action::Resume
                | Action::Freeze
                | Action::Unfreeze
                | Action::Renice
                | Action::Throttle
        )
    }

    /// Returns true if this is a follow-up action (not a decision action).
    pub fn is_follow_up(&self) -> bool {
        matches!(self, Action::Resume | Action::Unfreeze)
    }
}

/// Disabled action with a reason string.
#[derive(Debug, Clone, Serialize)]
pub struct DisabledAction {
    pub action: Action,
    pub reason: String,
}

/// Feasibility mask for actions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ActionFeasibility {
    pub disabled: Vec<DisabledAction>,
}

impl ActionFeasibility {
    pub fn allow_all() -> Self {
        Self {
            disabled: Vec::new(),
        }
    }

    /// Create feasibility mask based on process state constraints.
    ///
    /// This function applies fundamental OS-level constraints:
    ///
    /// **Zombie (Z) processes:**
    /// - Cannot be killed (they're already dead, only parent can reap)
    /// - Cannot be paused/resumed/frozen (no running code to stop)
    /// - Disables: Kill, Pause, Resume, Freeze, Unfreeze
    ///
    /// **D-state (uninterruptible sleep) processes:**
    /// - May not respond to SIGKILL (stuck in kernel I/O)
    /// - Kill action has low probability of success
    /// - Disables: Kill (with wchan diagnostic if available)
    ///
    /// # Arguments
    /// * `is_zombie` - true if process is in Z state
    /// * `is_disksleep` - true if process is in D state
    /// * `wchan` - optional kernel wait channel (what D-state is blocked on)
    pub fn from_process_state(is_zombie: bool, is_disksleep: bool, wchan: Option<&str>) -> Self {
        let mut disabled = Vec::new();

        if is_zombie {
            // Zombie processes cannot receive signals - they're already dead
            disabled.push(DisabledAction {
                action: Action::Kill,
                reason: "zombie process (Z state): already dead, cannot be killed - \
                         only parent can reap it"
                    .to_string(),
            });
            disabled.push(DisabledAction {
                action: Action::Pause,
                reason: "zombie process (Z state): cannot pause a dead process".to_string(),
            });
            disabled.push(DisabledAction {
                action: Action::Resume,
                reason: "zombie process (Z state): cannot resume a dead process".to_string(),
            });
            disabled.push(DisabledAction {
                action: Action::Freeze,
                reason: "zombie process (Z state): cannot freeze a dead process".to_string(),
            });
            disabled.push(DisabledAction {
                action: Action::Unfreeze,
                reason: "zombie process (Z state): cannot unfreeze a dead process".to_string(),
            });
            // Note: Restart might work if it targets the parent/supervisor,
            // but that's handled at a higher level (zombie routing)
        }

        if is_disksleep && !is_zombie {
            // D-state processes may ignore SIGKILL while in kernel I/O
            let reason = match wchan {
                Some(w) => format!(
                    "D-state process (uninterruptible sleep): blocked in kernel at '{}' - \
                     kill action is unreliable and may fail",
                    w
                ),
                None => "D-state process (uninterruptible sleep): blocked in kernel I/O - \
                         kill action is unreliable and may fail"
                    .to_string(),
            };
            disabled.push(DisabledAction {
                action: Action::Kill,
                reason,
            });
        }

        Self { disabled }
    }

    /// Merge two feasibility masks, combining their disabled actions.
    pub fn merge(&self, other: &ActionFeasibility) -> Self {
        let mut disabled = self.disabled.clone();
        for d in &other.disabled {
            if !disabled.iter().any(|existing| existing.action == d.action) {
                disabled.push(d.clone());
            }
        }
        Self { disabled }
    }

    pub fn is_allowed(&self, action: Action) -> bool {
        !self.disabled.iter().any(|d| d.action == action)
    }
}

/// Expected loss for an action.
#[derive(Debug, Clone, Serialize)]
pub struct ExpectedLoss {
    pub action: Action,
    pub loss: f64,
}

/// SPRT-style boundary information.
#[derive(Debug, Clone, Serialize)]
pub struct SprtBoundary {
    pub log_odds_threshold: f64,
    pub numerator: f64,
    pub denominator: f64,
}

/// Decision rationale summary.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionRationale {
    pub chosen_action: Action,
    pub tie_break: bool,
    pub disabled_actions: Vec<DisabledAction>,
    pub used_recovery_preference: bool,
}

/// Decision output for a single candidate.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionOutcome {
    pub expected_loss: Vec<ExpectedLoss>,
    pub optimal_action: Action,
    pub sprt_boundary: Option<SprtBoundary>,
    pub posterior_odds_abandoned_vs_useful: Option<f64>,
    pub recovery_expectations: Option<Vec<RecoveryExpectation>>,
    pub rationale: DecisionRationale,
}

/// Errors raised during decisioning.
#[derive(Debug, Error)]
pub enum DecisionError {
    #[error("invalid posterior: {message}")]
    InvalidPosterior { message: String },
    #[error("missing loss entry for action {action:?} in class {class}")]
    MissingLoss { action: Action, class: &'static str },
    #[error("no feasible actions after applying constraints")]
    NoFeasibleActions,
    #[error("invalid loss matrix: {message}")]
    InvalidLossMatrix { message: String },
}

/// Compute expected loss, optimal action, and SPRT boundary.
pub fn decide_action(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
) -> Result<DecisionOutcome, DecisionError> {
    validate_posterior(posterior)?;

    let mut expected_losses = Vec::new();
    let mut disabled = feasibility.disabled.clone();

    for action in Action::ALL {
        if !feasibility.is_allowed(action) {
            continue;
        }
        match expected_loss_for_action(action, posterior, &policy.loss_matrix) {
            Ok(loss) => expected_losses.push(ExpectedLoss { action, loss }),
            Err(DecisionError::MissingLoss { action, class }) => {
                disabled.push(DisabledAction {
                    action,
                    reason: format!("policy missing loss for class {class}"),
                });
            }
            Err(err) => return Err(err),
        }
    }

    if expected_losses.is_empty() {
        return Err(DecisionError::NoFeasibleActions);
    }

    let (optimal_action, tie_break) = select_optimal_action(&expected_losses);

    let sprt_boundary = compute_sprt_boundary(&policy.loss_matrix)?;
    let posterior_odds = posterior_odds_abandoned_vs_useful(posterior);

    Ok(DecisionOutcome {
        expected_loss: expected_losses,
        optimal_action,
        sprt_boundary,
        posterior_odds_abandoned_vs_useful: posterior_odds,
        recovery_expectations: None,
        rationale: DecisionRationale {
            chosen_action: optimal_action,
            tie_break,
            disabled_actions: disabled,
            used_recovery_preference: false,
        },
    })
}

/// Compute expected loss and optionally prefer actions with higher recovery likelihood.
pub fn decide_action_with_recovery(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    priors: &Priors,
    loss_tolerance: f64,
) -> Result<DecisionOutcome, DecisionError> {
    validate_posterior(posterior)?;

    let mut expected_losses = Vec::new();
    let mut disabled = feasibility.disabled.clone();

    for action in Action::ALL {
        if !feasibility.is_allowed(action) {
            continue;
        }
        match expected_loss_for_action(action, posterior, &policy.loss_matrix) {
            Ok(loss) => expected_losses.push(ExpectedLoss { action, loss }),
            Err(DecisionError::MissingLoss { action, class }) => {
                disabled.push(DisabledAction {
                    action,
                    reason: format!("policy missing loss for class {class}"),
                });
            }
            Err(err) => return Err(err),
        }
    }

    if expected_losses.is_empty() {
        return Err(DecisionError::NoFeasibleActions);
    }

    let recovery_expectations = expected_recovery_by_action(priors, posterior);
    let (mut optimal_action, mut tie_break) = select_optimal_action(&expected_losses);
    let mut used_recovery_preference = false;
    if !recovery_expectations.is_empty() {
        let (candidate_action, used_recovery) = select_action_with_recovery(
            &expected_losses,
            &recovery_expectations,
            loss_tolerance.max(0.0),
            optimal_action,
        );
        if used_recovery {
            used_recovery_preference = true;
            if candidate_action != optimal_action {
                tie_break = true;
            }
            optimal_action = candidate_action;
        }
    }

    let sprt_boundary = compute_sprt_boundary(&policy.loss_matrix)?;
    let posterior_odds = posterior_odds_abandoned_vs_useful(posterior);

    Ok(DecisionOutcome {
        expected_loss: expected_losses,
        optimal_action,
        sprt_boundary,
        posterior_odds_abandoned_vs_useful: posterior_odds,
        recovery_expectations: if recovery_expectations.is_empty() {
            None
        } else {
            Some(recovery_expectations)
        },
        rationale: DecisionRationale {
            chosen_action: optimal_action,
            tie_break,
            disabled_actions: disabled,
            used_recovery_preference,
        },
    })
}

fn validate_posterior(posterior: &ClassScores) -> Result<(), DecisionError> {
    let values = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];
    if values
        .iter()
        .any(|v: &f64| v.is_nan() || v.is_infinite() || *v < 0.0)
    {
        return Err(DecisionError::InvalidPosterior {
            message: "posterior contains NaN/Inf or negative values".to_string(),
        });
    }
    let sum: f64 = values.iter().sum();
    if (sum - 1.0).abs() > 1e-6 {
        return Err(DecisionError::InvalidPosterior {
            message: format!("posterior does not sum to 1 (sum={sum:.6})"),
        });
    }
    Ok(())
}

fn expected_loss_for_action(
    action: Action,
    posterior: &ClassScores,
    loss_matrix: &LossMatrix,
) -> Result<f64, DecisionError> {
    let useful = loss_for_action(&loss_matrix.useful, action, "useful")?;
    let useful_bad = loss_for_action(&loss_matrix.useful_bad, action, "useful_bad")?;
    let abandoned = loss_for_action(&loss_matrix.abandoned, action, "abandoned")?;
    let zombie = loss_for_action(&loss_matrix.zombie, action, "zombie")?;

    Ok(posterior.useful * useful
        + posterior.useful_bad * useful_bad
        + posterior.abandoned * abandoned
        + posterior.zombie * zombie)
}

fn loss_for_action(
    row: &LossRow,
    action: Action,
    class: &'static str,
) -> Result<f64, DecisionError> {
    match action {
        Action::Keep => Ok(row.keep),
        Action::Pause => row
            .pause
            .ok_or(DecisionError::MissingLoss { action, class }),
        // Freeze uses Pause's loss value (semantically similar: both stop the process temporarily)
        Action::Freeze => row
            .pause
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Throttle => row
            .throttle
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Renice => row
            .renice
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Restart => row
            .restart
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Kill => Ok(row.kill),
        // Resume/Unfreeze are follow-up actions, not primary decisions, so no loss entry
        Action::Resume | Action::Unfreeze => Err(DecisionError::MissingLoss { action, class }),
    }
}

fn select_optimal_action(expected: &[ExpectedLoss]) -> (Action, bool) {
    let mut best = &expected[0];
    let mut tie_break = false;
    for cand in expected.iter().skip(1) {
        if cand.loss < best.loss {
            best = cand;
            tie_break = false;
        } else if (cand.loss - best.loss).abs() <= 1e-12 {
            if cand.action.tie_break_rank() < best.action.tie_break_rank() {
                best = cand;
                tie_break = true;
            } else {
                tie_break = true;
            }
        }
    }
    (best.action, tie_break)
}

fn select_action_with_recovery(
    expected: &[ExpectedLoss],
    recovery: &[RecoveryExpectation],
    loss_tolerance: f64,
    fallback: Action,
) -> (Action, bool) {
    let mut best_loss = f64::INFINITY;
    for cand in expected {
        if cand.loss < best_loss {
            best_loss = cand.loss;
        }
    }

    let mut best_recovery = -1.0;
    let mut best_action = None;
    for cand in expected {
        if cand.loss > best_loss + loss_tolerance {
            continue;
        }
        if let Some(prob) = recovery
            .iter()
            .find(|r| r.action == cand.action)
            .map(|r| r.probability)
        {
            if prob > best_recovery {
                best_recovery = prob;
                best_action = Some(cand.action);
            }
        }
    }

    match best_action {
        Some(action) => (action, true),
        None => (fallback, false),
    }
}

fn compute_sprt_boundary(loss_matrix: &LossMatrix) -> Result<Option<SprtBoundary>, DecisionError> {
    let l_kill_useful = loss_matrix.useful.kill;
    let l_keep_useful = loss_matrix.useful.keep;
    let l_keep_abandoned = loss_matrix.abandoned.keep;
    let l_kill_abandoned = loss_matrix.abandoned.kill;

    let numerator = l_kill_useful - l_keep_useful;
    let denominator = l_keep_abandoned - l_kill_abandoned;
    if numerator <= 0.0 || denominator <= 0.0 {
        return Ok(None);
    }
    let ratio = numerator / denominator;
    if ratio <= 0.0 || ratio.is_nan() || ratio.is_infinite() {
        return Err(DecisionError::InvalidLossMatrix {
            message: "invalid SPRT boundary ratio".to_string(),
        });
    }
    Ok(Some(SprtBoundary {
        log_odds_threshold: ratio.ln(),
        numerator,
        denominator,
    }))
}

fn posterior_odds_abandoned_vs_useful(posterior: &ClassScores) -> Option<f64> {
    if posterior.useful <= 0.0 || posterior.abandoned <= 0.0 {
        return None;
    }
    Some((posterior.abandoned / posterior.useful).ln())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::{LossMatrix, LossRow, Policy};
    use crate::config::priors::{
        BetaParams, CausalInterventions, ClassPriors, Classes, InterventionPriors, Priors,
    };

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    fn policy_for_tests() -> Policy {
        Policy::default()
    }

    #[test]
    fn expected_loss_matches_definition() {
        let policy = policy_for_tests();
        let posterior = ClassScores {
            useful: 0.5,
            useful_bad: 0.2,
            abandoned: 0.2,
            zombie: 0.1,
        };
        let outcome =
            decide_action(&posterior, &policy, &ActionFeasibility::allow_all()).expect("decision");
        let keep_loss = outcome
            .expected_loss
            .iter()
            .find(|e| e.action == Action::Keep)
            .unwrap()
            .loss;
        let expected = 0.5 * policy.loss_matrix.useful.keep
            + 0.2 * policy.loss_matrix.useful_bad.keep
            + 0.2 * policy.loss_matrix.abandoned.keep
            + 0.1 * policy.loss_matrix.zombie.keep;
        assert!(approx_eq(keep_loss, expected, 1e-12));
    }

    #[test]
    fn tie_break_prefers_reversible() {
        let mut policy = policy_for_tests();
        policy.loss_matrix = LossMatrix {
            useful: LossRow {
                keep: 1.0,
                renice: Some(1.0),
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            useful_bad: LossRow {
                keep: 1.0,
                renice: Some(1.0),
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            abandoned: LossRow {
                keep: 1.0,
                renice: Some(1.0),
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            zombie: LossRow {
                keep: 1.0,
                renice: Some(1.0),
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
        };
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let outcome =
            decide_action(&posterior, &policy, &ActionFeasibility::allow_all()).expect("decision");
        assert_eq!(outcome.optimal_action, Action::Keep);
        assert!(outcome.rationale.tie_break);
    }

    #[test]
    fn invalid_posterior_rejected() {
        let policy = policy_for_tests();
        let posterior = ClassScores {
            useful: 0.5,
            useful_bad: 0.5,
            abandoned: 0.2,
            zombie: -0.2,
        };
        let err = decide_action(&posterior, &policy, &ActionFeasibility::allow_all()).unwrap_err();
        match err {
            DecisionError::InvalidPosterior { .. } => {}
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn sprt_boundary_computed() {
        let policy = policy_for_tests();
        let boundary = compute_sprt_boundary(&policy.loss_matrix).expect("boundary");
        let boundary = boundary.expect("boundary");
        assert!(boundary.log_odds_threshold.is_finite());
    }

    #[test]
    fn recovery_preference_overrides_small_loss_gap() {
        let posterior = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };

        let loss_row = LossRow {
            keep: 0.98,
            renice: Some(0.99),
            pause: Some(1.0),
            throttle: Some(2.0),
            restart: Some(2.0),
            kill: 0.99,
        };
        let policy = Policy {
            loss_matrix: LossMatrix {
                useful: loss_row.clone(),
                useful_bad: loss_row.clone(),
                abandoned: loss_row.clone(),
                zombie: loss_row.clone(),
            },
            ..Policy::default()
        };

        let class_priors = ClassPriors {
            prior_prob: 0.25,
            cpu_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
            },
            runtime_gamma: None,
            orphan_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
            },
            tty_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
            },
            net_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
            },
            io_active_beta: None,
            hazard_gamma: None,
            competing_hazards: None,
        };

        let priors = Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: Classes {
                useful: class_priors.clone(),
                useful_bad: class_priors.clone(),
                abandoned: class_priors.clone(),
                zombie: class_priors,
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: Some(CausalInterventions {
                pause: Some(InterventionPriors {
                    useful: Some(BetaParams {
                        alpha: 9.0,
                        beta: 1.0,
                    }),
                    useful_bad: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                    abandoned: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                    zombie: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                }),
                throttle: None,
                kill: Some(InterventionPriors {
                    useful: Some(BetaParams {
                        alpha: 1.0,
                        beta: 9.0,
                    }),
                    useful_bad: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                    abandoned: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                    zombie: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                    }),
                }),
                restart: None,
            }),
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        };

        let outcome = decide_action_with_recovery(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &priors,
            0.05,
        )
        .expect("decision");

        assert_eq!(outcome.optimal_action, Action::Pause);
        assert!(outcome.recovery_expectations.is_some());
        assert!(outcome.rationale.used_recovery_preference);
    }

    // =========================================================================
    // Process State Feasibility Tests
    // =========================================================================

    #[test]
    fn test_from_process_state_zombie_disables_kill_pause_resume_freeze() {
        let feasibility = ActionFeasibility::from_process_state(true, false, None);

        assert!(!feasibility.is_allowed(Action::Kill), "Kill should be disabled for zombie");
        assert!(!feasibility.is_allowed(Action::Pause), "Pause should be disabled for zombie");
        assert!(!feasibility.is_allowed(Action::Resume), "Resume should be disabled for zombie");
        assert!(!feasibility.is_allowed(Action::Freeze), "Freeze should be disabled for zombie");
        assert!(!feasibility.is_allowed(Action::Unfreeze), "Unfreeze should be disabled for zombie");

        // Other actions should still be allowed (they might target parent/supervisor)
        assert!(feasibility.is_allowed(Action::Keep), "Keep should be allowed for zombie");
        assert!(feasibility.is_allowed(Action::Restart), "Restart should be allowed (supervisor)");
        assert!(feasibility.is_allowed(Action::Renice), "Renice should be allowed for zombie");
        assert!(feasibility.is_allowed(Action::Throttle), "Throttle should be allowed for zombie");

        // Verify reason messages
        let kill_reason = feasibility
            .disabled
            .iter()
            .find(|d| d.action == Action::Kill)
            .map(|d| &d.reason);
        assert!(
            kill_reason.is_some_and(|r| r.contains("zombie") && r.contains("dead")),
            "Kill reason should mention zombie and dead"
        );
    }

    #[test]
    fn test_from_process_state_disksleep_disables_kill() {
        let feasibility = ActionFeasibility::from_process_state(false, true, None);

        assert!(!feasibility.is_allowed(Action::Kill), "Kill should be disabled for D-state");

        // Other actions should still be allowed (including Freeze - cgroup freeze works at cgroup level)
        assert!(feasibility.is_allowed(Action::Pause), "Pause should be allowed for D-state");
        assert!(feasibility.is_allowed(Action::Resume), "Resume should be allowed for D-state");
        assert!(feasibility.is_allowed(Action::Freeze), "Freeze should be allowed for D-state");
        assert!(feasibility.is_allowed(Action::Unfreeze), "Unfreeze should be allowed for D-state");
        assert!(feasibility.is_allowed(Action::Keep), "Keep should be allowed for D-state");

        // Verify reason mentions D-state
        let kill_reason = feasibility
            .disabled
            .iter()
            .find(|d| d.action == Action::Kill)
            .map(|d| &d.reason);
        assert!(
            kill_reason.is_some_and(|r| r.contains("D-state") && r.contains("unreliable")),
            "Kill reason should mention D-state and unreliable"
        );
    }

    #[test]
    fn test_from_process_state_disksleep_includes_wchan() {
        let feasibility =
            ActionFeasibility::from_process_state(false, true, Some("nfs_wait_on_request"));

        let kill_reason = feasibility
            .disabled
            .iter()
            .find(|d| d.action == Action::Kill)
            .map(|d| &d.reason);
        assert!(
            kill_reason.is_some_and(|r| r.contains("nfs_wait_on_request")),
            "Kill reason should include wchan value"
        );
    }

    #[test]
    fn test_from_process_state_normal_allows_all() {
        let feasibility = ActionFeasibility::from_process_state(false, false, None);

        assert!(feasibility.disabled.is_empty(), "Normal process should have no disabled actions");
        assert!(feasibility.is_allowed(Action::Kill));
        assert!(feasibility.is_allowed(Action::Pause));
        assert!(feasibility.is_allowed(Action::Resume));
        assert!(feasibility.is_allowed(Action::Freeze));
        assert!(feasibility.is_allowed(Action::Unfreeze));
        assert!(feasibility.is_allowed(Action::Keep));
    }

    #[test]
    fn test_feasibility_merge() {
        let state_feasibility = ActionFeasibility::from_process_state(true, false, None);
        let policy_feasibility = ActionFeasibility {
            disabled: vec![DisabledAction {
                action: Action::Restart,
                reason: "policy blocked".to_string(),
            }],
        };

        let merged = state_feasibility.merge(&policy_feasibility);

        // Should have both zombie-disabled actions AND policy-disabled actions
        assert!(!merged.is_allowed(Action::Kill), "Kill should be disabled (zombie)");
        assert!(!merged.is_allowed(Action::Pause), "Pause should be disabled (zombie)");
        assert!(!merged.is_allowed(Action::Restart), "Restart should be disabled (policy)");
        assert!(merged.is_allowed(Action::Keep), "Keep should be allowed");
    }

    #[test]
    fn test_zombie_decision_routes_away_from_kill() {
        let policy = policy_for_tests();
        let posterior = ClassScores {
            useful: 0.05,
            useful_bad: 0.05,
            abandoned: 0.10,
            zombie: 0.80, // High zombie probability would normally recommend Kill
        };

        // Without state constraints, Kill would be optimal
        let unconstrained = decide_action(&posterior, &policy, &ActionFeasibility::allow_all())
            .expect("unconstrained decision");
        assert_eq!(
            unconstrained.optimal_action,
            Action::Kill,
            "Without constraints, Kill should be optimal for zombie posterior"
        );

        // With zombie state constraints, Kill is disabled - should choose alternative
        let feasibility = ActionFeasibility::from_process_state(true, false, None);
        let constrained = decide_action(&posterior, &policy, &feasibility).expect("constrained");

        assert_ne!(
            constrained.optimal_action,
            Action::Kill,
            "Zombie process should not be killed directly"
        );
        assert!(
            constrained.rationale.disabled_actions.iter().any(|d| d.action == Action::Kill),
            "Kill should appear in disabled_actions"
        );
    }
}
