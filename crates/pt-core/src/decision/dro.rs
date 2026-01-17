//! Distributionally Robust Optimization (DRO) for decision-making under distribution shift.
//!
//! This module implements a safety layer that tightens decisions when the model
//! may be misspecified or when distribution drift is detected.
//!
//! # Background
//!
//! DRO replaces the nominal expected loss with a **worst-case** expected loss
//! over an ambiguity set around the nominal distribution:
//!
//! ```text
//! worst_case_loss = sup_{Q: W(Q,P) ≤ ε}  E_Q[L]
//! ```
//!
//! Where:
//! - P is the nominal posterior distribution
//! - Q ranges over distributions within a Wasserstein ball of radius ε
//! - ε encodes how much shift we want to be robust to
//!
//! # When DRO Activates
//!
//! DRO should be applied when any misspecification signal is raised:
//! - PPC (Posterior Predictive Check) failures
//! - Drift detection triggers (Wasserstein divergence threshold crossed)
//! - Robust Bayes η-tempering reduced due to mismatch
//! - Explicit --conservative flag
//!
//! # How DRO Changes Decisions
//!
//! 1. Compute nominal expected loss E_P[L(a,S)|x]
//! 2. Compute robust/worst-case expected loss bound for candidate actions
//! 3. If robust bound reverses the decision (e.g., kill becomes worse than keep/pause),
//!    **de-escalate** to the safer action
//!
//! # Wasserstein DRO for Discrete Distributions
//!
//! For our 4-class discrete posterior, the worst-case expectation can be computed
//! by shifting probability mass toward worst outcomes. With ground metric c(i,j)
//! (transport cost between classes), the Wasserstein DRO bound is:
//!
//! ```text
//! sup_{Q: W(Q,P) ≤ ε} E_Q[L] = E_P[L] + ε · Lip(L)
//! ```
//!
//! where Lip(L) is the Lipschitz constant of the loss function w.r.t. the ground metric.
//! For discrete distributions with uniform ground metric, this simplifies to:
//!
//! ```text
//! worst_case = E_P[L] + ε · (L_max - L_min) / 2
//! ```
//!
//! A more refined approach uses the dual formulation to compute the exact worst case.

use crate::config::policy::{LossMatrix, LossRow, Policy};
use crate::decision::expected_loss::Action;
use crate::inference::ClassScores;
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

/// DRO computation result for a single action.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DroLoss {
    /// The action evaluated.
    pub action: Action,
    /// Worst-case expected loss under the ambiguity set.
    pub robust_loss: f64,
    /// Nominal expected loss (for comparison).
    pub nominal_loss: f64,
    /// The ambiguity radius used.
    pub epsilon: f64,
    /// The loss inflation from DRO (robust - nominal).
    pub inflation: f64,
    /// Lipschitz constant of the loss for this action.
    pub lipschitz: f64,
}

/// DRO decision outcome.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DroOutcome {
    /// Whether DRO was applied.
    pub applied: bool,
    /// Reason for applying (or not applying) DRO.
    pub reason: String,
    /// The ambiguity radius used.
    pub ambiguity_radius: f64,
    /// Original optimal action based on nominal expected loss.
    pub original_action: Action,
    /// Robust optimal action after DRO.
    pub robust_action: Action,
    /// Worst-case expected loss for the robust action.
    pub worst_case_expected_loss: f64,
    /// Whether the action changed due to DRO.
    pub action_changed: bool,
    /// DRO losses for all feasible actions (for transparency).
    pub dro_losses: Vec<DroLoss>,
}

/// Errors raised during DRO computation.
#[derive(Debug, Error)]
pub enum DroError {
    #[error("invalid posterior: {message}")]
    InvalidPosterior { message: String },
    #[error("invalid epsilon: must be non-negative, got {epsilon}")]
    InvalidEpsilon { epsilon: f64 },
    #[error("no feasible actions")]
    NoFeasibleActions,
}

/// Trigger conditions that determine when DRO should be applied.
#[derive(Debug, Clone, Serialize)]
pub struct DroTrigger {
    /// PPC (Posterior Predictive Check) failure detected.
    pub ppc_failure: bool,
    /// Drift detection threshold crossed.
    pub drift_detected: bool,
    /// Wasserstein divergence value (if available).
    pub wasserstein_divergence: Option<f64>,
    /// Robust Bayes η-tempering was reduced.
    pub eta_tempering_reduced: bool,
    /// Explicit --conservative flag was set.
    pub explicit_conservative: bool,
    /// Model confidence is low (e.g., high entropy posterior).
    pub low_model_confidence: bool,
}

impl DroTrigger {
    /// Check if any trigger condition is met.
    pub fn should_apply(&self) -> bool {
        self.ppc_failure
            || self.drift_detected
            || self.eta_tempering_reduced
            || self.explicit_conservative
            || self.low_model_confidence
    }

    /// Get the reason string for why DRO was applied.
    pub fn reason(&self) -> String {
        let mut reasons: Vec<String> = Vec::new();

        if self.ppc_failure {
            reasons.push("ppc_failure".to_string());
        }
        if self.drift_detected {
            if let Some(div) = self.wasserstein_divergence {
                reasons.push(format!("drift_detected (W={:.3})", div));
            } else {
                reasons.push("drift_detected".to_string());
            }
        }
        if self.eta_tempering_reduced {
            reasons.push("eta_tempering_reduced".to_string());
        }
        if self.explicit_conservative {
            reasons.push("explicit_conservative_flag".to_string());
        }
        if self.low_model_confidence {
            reasons.push("low_model_confidence".to_string());
        }

        if reasons.is_empty() {
            "none".to_string()
        } else {
            reasons.join(", ")
        }
    }

    /// Create a trigger indicating no DRO should be applied.
    pub fn none() -> Self {
        Self {
            ppc_failure: false,
            drift_detected: false,
            wasserstein_divergence: None,
            eta_tempering_reduced: false,
            explicit_conservative: false,
            low_model_confidence: false,
        }
    }
}

impl Default for DroTrigger {
    fn default() -> Self {
        Self::none()
    }
}

/// Compute worst-case expected loss for a single action using Wasserstein DRO.
///
/// For a discrete distribution over 4 classes, we use the Lipschitz bound:
/// ```text
/// worst_case = E_P[L] + ε · Lip(L)
/// ```
///
/// where Lip(L) = max|L_i - L_j| / d(i,j) is the Lipschitz constant.
/// With a uniform ground metric (d(i,j) = 1 for i ≠ j), this becomes:
/// ```text
/// worst_case = E_P[L] + ε · (L_max - L_min)
/// ```
///
/// # Arguments
/// * `action` - The action to compute robust loss for
/// * `posterior` - Nominal posterior probabilities
/// * `loss_matrix` - Loss values for each (action, class) pair
/// * `epsilon` - Ambiguity radius (Wasserstein ball size)
pub fn compute_wasserstein_dro(
    action: Action,
    posterior: &ClassScores,
    loss_matrix: &LossMatrix,
    epsilon: f64,
) -> Result<DroLoss, DroError> {
    if epsilon < 0.0 {
        return Err(DroError::InvalidEpsilon { epsilon });
    }

    // Get losses for this action across all classes
    let losses = [
        loss_for_action_class(action, &loss_matrix.useful)?,
        loss_for_action_class(action, &loss_matrix.useful_bad)?,
        loss_for_action_class(action, &loss_matrix.abandoned)?,
        loss_for_action_class(action, &loss_matrix.zombie)?,
    ];

    let probs = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];

    // Compute nominal expected loss
    let nominal_loss: f64 = losses
        .iter()
        .zip(probs.iter())
        .map(|(l, p)| l * p)
        .sum();

    // Compute Lipschitz constant: max loss difference (with uniform ground metric)
    let l_min = losses.iter().cloned().fold(f64::INFINITY, f64::min);
    let l_max = losses.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let lipschitz = l_max - l_min;

    // Worst-case expected loss under Wasserstein DRO
    // This is the canonical Lipschitz bound for Wasserstein-1 robustness
    let robust_loss = nominal_loss + epsilon * lipschitz;
    let inflation = robust_loss - nominal_loss;

    Ok(DroLoss {
        action,
        robust_loss,
        nominal_loss,
        epsilon,
        inflation,
        lipschitz,
    })
}

/// Get loss for an action applied to a specific class.
fn loss_for_action_class(action: Action, row: &LossRow) -> Result<f64, DroError> {
    match action {
        Action::Keep => Ok(row.keep),
        Action::Pause | Action::Freeze => row.pause.ok_or_else(|| DroError::InvalidPosterior {
            message: format!("missing pause loss for action {action:?}"),
        }),
        Action::Throttle | Action::Quarantine => {
            row.throttle.ok_or_else(|| DroError::InvalidPosterior {
                message: format!("missing throttle loss for action {action:?}"),
            })
        }
        Action::Renice => row.renice.ok_or_else(|| DroError::InvalidPosterior {
            message: format!("missing renice loss for action {action:?}"),
        }),
        Action::Restart => row.restart.ok_or_else(|| DroError::InvalidPosterior {
            message: format!("missing restart loss for action {action:?}"),
        }),
        Action::Kill => Ok(row.kill),
        Action::Resume | Action::Unfreeze | Action::Unquarantine => {
            Err(DroError::InvalidPosterior {
                message: format!("follow-up action {action:?} has no loss"),
            })
        }
    }
}

/// Compute DRO for all feasible actions and select the robust optimal.
///
/// # Arguments
/// * `posterior` - Nominal posterior probabilities
/// * `policy` - Policy containing loss matrix
/// * `feasible_actions` - Actions to consider
/// * `epsilon` - Ambiguity radius (Wasserstein ball size)
/// * `original_optimal` - The action selected by nominal expected loss minimization
/// * `reason` - Reason string for why DRO is being applied
///
/// # Returns
/// DRO outcome showing whether the decision changed under robustness.
pub fn decide_with_dro(
    posterior: &ClassScores,
    policy: &Policy,
    feasible_actions: &[Action],
    epsilon: f64,
    original_optimal: Action,
    reason: &str,
) -> Result<DroOutcome, DroError> {
    if feasible_actions.is_empty() {
        return Err(DroError::NoFeasibleActions);
    }

    let mut dro_losses = Vec::new();

    for &action in feasible_actions {
        match compute_wasserstein_dro(action, posterior, &policy.loss_matrix, epsilon) {
            Ok(dro_loss) => dro_losses.push(dro_loss),
            Err(_) => continue, // Skip actions without valid loss entries
        }
    }

    if dro_losses.is_empty() {
        return Err(DroError::NoFeasibleActions);
    }

    // Select action with minimum robust loss (ties broken by reversibility preference)
    let robust_action = select_min_robust_loss(&dro_losses);
    let action_changed = robust_action != original_optimal;

    let worst_case_expected_loss = dro_losses
        .iter()
        .find(|d| d.action == robust_action)
        .map(|d| d.robust_loss)
        .unwrap_or(0.0);

    Ok(DroOutcome {
        applied: true,
        reason: reason.to_string(),
        ambiguity_radius: epsilon,
        original_action: original_optimal,
        robust_action,
        worst_case_expected_loss,
        action_changed,
        dro_losses,
    })
}

/// Select the action with minimum robust loss, with tie-breaking by reversibility.
fn select_min_robust_loss(dro_losses: &[DroLoss]) -> Action {
    let mut best = &dro_losses[0];

    for dro in dro_losses.iter().skip(1) {
        if dro.robust_loss < best.robust_loss {
            best = dro;
        } else if (dro.robust_loss - best.robust_loss).abs() <= 1e-12 {
            // Tie-break: prefer more reversible action (lower rank = safer)
            if tie_break_rank(dro.action) < tie_break_rank(best.action) {
                best = dro;
            }
        }
    }

    best.action
}

/// Returns the tie-break rank for an action (lower = preferred in ties).
fn tie_break_rank(action: Action) -> u8 {
    match action {
        Action::Keep => 0,
        Action::Renice => 1,
        Action::Pause | Action::Resume | Action::Freeze | Action::Unfreeze => 2,
        Action::Quarantine | Action::Unquarantine | Action::Throttle => 3,
        Action::Restart => 4,
        Action::Kill => 5,
    }
}

/// Compute adaptive epsilon based on the severity of drift/misspecification signals.
///
/// This function implements the logic from Plan §5.12 to scale the ambiguity
/// radius based on the strength of the misspecification signal.
///
/// # Arguments
/// * `base_epsilon` - Default epsilon from policy
/// * `trigger` - The trigger conditions that activated DRO
/// * `max_epsilon` - Maximum epsilon cap (policy-configurable)
///
/// # Returns
/// Adjusted epsilon value
pub fn compute_adaptive_epsilon(
    base_epsilon: f64,
    trigger: &DroTrigger,
    max_epsilon: f64,
) -> f64 {
    let mut epsilon = base_epsilon;

    // Scale up epsilon based on trigger severity
    if trigger.ppc_failure {
        epsilon *= 1.5; // PPC failure → moderate increase
    }
    if trigger.drift_detected {
        if let Some(div) = trigger.wasserstein_divergence {
            // Scale by drift magnitude (clamped)
            let scale = 1.0 + div.min(1.0);
            epsilon *= scale;
        } else {
            epsilon *= 1.3;
        }
    }
    if trigger.eta_tempering_reduced {
        epsilon *= 1.2;
    }
    if trigger.low_model_confidence {
        epsilon *= 1.4;
    }

    // Cap at maximum
    epsilon.min(max_epsilon)
}

/// Apply DRO gating to a decision, de-escalating if robustness changes the optimal action.
///
/// This is the main integration point for DRO in the decision pipeline.
///
/// # Arguments
/// * `nominal_action` - The action selected by nominal expected loss minimization
/// * `posterior` - Nominal posterior probabilities
/// * `policy` - Policy containing loss matrix and DRO config
/// * `trigger` - Trigger conditions for DRO
/// * `epsilon` - Ambiguity radius (use compute_adaptive_epsilon if dynamic)
///
/// # Returns
/// DRO outcome with the robust action (which may differ from nominal)
pub fn apply_dro_gate(
    nominal_action: Action,
    posterior: &ClassScores,
    policy: &Policy,
    trigger: &DroTrigger,
    epsilon: f64,
    feasible_actions: &[Action],
) -> DroOutcome {
    if !trigger.should_apply() {
        return DroOutcome {
            applied: false,
            reason: "no_trigger".to_string(),
            ambiguity_radius: epsilon,
            original_action: nominal_action,
            robust_action: nominal_action,
            worst_case_expected_loss: 0.0,
            action_changed: false,
            dro_losses: vec![],
        };
    }

    if feasible_actions.is_empty() {
        return DroOutcome {
            applied: false,
            reason: "no_feasible_actions".to_string(),
            ambiguity_radius: epsilon,
            original_action: nominal_action,
            robust_action: nominal_action,
            worst_case_expected_loss: 0.0,
            action_changed: false,
            dro_losses: vec![],
        };
    }

    match decide_with_dro(
        posterior,
        policy,
        feasible_actions,
        epsilon,
        nominal_action,
        &trigger.reason(),
    ) {
        Ok(outcome) => outcome,
        Err(_) => DroOutcome {
            applied: false,
            reason: "dro_computation_failed".to_string(),
            ambiguity_radius: epsilon,
            original_action: nominal_action,
            robust_action: nominal_action,
            worst_case_expected_loss: 0.0,
            action_changed: false,
            dro_losses: vec![],
        },
    }
}

/// Check if DRO de-escalated from a destructive action to a safer one.
///
/// This is useful for logging and understanding DRO's effect.
pub fn is_de_escalation(original: Action, robust: Action) -> bool {
    if original == robust {
        return false;
    }

    // De-escalation: moved from higher severity to lower severity
    tie_break_rank(robust) < tie_break_rank(original)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::{LossMatrix, LossRow, Policy};

    fn test_loss_matrix() -> LossMatrix {
        LossMatrix {
            useful: LossRow {
                keep: 0.0,
                pause: Some(5.0),
                throttle: Some(8.0),
                renice: Some(2.0),
                kill: 100.0,
                restart: Some(60.0),
            },
            useful_bad: LossRow {
                keep: 10.0,
                pause: Some(6.0),
                throttle: Some(8.0),
                renice: Some(4.0),
                kill: 20.0,
                restart: Some(12.0),
            },
            abandoned: LossRow {
                keep: 30.0,
                pause: Some(15.0),
                throttle: Some(10.0),
                renice: Some(12.0),
                kill: 1.0,
                restart: Some(8.0),
            },
            zombie: LossRow {
                keep: 50.0,
                pause: Some(20.0),
                throttle: Some(15.0),
                renice: Some(18.0),
                kill: 1.0,
                restart: Some(5.0),
            },
        }
    }

    #[test]
    fn test_dro_zero_epsilon_equals_nominal() {
        // With ε=0, DRO should give the same result as nominal expected loss
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        let dro = compute_wasserstein_dro(Action::Kill, &posterior, &loss_matrix, 0.0).unwrap();

        assert!(
            (dro.robust_loss - dro.nominal_loss).abs() < 1e-10,
            "With ε=0, robust_loss should equal nominal_loss"
        );
        assert!(
            dro.inflation.abs() < 1e-10,
            "With ε=0, inflation should be 0"
        );
    }

    #[test]
    fn test_dro_positive_epsilon_inflates_loss() {
        // With ε>0, robust loss should be >= nominal loss
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        let dro = compute_wasserstein_dro(Action::Kill, &posterior, &loss_matrix, 0.1).unwrap();

        assert!(
            dro.robust_loss >= dro.nominal_loss,
            "Robust loss should be >= nominal loss"
        );
        assert!(dro.inflation > 0.0, "Inflation should be positive");
    }

    #[test]
    fn test_dro_lipschitz_constant() {
        // Lipschitz constant should be L_max - L_min
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        let dro_kill = compute_wasserstein_dro(Action::Kill, &posterior, &loss_matrix, 0.1).unwrap();

        // For Kill: losses are [100, 20, 1, 1] → Lipschitz = 100 - 1 = 99
        assert!(
            (dro_kill.lipschitz - 99.0).abs() < 1e-10,
            "Kill Lipschitz should be 99, got {}",
            dro_kill.lipschitz
        );

        let dro_keep = compute_wasserstein_dro(Action::Keep, &posterior, &loss_matrix, 0.1).unwrap();

        // For Keep: losses are [0, 10, 30, 50] → Lipschitz = 50 - 0 = 50
        assert!(
            (dro_keep.lipschitz - 50.0).abs() < 1e-10,
            "Keep Lipschitz should be 50, got {}",
            dro_keep.lipschitz
        );
    }

    #[test]
    fn test_dro_reverses_decision() {
        // Scenario: Kill is optimal under nominal E[L], but DRO with high ε
        // should prefer a safer action due to worst-case loss inflation.
        let posterior = ClassScores {
            useful: 0.10,
            useful_bad: 0.05,
            abandoned: 0.80,
            zombie: 0.05,
        };
        let policy = Policy {
            loss_matrix: test_loss_matrix(),
            ..Policy::default()
        };

        let feasible = vec![Action::Keep, Action::Pause, Action::Kill];

        // With small ε, Kill should still be optimal (or close)
        let _dro_small = decide_with_dro(&posterior, &policy, &feasible, 0.01, Action::Kill, "test")
            .unwrap();

        // With large ε, DRO should de-escalate away from Kill
        let dro_large = decide_with_dro(&posterior, &policy, &feasible, 0.5, Action::Kill, "test")
            .unwrap();

        // Kill has high Lipschitz (99) so it should be penalized heavily with large ε
        assert!(
            dro_large.action_changed,
            "Large ε should cause action to change from Kill"
        );
        assert!(
            is_de_escalation(Action::Kill, dro_large.robust_action),
            "DRO should de-escalate from Kill"
        );
    }

    #[test]
    fn test_dro_trigger_should_apply() {
        let trigger = DroTrigger {
            ppc_failure: true,
            drift_detected: false,
            wasserstein_divergence: None,
            eta_tempering_reduced: false,
            explicit_conservative: false,
            low_model_confidence: false,
        };
        assert!(trigger.should_apply());
        assert!(trigger.reason().contains("ppc_failure"));

        let no_trigger = DroTrigger::none();
        assert!(!no_trigger.should_apply());
        assert_eq!(no_trigger.reason(), "none");
    }

    #[test]
    fn test_dro_trigger_reason_multiple() {
        let trigger = DroTrigger {
            ppc_failure: true,
            drift_detected: true,
            wasserstein_divergence: Some(0.15),
            eta_tempering_reduced: false,
            explicit_conservative: true,
            low_model_confidence: false,
        };

        let reason = trigger.reason();
        assert!(reason.contains("ppc_failure"));
        assert!(reason.contains("drift_detected"));
        assert!(reason.contains("0.15"));
        assert!(reason.contains("explicit_conservative"));
    }

    #[test]
    fn test_adaptive_epsilon() {
        let base = 0.1;
        let max = 0.5;

        // No triggers → base epsilon
        let trigger_none = DroTrigger::none();
        let eps = compute_adaptive_epsilon(base, &trigger_none, max);
        assert!((eps - base).abs() < 1e-10);

        // PPC failure → 1.5x
        let trigger_ppc = DroTrigger {
            ppc_failure: true,
            ..DroTrigger::none()
        };
        let eps_ppc = compute_adaptive_epsilon(base, &trigger_ppc, max);
        assert!(
            (eps_ppc - 0.15).abs() < 1e-10,
            "PPC failure should give 1.5x base"
        );

        // Multiple triggers → compound (capped at max)
        let trigger_multi = DroTrigger {
            ppc_failure: true,
            drift_detected: true,
            wasserstein_divergence: Some(0.5),
            eta_tempering_reduced: true,
            explicit_conservative: false,
            low_model_confidence: true,
        };
        let eps_multi = compute_adaptive_epsilon(base, &trigger_multi, max);
        assert!(
            eps_multi <= max,
            "Should be capped at max: {} <= {}",
            eps_multi,
            max
        );
    }

    #[test]
    fn test_apply_dro_gate_no_trigger() {
        let posterior = ClassScores {
            useful: 0.8,
            useful_bad: 0.1,
            abandoned: 0.05,
            zombie: 0.05,
        };
        let policy = Policy {
            loss_matrix: test_loss_matrix(),
            ..Policy::default()
        };

        let trigger = DroTrigger::none();
        let feasible = vec![Action::Keep, Action::Pause, Action::Kill];

        let outcome = apply_dro_gate(
            Action::Keep,
            &posterior,
            &policy,
            &trigger,
            0.1,
            &feasible,
        );

        assert!(!outcome.applied, "DRO should not be applied without trigger");
        assert!(!outcome.action_changed);
        assert_eq!(outcome.robust_action, Action::Keep);
    }

    #[test]
    fn test_apply_dro_gate_with_drift() {
        let posterior = ClassScores {
            useful: 0.10,
            useful_bad: 0.05,
            abandoned: 0.80,
            zombie: 0.05,
        };
        let policy = Policy {
            loss_matrix: test_loss_matrix(),
            ..Policy::default()
        };

        let trigger = DroTrigger {
            ppc_failure: false,
            drift_detected: true,
            wasserstein_divergence: Some(0.2),
            eta_tempering_reduced: false,
            explicit_conservative: false,
            low_model_confidence: false,
        };
        let feasible = vec![Action::Keep, Action::Pause, Action::Kill];

        let outcome = apply_dro_gate(
            Action::Kill,
            &posterior,
            &policy,
            &trigger,
            0.3, // Significant epsilon
            &feasible,
        );

        assert!(outcome.applied, "DRO should be applied with drift trigger");
        assert!(
            outcome.reason.contains("drift_detected"),
            "Reason should mention drift"
        );
        // With sufficient epsilon, Kill should be de-escalated
        assert!(
            !outcome.dro_losses.is_empty(),
            "Should have computed DRO losses"
        );
    }

    #[test]
    fn test_is_de_escalation() {
        assert!(is_de_escalation(Action::Kill, Action::Keep));
        assert!(is_de_escalation(Action::Kill, Action::Pause));
        assert!(is_de_escalation(Action::Restart, Action::Throttle));
        assert!(!is_de_escalation(Action::Keep, Action::Kill)); // Escalation, not de-escalation
        assert!(!is_de_escalation(Action::Keep, Action::Keep)); // No change
    }

    #[test]
    fn test_invalid_epsilon() {
        let posterior = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let loss_matrix = test_loss_matrix();

        let result = compute_wasserstein_dro(Action::Keep, &posterior, &loss_matrix, -0.1);
        assert!(matches!(result, Err(DroError::InvalidEpsilon { .. })));
    }

    #[test]
    fn test_dro_certain_posterior() {
        // With certain posterior (P=1 on one class), DRO inflation is pure Lipschitz term
        let posterior = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let loss_matrix = test_loss_matrix();
        let epsilon = 0.1;

        let dro_kill = compute_wasserstein_dro(Action::Kill, &posterior, &loss_matrix, epsilon).unwrap();

        // Nominal loss for Kill on useful = 100
        assert!(
            (dro_kill.nominal_loss - 100.0).abs() < 1e-10,
            "Nominal should be 100"
        );

        // Robust loss = 100 + ε * 99 = 100 + 9.9 = 109.9
        let expected_robust = 100.0 + epsilon * 99.0;
        assert!(
            (dro_kill.robust_loss - expected_robust).abs() < 1e-10,
            "Robust should be {}, got {}",
            expected_robust,
            dro_kill.robust_loss
        );
    }
}
