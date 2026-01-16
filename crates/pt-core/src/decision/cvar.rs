//! CVaR (Conditional Value at Risk) for risk-sensitive decision making.
//!
//! This module implements coherent risk measures for decision-making under uncertainty.
//! CVaR focuses on tail risk, penalizing actions that have catastrophic outcomes
//! even if their expected loss is low.
//!
//! # Background
//!
//! For a random loss L and confidence level α ∈ (0,1):
//! - VaR_α(L) = inf { η : P(L ≤ η) ≥ α } (the α-quantile)
//! - CVaR_α(L) = E[L | L ≥ VaR_α(L)] (expected loss in the worst 1-α tail)
//!
//! Equivalently, CVaR can be computed via the dual:
//!   CVaR_α(L) = min_η { η + (1/(1-α)) E[(L-η)_+] }
//!
//! For our 4-class discrete posterior, CVaR becomes tractable:
//! 1. Sort outcomes by loss (descending)
//! 2. Accumulate probability until we reach (1-α)
//! 3. Compute the conditional expectation over this tail
//!
//! # When to Apply
//!
//! CVaR should be used in:
//! - Robot mode (always): autonomous decisions need conservative bounds
//! - Low confidence decisions: when posteriors are diffuse
//! - High blast radius candidates: when the cost of error is large
//! - Policy override: explicit --conservative flag

use crate::config::policy::{LossMatrix, Policy};
use crate::decision::expected_loss::Action;
use crate::inference::ClassScores;
use serde::Serialize;
use thiserror::Error;

/// CVaR computation result for a single action.
#[derive(Debug, Clone, Serialize)]
pub struct CvarLoss {
    pub action: Action,
    /// CVaR at the specified confidence level (expected loss in worst tail).
    pub cvar: f64,
    /// Standard expected loss for comparison.
    pub expected_loss: f64,
    /// VaR at the specified confidence level (loss threshold for tail).
    pub var: f64,
    /// The confidence level used (e.g., 0.95).
    pub alpha: f64,
}

/// Risk-sensitive decision outcome.
#[derive(Debug, Clone, Serialize)]
pub struct RiskSensitiveOutcome {
    /// Whether risk-sensitive control was applied.
    pub applied: bool,
    /// Reason for applying (or not applying) risk-sensitive control.
    pub reason: String,
    /// Original optimal action based on expected loss.
    pub original_action: Action,
    /// Risk-adjusted optimal action based on CVaR.
    pub risk_adjusted_action: Action,
    /// CVaR results for all feasible actions.
    pub cvar_losses: Vec<CvarLoss>,
    /// Confidence level used.
    pub alpha: f64,
    /// Whether the action changed due to risk sensitivity.
    pub action_changed: bool,
}

/// Errors raised during CVaR computation.
#[derive(Debug, Error)]
pub enum CvarError {
    #[error("invalid posterior: {message}")]
    InvalidPosterior { message: String },
    #[error("invalid alpha: must be in (0, 1), got {alpha}")]
    InvalidAlpha { alpha: f64 },
    #[error("no feasible actions")]
    NoFeasibleActions,
}

/// Compute CVaR for a single action given posterior and loss matrix.
///
/// For a discrete distribution over 4 classes with posterior probabilities,
/// CVaR_α is computed by:
/// 1. Forming (loss, probability) pairs for each class
/// 2. Sorting by loss descending
/// 3. Computing the conditional expectation over the worst (1-α) tail
///
/// # Arguments
/// * `action` - The action to compute CVaR for
/// * `posterior` - Class probabilities (must sum to 1)
/// * `loss_matrix` - Loss values for each (action, class) pair
/// * `alpha` - Confidence level (e.g., 0.95 means worst 5% tail)
pub fn compute_cvar(
    action: Action,
    posterior: &ClassScores,
    loss_matrix: &LossMatrix,
    alpha: f64,
) -> Result<CvarLoss, CvarError> {
    if alpha <= 0.0 || alpha >= 1.0 {
        return Err(CvarError::InvalidAlpha { alpha });
    }

    // Get losses for this action across all classes
    let losses_and_probs = [
        (loss_for_action_class(action, &loss_matrix.useful)?, posterior.useful),
        (loss_for_action_class(action, &loss_matrix.useful_bad)?, posterior.useful_bad),
        (loss_for_action_class(action, &loss_matrix.abandoned)?, posterior.abandoned),
        (loss_for_action_class(action, &loss_matrix.zombie)?, posterior.zombie),
    ];

    // Compute expected loss (for comparison)
    let expected_loss: f64 = losses_and_probs
        .iter()
        .map(|(loss, prob)| loss * prob)
        .sum();

    // Sort by loss descending (worst outcomes first)
    let mut sorted: Vec<(f64, f64)> = losses_and_probs
        .iter()
        .filter(|(_, prob)| *prob > 0.0)
        .copied()
        .collect();
    sorted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // Compute CVaR: conditional expectation over worst (1-α) tail
    let tail_prob = 1.0 - alpha;
    let (cvar, var) = compute_discrete_cvar(&sorted, tail_prob);

    Ok(CvarLoss {
        action,
        cvar,
        expected_loss,
        var,
        alpha,
    })
}

/// Compute CVaR for a discrete distribution.
///
/// Given (loss, probability) pairs sorted by loss descending,
/// compute the conditional expectation over the worst tail_prob mass.
///
/// Returns (CVaR, VaR) tuple.
fn compute_discrete_cvar(sorted: &[(f64, f64)], tail_prob: f64) -> (f64, f64) {
    if sorted.is_empty() || tail_prob <= 0.0 {
        return (0.0, 0.0);
    }

    let mut accumulated_prob = 0.0;
    let mut weighted_sum = 0.0;
    let mut var = sorted[0].0; // VaR is the threshold where tail starts

    for (loss, prob) in sorted {
        if accumulated_prob >= tail_prob {
            break;
        }

        let remaining = tail_prob - accumulated_prob;
        let contrib_prob = prob.min(remaining);

        // Update VaR: the first loss value that enters the tail
        if accumulated_prob == 0.0 {
            var = *loss;
        }

        weighted_sum += loss * contrib_prob;
        accumulated_prob += prob;
    }

    // CVaR is the conditional expectation: weighted_sum / tail_prob
    let cvar = if accumulated_prob > 0.0 {
        weighted_sum / accumulated_prob.min(tail_prob)
    } else {
        sorted.first().map(|(l, _)| *l).unwrap_or(0.0)
    };

    (cvar, var)
}

/// Get loss for an action applied to a specific class.
fn loss_for_action_class(
    action: Action,
    row: &crate::config::policy::LossRow,
) -> Result<f64, CvarError> {
    match action {
        Action::Keep => Ok(row.keep),
        Action::Pause | Action::Freeze => row.pause.ok_or_else(|| CvarError::InvalidPosterior {
            message: format!("missing pause loss for action {action:?}"),
        }),
        Action::Throttle | Action::Quarantine => {
            row.throttle.ok_or_else(|| CvarError::InvalidPosterior {
                message: format!("missing throttle loss for action {action:?}"),
            })
        }
        Action::Renice => row.renice.ok_or_else(|| CvarError::InvalidPosterior {
            message: format!("missing renice loss for action {action:?}"),
        }),
        Action::Restart => row.restart.ok_or_else(|| CvarError::InvalidPosterior {
            message: format!("missing restart loss for action {action:?}"),
        }),
        Action::Kill => Ok(row.kill),
        Action::Resume | Action::Unfreeze | Action::Unquarantine => {
            Err(CvarError::InvalidPosterior {
                message: format!("follow-up action {action:?} has no loss"),
            })
        }
    }
}

/// Compute CVaR for all feasible actions and select the risk-adjusted optimal.
///
/// # Arguments
/// * `posterior` - Class probabilities
/// * `policy` - Policy containing loss matrix
/// * `feasible_actions` - Actions to consider
/// * `alpha` - Confidence level (e.g., 0.95)
/// * `original_optimal` - The action selected by expected loss minimization
///
/// # Returns
/// Risk-sensitive outcome showing whether CVaR changed the decision.
pub fn decide_with_cvar(
    posterior: &ClassScores,
    policy: &Policy,
    feasible_actions: &[Action],
    alpha: f64,
    original_optimal: Action,
    reason: &str,
) -> Result<RiskSensitiveOutcome, CvarError> {
    if feasible_actions.is_empty() {
        return Err(CvarError::NoFeasibleActions);
    }

    let mut cvar_losses = Vec::new();

    for &action in feasible_actions {
        match compute_cvar(action, posterior, &policy.loss_matrix, alpha) {
            Ok(cvar_loss) => cvar_losses.push(cvar_loss),
            Err(_) => continue, // Skip actions without valid loss entries
        }
    }

    if cvar_losses.is_empty() {
        return Err(CvarError::NoFeasibleActions);
    }

    // Select action with minimum CVaR (ties broken by reversibility preference)
    let risk_adjusted_action = select_min_cvar(&cvar_losses);
    let action_changed = risk_adjusted_action != original_optimal;

    Ok(RiskSensitiveOutcome {
        applied: true,
        reason: reason.to_string(),
        original_action: original_optimal,
        risk_adjusted_action,
        cvar_losses,
        alpha,
        action_changed,
    })
}

/// Select the action with minimum CVaR, with tie-breaking by reversibility.
fn select_min_cvar(cvar_losses: &[CvarLoss]) -> Action {
    let mut best = &cvar_losses[0];

    for cvar in cvar_losses.iter().skip(1) {
        if cvar.cvar < best.cvar {
            best = cvar;
        } else if (cvar.cvar - best.cvar).abs() <= 1e-12 {
            // Tie-break: prefer more reversible action (lower rank = safer)
            if tie_break_rank(cvar.action) < tie_break_rank(best.action) {
                best = cvar;
            }
        }
    }

    best.action
}

/// Returns the tie-break rank for an action (lower = preferred in ties).
/// Keep is most preferred, Kill is least preferred.
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

/// Determine if CVaR should be applied based on context.
#[derive(Debug, Clone)]
pub struct CvarTrigger {
    /// Whether robot mode is enabled.
    pub robot_mode: bool,
    /// Whether confidence is low (posterior entropy high).
    pub low_confidence: bool,
    /// Whether blast radius exceeds threshold.
    pub high_blast_radius: bool,
    /// Whether explicit --conservative flag was set.
    pub explicit_conservative: bool,
    /// The blast radius in MB (for logging).
    pub blast_radius_mb: Option<f64>,
}

impl CvarTrigger {
    /// Check if any trigger condition is met.
    pub fn should_apply(&self) -> bool {
        self.robot_mode || self.low_confidence || self.high_blast_radius || self.explicit_conservative
    }

    /// Get the reason string for why CVaR was applied.
    pub fn reason(&self) -> String {
        let mut reasons: Vec<String> = Vec::new();

        if self.robot_mode {
            reasons.push("robot_mode".to_string());
        }
        if self.low_confidence {
            reasons.push("low_confidence".to_string());
        }
        if self.high_blast_radius {
            if let Some(mb) = self.blast_radius_mb {
                reasons.push(format!("high_blast_radius ({:.0} MB)", mb));
            } else {
                reasons.push("high_blast_radius".to_string());
            }
        }
        if self.explicit_conservative {
            reasons.push("explicit_conservative_flag".to_string());
        }

        if reasons.is_empty() {
            "none".to_string()
        } else {
            reasons.join(", ")
        }
    }
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
    fn test_cvar_certain_useful_process() {
        // When we're certain the process is useful, CVaR for Kill should be very high
        let posterior = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let loss_matrix = test_loss_matrix();

        let cvar_keep = compute_cvar(Action::Keep, &posterior, &loss_matrix, 0.95).unwrap();
        let cvar_kill = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.95).unwrap();

        // With certainty, CVaR = E[L] = loss value
        assert!((cvar_keep.cvar - 0.0).abs() < 1e-6, "Keep CVaR should be 0");
        assert!(
            (cvar_kill.cvar - 100.0).abs() < 1e-6,
            "Kill CVaR should be 100"
        );
        assert!(
            (cvar_keep.expected_loss - 0.0).abs() < 1e-6,
            "Keep E[L] should be 0"
        );
    }

    #[test]
    fn test_cvar_uniform_posterior() {
        // With uniform posterior, CVaR focuses on worst outcomes
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        // At α=0.95 (5% tail), we focus on the worst outcome
        let cvar_kill = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.95).unwrap();

        // For Kill: losses are [100, 20, 1, 1] with probs [0.25, 0.25, 0.25, 0.25]
        // Sorted descending: (100, 0.25), (20, 0.25), (1, 0.25), (1, 0.25)
        // 5% tail = first 0.05 of mass, which is part of the (100, 0.25) bucket
        // CVaR should be 100 (the worst outcome dominates the 5% tail)
        assert!(
            (cvar_kill.cvar - 100.0).abs() < 1e-6,
            "CVaR should equal worst outcome for tight alpha"
        );

        // Expected loss: 0.25*100 + 0.25*20 + 0.25*1 + 0.25*1 = 30.5
        assert!(
            (cvar_kill.expected_loss - 30.5).abs() < 1e-6,
            "Expected loss should be 30.5"
        );
    }

    #[test]
    fn test_cvar_reverses_decision() {
        // Scenario: Kill has lower E[L] but much higher CVaR due to tail risk
        // This should cause CVaR to prefer a safer action

        // Posterior: mostly abandoned but some useful probability
        let posterior = ClassScores {
            useful: 0.10,
            useful_bad: 0.05,
            abandoned: 0.80,
            zombie: 0.05,
        };
        let loss_matrix = test_loss_matrix();

        // E[L] for Kill: 0.10*100 + 0.05*20 + 0.80*1 + 0.05*1 = 11.85
        // E[L] for Keep: 0.10*0 + 0.05*10 + 0.80*30 + 0.05*50 = 27.0

        // So by expected loss, Kill is optimal

        // But CVaR at α=0.95 for Kill:
        // Sorted: (100, 0.10), (20, 0.05), (1, 0.80), (1, 0.05)
        // 5% tail mass primarily in (100, 0.10) bucket
        // CVaR ≈ 100 (the catastrophic outcome dominates tail)

        let cvar_kill = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.95).unwrap();
        let cvar_keep = compute_cvar(Action::Keep, &posterior, &loss_matrix, 0.95).unwrap();

        // Kill has lower E[L] but much higher CVaR
        assert!(
            cvar_kill.expected_loss < cvar_keep.expected_loss,
            "Kill should have lower E[L]"
        );
        assert!(
            cvar_kill.cvar > cvar_keep.cvar,
            "Kill should have higher CVaR due to tail risk"
        );
    }

    #[test]
    fn test_cvar_alpha_extreme_values() {
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        // α close to 1 → very small tail → CVaR → worst outcome
        let cvar_high = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.99).unwrap();
        assert!(
            (cvar_high.cvar - 100.0).abs() < 1e-6,
            "α=0.99 should give worst outcome"
        );

        // α close to 0 → full distribution → CVaR approaches E[L]
        // At α=0.01, we consider 99% of the mass, so CVaR should be close to E[L]
        let cvar_low = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.01).unwrap();
        let relative_diff = (cvar_low.cvar - cvar_low.expected_loss).abs() / cvar_low.expected_loss;
        assert!(
            relative_diff < 0.02,
            "α=0.01 should be within 2% of E[L], got CVaR={}, E[L]={}",
            cvar_low.cvar,
            cvar_low.expected_loss
        );
    }

    #[test]
    fn test_invalid_alpha() {
        let posterior = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let loss_matrix = test_loss_matrix();

        assert!(matches!(
            compute_cvar(Action::Keep, &posterior, &loss_matrix, 0.0),
            Err(CvarError::InvalidAlpha { .. })
        ));
        assert!(matches!(
            compute_cvar(Action::Keep, &posterior, &loss_matrix, 1.0),
            Err(CvarError::InvalidAlpha { .. })
        ));
        assert!(matches!(
            compute_cvar(Action::Keep, &posterior, &loss_matrix, -0.5),
            Err(CvarError::InvalidAlpha { .. })
        ));
    }

    #[test]
    fn test_decide_with_cvar() {
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
        let outcome = decide_with_cvar(
            &posterior,
            &policy,
            &feasible,
            0.95,
            Action::Kill, // Would be optimal by E[L]
            "test_reason",
        )
        .unwrap();

        assert!(outcome.applied);
        assert_eq!(outcome.alpha, 0.95);
        assert_eq!(outcome.original_action, Action::Kill);
        // CVaR should prefer a safer action due to tail risk
        assert_ne!(
            outcome.risk_adjusted_action,
            Action::Kill,
            "CVaR should avoid Kill due to tail risk"
        );
        assert!(outcome.action_changed);
    }

    #[test]
    fn test_cvar_trigger() {
        let trigger = CvarTrigger {
            robot_mode: true,
            low_confidence: false,
            high_blast_radius: false,
            explicit_conservative: false,
            blast_radius_mb: None,
        };
        assert!(trigger.should_apply());
        assert!(trigger.reason().contains("robot_mode"));

        let no_trigger = CvarTrigger {
            robot_mode: false,
            low_confidence: false,
            high_blast_radius: false,
            explicit_conservative: false,
            blast_radius_mb: None,
        };
        assert!(!no_trigger.should_apply());
    }

    #[test]
    fn test_var_computation() {
        // VaR should be the threshold where the tail starts
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let loss_matrix = test_loss_matrix();

        let cvar = compute_cvar(Action::Kill, &posterior, &loss_matrix, 0.95).unwrap();

        // VaR at 95% should be the worst outcome (100) since it's in the 5% tail
        assert!(
            (cvar.var - 100.0).abs() < 1e-6,
            "VaR should be worst outcome for tight alpha"
        );
    }
}
