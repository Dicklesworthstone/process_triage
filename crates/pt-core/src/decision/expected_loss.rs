//! Expected loss decisioning and SPRT-style boundary computation.

use crate::config::policy::{LossMatrix, LossRow, Policy};
use crate::inference::ClassScores;
use serde::Serialize;
use thiserror::Error;

/// Supported actions for early decisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Keep,
    Pause,
    Throttle,
    Restart,
    Kill,
}

impl Action {
    const ALL: [Action; 5] = [
        Action::Keep,
        Action::Pause,
        Action::Throttle,
        Action::Restart,
        Action::Kill,
    ];

    fn tie_break_rank(&self) -> u8 {
        match self {
            Action::Keep => 0,
            Action::Pause => 1,
            Action::Throttle => 2,
            Action::Restart => 3,
            Action::Kill => 4,
        }
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
        Self { disabled: Vec::new() }
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
}

/// Decision output for a single candidate.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionOutcome {
    pub expected_loss: Vec<ExpectedLoss>,
    pub optimal_action: Action,
    pub sprt_boundary: Option<SprtBoundary>,
    pub posterior_odds_abandoned_vs_useful: Option<f64>,
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
        rationale: DecisionRationale {
            chosen_action: optimal_action,
            tie_break,
            disabled_actions: disabled,
        },
    })
}

fn validate_posterior(posterior: &ClassScores) -> Result<(), DecisionError> {
    let values = [posterior.useful, posterior.useful_bad, posterior.abandoned, posterior.zombie];
    if values.iter().any(|v| v.is_nan() || v.is_infinite() || *v < 0.0) {
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

fn loss_for_action(row: &LossRow, action: Action, class: &'static str) -> Result<f64, DecisionError> {
    match action {
        Action::Keep => Ok(row.keep),
        Action::Pause => row.pause.ok_or(DecisionError::MissingLoss { action, class }),
        Action::Throttle => row
            .throttle
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Restart => row
            .restart
            .ok_or(DecisionError::MissingLoss { action, class }),
        Action::Kill => Ok(row.kill),
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
    use crate::config::policy::{Policy, LossMatrix, LossRow};

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
        let outcome = decide_action(&posterior, &policy, &ActionFeasibility::allow_all())
            .expect("decision");
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
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            useful_bad: LossRow {
                keep: 1.0,
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            abandoned: LossRow {
                keep: 1.0,
                pause: Some(1.0),
                throttle: Some(1.0),
                kill: 1.0,
                restart: Some(1.0),
            },
            zombie: LossRow {
                keep: 1.0,
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
        let outcome = decide_action(&posterior, &policy, &ActionFeasibility::allow_all())
            .expect("decision");
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
}
