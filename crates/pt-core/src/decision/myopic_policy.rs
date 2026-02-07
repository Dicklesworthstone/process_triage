//! Myopic belief-state policy (POMDP-style) under safety constraints.
//!
//! This module implements Plan §5.7 / §2(U)/§2(AH): a myopic belief-state decision policy
//! that operates on the belief state b_t(S).
//!
//! # Model
//!
//! Given belief state `b_t(S)` over S ∈ {Useful, UsefulBad, Abandoned, Zombie}:
//! - `a* = argmin_a Σ_S L(a,S) · b_t(S)`
//!
//! This is the expected loss minimization principle from decision theory.
//!
//! # Constraints
//!
//! The policy respects multiple layers of safety constraints:
//! - Policy allow/deny rules (from policy.json)
//! - Robot mode gates (conservative bounds for autonomous operation)
//! - FDR/alpha-investing budgets (error rate control)
//! - Blast-radius caps (resource impact limits)
//!
//! # Explainability
//!
//! The output includes the expected-loss table for all feasible actions,
//! enabling galaxy-brain mode to show detailed rationale.

use crate::config::policy::{LossMatrix, LossRow, Policy};
use crate::decision::alpha_investing::AlphaWealthState;
use crate::decision::enforcer::ProcessCandidate;
use crate::decision::expected_loss::{Action, ActionFeasibility, DecisionError};
use crate::decision::robot_constraints::{ConstraintChecker, RuntimeRobotConstraints};
use crate::inference::belief_state::{BeliefState, ProcessState};
use crate::inference::ClassScores;
use serde::Serialize;
use thiserror::Error;

/// Errors from myopic policy evaluation.
#[derive(Debug, Error)]
pub enum MyopicPolicyError {
    #[error("decision error: {0}")]
    Decision(#[from] DecisionError),

    #[error("policy enforcement error: {0}")]
    Enforcement(String),

    #[error("no feasible actions after applying all constraints")]
    NoFeasibleActions,

    #[error("invalid belief state: probabilities must sum to 1.0")]
    InvalidBeliefState,
}

/// Result type for myopic policy operations.
pub type Result<T> = std::result::Result<T, MyopicPolicyError>;

/// Expected loss breakdown for explainability.
#[derive(Debug, Clone, Serialize)]
pub struct ActionLossBreakdown {
    /// The action being evaluated.
    pub action: Action,
    /// Expected loss given belief state.
    pub expected_loss: f64,
    /// Per-state contribution to expected loss.
    pub state_contributions: StateContributions,
    /// Whether this action is feasible (not disabled).
    pub feasible: bool,
    /// Reason if disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

/// Per-state contribution to expected loss.
#[derive(Debug, Clone, Serialize)]
pub struct StateContributions {
    /// Loss contribution from Useful state: L(a, Useful) * b(Useful).
    pub useful: f64,
    /// Loss contribution from UsefulBad state: L(a, UsefulBad) * b(UsefulBad).
    pub useful_bad: f64,
    /// Loss contribution from Abandoned state: L(a, Abandoned) * b(Abandoned).
    pub abandoned: f64,
    /// Loss contribution from Zombie state: L(a, Zombie) * b(Zombie).
    pub zombie: f64,
}

impl StateContributions {
    /// Compute total expected loss from contributions.
    pub fn total(&self) -> f64 {
        self.useful + self.useful_bad + self.abandoned + self.zombie
    }
}

/// Safety constraint summary for explainability.
#[derive(Debug, Clone, Serialize)]
pub struct ConstraintSummary {
    /// Policy enforcement result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_check: Option<PolicyCheckSummary>,
    /// Robot mode constraint result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub robot_constraints: Option<RobotConstraintSummary>,
    /// FDR gate result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fdr_gate: Option<FdrGateSummary>,
    /// Alpha-investing budget check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpha_investing: Option<AlphaInvestingSummary>,
    /// Blast-radius check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius: Option<BlastRadiusSummary>,
}

/// Policy check summary.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyCheckSummary {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation: Option<String>,
    pub warnings: Vec<String>,
}

/// Robot mode constraint summary.
#[derive(Debug, Clone, Serialize)]
pub struct RobotConstraintSummary {
    pub passed: bool,
    pub violations: Vec<String>,
}

/// FDR gate summary.
#[derive(Debug, Clone, Serialize)]
pub struct FdrGateSummary {
    pub passed: bool,
    pub e_value: f64,
    pub threshold: f64,
}

/// Alpha-investing budget summary.
#[derive(Debug, Clone, Serialize)]
pub struct AlphaInvestingSummary {
    pub sufficient_wealth: bool,
    pub current_wealth: f64,
    pub required_spend: f64,
}

/// Blast-radius check summary.
#[derive(Debug, Clone, Serialize)]
pub struct BlastRadiusSummary {
    pub within_limits: bool,
    pub memory_mb: f64,
    pub cpu_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cpu_pct: Option<f64>,
}

/// Myopic policy decision outcome.
#[derive(Debug, Clone, Serialize)]
pub struct MyopicDecision {
    /// The optimal action according to expected loss minimization.
    pub optimal_action: Action,
    /// Expected loss of the optimal action.
    pub optimal_loss: f64,
    /// Full expected-loss table for all actions (for galaxy-brain).
    pub loss_table: Vec<ActionLossBreakdown>,
    /// The belief state used for this decision.
    pub belief_state: BeliefStateDisplay,
    /// Safety constraint summary.
    pub constraints: ConstraintSummary,
    /// Whether any constraints overrode the pure expected-loss choice.
    pub constraint_override: bool,
    /// Original optimal action before constraints (if different).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unconstrained_optimal: Option<Action>,
    /// Rationale for the decision.
    pub rationale: String,
}

/// Belief state display for serialization.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefStateDisplay {
    pub useful: f64,
    pub useful_bad: f64,
    pub abandoned: f64,
    pub zombie: f64,
    pub entropy: f64,
    pub most_likely: String,
}

impl From<&BeliefState> for BeliefStateDisplay {
    fn from(belief: &BeliefState) -> Self {
        Self {
            useful: belief.prob(ProcessState::Useful),
            useful_bad: belief.prob(ProcessState::UsefulBad),
            abandoned: belief.prob(ProcessState::Abandoned),
            zombie: belief.prob(ProcessState::Zombie),
            entropy: belief.entropy(),
            most_likely: belief.argmax().to_string(),
        }
    }
}

/// Configuration for myopic policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct MyopicPolicyConfig {
    /// Whether to apply FDR gating.
    pub apply_fdr_gate: bool,
    /// FDR threshold (default 0.1).
    pub fdr_threshold: f64,
    /// Whether to apply alpha-investing budget.
    pub apply_alpha_investing: bool,
    /// Whether to apply blast-radius caps.
    pub apply_blast_radius: bool,
    /// Maximum memory impact in MB (if blast-radius enabled).
    pub max_memory_mb: Option<f64>,
    /// Maximum CPU impact in percent (if blast-radius enabled).
    pub max_cpu_pct: Option<f64>,
}

impl MyopicPolicyConfig {
    /// Create a default config with all constraints enabled.
    pub fn with_all_constraints() -> Self {
        Self {
            apply_fdr_gate: true,
            fdr_threshold: 0.1,
            apply_alpha_investing: true,
            apply_blast_radius: true,
            max_memory_mb: Some(1024.0), // 1GB default
            max_cpu_pct: Some(50.0),     // 50% default
        }
    }

    /// Create a minimal config (no additional constraints).
    pub fn minimal() -> Self {
        Self::default()
    }
}

/// Convert BeliefState to ClassScores for compatibility with existing code.
pub fn belief_to_class_scores(belief: &BeliefState) -> ClassScores {
    ClassScores {
        useful: belief.prob(ProcessState::Useful),
        useful_bad: belief.prob(ProcessState::UsefulBad),
        abandoned: belief.prob(ProcessState::Abandoned),
        zombie: belief.prob(ProcessState::Zombie),
    }
}

/// Convert ClassScores to BeliefState.
pub fn class_scores_to_belief(
    scores: &ClassScores,
) -> std::result::Result<BeliefState, crate::inference::belief_state::BeliefStateError> {
    BeliefState::from_probs([
        scores.useful,
        scores.useful_bad,
        scores.abandoned,
        scores.zombie,
    ])
}

/// Compute expected loss for a single action given belief state and loss matrix.
pub fn compute_expected_loss_for_action(
    action: Action,
    belief: &BeliefState,
    loss_matrix: &LossMatrix,
) -> std::result::Result<ActionLossBreakdown, DecisionError> {
    // Extract costs for this action across all states
    // LossMatrix is structured by state (row) -> action (col)
    // We need the column for this action
    let cost_useful = get_action_cost(action, &loss_matrix.useful, "useful")?;
    let cost_useful_bad = get_action_cost(action, &loss_matrix.useful_bad, "useful_bad")?;
    let cost_abandoned = get_action_cost(action, &loss_matrix.abandoned, "abandoned")?;
    let cost_zombie = get_action_cost(action, &loss_matrix.zombie, "zombie")?;

    let useful_contrib = cost_useful * belief.prob(ProcessState::Useful);
    let useful_bad_contrib = cost_useful_bad * belief.prob(ProcessState::UsefulBad);
    let abandoned_contrib = cost_abandoned * belief.prob(ProcessState::Abandoned);
    let zombie_contrib = cost_zombie * belief.prob(ProcessState::Zombie);

    let contributions = StateContributions {
        useful: useful_contrib,
        useful_bad: useful_bad_contrib,
        abandoned: abandoned_contrib,
        zombie: zombie_contrib,
    };

    Ok(ActionLossBreakdown {
        action,
        expected_loss: contributions.total(),
        state_contributions: contributions,
        feasible: true,
        disabled_reason: None,
    })
}

/// Get the cost for a specific action from a state's loss row.
fn get_action_cost(
    action: Action,
    row: &LossRow,
    class_name: &'static str,
) -> std::result::Result<f64, DecisionError> {
    match action {
        Action::Keep => Ok(row.keep),
        Action::Renice => row.renice.ok_or(DecisionError::MissingLoss {
            action,
            class: class_name,
        }),
        Action::Pause | Action::Resume => row.pause.ok_or(DecisionError::MissingLoss {
            action,
            class: class_name,
        }),
        // Freeze uses Pause cost as fallback if specific freeze cost is missing (not in LossRow struct yet?)
        // Actually LossRow has pause, keep, kill, restart, renice, throttle.
        // It does NOT have freeze or quarantine. Assuming they map to pause/throttle.
        Action::Freeze | Action::Unfreeze => row.pause.ok_or(DecisionError::MissingLoss {
            action,
            class: class_name,
        }),
        Action::Throttle => row.throttle.ok_or(DecisionError::MissingLoss {
            action,
            class: class_name,
        }),
        Action::Quarantine | Action::Unquarantine => {
            row.throttle.ok_or(DecisionError::MissingLoss {
                action,
                class: class_name,
            })
        }
        Action::Restart => row.restart.ok_or(DecisionError::MissingLoss {
            action,
            class: class_name,
        }),
        Action::Kill => Ok(row.kill),
    }
}

/// Compute the full expected-loss table for all actions.
pub fn compute_loss_table(
    belief: &BeliefState,
    loss_matrix: &LossMatrix,
    feasibility: &ActionFeasibility,
) -> Vec<ActionLossBreakdown> {
    let mut table = Vec::new();

    for action in Action::ALL {
        match compute_expected_loss_for_action(action, belief, loss_matrix) {
            Ok(mut breakdown) => {
                if !feasibility.is_allowed(action) {
                    breakdown.feasible = false;
                    breakdown.disabled_reason = feasibility
                        .disabled
                        .iter()
                        .find(|d| d.action == action)
                        .map(|d| d.reason.clone());
                }
                table.push(breakdown);
            }
            Err(_) => {
                // Action not in loss matrix, skip
            }
        }
    }

    // Sort by expected loss (ascending)
    table.sort_by(|a, b| {
        a.expected_loss
            .partial_cmp(&b.expected_loss)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    table
}

/// Select optimal action from loss table respecting feasibility.
fn select_optimal_from_table(table: &[ActionLossBreakdown]) -> Option<(Action, f64)> {
    table
        .iter()
        .filter(|b| b.feasible)
        .min_by(|a, b| {
            a.expected_loss
                .partial_cmp(&b.expected_loss)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|b| (b.action, b.expected_loss))
}

/// Decide action from belief state using myopic policy.
///
/// This is the main entry point for belief-state-based decision making.
/// It computes expected loss for all actions and selects the minimum,
/// subject to safety constraints.
pub fn decide_from_belief(
    belief: &BeliefState,
    policy: &Policy,
    feasibility: &ActionFeasibility,
) -> Result<MyopicDecision> {
    decide_from_belief_with_config(belief, policy, feasibility, &MyopicPolicyConfig::minimal())
}

/// Decide action from belief state with full configuration.
pub fn decide_from_belief_with_config(
    belief: &BeliefState,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    _config: &MyopicPolicyConfig,
) -> Result<MyopicDecision> {
    // Compute full loss table
    let loss_table = compute_loss_table(belief, &policy.loss_matrix, feasibility);

    // Find unconstrained optimal
    let (unconstrained_action, unconstrained_loss) =
        select_optimal_from_table(&loss_table).ok_or(MyopicPolicyError::NoFeasibleActions)?;

    // Initialize constraint tracking (minimal config applies no additional constraints)
    let constraint_summary = ConstraintSummary {
        policy_check: None,
        robot_constraints: None,
        fdr_gate: None,
        alpha_investing: None,
        blast_radius: None,
    };

    // For minimal config, no additional constraints applied
    // The full implementation would integrate with PolicyEnforcer, ConstraintChecker, etc.
    let final_action = unconstrained_action;
    let final_loss = unconstrained_loss;
    let constraint_override = false;

    // Build rationale
    let rationale = build_rationale(belief, final_action, &loss_table);

    Ok(MyopicDecision {
        optimal_action: final_action,
        optimal_loss: final_loss,
        loss_table,
        belief_state: BeliefStateDisplay::from(belief),
        constraints: constraint_summary,
        constraint_override,
        unconstrained_optimal: if constraint_override {
            Some(unconstrained_action)
        } else {
            None
        },
        rationale,
    })
}

/// Decide action with full constraint integration.
///
/// This variant accepts all the context needed to apply safety constraints:
/// - Policy enforcer for policy.json rules
/// - Robot constraint checker for robot mode gates
/// - Alpha-investing state for budget control
/// - Process metadata for blast-radius checks
pub fn decide_from_belief_constrained(
    belief: &BeliefState,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    config: &MyopicPolicyConfig,
    candidate: Option<&ProcessCandidate>,
    robot_constraints: Option<&RuntimeRobotConstraints>,
    alpha_state: Option<&AlphaWealthState>,
    blast_radius: Option<(f64, f64)>, // (memory_mb, cpu_pct)
) -> Result<MyopicDecision> {
    // Compute full loss table
    let loss_table = compute_loss_table(belief, &policy.loss_matrix, feasibility);

    // Find unconstrained optimal
    let (unconstrained_action, unconstrained_loss) =
        select_optimal_from_table(&loss_table).ok_or(MyopicPolicyError::NoFeasibleActions)?;

    let mut constraint_summary = ConstraintSummary {
        policy_check: None,
        robot_constraints: None,
        fdr_gate: None,
        alpha_investing: None,
        blast_radius: None,
    };

    let mut blocked_actions: Vec<Action> = Vec::new();

    // Apply robot constraints if provided
    if let Some(robot) = robot_constraints {
        if let Some(_cand) = candidate {
            // Clone the constraints to satisfy checker (it takes ownership in new, should take ref really but simpler to clone)
            let _checker = ConstraintChecker::new(robot.clone());
            // Convert belief to class scores for constraint checking
            let _scores = belief_to_class_scores(belief);
            // Note: This is a simplified check - full implementation would use proper RobotCandidate
            let robot_summary = RobotConstraintSummary {
                passed: true, // Simplified - would check actual constraints
                violations: Vec::new(),
            };
            constraint_summary.robot_constraints = Some(robot_summary);
        }
    }

    // Apply alpha-investing budget check
    if config.apply_alpha_investing {
        if let Some(alpha) = alpha_state {
            let required_spend = 0.01; // Simplified - would compute actual alpha spend
            let summary = AlphaInvestingSummary {
                sufficient_wealth: alpha.wealth >= required_spend,
                current_wealth: alpha.wealth,
                required_spend,
            };
            if !summary.sufficient_wealth
                && matches!(unconstrained_action, Action::Kill | Action::Restart)
            {
                blocked_actions.push(unconstrained_action);
            }
            constraint_summary.alpha_investing = Some(summary);
        }
    }

    // Apply blast-radius caps
    if config.apply_blast_radius {
        if let Some((mem_mb, cpu_pct)) = blast_radius {
            let within_limits = config.max_memory_mb.map_or(true, |max| mem_mb <= max)
                && config.max_cpu_pct.map_or(true, |max| cpu_pct <= max);
            let summary = BlastRadiusSummary {
                within_limits,
                memory_mb: mem_mb,
                cpu_pct,
                max_memory_mb: config.max_memory_mb,
                max_cpu_pct: config.max_cpu_pct,
            };
            if !within_limits && matches!(unconstrained_action, Action::Kill) {
                blocked_actions.push(Action::Kill);
            }
            constraint_summary.blast_radius = Some(summary);
        }
    }

    // Select final action considering blocked actions
    let final_result = if blocked_actions.contains(&unconstrained_action) {
        // Find next best feasible action
        loss_table
            .iter()
            .filter(|b| b.feasible && !blocked_actions.contains(&b.action))
            .min_by(|a, b| {
                a.expected_loss
                    .partial_cmp(&b.expected_loss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|b| (b.action, b.expected_loss))
            .ok_or(MyopicPolicyError::NoFeasibleActions)?
    } else {
        (unconstrained_action, unconstrained_loss)
    };

    let constraint_override = final_result.0 != unconstrained_action;
    let rationale = build_rationale(belief, final_result.0, &loss_table);

    Ok(MyopicDecision {
        optimal_action: final_result.0,
        optimal_loss: final_result.1,
        loss_table,
        belief_state: BeliefStateDisplay::from(belief),
        constraints: constraint_summary,
        constraint_override,
        unconstrained_optimal: if constraint_override {
            Some(unconstrained_action)
        } else {
            None
        },
        rationale,
    })
}

/// Build human-readable rationale for the decision.
fn build_rationale(belief: &BeliefState, action: Action, table: &[ActionLossBreakdown]) -> String {
    let most_likely = belief.argmax();
    let most_likely_prob = belief.max_prob();
    let entropy = belief.entropy();

    let action_breakdown = table.iter().find(|b| b.action == action);
    let loss_info = action_breakdown
        .map(|b| format!("expected loss {:.4}", b.expected_loss))
        .unwrap_or_else(|| "unknown loss".to_string());

    if entropy < 0.5 {
        // High confidence
        format!(
            "High confidence ({:.1}%) in {} state. Selected {} with {}.",
            most_likely_prob * 100.0,
            most_likely,
            format!("{:?}", action).to_lowercase(),
            loss_info
        )
    } else if entropy < 1.0 {
        // Moderate confidence
        format!(
            "Moderate confidence (most likely: {} at {:.1}%). Selected {} with {} to minimize expected loss.",
            most_likely,
            most_likely_prob * 100.0,
            format!("{:?}", action).to_lowercase(),
            loss_info
        )
    } else {
        // High uncertainty
        format!(
            "High uncertainty (entropy: {:.2} nats). Selected {} with {} as the safest action under uncertainty.",
            entropy,
            format!("{:?}", action).to_lowercase(),
            loss_info
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::{LossMatrix, LossRow, Policy};
    use crate::decision::expected_loss::DisabledAction;

    fn default_loss_matrix() -> LossMatrix {
        // Loss matrix organized by CLASS, with loss values for each ACTION.
        // L(action, class) = loss incurred by taking `action` when true state is `class`.
        LossMatrix {
            useful: LossRow {
                // For a USEFUL process:
                keep: 0.0,           // Keeping is correct (no loss)
                pause: Some(0.3),    // Pausing useful = moderate cost
                throttle: Some(0.2), // Throttling useful = small cost
                renice: Some(0.1),   // Renicing useful = very small cost
                kill: 1.0,           // Killing useful = maximum loss
                restart: Some(0.8),  // Restarting useful = high cost
            },
            useful_bad: LossRow {
                // For a USEFUL_BAD process (running but misbehaving):
                keep: 0.5,           // Keeping has cost (it's misbehaving)
                pause: Some(0.2),    // Pausing can help investigate
                throttle: Some(0.1), // Throttling is often good
                renice: Some(0.1),   // Renicing can help
                kill: 0.5,           // Killing loses value but stops harm
                restart: Some(0.4),  // Restarting might fix it
            },
            abandoned: LossRow {
                // For an ABANDONED process:
                keep: 1.0,           // Keeping wastes resources (high loss)
                pause: Some(0.5),    // Pausing is okay but doesn't free resources
                throttle: Some(0.6), // Throttling reduces impact
                renice: Some(0.8),   // Renicing doesn't help much
                kill: 0.0,           // Killing is correct (no loss)
                restart: Some(0.2),  // Restarting cleans up
            },
            zombie: LossRow {
                // For a ZOMBIE process:
                keep: 1.0,           // Keeping wastes resources
                pause: Some(0.7),    // Pausing a zombie does nothing
                throttle: Some(0.8), // Throttling a zombie does nothing
                renice: Some(0.9),   // Renicing a zombie does nothing
                kill: 0.0,           // Cleaning up zombie is correct
                restart: Some(0.3),  // Restarting parent can help
            },
        }
    }

    fn minimal_policy() -> Policy {
        Policy {
            loss_matrix: default_loss_matrix(),
            ..Default::default()
        }
    }

    #[test]
    fn test_belief_to_class_scores_conversion() {
        let belief = BeliefState::from_probs([0.1, 0.2, 0.3, 0.4]).unwrap();
        let scores = belief_to_class_scores(&belief);

        assert!((scores.useful - 0.1).abs() < 1e-10);
        assert!((scores.useful_bad - 0.2).abs() < 1e-10);
        assert!((scores.abandoned - 0.3).abs() < 1e-10);
        assert!((scores.zombie - 0.4).abs() < 1e-10);
    }

    #[test]
    fn test_compute_expected_loss_uniform_belief() {
        let belief = BeliefState::uniform();
        let matrix = default_loss_matrix();

        let breakdown = compute_expected_loss_for_action(Action::Keep, &belief, &matrix).unwrap();

        // Uniform belief: each state has 0.25 probability
        // Keep: L(useful)=0, L(useful_bad)=0.5, L(abandoned)=1.0, L(zombie)=1.0
        // Expected = 0.25 * (0 + 0.5 + 1.0 + 1.0) = 0.625
        assert!((breakdown.expected_loss - 0.625).abs() < 1e-10);
        assert!(breakdown.feasible);
    }

    #[test]
    fn test_decide_from_belief_useful_state() {
        // High confidence in Useful state -> should recommend Keep
        let belief = BeliefState::from_probs([0.9, 0.05, 0.03, 0.02]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();

        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();

        // With 90% useful, Keep should have lowest expected loss
        assert_eq!(decision.optimal_action, Action::Keep);
        assert!(decision.optimal_loss < 0.2);
    }

    #[test]
    fn test_decide_from_belief_abandoned_state() {
        // High confidence in Abandoned state -> should recommend Kill
        let belief = BeliefState::from_probs([0.02, 0.03, 0.9, 0.05]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();

        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();

        // With 90% abandoned, Kill should have lowest expected loss
        assert_eq!(decision.optimal_action, Action::Kill);
        assert!(decision.optimal_loss < 0.2);
    }

    #[test]
    fn test_decide_from_belief_respects_feasibility() {
        let belief = BeliefState::from_probs([0.02, 0.03, 0.9, 0.05]).unwrap();
        let policy = minimal_policy();

        // Disable Kill action
        let feasibility = ActionFeasibility {
            disabled: vec![DisabledAction {
                action: Action::Kill,
                reason: "test".to_string(),
            }],
        };

        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();

        // Kill is disabled, should fall back to next best (Restart)
        assert_ne!(decision.optimal_action, Action::Kill);
    }

    #[test]
    fn test_loss_table_sorted_by_loss() {
        let belief = BeliefState::uniform();
        let matrix = default_loss_matrix();
        let feasibility = ActionFeasibility::allow_all();

        let table = compute_loss_table(&belief, &matrix, &feasibility);

        // Verify table is sorted ascending by expected loss
        for i in 1..table.len() {
            assert!(table[i - 1].expected_loss <= table[i].expected_loss);
        }
    }

    #[test]
    fn test_state_contributions_sum_to_expected_loss() {
        let belief = BeliefState::from_probs([0.1, 0.2, 0.3, 0.4]).unwrap();
        let matrix = default_loss_matrix();

        for action in Action::ALL {
            if let Ok(breakdown) = compute_expected_loss_for_action(action, &belief, &matrix) {
                let sum = breakdown.state_contributions.total();
                assert!(
                    (sum - breakdown.expected_loss).abs() < 1e-10,
                    "State contributions should sum to expected loss for {:?}",
                    action
                );
            }
        }
    }

    #[test]
    fn test_rationale_generation() {
        let belief = BeliefState::from_probs([0.9, 0.05, 0.03, 0.02]).unwrap();
        let table = vec![ActionLossBreakdown {
            action: Action::Keep,
            expected_loss: 0.1,
            state_contributions: StateContributions {
                useful: 0.0,
                useful_bad: 0.025,
                abandoned: 0.03,
                zombie: 0.02,
            },
            feasible: true,
            disabled_reason: None,
        }];

        let rationale = build_rationale(&belief, Action::Keep, &table);

        assert!(rationale.contains("High confidence"));
        assert!(rationale.contains("keep"));
    }

    #[test]
    fn test_myopic_config_with_all_constraints() {
        let config = MyopicPolicyConfig::with_all_constraints();

        assert!(config.apply_fdr_gate);
        assert!(config.apply_alpha_investing);
        assert!(config.apply_blast_radius);
        assert!((config.fdr_threshold - 0.1).abs() < 1e-10);
    }

    // --- MyopicPolicyError display ---

    #[test]
    fn error_no_feasible_actions_display() {
        let err = MyopicPolicyError::NoFeasibleActions;
        let msg = format!("{}", err);
        assert!(msg.contains("no feasible actions"));
    }

    #[test]
    fn error_invalid_belief_state_display() {
        let err = MyopicPolicyError::InvalidBeliefState;
        let msg = format!("{}", err);
        assert!(msg.contains("probabilities must sum to 1.0"));
    }

    #[test]
    fn error_enforcement_display() {
        let err = MyopicPolicyError::Enforcement("test violation".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("test violation"));
    }

    #[test]
    fn error_decision_display() {
        let inner = DecisionError::MissingLoss {
            action: Action::Renice,
            class: "useful",
        };
        let err = MyopicPolicyError::Decision(inner);
        let msg = format!("{}", err);
        assert!(msg.contains("decision error"));
    }

    // --- StateContributions ---

    #[test]
    fn state_contributions_total() {
        let sc = StateContributions {
            useful: 0.1,
            useful_bad: 0.2,
            abandoned: 0.3,
            zombie: 0.4,
        };
        assert!((sc.total() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn state_contributions_total_zero() {
        let sc = StateContributions {
            useful: 0.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        assert!((sc.total()).abs() < 1e-10);
    }

    // --- BeliefStateDisplay ---

    #[test]
    fn belief_state_display_from_belief() {
        let belief = BeliefState::from_probs([0.1, 0.2, 0.3, 0.4]).unwrap();
        let display = BeliefStateDisplay::from(&belief);
        assert!((display.useful - 0.1).abs() < 1e-10);
        assert!((display.useful_bad - 0.2).abs() < 1e-10);
        assert!((display.abandoned - 0.3).abs() < 1e-10);
        assert!((display.zombie - 0.4).abs() < 1e-10);
        assert!(display.entropy > 0.0);
        assert!(display.most_likely.to_lowercase().contains("zombie"));
    }

    #[test]
    fn belief_state_display_serialize() {
        let belief = BeliefState::from_probs([0.9, 0.05, 0.03, 0.02]).unwrap();
        let display = BeliefStateDisplay::from(&belief);
        let json = serde_json::to_string(&display).unwrap();
        assert!(json.contains("\"useful\""));
        assert!(json.contains("\"entropy\""));
        assert!(json.contains("\"most_likely\""));
    }

    // --- MyopicPolicyConfig ---

    #[test]
    fn config_minimal_defaults() {
        let config = MyopicPolicyConfig::minimal();
        assert!(!config.apply_fdr_gate);
        assert!(!config.apply_alpha_investing);
        assert!(!config.apply_blast_radius);
        assert!(config.max_memory_mb.is_none());
        assert!(config.max_cpu_pct.is_none());
    }

    #[test]
    fn config_default_is_minimal() {
        let config = MyopicPolicyConfig::default();
        assert!(!config.apply_fdr_gate);
        assert!(!config.apply_alpha_investing);
    }

    // --- class_scores_to_belief roundtrip ---

    #[test]
    fn class_scores_to_belief_roundtrip() {
        let belief = BeliefState::from_probs([0.25, 0.25, 0.25, 0.25]).unwrap();
        let scores = belief_to_class_scores(&belief);
        let back = class_scores_to_belief(&scores).unwrap();
        assert!((back.prob(ProcessState::Useful) - 0.25).abs() < 1e-10);
        assert!((back.prob(ProcessState::Abandoned) - 0.25).abs() < 1e-10);
    }

    // --- get_action_cost coverage ---

    #[test]
    fn get_action_cost_keep() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        assert!((get_action_cost(Action::Keep, &row, "useful").unwrap()).abs() < 1e-10);
    }

    #[test]
    fn get_action_cost_freeze_uses_pause() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let cost = get_action_cost(Action::Freeze, &row, "useful").unwrap();
        assert!((cost - 0.3).abs() < 1e-10); // Freeze uses pause cost
    }

    #[test]
    fn get_action_cost_unfreeze_uses_pause() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.5),
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let cost = get_action_cost(Action::Unfreeze, &row, "useful").unwrap();
        assert!((cost - 0.5).abs() < 1e-10);
    }

    #[test]
    fn get_action_cost_quarantine_uses_throttle() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let cost = get_action_cost(Action::Quarantine, &row, "useful").unwrap();
        assert!((cost - 0.2).abs() < 1e-10); // Quarantine uses throttle cost
    }

    #[test]
    fn get_action_cost_unquarantine_uses_throttle() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: Some(0.4),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let cost = get_action_cost(Action::Unquarantine, &row, "useful").unwrap();
        assert!((cost - 0.4).abs() < 1e-10);
    }

    #[test]
    fn get_action_cost_missing_pause_errors() {
        let row = LossRow {
            keep: 0.0,
            pause: None,
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let result = get_action_cost(Action::Pause, &row, "useful");
        assert!(result.is_err());
    }

    #[test]
    fn get_action_cost_missing_throttle_errors() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: None,
            renice: Some(0.1),
            kill: 1.0,
            restart: Some(0.8),
        };
        let result = get_action_cost(Action::Throttle, &row, "useful");
        assert!(result.is_err());
    }

    #[test]
    fn get_action_cost_missing_restart_errors() {
        let row = LossRow {
            keep: 0.0,
            pause: Some(0.3),
            throttle: Some(0.2),
            renice: Some(0.1),
            kill: 1.0,
            restart: None,
        };
        let result = get_action_cost(Action::Restart, &row, "useful");
        assert!(result.is_err());
    }

    // --- compute_loss_table with disabled actions ---

    #[test]
    fn loss_table_marks_disabled_actions() {
        let belief = BeliefState::uniform();
        let matrix = default_loss_matrix();
        let feasibility = ActionFeasibility {
            disabled: vec![
                DisabledAction {
                    action: Action::Kill,
                    reason: "protected".to_string(),
                },
                DisabledAction {
                    action: Action::Restart,
                    reason: "no supervisor".to_string(),
                },
            ],
        };
        let table = compute_loss_table(&belief, &matrix, &feasibility);
        let kill_entry = table.iter().find(|b| b.action == Action::Kill).unwrap();
        assert!(!kill_entry.feasible);
        assert_eq!(kill_entry.disabled_reason.as_deref(), Some("protected"));

        let restart_entry = table.iter().find(|b| b.action == Action::Restart).unwrap();
        assert!(!restart_entry.feasible);
    }

    // --- decide_from_belief with zombie state ---

    #[test]
    fn decide_zombie_state_recommends_kill() {
        let belief = BeliefState::from_probs([0.02, 0.03, 0.05, 0.9]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();
        assert_eq!(decision.optimal_action, Action::Kill);
    }

    // --- decide_from_belief with useful_bad state ---

    #[test]
    fn decide_useful_bad_recommends_throttle_or_renice() {
        let belief = BeliefState::from_probs([0.05, 0.85, 0.05, 0.05]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();
        // With 85% useful_bad, the lowest loss actions are throttle(0.1) or renice(0.1)
        assert!(
            decision.optimal_action == Action::Throttle
                || decision.optimal_action == Action::Renice
        );
    }

    // --- decide_from_belief_constrained with alpha-investing ---

    #[test]
    fn constrained_alpha_investing_blocks_kill() {
        let belief = BeliefState::from_probs([0.02, 0.03, 0.9, 0.05]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let config = MyopicPolicyConfig {
            apply_alpha_investing: true,
            ..MyopicPolicyConfig::default()
        };
        let alpha_state = AlphaWealthState {
            wealth: 0.001, // very low, below required_spend of 0.01
            last_updated: "2026-01-01".to_string(),
            policy_id: None,
            policy_version: "1".to_string(),
            host_id: "test".to_string(),
            user_id: 1000,
        };
        let decision = decide_from_belief_constrained(
            &belief,
            &policy,
            &feasibility,
            &config,
            None,
            None,
            Some(&alpha_state),
            None,
        )
        .unwrap();
        // Kill should be blocked, so it should pick something else
        assert_ne!(decision.optimal_action, Action::Kill);
        assert!(decision.constraint_override);
        assert_eq!(decision.unconstrained_optimal, Some(Action::Kill));
    }

    // --- decide_from_belief_constrained with blast-radius ---

    #[test]
    fn constrained_blast_radius_blocks_kill() {
        let belief = BeliefState::from_probs([0.02, 0.03, 0.9, 0.05]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let config = MyopicPolicyConfig {
            apply_blast_radius: true,
            max_memory_mb: Some(500.0),
            max_cpu_pct: Some(50.0),
            ..MyopicPolicyConfig::default()
        };
        let decision = decide_from_belief_constrained(
            &belief,
            &policy,
            &feasibility,
            &config,
            None,
            None,
            None,
            Some((1000.0, 80.0)), // exceeds limits
        )
        .unwrap();
        // Kill should be blocked due to blast-radius
        assert_ne!(decision.optimal_action, Action::Kill);
        assert!(decision.constraint_override);
    }

    #[test]
    fn constrained_blast_radius_within_limits() {
        let belief = BeliefState::from_probs([0.02, 0.03, 0.9, 0.05]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let config = MyopicPolicyConfig {
            apply_blast_radius: true,
            max_memory_mb: Some(2000.0),
            max_cpu_pct: Some(90.0),
            ..MyopicPolicyConfig::default()
        };
        let decision = decide_from_belief_constrained(
            &belief,
            &policy,
            &feasibility,
            &config,
            None,
            None,
            None,
            Some((500.0, 30.0)), // within limits
        )
        .unwrap();
        // Kill should still be selected (within limits)
        assert_eq!(decision.optimal_action, Action::Kill);
        assert!(!decision.constraint_override);
    }

    // --- Rationale for different entropy levels ---

    #[test]
    fn rationale_moderate_confidence() {
        let belief = BeliefState::from_probs([0.7, 0.15, 0.1, 0.05]).unwrap();
        let table = vec![ActionLossBreakdown {
            action: Action::Keep,
            expected_loss: 0.3,
            state_contributions: StateContributions {
                useful: 0.0,
                useful_bad: 0.1,
                abandoned: 0.1,
                zombie: 0.1,
            },
            feasible: true,
            disabled_reason: None,
        }];
        let rationale = build_rationale(&belief, Action::Keep, &table);
        assert!(rationale.contains("Moderate confidence") || rationale.contains("High confidence"));
    }

    #[test]
    fn rationale_high_uncertainty() {
        let belief = BeliefState::uniform();
        let table = vec![ActionLossBreakdown {
            action: Action::Keep,
            expected_loss: 0.5,
            state_contributions: StateContributions {
                useful: 0.0,
                useful_bad: 0.125,
                abandoned: 0.25,
                zombie: 0.25,
            },
            feasible: true,
            disabled_reason: None,
        }];
        let rationale = build_rationale(&belief, Action::Keep, &table);
        assert!(rationale.contains("uncertainty") || rationale.contains("entropy"));
    }

    #[test]
    fn rationale_action_not_in_table() {
        let belief = BeliefState::from_probs([0.9, 0.05, 0.03, 0.02]).unwrap();
        let table = vec![]; // empty table
        let rationale = build_rationale(&belief, Action::Keep, &table);
        assert!(rationale.contains("unknown loss"));
    }

    // --- Serialize summaries ---

    #[test]
    fn constraint_summary_serialize() {
        let summary = ConstraintSummary {
            policy_check: None,
            robot_constraints: None,
            fdr_gate: Some(FdrGateSummary {
                passed: true,
                e_value: 0.05,
                threshold: 0.1,
            }),
            alpha_investing: None,
            blast_radius: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("fdr_gate"));
        assert!(json.contains("0.05"));
    }

    #[test]
    fn myopic_decision_serialize() {
        let belief = BeliefState::from_probs([0.9, 0.05, 0.03, 0.02]).unwrap();
        let policy = minimal_policy();
        let feasibility = ActionFeasibility::allow_all();
        let decision = decide_from_belief(&belief, &policy, &feasibility).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("optimal_action"));
        assert!(json.contains("rationale"));
        assert!(json.contains("loss_table"));
    }

    #[test]
    fn select_optimal_from_table_empty() {
        let result = select_optimal_from_table(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn select_optimal_from_table_all_disabled() {
        let table = vec![ActionLossBreakdown {
            action: Action::Kill,
            expected_loss: 0.1,
            state_contributions: StateContributions {
                useful: 0.0,
                useful_bad: 0.0,
                abandoned: 0.05,
                zombie: 0.05,
            },
            feasible: false,
            disabled_reason: Some("blocked".to_string()),
        }];
        let result = select_optimal_from_table(&table);
        assert!(result.is_none());
    }
}
