//! Multi-objective kill set optimization for goal-oriented plans.
//!
//! Selects a set of actions that achieves user resource goals with minimal
//! expected risk, respecting safety constraints (protected processes, blast
//! radius limits, FDR budgets).
//!
//! # Algorithms
//!
//! - **Greedy**: Sort by efficiency (contribution/loss), select greedily.
//! - **DP-exact**: Dynamic programming for small candidate sets (N ≤ 30).
//! - **Local search**: Swap-based improvement on greedy solutions.
//!
//! When goals are infeasible, reports the shortfall and best-effort plan.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;

/// A resource goal the user wants to achieve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGoal {
    /// Resource type (e.g., "memory_mb", "cpu_pct", "port", "fd_count").
    pub resource: String,
    /// Target amount to free/reclaim.
    pub target: f64,
    /// Weight for multi-goal scalarization (higher = more important).
    pub weight: f64,
}

/// An action candidate for the optimizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptCandidate {
    /// Unique identifier (e.g., PID or identity hash).
    pub id: String,
    /// Expected loss of taking the kill action.
    pub expected_loss: f64,
    /// Expected resource contributions per goal resource type.
    pub contributions: Vec<f64>,
    /// Whether this candidate is blocked by safety constraints.
    pub blocked: bool,
    /// Reason for blocking (if blocked).
    pub block_reason: Option<String>,
}

/// A selected action in the optimized plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedAction {
    /// Candidate ID.
    pub id: String,
    /// Expected loss.
    pub expected_loss: f64,
    /// Contributions toward each goal.
    pub contributions: Vec<f64>,
}

/// Result of optimization: the chosen plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationResult {
    /// Selected actions.
    pub selected: Vec<SelectedAction>,
    /// Total expected loss.
    pub total_loss: f64,
    /// Total contribution toward each goal.
    pub total_contributions: Vec<f64>,
    /// Per-goal: how much of the target is achieved.
    pub goal_achievement: Vec<GoalAchievement>,
    /// Whether all goals are met.
    pub feasible: bool,
    /// Algorithm used.
    pub algorithm: String,
    /// Alternative plans (Pareto tradeoffs).
    pub alternatives: Vec<AlternativePlan>,
    /// Structured optimization log events.
    pub log_events: Vec<OptimizationLogEvent>,
}

/// Achievement status for a single goal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalAchievement {
    /// Resource name.
    pub resource: String,
    /// Target value.
    pub target: f64,
    /// Achieved value.
    pub achieved: f64,
    /// Shortfall (target - achieved), 0 if met.
    pub shortfall: f64,
    /// Whether this goal is met.
    pub met: bool,
}

/// An alternative plan showing a different tradeoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativePlan {
    /// Description of the tradeoff.
    pub description: String,
    /// Number of actions.
    pub action_count: usize,
    /// Total expected loss.
    pub total_loss: f64,
    /// Goal achievements.
    pub goal_achievement: Vec<GoalAchievement>,
}

/// Structured log event emitted by optimizers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationLogEvent {
    pub event: String,
    pub algorithm: String,
    pub candidate_id: Option<String>,
    pub loss: Option<f64>,
    pub score: Option<f64>,
    pub total_loss: Option<f64>,
    pub total_contributions: Vec<f64>,
    pub target: Option<f64>,
    pub current_contribution: Option<f64>,
    pub remaining_max: Option<f64>,
    pub note: Option<String>,
}

impl OptimizationLogEvent {
    fn new(event: &str, algorithm: &str) -> Self {
        Self {
            event: event.to_string(),
            algorithm: algorithm.to_string(),
            candidate_id: None,
            loss: None,
            score: None,
            total_loss: None,
            total_contributions: Vec::new(),
            target: None,
            current_contribution: None,
            remaining_max: None,
            note: None,
        }
    }
}

/// Result of checking whether to re-optimize after candidate set changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReoptimizationDecision {
    pub reoptimized: bool,
    pub reason: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub result: OptimizationResult,
}

/// User preference model (risk tolerance) learned from plan choices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceModel {
    /// Risk tolerance in [0,1]. 0 = conservative, 1 = aggressive.
    pub risk_tolerance: f64,
    /// Learning rate for preference updates.
    pub learning_rate: f64,
}

impl Default for PreferenceModel {
    fn default() -> Self {
        Self {
            risk_tolerance: 0.5,
            learning_rate: 0.2,
        }
    }
}

/// Result of a preference update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceUpdate {
    pub prior: f64,
    pub observed: f64,
    pub updated: f64,
}

impl PreferenceModel {
    /// Update preference model from a chosen alternative plan.
    pub fn update_from_choice(
        &mut self,
        chosen: &AlternativePlan,
        alternatives: &[AlternativePlan],
    ) -> PreferenceUpdate {
        let prior = self.risk_tolerance.clamp(0.0, 1.0);
        let (min_loss, max_loss) = alternatives
            .iter()
            .fold((f64::INFINITY, f64::NEG_INFINITY), |(min, max), alt| {
                (min.min(alt.total_loss), max.max(alt.total_loss))
            });
        let observed = if max_loss > min_loss {
            (chosen.total_loss - min_loss) / (max_loss - min_loss)
        } else {
            0.5
        };
        let updated = (prior * (1.0 - self.learning_rate)
            + observed * self.learning_rate)
            .clamp(0.0, 1.0);
        self.risk_tolerance = updated;
        PreferenceUpdate {
            prior,
            observed,
            updated,
        }
    }

    /// Adjust loss based on risk tolerance (penalize higher loss for conservative users).
    pub fn adjust_loss(&self, loss: f64) -> f64 {
        let risk = self.risk_tolerance.clamp(0.0, 1.0);
        let exponent = 1.0 + (1.0 - risk);
        loss.powf(exponent).max(1e-12)
    }
}

/// Greedy optimization: sort by efficiency, select until goals met.
pub fn optimize_greedy(candidates: &[OptCandidate], goals: &[ResourceGoal]) -> OptimizationResult {
    optimize_greedy_internal(candidates, goals, None, "greedy")
}

/// Greedy optimization with a user preference model applied to loss sensitivity.
pub fn optimize_greedy_with_preferences(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    prefs: &PreferenceModel,
) -> OptimizationResult {
    optimize_greedy_internal(candidates, goals, Some(prefs), "greedy_pref")
}

fn optimize_greedy_internal(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    prefs: Option<&PreferenceModel>,
    algorithm_label: &str,
) -> OptimizationResult {
    let mut log_events = Vec::new();
    let mut start_event = OptimizationLogEvent::new("optimizer_start", algorithm_label);
    start_event.note = Some(format!("candidates={} goals={}", candidates.len(), goals.len()));
    log_events.push(start_event);

    let adjust_loss = |loss: f64| prefs.map_or(loss, |p| p.adjust_loss(loss));

    if candidates.is_empty() {
        let goal_achievement: Vec<GoalAchievement> = goals
            .iter()
            .map(|g| GoalAchievement {
                resource: g.resource.clone(),
                target: g.target,
                achieved: 0.0,
                shortfall: g.target,
                met: g.target <= 0.0,
            })
            .collect();
        return OptimizationResult {
            selected: Vec::new(),
            total_loss: 0.0,
            total_contributions: vec![0.0; goals.len()],
            goal_achievement,
            feasible: goals.iter().all(|g| g.target <= 0.0),
            algorithm: algorithm_label.to_string(),
            alternatives: Vec::new(),
            log_events,
        };
    }

    assert_eq!(
        goals.len(),
        candidates[0].contributions.len(),
        "Contribution vector length must match number of goals"
    );

    // Filter out blocked candidates.
    let mut eligible: Vec<(usize, &OptCandidate)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.blocked && c.expected_loss >= 0.0)
        .collect();
    let blocked_count = candidates.iter().filter(|c| c.blocked).count();
    if blocked_count > 0 {
        let mut event = OptimizationLogEvent::new("constraint_violation", algorithm_label);
        event.note = Some(format!("blocked_candidates={}", blocked_count));
        log_events.push(event);
    }

    // Compute scalarized efficiency: weighted_contribution / adjusted_loss.
    let scalarize = |c: &OptCandidate| -> f64 {
        let weighted_contrib: f64 = c
            .contributions
            .iter()
            .zip(goals.iter())
            .map(|(contrib, goal)| contrib * goal.weight)
            .sum();
        let loss = adjust_loss(c.expected_loss);
        if loss > 1e-15 {
            weighted_contrib / loss
        } else {
            weighted_contrib * 1e10 // Free lunch: near-zero loss
        }
    };

    eligible.sort_by(|a, b| {
        scalarize(b.1)
            .partial_cmp(&scalarize(a.1))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut selected = Vec::new();
    let mut remaining_targets: Vec<f64> = goals.iter().map(|g| g.target).collect();
    let mut total_loss = 0.0;

    for (_, cand) in &eligible {
        // Check if all goals are already met.
        if remaining_targets.iter().all(|t| *t <= 0.0) {
            break;
        }

        let mut eval = OptimizationLogEvent::new("objective_eval", algorithm_label);
        eval.candidate_id = Some(cand.id.clone());
        eval.loss = Some(cand.expected_loss);
        eval.score = Some(scalarize(cand));
        eval.total_contributions = cand.contributions.clone();
        log_events.push(eval);

        selected.push(SelectedAction {
            id: cand.id.clone(),
            expected_loss: cand.expected_loss,
            contributions: cand.contributions.clone(),
        });

        total_loss += cand.expected_loss;
        for (i, contrib) in cand.contributions.iter().enumerate() {
            remaining_targets[i] -= contrib;
        }
    }

    let total_contributions: Vec<f64> = (0..goals.len())
        .map(|i| goals[i].target - remaining_targets[i])
        .collect();

    let goal_achievement: Vec<GoalAchievement> = goals
        .iter()
        .zip(total_contributions.iter())
        .zip(remaining_targets.iter())
        .map(|((goal, achieved), remaining)| GoalAchievement {
            resource: goal.resource.clone(),
            target: goal.target,
            achieved: *achieved,
            shortfall: remaining.max(0.0),
            met: *remaining <= 0.0,
        })
        .collect();

    let feasible = goal_achievement.iter().all(|g| g.met);

    // Generate alternatives: fewer actions (conservative), more actions (aggressive).
    let alternatives = generate_alternatives(&selected, goals, &eligible, &mut log_events);
    let mut converged = OptimizationLogEvent::new("converged", algorithm_label);
    converged.total_loss = Some(total_loss);
    converged.total_contributions = total_contributions.clone();
    log_events.push(converged);

    OptimizationResult {
        selected,
        total_loss,
        total_contributions,
        goal_achievement,
        feasible,
        algorithm: algorithm_label.to_string(),
        alternatives,
        log_events,
    }
}

/// DP-exact optimization for small candidate sets.
///
/// Uses a pseudo-polynomial DP on discretized goal space.
/// Only practical for small N (≤ 30) and single goal.
pub fn optimize_dp(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    resolution: f64,
) -> OptimizationResult {
    let mut log_events = Vec::new();
    let mut start_event = OptimizationLogEvent::new("optimizer_start", "dp_exact");
    start_event.note = Some(format!(
        "candidates={} goals={} resolution={}",
        candidates.len(),
        goals.len(),
        resolution
    ));
    log_events.push(start_event);

    // Only supports single-goal for DP.
    if goals.len() != 1 || candidates.is_empty() {
        let mut greedy = optimize_greedy(candidates, goals);
        greedy.algorithm = "dp_exact (unsupported, greedy fallback)".to_string();
        greedy.log_events.extend(log_events);
        return greedy;
    }

    let eligible: Vec<&OptCandidate> = candidates
        .iter()
        .filter(|c| !c.blocked && c.expected_loss >= 0.0)
        .collect();

    if eligible.len() > 30 {
        let mut greedy = optimize_greedy(candidates, goals);
        greedy.algorithm = "dp_exact (too_many_candidates, greedy fallback)".to_string();
        greedy.log_events.extend(log_events);
        return greedy;
    }

    let target = goals[0].target;
    let max_steps = (target / resolution).ceil() as usize + 1;

    // dp[j] = minimum loss to achieve at least j*resolution contribution.
    let mut dp = vec![f64::INFINITY; max_steps + 1];
    let mut dp_selection: Vec<HashSet<usize>> = vec![HashSet::new(); max_steps + 1];
    dp[0] = 0.0;

    for (idx, cand) in eligible.iter().enumerate() {
        let contrib_steps = (cand.contributions[0] / resolution).ceil() as usize;
        // Iterate backwards (0-1 knapsack).
        for j in (0..=max_steps).rev() {
            let new_j = (j + contrib_steps).min(max_steps);
            let new_loss = dp[j] + cand.expected_loss;
            if new_loss < dp[new_j] {
                dp[new_j] = new_loss;
                let mut sel = dp_selection[j].clone();
                sel.insert(idx);
                dp_selection[new_j] = sel;
            }
        }
    }

    // Find the best solution that meets the target.
    let target_step = (target / resolution).ceil() as usize;
    let best_j = (target_step..=max_steps).min_by(|a, b| {
        dp[*a]
            .partial_cmp(&dp[*b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let (selected, total_loss) = match best_j {
        Some(j) if dp[j] < f64::INFINITY => {
            let sel: Vec<SelectedAction> = dp_selection[j]
                .iter()
                .map(|&idx| {
                    let c = eligible[idx];
                    SelectedAction {
                        id: c.id.clone(),
                        expected_loss: c.expected_loss,
                        contributions: c.contributions.clone(),
                    }
                })
                .collect();
            let loss = dp[j];
            (sel, loss)
        }
        _ => {
            // Infeasible; fall back to greedy best-effort.
            let mut greedy = optimize_greedy(candidates, goals);
            let mut event = OptimizationLogEvent::new("constraint_violation", "dp_exact");
            event.note = Some("dp_infeasible".to_string());
            log_events.push(event);
            greedy.algorithm = "dp_exact (infeasible, greedy fallback)".to_string();
            greedy.log_events.extend(log_events);
            return greedy;
        }
    };

    let total_contributions: Vec<f64> = vec![selected.iter().map(|s| s.contributions[0]).sum()];

    let achieved = total_contributions[0];
    let goal_achievement = vec![GoalAchievement {
        resource: goals[0].resource.clone(),
        target,
        achieved,
        shortfall: (target - achieved).max(0.0),
        met: achieved >= target,
    }];

    OptimizationResult {
        selected,
        total_loss,
        total_contributions,
        goal_achievement,
        feasible: achieved >= target,
        algorithm: "dp_exact".to_string(),
        alternatives: Vec::new(),
        log_events,
    }
}

/// ILP-style exact optimization via branch-and-bound (single goal).
///
/// Uses constraint propagation to prune infeasible branches: if the remaining
/// maximum possible contribution cannot reach the target, the branch is cut.
pub fn optimize_ilp(candidates: &[OptCandidate], goals: &[ResourceGoal]) -> OptimizationResult {
    let mut log_events = Vec::new();
    let mut start_event = OptimizationLogEvent::new("optimizer_start", "ilp_branch_bound");
    start_event.note = Some(format!("candidates={} goals={}", candidates.len(), goals.len()));
    log_events.push(start_event);

    if goals.len() != 1 || candidates.is_empty() {
        let mut greedy = optimize_greedy(candidates, goals);
        greedy.algorithm = "ilp_branch_bound (unsupported, greedy fallback)".to_string();
        greedy.log_events.extend(log_events);
        return greedy;
    }

    let eligible: Vec<&OptCandidate> = candidates
        .iter()
        .filter(|c| !c.blocked && c.expected_loss >= 0.0)
        .collect();

    if eligible.is_empty() {
        let mut greedy = optimize_greedy(candidates, goals);
        greedy.algorithm = "ilp_branch_bound (no_candidates, greedy fallback)".to_string();
        greedy.log_events.extend(log_events);
        return greedy;
    }

    let target = goals[0].target;
    let mut ordered = eligible;
    ordered.sort_by(|a, b| {
        pareto_efficiency(b, goals)
            .partial_cmp(&pareto_efficiency(a, goals))
            .unwrap_or(Ordering::Equal)
    });

    let n = ordered.len();
    let mut suffix_max = vec![0.0; n + 1];
    for i in (0..n).rev() {
        suffix_max[i] = suffix_max[i + 1] + ordered[i].contributions[0];
    }

    let mut best_loss = f64::INFINITY;
    let mut best_selection: Vec<usize> = Vec::new();
    let mut current: Vec<usize> = Vec::new();

    fn dfs(
        idx: usize,
        ordered: &[&OptCandidate],
        target: f64,
        suffix_max: &[f64],
        current_loss: f64,
        current_contrib: f64,
        current: &mut Vec<usize>,
        best_loss: &mut f64,
        best_selection: &mut Vec<usize>,
        log_events: &mut Vec<OptimizationLogEvent>,
    ) {
        if current_contrib >= target {
            if current_loss < *best_loss {
                *best_loss = current_loss;
                *best_selection = current.clone();
                let mut event = OptimizationLogEvent::new("objective_improved", "ilp_branch_bound");
                event.total_loss = Some(current_loss);
                event.current_contribution = Some(current_contrib);
                event.target = Some(target);
                log_events.push(event);
            }
            return;
        }

        if idx >= ordered.len() {
            return;
        }

        if current_loss >= *best_loss {
            return;
        }

        if current_contrib + suffix_max[idx] < target {
            let mut event = OptimizationLogEvent::new("constraint_prune", "ilp_branch_bound");
            event.current_contribution = Some(current_contrib);
            event.remaining_max = Some(suffix_max[idx]);
            event.target = Some(target);
            log_events.push(event);
            return;
        }

        // Include candidate.
        current.push(idx);
        dfs(
            idx + 1,
            ordered,
            target,
            suffix_max,
            current_loss + ordered[idx].expected_loss,
            current_contrib + ordered[idx].contributions[0],
            current,
            best_loss,
            best_selection,
            log_events,
        );
        current.pop();

        // Exclude candidate.
        dfs(
            idx + 1,
            ordered,
            target,
            suffix_max,
            current_loss,
            current_contrib,
            current,
            best_loss,
            best_selection,
            log_events,
        );
    }

    dfs(
        0,
        &ordered,
        target,
        &suffix_max,
        0.0,
        0.0,
        &mut current,
        &mut best_loss,
        &mut best_selection,
        &mut log_events,
    );

    if best_loss == f64::INFINITY {
        let mut greedy = optimize_greedy(candidates, goals);
        let mut event = OptimizationLogEvent::new("constraint_violation", "ilp_branch_bound");
        event.note = Some("ilp_infeasible".to_string());
        log_events.push(event);
        greedy.algorithm = "ilp_branch_bound (infeasible, greedy fallback)".to_string();
        greedy.log_events.extend(log_events);
        return greedy;
    }

    let selected: Vec<SelectedAction> = best_selection
        .iter()
        .map(|&idx| {
            let c = ordered[idx];
            SelectedAction {
                id: c.id.clone(),
                expected_loss: c.expected_loss,
                contributions: c.contributions.clone(),
            }
        })
        .collect();

    let total_contributions = vec![selected.iter().map(|s| s.contributions[0]).sum()];
    let achieved = total_contributions[0];
    let goal_achievement = vec![GoalAchievement {
        resource: goals[0].resource.clone(),
        target,
        achieved,
        shortfall: (target - achieved).max(0.0),
        met: achieved >= target,
    }];

    OptimizationResult {
        selected,
        total_loss: best_loss,
        total_contributions,
        goal_achievement,
        feasible: achieved >= target,
        algorithm: "ilp_branch_bound".to_string(),
        alternatives: Vec::new(),
        log_events,
    }
}

/// Re-optimize when the candidate set changes materially.
///
/// Returns the previous plan if changes are minor; otherwise recomputes.
pub fn reoptimize_on_change(
    previous: &OptimizationResult,
    prev_candidates: &[OptCandidate],
    new_candidates: &[OptCandidate],
    goals: &[ResourceGoal],
) -> ReoptimizationDecision {
    const CHURN_THRESHOLD: f64 = 0.2;

    let prev_ids: HashSet<&str> = prev_candidates.iter().map(|c| c.id.as_str()).collect();
    let new_ids: HashSet<&str> = new_candidates.iter().map(|c| c.id.as_str()).collect();

    let mut added: Vec<String> = new_ids
        .iter()
        .filter(|id| !prev_ids.contains(*id))
        .map(|id| (*id).to_string())
        .collect();
    let mut removed: Vec<String> = prev_ids
        .iter()
        .filter(|id| !new_ids.contains(*id))
        .map(|id| (*id).to_string())
        .collect();
    added.sort();
    removed.sort();

    let missing_selected: Vec<String> = previous
        .selected
        .iter()
        .filter(|s| !new_ids.contains(s.id.as_str()))
        .map(|s| s.id.clone())
        .collect();

    let reopt_reason = if added.is_empty() && removed.is_empty() {
        "no_change".to_string()
    } else if !missing_selected.is_empty() {
        "selected_missing".to_string()
    } else if prev_ids.is_empty() {
        "prev_empty".to_string()
    } else {
        let churn = (added.len() + removed.len()) as f64 / prev_ids.len() as f64;
        if churn >= CHURN_THRESHOLD {
            "churn_threshold".to_string()
        } else {
            "stable".to_string()
        }
    };

    if matches!(reopt_reason.as_str(), "stable" | "no_change") {
        let mut result = previous.clone();
        let mut event = OptimizationLogEvent::new("reopt_skip", "reopt");
        event.note = Some(reopt_reason.clone());
        event.total_loss = Some(result.total_loss);
        event.total_contributions = result.total_contributions.clone();
        result.log_events.push(event);
        return ReoptimizationDecision {
            reoptimized: false,
            reason: reopt_reason,
            added,
            removed,
            result,
        };
    }

    let mut result = if goals.len() == 1 {
        optimize_ilp(new_candidates, goals)
    } else {
        optimize_greedy(new_candidates, goals)
    };

    let mut event = OptimizationLogEvent::new("reoptimized", "reopt");
    event.note = Some(reopt_reason.clone());
    event.total_loss = Some(result.total_loss);
    event.total_contributions = result.total_contributions.clone();
    result.log_events.push(event);

    ReoptimizationDecision {
        reoptimized: true,
        reason: reopt_reason,
        added,
        removed,
        result,
    }
}

/// Local search improvement: try pairwise swaps to reduce loss.
pub fn local_search_improve(
    result: &mut OptimizationResult,
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    max_iterations: usize,
) {
    let eligible: Vec<&OptCandidate> = candidates.iter().filter(|c| !c.blocked).collect();

    let selected_ids: HashSet<String> = result.selected.iter().map(|s| s.id.clone()).collect();
    let not_selected: Vec<&OptCandidate> = eligible
        .iter()
        .filter(|c| !selected_ids.contains(&c.id))
        .copied()
        .collect();

    for _ in 0..max_iterations {
        let mut improved = false;

        for i in 0..result.selected.len() {
            for replacement in &not_selected {
                if selected_ids.contains(&replacement.id) {
                    continue;
                }

                // Check if swapping reduces loss while maintaining feasibility.
                let old = &result.selected[i];
                let loss_delta = replacement.expected_loss - old.expected_loss;

                if loss_delta >= 0.0 {
                    continue;
                }

                // Check contributions: ensure goals are still met.
                let mut still_feasible = true;
                for (g, goal) in goals.iter().enumerate() {
                    let new_total = result.total_contributions[g]
                        - old.contributions.get(g).copied().unwrap_or(0.0)
                        + replacement.contributions.get(g).copied().unwrap_or(0.0);
                    if new_total < goal.target && result.goal_achievement[g].met {
                        still_feasible = false;
                        break;
                    }
                }

                if still_feasible {
                    // Perform swap.
                    result.total_loss += loss_delta;
                    for g in 0..goals.len() {
                        let old_c = old.contributions.get(g).copied().unwrap_or(0.0);
                        let new_c = replacement.contributions.get(g).copied().unwrap_or(0.0);
                        result.total_contributions[g] += new_c - old_c;
                    }
                    result.selected[i] = SelectedAction {
                        id: replacement.id.clone(),
                        expected_loss: replacement.expected_loss,
                        contributions: replacement.contributions.clone(),
                    };
                    improved = true;
                    break;
                }
            }
            if improved {
                break;
            }
        }

        if !improved {
            break;
        }
    }

    // Update goal achievements after improvement.
    for (g, goal) in goals.iter().enumerate() {
        result.goal_achievement[g].achieved = result.total_contributions[g];
        result.goal_achievement[g].shortfall =
            (goal.target - result.total_contributions[g]).max(0.0);
        result.goal_achievement[g].met = result.total_contributions[g] >= goal.target;
    }
}

fn generate_alternatives(
    selected: &[SelectedAction],
    goals: &[ResourceGoal],
    eligible: &[(usize, &OptCandidate)],
    log_events: &mut Vec<OptimizationLogEvent>,
) -> Vec<AlternativePlan> {
    let mut alts: Vec<AlternativePlan> = Vec::new();
    let mut seen = HashSet::new();

    let mut push_unique = |alt: AlternativePlan| {
        let key = alternative_key(&alt);
        if seen.insert(key) {
            alts.push(alt);
        }
    };

    let goals_len = goals.len();

    if selected.len() > 1 {
        // Conservative: use fewer actions (first N-1).
        let fewer = &selected[..selected.len() - 1];
        let loss: f64 = fewer.iter().map(|s| s.expected_loss).sum();
        let totals = total_contributions_from_actions(fewer, goals_len);
        let achievements = compute_goal_achievements(goals, &totals);

        push_unique(AlternativePlan {
            description: "Conservative: fewer actions, potentially under target".to_string(),
            action_count: fewer.len(),
            total_loss: loss,
            goal_achievement: achievements,
        });
    }

    // Aggressive: add one more action if available.
    if selected.len() < eligible.len() {
        let selected_ids: HashSet<&str> = selected.iter().map(|s| s.id.as_str()).collect();
        let next = eligible
            .iter()
            .find(|(_, c)| !selected_ids.contains(c.id.as_str()));

        if let Some((_, extra)) = next {
            let mut more = selected.to_vec();
            more.push(SelectedAction {
                id: extra.id.clone(),
                expected_loss: extra.expected_loss,
                contributions: extra.contributions.clone(),
            });
            let loss: f64 = more.iter().map(|s| s.expected_loss).sum();
            let totals = total_contributions_from_actions(&more, goals_len);
            let achievements = compute_goal_achievements(goals, &totals);

            push_unique(AlternativePlan {
                description: "Aggressive: more headroom, higher total loss".to_string(),
                action_count: more.len(),
                total_loss: loss,
                goal_achievement: achievements,
            });
        }
    }

    for alt in compute_pareto_frontier(eligible, goals, 8, log_events) {
        push_unique(alt);
    }

    alts
}

fn alternative_key(alt: &AlternativePlan) -> String {
    let mut parts = Vec::with_capacity(alt.goal_achievement.len() + 2);
    parts.push(format!("actions={}", alt.action_count));
    parts.push(format!("loss={:.6}", alt.total_loss));
    for g in &alt.goal_achievement {
        parts.push(format!("{}={:.6}", g.resource, g.achieved));
    }
    parts.join("|")
}

fn total_contributions_from_actions(actions: &[SelectedAction], goals_len: usize) -> Vec<f64> {
    let mut totals = vec![0.0; goals_len];
    for action in actions {
        for (g, contrib) in action.contributions.iter().enumerate().take(goals_len) {
            totals[g] += *contrib;
        }
    }
    totals
}

fn compute_goal_achievements(goals: &[ResourceGoal], totals: &[f64]) -> Vec<GoalAchievement> {
    goals
        .iter()
        .enumerate()
        .map(|(g, goal)| {
            let achieved = totals.get(g).copied().unwrap_or(0.0);
            GoalAchievement {
                resource: goal.resource.clone(),
                target: goal.target,
                achieved,
                shortfall: (goal.target - achieved).max(0.0),
                met: achieved >= goal.target,
            }
        })
        .collect()
}

fn compute_pareto_frontier(
    eligible: &[(usize, &OptCandidate)],
    goals: &[ResourceGoal],
    max_sets: usize,
    log_events: &mut Vec<OptimizationLogEvent>,
) -> Vec<AlternativePlan> {
    if eligible.is_empty() || goals.is_empty() || max_sets == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<&OptCandidate> = eligible.iter().map(|(_, c)| *c).collect();
    let goals_len = goals.len();

    if candidates.len() > 16 {
        let mut event = OptimizationLogEvent::new("constraint_violation", "pareto_frontier");
        event.note = Some(format!(
            "candidate_cap: {} -> {}",
            candidates.len(),
            16
        ));
        log_events.push(event);
        candidates.sort_by(|a, b| {
            pareto_efficiency(b, goals)
                .partial_cmp(&pareto_efficiency(a, goals))
                .unwrap_or(Ordering::Equal)
        });
        candidates.truncate(16);
    }

    let n = candidates.len();
    let mut sets: Vec<ParetoSet> = Vec::new();

    for mask in 1..(1_u32 << n) {
        let mut actions = Vec::new();
        let mut total_loss = 0.0;
        let mut totals = vec![0.0; goals_len];

        for i in 0..n {
            if (mask & (1_u32 << i)) != 0 {
                let cand = candidates[i];
                actions.push(SelectedAction {
                    id: cand.id.clone(),
                    expected_loss: cand.expected_loss,
                    contributions: cand.contributions.clone(),
                });
                total_loss += cand.expected_loss;
                for (g, contrib) in cand.contributions.iter().enumerate().take(goals_len) {
                    totals[g] += *contrib;
                }
            }
        }

        sets.push(ParetoSet {
            actions,
            total_loss,
            total_contributions: totals,
        });
    }

    let mut frontier = Vec::new();
    for i in 0..sets.len() {
        let mut dominated = false;
        for j in 0..sets.len() {
            if i == j {
                continue;
            }
            if pareto_dominates(&sets[j], &sets[i]) {
                dominated = true;
                break;
            }
        }
        if !dominated {
            frontier.push(sets[i].clone());
        }
    }

    frontier.sort_by(|a, b| {
        let loss_cmp = a
            .total_loss
            .partial_cmp(&b.total_loss)
            .unwrap_or(Ordering::Equal);
        if loss_cmp != Ordering::Equal {
            return loss_cmp;
        }
        let sum_a: f64 = a.total_contributions.iter().sum();
        let sum_b: f64 = b.total_contributions.iter().sum();
        sum_b.partial_cmp(&sum_a).unwrap_or(Ordering::Equal)
    });

    let mut alternatives: Vec<AlternativePlan> = frontier
        .into_iter()
        .map(|set| {
            let sum_contrib: f64 = set.total_contributions.iter().sum();
            let mut event = OptimizationLogEvent::new("pareto_point", "pareto_frontier");
            event.total_loss = Some(set.total_loss);
            event.total_contributions = set.total_contributions.clone();
            log_events.push(event);
            AlternativePlan {
                description: format!("Pareto: loss {:.3}, contribution {:.3}", set.total_loss, sum_contrib),
                action_count: set.actions.len(),
                total_loss: set.total_loss,
                goal_achievement: compute_goal_achievements(goals, &set.total_contributions),
            }
        })
        .collect();

    if alternatives.len() > max_sets {
        let mut reduced = Vec::with_capacity(max_sets);
        if max_sets == 1 {
            reduced.push(alternatives[0].clone());
            return reduced;
        }
        let step = (alternatives.len() - 1) as f64 / (max_sets - 1) as f64;
        let mut last_idx = None;
        for i in 0..max_sets {
            let idx = (i as f64 * step).round() as usize;
            if last_idx == Some(idx) {
                continue;
            }
            reduced.push(alternatives[idx].clone());
            last_idx = Some(idx);
        }
        alternatives = reduced;
    }

    alternatives
}

#[derive(Clone)]
struct ParetoSet {
    actions: Vec<SelectedAction>,
    total_loss: f64,
    total_contributions: Vec<f64>,
}

fn pareto_efficiency(candidate: &OptCandidate, goals: &[ResourceGoal]) -> f64 {
    let weighted: f64 = candidate
        .contributions
        .iter()
        .zip(goals.iter())
        .map(|(c, g)| c * g.weight)
        .sum();
    if candidate.expected_loss > 1e-12 {
        weighted / candidate.expected_loss
    } else {
        weighted * 1e8
    }
}

fn pareto_dominates(a: &ParetoSet, b: &ParetoSet) -> bool {
    let eps = 1e-9;
    if a.total_loss > b.total_loss + eps {
        return false;
    }
    let mut strictly_better = a.total_loss + eps < b.total_loss;
    for (a_c, b_c) in a
        .total_contributions
        .iter()
        .zip(b.total_contributions.iter())
    {
        if *a_c + eps < *b_c {
            return false;
        }
        if *a_c > *b_c + eps {
            strictly_better = true;
        }
    }
    strictly_better
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidates(n: usize) -> Vec<OptCandidate> {
        (0..n)
            .map(|i| OptCandidate {
                id: format!("pid_{}", i),
                expected_loss: (i + 1) as f64 * 0.1,
                contributions: vec![(i + 1) as f64 * 100.0], // Memory contribution
                blocked: false,
                block_reason: None,
            })
            .collect()
    }

    #[test]
    fn test_greedy_basic() {
        let candidates = make_candidates(5);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 300.0,
            weight: 1.0,
        }];

        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert!(result.total_loss > 0.0);
        assert!(result.goal_achievement[0].met);
    }

    #[test]
    fn test_greedy_infeasible() {
        let candidates = make_candidates(2); // Can only free 100+200=300
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 1000.0, // More than available
            weight: 1.0,
        }];

        let result = optimize_greedy(&candidates, &goals);
        assert!(!result.feasible);
        assert!(result.goal_achievement[0].shortfall > 0.0);
    }

    #[test]
    fn test_greedy_blocked_candidates() {
        let mut candidates = make_candidates(5);
        // Block the most efficient candidates.
        candidates[4].blocked = true;
        candidates[4].block_reason = Some("protected".to_string());
        candidates[3].blocked = true;

        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];

        let result = optimize_greedy(&candidates, &goals);
        // Should not include blocked candidates.
        assert!(result
            .selected
            .iter()
            .all(|s| s.id != "pid_4" && s.id != "pid_3"));
    }

    #[test]
    fn test_greedy_efficiency_ordering() {
        // Candidate A: low loss (0.1), high contribution (500).
        // Candidate B: high loss (5.0), low contribution (100).
        let candidates = vec![
            OptCandidate {
                id: "A".to_string(),
                expected_loss: 0.1,
                contributions: vec![500.0],
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "B".to_string(),
                expected_loss: 5.0,
                contributions: vec![100.0],
                blocked: false,
                block_reason: None,
            },
        ];

        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 400.0,
            weight: 1.0,
        }];

        let result = optimize_greedy(&candidates, &goals);
        // Should pick A first (much more efficient).
        assert_eq!(result.selected[0].id, "A");
        // A alone has 500 >= 400, so B shouldn't be needed.
        assert_eq!(result.selected.len(), 1);
    }

    #[test]
    fn test_dp_exact_single_goal() {
        let candidates = vec![
            OptCandidate {
                id: "A".to_string(),
                expected_loss: 1.0,
                contributions: vec![200.0],
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "B".to_string(),
                expected_loss: 0.5,
                contributions: vec![150.0],
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "C".to_string(),
                expected_loss: 0.3,
                contributions: vec![100.0],
                blocked: false,
                block_reason: None,
            },
        ];

        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 250.0,
            weight: 1.0,
        }];

        let result = optimize_dp(&candidates, &goals, 10.0);
        assert!(result.feasible);
        // B+C = 250 at cost 0.8, which beats A+C = 300 at cost 1.3 or A alone = 200 (infeasible).
        assert!(result.total_loss <= 0.81);
        assert_eq!(result.algorithm, "dp_exact");
    }

    #[test]
    fn test_local_search_improvement() {
        // Start with a suboptimal greedy solution, then improve.
        let candidates = vec![
            OptCandidate {
                id: "expensive".to_string(),
                expected_loss: 10.0,
                contributions: vec![300.0],
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "cheap".to_string(),
                expected_loss: 0.1,
                contributions: vec![300.0],
                blocked: false,
                block_reason: None,
            },
        ];

        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];

        // Force selecting "expensive" first.
        let mut result = OptimizationResult {
            selected: vec![SelectedAction {
                id: "expensive".to_string(),
                expected_loss: 10.0,
                contributions: vec![300.0],
            }],
            total_loss: 10.0,
            total_contributions: vec![300.0],
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 200.0,
                achieved: 300.0,
                shortfall: 0.0,
                met: true,
            }],
            feasible: true,
            algorithm: "greedy".to_string(),
            alternatives: Vec::new(),
            log_events: Vec::new(),
        };

        local_search_improve(&mut result, &candidates, &goals, 10);
        // Should swap expensive for cheap.
        assert_eq!(result.selected[0].id, "cheap");
        assert!(result.total_loss < 1.0);
    }

    #[test]
    fn test_alternatives_generated() {
        let candidates = make_candidates(5);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 300.0,
            weight: 1.0,
        }];

        let result = optimize_greedy(&candidates, &goals);
        // Should have at least one alternative (conservative or aggressive).
        assert!(!result.alternatives.is_empty());
    }

    #[test]
    fn test_multi_goal() {
        let candidates = vec![
            OptCandidate {
                id: "mem_hog".to_string(),
                expected_loss: 0.5,
                contributions: vec![500.0, 10.0], // Memory, CPU
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "cpu_hog".to_string(),
                expected_loss: 0.3,
                contributions: vec![50.0, 80.0], // Memory, CPU
                blocked: false,
                block_reason: None,
            },
        ];

        let goals = vec![
            ResourceGoal {
                resource: "memory_mb".to_string(),
                target: 100.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "cpu_pct".to_string(),
                target: 50.0,
                weight: 1.0,
            },
        ];

        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(result.goal_achievement.len(), 2);
    }

    #[test]
    fn test_empty_candidates() {
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];

        let result = optimize_greedy(&[], &goals);
        assert!(!result.feasible);
        assert!(result.selected.is_empty());
    }
}
