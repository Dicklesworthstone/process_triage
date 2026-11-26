//! Multi-objective kill set optimization for goal-oriented plans.
//!
//! Selects a set of actions that achieves user resource goals with minimal
//! expected risk, respecting safety constraints (protected processes, blast
//! radius limits, FDR budgets).
//!
//! # Algorithms
//!
//! - **Greedy**: Select by remaining, target-normalized progress per unit of loss.
//! - **DP-exact**: Dynamic programming for small candidate sets (N ≤ 30).
//! - **Local search**: Swap-based improvement on greedy solutions.
//!
//! When goals are infeasible, reports the shortfall and best-effort plan.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<OptimizationSearchStats>,
}

/// Deterministic work accounting for a bounded exact-search attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSearchStats {
    pub visited_nodes: usize,
    pub node_budget: usize,
    pub candidate_limit: usize,
    pub eligible_candidates: usize,
    pub optimum_proven: bool,
    pub omitted_log_events: usize,
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
            search: None,
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
    /// Risk tolerance in \[0,1\]. 0 = conservative, 1 = aggressive.
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
        let updated =
            (prior * (1.0 - self.learning_rate) + observed * self.learning_rate).clamp(0.0, 1.0);
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

/// Greedy optimization: rank marginal progress per loss until goals are met.
///
/// Each resource is normalized by its target, and excess beyond its remaining
/// deficit earns no selection credit. Thus units (bytes versus MiB, for example)
/// do not change the objective and a satisfied goal cannot keep driving kills.
pub fn optimize_greedy(candidates: &[OptCandidate], goals: &[ResourceGoal]) -> OptimizationResult {
    optimize_greedy_internal(
        candidates,
        goals,
        None,
        "greedy",
        true,
        usize::MAX,
        GreedyObjective::LossEfficiency,
    )
}

/// Greedy optimization subject to a hard limit on the number of actions.
///
/// Compares loss-efficient and maximum-progress selections, plus individually
/// feasible actions. This avoids spending a small action budget on cheap partial
/// contributors when a larger contributor can meet the goals within the limit.
/// Multi-goal selection remains a heuristic: an unmet result is not proof that
/// no feasible combination exists. Neither selections nor alternatives exceed
/// `max_actions`.
pub fn optimize_greedy_with_limit(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    max_actions: usize,
) -> OptimizationResult {
    optimize_greedy_limited_internal(candidates, goals, max_actions, true)
}

/// Greedy optimization with a user preference model applied to loss sensitivity.
pub fn optimize_greedy_with_preferences(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    prefs: &PreferenceModel,
) -> OptimizationResult {
    optimize_greedy_internal(
        candidates,
        goals,
        Some(prefs),
        "greedy_pref",
        true,
        usize::MAX,
        GreedyObjective::LossEfficiency,
    )
}

#[derive(Clone, Copy)]
enum GreedyObjective {
    LossEfficiency,
    Progress,
}

/// A stale entry is an upper bound: deficits only decrease, so marginal gain
/// cannot increase. Re-evaluate only entries that reach the top of the heap.
#[derive(Clone, Copy, Debug)]
struct GreedyRank {
    weighted: bool,
    costless: bool,
    log_efficiency: f64,
    index: usize,
    generation: usize,
}

impl PartialEq for GreedyRank {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for GreedyRank {}

impl PartialOrd for GreedyRank {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GreedyRank {
    fn cmp(&self, other: &Self) -> Ordering {
        self.weighted
            .cmp(&other.weighted)
            .then_with(|| self.costless.cmp(&other.costless))
            .then_with(|| self.log_efficiency.total_cmp(&other.log_efficiency))
            // Preserve the input order for equal priorities, as stable sorting
            // did before. The generation is freshness metadata, not priority.
            .then_with(|| other.index.cmp(&self.index))
    }
}

fn log_add_positive(a: f64, b: f64) -> f64 {
    if a == f64::NEG_INFINITY {
        b
    } else {
        a.max(b) + (a.min(b) - a.max(b)).exp().ln_1p()
    }
}

fn marginal_rank(
    candidate: &OptCandidate,
    adjusted_loss: f64,
    goals: &[ResourceGoal],
    remaining: impl Iterator<Item = f64>,
    index: usize,
    generation: usize,
) -> Option<GreedyRank> {
    let mut weighted_gain = f64::NEG_INFINITY;
    let mut unweighted_gain = f64::NEG_INFINITY;
    for ((contribution, goal), deficit) in candidate.contributions.iter().zip(goals).zip(remaining)
    {
        if *contribution <= 0.0 || deficit <= 0.0 {
            continue;
        }
        // Log space avoids overflow/underflow when loss, target, or weight
        // spans many orders of magnitude. No measurement is rounded to zero.
        let log_fraction = contribution.min(deficit).ln() - goal.target.ln();
        unweighted_gain = log_add_positive(unweighted_gain, log_fraction);
        if goal.weight > 0.0 {
            weighted_gain = log_add_positive(weighted_gain, log_fraction + goal.weight.ln());
        }
    }
    let weighted = weighted_gain.is_finite();
    let gain = if weighted {
        weighted_gain
    } else {
        // Zero-weight goals are still constraints. Work on them after all
        // attainable positive-weight progress, instead of abandoning them.
        unweighted_gain
    };
    gain.is_finite().then(|| GreedyRank {
        weighted,
        costless: adjusted_loss == 0.0,
        log_efficiency: if adjusted_loss == 0.0 {
            gain
        } else {
            gain - adjusted_loss.ln()
        },
        index,
        generation,
    })
}

fn valid_goal_inputs(goals: &[ResourceGoal]) -> bool {
    goals.iter().all(|goal| {
        goal.target.is_finite()
            && goal.target >= 0.0
            && goal.weight.is_finite()
            && goal.weight >= 0.0
    })
}

fn valid_candidate_inputs(candidate: &OptCandidate, goal_count: usize) -> bool {
    candidate.expected_loss.is_finite()
        && candidate.expected_loss >= 0.0
        && candidate.contributions.len() == goal_count
        && candidate
            .contributions
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0)
}

fn record_invalid_candidates(
    events: &mut Vec<OptimizationLogEvent>,
    algorithm: &str,
    count: usize,
) {
    if count > 0 {
        let mut event = OptimizationLogEvent::new("invalid_input", algorithm);
        event.note = Some(format!("excluded_invalid_candidates={count}: loss and contributions must be finite and non-negative, with one contribution per goal"));
        events.push(event);
    }
}

fn optimize_greedy_internal(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    prefs: Option<&PreferenceModel>,
    algorithm_label: &str,
    include_alternatives: bool,
    max_actions: usize,
    objective: GreedyObjective,
) -> OptimizationResult {
    let mut log_events = Vec::new();
    let mut start_event = OptimizationLogEvent::new("optimizer_start", algorithm_label);
    start_event.note = Some(format!(
        "candidates={} goals={} score=log(target_normalized_remaining_gain/adjusted_loss)",
        candidates.len(),
        goals.len()
    ));
    log_events.push(start_event);

    let adjust_loss = |loss: f64| prefs.map_or(loss, |p| p.adjust_loss(loss));
    let ranking_loss = |loss: f64| match objective {
        GreedyObjective::LossEfficiency => adjust_loss(loss),
        GreedyObjective::Progress => 1.0,
    };
    if max_actions < candidates.len() {
        let mut event = OptimizationLogEvent::new("action_limit", algorithm_label);
        event.note = Some(format!("max_actions={max_actions}"));
        log_events.push(event);
    }

    if !valid_goal_inputs(goals) || prefs.is_some_and(|prefs| !prefs.risk_tolerance.is_finite()) {
        let mut invalid = OptimizationLogEvent::new("invalid_input", algorithm_label);
        invalid.note = Some("targets, weights and risk preference must be finite; targets and weights must be non-negative".into());
        log_events.push(invalid);
        return OptimizationResult {
            selected: Vec::new(),
            total_loss: 0.0,
            total_contributions: vec![0.0; goals.len()],
            // There is no meaningful numerical achievement for a malformed
            // goal. Do not publish fabricated zero targets or NaN measurements.
            goal_achievement: Vec::new(),
            feasible: false,
            algorithm: algorithm_label.to_string(),
            alternatives: Vec::new(),
            log_events,
        };
    }

    let valid_candidate = |candidate: &OptCandidate| {
        valid_candidate_inputs(candidate, goals.len())
            && adjust_loss(candidate.expected_loss).is_finite()
    };
    record_invalid_candidates(
        &mut log_events,
        algorithm_label,
        candidates
            .iter()
            .filter(|candidate| !valid_candidate(candidate))
            .count(),
    );

    // A missing resource observation contributes zero. Do not turn a shortfall
    // into gratuitous actions, including in the alternative plans below.
    let eligible: Vec<(usize, &OptCandidate)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            !c.blocked
                && valid_candidate(c)
                && c.contributions
                    .iter()
                    .zip(goals)
                    .any(|(contribution, goal)| *contribution > 0.0 && goal.target > 0.0)
        })
        .collect();
    let blocked_count = candidates.iter().filter(|c| c.blocked).count();
    if blocked_count > 0 {
        let mut event = OptimizationLogEvent::new("constraint_violation", algorithm_label);
        event.note = Some(format!("blocked_candidates={}", blocked_count));
        log_events.push(event);
    }

    let mut selected = Vec::new();
    let mut remaining_targets: Vec<f64> = goals.iter().map(|g| g.target).collect();
    let mut total_contributions = vec![0.0; goals.len()];
    let mut total_loss = 0.0;
    let mut heap: BinaryHeap<_> = eligible
        .iter()
        .filter_map(|(index, candidate)| {
            marginal_rank(
                candidate,
                ranking_loss(candidate.expected_loss),
                goals,
                remaining_targets.iter().copied(),
                *index,
                0,
            )
        })
        .collect();

    while let Some(rank) = heap.pop() {
        // Stop when goals are met or the executable action budget is spent.
        if selected.len() >= max_actions || remaining_targets.iter().all(|t| *t <= 0.0) {
            break;
        }
        let cand = &candidates[rank.index];
        if rank.generation != selected.len() {
            if let Some(updated) = marginal_rank(
                cand,
                ranking_loss(cand.expected_loss),
                goals,
                remaining_targets.iter().copied(),
                rank.index,
                selected.len(),
            ) {
                heap.push(updated);
            }
            continue;
        }
        // Keep the result finite and reviewable even for library callers with
        // extreme inputs. Never count an action whose aggregate cannot be represented.
        if !(total_loss + cand.expected_loss).is_finite()
            || total_contributions
                .iter()
                .zip(&cand.contributions)
                .any(|(total, value)| !(*total + value).is_finite())
        {
            if include_alternatives || log_events.len() < ILP_SEARCH_LOG_LIMIT {
                let mut event = OptimizationLogEvent::new("constraint_violation", algorithm_label);
                event.candidate_id = Some(cand.id.clone());
                event.note =
                    Some("aggregate loss or contribution exceeds finite numeric capacity".into());
                log_events.push(event);
            }
            continue;
        }

        if include_alternatives || log_events.len() < ILP_SEARCH_LOG_LIMIT {
            let mut eval = OptimizationLogEvent::new("objective_eval", algorithm_label);
            eval.candidate_id = Some(cand.id.clone());
            eval.loss = Some(cand.expected_loss);
            eval.score = Some(rank.log_efficiency);
            eval.total_contributions = cand.contributions.clone();
            log_events.push(eval);
        }

        selected.push(SelectedAction {
            id: cand.id.clone(),
            expected_loss: cand.expected_loss,
            contributions: cand.contributions.clone(),
        });

        total_loss += cand.expected_loss;
        for (i, contrib) in cand.contributions.iter().enumerate() {
            total_contributions[i] += contrib;
            remaining_targets[i] = (goals[i].target - total_contributions[i]).max(0.0);
        }
    }

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
    // The bounded exact-search fallback must not enter the exponential Pareto
    // enumeration, nor collect an unbounded per-candidate diagnostic log.
    let alternatives = if include_alternatives {
        generate_alternatives(&selected, goals, &eligible, max_actions, &mut log_events)
    } else {
        Vec::new()
    };
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

// Rank partial plans by capped, target-normalized progress. Log space keeps
// comparisons finite even when resource weights span extreme magnitudes.
fn partial_progress(result: &OptimizationResult, goals: &[ResourceGoal]) -> (f64, f64) {
    let mut weighted = f64::NEG_INFINITY;
    let mut unweighted = f64::NEG_INFINITY;
    for (total, goal) in result.total_contributions.iter().zip(goals) {
        if *total <= 0.0 || goal.target <= 0.0 {
            continue;
        }
        let fraction = total.min(goal.target).ln() - goal.target.ln();
        unweighted = log_add_positive(unweighted, fraction);
        if goal.weight > 0.0 {
            weighted = log_add_positive(weighted, fraction + goal.weight.ln());
        }
    }
    (weighted, unweighted)
}

fn prefer_bounded_result(
    candidate: &OptimizationResult,
    current: &OptimizationResult,
    goals: &[ResourceGoal],
) -> bool {
    if candidate.feasible != current.feasible {
        return candidate.feasible;
    }
    if !candidate.feasible {
        let proposed = partial_progress(candidate, goals);
        let existing = partial_progress(current, goals);
        let progress = proposed
            .0
            .total_cmp(&existing.0)
            .then_with(|| proposed.1.total_cmp(&existing.1));
        if progress != Ordering::Equal {
            return progress == Ordering::Greater;
        }
    }
    candidate.total_loss < current.total_loss
        || (candidate.total_loss == current.total_loss
            && candidate.selected.len() < current.selected.len())
}

fn optimize_greedy_limited_internal(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    max_actions: usize,
    include_alternatives: bool,
) -> OptimizationResult {
    // Preserve the existing unconstrained objective and diagnostics when the
    // limit cannot bind; invalid inputs and zero budgets need only one pass.
    if max_actions >= candidates.len() || max_actions == 0 || !valid_goal_inputs(goals) {
        return optimize_greedy_internal(
            candidates,
            goals,
            None,
            "greedy",
            include_alternatives,
            max_actions,
            GreedyObjective::LossEfficiency,
        );
    }

    let mut result = optimize_greedy_internal(
        candidates,
        goals,
        None,
        "greedy",
        false,
        max_actions,
        GreedyObjective::LossEfficiency,
    );
    let mut strategy = "loss_efficiency";
    let progress = optimize_greedy_internal(
        candidates,
        goals,
        None,
        "greedy_progress",
        false,
        max_actions,
        GreedyObjective::Progress,
    );
    if prefer_bounded_result(&progress, &result, goals) {
        result = progress;
        strategy = "maximum_progress";
    }

    // A zero-weight constraint can tie a partial contributor with an action
    // satisfying every goal. Explicitly retain the cheapest one-action solution
    // instead of allowing input order or weights to hide that feasible plan.
    if let Some(single) = candidates
        .iter()
        .filter(|candidate| {
            !candidate.blocked
                && valid_candidate_inputs(candidate, goals.len())
                && candidate
                    .contributions
                    .iter()
                    .zip(goals)
                    .all(|(contribution, goal)| *contribution >= goal.target)
        })
        .min_by(|a, b| a.expected_loss.total_cmp(&b.expected_loss))
    {
        let one_action = optimize_greedy_internal(
            std::slice::from_ref(single),
            goals,
            None,
            "greedy_single_action",
            false,
            max_actions,
            GreedyObjective::LossEfficiency,
        );
        if prefer_bounded_result(&one_action, &result, goals) {
            result = one_action;
            strategy = "single_action";
        }
    }

    if include_alternatives {
        let eligible: Vec<_> = candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                !candidate.blocked
                    && valid_candidate_inputs(candidate, goals.len())
                    && candidate
                        .contributions
                        .iter()
                        .zip(goals)
                        .any(|(contribution, goal)| *contribution > 0.0 && goal.target > 0.0)
            })
            .collect();
        result.alternatives = generate_alternatives(
            &result.selected,
            goals,
            &eligible,
            max_actions,
            &mut result.log_events,
        );
    }
    result.algorithm = "greedy (action limit, multi-start heuristic)".to_string();
    let mut event = OptimizationLogEvent::new("bounded_strategy", "greedy");
    event.note = Some(format!(
        "max_actions={max_actions} strategy={strategy}; multi-goal feasibility and optimality are not proven"
    ));
    event.total_loss = Some(result.total_loss);
    event.total_contributions = result.total_contributions.clone();
    result.log_events.push(event);
    result
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

const ILP_NODE_BUDGET: usize = 25_000;
const ILP_CANDIDATE_LIMIT: usize = 64;
// Bound the remaining-capacity table and the work per search node as well as
// recursion depth. At the limits it contains 16 * 65 * 65 f64 cells.
const ILP_GOAL_LIMIT: usize = 16;
const ILP_SEARCH_LOG_LIMIT: usize = 128;
// Optional Pareto alternatives enumerate subsets and compare them pairwise.
// Eight candidates bound this at 255 subsets and fewer than 65,025 comparisons.
const PARETO_CANDIDATE_LIMIT: usize = 8;

#[derive(Default)]
struct IlpSearchBudget {
    visited_nodes: usize,
    exhausted: bool,
    omitted_log_events: usize,
}

impl IlpSearchBudget {
    fn enter_node(&mut self) -> bool {
        if self.visited_nodes >= ILP_NODE_BUDGET {
            self.exhausted = true;
            return false;
        }
        self.visited_nodes += 1;
        true
    }

    fn record(&mut self, events: &mut Vec<OptimizationLogEvent>, event: OptimizationLogEvent) {
        if events.len() < ILP_SEARCH_LOG_LIMIT {
            events.push(event);
        } else {
            self.omitted_log_events += 1;
        }
    }

    fn summary(&self, eligible_candidates: usize, optimum_proven: bool) -> OptimizationSearchStats {
        OptimizationSearchStats {
            visited_nodes: self.visited_nodes,
            node_budget: ILP_NODE_BUDGET,
            candidate_limit: ILP_CANDIDATE_LIMIT,
            eligible_candidates,
            optimum_proven,
            omitted_log_events: self.omitted_log_events,
        }
    }
}

fn ilp_greedy_fallback(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    max_actions: usize,
    reason: &str,
    log_events: Vec<OptimizationLogEvent>,
) -> OptimizationResult {
    let mut result = optimize_greedy_limited_internal(candidates, goals, max_actions, false);
    result.algorithm = format!("ilp_branch_bound ({reason}, greedy fallback; optimum not proven)");
    result.log_events.extend(log_events);
    result
}

/// Bounded branch-and-bound optimization for simultaneous resource goals.
///
/// Uses constraint propagation to prune infeasible branches: if the remaining
/// maximum possible contribution cannot reach any required target, the branch
/// is cut. A deterministic node budget bounds work and diagnostic volume.
/// At most 64 candidates and 16 goals enter exact search; larger inputs use
/// greedy selection without claiming infeasibility or optimality is proven.
/// Budget exhaustion retains a feasible incumbent without claiming optimality.
pub fn optimize_ilp(candidates: &[OptCandidate], goals: &[ResourceGoal]) -> OptimizationResult {
    optimize_ilp_with_limit(candidates, goals, usize::MAX)
}

/// Branch-and-bound optimization with a hard action-count constraint.
///
/// The incumbent, remaining-capacity bound, search, and greedy fallback all
/// respect `max_actions`. A capacity-ordered seed keeps a large contribution
/// from being hidden behind cheaper partial contributors when work is bounded.
/// Every target is a constraint, including targets whose ranking weight is zero.
/// Optimality is reported only if the bounded search completes.
pub fn optimize_ilp_with_limit(
    candidates: &[OptCandidate],
    goals: &[ResourceGoal],
    max_actions: usize,
) -> OptimizationResult {
    let mut log_events = Vec::new();
    let mut start_event = OptimizationLogEvent::new("optimizer_start", "ilp_branch_bound");
    start_event.note = Some(format!(
        "candidates={} goals={}",
        candidates.len(),
        goals.len()
    ));
    log_events.push(start_event);

    if goals.is_empty() || candidates.is_empty() || !valid_goal_inputs(goals) {
        return ilp_greedy_fallback(candidates, goals, max_actions, "unsupported", log_events);
    }

    record_invalid_candidates(
        &mut log_events,
        "ilp_branch_bound",
        candidates
            .iter()
            .filter(|candidate| !valid_candidate_inputs(candidate, goals.len()))
            .count(),
    );

    let eligible: Vec<&OptCandidate> = candidates
        .iter()
        .filter(|c| {
            !c.blocked
                && valid_candidate_inputs(c, goals.len())
                && c.contributions
                    .iter()
                    .zip(goals)
                    .any(|(contribution, goal)| *contribution > 0.0 && goal.target > 0.0)
        })
        .collect();

    if eligible.is_empty() {
        return ilp_greedy_fallback(candidates, goals, max_actions, "no_candidates", log_events);
    }
    if eligible.len() > ILP_CANDIDATE_LIMIT {
        let mut event = OptimizationLogEvent::new("search_budget_exhausted", "ilp_branch_bound");
        event.note = Some("candidate_limit: recursive search not entered".to_string());
        event.search = Some(IlpSearchBudget::default().summary(eligible.len(), false));
        log_events.push(event);
        return ilp_greedy_fallback(
            candidates,
            goals,
            max_actions,
            "candidate_limit",
            log_events,
        );
    }

    if goals.len() > ILP_GOAL_LIMIT {
        let mut event = OptimizationLogEvent::new("search_budget_exhausted", "ilp_branch_bound");
        event.note = Some(format!(
            "goal_limit: {} goals exceed {ILP_GOAL_LIMIT}; recursive search not entered",
            goals.len()
        ));
        event.search = Some(IlpSearchBudget::default().summary(eligible.len(), false));
        log_events.push(event);
        return ilp_greedy_fallback(candidates, goals, max_actions, "goal_limit", log_events);
    }

    let mut ordered = eligible;
    ordered.sort_by_cached_key(|candidate| std::cmp::Reverse(pareto_efficiency(candidate, goals)));

    let n = ordered.len();
    // Clamp before sizing the table: the unconstrained API passes usize::MAX.
    let max_actions = max_actions.min(n);
    let mut suffix_capacity =
        vec![vec![vec![0.0_f64; max_actions + 1]; n + 1]; goals.len()];
    for (goal_index, capacity) in suffix_capacity.iter_mut().enumerate() {
        for i in (0..n).rev() {
            for slots in 1..=max_actions {
                // Each resource gets an independent optimistic bound. Its
                // maximizing subset need not also maximize the other resources.
                // Upward rounding prevents numerical underestimation.
                let with_candidate =
                    (ordered[i].contributions[goal_index] + capacity[i + 1][slots - 1])
                        .next_up();
                capacity[i][slots] = capacity[i + 1][slots].max(with_candidate);
            }
        }
    }

    fn feasible_seed(
        ordered: &[&OptCandidate],
        indices: impl IntoIterator<Item = usize>,
        goals: &[ResourceGoal],
        max_actions: usize,
    ) -> (f64, Vec<usize>) {
        let mut loss = 0.0;
        let mut contributions = vec![0.0; goals.len()];
        let mut selection = Vec::new();
        for idx in indices {
            if contributions
                .iter()
                .zip(goals)
                .all(|(total, goal)| *total >= goal.target)
                || selection.len() >= max_actions
            {
                break;
            }
            let next_loss = loss + ordered[idx].expected_loss;
            if !next_loss.is_finite()
                || contributions
                    .iter()
                    .zip(&ordered[idx].contributions)
                    .any(|(total, contribution)| !(*total + contribution).is_finite())
            {
                continue;
            }
            loss = next_loss;
            for (total, contribution) in contributions.iter_mut().zip(&ordered[idx].contributions) {
                *total += contribution;
            }
            selection.push(idx);
        }
        if contributions
            .iter()
            .zip(goals)
            .all(|(total, goal)| *total >= goal.target)
        {
            (loss, selection)
        } else {
            (f64::INFINITY, Vec::new())
        }
    }

    // An efficiency seed may spend all slots without meeting the target.
    // Also try the largest contributors to each resource. A seed is accepted
    // only when it meets all goals; no resource or zero-weight goal is optional.
    let (mut best_loss, mut best_selection) = feasible_seed(&ordered, 0..n, goals, max_actions);
    if max_actions < n {
        for (goal_index, goal) in goals.iter().enumerate() {
            if goal.target == 0.0 {
                continue;
            }
            let mut by_capacity: Vec<usize> = (0..n).collect();
            by_capacity.sort_by(|&a, &b| {
                ordered[b].contributions[goal_index]
                    .total_cmp(&ordered[a].contributions[goal_index])
                    .then_with(|| {
                        ordered[a]
                            .expected_loss
                            .total_cmp(&ordered[b].expected_loss)
                    })
                    .then_with(|| a.cmp(&b))
            });
            let (capacity_loss, capacity_selection) =
                feasible_seed(&ordered, by_capacity, goals, max_actions);
            if capacity_loss < best_loss {
                best_loss = capacity_loss;
                best_selection = capacity_selection;
            }
        }
    }
    let mut current: Vec<usize> = Vec::new();
    let mut budget = IlpSearchBudget::default();

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        idx: usize,
        ordered: &[&OptCandidate],
        goals: &[ResourceGoal],
        suffix_capacity: &[Vec<Vec<f64>>],
        max_actions: usize,
        current_loss: f64,
        current_contrib: &[f64],
        current: &mut Vec<usize>,
        best_loss: &mut f64,
        best_selection: &mut Vec<usize>,
        log_events: &mut Vec<OptimizationLogEvent>,
        budget: &mut IlpSearchBudget,
    ) {
        if !budget.enter_node() {
            return;
        }
        if current_contrib
            .iter()
            .zip(goals)
            .all(|(total, goal)| *total >= goal.target)
        {
            if current_loss < *best_loss {
                *best_loss = current_loss;
                *best_selection = current.clone();
                let mut event = OptimizationLogEvent::new("objective_improved", "ilp_branch_bound");
                event.total_loss = Some(current_loss);
                if goals.len() == 1 {
                    event.current_contribution = Some(current_contrib[0]);
                    event.target = Some(goals[0].target);
                } else {
                    event.total_contributions = current_contrib.to_vec();
                }
                budget.record(log_events, event);
            }
            return;
        }

        if idx >= ordered.len() || current.len() >= max_actions {
            return;
        }

        if current_loss >= *best_loss {
            return;
        }

        let remaining_slots = max_actions - current.len();
        for (goal_index, goal) in goals.iter().enumerate() {
            let remaining_max = suffix_capacity[goal_index][idx][remaining_slots];
            if (current_contrib[goal_index] + remaining_max).next_up() < goal.target {
                let mut event = OptimizationLogEvent::new("constraint_prune", "ilp_branch_bound");
                event.current_contribution = Some(current_contrib[goal_index]);
                event.remaining_max = Some(remaining_max);
                event.target = Some(goal.target);
                if goals.len() > 1 {
                    event.note = Some(format!(
                        "resource={} remaining_action_slots={remaining_slots}",
                        goal.resource
                    ));
                }
                budget.record(log_events, event);
                return;
            }
        }

        // Include only actions whose reported aggregate remains finite.
        let next_loss = current_loss + ordered[idx].expected_loss;
        // The goal limit bounds this stack buffer; no per-node allocation is
        // needed, and the single-goal path retains its bounded search cost.
        let mut next_contrib = [0.0; ILP_GOAL_LIMIT];
        for (goal_index, total) in current_contrib.iter().enumerate() {
            next_contrib[goal_index] = total + ordered[idx].contributions[goal_index];
        }
        let next_contrib = &next_contrib[..goals.len()];
        if next_loss.is_finite() && next_contrib.iter().all(|total| total.is_finite()) {
            current.push(idx);
            dfs(
                idx + 1,
                ordered,
                goals,
                suffix_capacity,
                max_actions,
                next_loss,
                next_contrib,
                current,
                best_loss,
                best_selection,
                log_events,
                budget,
            );
            current.pop();
        }
        if budget.exhausted {
            return;
        }

        // Exclude candidate.
        dfs(
            idx + 1,
            ordered,
            goals,
            suffix_capacity,
            max_actions,
            current_loss,
            current_contrib,
            current,
            best_loss,
            best_selection,
            log_events,
            budget,
        );
    }

    let initial_contributions = [0.0; ILP_GOAL_LIMIT];
    dfs(
        0,
        &ordered,
        goals,
        &suffix_capacity,
        max_actions,
        0.0,
        &initial_contributions[..goals.len()],
        &mut current,
        &mut best_loss,
        &mut best_selection,
        &mut log_events,
        &mut budget,
    );

    let mut summary = OptimizationLogEvent::new(
        if budget.exhausted {
            "search_budget_exhausted"
        } else {
            "search_completed"
        },
        "ilp_branch_bound",
    );
    summary.search = Some(budget.summary(n, !budget.exhausted && best_loss.is_finite()));
    if budget.exhausted {
        summary.note = Some(if best_loss.is_finite() {
            "node_budget: retaining best feasible incumbent; optimum not proven".to_string()
        } else {
            "node_budget: feasible incumbent not found; feasibility and optimum not proven"
                .to_string()
        });
    }
    log_events.push(summary);

    if best_loss == f64::INFINITY {
        let mut event = OptimizationLogEvent::new("constraint_violation", "ilp_branch_bound");
        let reason = if budget.exhausted {
            "node_budget_exhausted"
        } else {
            "infeasible"
        };
        event.note = Some(if budget.exhausted {
            "no feasible incumbent found before the search budget expired".to_string()
        } else {
            "ilp_infeasible".to_string()
        });
        log_events.push(event);
        return ilp_greedy_fallback(candidates, goals, max_actions, reason, log_events);
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

    let total_contributions = total_contributions_from_actions(&selected, goals.len());
    let goal_achievement = compute_goal_achievements(goals, &total_contributions);
    let feasible = goal_achievement.iter().all(|goal| goal.met);

    OptimizationResult {
        selected,
        total_loss: best_loss,
        total_contributions,
        goal_achievement,
        feasible,
        algorithm: if budget.exhausted {
            "ilp_branch_bound (node_budget_exhausted, best feasible incumbent; optimum not proven)"
                .to_string()
        } else {
            "ilp_branch_bound".to_string()
        },
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

    let mut result = optimize_ilp(new_candidates, goals);

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

    for _ in 0..max_iterations {
        let selected_ids: HashSet<String> = result.selected.iter().map(|s| s.id.clone()).collect();
        let not_selected: Vec<&OptCandidate> = eligible
            .iter()
            .filter(|c| !selected_ids.contains(&c.id))
            .copied()
            .collect();

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
                    for (g, total) in result
                        .total_contributions
                        .iter_mut()
                        .enumerate()
                        .take(goals.len())
                    {
                        let old_c = old.contributions.get(g).copied().unwrap_or(0.0);
                        let new_c = replacement.contributions.get(g).copied().unwrap_or(0.0);
                        *total += new_c - old_c;
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
    max_actions: usize,
    log_events: &mut Vec<OptimizationLogEvent>,
) -> Vec<AlternativePlan> {
    let mut alts: Vec<AlternativePlan> = Vec::new();
    let mut seen = HashSet::new();

    let mut push_unique = |alt: AlternativePlan| {
        if alt.action_count > max_actions
            || !alt.total_loss.is_finite()
            || alt
                .goal_achievement
                .iter()
                .any(|goal| !goal.achieved.is_finite())
        {
            return;
        }
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
    if selected.len() < eligible.len() && selected.len() < max_actions {
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

    for alt in compute_pareto_frontier(eligible, goals, 8, max_actions, log_events) {
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
    max_actions: usize,
    log_events: &mut Vec<OptimizationLogEvent>,
) -> Vec<AlternativePlan> {
    if eligible.is_empty() || goals.is_empty() || max_sets == 0 || max_actions == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<&OptCandidate> = eligible.iter().map(|(_, c)| *c).collect();
    let goals_len = goals.len();

    if candidates.len() > PARETO_CANDIDATE_LIMIT {
        let mut event = OptimizationLogEvent::new("constraint_violation", "pareto_frontier");
        event.note = Some(format!(
            "candidate_cap: {} -> {}",
            candidates.len(),
            PARETO_CANDIDATE_LIMIT
        ));
        log_events.push(event);
        candidates
            .sort_by_cached_key(|candidate| std::cmp::Reverse(pareto_efficiency(candidate, goals)));
        candidates.truncate(PARETO_CANDIDATE_LIMIT);
    }

    let n = candidates.len();
    let mut sets: Vec<ParetoSet> = Vec::new();

    for mask in 1..(1_u32 << n) {
        if mask.count_ones() as usize > max_actions {
            continue;
        }
        let mut actions = Vec::new();
        let mut total_loss = 0.0;
        let mut totals = vec![0.0; goals_len];

        #[allow(clippy::needless_range_loop)]
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

        if !total_loss.is_finite() || totals.iter().any(|value| !value.is_finite()) {
            continue;
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
                description: format!(
                    "Pareto: loss {:.3}, contribution {:.3}",
                    set.total_loss, sum_contrib
                ),
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

fn pareto_efficiency(candidate: &OptCandidate, goals: &[ResourceGoal]) -> Option<GreedyRank> {
    // Initial branch ordering and the bounded alternative shortlist use the
    // same normalized, capped objective. Exact search still minimizes actual
    // expected loss; this only determines which incumbent it discovers first.
    marginal_rank(
        candidate,
        candidate.expected_loss,
        goals,
        goals.iter().map(|goal| goal.target),
        0,
        0,
    )
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
    fn infeasible_goals_never_select_zero_progress_actions() {
        let mut candidates = make_candidates(2);
        candidates[0].contributions = vec![0.0];
        candidates[1].contributions = vec![4.0];
        let goals = [ResourceGoal {
            resource: "fd_count".to_string(),
            target: 10.0,
            weight: 1.0,
        }];
        for result in [
            optimize_greedy(&candidates, &goals),
            optimize_ilp(&candidates, &goals),
        ] {
            assert!(!result.feasible);
            assert_eq!(result.selected.len(), 1);
            assert_eq!(result.selected[0].id, "pid_1");
            assert_eq!(result.total_contributions, [4.0]);
            assert_eq!(result.total_loss, candidates[1].expected_loss);
            assert!(result.alternatives.iter().all(|alt| alt.action_count <= 1));
        }
        candidates[1].contributions[0] = 0.0;
        let result = optimize_ilp(&candidates, &goals);
        assert!(!result.feasible);
        assert!(result.selected.is_empty());
        assert!(result.alternatives.is_empty());
        assert_eq!(result.total_loss, 0.0);
        assert_eq!(result.goal_achievement[0].shortfall, 10.0);
    }

    #[test]
    fn greedy_does_not_spend_on_an_already_met_dimension() {
        let mut candidates = make_candidates(3);
        candidates[0].contributions = vec![10.0, 0.0];
        candidates[1].contributions = vec![5.0, 0.0];
        candidates[2].contributions = vec![0.0, 1.0];
        let goals = [
            ResourceGoal {
                resource: "fd_count".to_string(),
                target: 10.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "port_3000".to_string(),
                target: 2.0,
                weight: 1.0,
            },
        ];
        let result = optimize_greedy(&candidates, &goals);
        assert!(!result.feasible);
        assert_eq!(
            result
                .selected
                .iter()
                .map(|action| action.id.as_str())
                .collect::<Vec<_>>(),
            ["pid_0", "pid_2"]
        );
        assert_eq!(result.total_contributions, [10.0, 1.0]);
        assert_eq!(
            result.total_loss,
            candidates[0].expected_loss + candidates[2].expected_loss
        );
    }

    fn goal_candidate(id: &str, loss: f64, contributions: &[f64]) -> OptCandidate {
        OptCandidate {
            id: id.into(),
            expected_loss: loss,
            contributions: contributions.to_vec(),
            blocked: false,
            block_reason: None,
        }
    }

    fn selected_ids(result: &OptimizationResult) -> Vec<&str> {
        result
            .selected
            .iter()
            .map(|action| action.id.as_str())
            .collect()
    }

    #[test]
    fn greedy_caps_overshoot_and_is_invariant_to_resource_units() {
        // Raw contribution/loss chooses the enormous process at loss 10.
        // Its excess RAM does not advance either requested goal beyond 100%.
        for memory_unit in [1.0, 1024.0 * 1024.0, 1.0 / 1024.0] {
            let goals = [
                ResourceGoal {
                    resource: "memory".into(),
                    target: 1024.0 * memory_unit,
                    weight: 1.0,
                },
                ResourceGoal {
                    resource: "port_3000".into(),
                    target: 1.0,
                    weight: 1.0,
                },
            ];
            let candidates = [
                goal_candidate("memory", 1.0, &[1024.0 * memory_unit, 0.0]),
                goal_candidate("listener", 2.0, &[0.0, 1.0]),
                goal_candidate("enormous", 10.0, &[1e9 * memory_unit, 1.0]),
            ];
            let result = optimize_greedy(&candidates, &goals);
            assert!(result.feasible);
            assert_eq!(selected_ids(&result), ["memory", "listener"]);
            assert_eq!(result.total_loss, 3.0);
            assert_eq!(result.total_contributions, [1024.0 * memory_unit, 1.0]);
        }
    }

    #[test]
    fn greedy_recomputes_marginal_gain_after_each_selection() {
        let goals = [
            ResourceGoal {
                resource: "memory_mb".into(),
                target: 100.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "fd_count".into(),
                target: 100.0,
                weight: 1.0,
            },
        ];
        let candidates = [
            goal_candidate("memory", 1.0, &[100.0, 10.0]),
            goal_candidate("mixed", 2.0, &[90.0, 100.0]),
            goal_candidate("descriptors", 1.1, &[0.0, 90.0]),
        ];
        // Initial normalized efficiencies: 1.1, 0.95, 0.9/1.1. After the
        // memory action the mixed action drops to 0.45 and must be re-ranked.
        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(selected_ids(&result), ["memory", "descriptors"]);
        assert_eq!(result.total_loss, 2.1);
        assert_eq!(result.total_contributions, [100.0, 100.0]);
    }

    #[test]
    fn greedy_preserves_weights_and_still_meets_zero_weight_constraints() {
        let candidates = [
            goal_candidate("first", 1.0, &[1.0, 0.0]),
            goal_candidate("second", 1.0, &[0.0, 1.0]),
        ];
        for (weights, expected) in [
            ([1.0, 4.0], ["second", "first"]),
            ([0.0, 1.0], ["second", "first"]),
            ([0.0, 0.0], ["first", "second"]),
        ] {
            let goals = [
                ResourceGoal {
                    resource: "first".into(),
                    target: 1.0,
                    weight: weights[0],
                },
                ResourceGoal {
                    resource: "second".into(),
                    target: 1.0,
                    weight: weights[1],
                },
            ];
            let result = optimize_greedy(&candidates, &goals);
            assert!(result.feasible);
            assert_eq!(selected_ids(&result), expected);
        }
    }

    #[test]
    fn greedy_ties_are_stable_and_true_zero_loss_is_preferred() {
        let goals = [ResourceGoal {
            resource: "fd_count".into(),
            target: 1.0,
            weight: 1.0,
        }];
        let mut candidates = vec![
            goal_candidate("first", 1.0, &[1.0]),
            goal_candidate("second", 1.0, &[1.0]),
        ];
        assert_eq!(
            selected_ids(&optimize_greedy(&candidates, &goals)),
            ["first"]
        );
        candidates.push(goal_candidate("free", 0.0, &[1.0]));
        assert_eq!(
            selected_ids(&optimize_greedy(&candidates, &goals)),
            ["free"]
        );
        candidates[2].blocked = true;
        assert_eq!(
            selected_ids(&optimize_greedy(&candidates, &goals)),
            ["first"]
        );

        let empty = optimize_greedy(&candidates, &[]);
        assert!(empty.feasible);
        assert!(empty.selected.is_empty());
        assert!(empty.total_contributions.is_empty());
        let zero = optimize_greedy(
            &candidates,
            &[ResourceGoal {
                target: 0.0,
                ..goals[0].clone()
            }],
        );
        assert!(zero.feasible);
        assert!(zero.selected.is_empty());
        assert!(zero.alternatives.is_empty());
    }

    #[test]
    fn greedy_rejects_malformed_candidates_and_goals_without_panicking() {
        let goals = [ResourceGoal {
            resource: "fd_count".into(),
            target: 1.0,
            weight: 1.0,
        }];
        let candidates = [
            goal_candidate("nan_loss", f64::NAN, &[1.0]),
            goal_candidate("infinite_loss", f64::INFINITY, &[1.0]),
            goal_candidate("negative_loss", -1.0, &[1.0]),
            goal_candidate("nan_contribution", 0.0, &[f64::NAN]),
            goal_candidate("infinite_contribution", 0.0, &[f64::INFINITY]),
            goal_candidate("negative_contribution", 0.0, &[-1.0]),
            goal_candidate("short_vector", 0.0, &[]),
            goal_candidate("long_vector", 0.0, &[1.0, 1.0]),
            goal_candidate("valid", 1.0, &[1.0]),
        ];
        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(selected_ids(&result), ["valid"]);
        assert_eq!(result.total_loss, 1.0);
        for result in [result, optimize_ilp(&candidates, &goals)] {
            assert!(result.log_events.iter().any(|event| {
                event.event == "invalid_input"
                    && event
                        .note
                        .as_deref()
                        .is_some_and(|note| note.starts_with("excluded_invalid_candidates=8:"))
            }));
            assert_eq!(selected_ids(&result), ["valid"]);
        }

        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            for goal in [
                ResourceGoal {
                    target: bad,
                    ..goals[0].clone()
                },
                ResourceGoal {
                    weight: bad,
                    ..goals[0].clone()
                },
            ] {
                let result = optimize_greedy(&candidates, &[goal]);
                assert!(!result.feasible);
                assert!(result.selected.is_empty());
                assert!(result.goal_achievement.is_empty());
                assert!(result
                    .log_events
                    .iter()
                    .any(|event| event.event == "invalid_input"));
            }
        }
        let result = optimize_greedy_with_preferences(
            &candidates,
            &goals,
            &PreferenceModel {
                risk_tolerance: f64::NAN,
                ..PreferenceModel::default()
            },
        );
        assert!(!result.feasible);
        assert!(result.selected.is_empty());
    }

    #[test]
    fn greedy_log_ranking_retains_tiny_progress_and_finite_totals() {
        let goals = [ResourceGoal {
            resource: "memory".into(),
            target: 1e300,
            weight: 1e300,
        }];
        let candidates = [goal_candidate("tiny", 1e-300, &[1e-300])];
        let result = optimize_greedy(&candidates, &goals);
        assert!(!result.feasible);
        assert_eq!(selected_ids(&result), ["tiny"]);
        assert_eq!(result.total_contributions, [1e-300]);
        assert!(result
            .log_events
            .iter()
            .filter_map(|event| event.score)
            .all(f64::is_finite));

        let goals = [
            ResourceGoal {
                resource: "memory".into(),
                target: f64::MAX,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "fds".into(),
                target: 2.0,
                weight: 1.0,
            },
        ];
        let candidates = [
            goal_candidate("first", f64::MAX, &[f64::MAX, 1.0]),
            goal_candidate("second", f64::MAX, &[f64::MAX, 1.0]),
        ];
        let result = optimize_greedy(&candidates, &goals);
        assert!(!result.feasible);
        assert_eq!(selected_ids(&result), ["first"]);
        assert!(result.total_loss.is_finite());
        assert!(result
            .total_contributions
            .iter()
            .all(|value| value.is_finite()));
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["total_loss"].is_number());
        assert!(result
            .alternatives
            .iter()
            .all(|alternative| alternative.total_loss.is_finite()));
    }

    #[test]
    fn lazy_greedy_matches_eager_deficit_recalculation() {
        // An independent, small O(N^2) reference evaluates ordinary arithmetic
        // afresh after every action. Production uses logarithms and stale heap
        // bounds; agreement checks that lazy invalidation never skips a winner.
        let goals = [
            ResourceGoal {
                resource: "memory".into(),
                target: 4000.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "ports".into(),
                target: 17.0,
                weight: 2.0,
            },
            ResourceGoal {
                resource: "fds".into(),
                target: 300.0,
                weight: 4.0,
            },
        ];
        for seed in 0..12 {
            let candidates: Vec<_> = (0..24)
                .map(|i| {
                    let mut candidate = goal_candidate(
                        &format!("{i}"),
                        ((i * 31 + seed * 7) % 97 + 1) as f64,
                        &[
                            ((i * 79 + seed * 17) % 700 + 1) as f64,
                            ((i * 3 + seed * 5) % 8) as f64,
                            ((i * 29 + seed * 13) % 100) as f64,
                        ],
                    );
                    candidate.blocked = i % 13 == 0;
                    candidate
                })
                .collect();
            let mut remaining: Vec<_> = goals.iter().map(|goal| goal.target).collect();
            let mut used = HashSet::new();
            let mut expected = Vec::new();
            while remaining.iter().any(|value| *value > 0.0) {
                let mut best = None;
                let mut best_score = 0.0;
                for (index, candidate) in candidates.iter().enumerate() {
                    if candidate.blocked || used.contains(&index) {
                        continue;
                    }
                    let score = candidate
                        .contributions
                        .iter()
                        .zip(&goals)
                        .zip(&remaining)
                        .map(|((value, goal), deficit)| {
                            value.min(*deficit) / goal.target * goal.weight
                        })
                        .sum::<f64>()
                        / candidate.expected_loss;
                    if score > best_score {
                        best = Some(index);
                        best_score = score;
                    }
                }
                let Some(index) = best else {
                    break;
                };
                used.insert(index);
                expected.push(candidates[index].id.as_str());
                for (deficit, contribution) in
                    remaining.iter_mut().zip(&candidates[index].contributions)
                {
                    *deficit = (*deficit - contribution).max(0.0);
                }
            }
            let actual = optimize_greedy(&candidates, &goals);
            assert_eq!(selected_ids(&actual), expected, "seed={seed}");
        }
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

    // --- Serde roundtrip tests ---

    #[test]
    fn resource_goal_serde_roundtrip() {
        let goal = ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 512.0,
            weight: 2.5,
        };
        let json = serde_json::to_string(&goal).unwrap();
        let deser: ResourceGoal = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.resource, "memory_mb");
        assert!((deser.target - 512.0).abs() < 1e-9);
        assert!((deser.weight - 2.5).abs() < 1e-9);
    }

    #[test]
    fn opt_candidate_serde_roundtrip() {
        let cand = OptCandidate {
            id: "pid_42".to_string(),
            expected_loss: 0.75,
            contributions: vec![100.0, 50.0],
            blocked: true,
            block_reason: Some("protected".to_string()),
        };
        let json = serde_json::to_string(&cand).unwrap();
        let deser: OptCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "pid_42");
        assert!(deser.blocked);
        assert_eq!(deser.block_reason.as_deref(), Some("protected"));
        assert_eq!(deser.contributions.len(), 2);
    }

    #[test]
    fn selected_action_serde_roundtrip() {
        let sa = SelectedAction {
            id: "pid_1".to_string(),
            expected_loss: 0.3,
            contributions: vec![200.0],
        };
        let json = serde_json::to_string(&sa).unwrap();
        let deser: SelectedAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "pid_1");
        assert!((deser.expected_loss - 0.3).abs() < 1e-9);
    }

    #[test]
    fn goal_achievement_serde_roundtrip() {
        let ga = GoalAchievement {
            resource: "cpu_pct".to_string(),
            target: 50.0,
            achieved: 45.0,
            shortfall: 5.0,
            met: false,
        };
        let json = serde_json::to_string(&ga).unwrap();
        let deser: GoalAchievement = serde_json::from_str(&json).unwrap();
        assert!(!deser.met);
        assert!((deser.shortfall - 5.0).abs() < 1e-9);
    }

    #[test]
    fn alternative_plan_serde_roundtrip() {
        let alt = AlternativePlan {
            description: "Conservative plan".to_string(),
            action_count: 2,
            total_loss: 0.5,
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 100.0,
                achieved: 80.0,
                shortfall: 20.0,
                met: false,
            }],
        };
        let json = serde_json::to_string(&alt).unwrap();
        let deser: AlternativePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.action_count, 2);
        assert_eq!(deser.goal_achievement.len(), 1);
    }

    #[test]
    fn optimization_log_event_new_defaults() {
        let event = OptimizationLogEvent::new("test_event", "test_algo");
        assert_eq!(event.event, "test_event");
        assert_eq!(event.algorithm, "test_algo");
        assert!(event.candidate_id.is_none());
        assert!(event.loss.is_none());
        assert!(event.score.is_none());
        assert!(event.total_loss.is_none());
        assert!(event.total_contributions.is_empty());
        assert!(event.target.is_none());
        assert!(event.current_contribution.is_none());
        assert!(event.remaining_max.is_none());
        assert!(event.note.is_none());
    }

    #[test]
    fn optimization_log_event_serde_roundtrip() {
        let mut event = OptimizationLogEvent::new("converged", "greedy");
        event.total_loss = Some(1.5);
        event.total_contributions = vec![300.0, 50.0];
        let json = serde_json::to_string(&event).unwrap();
        let deser: OptimizationLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.event, "converged");
        assert_eq!(deser.total_contributions.len(), 2);
    }

    // --- PreferenceModel tests ---

    #[test]
    fn preference_model_default() {
        let pm = PreferenceModel::default();
        assert!((pm.risk_tolerance - 0.5).abs() < 1e-9);
        assert!((pm.learning_rate - 0.2).abs() < 1e-9);
    }

    #[test]
    fn preference_model_adjust_loss_conservative() {
        // risk_tolerance = 0 => exponent = 2.0 => loss^2
        let pm = PreferenceModel {
            risk_tolerance: 0.0,
            learning_rate: 0.2,
        };
        let adjusted = pm.adjust_loss(0.5);
        // 0.5^2 = 0.25
        assert!((adjusted - 0.25).abs() < 1e-9);
    }

    #[test]
    fn preference_model_adjust_loss_aggressive() {
        // risk_tolerance = 1.0 => exponent = 1.0 => loss^1 = loss
        let pm = PreferenceModel {
            risk_tolerance: 1.0,
            learning_rate: 0.2,
        };
        let adjusted = pm.adjust_loss(0.5);
        assert!((adjusted - 0.5).abs() < 1e-9);
    }

    #[test]
    fn preference_model_adjust_loss_min_floor() {
        let pm = PreferenceModel::default();
        let adjusted = pm.adjust_loss(0.0);
        // Should be at least 1e-12
        assert!(adjusted >= 1e-12);
    }

    #[test]
    fn preference_model_update_from_choice_learns() {
        let mut pm = PreferenceModel {
            risk_tolerance: 0.5,
            learning_rate: 0.5,
        };

        let chosen = AlternativePlan {
            description: "aggressive".to_string(),
            action_count: 5,
            total_loss: 8.0, // high loss = aggressive
            goal_achievement: vec![],
        };
        let alternatives = vec![
            AlternativePlan {
                description: "safe".to_string(),
                action_count: 1,
                total_loss: 2.0,
                goal_achievement: vec![],
            },
            AlternativePlan {
                description: "aggressive".to_string(),
                action_count: 5,
                total_loss: 8.0,
                goal_achievement: vec![],
            },
        ];

        let update = pm.update_from_choice(&chosen, &alternatives);
        assert!((update.prior - 0.5).abs() < 1e-9);
        assert!((update.observed - 1.0).abs() < 1e-9); // (8-2)/(8-2) = 1.0
                                                       // updated = 0.5 * 0.5 + 1.0 * 0.5 = 0.75
        assert!((update.updated - 0.75).abs() < 1e-9);
        assert!((pm.risk_tolerance - 0.75).abs() < 1e-9);
    }

    #[test]
    fn preference_model_update_equal_alternatives() {
        let mut pm = PreferenceModel::default();
        let chosen = AlternativePlan {
            description: "only".to_string(),
            action_count: 1,
            total_loss: 5.0,
            goal_achievement: vec![],
        };
        let alternatives = vec![AlternativePlan {
            description: "only".to_string(),
            action_count: 1,
            total_loss: 5.0,
            goal_achievement: vec![],
        }];
        let update = pm.update_from_choice(&chosen, &alternatives);
        // min == max => observed = 0.5
        assert!((update.observed - 0.5).abs() < 1e-9);
    }

    #[test]
    fn preference_update_serde_roundtrip() {
        let pu = PreferenceUpdate {
            prior: 0.5,
            observed: 0.8,
            updated: 0.56,
        };
        let json = serde_json::to_string(&pu).unwrap();
        let deser: PreferenceUpdate = serde_json::from_str(&json).unwrap();
        assert!((deser.prior - 0.5).abs() < 1e-9);
    }

    // --- optimize_greedy_with_preferences ---

    #[test]
    fn greedy_with_preferences_conservative() {
        let candidates = make_candidates(5);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 300.0,
            weight: 1.0,
        }];
        let prefs = PreferenceModel {
            risk_tolerance: 0.0, // very conservative
            learning_rate: 0.2,
        };
        let result = optimize_greedy_with_preferences(&candidates, &goals, &prefs);
        assert_eq!(result.algorithm, "greedy_pref");
        assert!(result.feasible);
    }

    // --- DP fallback tests ---

    #[test]
    fn dp_multi_goal_falls_back_to_greedy() {
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
        // Multi-goal candidates need matching contribution vectors
        let candidates = vec![OptCandidate {
            id: "a".to_string(),
            expected_loss: 0.5,
            contributions: vec![200.0, 80.0],
            blocked: false,
            block_reason: None,
        }];
        let result = optimize_dp(&candidates, &goals, 10.0);
        assert!(result.algorithm.contains("greedy fallback"));
    }

    #[test]
    fn dp_empty_candidates_falls_back() {
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_dp(&[], &goals, 10.0);
        assert!(result.algorithm.contains("greedy fallback"));
        assert!(!result.feasible);
    }

    #[test]
    fn dp_infeasible_falls_back() {
        let candidates = vec![OptCandidate {
            id: "small".to_string(),
            expected_loss: 0.1,
            contributions: vec![10.0],
            blocked: false,
            block_reason: None,
        }];
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 10000.0, // way more than 10
            weight: 1.0,
        }];
        let result = optimize_dp(&candidates, &goals, 1.0);
        // Should be infeasible; either DP or greedy fallback but not feasible
        assert!(!result.feasible);
    }

    // --- ILP tests ---

    #[test]
    fn action_limit_changes_the_optimum_instead_of_truncating_it() {
        let candidates = [
            goal_candidate("cheap-a", 1.0, &[60.0]),
            goal_candidate("cheap-b", 1.0, &[60.0]),
            goal_candidate("sufficient", 5.0, &[100.0]),
        ];
        let goals = [ResourceGoal {
            resource: "memory".into(),
            target: 100.0,
            weight: 1.0,
        }];
        let unconstrained = optimize_ilp(&candidates, &goals);
        assert_eq!(unconstrained.total_loss, 2.0);
        assert_eq!(unconstrained.selected.len(), 2);

        for result in [
            optimize_ilp_with_limit(&candidates, &goals, 1),
            optimize_greedy_with_limit(&candidates, &goals, 1),
        ] {
            assert!(result.feasible);
            assert_eq!(selected_ids(&result), ["sufficient"]);
            assert_eq!(result.total_loss, 5.0);
            assert_eq!(result.total_contributions, [100.0]);
            assert!(result
                .alternatives
                .iter()
                .all(|plan| plan.action_count <= 1));
        }

        assert_eq!(
            serde_json::to_value(optimize_ilp(&candidates, &goals)).unwrap(),
            serde_json::to_value(optimize_ilp_with_limit(&candidates, &goals, usize::MAX)).unwrap()
        );
        assert_eq!(
            serde_json::to_value(optimize_greedy(&candidates, &goals)).unwrap(),
            serde_json::to_value(optimize_greedy_with_limit(&candidates, &goals, usize::MAX))
                .unwrap()
        );
    }

    #[test]
    fn zero_action_limit_reports_shortfall_but_accepts_already_met_goals() {
        let candidates = [goal_candidate("holder", 1.0, &[100.0])];
        for target in [0.0, 100.0] {
            let goals = [ResourceGoal {
                resource: "memory".into(),
                target,
                weight: 1.0,
            }];
            for result in [
                optimize_ilp_with_limit(&candidates, &goals, 0),
                optimize_greedy_with_limit(&candidates, &goals, 0),
            ] {
                assert!(result.selected.is_empty());
                assert!(result.alternatives.is_empty());
                assert_eq!(result.feasible, target == 0.0);
                assert_eq!(result.total_loss, 0.0);
                assert_eq!(result.total_contributions, [0.0]);
                assert_eq!(result.goal_achievement[0].shortfall, target);
            }
        }
    }

    #[test]
    fn limited_multigoal_greedy_preserves_a_joint_holder_even_with_zero_weight() {
        let candidates = [
            goal_candidate("memory-only", 1.0, &[100.0, 0.0]),
            goal_candidate("fds-only", 1.0, &[0.0, 100.0]),
            goal_candidate("joint-holder", 9.0, &[100.0, 100.0]),
        ];
        for fd_weight in [0.0, 1.0] {
            let goals = [
                ResourceGoal {
                    resource: "memory".into(),
                    target: 100.0,
                    weight: 1.0,
                },
                ResourceGoal {
                    resource: "fds".into(),
                    target: 100.0,
                    weight: fd_weight,
                },
            ];
            for result in [
                optimize_greedy_with_limit(&candidates, &goals, 1),
                optimize_ilp_with_limit(&candidates, &goals, 1),
            ] {
                assert!(result.feasible);
                assert_eq!(selected_ids(&result), ["joint-holder"]);
                assert_eq!(result.total_loss, 9.0);
                assert_eq!(result.total_contributions, [100.0, 100.0]);
                assert!(result
                    .alternatives
                    .iter()
                    .all(|plan| plan.action_count <= 1));
            }
            let result = optimize_greedy_with_limit(&candidates, &goals, 2);
            assert!(result.feasible);
            assert_eq!(result.total_loss, 2.0);
            assert_eq!(result.selected.len(), 2);
            assert!(result
                .alternatives
                .iter()
                .all(|plan| plan.action_count <= 2));
        }
    }

    #[test]
    fn limited_solvers_exclude_blocked_and_invalid_candidates() {
        let mut protected = goal_candidate("protected", 0.0, &[1000.0]);
        protected.blocked = true;
        protected.block_reason = Some("protected process".into());
        let candidates = [
            protected,
            goal_candidate("nan-loss", f64::NAN, &[1000.0]),
            goal_candidate("infinite-contribution", 0.0, &[f64::INFINITY]),
            goal_candidate("missing-observation", 0.0, &[]),
            goal_candidate("no-progress", 0.0, &[0.0]),
            goal_candidate("safe-partial", 1.0, &[60.0]),
            goal_candidate("safe-partial-2", 1.0, &[60.0]),
        ];
        let goals = [ResourceGoal {
            resource: "memory".into(),
            target: 100.0,
            weight: 1.0,
        }];
        for result in [
            optimize_ilp_with_limit(&candidates, &goals, 1),
            optimize_greedy_with_limit(&candidates, &goals, 1),
        ] {
            assert!(!result.feasible);
            assert_eq!(selected_ids(&result), ["safe-partial"]);
            assert_eq!(result.total_loss, 1.0);
            assert_eq!(result.total_contributions, [60.0]);
            assert_eq!(result.goal_achievement[0].shortfall, 40.0);
            assert!(result
                .alternatives
                .iter()
                .all(|plan| plan.action_count <= 1));
        }

        let invalid_goal = [ResourceGoal {
            target: f64::NAN,
            ..goals[0].clone()
        }];
        for result in [
            optimize_ilp_with_limit(&candidates, &invalid_goal, 1),
            optimize_greedy_with_limit(&candidates, &invalid_goal, 1),
        ] {
            assert!(!result.feasible);
            assert!(result.selected.is_empty());
            assert!(result.goal_achievement.is_empty());
        }
    }

    #[test]
    fn limited_ilp_matches_an_independent_exhaustive_subset_oracle() {
        let mut state = 0x71c9_43b8_2a65_0df1_u64;
        let mut sample = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state >> 32
        };
        for case in 0..48 {
            let count = 1 + (sample() % 8) as usize;
            let candidates: Vec<_> = (0..count)
                .map(|index| {
                    let mut candidate = goal_candidate(
                        &format!("case-{case}-candidate-{index}"),
                        (sample() % 9) as f64,
                        &[(sample() % 17) as f64],
                    );
                    candidate.blocked = sample().is_multiple_of(7);
                    candidate
                })
                .collect();
            let target = (sample() % 65) as f64;
            let goals = [ResourceGoal {
                resource: "memory".into(),
                target,
                weight: 1.0,
            }];

            for limit in 0..=count + 1 {
                // Enumerate raw subsets without using the optimizer's ranking,
                // eligibility, pruning, incumbent, or achievement helpers.
                let mut optimum: Option<f64> = None;
                for mask in 0..(1_u32 << count) {
                    if mask.count_ones() as usize > limit {
                        continue;
                    }
                    let mut loss = 0.0;
                    let mut contribution = 0.0;
                    let mut blocked = false;
                    for (index, candidate) in candidates.iter().enumerate() {
                        if mask & (1_u32 << index) != 0 {
                            blocked |= candidate.blocked;
                            loss += candidate.expected_loss;
                            contribution += candidate.contributions[0];
                        }
                    }
                    if !blocked && contribution >= target {
                        optimum = Some(optimum.map_or(loss, |previous| previous.min(loss)));
                    }
                }

                let result = optimize_ilp_with_limit(&candidates, &goals, limit);
                assert_eq!(
                    result.feasible,
                    optimum.is_some(),
                    "case={case} limit={limit}"
                );
                if let Some(loss) = optimum {
                    assert_eq!(result.total_loss, loss, "case={case} limit={limit}");
                }
                assert!(result.selected.len() <= limit);
                let mut ids = HashSet::new();
                let mut measured = 0.0;
                let mut actual_loss = 0.0;
                for selected in &result.selected {
                    assert!(ids.insert(selected.id.as_str()));
                    let original = candidates
                        .iter()
                        .find(|candidate| candidate.id == selected.id)
                        .unwrap();
                    assert!(!original.blocked);
                    measured += original.contributions[0];
                    actual_loss += original.expected_loss;
                }
                assert_eq!(result.total_contributions, [measured]);
                assert_eq!(result.total_loss, actual_loss);
                assert_eq!(result.goal_achievement[0].met, measured >= target);
                assert_eq!(
                    result.goal_achievement[0].shortfall,
                    (target - measured).max(0.0)
                );
            }
        }
    }

    #[test]
    fn limited_ilp_large_set_fallback_retains_a_sufficient_action() {
        let mut candidates: Vec<_> = (0..ILP_CANDIDATE_LIMIT + 1)
            .map(|index| goal_candidate(&format!("partial-{index}"), 1.0, &[60.0]))
            .collect();
        candidates.push(goal_candidate("sufficient", 5.0, &[100.0]));
        let goals = [ResourceGoal {
            resource: "memory".into(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_ilp_with_limit(&candidates, &goals, 1);
        assert!(result.feasible);
        assert_eq!(selected_ids(&result), ["sufficient"]);
        assert_eq!(result.total_loss, 5.0);
        assert_eq!(result.total_contributions, [100.0]);
        assert!(result.algorithm.contains("candidate_limit"));
        assert!(result.algorithm.contains("optimum not proven"));
        let search = result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap();
        assert_eq!(search.visited_nodes, 0);
        assert!(!search.optimum_proven);
        assert!(result.alternatives.is_empty());
        assert!(result.log_events.len() <= ILP_SEARCH_LOG_LIMIT + 4);
    }

    #[test]
    fn limited_ilp_budget_retains_capacity_seed_when_efficiency_seed_cannot_fit() {
        let mut candidates: Vec<_> = (0..50)
            .map(|index| goal_candidate(&format!("partial-{index}"), 0.25, &[1.0]))
            .collect();
        candidates.push(goal_candidate("sufficient", 100.0, &[100.0]));
        let goals = [ResourceGoal {
            resource: "memory".into(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_ilp_with_limit(&candidates, &goals, 25);
        assert!(result.feasible);
        assert_eq!(selected_ids(&result), ["sufficient"]);
        assert_eq!(result.total_loss, 100.0);
        assert_eq!(result.total_contributions, [100.0]);
        assert!(result.algorithm.contains("node_budget_exhausted"));
        let search = result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap();
        assert_eq!(search.visited_nodes, ILP_NODE_BUDGET);
        assert!(!search.optimum_proven);
        assert!(result.log_events.len() <= ILP_SEARCH_LOG_LIMIT + 1);
    }


    #[test]
    fn combined_goal_search_replaces_a_greedy_dead_end_with_a_feasible_cover() {
        for memory_scale in [1.0, 1024.0] {
            for cpu_weight in [0.0, 1.0, 1000.0] {
                let candidates = [
                    goal_candidate("partial-both", 1.0, &[9.0 * memory_scale, 9.0]),
                    goal_candidate("memory-holder", 2.0, &[10.0 * memory_scale, 0.0]),
                    goal_candidate("cpu-holder", 2.0, &[0.0, 10.0]),
                ];
                let goals = [
                    ResourceGoal {
                        resource: "memory".into(),
                        target: 10.0 * memory_scale,
                        weight: 1.0,
                    },
                    ResourceGoal {
                        resource: "cpu".into(),
                        target: 10.0,
                        weight: cpu_weight,
                    },
                ];
                let result = optimize_ilp_with_limit(&candidates, &goals, 2);
                assert!(result.feasible, "{result:?}");
                let mut ids = selected_ids(&result);
                ids.sort_unstable();
                assert_eq!(ids, ["cpu-holder", "memory-holder"]);
                assert_eq!(result.total_loss, 4.0);
                assert_eq!(result.total_contributions, [10.0 * memory_scale, 10.0]);
                assert!(result.goal_achievement.iter().all(|goal| goal.met));
                assert!(result
                    .log_events
                    .iter()
                    .find_map(|event| event.search.as_ref())
                    .unwrap()
                    .optimum_proven);

                // Replanning must not fall back to the old multi-goal greedy
                // path, which spends five loss units on all three candidates.
                let previous = optimize_ilp(&[], &goals);
                let updated = reoptimize_on_change(&previous, &[], &candidates, &goals);
                assert!(updated.reoptimized);
                assert!(updated.result.feasible);
                assert_eq!(updated.result.total_loss, 4.0);
                assert_eq!(updated.result.selected.len(), 2);
            }
        }
    }

    #[test]
    fn multigoal_ilp_matches_an_independent_exhaustive_subset_oracle() {
        let mut state = 0x9f62_0d71_aa35_4be8_u64;
        let mut sample = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state >> 32
        };
        let mut feasible_cases = 0;
        let mut infeasible_cases = 0;
        for case in 0..48 {
            let count = 3 + (sample() % 5) as usize;
            let dimensions = 2 + (sample() % 3) as usize;
            let candidates: Vec<_> = (0..count)
                .map(|index| {
                    let contributions: Vec<_> =
                        (0..dimensions).map(|_| (sample() % 12) as f64).collect();
                    let mut candidate = goal_candidate(
                        &format!("case-{case}-candidate-{index}"),
                        (sample() % 9) as f64,
                        &contributions,
                    );
                    candidate.blocked = sample().is_multiple_of(7);
                    candidate
                })
                .collect();
            let goals: Vec<_> = (0..dimensions)
                .map(|dimension| {
                    let available: u64 = candidates
                        .iter()
                        .filter(|candidate| !candidate.blocked)
                        .map(|candidate| candidate.contributions[dimension] as u64)
                        .sum();
                    ResourceGoal {
                        resource: format!("resource-{dimension}"),
                        target: (sample() % (available + 5)) as f64,
                        weight: (sample() % 4) as f64,
                    }
                })
                .collect();

            for limit in 0..=count + 1 {
                // Independent enumeration over raw input records: no optimizer
                // eligibility, ranking, bounds, seed or achievement helper.
                let mut optimum: Option<f64> = None;
                for mask in 0..(1_u32 << count) {
                    if mask.count_ones() as usize > limit {
                        continue;
                    }
                    let mut totals = vec![0.0; dimensions];
                    let mut loss = 0.0;
                    let mut blocked = false;
                    for (index, candidate) in candidates.iter().enumerate() {
                        if mask & (1_u32 << index) != 0 {
                            blocked |= candidate.blocked;
                            loss += candidate.expected_loss;
                            for (total, contribution) in
                                totals.iter_mut().zip(&candidate.contributions)
                            {
                                *total += contribution;
                            }
                        }
                    }
                    if !blocked
                        && totals.iter().zip(&goals).all(|(total, goal)| *total >= goal.target)
                    {
                        optimum = Some(optimum.map_or(loss, |previous| previous.min(loss)));
                    }
                }

                let result = optimize_ilp_with_limit(&candidates, &goals, limit);
                assert_eq!(
                    result.feasible,
                    optimum.is_some(),
                    "case={case} limit={limit}"
                );
                if let Some(loss) = optimum {
                    feasible_cases += 1;
                    assert_eq!(result.total_loss, loss, "case={case} limit={limit}");
                } else {
                    infeasible_cases += 1;
                }
                assert!(result.selected.len() <= limit);
                let mut ids = HashSet::new();
                let mut measured = vec![0.0; dimensions];
                let mut actual_loss = 0.0;
                for selected in &result.selected {
                    assert!(ids.insert(selected.id.as_str()));
                    let original = candidates
                        .iter()
                        .find(|candidate| candidate.id == selected.id)
                        .unwrap();
                    assert!(!original.blocked);
                    actual_loss += original.expected_loss;
                    for (total, contribution) in measured.iter_mut().zip(&original.contributions) {
                        *total += contribution;
                    }
                }
                assert_eq!(result.total_loss, actual_loss);
                assert_eq!(result.total_contributions, measured);
                assert_eq!(result.goal_achievement.len(), dimensions);
                for ((achievement, goal), measured) in
                    result.goal_achievement.iter().zip(&goals).zip(measured)
                {
                    assert_eq!(achievement.achieved, measured);
                    assert_eq!(achievement.met, measured >= goal.target);
                    assert_eq!(achievement.shortfall, (goal.target - measured).max(0.0));
                }
            }
        }
        assert!(feasible_cases > 0);
        assert!(infeasible_cases > 0);
    }

    #[test]
    fn multigoal_dimension_limit_uses_a_capped_nonrecursive_fallback() {
        let goals: Vec<_> = (0..ILP_GOAL_LIMIT + 1)
            .map(|dimension| ResourceGoal {
                resource: format!("resource-{dimension}"),
                target: 1.0,
                weight: 1.0,
            })
            .collect();
        let candidates = [
            goal_candidate("partial", 1.0, &vec![0.5; goals.len()]),
            goal_candidate("sufficient", 3.0, &vec![1.0; goals.len()]),
        ];
        for limit in [0, 1, usize::MAX] {
            let result = optimize_ilp_with_limit(&candidates, &goals, limit);
            assert_eq!(result.feasible, limit > 0);
            assert!(result.selected.len() <= limit);
            if limit == 1 {
                assert_eq!(selected_ids(&result), ["sufficient"]);
                assert_eq!(result.total_loss, 3.0);
            }
            assert!(result.algorithm.contains("goal_limit"));
            assert!(result.algorithm.contains("optimum not proven"));
            let search = result
                .log_events
                .iter()
                .find_map(|event| event.search.as_ref())
                .unwrap();
            assert_eq!(search.visited_nodes, 0);
            assert!(!search.optimum_proven);
            assert!(result.alternatives.is_empty());
        }
    }

    #[test]
    fn multigoal_search_rejects_nonfinite_secondary_totals_and_blocked_holders() {
        let mut protected = goal_candidate("protected", 0.0, &[2.0, 1.0]);
        protected.blocked = true;
        let candidates = [
            protected,
            goal_candidate("invalid", 0.0, &[2.0, f64::NAN]),
            goal_candidate("large-a", 1.0, &[1.0, f64::MAX]),
            goal_candidate("large-b", 1.0, &[1.0, f64::MAX]),
            goal_candidate("finite-complement", 4.0, &[1.0, 0.0]),
        ];
        let goals = [
            ResourceGoal {
                resource: "memory".into(),
                target: 2.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "cpu".into(),
                target: 1.0,
                weight: 0.0,
            },
        ];
        let result = optimize_ilp_with_limit(&candidates, &goals, 2);
        assert!(result.feasible);
        assert_eq!(result.selected.len(), 2);
        assert!(result.selected.iter().any(|action| action.id == "finite-complement"));
        assert!(result
            .selected
            .iter()
            .all(|action| action.id != "protected" && action.id != "invalid"));
        assert_eq!(result.total_loss, 5.0);
        assert_eq!(result.total_contributions, [2.0, f64::MAX]);
        assert!(result.total_contributions.iter().all(|total| total.is_finite()));
    }

    #[test]
    fn multigoal_work_budget_retains_a_feasible_incumbent_without_proving_optimality() {
        let candidates: Vec<_> = (0..50)
            .map(|index| goal_candidate(&format!("candidate-{index}"), 1.0, &[1.0, 1.0]))
            .collect();
        let goals: Vec<_> = ["memory", "cpu"]
            .into_iter()
            .map(|resource| ResourceGoal {
                resource: resource.into(),
                target: 25.0,
                weight: 1.0,
            })
            .collect();
        let result = optimize_ilp_with_limit(&candidates, &goals, 25);
        assert!(result.feasible);
        assert_eq!(result.selected.len(), 25);
        assert_eq!(result.total_loss, 25.0);
        assert_eq!(result.total_contributions, [25.0, 25.0]);
        assert!(result.algorithm.contains("node_budget_exhausted"));
        let search = result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap();
        assert_eq!(search.visited_nodes, ILP_NODE_BUDGET);
        assert!(!search.optimum_proven);
        assert!(result.log_events.len() <= ILP_SEARCH_LOG_LIMIT + 1);
    }

    #[test]
    fn multigoal_budget_without_an_incumbent_does_not_claim_proven_infeasibility() {
        // Both resources can individually reach 70 with at most 25 actions,
        // but their disjoint holders need 18 + 18 actions together. Independent
        // resource bounds admit enough branches to exhaust the work budget.
        let candidates: Vec<_> = (0..50)
            .map(|index| {
                let contribution = if index < 25 { [4.0, 0.0] } else { [0.0, 4.0] };
                goal_candidate(&format!("candidate-{index}"), 1.0, &contribution)
            })
            .collect();
        let goals: Vec<_> = ["memory", "cpu"]
            .into_iter()
            .map(|resource| ResourceGoal {
                resource: resource.into(),
                target: 70.0,
                weight: 1.0,
            })
            .collect();
        let result = optimize_ilp_with_limit(&candidates, &goals, 25);
        assert!(!result.feasible);
        assert!(result.selected.len() <= 25);
        assert!(result.algorithm.contains("node_budget_exhausted"));
        assert!(!result.algorithm.contains("infeasible"));
        let event = result
            .log_events
            .iter()
            .find(|event| event.event == "search_budget_exhausted")
            .unwrap();
        let search = event.search.as_ref().unwrap();
        assert_eq!(search.visited_nodes, ILP_NODE_BUDGET);
        assert!(!search.optimum_proven);
        assert!(event.note.as_deref().unwrap().contains("feasibility and optimum not proven"));
        assert!(!result
            .log_events
            .iter()
            .any(|event| event.note.as_deref() == Some("ilp_infeasible")));
        assert!(result.log_events.len() <= 2 * ILP_SEARCH_LOG_LIMIT + 4);
    }

    #[test]
    fn ilp_single_goal_basic() {
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
        let result = optimize_ilp(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(result.algorithm, "ilp_branch_bound");
        // B+C = 250 at cost 0.8 is optimal
        assert!(result.total_loss <= 0.81);
        let search = result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap();
        assert!(search.optimum_proven);
        assert!(search.visited_nodes <= search.node_budget);
        assert!(!result
            .log_events
            .iter()
            .any(|event| event.event == "search_budget_exhausted"));
    }

    #[test]
    fn ilp_budget_bounds_equal_cost_search_and_preserves_safe_incumbent() {
        // There are C(50, 25) equally priced solutions. Without a work budget,
        // include/exclude search keeps exploring after finding the first one.
        let mut candidates: Vec<_> = (0..50)
            .map(|index| OptCandidate {
                id: format!("eligible-{index}"),
                expected_loss: 1.0,
                contributions: vec![1.0],
                blocked: false,
                block_reason: None,
            })
            .collect();
        candidates.push(OptCandidate {
            id: "blocked".to_string(),
            expected_loss: 0.0,
            contributions: vec![1000.0],
            blocked: true,
            block_reason: Some("protected".to_string()),
        });
        candidates.push(OptCandidate {
            id: "no-observation".to_string(),
            expected_loss: 0.0,
            contributions: vec![0.0],
            blocked: false,
            block_reason: None,
        });
        let goals = [ResourceGoal {
            resource: "fd_count".to_string(),
            target: 25.0,
            weight: 1.0,
        }];

        let result = optimize_ilp(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(result.selected.len(), 25);
        assert_eq!(result.total_contributions, [25.0]);
        assert_eq!(result.total_loss, 25.0);
        assert!(result
            .selected
            .iter()
            .all(|action| action.id.starts_with("eligible-")));
        assert!(result.algorithm.contains("node_budget_exhausted"));
        assert!(result.algorithm.contains("optimum not proven"));
        let event = result
            .log_events
            .iter()
            .find(|event| event.event == "search_budget_exhausted")
            .unwrap();
        let search = event.search.as_ref().unwrap();
        assert_eq!(search.visited_nodes, ILP_NODE_BUDGET);
        assert_eq!(search.node_budget, ILP_NODE_BUDGET);
        assert_eq!(search.eligible_candidates, 50);
        assert!(!search.optimum_proven);
        assert!(result.log_events.len() <= ILP_SEARCH_LOG_LIMIT + 1);
        assert!(result.alternatives.is_empty());
    }

    #[test]
    fn ilp_budget_uses_nonrecursive_fallback_without_pareto_enumeration() {
        let count = ILP_CANDIDATE_LIMIT * 4;
        let candidates: Vec<_> = (0..count)
            .map(|index| OptCandidate {
                id: format!("eligible-{index}"),
                expected_loss: 1.0,
                contributions: vec![1.0],
                blocked: false,
                block_reason: None,
            })
            .collect();
        let goals = [ResourceGoal {
            resource: "fd_count".to_string(),
            target: count as f64,
            weight: 1.0,
        }];
        let result = optimize_ilp(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(result.selected.len(), count);
        assert_eq!(result.total_loss, count as f64);
        assert_eq!(result.total_contributions, [count as f64]);
        assert!(result.algorithm.contains("candidate_limit"));
        assert!(result.algorithm.contains("greedy fallback"));
        assert!(result.algorithm.contains("optimum not proven"));
        let search = result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap();
        assert_eq!(
            search.visited_nodes, 0,
            "large sets must not enter recursion"
        );
        assert_eq!(search.candidate_limit, ILP_CANDIDATE_LIMIT);
        assert_eq!(search.eligible_candidates, count);
        assert!(!search.optimum_proven);
        assert!(result.log_events.len() <= ILP_SEARCH_LOG_LIMIT + 3);
        assert!(result.alternatives.is_empty());
    }

    #[test]
    fn composite_goal_bounds_optional_frontier_without_truncating_primary_plan() {
        let candidates: Vec<_> = (0..50)
            .map(|index| OptCandidate {
                id: format!("eligible-{index}"),
                expected_loss: 1.0,
                contributions: vec![1.0, 1.0],
                blocked: false,
                block_reason: None,
            })
            .collect();
        let goals = [
            ResourceGoal {
                resource: "memory_mb".to_string(),
                target: 25.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "fd_count".to_string(),
                target: 25.0,
                weight: 1.0,
            },
        ];
        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert_eq!(result.selected.len(), 25);
        assert_eq!(result.total_loss, 25.0);
        assert_eq!(result.total_contributions, [25.0, 25.0]);
        let cap = result
            .log_events
            .iter()
            .find(|event| {
                event.algorithm == "pareto_frontier"
                    && event
                        .note
                        .as_deref()
                        .is_some_and(|note| note.starts_with("candidate_cap:"))
            })
            .expect("truncating optional alternatives must be explicit");
        assert_eq!(cap.note.as_deref(), Some("candidate_cap: 50 -> 8"));
        assert!(result
            .selected
            .iter()
            .any(|action| action.id == "eligible-24"));
        assert!(result
            .alternatives
            .iter()
            .any(|alternative| alternative.action_count == 26));
    }

    #[test]
    fn ilp_multi_goal_finds_and_proves_a_joint_solution() {
        let candidates = vec![OptCandidate {
            id: "a".to_string(),
            expected_loss: 0.5,
            contributions: vec![200.0, 80.0],
            blocked: false,
            block_reason: None,
        }];
        let goals = vec![
            ResourceGoal {
                resource: "mem".to_string(),
                target: 100.0,
                weight: 1.0,
            },
            ResourceGoal {
                resource: "cpu".to_string(),
                target: 50.0,
                weight: 1.0,
            },
        ];
        let result = optimize_ilp(&candidates, &goals);
        assert_eq!(result.algorithm, "ilp_branch_bound");
        assert!(result.feasible);
        assert_eq!(selected_ids(&result), ["a"]);
        assert_eq!(result.total_loss, 0.5);
        assert_eq!(result.total_contributions, [200.0, 80.0]);
        assert!(result
            .log_events
            .iter()
            .find_map(|event| event.search.as_ref())
            .unwrap()
            .optimum_proven);
    }

    #[test]
    fn ilp_empty_candidates_falls_back() {
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_ilp(&[], &goals);
        assert!(result.algorithm.contains("greedy fallback"));
    }

    #[test]
    fn ilp_all_blocked_falls_back() {
        let candidates = vec![OptCandidate {
            id: "blocked".to_string(),
            expected_loss: 0.5,
            contributions: vec![200.0],
            blocked: true,
            block_reason: Some("protected".to_string()),
        }];
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_ilp(&candidates, &goals);
        assert!(result.algorithm.contains("greedy fallback"));
    }

    #[test]
    fn ilp_infeasible_falls_back() {
        let candidates = vec![OptCandidate {
            id: "tiny".to_string(),
            expected_loss: 0.1,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        }];
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 10000.0,
            weight: 1.0,
        }];
        let result = optimize_ilp(&candidates, &goals);
        assert!(!result.feasible);
    }

    // --- Reoptimization tests ---

    #[test]
    fn reoptimize_no_change() {
        let candidates = make_candidates(3);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let prev = optimize_greedy(&candidates, &goals);
        let decision = reoptimize_on_change(&prev, &candidates, &candidates, &goals);
        assert!(!decision.reoptimized);
        assert_eq!(decision.reason, "no_change");
        assert!(decision.added.is_empty());
        assert!(decision.removed.is_empty());
    }

    #[test]
    fn reoptimize_stable_below_threshold() {
        let candidates = make_candidates(10);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let prev = optimize_greedy(&candidates, &goals);

        // Add 1 candidate to 10 = 10% churn, below 20% threshold
        let mut new_candidates = candidates.clone();
        new_candidates.push(OptCandidate {
            id: "pid_10".to_string(),
            expected_loss: 0.5,
            contributions: vec![100.0],
            blocked: false,
            block_reason: None,
        });
        let decision = reoptimize_on_change(&prev, &candidates, &new_candidates, &goals);
        assert!(!decision.reoptimized);
        assert_eq!(decision.reason, "stable");
    }

    #[test]
    fn reoptimize_churn_threshold_exceeded() {
        let candidates = make_candidates(5);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let prev = optimize_greedy(&candidates, &goals);

        // Replace 2 of 5 candidates = 40% churn, exceeds 20% threshold
        let mut new_candidates = candidates[..3].to_vec();
        new_candidates.push(OptCandidate {
            id: "new_a".to_string(),
            expected_loss: 0.2,
            contributions: vec![150.0],
            blocked: false,
            block_reason: None,
        });
        new_candidates.push(OptCandidate {
            id: "new_b".to_string(),
            expected_loss: 0.3,
            contributions: vec![200.0],
            blocked: false,
            block_reason: None,
        });
        let decision = reoptimize_on_change(&prev, &candidates, &new_candidates, &goals);
        assert!(decision.reoptimized);
        assert_eq!(decision.reason, "churn_threshold");
    }

    #[test]
    fn reoptimize_selected_missing() {
        let candidates = make_candidates(5);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 300.0,
            weight: 1.0,
        }];
        let prev = optimize_greedy(&candidates, &goals);

        // Remove some candidates that are in the selected set
        let selected_ids: HashSet<String> = prev.selected.iter().map(|s| s.id.clone()).collect();
        let new_candidates: Vec<OptCandidate> = candidates
            .into_iter()
            .filter(|c| !selected_ids.contains(&c.id))
            .collect();
        // Only run if we actually removed selected candidates
        if !new_candidates.is_empty() {
            let decision =
                reoptimize_on_change(&prev, &make_candidates(5), &new_candidates, &goals);
            assert!(decision.reoptimized);
            assert_eq!(decision.reason, "selected_missing");
        }
    }

    #[test]
    fn reoptimize_prev_empty() {
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        // Start with empty prev
        let prev = optimize_greedy(&[], &goals);
        let new_candidates = make_candidates(3);
        let decision = reoptimize_on_change(&prev, &[], &new_candidates, &goals);
        assert!(decision.reoptimized);
        assert_eq!(decision.reason, "prev_empty");
    }

    #[test]
    fn reoptimization_decision_serde_roundtrip() {
        let candidates = make_candidates(3);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let prev = optimize_greedy(&candidates, &goals);
        let decision = reoptimize_on_change(&prev, &candidates, &candidates, &goals);
        let json = serde_json::to_string(&decision).unwrap();
        let deser: ReoptimizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.reoptimized, decision.reoptimized);
        assert_eq!(deser.reason, decision.reason);
    }

    // --- Local search edge cases ---

    #[test]
    fn local_search_no_improvement_possible() {
        // Already optimal: only one candidate
        let candidates = vec![OptCandidate {
            id: "only".to_string(),
            expected_loss: 0.1,
            contributions: vec![200.0],
            blocked: false,
            block_reason: None,
        }];
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];
        let mut result = optimize_greedy(&candidates, &goals);
        let original_loss = result.total_loss;
        local_search_improve(&mut result, &candidates, &goals, 10);
        // No change since there's nothing to swap with
        assert!((result.total_loss - original_loss).abs() < 1e-9);
    }

    // --- Log events presence ---

    #[test]
    fn greedy_emits_log_events() {
        let candidates = make_candidates(3);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let result = optimize_greedy(&candidates, &goals);
        assert!(!result.log_events.is_empty());
        // Should have at least optimizer_start and converged
        assert!(result
            .log_events
            .iter()
            .any(|e| e.event == "optimizer_start"));
        assert!(result.log_events.iter().any(|e| e.event == "converged"));
    }

    #[test]
    fn greedy_zero_target_is_feasible() {
        let candidates = make_candidates(3);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 0.0,
            weight: 1.0,
        }];
        let result = optimize_greedy(&candidates, &goals);
        assert!(result.feasible);
        assert!(result.selected.is_empty());
    }

    #[test]
    fn optimization_result_serde_roundtrip() {
        let candidates = make_candidates(3);
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 200.0,
            weight: 1.0,
        }];
        let result = optimize_greedy(&candidates, &goals);
        let json = serde_json::to_string(&result).unwrap();
        let deser: OptimizationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.algorithm, "greedy");
        assert_eq!(deser.feasible, result.feasible);
        assert_eq!(deser.selected.len(), result.selected.len());
    }

    #[test]
    fn greedy_negative_loss_candidates_excluded() {
        // Negative expected_loss should be filtered out (eligible filter requires >= 0.0)
        let candidates = vec![
            OptCandidate {
                id: "negative".to_string(),
                expected_loss: -1.0,
                contributions: vec![500.0],
                blocked: false,
                block_reason: None,
            },
            OptCandidate {
                id: "positive".to_string(),
                expected_loss: 0.1,
                contributions: vec![200.0],
                blocked: false,
                block_reason: None,
            },
        ];
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 100.0,
            weight: 1.0,
        }];
        let result = optimize_greedy(&candidates, &goals);
        // Only "positive" should be selected (negative loss is excluded)
        assert!(result.selected.iter().all(|s| s.id != "negative"));
    }

    #[test]
    fn pareto_dominates_basic() {
        let a = ParetoSet {
            actions: vec![],
            total_loss: 1.0,
            total_contributions: vec![200.0],
        };
        let b = ParetoSet {
            actions: vec![],
            total_loss: 2.0,
            total_contributions: vec![100.0],
        };
        // a dominates b: lower loss AND higher contribution
        assert!(pareto_dominates(&a, &b));
        assert!(!pareto_dominates(&b, &a));
    }

    #[test]
    fn pareto_dominates_neither() {
        let a = ParetoSet {
            actions: vec![],
            total_loss: 1.0,
            total_contributions: vec![100.0],
        };
        let b = ParetoSet {
            actions: vec![],
            total_loss: 2.0,
            total_contributions: vec![200.0],
        };
        // Neither dominates: a has lower loss, b has higher contribution
        assert!(!pareto_dominates(&a, &b));
        assert!(!pareto_dominates(&b, &a));
    }

    #[test]
    fn pareto_efficiency_zero_loss() {
        let cand = OptCandidate {
            id: "free".to_string(),
            expected_loss: 0.0,
            contributions: vec![100.0],
            blocked: false,
            block_reason: None,
        };
        let goals = vec![ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 50.0,
            weight: 1.0,
        }];
        let eff = pareto_efficiency(&cand, &goals);
        assert!(eff.is_some_and(|rank| rank.costless));
        let costly = OptCandidate {
            expected_loss: f64::MIN_POSITIVE,
            ..cand
        };
        assert!(eff > pareto_efficiency(&costly, &goals));
    }

    #[test]
    fn auxiliary_ranking_caps_progress_and_is_invariant_to_units() {
        for unit in [1.0, 1024.0 * 1024.0, 1.0 / 1024.0] {
            let goals = [
                ResourceGoal {
                    resource: "memory".into(),
                    target: 1024.0 * unit,
                    weight: 1.0,
                },
                ResourceGoal {
                    resource: "port".into(),
                    target: 1.0,
                    weight: 1.0,
                },
            ];
            let memory = goal_candidate("memory", 1.0, &[1024.0 * unit, 0.0]);
            let listener = goal_candidate("listener", 2.0, &[0.0, 1.0]);
            let enormous = goal_candidate("enormous", 10.0, &[1e9 * unit, 1.0]);
            assert!(pareto_efficiency(&memory, &goals) > pareto_efficiency(&listener, &goals));
            assert!(pareto_efficiency(&listener, &goals) > pareto_efficiency(&enormous, &goals));
        }
    }
}
