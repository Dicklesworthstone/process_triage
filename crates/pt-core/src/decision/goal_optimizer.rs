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

/// Greedy optimization: sort by efficiency, select until goals met.
pub fn optimize_greedy(candidates: &[OptCandidate], goals: &[ResourceGoal]) -> OptimizationResult {
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
            algorithm: "greedy".to_string(),
            alternatives: Vec::new(),
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

    // Compute scalarized efficiency: weighted_contribution / loss.
    let scalarize = |c: &OptCandidate| -> f64 {
        let weighted_contrib: f64 = c
            .contributions
            .iter()
            .zip(goals.iter())
            .map(|(contrib, goal)| contrib * goal.weight)
            .sum();
        if c.expected_loss > 1e-15 {
            weighted_contrib / c.expected_loss
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
    let alternatives = generate_alternatives(&selected, goals, &eligible);

    OptimizationResult {
        selected,
        total_loss,
        total_contributions,
        goal_achievement,
        feasible,
        algorithm: "greedy".to_string(),
        alternatives,
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
    // Only supports single-goal for DP.
    if goals.len() != 1 || candidates.is_empty() {
        return optimize_greedy(candidates, goals);
    }

    let eligible: Vec<&OptCandidate> = candidates
        .iter()
        .filter(|c| !c.blocked && c.expected_loss >= 0.0)
        .collect();

    if eligible.len() > 30 {
        return optimize_greedy(candidates, goals);
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
            let greedy = optimize_greedy(candidates, goals);
            return OptimizationResult {
                algorithm: "dp (infeasible, greedy fallback)".to_string(),
                ..greedy
            };
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
) -> Vec<AlternativePlan> {
    let mut alts = Vec::new();

    if selected.len() > 1 {
        // Conservative: use fewer actions (first N-1).
        let fewer = &selected[..selected.len() - 1];
        let loss: f64 = fewer.iter().map(|s| s.expected_loss).sum();
        let achievements: Vec<GoalAchievement> = goals
            .iter()
            .enumerate()
            .map(|(g, goal)| {
                let achieved: f64 = fewer
                    .iter()
                    .map(|s| s.contributions.get(g).copied().unwrap_or(0.0))
                    .sum();
                GoalAchievement {
                    resource: goal.resource.clone(),
                    target: goal.target,
                    achieved,
                    shortfall: (goal.target - achieved).max(0.0),
                    met: achieved >= goal.target,
                }
            })
            .collect();

        alts.push(AlternativePlan {
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
            let achievements: Vec<GoalAchievement> = goals
                .iter()
                .enumerate()
                .map(|(g, goal)| {
                    let achieved: f64 = more
                        .iter()
                        .map(|s| s.contributions.get(g).copied().unwrap_or(0.0))
                        .sum();
                    GoalAchievement {
                        resource: goal.resource.clone(),
                        target: goal.target,
                        achieved,
                        shortfall: (goal.target - achieved).max(0.0),
                        met: achieved >= goal.target,
                    }
                })
                .collect();

            alts.push(AlternativePlan {
                description: "Aggressive: more headroom, higher total loss".to_string(),
                action_count: more.len(),
                total_loss: loss,
                goal_achievement: achievements,
            });
        }
    }

    alts
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
