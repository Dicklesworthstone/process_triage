//! Goal-aware plan optimization under safety constraints.
//!
//! Selects action sets that best satisfy resource goals while respecting
//! policy constraints (same-UID, max actions, protected patterns, blast radius).
//! Produces multiple plan variants near tradeoff boundaries.

use serde::{Deserialize, Serialize};

/// A candidate action for goal-aware planning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCandidate {
    /// Process identifier.
    pub pid: u32,
    /// Expected goal contribution (in goal units: bytes, fraction, count).
    pub expected_contribution: f64,
    /// Contribution confidence (0.0 to 1.0).
    pub confidence: f64,
    /// Expected risk/loss from this action (lower is safer).
    pub risk: f64,
    /// Whether this candidate is protected (cannot be included).
    pub is_protected: bool,
    /// UID of the process.
    pub uid: u32,
    /// Label for display.
    pub label: String,
}

/// Safety constraints for plan optimization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanConstraints {
    /// Maximum number of actions per plan.
    pub max_actions: usize,
    /// Maximum total risk budget.
    pub max_total_risk: f64,
    /// Only include candidates with this UID (if set).
    pub same_uid: Option<u32>,
    /// Goal target value to achieve.
    pub goal_target: f64,
    /// Minimum confidence for a candidate to be included.
    pub min_confidence: f64,
}

impl Default for PlanConstraints {
    fn default() -> Self {
        Self {
            max_actions: 10,
            max_total_risk: 5.0,
            same_uid: None,
            goal_target: 0.0,
            min_confidence: 0.1,
        }
    }
}

/// A selected action in a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAction {
    /// Process identifier.
    pub pid: u32,
    /// Label.
    pub label: String,
    /// Expected contribution.
    pub expected_contribution: f64,
    /// Risk.
    pub risk: f64,
    /// Marginal benefit/risk ratio at time of selection.
    pub marginal_ratio: f64,
    /// Justification.
    pub justification: String,
}

/// A complete plan variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalPlan {
    /// Name/type of this variant.
    pub variant: PlanVariant,
    /// Selected actions in order.
    pub actions: Vec<PlanAction>,
    /// Total expected contribution toward goal.
    pub total_contribution: f64,
    /// Total risk.
    pub total_risk: f64,
    /// Whether the goal target is expected to be met.
    pub goal_achievable: bool,
    /// Fraction of goal expected to be achieved.
    pub goal_fraction: f64,
    /// Binding constraints (which constraints limit the plan).
    pub binding_constraints: Vec<String>,
}

/// Plan variant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanVariant {
    /// Balanced: best benefit/risk tradeoff.
    Balanced,
    /// Conservative: minimize risk, may not fully achieve goal.
    Conservative,
    /// Aggressive: maximize goal progress, higher risk.
    Aggressive,
}

impl std::fmt::Display for PlanVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Balanced => write!(f, "balanced"),
            Self::Conservative => write!(f, "conservative"),
            Self::Aggressive => write!(f, "aggressive"),
        }
    }
}

/// Optimize a plan toward a goal under constraints.
///
/// Returns up to 3 plan variants: conservative, balanced, aggressive.
pub fn optimize_goal_plan(
    candidates: &[PlanCandidate],
    constraints: &PlanConstraints,
) -> Vec<GoalPlan> {
    if candidates.is_empty() || constraints.goal_target <= 0.0 {
        return vec![];
    }

    // Filter eligible candidates.
    let eligible: Vec<&PlanCandidate> = candidates
        .iter()
        .filter(|c| {
            !c.is_protected
                && c.confidence >= constraints.min_confidence
                && c.expected_contribution > 0.0
                && constraints.same_uid.map_or(true, |uid| c.uid == uid)
        })
        .collect();

    if eligible.is_empty() {
        return vec![];
    }

    let mut plans = Vec::new();

    // Conservative: sort by risk (ascending), take lowest risk until goal or max_actions.
    let conservative = greedy_select(
        &eligible,
        constraints,
        |a, b| {
            a.risk
                .partial_cmp(&b.risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        },
        PlanVariant::Conservative,
    );
    plans.push(conservative);

    // Balanced: sort by benefit/risk ratio (descending).
    let balanced = greedy_select(
        &eligible,
        constraints,
        |a, b| {
            let ratio_a = a.expected_contribution / a.risk.max(0.001);
            let ratio_b = b.expected_contribution / b.risk.max(0.001);
            ratio_b
                .partial_cmp(&ratio_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        },
        PlanVariant::Balanced,
    );
    plans.push(balanced);

    // Aggressive: sort by contribution (descending).
    let aggressive = greedy_select(
        &eligible,
        constraints,
        |a, b| {
            b.expected_contribution
                .partial_cmp(&a.expected_contribution)
                .unwrap_or(std::cmp::Ordering::Equal)
        },
        PlanVariant::Aggressive,
    );
    plans.push(aggressive);

    // Deduplicate identical plans.
    plans.dedup_by(|a, b| {
        a.actions.len() == b.actions.len()
            && a.actions
                .iter()
                .zip(b.actions.iter())
                .all(|(x, y)| x.pid == y.pid)
    });

    plans
}

fn greedy_select<F>(
    eligible: &[&PlanCandidate],
    constraints: &PlanConstraints,
    sort_fn: F,
    variant: PlanVariant,
) -> GoalPlan
where
    F: FnMut(&&PlanCandidate, &&PlanCandidate) -> std::cmp::Ordering,
{
    let mut sorted: Vec<&PlanCandidate> = eligible.to_vec();
    sorted.sort_by(sort_fn);

    let mut actions = Vec::new();
    let mut total_contribution = 0.0;
    let mut total_risk = 0.0;
    let mut binding = Vec::new();

    for candidate in sorted {
        if actions.len() >= constraints.max_actions {
            binding.push("max_actions".to_string());
            break;
        }
        if total_risk + candidate.risk > constraints.max_total_risk {
            binding.push("max_total_risk".to_string());
            continue; // Try next candidate (might have lower risk).
        }

        let marginal_ratio = candidate.expected_contribution / candidate.risk.max(0.001);

        actions.push(PlanAction {
            pid: candidate.pid,
            label: candidate.label.clone(),
            expected_contribution: candidate.expected_contribution,
            risk: candidate.risk,
            marginal_ratio,
            justification: format!(
                "Contributes {:.2} toward goal (ratio {:.1})",
                candidate.expected_contribution, marginal_ratio
            ),
        });

        total_contribution += candidate.expected_contribution;
        total_risk += candidate.risk;

        if total_contribution >= constraints.goal_target {
            break;
        }
    }

    let goal_fraction = if constraints.goal_target > 0.0 {
        (total_contribution / constraints.goal_target).min(1.0)
    } else {
        0.0
    };

    GoalPlan {
        variant,
        actions,
        total_contribution,
        total_risk,
        goal_achievable: total_contribution >= constraints.goal_target,
        goal_fraction,
        binding_constraints: binding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidates() -> Vec<PlanCandidate> {
        vec![
            PlanCandidate {
                pid: 1,
                expected_contribution: 100.0,
                confidence: 0.9,
                risk: 1.0,
                is_protected: false,
                uid: 1000,
                label: "big-safe".to_string(),
            },
            PlanCandidate {
                pid: 2,
                expected_contribution: 200.0,
                confidence: 0.8,
                risk: 3.0,
                is_protected: false,
                uid: 1000,
                label: "big-risky".to_string(),
            },
            PlanCandidate {
                pid: 3,
                expected_contribution: 50.0,
                confidence: 0.95,
                risk: 0.5,
                is_protected: false,
                uid: 1000,
                label: "small-safe".to_string(),
            },
            PlanCandidate {
                pid: 4,
                expected_contribution: 150.0,
                confidence: 0.7,
                risk: 2.0,
                is_protected: true, // Protected
                uid: 1000,
                label: "protected".to_string(),
            },
        ]
    }

    #[test]
    fn test_basic_optimization() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 200.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        assert!(!plans.is_empty());
        // Every plan should exclude protected candidate.
        for plan in &plans {
            assert!(plan.actions.iter().all(|a| a.pid != 4));
        }
    }

    #[test]
    fn test_protected_excluded() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 500.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            assert!(!plan.actions.iter().any(|a| a.pid == 4));
        }
    }

    #[test]
    fn test_risk_budget() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 500.0,
            max_total_risk: 2.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            assert!(
                plan.total_risk <= 2.0 + 0.01,
                "Risk {} exceeds budget 2.0",
                plan.total_risk
            );
        }
    }

    #[test]
    fn test_max_actions() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 500.0,
            max_actions: 1,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            assert!(plan.actions.len() <= 1);
        }
    }

    #[test]
    fn test_same_uid_filter() {
        let mut candidates = make_candidates();
        candidates.push(PlanCandidate {
            pid: 5,
            expected_contribution: 300.0,
            confidence: 0.9,
            risk: 1.0,
            is_protected: false,
            uid: 2000, // Different UID
            label: "other-user".to_string(),
        });
        let constraints = PlanConstraints {
            goal_target: 200.0,
            same_uid: Some(1000),
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        for plan in &plans {
            assert!(plan.actions.iter().all(|a| a.pid != 5));
        }
    }

    #[test]
    fn test_goal_achievable_flag() {
        let candidates = make_candidates();
        // Goal easily achievable.
        let constraints = PlanConstraints {
            goal_target: 100.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        assert!(plans.iter().any(|p| p.goal_achievable));

        // Goal impossible.
        let constraints = PlanConstraints {
            goal_target: 10000.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        assert!(plans.iter().all(|p| !p.goal_achievable));
    }

    #[test]
    fn test_empty_candidates() {
        let plans = optimize_goal_plan(
            &[],
            &PlanConstraints {
                goal_target: 100.0,
                ..Default::default()
            },
        );
        assert!(plans.is_empty());
    }

    #[test]
    fn test_deterministic() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 200.0,
            ..Default::default()
        };
        let plans1 = optimize_goal_plan(&candidates, &constraints);
        let plans2 = optimize_goal_plan(&candidates, &constraints);
        assert_eq!(plans1.len(), plans2.len());
        for (p1, p2) in plans1.iter().zip(plans2.iter()) {
            assert_eq!(p1.actions.len(), p2.actions.len());
            for (a1, a2) in p1.actions.iter().zip(p2.actions.iter()) {
                assert_eq!(a1.pid, a2.pid);
            }
        }
    }

    #[test]
    fn test_variants_differ() {
        let candidates = make_candidates();
        let constraints = PlanConstraints {
            goal_target: 300.0,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        // Should have at least balanced variant.
        assert!(plans.iter().any(|p| p.variant == PlanVariant::Balanced));
    }

    #[test]
    fn test_high_risk_low_benefit_excluded() {
        // Property: if a candidate has higher risk AND lower benefit than another,
        // the balanced plan should prefer the better one.
        let candidates = vec![
            PlanCandidate {
                pid: 1,
                expected_contribution: 100.0,
                confidence: 0.9,
                risk: 1.0,
                is_protected: false,
                uid: 1000,
                label: "good".to_string(),
            },
            PlanCandidate {
                pid: 2,
                expected_contribution: 10.0,
                confidence: 0.9,
                risk: 4.0,
                is_protected: false,
                uid: 1000,
                label: "bad".to_string(),
            },
        ];
        let constraints = PlanConstraints {
            goal_target: 100.0,
            max_actions: 1,
            ..Default::default()
        };
        let plans = optimize_goal_plan(&candidates, &constraints);
        // All variants should prefer pid=1 (better ratio).
        for plan in &plans {
            assert_eq!(
                plan.actions[0].pid, 1,
                "Variant {:?} should pick pid=1",
                plan.variant
            );
        }
    }
}
