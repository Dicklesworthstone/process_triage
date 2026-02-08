//! Active sensing policy for probe budgeting (VOI / index policy).
//!
//! This module allocates probes across many candidates under a strict overhead
//! budget. It ranks probe opportunities by a Whittle-style index derived from
//! VOI per unit cost, then selects deterministically subject to budgets.

use crate::config::Policy;
use crate::decision::expected_loss::ActionFeasibility;
use crate::decision::voi::{compute_voi, ProbeCost, ProbeCostModel, ProbeType, ProbeVoi, VoiError};
use crate::inference::ClassScores;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Candidate eligible for additional probing.
#[derive(Debug, Clone)]
pub struct ProbeCandidate {
    pub id: String,
    pub posterior: ClassScores,
    pub feasibility: ActionFeasibility,
    pub available_probes: Vec<ProbeType>,
}

impl ProbeCandidate {
    pub fn new<S: Into<String>>(
        id: S,
        posterior: ClassScores,
        feasibility: ActionFeasibility,
        available_probes: Vec<ProbeType>,
    ) -> Self {
        Self {
            id: id.into(),
            posterior,
            feasibility,
            available_probes,
        }
    }
}

/// Budget limits for probe selection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProbeBudget {
    /// Wall-clock time budget in seconds.
    pub time_seconds: f64,
    /// Overhead budget (0.0-1.0 scale).
    pub overhead: f64,
}

impl ProbeBudget {
    pub fn new(time_seconds: f64, overhead: f64) -> Self {
        Self {
            time_seconds: time_seconds.max(0.0),
            overhead: overhead.max(0.0),
        }
    }

    pub fn can_afford(&self, cost: &ProbeCost) -> bool {
        cost.time_seconds <= self.time_seconds + 1e-9 && cost.overhead <= self.overhead + 1e-9
    }

    pub fn consume(&mut self, cost: &ProbeCost) {
        self.time_seconds = (self.time_seconds - cost.time_seconds).max(0.0);
        self.overhead = (self.overhead - cost.overhead).max(0.0);
    }
}

/// Selection policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSensingPolicy {
    /// Maximum probes to allocate per candidate.
    pub max_probes_per_candidate: usize,
    /// Require probes to have negative VOI (worthwhile).
    pub require_negative_voi: bool,
    /// Minimum VOI-per-cost ratio to consider.
    pub min_ratio: f64,
}

impl Default for ActiveSensingPolicy {
    fn default() -> Self {
        Self {
            max_probes_per_candidate: 1,
            require_negative_voi: true,
            min_ratio: 0.0,
        }
    }
}

/// A ranked probe opportunity (candidate + probe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOpportunity {
    pub candidate_id: String,
    pub probe: ProbeType,
    pub voi: f64,
    pub ratio: f64,
    pub cost: ProbeCost,
    pub score: f64,
}

/// Output plan from active sensing selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSensingPlan {
    pub selections: Vec<ProbeOpportunity>,
    pub remaining_budget: ProbeBudget,
}

/// Errors from active sensing selection.
#[derive(Debug, Error)]
pub enum ActiveSensingError {
    #[error("VOI error: {0}")]
    Voi(#[from] VoiError),
}

/// Build a ranked list of probe opportunities for all candidates.
fn collect_opportunities(
    candidates: &[ProbeCandidate],
    policy: &Policy,
    cost_model: &ProbeCostModel,
) -> Result<Vec<ProbeOpportunity>, ActiveSensingError> {
    let mut opportunities = Vec::new();

    for candidate in candidates {
        let probes = if candidate.available_probes.is_empty() {
            None
        } else {
            Some(candidate.available_probes.as_slice())
        };

        let voi_analysis = compute_voi(
            &candidate.posterior,
            policy,
            &candidate.feasibility,
            cost_model,
            probes,
        )?;

        for probe in voi_analysis.probes {
            let details = cost_model.cost_details(probe.probe);
            let score = compute_index_score(&probe, &details);
            opportunities.push(ProbeOpportunity {
                candidate_id: candidate.id.clone(),
                probe: probe.probe,
                voi: probe.voi,
                ratio: probe.ratio,
                cost: details,
                score,
            });
        }
    }

    Ok(opportunities)
}

fn compute_index_score(voi: &ProbeVoi, cost: &ProbeCost) -> f64 {
    let denom = cost.total().max(1e-9);
    (-voi.voi) / denom
}

/// Allocate probes under a global budget using a Whittle-style index policy.
pub fn allocate_probes(
    candidates: &[ProbeCandidate],
    policy: &Policy,
    cost_model: &ProbeCostModel,
    selection_policy: &ActiveSensingPolicy,
    budget: ProbeBudget,
) -> Result<ActiveSensingPlan, ActiveSensingError> {
    let mut opportunities = collect_opportunities(candidates, policy, cost_model)?;

    // Deterministic sorting: score desc, candidate_id asc, probe name asc.
    opportunities.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.candidate_id.cmp(&b.candidate_id))
            .then_with(|| a.probe.name().cmp(b.probe.name()))
    });

    let mut remaining = budget;
    let mut per_candidate_counts: HashMap<String, usize> = HashMap::new();
    let mut selections = Vec::new();

    for opp in opportunities {
        let count = per_candidate_counts
            .get(&opp.candidate_id)
            .copied()
            .unwrap_or(0);
        if count >= selection_policy.max_probes_per_candidate {
            continue;
        }

        if selection_policy.require_negative_voi && opp.voi >= 0.0 {
            continue;
        }

        if opp.ratio < selection_policy.min_ratio {
            continue;
        }

        if !remaining.can_afford(&opp.cost) {
            continue;
        }

        remaining.consume(&opp.cost);
        selections.push(opp.clone());
        per_candidate_counts.insert(opp.candidate_id.clone(), count + 1);
    }

    Ok(ActiveSensingPlan {
        selections,
        remaining_budget: remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::expected_loss::ActionFeasibility;
    use crate::decision::voi::ProbeCostModel;

    fn uncertain_posterior() -> ClassScores {
        ClassScores {
            useful: 0.4,
            useful_bad: 0.1,
            abandoned: 0.4,
            zombie: 0.1,
        }
    }

    fn confident_posterior() -> ClassScores {
        ClassScores {
            useful: 0.97,
            useful_bad: 0.01,
            abandoned: 0.01,
            zombie: 0.01,
        }
    }

    #[test]
    fn test_budget_respected() {
        let candidates = vec![ProbeCandidate::new(
            "pid-1",
            uncertain_posterior(),
            ActionFeasibility::allow_all(),
            vec![ProbeType::QuickScan, ProbeType::DeepScan],
        )];

        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let selection_policy = ActiveSensingPolicy::default();
        let budget = ProbeBudget::new(2.0, 0.2); // Tight budget

        let plan = allocate_probes(&candidates, &policy, &cost_model, &selection_policy, budget)
            .expect("allocation should succeed");

        let used_time = budget.time_seconds - plan.remaining_budget.time_seconds;
        let used_overhead = budget.overhead - plan.remaining_budget.overhead;

        assert!(used_time <= budget.time_seconds + 1e-8);
        assert!(used_overhead <= budget.overhead + 1e-8);
    }

    #[test]
    fn test_deterministic_ordering() {
        let candidates = vec![
            ProbeCandidate::new(
                "a",
                uncertain_posterior(),
                ActionFeasibility::allow_all(),
                vec![ProbeType::QuickScan],
            ),
            ProbeCandidate::new(
                "b",
                uncertain_posterior(),
                ActionFeasibility::allow_all(),
                vec![ProbeType::QuickScan],
            ),
        ];

        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let selection_policy = ActiveSensingPolicy {
            max_probes_per_candidate: 1,
            require_negative_voi: false,
            min_ratio: f64::NEG_INFINITY,
        };
        let budget = ProbeBudget::new(10.0, 1.0);

        let plan = allocate_probes(&candidates, &policy, &cost_model, &selection_policy, budget)
            .expect("allocation should succeed");

        assert!(
            plan.selections.len() >= 1,
            "expected at least one selection"
        );
        let first = &plan.selections[0];
        assert_eq!(first.candidate_id, "a");
    }

    #[test]
    fn test_requires_negative_voi_by_default() {
        let candidates = vec![ProbeCandidate::new(
            "pid-1",
            confident_posterior(),
            ActionFeasibility::allow_all(),
            vec![ProbeType::QuickScan, ProbeType::DeepScan],
        )];

        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let selection_policy = ActiveSensingPolicy::default();
        let budget = ProbeBudget::new(60.0, 1.0);

        let plan = allocate_probes(&candidates, &policy, &cost_model, &selection_policy, budget)
            .expect("allocation should succeed");

        // With high confidence, VOI should be non-negative; default policy skips.
        assert!(plan.selections.is_empty());
    }

    // ── ProbeBudget ───────────────────────────────────────────────────

    #[test]
    fn budget_new_clamps_negatives() {
        let b = ProbeBudget::new(-5.0, -1.0);
        assert_eq!(b.time_seconds, 0.0);
        assert_eq!(b.overhead, 0.0);
    }

    #[test]
    fn budget_can_afford_within_epsilon() {
        let b = ProbeBudget::new(1.0, 0.5);
        let cost = ProbeCost {
            time_seconds: 1.0,
            overhead: 0.5,
            intrusiveness: 0.0,
            risk: 0.0,
        };
        assert!(b.can_afford(&cost));
    }

    #[test]
    fn budget_cannot_afford_excess() {
        let b = ProbeBudget::new(1.0, 0.5);
        let cost = ProbeCost {
            time_seconds: 2.0,
            overhead: 0.1,
            intrusiveness: 0.0,
            risk: 0.0,
        };
        assert!(!b.can_afford(&cost));
    }

    #[test]
    fn budget_consume_reduces() {
        let mut b = ProbeBudget::new(10.0, 1.0);
        let cost = ProbeCost {
            time_seconds: 3.0,
            overhead: 0.4,
            intrusiveness: 0.0,
            risk: 0.0,
        };
        b.consume(&cost);
        assert!((b.time_seconds - 7.0).abs() < 1e-9);
        assert!((b.overhead - 0.6).abs() < 1e-9);
    }

    #[test]
    fn budget_consume_floors_at_zero() {
        let mut b = ProbeBudget::new(1.0, 0.1);
        let cost = ProbeCost {
            time_seconds: 5.0,
            overhead: 1.0,
            intrusiveness: 0.0,
            risk: 0.0,
        };
        b.consume(&cost);
        assert_eq!(b.time_seconds, 0.0);
        assert_eq!(b.overhead, 0.0);
    }

    #[test]
    fn budget_serde_roundtrip() {
        let b = ProbeBudget::new(30.0, 0.5);
        let json = serde_json::to_string(&b).unwrap();
        let back: ProbeBudget = serde_json::from_str(&json).unwrap();
        assert!((back.time_seconds - 30.0).abs() < 1e-9);
        assert!((back.overhead - 0.5).abs() < 1e-9);
    }

    // ── ActiveSensingPolicy ───────────────────────────────────────────

    #[test]
    fn active_sensing_policy_defaults() {
        let p = ActiveSensingPolicy::default();
        assert_eq!(p.max_probes_per_candidate, 1);
        assert!(p.require_negative_voi);
        assert_eq!(p.min_ratio, 0.0);
    }

    #[test]
    fn active_sensing_policy_serde_roundtrip() {
        let p = ActiveSensingPolicy {
            max_probes_per_candidate: 3,
            require_negative_voi: false,
            min_ratio: -1.0,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: ActiveSensingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_probes_per_candidate, 3);
        assert!(!back.require_negative_voi);
    }

    // ── ProbeOpportunity serde ────────────────────────────────────────

    #[test]
    fn probe_opportunity_serde_roundtrip() {
        let opp = ProbeOpportunity {
            candidate_id: "p1".to_string(),
            probe: ProbeType::QuickScan,
            voi: -0.3,
            ratio: 0.5,
            cost: ProbeCost {
                time_seconds: 1.0,
                overhead: 0.1,
                intrusiveness: 0.0,
                risk: 0.0,
            },
            score: 3.0,
        };
        let json = serde_json::to_string(&opp).unwrap();
        let back: ProbeOpportunity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.candidate_id, "p1");
        assert!((back.score - 3.0).abs() < 1e-9);
    }

    // ── ActiveSensingPlan serde ───────────────────────────────────────

    #[test]
    fn active_sensing_plan_serde_roundtrip() {
        let plan = ActiveSensingPlan {
            selections: vec![],
            remaining_budget: ProbeBudget::new(5.0, 0.5),
        };
        let json = serde_json::to_string(&plan).unwrap();
        let back: ActiveSensingPlan = serde_json::from_str(&json).unwrap();
        assert!(back.selections.is_empty());
    }

    // ── ProbeCandidate ────────────────────────────────────────────────

    #[test]
    fn probe_candidate_new_string_id() {
        let c = ProbeCandidate::new(
            String::from("pid-99"),
            uncertain_posterior(),
            ActionFeasibility::allow_all(),
            vec![],
        );
        assert_eq!(c.id, "pid-99");
    }

    #[test]
    fn probe_candidate_empty_probes() {
        let c = ProbeCandidate::new(
            "x",
            confident_posterior(),
            ActionFeasibility::allow_all(),
            vec![],
        );
        assert!(c.available_probes.is_empty());
    }

    // ── allocate_probes edge cases ────────────────────────────────────

    #[test]
    fn allocate_empty_candidates() {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let sp = ActiveSensingPolicy::default();
        let budget = ProbeBudget::new(60.0, 1.0);

        let plan = allocate_probes(&[], &policy, &cost_model, &sp, budget).unwrap();
        assert!(plan.selections.is_empty());
    }

    #[test]
    fn allocate_zero_budget() {
        let candidates = vec![ProbeCandidate::new(
            "p1",
            uncertain_posterior(),
            ActionFeasibility::allow_all(),
            vec![ProbeType::QuickScan],
        )];
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let sp = ActiveSensingPolicy {
            require_negative_voi: false,
            min_ratio: f64::NEG_INFINITY,
            ..Default::default()
        };
        let budget = ProbeBudget::new(0.0, 0.0);

        let plan = allocate_probes(&candidates, &policy, &cost_model, &sp, budget).unwrap();
        assert!(plan.selections.is_empty());
    }

    #[test]
    fn allocate_max_probes_per_candidate_limit() {
        let candidates = vec![ProbeCandidate::new(
            "p1",
            uncertain_posterior(),
            ActionFeasibility::allow_all(),
            vec![
                ProbeType::QuickScan,
                ProbeType::DeepScan,
                ProbeType::NetSnapshot,
            ],
        )];
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let sp = ActiveSensingPolicy {
            max_probes_per_candidate: 1,
            require_negative_voi: false,
            min_ratio: f64::NEG_INFINITY,
        };
        let budget = ProbeBudget::new(100.0, 10.0);

        let plan = allocate_probes(&candidates, &policy, &cost_model, &sp, budget).unwrap();
        assert!(plan.selections.len() <= 1);
    }

    #[test]
    fn allocate_remaining_budget_non_negative() {
        let candidates = vec![ProbeCandidate::new(
            "p1",
            uncertain_posterior(),
            ActionFeasibility::allow_all(),
            vec![ProbeType::QuickScan, ProbeType::DeepScan],
        )];
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let sp = ActiveSensingPolicy {
            max_probes_per_candidate: 5,
            require_negative_voi: false,
            min_ratio: f64::NEG_INFINITY,
        };
        let budget = ProbeBudget::new(100.0, 10.0);

        let plan = allocate_probes(&candidates, &policy, &cost_model, &sp, budget).unwrap();
        assert!(plan.remaining_budget.time_seconds >= 0.0);
        assert!(plan.remaining_budget.overhead >= 0.0);
    }
}
