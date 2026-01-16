//! Sequential stopping rules (SPRT + ESN heuristics).
//!
//! This module provides a deterministic probe-vs-act policy based on expected
//! loss and VOI, along with a simple ESN-style prioritization heuristic for
//! multiple candidates under a fixed budget.

use crate::config::Policy;
use crate::decision::expected_loss::{decide_action, Action, ActionFeasibility, DecisionError};
use crate::decision::voi::{compute_voi, ProbeCostModel, ProbeType, VoiAnalysis, VoiError};
use crate::inference::ClassScores;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Sequential decision output for a single candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequentialDecision {
    pub action_now: Action,
    pub should_probe: bool,
    pub recommended_probe: Option<ProbeType>,
    pub esn_estimate: Option<f64>,
    pub rationale: String,
}

/// Lightweight ledger entry for sequential evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequentialLedgerEntry {
    pub probe: ProbeType,
    pub voi: f64,
    pub expected_loss_after: f64,
}

/// ESN prioritization record for multiple candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsnPriority {
    pub candidate_id: String,
    pub esn_estimate: Option<f64>,
    pub recommended_probe: Option<ProbeType>,
    pub should_probe: bool,
}

/// Candidate input for ESN prioritization.
#[derive(Debug, Clone)]
pub struct EsnCandidate {
    pub candidate_id: String,
    pub posterior: ClassScores,
    pub feasibility: ActionFeasibility,
    pub available_probes: Vec<ProbeType>,
}

impl EsnCandidate {
    pub fn new<S: Into<String>>(
        candidate_id: S,
        posterior: ClassScores,
        feasibility: ActionFeasibility,
        available_probes: Vec<ProbeType>,
    ) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            posterior,
            feasibility,
            available_probes,
        }
    }
}

#[derive(Debug, Error)]
pub enum SequentialError {
    #[error("decision error: {0}")]
    Decision(#[from] DecisionError),
    #[error("voi error: {0}")]
    Voi(#[from] VoiError),
}

/// Decide whether to act now or acquire another probe.
pub fn decide_sequential(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    cost_model: &ProbeCostModel,
    available_probes: Option<&[ProbeType]>,
) -> Result<(SequentialDecision, Vec<SequentialLedgerEntry>), SequentialError> {
    let decision = decide_action(posterior, policy, feasibility)?;
    let voi = compute_voi(posterior, policy, feasibility, cost_model, available_probes)?;

    let esn_estimate = estimate_esn(&voi);
    let should_probe = !voi.act_now && voi.best_probe.is_some();

    let recommended_probe = if should_probe { voi.best_probe } else { None };
    let action_now = decision.optimal_action;

    let rationale = if should_probe {
        voi.rationale.clone()
    } else {
        format!("Act now: {:?}", action_now)
    };

    let ledger = voi
        .probes
        .iter()
        .map(|probe| SequentialLedgerEntry {
            probe: probe.probe,
            voi: probe.voi,
            expected_loss_after: probe.expected_loss_after,
        })
        .collect();

    Ok((
        SequentialDecision {
            action_now,
            should_probe,
            recommended_probe,
            esn_estimate,
            rationale,
        },
        ledger,
    ))
}

/// Prioritize candidates by ESN (expected probes to reach a decision).
pub fn prioritize_by_esn(
    candidates: &[EsnCandidate],
    policy: &Policy,
    cost_model: &ProbeCostModel,
) -> Result<Vec<EsnPriority>, SequentialError> {
    let mut priorities = Vec::new();

    for candidate in candidates {
        let (decision, _) = decide_sequential(
            &candidate.posterior,
            policy,
            &candidate.feasibility,
            cost_model,
            Some(candidate.available_probes.as_slice()),
        )?;

        priorities.push(EsnPriority {
            candidate_id: candidate.candidate_id.clone(),
            esn_estimate: decision.esn_estimate,
            recommended_probe: decision.recommended_probe,
            should_probe: decision.should_probe,
        });
    }

    priorities.sort_by(|a, b| {
        let a_score = a.esn_estimate.unwrap_or(f64::INFINITY);
        let b_score = b.esn_estimate.unwrap_or(f64::INFINITY);
        a_score
            .partial_cmp(&b_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.candidate_id.cmp(&b.candidate_id))
    });

    Ok(priorities)
}

fn estimate_esn(voi: &VoiAnalysis) -> Option<f64> {
    if voi.current_expected_loss.len() < 2 {
        return None;
    }

    let mut losses = voi.current_expected_loss.clone();
    losses.sort_by(|a, b| a.loss.partial_cmp(&b.loss).unwrap_or(std::cmp::Ordering::Equal));

    let gap = (losses[1].loss - losses[0].loss).max(0.0);
    if gap <= 0.0 {
        return None;
    }

    let best_probe = voi.probes.iter().min_by(|a, b| {
        a.voi
            .partial_cmp(&b.voi)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;

    if best_probe.voi >= 0.0 {
        return None;
    }

    let expected_gain = (voi.current_min_loss - best_probe.expected_loss_after).max(1e-6);
    Some((gap / expected_gain).max(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            useful: 0.95,
            useful_bad: 0.02,
            abandoned: 0.02,
            zombie: 0.01,
        }
    }

    #[test]
    fn test_sequential_probe_vs_act() {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let (decision, _ledger) = decide_sequential(
            &uncertain_posterior(),
            &policy,
            &feasibility,
            &cost_model,
            None,
        )
        .expect("decision should succeed");

        assert!(decision.should_probe || decision.action_now != Action::Kill);
    }

    #[test]
    fn test_sequential_confident_act_now() {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let (decision, _ledger) = decide_sequential(
            &confident_posterior(),
            &policy,
            &feasibility,
            &cost_model,
            None,
        )
        .expect("decision should succeed");

        assert_ne!(
            decision.action_now,
            Action::Kill,
            "confident useful posterior should not recommend kill"
        );
        if decision.should_probe {
            assert!(decision.recommended_probe.is_some());
        }
    }

    #[test]
    fn test_esn_prioritization_ordering() {
        let policy = Policy::default();
        let cost_model = ProbeCostModel::default();
        let feasibility = ActionFeasibility::allow_all();

        let candidates = vec![
            EsnCandidate::new(
                "b",
                uncertain_posterior(),
                feasibility.clone(),
                vec![ProbeType::QuickScan],
            ),
            EsnCandidate::new(
                "a",
                confident_posterior(),
                feasibility.clone(),
                vec![ProbeType::QuickScan],
            ),
        ];

        let ranked = prioritize_by_esn(&candidates, &policy, &cost_model)
            .expect("prioritization should succeed");

        assert_eq!(ranked[0].candidate_id, "a");
    }
}
