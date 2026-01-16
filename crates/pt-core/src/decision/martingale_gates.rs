//! Time-uniform martingale gates (e-process controls).
//!
//! Provides helpers for converting martingale summaries into e-values and
//! applying FDR control. These gates are anytime-valid under optional stopping.

use crate::config::Policy;
use crate::decision::alpha_investing::{AlphaInvestingPolicy, AlphaWealthState};
use crate::decision::fdr_selection::{
    select_fdr, FdrCandidate, FdrError, FdrMethod as SelectionFdrMethod, FdrSelectionResult,
    TargetIdentity,
};
use crate::inference::martingale::{BoundType, MartingaleResult};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Candidate for martingale gating.
#[derive(Debug, Clone)]
pub struct MartingaleGateCandidate {
    pub target: TargetIdentity,
    pub result: MartingaleResult,
}

/// Gate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MartingaleGateConfig {
    /// Minimum observations required to consider the gate.
    pub min_observations: usize,
    /// Require anomaly detection for eligibility.
    pub require_anomaly: bool,
}

impl Default for MartingaleGateConfig {
    fn default() -> Self {
        Self {
            min_observations: 3,
            require_anomaly: true,
        }
    }
}

/// Source of alpha used for gating.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlphaSource {
    Policy,
    AlphaInvesting,
}

/// Per-candidate martingale gate output.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleGateResult {
    pub target: TargetIdentity,
    pub n: usize,
    pub e_value: f64,
    pub tail_probability: f64,
    pub confidence_radius: f64,
    pub bound_type: BoundType,
    pub anomaly_detected: bool,
    pub eligible: bool,
    pub gate_passed: bool,
    pub selected_by_fdr: bool,
}

/// Aggregate gate summary including FDR selection.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleGateSummary {
    pub alpha: f64,
    pub alpha_source: AlphaSource,
    pub fdr_method: SelectionFdrMethod,
    pub fdr_result: Option<FdrSelectionResult>,
    pub results: Vec<MartingaleGateResult>,
}

#[derive(Debug, Error)]
pub enum MartingaleGateError {
    #[error("FDR error: {0}")]
    Fdr(#[from] FdrError),
    #[error("invalid alpha from policy")]
    InvalidAlpha,
}

/// Resolve FDR method from policy.
pub fn fdr_method_from_policy(policy: &Policy) -> SelectionFdrMethod {
    match policy.fdr_control.method.as_str() {
        "bh" | "ebh" => SelectionFdrMethod::EBh,
        "by" | "eby" => SelectionFdrMethod::EBy,
        "none" => SelectionFdrMethod::None,
        "alpha_investing" => SelectionFdrMethod::EBy,
        _ => SelectionFdrMethod::EBy,
    }
}

/// Resolve the alpha level from policy and optional alpha-investing state.
pub fn resolve_alpha(
    policy: &Policy,
    alpha_state: Option<&AlphaWealthState>,
) -> Result<(f64, AlphaSource), MartingaleGateError> {
    if policy.fdr_control.method == pt_config::policy::FdrMethod::AlphaInvesting {
        if let Some(state) = alpha_state {
            if let Ok(cfg) = AlphaInvestingPolicy::from_policy(policy) {
                let alpha = cfg.alpha_spend_for_wealth(state.wealth);
                if alpha > 0.0 && alpha <= 1.0 {
                    return Ok((alpha, AlphaSource::AlphaInvesting));
                }
            }
        }
    }

    let alpha = policy.fdr_control.alpha;
    if alpha <= 0.0 || alpha > 1.0 {
        return Err(MartingaleGateError::InvalidAlpha);
    }
    Ok((alpha, AlphaSource::Policy))
}

fn evaluate_gate(
    candidate: &MartingaleGateCandidate,
    config: &MartingaleGateConfig,
    alpha: f64,
) -> MartingaleGateResult {
    let result = &candidate.result;
    let eligible = result.n >= config.min_observations
        && (!config.require_anomaly || result.anomaly_detected);
    let threshold = 1.0 / alpha;
    let gate_passed = eligible && result.e_value >= threshold;

    MartingaleGateResult {
        target: candidate.target.clone(),
        n: result.n,
        e_value: result.e_value,
        tail_probability: result.tail_probability,
        confidence_radius: result.time_uniform_radius,
        bound_type: result.best_bound,
        anomaly_detected: result.anomaly_detected,
        eligible,
        gate_passed,
        selected_by_fdr: false,
    }
}

/// Apply martingale gates with optional FDR control.
pub fn apply_martingale_gates(
    candidates: &[MartingaleGateCandidate],
    policy: &Policy,
    config: &MartingaleGateConfig,
    alpha_state: Option<&AlphaWealthState>,
) -> Result<MartingaleGateSummary, MartingaleGateError> {
    let (alpha, alpha_source) = resolve_alpha(policy, alpha_state)?;
    let fdr_method = fdr_method_from_policy(policy);

    let mut results: Vec<MartingaleGateResult> = candidates
        .iter()
        .map(|candidate| evaluate_gate(candidate, config, alpha))
        .collect();

    let eligible_candidates: Vec<FdrCandidate> = results
        .iter()
        .filter(|r| r.eligible)
        .map(|r| FdrCandidate {
            target: r.target.clone(),
            e_value: r.e_value,
        })
        .collect();

    let mut fdr_result = None;

    if policy.fdr_control.enabled
        && !eligible_candidates.is_empty()
        && policy
            .fdr_control
            .min_candidates
            .map(|min| eligible_candidates.len() as u32 >= min)
            .unwrap_or(true)
    {
        let selection = select_fdr(&eligible_candidates, alpha, fdr_method)?;
        let selected_ids = &selection.selected_ids;

        for result in &mut results {
            result.selected_by_fdr = selected_ids.iter().any(|id| id.pid == result.target.pid);
        }

        fdr_result = Some(selection);
    } else {
        for result in &mut results {
            result.selected_by_fdr = result.gate_passed;
        }
    }

    Ok(MartingaleGateSummary {
        alpha,
        alpha_source,
        fdr_method,
        fdr_result,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::{AlphaInvesting, FdrMethod};
    use crate::inference::martingale::{MartingaleAnalyzer, MartingaleConfig};

    fn make_target(pid: i32) -> TargetIdentity {
        TargetIdentity {
            pid,
            start_id: format!("start-{}", pid),
            uid: 1000,
        }
    }

    fn high_evalue_result() -> MartingaleResult {
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        for _ in 0..20 {
            analyzer.update(0.8);
        }
        analyzer.summary()
    }

    #[test]
    fn test_alpha_investing_resolution() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::AlphaInvesting;
        policy.fdr_control.alpha = 0.5;
        policy.fdr_control.alpha_investing = Some(AlphaInvesting {
            w0: Some(0.2),
            alpha_spend: Some(0.1),
            alpha_earn: Some(0.01),
        });

        let state = AlphaWealthState {
            wealth: 0.2,
            last_updated: "now".to_string(),
            policy_id: policy.policy_id.clone(),
            policy_version: policy.schema_version.clone(),
            host_id: "host".to_string(),
            user_id: 1000,
        };

        let (alpha, source) = resolve_alpha(&policy, Some(&state)).unwrap();
        assert_eq!(source, AlphaSource::AlphaInvesting);
        assert!((alpha - 0.02).abs() < 1e-12, "alpha should be spend fraction");
    }

    #[test]
    fn test_fdr_selection_marks_candidates() {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();

        let candidates = vec![
            MartingaleGateCandidate {
                target: make_target(1),
                result: high_evalue_result(),
            },
            MartingaleGateCandidate {
                target: make_target(2),
                result: high_evalue_result(),
            },
        ];

        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        assert!(!summary.results.is_empty());

        let any_selected = summary.results.iter().any(|r| r.selected_by_fdr);
        assert!(any_selected, "expected at least one selection");
    }
}
