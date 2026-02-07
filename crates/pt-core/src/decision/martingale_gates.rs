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
    let eligible =
        result.n >= config.min_observations && (!config.require_anomaly || result.anomaly_detected);
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
        assert!(
            (alpha - 0.02).abs() < 1e-12,
            "alpha should be spend fraction"
        );
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

    // ── MartingaleGateConfig defaults ─────────────────────────────

    #[test]
    fn config_default_min_observations() {
        let cfg = MartingaleGateConfig::default();
        assert_eq!(cfg.min_observations, 3);
    }

    #[test]
    fn config_default_require_anomaly() {
        let cfg = MartingaleGateConfig::default();
        assert!(cfg.require_anomaly);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = MartingaleGateConfig {
            min_observations: 7,
            require_anomaly: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MartingaleGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_observations, 7);
        assert!(!back.require_anomaly);
    }

    // ── AlphaSource ───────────────────────────────────────────────

    #[test]
    fn alpha_source_serde_policy() {
        let json = serde_json::to_string(&AlphaSource::Policy).unwrap();
        assert_eq!(json, "\"policy\"");
        let back: AlphaSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AlphaSource::Policy);
    }

    #[test]
    fn alpha_source_serde_alpha_investing() {
        let json = serde_json::to_string(&AlphaSource::AlphaInvesting).unwrap();
        assert_eq!(json, "\"alpha_investing\"");
        let back: AlphaSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AlphaSource::AlphaInvesting);
    }

    #[test]
    fn alpha_source_eq() {
        assert_eq!(AlphaSource::Policy, AlphaSource::Policy);
        assert_ne!(AlphaSource::Policy, AlphaSource::AlphaInvesting);
    }

    // ── fdr_method_from_policy ────────────────────────────────────

    #[test]
    fn fdr_method_bh() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::Bh;
        let m = fdr_method_from_policy(&policy);
        assert_eq!(m, SelectionFdrMethod::EBh);
    }

    #[test]
    fn fdr_method_by() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::By;
        let m = fdr_method_from_policy(&policy);
        assert_eq!(m, SelectionFdrMethod::EBy);
    }

    #[test]
    fn fdr_method_none() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::None;
        let m = fdr_method_from_policy(&policy);
        assert_eq!(m, SelectionFdrMethod::None);
    }

    #[test]
    fn fdr_method_alpha_investing() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::AlphaInvesting;
        let m = fdr_method_from_policy(&policy);
        assert_eq!(m, SelectionFdrMethod::EBy);
    }

    // ── resolve_alpha ─────────────────────────────────────────────

    #[test]
    fn resolve_alpha_from_policy_default() {
        let policy = Policy::default();
        let (alpha, source) = resolve_alpha(&policy, None).unwrap();
        assert_eq!(source, AlphaSource::Policy);
        assert!((alpha - 0.05).abs() < 1e-12);
    }

    #[test]
    fn resolve_alpha_custom_policy_alpha() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 0.10;
        let (alpha, _) = resolve_alpha(&policy, None).unwrap();
        assert!((alpha - 0.10).abs() < 1e-12);
    }

    #[test]
    fn resolve_alpha_zero_alpha_error() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 0.0;
        let result = resolve_alpha(&policy, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_alpha_negative_alpha_error() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = -0.1;
        let result = resolve_alpha(&policy, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_alpha_above_one_error() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 1.5;
        let result = resolve_alpha(&policy, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_alpha_exactly_one_ok() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 1.0;
        let (alpha, source) = resolve_alpha(&policy, None).unwrap();
        assert_eq!(source, AlphaSource::Policy);
        assert!((alpha - 1.0).abs() < 1e-12);
    }

    #[test]
    fn resolve_alpha_investing_without_state_falls_back() {
        let mut policy = Policy::default();
        policy.fdr_control.method = FdrMethod::AlphaInvesting;
        policy.fdr_control.alpha = 0.05;
        // No alpha_state → falls back to policy alpha
        let (alpha, source) = resolve_alpha(&policy, None).unwrap();
        assert_eq!(source, AlphaSource::Policy);
        assert!((alpha - 0.05).abs() < 1e-12);
    }

    // ── apply_martingale_gates ─────────────────────────────────────

    #[test]
    fn apply_empty_candidates() {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let summary = apply_martingale_gates(&[], &policy, &config, None).unwrap();
        assert!(summary.results.is_empty());
        assert_eq!(summary.alpha_source, AlphaSource::Policy);
    }

    #[test]
    fn apply_ineligible_low_observations() {
        let mut result = high_evalue_result();
        result.n = 1; // below min_observations=3
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(10),
            result,
        }];
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        assert_eq!(summary.results.len(), 1);
        assert!(!summary.results[0].eligible);
        assert!(!summary.results[0].gate_passed);
    }

    #[test]
    fn apply_ineligible_no_anomaly() {
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        // Feed values close to 0 so anomaly_detected stays false
        for _ in 0..5 {
            analyzer.update(0.01);
        }
        let result = analyzer.summary();
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(20),
            result,
        }];
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        // With require_anomaly=true and no anomaly, not eligible
        assert!(!summary.results[0].eligible);
    }

    #[test]
    fn apply_eligible_without_anomaly_requirement() {
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
        for _ in 0..5 {
            analyzer.update(0.01);
        }
        let result = analyzer.summary();
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(30),
            result,
        }];
        let policy = Policy::default();
        let config = MartingaleGateConfig {
            min_observations: 3,
            require_anomaly: false,
        };
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        // require_anomaly=false, n >= 3, so eligible
        assert!(summary.results[0].eligible);
    }

    #[test]
    fn apply_fdr_disabled_falls_through() {
        let mut policy = Policy::default();
        policy.fdr_control.enabled = false;
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
        assert!(summary.fdr_result.is_none());
        // selected_by_fdr matches gate_passed when FDR is disabled
        for r in &summary.results {
            assert_eq!(r.selected_by_fdr, r.gate_passed);
        }
    }

    #[test]
    fn apply_below_min_candidates_skips_fdr() {
        let mut policy = Policy::default();
        policy.fdr_control.min_candidates = Some(10);
        let config = MartingaleGateConfig::default();
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(1),
            result: high_evalue_result(),
        }];
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        // Only 1 eligible candidate but min_candidates=10, so no FDR
        assert!(summary.fdr_result.is_none());
    }

    #[test]
    fn summary_alpha_matches_policy() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha = 0.01;
        let config = MartingaleGateConfig::default();
        let summary = apply_martingale_gates(&[], &policy, &config, None).unwrap();
        assert!((summary.alpha - 0.01).abs() < 1e-12);
    }

    #[test]
    fn gate_result_fields_from_high_evalue() {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(42),
            result: high_evalue_result(),
        }];
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        let r = &summary.results[0];
        assert_eq!(r.target.pid, 42);
        assert_eq!(r.n, 20);
        assert!(r.e_value > 0.0);
        assert!(r.confidence_radius >= 0.0);
    }

    #[test]
    fn summary_serializes_to_json() {
        let policy = Policy::default();
        let config = MartingaleGateConfig::default();
        let candidates = vec![MartingaleGateCandidate {
            target: make_target(1),
            result: high_evalue_result(),
        }];
        let summary = apply_martingale_gates(&candidates, &policy, &config, None).unwrap();
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"alpha\""));
        assert!(json.contains("\"alpha_source\""));
        assert!(json.contains("\"results\""));
    }

    // ── MartingaleGateError ───────────────────────────────────────

    #[test]
    fn error_display_invalid_alpha() {
        let err = MartingaleGateError::InvalidAlpha;
        let msg = err.to_string();
        assert!(msg.contains("invalid alpha"));
    }

    #[test]
    fn error_display_fdr() {
        let fdr_err = FdrError::NoCandidates;
        let err = MartingaleGateError::from(fdr_err);
        let msg = err.to_string();
        assert!(msg.contains("FDR error"));
    }

    #[test]
    fn error_from_fdr_error() {
        let fdr_err = FdrError::NoCandidates;
        let gate_err: MartingaleGateError = fdr_err.into();
        assert!(matches!(gate_err, MartingaleGateError::Fdr(_)));
    }
}
