//! Agent decision explanation API.
//!
//! Composite API that assembles a complete explanation from the evidence
//! ledger, natural language explainer, flip conditions, and confidence
//! visualization into a single structured response suitable for agent
//! consumption at multiple verbosity levels.

use serde::{Deserialize, Serialize};

use super::confidence_viz::{
    CalibrationStatus, ConfidenceBadge, ConfidenceVizInput, GateStatus,
    SafetyBadge, compute_confidence_viz,
};
use super::explain::{ExplainConfig, explain};
use super::flip_conditions::{FlipAnalysis, FlipConfig, compute_flip_conditions};
use super::ledger::{BayesFactorEntry, Classification, Confidence, EvidenceLedger};

// ---------------------------------------------------------------------------
// Verbosity
// ---------------------------------------------------------------------------

/// Explanation verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationVerbosity {
    /// Just summary and recommendation.
    Brief,
    /// Summary, evidence breakdown, counterfactuals.
    Normal,
    /// Everything including confidence analysis.
    Verbose,
    /// Full mathematical derivation.
    GalaxyBrain,
}

// ---------------------------------------------------------------------------
// Evidence breakdown item
// ---------------------------------------------------------------------------

/// Evidence factor for the explanation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFactor {
    pub factor: String,
    pub contribution_bits: f64,
    pub strength: String,
    pub direction: String,
    pub explanation: String,
}

/// Counterfactual scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterfactual {
    pub condition: String,
    pub estimated_delta_bits: f64,
    pub could_flip: bool,
}

/// Confidence analysis section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceAnalysis {
    pub confidence_badge: ConfidenceBadge,
    pub safety_badge: SafetyBadge,
    pub calibration: CalibrationStatus,
    pub gate_status: GateStatus,
    pub knife_edge: bool,
}

// ---------------------------------------------------------------------------
// Complete explanation response
// ---------------------------------------------------------------------------

/// Complete explanation response for a process decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationResponse {
    pub classification: Classification,
    pub confidence: Confidence,
    pub posterior_probability: f64,

    /// Brief natural language summary.
    pub summary: String,

    /// Detailed natural language explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Evidence breakdown (sorted by absolute contribution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_breakdown: Option<Vec<EvidenceFactor>>,

    /// Counterfactuals / flip conditions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterfactuals: Option<Vec<Counterfactual>>,

    /// Confidence analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_analysis: Option<ConfidenceAnalysis>,

    /// Contributing factors (human-readable phrases).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contributing_factors: Option<Vec<String>>,

    /// Countervailing signals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countervailing: Option<Vec<String>>,

    /// Galaxy-brain math trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub math_trace: Option<String>,
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Configuration for explanation API.
#[derive(Debug, Clone)]
pub struct ExplainApiConfig {
    pub verbosity: ExplanationVerbosity,
    pub max_evidence_factors: usize,
    pub max_counterfactuals: usize,
}

impl Default for ExplainApiConfig {
    fn default() -> Self {
        Self {
            verbosity: ExplanationVerbosity::Normal,
            max_evidence_factors: 10,
            max_counterfactuals: 5,
        }
    }
}

/// Build a complete explanation response from an evidence ledger.
pub fn build_explanation(
    ledger: &EvidenceLedger,
    config: &ExplainApiConfig,
    viz_input: &ConfidenceVizInput,
    galaxy_brain_trace: Option<&str>,
) -> ExplanationResponse {
    let nl = explain(ledger, &ExplainConfig::default());
    let posterior_p = posterior_for_class(ledger);

    let mut response = ExplanationResponse {
        classification: ledger.classification,
        confidence: ledger.confidence,
        posterior_probability: posterior_p,
        summary: nl.summary.clone(),
        detail: None,
        evidence_breakdown: None,
        counterfactuals: None,
        confidence_analysis: None,
        contributing_factors: None,
        countervailing: None,
        math_trace: None,
    };

    if config.verbosity >= ExplanationVerbosity::Normal {
        response.detail = Some(nl.detail.clone());
        response.evidence_breakdown = Some(build_evidence_factors(
            &ledger.bayes_factors,
            config.max_evidence_factors,
        ));
        response.contributing_factors = Some(nl.contributing_factors.clone());
        response.countervailing = Some(nl.countervailing.clone());

        let flip = compute_flip_conditions(ledger, &FlipConfig {
            max_scenarios: config.max_counterfactuals,
            ..Default::default()
        });
        response.counterfactuals = Some(build_counterfactuals(&flip));
    }

    if config.verbosity >= ExplanationVerbosity::Verbose {
        let viz = compute_confidence_viz(ledger, viz_input);
        response.confidence_analysis = Some(ConfidenceAnalysis {
            confidence_badge: viz.confidence,
            safety_badge: viz.safety,
            calibration: viz.calibration,
            gate_status: viz.gates,
            knife_edge: viz.knife_edge,
        });
    }

    if config.verbosity >= ExplanationVerbosity::GalaxyBrain {
        response.math_trace = galaxy_brain_trace.map(|s| s.to_string());
    }

    response
}

fn posterior_for_class(ledger: &EvidenceLedger) -> f64 {
    match ledger.classification {
        Classification::Useful => ledger.posterior.posterior.useful,
        Classification::UsefulBad => ledger.posterior.posterior.useful_bad,
        Classification::Abandoned => ledger.posterior.posterior.abandoned,
        Classification::Zombie => ledger.posterior.posterior.zombie,
    }
}

fn build_evidence_factors(
    bayes_factors: &[BayesFactorEntry],
    max: usize,
) -> Vec<EvidenceFactor> {
    bayes_factors
        .iter()
        .take(max)
        .map(|bf| {
            let explanation = format!(
                "{} contributes {:.1} bits {} (BF={:.2})",
                bf.feature,
                bf.delta_bits.abs(),
                bf.direction,
                bf.bf,
            );
            EvidenceFactor {
                factor: bf.feature.clone(),
                contribution_bits: bf.delta_bits,
                strength: bf.strength.clone(),
                direction: bf.direction.clone(),
                explanation,
            }
        })
        .collect()
}

fn build_counterfactuals(flip: &FlipAnalysis) -> Vec<Counterfactual> {
    flip.scenarios
        .iter()
        .map(|s| Counterfactual {
            condition: format!("Remove/reverse '{}' evidence", s.feature),
            estimated_delta_bits: s.required_delta_bits,
            could_flip: s.required_delta_bits.abs() < s.current_bits.abs() * 2.0,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::{ClassScores, PosteriorResult};
    use std::collections::HashMap;

    fn bf(feature: &str, log_bf: f64) -> BayesFactorEntry {
        let delta_bits = log_bf / std::f64::consts::LN_2;
        BayesFactorEntry {
            feature: feature.to_string(),
            bf: log_bf.exp(),
            log_bf,
            delta_bits,
            direction: if log_bf > 0.0 {
                "supports abandoned".to_string()
            } else {
                "supports useful".to_string()
            },
            strength: "strong".to_string(),
        }
    }

    fn mock_ledger() -> EvidenceLedger {
        EvidenceLedger {
            posterior: PosteriorResult {
                posterior: ClassScores {
                    useful: 0.05,
                    useful_bad: 0.03,
                    abandoned: 0.87,
                    zombie: 0.05,
                },
                log_posterior: ClassScores::default(),
                log_odds_abandoned_useful: 2.86,
                evidence_terms: vec![],
            },
            classification: Classification::Abandoned,
            confidence: Confidence::High,
            bayes_factors: vec![
                bf("cpu_occupancy", 1.9),
                bf("age_elapsed", 1.6),
                bf("net_sockets", -1.2),
            ],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        }
    }

    fn default_viz_input() -> ConfidenceVizInput {
        ConfidenceVizInput {
            top_posterior: 0.87,
            confidence: Some(Confidence::High),
            ..Default::default()
        }
    }

    #[test]
    fn test_brief_mode() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Brief,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        assert!(!resp.summary.is_empty());
        assert!(resp.detail.is_none());
        assert!(resp.evidence_breakdown.is_none());
        assert!(resp.counterfactuals.is_none());
        assert!(resp.confidence_analysis.is_none());
    }

    #[test]
    fn test_normal_mode() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Normal,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        assert!(resp.detail.is_some());
        assert!(resp.evidence_breakdown.is_some());
        assert!(resp.counterfactuals.is_some());
        assert!(resp.contributing_factors.is_some());
        assert!(resp.confidence_analysis.is_none()); // Only in verbose
    }

    #[test]
    fn test_verbose_mode() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Verbose,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        assert!(resp.confidence_analysis.is_some());
        assert!(resp.math_trace.is_none()); // Only in galaxy-brain
    }

    #[test]
    fn test_galaxy_brain_mode() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::GalaxyBrain,
            ..Default::default()
        };
        let trace = "P(A|x) = P(x|A)P(A) / P(x) = ...";
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), Some(trace));

        assert!(resp.confidence_analysis.is_some());
        assert!(resp.math_trace.is_some());
        assert!(resp.math_trace.unwrap().contains("P(A|x)"));
    }

    #[test]
    fn test_evidence_factors() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Normal,
            max_evidence_factors: 2,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        let evidence = resp.evidence_breakdown.unwrap();
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].factor, "cpu_occupancy");
    }

    #[test]
    fn test_counterfactuals_present() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Normal,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        let cf = resp.counterfactuals.unwrap();
        assert!(!cf.is_empty());
        assert!(cf[0].condition.contains("cpu_occupancy"));
    }

    #[test]
    fn test_serialization() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Verbose,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        let json = serde_json::to_string_pretty(&resp).unwrap();
        let restored: ExplanationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.classification, Classification::Abandoned);
        assert!(restored.confidence_analysis.is_some());
    }

    #[test]
    fn test_brief_serialization_compact() {
        let config = ExplainApiConfig {
            verbosity: ExplanationVerbosity::Brief,
            ..Default::default()
        };
        let resp = build_explanation(&mock_ledger(), &config, &default_viz_input(), None);

        let json = serde_json::to_string(&resp).unwrap();
        // Brief mode should not include optional fields.
        assert!(!json.contains("evidence_breakdown"));
        assert!(!json.contains("counterfactuals"));
        assert!(!json.contains("confidence_analysis"));
    }
}
