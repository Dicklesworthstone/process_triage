//! What-if / flip-conditions explainer.
//!
//! Computes which evidence changes would reverse a classification decision.
//! For each dominant evidence term, estimates how much that feature would
//! need to shift to flip the posterior below/above the decision threshold.

use serde::{Deserialize, Serialize};

use super::ledger::{BayesFactorEntry, Classification, EvidenceLedger};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single flip scenario: what change in evidence would reverse the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipScenario {
    /// Feature whose change would trigger the flip.
    pub feature: String,
    /// Current log Bayes factor for this feature.
    pub current_log_bf: f64,
    /// Current delta in bits.
    pub current_bits: f64,
    /// Required delta in log_bf to flip the classification.
    pub required_delta_log_bf: f64,
    /// Required delta in bits.
    pub required_delta_bits: f64,
    /// Estimated probability shift if this feature were removed.
    pub delta_p_if_removed: f64,
    /// Human-readable explanation of the flip condition.
    pub explanation: String,
}

/// Configuration for flip-condition analysis.
#[derive(Debug, Clone)]
pub struct FlipConfig {
    /// Maximum number of flip scenarios to return.
    pub max_scenarios: usize,
    /// Decision threshold: posterior probability below which classification flips.
    pub threshold: f64,
}

impl Default for FlipConfig {
    fn default() -> Self {
        Self {
            max_scenarios: 5,
            threshold: 0.5,
        }
    }
}

/// Complete flip-condition analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipAnalysis {
    pub classification: Classification,
    /// Current posterior probability for the classified state.
    pub current_posterior: f64,
    /// Margin above the decision threshold.
    pub margin: f64,
    /// Ranked flip scenarios (easiest flip first).
    pub scenarios: Vec<FlipScenario>,
    /// Summary text.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

/// Compute flip conditions from an evidence ledger.
pub fn compute_flip_conditions(ledger: &EvidenceLedger, config: &FlipConfig) -> FlipAnalysis {
    let current_posterior = posterior_for_class(ledger);
    let margin = current_posterior - config.threshold;

    // Only analyse supporting factors (those that push toward the classification).
    let supporting: Vec<&BayesFactorEntry> = ledger
        .bayes_factors
        .iter()
        .filter(|bf| is_supporting(bf, ledger.classification))
        .collect();

    // Total supporting log-odds.
    let total_support_log_bf: f64 = supporting.iter().map(|bf| bf.log_bf.abs()).sum();

    let mut scenarios: Vec<FlipScenario> =
        supporting
            .iter()
            .map(|bf| {
                let abs_bits = bf.delta_bits.abs();
                let fraction = if total_support_log_bf > 0.0 {
                    bf.log_bf.abs() / total_support_log_bf
                } else {
                    0.0
                };
                // Approximate delta_p if this feature were entirely removed.
                let delta_p = fraction * margin.max(0.0);

                // How much would log_bf need to change to eliminate margin?
                // Rough linear approximation: required_delta ≈ margin / fraction_per_unit.
                let required_delta_log_bf = if fraction > 0.0 {
                    margin / fraction
                } else {
                    f64::INFINITY
                };
                let required_delta_bits = required_delta_log_bf / std::f64::consts::LN_2;

                let explanation =
                    format!(
                "If '{}' evidence were removed ({:.1} bits), posterior would drop ~{:.1}pp. \
                 To flip, this feature would need to shift by {:.1} bits.",
                bf.feature, abs_bits, delta_p * 100.0, required_delta_bits.abs(),
            );

                FlipScenario {
                    feature: bf.feature.clone(),
                    current_log_bf: bf.log_bf,
                    current_bits: bf.delta_bits,
                    required_delta_log_bf,
                    required_delta_bits,
                    delta_p_if_removed: delta_p,
                    explanation,
                }
            })
            .collect();

    // Sort by required_delta_bits ascending (easiest flip first).
    scenarios.sort_by(|a, b| {
        a.required_delta_bits
            .abs()
            .partial_cmp(&b.required_delta_bits.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    scenarios.truncate(config.max_scenarios);

    let summary = build_summary(ledger.classification, current_posterior, margin, &scenarios);

    FlipAnalysis {
        classification: ledger.classification,
        current_posterior,
        margin,
        scenarios,
        summary,
    }
}

fn posterior_for_class(ledger: &EvidenceLedger) -> f64 {
    match ledger.classification {
        Classification::Useful => ledger.posterior.posterior.useful,
        Classification::UsefulBad => ledger.posterior.posterior.useful_bad,
        Classification::Abandoned => ledger.posterior.posterior.abandoned,
        Classification::Zombie => ledger.posterior.posterior.zombie,
    }
}

fn is_supporting(bf: &BayesFactorEntry, class: Classification) -> bool {
    match class {
        Classification::Abandoned | Classification::Zombie => bf.log_bf > 0.0,
        Classification::Useful | Classification::UsefulBad => bf.log_bf < 0.0,
    }
}

fn build_summary(
    class: Classification,
    posterior: f64,
    margin: f64,
    scenarios: &[FlipScenario],
) -> String {
    if scenarios.is_empty() {
        return format!(
            "Classification {:?} (P={:.1}%) has no dominant evidence to flip.",
            class,
            posterior * 100.0,
        );
    }

    let easiest = &scenarios[0];
    format!(
        "Classification {:?} (P={:.1}%, margin={:.1}pp). \
         Easiest flip: change '{}' by {:.1} bits.",
        class,
        posterior * 100.0,
        margin * 100.0,
        easiest.feature,
        easiest.required_delta_bits.abs(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::ledger::{Confidence, EvidenceLedger};
    use crate::inference::posterior::{ClassScores, PosteriorResult};
    use std::collections::HashMap;

    fn mock_posterior() -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores {
                useful: 0.05,
                useful_bad: 0.03,
                abandoned: 0.87,
                zombie: 0.05,
            },
            log_posterior: ClassScores::default(),
            log_odds_abandoned_useful: 2.86,
            evidence_terms: vec![],
        }
    }

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

    fn mock_ledger(factors: Vec<BayesFactorEntry>) -> EvidenceLedger {
        EvidenceLedger {
            posterior: mock_posterior(),
            classification: Classification::Abandoned,
            confidence: Confidence::High,
            bayes_factors: factors,
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        }
    }

    #[test]
    fn test_basic_flip_analysis() {
        let ledger = mock_ledger(vec![bf("cpu_occupancy", 1.9), bf("age_elapsed", 1.6)]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        assert_eq!(analysis.classification, Classification::Abandoned);
        assert!((analysis.current_posterior - 0.87).abs() < 1e-9);
        assert!(analysis.margin > 0.0);
        assert!(!analysis.scenarios.is_empty());
    }

    #[test]
    fn test_scenarios_sorted_by_ease() {
        let ledger = mock_ledger(vec![
            bf("cpu_occupancy", 1.9),
            bf("age_elapsed", 1.6),
            bf("fd_count", 0.4),
        ]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        // Largest contributor (cpu) should need least relative change.
        for w in analysis.scenarios.windows(2) {
            assert!(w[0].required_delta_bits.abs() <= w[1].required_delta_bits.abs());
        }
    }

    #[test]
    fn test_max_scenarios_limit() {
        let ledger = mock_ledger(vec![
            bf("a", 1.0),
            bf("b", 0.8),
            bf("c", 0.6),
            bf("d", 0.4),
            bf("e", 0.2),
            bf("f", 0.1),
        ]);
        let config = FlipConfig {
            max_scenarios: 3,
            ..Default::default()
        };
        let analysis = compute_flip_conditions(&ledger, &config);
        assert_eq!(analysis.scenarios.len(), 3);
    }

    #[test]
    fn test_opposing_evidence_excluded() {
        let ledger = mock_ledger(vec![
            bf("cpu_occupancy", 1.9), // supports abandoned
            bf("net_sockets", -1.2),  // opposes abandoned
        ]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        // Only cpu_occupancy should appear (it supports the classification).
        assert_eq!(analysis.scenarios.len(), 1);
        assert_eq!(analysis.scenarios[0].feature, "cpu_occupancy");
    }

    #[test]
    fn test_empty_evidence() {
        let ledger = mock_ledger(vec![]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        assert!(analysis.scenarios.is_empty());
        assert!(analysis.summary.contains("no dominant evidence"));
    }

    #[test]
    fn test_summary_format() {
        let ledger = mock_ledger(vec![bf("cpu_occupancy", 1.9)]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        assert!(analysis.summary.contains("Abandoned"));
        assert!(analysis.summary.contains("cpu_occupancy"));
        assert!(analysis.summary.contains("bits"));
    }

    #[test]
    fn test_useful_classification() {
        let ledger = EvidenceLedger {
            posterior: PosteriorResult {
                posterior: ClassScores {
                    useful: 0.90,
                    useful_bad: 0.03,
                    abandoned: 0.05,
                    zombie: 0.02,
                },
                log_posterior: ClassScores::default(),
                log_odds_abandoned_useful: -2.9,
                evidence_terms: vec![],
            },
            classification: Classification::Useful,
            confidence: Confidence::High,
            bayes_factors: vec![
                bf("cpu_occupancy", -2.0), // supports useful
                bf("net_sockets", -1.5),   // supports useful
            ],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        };
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        assert_eq!(analysis.classification, Classification::Useful);
        assert_eq!(analysis.scenarios.len(), 2);
    }

    #[test]
    fn test_serialization() {
        let ledger = mock_ledger(vec![bf("cpu", 1.5)]);
        let analysis = compute_flip_conditions(&ledger, &FlipConfig::default());

        let json = serde_json::to_string(&analysis).unwrap();
        let restored: FlipAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.classification, Classification::Abandoned);
        assert_eq!(restored.scenarios.len(), 1);
    }
}
