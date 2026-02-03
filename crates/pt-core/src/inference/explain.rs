//! Natural language explanation generator.
//!
//! Translates Bayesian evidence ledgers into plain English explanations
//! that non-statisticians can understand. Explanations are template-based
//! with confidence-adaptive hedging and ranked evidence contributions.
//!
//! # Example outputs
//!
//! - High confidence: "This process is almost certainly abandoned because
//!   it has been idle for 3 days with zero CPU activity and no open files."
//! - Medium confidence: "This process appears to be abandoned, mainly due
//!   to its prolonged inactivity and orphan status."
//! - Low confidence: "This process might be abandoned; notable signals
//!   include low CPU usage, though network activity suggests caution."

use serde::{Deserialize, Serialize};

use super::ledger::{BayesFactorEntry, Classification, Confidence, EvidenceLedger};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A complete natural language explanation for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaturalExplanation {
    /// One-sentence summary (suitable for TUI or compact display).
    pub summary: String,
    /// Extended explanation with evidence breakdown.
    pub detail: String,
    /// The underlying classification.
    pub classification: Classification,
    /// Confidence level.
    pub confidence: Confidence,
    /// Top contributing factors (human-readable phrases).
    pub contributing_factors: Vec<String>,
    /// Countervailing signals (factors arguing against the classification).
    pub countervailing: Vec<String>,
}

/// Configuration for explanation generation.
#[derive(Debug, Clone)]
pub struct ExplainConfig {
    /// Maximum number of top factors to mention.
    pub max_factors: usize,
    /// Maximum number of countervailing signals to mention.
    pub max_countervailing: usize,
}

impl Default for ExplainConfig {
    fn default() -> Self {
        Self {
            max_factors: 3,
            max_countervailing: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Feature name → human-readable phrasing
// ---------------------------------------------------------------------------

/// Convert a feature name and its Bayes factor entry to a human-readable phrase.
fn phrase_feature(entry: &BayesFactorEntry) -> String {
    let name = entry.feature.to_lowercase();
    let abs_bits = entry.delta_bits.abs();
    let strength_word = if abs_bits > 3.3 {
        "very strong"
    } else if abs_bits > 2.0 {
        "strong"
    } else if abs_bits > 1.0 {
        "moderate"
    } else {
        "weak"
    };

    // Map known feature names to natural language.
    let base = if name.contains("cpu") || name.contains("occupancy") {
        if entry.log_bf > 0.0 {
            "very low CPU activity"
        } else {
            "active CPU usage"
        }
    } else if name.contains("age") || name.contains("runtime") || name.contains("elapsed") {
        if entry.log_bf > 0.0 {
            "running for an unusually long time"
        } else {
            "relatively short runtime"
        }
    } else if name.contains("memory") || name.contains("rss") || name.contains("vsz") {
        if entry.log_bf > 0.0 {
            "memory held without active use"
        } else {
            "normal memory usage pattern"
        }
    } else if name.contains("fd") || name.contains("file") {
        if entry.log_bf > 0.0 {
            "no recent file activity"
        } else {
            "active file I/O"
        }
    } else if name.contains("net") || name.contains("socket") || name.contains("port") {
        if entry.log_bf > 0.0 {
            "no network connections"
        } else {
            "active network connections"
        }
    } else if name.contains("orphan") || name.contains("ppid") {
        if entry.log_bf > 0.0 {
            "orphaned (no parent process)"
        } else {
            "has a normal parent process"
        }
    } else if name.contains("state") || name.contains("zombie") {
        if entry.log_bf > 0.0 {
            "in a zombie or stopped state"
        } else {
            "in a normal running state"
        }
    } else if name.contains("thread") || name.contains("nlwp") {
        if entry.log_bf > 0.0 {
            "unusual thread count"
        } else {
            "normal thread activity"
        }
    } else if name.contains("child") || name.contains("spawn") {
        if entry.log_bf > 0.0 {
            "no child processes"
        } else {
            "actively spawning child processes"
        }
    } else {
        // Fallback for unknown features.
        return format!(
            "{} signal from {} ({})",
            strength_word, entry.feature, entry.direction
        );
    };

    format!("{} ({} signal)", base, strength_word)
}

// ---------------------------------------------------------------------------
// Core generation
// ---------------------------------------------------------------------------

/// Generate a natural language explanation from an evidence ledger.
pub fn explain(ledger: &EvidenceLedger, config: &ExplainConfig) -> NaturalExplanation {
    let class_name = classification_name(ledger.classification);
    let confidence = ledger.confidence;

    // Separate supporting vs countervailing factors.
    let (supporting, opposing): (Vec<&BayesFactorEntry>, Vec<&BayesFactorEntry>) = ledger
        .bayes_factors
        .iter()
        .partition(|bf| match ledger.classification {
            Classification::Abandoned | Classification::Zombie => bf.log_bf > 0.0,
            Classification::Useful | Classification::UsefulBad => bf.log_bf < 0.0,
        });

    let contributing_factors: Vec<String> = supporting
        .iter()
        .take(config.max_factors)
        .map(|bf| phrase_feature(bf))
        .collect();

    let countervailing: Vec<String> = opposing
        .iter()
        .take(config.max_countervailing)
        .map(|bf| phrase_feature(bf))
        .collect();

    // Build summary.
    let summary = build_summary(class_name, confidence, &contributing_factors);

    // Build detail.
    let detail = build_detail(
        class_name,
        confidence,
        &contributing_factors,
        &countervailing,
    );

    NaturalExplanation {
        summary,
        detail,
        classification: ledger.classification,
        confidence,
        contributing_factors,
        countervailing,
    }
}

fn build_summary(class_name: &str, confidence: Confidence, factors: &[String]) -> String {
    let factors_clause = if factors.is_empty() {
        String::new()
    } else {
        format!(" because of {}", join_natural(factors))
    };

    match confidence {
        Confidence::VeryHigh => {
            format!(
                "This process is almost certainly {}{}.",
                class_name, factors_clause,
            )
        }
        Confidence::High => {
            format!(
                "This process is very likely {}{}.",
                class_name, factors_clause,
            )
        }
        Confidence::Medium => {
            format!(
                "This process appears to be {}{}.",
                class_name, factors_clause,
            )
        }
        Confidence::Low => {
            if factors.is_empty() {
                format!(
                    "Insufficient evidence to confidently classify this process; it may be {}.",
                    class_name,
                )
            } else {
                format!(
                    "This process might be {}; notable signals include {}.",
                    class_name,
                    join_natural(factors),
                )
            }
        }
    }
}

fn build_detail(
    class_name: &str,
    confidence: Confidence,
    factors: &[String],
    countervailing: &[String],
) -> String {
    let mut parts = Vec::new();

    // Opening.
    let confidence_desc = match confidence {
        Confidence::VeryHigh => "very high confidence (>99%)",
        Confidence::High => "high confidence (>95%)",
        Confidence::Medium => "medium confidence (>80%)",
        Confidence::Low => "low confidence (<80%)",
    };
    parts.push(format!(
        "Classification: {} with {}.",
        class_name, confidence_desc,
    ));

    // Evidence for.
    if !factors.is_empty() {
        parts.push(format!("Key evidence: {}.", join_natural(factors),));
    }

    // Countervailing evidence.
    if !countervailing.is_empty() {
        parts.push(format!(
            "However, {} {} against this classification.",
            join_natural(countervailing),
            if countervailing.len() == 1 {
                "argues"
            } else {
                "argue"
            },
        ));
    }

    parts.join(" ")
}

fn classification_name(class: Classification) -> &'static str {
    match class {
        Classification::Useful => "useful",
        Classification::UsefulBad => "useful but problematic",
        Classification::Abandoned => "abandoned",
        Classification::Zombie => "a zombie",
    }
}

/// Join strings with commas and "and" for natural English.
fn join_natural(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        _ => {
            let (last, rest) = items.split_last().unwrap();
            format!("{}, and {}", rest.join(", "), last)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::{ClassScores, PosteriorResult};

    fn default_posterior() -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores::default(),
            log_posterior: ClassScores::default(),
            log_odds_abandoned_useful: 0.0,
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
            strength: if delta_bits.abs() > 3.3 {
                "decisive".to_string()
            } else if delta_bits.abs() > 2.0 {
                "strong".to_string()
            } else {
                "weak".to_string()
            },
        }
    }

    fn mock_ledger(
        classification: Classification,
        confidence: Confidence,
        factors: Vec<BayesFactorEntry>,
    ) -> EvidenceLedger {
        EvidenceLedger {
            posterior: default_posterior(),
            classification,
            confidence,
            bayes_factors: factors,
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_high_confidence_abandoned() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::VeryHigh,
            vec![
                bf("cpu_occupancy", 3.0),
                bf("age_elapsed", 2.5),
                bf("fd_count", 1.5),
            ],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("almost certainly abandoned"));
        assert!(explanation.summary.contains("CPU"));
        assert_eq!(explanation.contributing_factors.len(), 3);
    }

    #[test]
    fn test_medium_confidence_abandoned() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::Medium,
            vec![bf("cpu_occupancy", 2.0)],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("appears to be abandoned"));
    }

    #[test]
    fn test_low_confidence() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::Low,
            vec![bf("cpu_occupancy", 0.5)],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("might be abandoned"));
    }

    #[test]
    fn test_low_confidence_no_factors() {
        let ledger = mock_ledger(Classification::Useful, Confidence::Low, vec![]);
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("Insufficient evidence"));
    }

    #[test]
    fn test_useful_classification() {
        let ledger = mock_ledger(
            Classification::Useful,
            Confidence::High,
            vec![bf("cpu_occupancy", -2.5), bf("net_sockets", -1.8)],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("very likely useful"));
        assert!(explanation.contributing_factors.len() == 2);
    }

    #[test]
    fn test_zombie_classification() {
        let ledger = mock_ledger(
            Classification::Zombie,
            Confidence::VeryHigh,
            vec![bf("state_flag", 4.0)],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert!(explanation.summary.contains("a zombie"));
    }

    #[test]
    fn test_countervailing_evidence() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::Medium,
            vec![
                bf("cpu_occupancy", 2.5), // Supports abandoned
                bf("net_sockets", -1.5),  // Opposes (has network)
            ],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        assert_eq!(explanation.contributing_factors.len(), 1);
        assert_eq!(explanation.countervailing.len(), 1);
        assert!(explanation.detail.contains("However"));
    }

    #[test]
    fn test_max_factors_limit() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::High,
            vec![
                bf("cpu_occupancy", 3.0),
                bf("age_elapsed", 2.5),
                bf("fd_count", 2.0),
                bf("memory_rss", 1.5),
                bf("orphan_ppid", 1.2),
            ],
        );
        let config = ExplainConfig {
            max_factors: 2,
            max_countervailing: 1,
        };
        let explanation = explain(&ledger, &config);

        assert_eq!(explanation.contributing_factors.len(), 2);
    }

    #[test]
    fn test_join_natural_one() {
        assert_eq!(join_natural(&["foo".to_string()]), "foo");
    }

    #[test]
    fn test_join_natural_two() {
        assert_eq!(
            join_natural(&["foo".to_string(), "bar".to_string()]),
            "foo and bar"
        );
    }

    #[test]
    fn test_join_natural_three() {
        assert_eq!(
            join_natural(&["a".to_string(), "b".to_string(), "c".to_string()]),
            "a, b, and c"
        );
    }

    #[test]
    fn test_serialization() {
        let ledger = mock_ledger(
            Classification::Abandoned,
            Confidence::High,
            vec![bf("cpu_occupancy", 2.5)],
        );
        let explanation = explain(&ledger, &ExplainConfig::default());

        let json = serde_json::to_string_pretty(&explanation).unwrap();
        let restored: NaturalExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.classification, Classification::Abandoned);
    }
}
