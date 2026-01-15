//! Evidence ledger for process classification explainability.
//!
//! The evidence ledger explains each feature's contribution to classification:
//! - Computes Bayes factors from log-likelihood differences
//! - Sorts contributions by magnitude
//! - Maps features to display glyphs
//! - Generates human-readable "why" summaries
//!
//! This supports galaxy-brain mode visualization and debugging of classifications.

use pt_math::bayes_factor::{EvidenceDirection, EvidenceStrength, EvidenceSummary};
use serde::Serialize;
use std::collections::HashMap;

use super::{ClassScores, EvidenceTerm, PosteriorResult};

/// Classification result from the 4-state model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Useful,
    UsefulBad,
    Abandoned,
    Zombie,
}

impl Classification {
    /// Determine classification from posterior scores (argmax).
    pub fn from_posterior(scores: &ClassScores) -> Self {
        let values = [
            (scores.useful, Classification::Useful),
            (scores.useful_bad, Classification::UsefulBad),
            (scores.abandoned, Classification::Abandoned),
            (scores.zombie, Classification::Zombie),
        ];
        values
            .into_iter()
            .max_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, c)| c)
            .unwrap_or(Classification::Useful)
    }

    /// Get the class index (0-3) for array access.
    pub fn index(&self) -> usize {
        match self {
            Classification::Useful => 0,
            Classification::UsefulBad => 1,
            Classification::Abandoned => 2,
            Classification::Zombie => 3,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Classification::Useful => "useful",
            Classification::UsefulBad => "useful_bad",
            Classification::Abandoned => "abandoned",
            Classification::Zombie => "zombie",
        }
    }
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Confidence level based on posterior probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl Confidence {
    /// Determine confidence from max posterior probability.
    pub fn from_max_posterior(p: f64) -> Self {
        if p >= 0.95 {
            Confidence::VeryHigh
        } else if p >= 0.80 {
            Confidence::High
        } else if p >= 0.60 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::VeryHigh => "very_high",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A single feature's Bayes factor contribution to classification.
#[derive(Debug, Clone, Serialize)]
pub struct BayesFactorEntry {
    /// Feature name (cpu, tty, orphan, etc.).
    pub feature: String,
    /// Log Bayes factor (positive favors predicted class).
    pub log_bf: f64,
    /// Bayes factor (exp of log_bf, clamped).
    pub bf: f64,
    /// Evidence in bits (MDL interpretation).
    pub delta_bits: f64,
    /// Direction: toward predicted class or toward reference.
    pub direction: Direction,
    /// Strength on Jeffreys scale.
    pub strength: EvidenceStrength,
    /// Human-readable description of evidence.
    pub description: Option<String>,
}

/// Direction of evidence contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Evidence supports the predicted classification.
    TowardPredicted,
    /// Evidence opposes the predicted classification (favors reference).
    TowardReference,
    /// Evidence is neutral.
    Neutral,
}

impl Direction {
    fn from_log_bf(log_bf: f64) -> Self {
        if log_bf.abs() < f64::EPSILON {
            Direction::Neutral
        } else if log_bf > 0.0 {
            Direction::TowardPredicted
        } else {
            Direction::TowardReference
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::TowardPredicted => write!(f, "toward_predicted"),
            Direction::TowardReference => write!(f, "toward_reference"),
            Direction::Neutral => write!(f, "neutral"),
        }
    }
}

/// Feature glyph for visualization.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureGlyph {
    /// Feature name.
    pub feature: String,
    /// Display glyph.
    pub glyph: &'static str,
    /// Short label.
    pub label: &'static str,
}

/// Default glyph mapping for features.
pub fn default_glyph_map() -> HashMap<&'static str, FeatureGlyph> {
    let mut map = HashMap::new();
    map.insert(
        "cpu",
        FeatureGlyph {
            feature: "cpu".to_string(),
            glyph: "🔥",
            label: "CPU",
        },
    );
    map.insert(
        "runtime",
        FeatureGlyph {
            feature: "runtime".to_string(),
            glyph: "⏱️",
            label: "Runtime",
        },
    );
    map.insert(
        "orphan",
        FeatureGlyph {
            feature: "orphan".to_string(),
            glyph: "👻",
            label: "Orphan",
        },
    );
    map.insert(
        "tty",
        FeatureGlyph {
            feature: "tty".to_string(),
            glyph: "💀",
            label: "TTY",
        },
    );
    map.insert(
        "net",
        FeatureGlyph {
            feature: "net".to_string(),
            glyph: "🌐",
            label: "Net",
        },
    );
    map.insert(
        "io_active",
        FeatureGlyph {
            feature: "io_active".to_string(),
            glyph: "⚡",
            label: "I/O",
        },
    );
    map.insert(
        "state_flag",
        FeatureGlyph {
            feature: "state_flag".to_string(),
            glyph: "🚦",
            label: "State",
        },
    );
    map.insert(
        "command_category",
        FeatureGlyph {
            feature: "command_category".to_string(),
            glyph: "📦",
            label: "Category",
        },
    );
    map.insert(
        "prior",
        FeatureGlyph {
            feature: "prior".to_string(),
            glyph: "📊",
            label: "Prior",
        },
    );
    map
}

/// Get the glyph for a feature.
pub fn get_glyph(feature: &str) -> &'static str {
    match feature {
        "cpu" => "🔥",
        "runtime" => "⏱️",
        "orphan" => "👻",
        "tty" => "💀",
        "net" => "🌐",
        "io_active" => "⚡",
        "state_flag" => "🚦",
        "command_category" => "📦",
        "prior" => "📊",
        _ => "❓",
    }
}

/// Complete evidence ledger for a process classification.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceLedger {
    /// Process ID (if known).
    pub pid: Option<u32>,
    /// Predicted classification.
    pub classification: Classification,
    /// Raw posterior probabilities.
    pub posterior: ClassScores,
    /// Confidence level.
    pub confidence: Confidence,
    /// All Bayes factor entries, sorted by magnitude (descending).
    pub bayes_factors: Vec<BayesFactorEntry>,
    /// Top evidence summaries (human-readable).
    pub top_evidence: Vec<String>,
    /// Feature glyphs map.
    pub evidence_glyphs: HashMap<String, String>,
    /// Human-readable why summary.
    pub why_summary: String,
}

impl EvidenceLedger {
    /// Build an evidence ledger from a posterior result.
    ///
    /// # Arguments
    /// * `result` - The posterior computation result
    /// * `pid` - Optional process ID for context
    /// * `reference_class` - Class to compare against (default: useful)
    pub fn from_posterior_result(
        result: &PosteriorResult,
        pid: Option<u32>,
        reference_class: Option<Classification>,
    ) -> Self {
        let classification = Classification::from_posterior(&result.posterior);
        let reference = reference_class.unwrap_or(Classification::Useful);
        let max_posterior = max_posterior_value(&result.posterior);
        let confidence = Confidence::from_max_posterior(max_posterior);

        // Compute Bayes factors for each evidence term
        let mut bayes_factors: Vec<BayesFactorEntry> = result
            .evidence_terms
            .iter()
            .map(|term| compute_bf_entry(term, classification, reference))
            .collect();

        // Sort by absolute log_bf (magnitude), descending
        bayes_factors.sort_by(|a, b| {
            b.log_bf
                .abs()
                .partial_cmp(&a.log_bf.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Generate top evidence summaries (top 3)
        let top_evidence: Vec<String> = bayes_factors
            .iter()
            .filter(|bf| bf.strength as u8 >= EvidenceStrength::Substantial as u8)
            .take(3)
            .map(|bf| format_evidence_summary(bf))
            .collect();

        // Build glyph map for features present
        let evidence_glyphs: HashMap<String, String> = bayes_factors
            .iter()
            .map(|bf| (bf.feature.clone(), get_glyph(&bf.feature).to_string()))
            .collect();

        // Generate why summary
        let why_summary = generate_why_summary(&bayes_factors, classification, confidence);

        EvidenceLedger {
            pid,
            classification,
            posterior: result.posterior,
            confidence,
            bayes_factors,
            top_evidence,
            evidence_glyphs,
            why_summary,
        }
    }

    /// Get the top N Bayes factor entries by magnitude.
    pub fn top_factors(&self, n: usize) -> &[BayesFactorEntry] {
        let len = self.bayes_factors.len().min(n);
        &self.bayes_factors[..len]
    }

    /// Get entries that support the classification.
    pub fn supporting_evidence(&self) -> Vec<&BayesFactorEntry> {
        self.bayes_factors
            .iter()
            .filter(|bf| bf.direction == Direction::TowardPredicted)
            .collect()
    }

    /// Get entries that oppose the classification.
    pub fn opposing_evidence(&self) -> Vec<&BayesFactorEntry> {
        self.bayes_factors
            .iter()
            .filter(|bf| bf.direction == Direction::TowardReference)
            .collect()
    }

    /// Check if classification has strong evidence support.
    pub fn has_strong_support(&self) -> bool {
        self.bayes_factors
            .iter()
            .any(|bf| {
                bf.direction == Direction::TowardPredicted
                    && bf.strength as u8 >= EvidenceStrength::Strong as u8
            })
    }
}

/// Compute a Bayes factor entry from an evidence term.
fn compute_bf_entry(
    term: &EvidenceTerm,
    predicted: Classification,
    reference: Classification,
) -> BayesFactorEntry {
    let log_lik_predicted = get_class_log_lik(&term.log_likelihood, predicted);
    let log_lik_reference = get_class_log_lik(&term.log_likelihood, reference);

    // Log Bayes factor: positive means evidence favors predicted class
    let log_bf = log_lik_predicted - log_lik_reference;
    let summary = EvidenceSummary::from_log_bf(log_bf);

    BayesFactorEntry {
        feature: term.feature.clone(),
        log_bf,
        bf: summary.e_value,
        delta_bits: summary.delta_bits,
        direction: Direction::from_log_bf(log_bf),
        strength: summary.strength,
        description: None,
    }
}

/// Get log-likelihood value for a class.
fn get_class_log_lik(scores: &ClassScores, class: Classification) -> f64 {
    match class {
        Classification::Useful => scores.useful,
        Classification::UsefulBad => scores.useful_bad,
        Classification::Abandoned => scores.abandoned,
        Classification::Zombie => scores.zombie,
    }
}

/// Get the maximum posterior value.
fn max_posterior_value(posterior: &ClassScores) -> f64 {
    posterior
        .useful
        .max(posterior.useful_bad)
        .max(posterior.abandoned)
        .max(posterior.zombie)
}

/// Format a human-readable summary for a Bayes factor entry.
fn format_evidence_summary(bf: &BayesFactorEntry) -> String {
    let direction = if bf.direction == Direction::TowardPredicted {
        "supports"
    } else {
        "opposes"
    };
    let glyph = get_glyph(&bf.feature);
    format!(
        "{} {} {} classification (BF={:.1}, {})",
        glyph,
        bf.feature,
        direction,
        bf.bf,
        bf.strength.label()
    )
}

/// Generate a complete why summary.
fn generate_why_summary(
    bayes_factors: &[BayesFactorEntry],
    classification: Classification,
    confidence: Confidence,
) -> String {
    let supporting: Vec<_> = bayes_factors
        .iter()
        .filter(|bf| {
            bf.direction == Direction::TowardPredicted
                && bf.strength as u8 >= EvidenceStrength::Substantial as u8
        })
        .take(3)
        .collect();

    let opposing: Vec<_> = bayes_factors
        .iter()
        .filter(|bf| {
            bf.direction == Direction::TowardReference
                && bf.strength as u8 >= EvidenceStrength::Substantial as u8
        })
        .take(2)
        .collect();

    let mut parts = Vec::new();

    parts.push(format!(
        "Classified as {} with {} confidence.",
        classification, confidence
    ));

    if !supporting.is_empty() {
        let features: Vec<_> = supporting.iter().map(|bf| bf.feature.as_str()).collect();
        let feature_list = features.join(", ");
        parts.push(format!("Key supporting evidence: {}.", feature_list));
    }

    if !opposing.is_empty() {
        let features: Vec<_> = opposing.iter().map(|bf| bf.feature.as_str()).collect();
        let feature_list = features.join(", ");
        parts.push(format!("Opposing evidence: {}.", feature_list));
    }

    if supporting.is_empty() && opposing.is_empty() {
        parts.push("Classification based primarily on prior probabilities.".to_string());
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_posterior() -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores {
                useful: 0.1,
                useful_bad: 0.05,
                abandoned: 0.8,
                zombie: 0.05,
            },
            log_posterior: ClassScores {
                useful: 0.1f64.ln(),
                useful_bad: 0.05f64.ln(),
                abandoned: 0.8f64.ln(),
                zombie: 0.05f64.ln(),
            },
            log_odds_abandoned_useful: (0.8f64 / 0.1f64).ln(),
            evidence_terms: vec![
                EvidenceTerm {
                    feature: "prior".to_string(),
                    log_likelihood: ClassScores {
                        useful: 0.25f64.ln(),
                        useful_bad: 0.25f64.ln(),
                        abandoned: 0.25f64.ln(),
                        zombie: 0.25f64.ln(),
                    },
                },
                EvidenceTerm {
                    feature: "tty".to_string(),
                    log_likelihood: ClassScores {
                        useful: 0.2f64.ln(),
                        useful_bad: 0.3f64.ln(),
                        abandoned: 0.9f64.ln(),
                        zombie: 0.5f64.ln(),
                    },
                },
                EvidenceTerm {
                    feature: "cpu".to_string(),
                    log_likelihood: ClassScores {
                        useful: 0.5f64.ln(),
                        useful_bad: 0.8f64.ln(),
                        abandoned: 0.7f64.ln(),
                        zombie: 0.1f64.ln(),
                    },
                },
                EvidenceTerm {
                    feature: "orphan".to_string(),
                    log_likelihood: ClassScores {
                        useful: 0.1f64.ln(),
                        useful_bad: 0.2f64.ln(),
                        abandoned: 0.8f64.ln(),
                        zombie: 0.3f64.ln(),
                    },
                },
            ],
        }
    }

    #[test]
    fn classification_from_posterior() {
        let scores = ClassScores {
            useful: 0.1,
            useful_bad: 0.05,
            abandoned: 0.8,
            zombie: 0.05,
        };
        assert_eq!(
            Classification::from_posterior(&scores),
            Classification::Abandoned
        );
    }

    #[test]
    fn classification_labels() {
        assert_eq!(Classification::Useful.label(), "useful");
        assert_eq!(Classification::UsefulBad.label(), "useful_bad");
        assert_eq!(Classification::Abandoned.label(), "abandoned");
        assert_eq!(Classification::Zombie.label(), "zombie");
    }

    #[test]
    fn confidence_levels() {
        assert_eq!(Confidence::from_max_posterior(0.99), Confidence::VeryHigh);
        assert_eq!(Confidence::from_max_posterior(0.85), Confidence::High);
        assert_eq!(Confidence::from_max_posterior(0.70), Confidence::Medium);
        assert_eq!(Confidence::from_max_posterior(0.40), Confidence::Low);
    }

    #[test]
    fn ledger_from_posterior_result() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, Some(1234), None);

        assert_eq!(ledger.pid, Some(1234));
        assert_eq!(ledger.classification, Classification::Abandoned);
        assert_eq!(ledger.confidence, Confidence::High);
        assert!(!ledger.bayes_factors.is_empty());
        assert!(!ledger.why_summary.is_empty());
    }

    #[test]
    fn bayes_factors_sorted_by_magnitude() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        // Check that factors are sorted by absolute log_bf
        for i in 1..ledger.bayes_factors.len() {
            assert!(
                ledger.bayes_factors[i - 1].log_bf.abs()
                    >= ledger.bayes_factors[i].log_bf.abs(),
                "Bayes factors should be sorted by magnitude"
            );
        }
    }

    #[test]
    fn tty_provides_strong_evidence_for_abandoned() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        let tty_entry = ledger
            .bayes_factors
            .iter()
            .find(|bf| bf.feature == "tty")
            .expect("tty should be in ledger");

        // tty: abandoned = ln(0.9), useful = ln(0.2)
        // log_bf = ln(0.9) - ln(0.2) = ln(4.5) ≈ 1.5, which is substantial
        assert!(tty_entry.log_bf > 0.0, "tty should favor abandoned");
        assert_eq!(tty_entry.direction, Direction::TowardPredicted);
    }

    #[test]
    fn prior_is_neutral() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        let prior_entry = ledger
            .bayes_factors
            .iter()
            .find(|bf| bf.feature == "prior")
            .expect("prior should be in ledger");

        // Uniform prior: all classes have same log_lik
        assert!(
            prior_entry.log_bf.abs() < 1e-10,
            "prior should be neutral with uniform priors"
        );
    }

    #[test]
    fn evidence_glyphs_populated() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        assert!(ledger.evidence_glyphs.contains_key("tty"));
        assert!(ledger.evidence_glyphs.contains_key("cpu"));
        assert_eq!(ledger.evidence_glyphs.get("tty"), Some(&"💀".to_string()));
    }

    #[test]
    fn top_factors_limits_results() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        assert_eq!(ledger.top_factors(2).len(), 2);
        assert_eq!(ledger.top_factors(100).len(), ledger.bayes_factors.len());
    }

    #[test]
    fn supporting_evidence_filters_correctly() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        let supporting = ledger.supporting_evidence();
        for entry in supporting {
            assert_eq!(entry.direction, Direction::TowardPredicted);
        }
    }

    #[test]
    fn opposing_evidence_filters_correctly() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        let opposing = ledger.opposing_evidence();
        for entry in opposing {
            assert_eq!(entry.direction, Direction::TowardReference);
        }
    }

    #[test]
    fn direction_from_log_bf() {
        assert_eq!(Direction::from_log_bf(1.0), Direction::TowardPredicted);
        assert_eq!(Direction::from_log_bf(-1.0), Direction::TowardReference);
        assert_eq!(Direction::from_log_bf(0.0), Direction::Neutral);
    }

    #[test]
    fn glyph_mapping() {
        assert_eq!(get_glyph("cpu"), "🔥");
        assert_eq!(get_glyph("tty"), "💀");
        assert_eq!(get_glyph("orphan"), "👻");
        assert_eq!(get_glyph("unknown"), "❓");
    }

    #[test]
    fn why_summary_contains_classification() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        assert!(ledger.why_summary.contains("abandoned"));
        assert!(ledger.why_summary.contains("high"));
    }

    #[test]
    fn has_strong_support_with_substantial_evidence() {
        let result = make_test_posterior();
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        // Our test data has strong tty and orphan evidence
        // Check if any supporting evidence has Strong or better strength
        let has_strong = ledger.bayes_factors.iter().any(|bf| {
            bf.direction == Direction::TowardPredicted
                && bf.strength as u8 >= EvidenceStrength::Strong as u8
        });

        assert_eq!(ledger.has_strong_support(), has_strong);
    }
}
