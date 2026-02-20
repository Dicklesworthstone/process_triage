//! Evidence ledger for explainability.
//!
//! Provides structures and helpers for human-readable evidence summaries
//! and Bayes factor breakdowns.

use super::posterior::PosteriorResult;
use crate::collect::ProcessRecord;
use crate::config::priors::Priors;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BayesFactorEntry {
    pub feature: String,
    pub bf: f64,
    pub log_bf: f64,
    pub delta_bits: f64,
    pub direction: String,
    pub strength: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLedger {
    pub posterior: PosteriorResult,
    pub classification: Classification,
    pub confidence: Confidence,
    pub bayes_factors: Vec<BayesFactorEntry>,
    pub top_evidence: Vec<String>,
    pub why_summary: String,
    pub evidence_glyphs: HashMap<String, String>,
}

impl EvidenceLedger {
    pub fn from_posterior_result(
        result: &PosteriorResult,
        _pid: Option<u32>,
        _reference: Option<Classification>,
    ) -> Self {
        // Find the highest probability class
        let scores = [
            (Classification::Useful, result.posterior.useful),
            (Classification::UsefulBad, result.posterior.useful_bad),
            (Classification::Abandoned, result.posterior.abandoned),
            (Classification::Zombie, result.posterior.zombie),
        ];

        let (classification, prob) = scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(c, p)| (*c, *p))
            .unwrap_or((Classification::Useful, 0.0));

        let confidence = if prob > 0.99 {
            Confidence::VeryHigh
        } else if prob > 0.95 {
            Confidence::High
        } else if prob > 0.80 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let summary = format!(
            "Classified as {:?} with {} confidence.",
            classification, confidence
        );

        // Calculate Bayes Factors for Abandoned vs Useful
        let mut bayes_factors = Vec::new();
        for term in &result.evidence_terms {
            // log(P(f|Abandoned) / P(f|Useful)) = log(P(f|A)) - log(P(f|U))
            let log_bf = term.log_likelihood.abandoned - term.log_likelihood.useful;

            // Skip terms with negligible impact
            if log_bf.abs() < 0.01 {
                continue;
            }

            let bf = log_bf.exp();
            let delta_bits = log_bf / std::f64::consts::LN_2;

            let direction = if log_bf > 0.0 {
                "supports abandoned".to_string()
            } else {
                "supports useful".to_string()
            };

            let abs_bits = delta_bits.abs();
            let strength = if abs_bits > 3.3 {
                // > 10:1
                "decisive".to_string()
            } else if abs_bits > 2.0 {
                // > 4:1
                "strong".to_string()
            } else if abs_bits > 1.0 {
                // > 2:1
                "substantial".to_string()
            } else {
                "weak".to_string()
            };

            bayes_factors.push(BayesFactorEntry {
                feature: term.feature.clone(),
                bf,
                log_bf,
                delta_bits,
                direction,
                strength,
            });
        }

        // Sort by absolute impact (descending)
        bayes_factors.sort_by(|a, b| {
            b.delta_bits
                .abs()
                .partial_cmp(&a.delta_bits.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Generate top evidence summary
        let mut top_evidence = Vec::new();
        for bf in bayes_factors.iter().take(3) {
            let desc = format!(
                "{} ({:.1} bits {})",
                bf.feature,
                bf.delta_bits.abs(),
                if bf.log_bf > 0.0 {
                    "toward abandoned"
                } else {
                    "toward useful"
                }
            );
            top_evidence.push(desc);
        }

        let evidence_glyphs: HashMap<String, String> = bayes_factors
            .iter()
            .map(|bf| (bf.feature.clone(), get_glyph(&bf.feature).to_string()))
            .collect();

        Self {
            posterior: result.clone(),
            classification,
            confidence,
            bayes_factors,
            top_evidence,
            why_summary: summary,
            evidence_glyphs,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    TowardPredicted,
    TowardReference,
    Neutral,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    VeryHigh,
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::VeryHigh => "very_high",
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureGlyph {
    pub feature: String,
    pub glyph: char,
}

pub fn get_glyph(feature: &str) -> char {
    match feature {
        "prior" => '\u{1F3B2}',            // dice - prior probability
        "cpu" => '\u{1F4BB}',              // laptop - CPU activity
        "runtime" => '\u{23F1}',           // stopwatch - process age
        "orphan" => '\u{1F47B}',           // ghost - orphaned process
        "tty" => '\u{1F5A5}',              // desktop computer - terminal
        "net" => '\u{1F310}',              // globe - network activity
        "io_active" => '\u{1F4BE}',        // floppy - I/O activity
        "state_flag" => '\u{1F6A9}',       // flag - process state
        "command_category" => '\u{1F3F7}', // label - command type
        "signature_match" => '\u{1F50D}',  // magnifying glass
        "fast_path" => '\u{26A1}',         // lightning bolt
        _ => '?',
    }
}

pub fn default_glyph_map() -> std::collections::HashMap<String, char> {
    let features = [
        "prior",
        "cpu",
        "runtime",
        "orphan",
        "tty",
        "net",
        "io_active",
        "state_flag",
        "command_category",
        "signature_match",
        "fast_path",
    ];
    features
        .iter()
        .map(|f| (f.to_string(), get_glyph(f)))
        .collect()
}

pub fn build_process_explanation(proc: &ProcessRecord, priors: &Priors) -> serde_json::Value {
    // 1. Convert ProcessRecord to Evidence
    // This requires mapping logic which is likely in decision/mod.rs or inference/mod.rs
    // For now, we'll construct minimal evidence based on the record
    use crate::inference::{compute_posterior, CpuEvidence, Evidence};

    let state_flag = priors.state_flags.as_ref().and_then(|sf| {
        let state_str = proc.state.to_string();
        sf.flag_names.iter().position(|name| name == &state_str)
    });

    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction {
            occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
        }),
        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
        orphan: Some(proc.ppid.0 == 1),
        tty: Some(proc.tty.is_some()),
        // Other fields would come from deep scan if available
        net: None,
        io_active: None,
        state_flag,
        command_category: None, // Needs category mapping
    };

    // 2. Compute posterior
    let result = match compute_posterior(priors, &evidence) {
        Ok(res) => res,
        Err(e) => {
            return serde_json::json!({
                "pid": proc.pid.0,
                "error": e.to_string()
            });
        }
    };

    // 3. Determine classification and confidence
    let (class, prob) = if result.posterior.abandoned > result.posterior.useful {
        ("abandoned", result.posterior.abandoned)
    } else {
        ("useful", result.posterior.useful)
    };

    let confidence = if prob > 0.99 {
        Confidence::VeryHigh
    } else if prob > 0.95 {
        Confidence::High
    } else if prob > 0.80 {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    // 4. Calculate per-feature Bayes Factors (Abandoned vs Useful)
    let mut bfs: Vec<BayesFactorEntry> = Vec::new();
    for term in &result.evidence_terms {
        let log_bf = term.log_likelihood.abandoned - term.log_likelihood.useful;
        if log_bf.abs() < 0.01 {
            continue;
        }
        let bf = log_bf.exp();
        let delta_bits = log_bf / std::f64::consts::LN_2;
        let direction = if log_bf > 0.0 {
            "supports abandoned".to_string()
        } else {
            "supports useful".to_string()
        };
        let abs_bits = delta_bits.abs();
        let strength = if abs_bits > 3.3 {
            "decisive".to_string()
        } else if abs_bits > 2.0 {
            "strong".to_string()
        } else if abs_bits > 1.0 {
            "substantial".to_string()
        } else {
            "weak".to_string()
        };
        bfs.push(BayesFactorEntry {
            feature: term.feature.clone(),
            bf,
            log_bf,
            delta_bits,
            direction,
            strength,
        });
    }
    bfs.sort_by(|a, b| {
        b.delta_bits
            .abs()
            .partial_cmp(&a.delta_bits.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // 5. Generate summary
    let summary = format!(
        "Process {} is likely {} ({:.1}% confidence).",
        proc.pid.0,
        class,
        prob * 100.0
    );

    serde_json::json!({
        "pid": proc.pid.0,
        "classification": class,
        "confidence": confidence.to_string(),
        "posterior": result.posterior,
        "bayes_factors": bfs,
        "why_summary": summary,
        "evidence": evidence_to_json(&evidence),
    })
}

fn evidence_to_json(evidence: &crate::inference::Evidence) -> serde_json::Value {
    let cpu = match &evidence.cpu {
        Some(crate::inference::CpuEvidence::Fraction { occupancy }) => {
            serde_json::json!({ "type": "fraction", "occupancy": occupancy })
        }
        Some(crate::inference::CpuEvidence::Binomial { k, n, eta }) => {
            serde_json::json!({ "type": "binomial", "k": k, "n": n, "eta": eta })
        }
        None => serde_json::Value::Null,
    };

    serde_json::json!({
        "cpu": cpu,
        "runtime_seconds": evidence.runtime_seconds,
        "orphan": evidence.orphan,
        "tty": evidence.tty,
        "net": evidence.net,
        "io_active": evidence.io_active,
        "state_flag": evidence.state_flag,
        "command_category": evidence.command_category,
    })
}

// Re-export Classification if needed by other modules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Useful,
    UsefulBad,
    Abandoned,
    Zombie,
}

impl Classification {
    pub fn label(&self) -> &'static str {
        match self {
            Classification::Useful => "useful",
            Classification::UsefulBad => "useful_bad",
            Classification::Abandoned => "abandoned",
            Classification::Zombie => "zombie",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::{ClassScores, EvidenceTerm, PosteriorResult};

    fn make_posterior(
        useful: f64,
        useful_bad: f64,
        abandoned: f64,
        zombie: f64,
    ) -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores {
                useful,
                useful_bad,
                abandoned,
                zombie,
            },
            log_posterior: ClassScores::default(),
            log_odds_abandoned_useful: 0.0,
            evidence_terms: vec![],
        }
    }

    fn make_posterior_with_terms(
        useful: f64,
        abandoned: f64,
        terms: Vec<EvidenceTerm>,
    ) -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores {
                useful,
                useful_bad: 0.0,
                abandoned,
                zombie: 0.0,
            },
            log_posterior: ClassScores::default(),
            log_odds_abandoned_useful: 0.0,
            evidence_terms: terms,
        }
    }

    fn make_term(feature: &str, abandoned_ll: f64, useful_ll: f64) -> EvidenceTerm {
        EvidenceTerm {
            feature: feature.to_string(),
            log_likelihood: ClassScores {
                useful: useful_ll,
                useful_bad: 0.0,
                abandoned: abandoned_ll,
                zombie: 0.0,
            },
        }
    }

    // ── Classification ──────────────────────────────────────────────

    #[test]
    fn classification_label_useful() {
        assert_eq!(Classification::Useful.label(), "useful");
    }

    #[test]
    fn classification_label_useful_bad() {
        assert_eq!(Classification::UsefulBad.label(), "useful_bad");
    }

    #[test]
    fn classification_label_abandoned() {
        assert_eq!(Classification::Abandoned.label(), "abandoned");
    }

    #[test]
    fn classification_label_zombie() {
        assert_eq!(Classification::Zombie.label(), "zombie");
    }

    #[test]
    fn classification_serde_roundtrip() {
        for c in [
            Classification::Useful,
            Classification::UsefulBad,
            Classification::Abandoned,
            Classification::Zombie,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let back: Classification = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn classification_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&Classification::UsefulBad).unwrap(),
            r#""useful_bad""#
        );
        assert_eq!(
            serde_json::to_string(&Classification::Abandoned).unwrap(),
            r#""abandoned""#
        );
    }

    // ── Confidence ──────────────────────────────────────────────────

    #[test]
    fn confidence_label_values() {
        assert_eq!(Confidence::VeryHigh.label(), "very_high");
        assert_eq!(Confidence::High.label(), "high");
        assert_eq!(Confidence::Medium.label(), "medium");
        assert_eq!(Confidence::Low.label(), "low");
    }

    #[test]
    fn confidence_display() {
        assert_eq!(format!("{}", Confidence::VeryHigh), "very_high");
        assert_eq!(format!("{}", Confidence::High), "high");
        assert_eq!(format!("{}", Confidence::Medium), "medium");
        assert_eq!(format!("{}", Confidence::Low), "low");
    }

    #[test]
    fn confidence_serde_roundtrip() {
        for c in [
            Confidence::VeryHigh,
            Confidence::High,
            Confidence::Medium,
            Confidence::Low,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let back: Confidence = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn confidence_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&Confidence::VeryHigh).unwrap(),
            r#""very_high""#
        );
    }

    // ── Direction ───────────────────────────────────────────────────

    #[test]
    fn direction_display() {
        assert_eq!(
            format!("{}", Direction::TowardPredicted),
            "toward_predicted"
        );
        assert_eq!(
            format!("{}", Direction::TowardReference),
            "toward_reference"
        );
        assert_eq!(format!("{}", Direction::Neutral), "neutral");
    }

    #[test]
    fn direction_serde() {
        assert_eq!(
            serde_json::to_string(&Direction::TowardPredicted).unwrap(),
            r#""toward_predicted""#
        );
        assert_eq!(
            serde_json::to_string(&Direction::TowardReference).unwrap(),
            r#""toward_reference""#
        );
        assert_eq!(
            serde_json::to_string(&Direction::Neutral).unwrap(),
            r#""neutral""#
        );
    }

    // ── get_glyph / default_glyph_map ───────────────────────────────

    #[test]
    fn get_glyph_returns_known_glyphs() {
        assert_eq!(get_glyph("cpu"), '\u{1F4BB}');
        assert_eq!(get_glyph("runtime"), '\u{23F1}');
        assert_eq!(get_glyph("orphan"), '\u{1F47B}');
        assert_eq!(get_glyph("prior"), '\u{1F3B2}');
        // Unknown features still return '?'
        assert_eq!(get_glyph(""), '?');
        assert_eq!(get_glyph("unknown_feature"), '?');
    }

    #[test]
    fn default_glyph_map_contains_known_features() {
        let map = default_glyph_map();
        assert!(!map.is_empty());
        assert_eq!(map.get("cpu"), Some(&'\u{1F4BB}'));
        assert_eq!(map.get("runtime"), Some(&'\u{23F1}'));
        assert_eq!(map.get("orphan"), Some(&'\u{1F47B}'));
        assert!(!map.contains_key("unknown"));
    }

    // ── EvidenceLedger::from_posterior_result ─────────────────────────

    #[test]
    fn ledger_classifies_useful_highest() {
        let result = make_posterior(0.90, 0.05, 0.03, 0.02);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.classification, Classification::Useful);
    }

    #[test]
    fn ledger_classifies_abandoned_highest() {
        let result = make_posterior(0.05, 0.05, 0.85, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.classification, Classification::Abandoned);
    }

    #[test]
    fn ledger_classifies_zombie_highest() {
        let result = make_posterior(0.01, 0.01, 0.01, 0.97);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.classification, Classification::Zombie);
    }

    #[test]
    fn ledger_classifies_useful_bad_highest() {
        let result = make_posterior(0.10, 0.80, 0.05, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.classification, Classification::UsefulBad);
    }

    #[test]
    fn ledger_confidence_very_high() {
        let result = make_posterior(0.995, 0.002, 0.002, 0.001);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::VeryHigh);
    }

    #[test]
    fn ledger_confidence_high() {
        let result = make_posterior(0.97, 0.01, 0.01, 0.01);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::High);
    }

    #[test]
    fn ledger_confidence_medium() {
        let result = make_posterior(0.85, 0.05, 0.05, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::Medium);
    }

    #[test]
    fn ledger_confidence_low() {
        let result = make_posterior(0.40, 0.20, 0.30, 0.10);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::Low);
    }

    #[test]
    fn ledger_confidence_boundary_at_099() {
        let result = make_posterior(0.99, 0.005, 0.003, 0.002);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::High);
    }

    #[test]
    fn ledger_confidence_boundary_at_095() {
        let result = make_posterior(0.95, 0.02, 0.02, 0.01);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::Medium);
    }

    #[test]
    fn ledger_confidence_boundary_at_080() {
        let result = make_posterior(0.80, 0.10, 0.05, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.confidence, Confidence::Low);
    }

    #[test]
    fn ledger_why_summary_format() {
        let result = make_posterior(0.05, 0.05, 0.85, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert!(ledger.why_summary.contains("Abandoned"));
        assert!(ledger.why_summary.contains("medium"));
    }

    #[test]
    fn ledger_bayes_factors_from_terms() {
        let terms = vec![
            make_term("cpu", -2.0, -0.5),
            make_term("runtime", -0.1, -3.0),
        ];
        let result = make_posterior_with_terms(0.3, 0.7, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors.len(), 2);
    }

    #[test]
    fn ledger_bayes_factor_direction_abandoned() {
        let terms = vec![
            make_term("runtime", -0.1, -3.0), // log_bf = 2.9 > 0
        ];
        let result = make_posterior_with_terms(0.3, 0.7, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].direction, "supports abandoned");
    }

    #[test]
    fn ledger_bayes_factor_direction_useful() {
        let terms = vec![
            make_term("cpu", -3.0, -0.1), // log_bf = -2.9 < 0
        ];
        let result = make_posterior_with_terms(0.8, 0.2, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].direction, "supports useful");
    }

    #[test]
    fn ledger_bayes_factor_strength_decisive() {
        // |delta_bits| > 3.3
        let terms = vec![
            make_term("feature", 0.0, -5.0), // log_bf = 5.0, delta_bits ≈ 7.2
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].strength, "decisive");
    }

    #[test]
    fn ledger_bayes_factor_strength_strong() {
        // 2.0 < |delta_bits| <= 3.3
        let terms = vec![
            make_term("feature", 0.0, -1.8), // log_bf = 1.8, delta_bits ≈ 2.6
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].strength, "strong");
    }

    #[test]
    fn ledger_bayes_factor_strength_substantial() {
        // 1.0 < |delta_bits| <= 2.0
        let terms = vec![
            make_term("feature", 0.0, -1.0), // log_bf = 1.0, delta_bits ≈ 1.44
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].strength, "substantial");
    }

    #[test]
    fn ledger_bayes_factor_strength_weak() {
        // |delta_bits| <= 1.0
        let terms = vec![
            make_term("feature", 0.0, -0.5), // log_bf = 0.5, delta_bits ≈ 0.72
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].strength, "weak");
    }

    #[test]
    fn ledger_skips_negligible_terms() {
        let terms = vec![
            make_term("negligible", -1.0, -1.005), // |log_bf| = 0.005 < 0.01
            make_term("significant", 0.0, -2.0),
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors.len(), 1);
        assert_eq!(ledger.bayes_factors[0].feature, "significant");
    }

    #[test]
    fn ledger_bayes_factors_sorted_by_abs_delta_bits() {
        let terms = vec![
            make_term("small", 0.0, -0.5),
            make_term("large", 0.0, -5.0),
            make_term("medium", 0.0, -1.5),
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.bayes_factors[0].feature, "large");
        assert_eq!(ledger.bayes_factors[1].feature, "medium");
        assert_eq!(ledger.bayes_factors[2].feature, "small");
    }

    #[test]
    fn ledger_top_evidence_limited_to_3() {
        let terms = vec![
            make_term("a", 0.0, -1.0),
            make_term("b", 0.0, -2.0),
            make_term("c", 0.0, -3.0),
            make_term("d", 0.0, -4.0),
            make_term("e", 0.0, -5.0),
        ];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.top_evidence.len(), 3);
    }

    #[test]
    fn ledger_top_evidence_toward_abandoned() {
        let terms = vec![make_term("runtime", 0.0, -3.0)];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert!(ledger.top_evidence[0].contains("runtime"));
        assert!(ledger.top_evidence[0].contains("bits"));
        assert!(ledger.top_evidence[0].contains("toward abandoned"));
    }

    #[test]
    fn ledger_top_evidence_toward_useful() {
        let terms = vec![
            make_term("cpu", -3.0, 0.0), // log_bf < 0
        ];
        let result = make_posterior_with_terms(0.8, 0.2, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert!(ledger.top_evidence[0].contains("toward useful"));
    }

    #[test]
    fn ledger_empty_terms_gives_empty_bayes_factors() {
        let result = make_posterior(0.9, 0.05, 0.03, 0.02);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert!(ledger.bayes_factors.is_empty());
        assert!(ledger.top_evidence.is_empty());
    }

    #[test]
    fn ledger_evidence_glyphs_initially_empty() {
        let result = make_posterior(0.9, 0.05, 0.03, 0.02);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert!(ledger.evidence_glyphs.is_empty());
    }

    #[test]
    fn ledger_bf_is_exp_of_log_bf() {
        let terms = vec![make_term("test", 0.0, -2.0)];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        let entry = &ledger.bayes_factors[0];
        assert!((entry.bf - entry.log_bf.exp()).abs() < 1e-10);
    }

    #[test]
    fn ledger_delta_bits_is_log_bf_over_ln2() {
        let terms = vec![make_term("test", 0.0, -2.0)];
        let result = make_posterior_with_terms(0.1, 0.9, terms);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        let entry = &ledger.bayes_factors[0];
        let expected = entry.log_bf / std::f64::consts::LN_2;
        assert!((entry.delta_bits - expected).abs() < 1e-10);
    }

    #[test]
    fn ledger_posterior_cloned() {
        let result = make_posterior(0.5, 0.2, 0.2, 0.1);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        assert_eq!(ledger.posterior, result);
    }

    // ── BayesFactorEntry serde ──────────────────────────────────────

    #[test]
    fn bayes_factor_entry_serde_roundtrip() {
        let entry = BayesFactorEntry {
            feature: "runtime".to_string(),
            bf: 7.389,
            log_bf: 2.0,
            delta_bits: 2.885,
            direction: "supports abandoned".to_string(),
            strength: "strong".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: BayesFactorEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // ── EvidenceLedger serde ────────────────────────────────────────

    #[test]
    fn evidence_ledger_serde_roundtrip() {
        let result = make_posterior(0.1, 0.05, 0.8, 0.05);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: EvidenceLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger.classification, back.classification);
        assert_eq!(ledger.confidence, back.confidence);
    }

    // ── FeatureGlyph ────────────────────────────────────────────────

    #[test]
    fn feature_glyph_debug() {
        let fg = FeatureGlyph {
            feature: "cpu".to_string(),
            glyph: '?',
        };
        let dbg = format!("{:?}", fg);
        assert!(dbg.contains("cpu"));
    }
}
