//! Signature-informed inference fast path.
//!
//! This module implements a fast-path classification bypass for processes
//! that match high-confidence signatures. When a signature match score
//! exceeds the configured threshold and the signature has explicit priors,
//! we can skip full Bayesian inference and use the signature's classification
//! directly.
//!
//! # Why Fast-Path?
//!
//! Full Bayesian inference is computationally expensive. For well-known
//! process patterns (like Jest workers, VS Code language servers, etc.),
//! we can achieve high-confidence classification directly from signature
//! matching, reducing latency and resource usage.
//!
//! # Safety Considerations
//!
//! - Fast-path only applies when signature match score >= threshold (default 0.9)
//! - Fast-path only applies when signature has explicit classification priors
//! - Fast-path can be disabled via configuration
//! - All fast-path decisions are logged in the evidence ledger for auditability

use crate::inference::ledger::{BayesFactorEntry, Classification, Confidence, EvidenceLedger};
use crate::inference::posterior::{ClassScores, PosteriorResult};
use crate::supervision::signature::{SignatureMatch, SignaturePriors};
use serde::{Deserialize, Serialize};

/// Configuration for the signature fast-path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPathConfig {
    /// Whether fast-path is enabled (default: true).
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Minimum signature match score to trigger fast-path (default: 0.9).
    /// Score must be >= this threshold.
    #[serde(default = "default_threshold")]
    pub min_confidence_threshold: f64,

    /// Whether signature must have explicit priors to trigger fast-path (default: true).
    /// When true, signatures without classification priors fall through to full inference.
    #[serde(default = "default_require_priors")]
    pub require_explicit_priors: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_threshold() -> f64 {
    0.9
}

fn default_require_priors() -> bool {
    true
}

impl Default for FastPathConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_confidence_threshold: default_threshold(),
            require_explicit_priors: default_require_priors(),
        }
    }
}

impl FastPathConfig {
    /// Create a disabled fast-path config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create a fast-path config with custom threshold.
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            min_confidence_threshold: threshold,
            ..Default::default()
        }
    }
}

/// Result of fast-path classification.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FastPathResult {
    /// Classification from signature.
    pub classification: Classification,

    /// Confidence level of the classification.
    pub confidence: Confidence,

    /// Posterior probabilities derived from signature priors.
    pub posterior: PosteriorResult,

    /// Name of the matched signature.
    pub signature_name: String,

    /// Match score that triggered fast-path.
    pub match_score: f64,

    /// Evidence ledger explaining the fast-path decision.
    pub ledger: EvidenceLedger,

    /// Indicates that full inference was bypassed.
    pub bypassed_inference: bool,
}

/// Reason why fast-path was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPathSkipReason {
    /// Fast-path is disabled in configuration.
    Disabled,
    /// No signature match provided.
    NoMatch,
    /// Match score below threshold.
    ScoreBelowThreshold,
    /// Signature has no explicit priors.
    NoPriors,
}

/// Attempt to use signature fast-path for classification.
///
/// Returns `Some(FastPathResult)` if fast-path conditions are met,
/// or `None` if full inference should be used instead.
///
/// # Arguments
///
/// * `config` - Fast-path configuration
/// * `signature_match` - Optional signature match result
/// * `pid` - Process ID (for logging)
///
/// # Returns
///
/// * `Ok(Some(result))` - Fast-path succeeded, use this classification
/// * `Ok(None)` - Fast-path conditions not met, use full inference
pub fn try_signature_fast_path(
    config: &FastPathConfig,
    signature_match: Option<&SignatureMatch<'_>>,
    pid: u32,
) -> Result<Option<FastPathResult>, FastPathSkipReason> {
    // Check if fast-path is enabled
    if !config.enabled {
        return Err(FastPathSkipReason::Disabled);
    }

    // Check if we have a signature match
    let sig_match = match signature_match {
        Some(m) => m,
        None => return Err(FastPathSkipReason::NoMatch),
    };

    // Check match score against threshold
    if sig_match.score < config.min_confidence_threshold {
        return Err(FastPathSkipReason::ScoreBelowThreshold);
    }

    // Check if signature has explicit priors
    let sig_priors = &sig_match.signature.priors;
    if config.require_explicit_priors && sig_priors.is_empty() {
        return Err(FastPathSkipReason::NoPriors);
    }

    // Fast-path conditions met - derive classification from signature priors
    let (classification, posterior) = derive_classification_from_priors(sig_priors);
    let prob = match classification {
        Classification::Abandoned => posterior.abandoned,
        Classification::Useful => posterior.useful,
        Classification::UsefulBad => posterior.useful_bad,
        Classification::Zombie => posterior.zombie,
    };

    let confidence = prob_to_confidence(prob);

    // Build evidence ledger for fast-path
    let ledger = build_fast_path_ledger(
        sig_match.signature.name.as_str(),
        sig_match.score,
        classification,
        confidence,
        &posterior,
        pid,
    );

    // Compute log posteriors from normalized probabilities
    let log_posterior = ClassScores {
        useful: posterior.useful.ln(),
        useful_bad: posterior.useful_bad.ln(),
        abandoned: posterior.abandoned.ln(),
        zombie: posterior.zombie.ln(),
    };
    let log_odds = log_posterior.abandoned - log_posterior.useful;

    Ok(Some(FastPathResult {
        classification,
        confidence,
        posterior: PosteriorResult {
            posterior,
            log_posterior,
            log_odds_abandoned_useful: log_odds,
            evidence_terms: vec![], // No Bayesian evidence computation
        },
        signature_name: sig_match.signature.name.clone(),
        match_score: sig_match.score,
        ledger,
        bypassed_inference: true,
    }))
}

/// Derive classification and posterior from signature priors.
fn derive_classification_from_priors(priors: &SignaturePriors) -> (Classification, ClassScores) {
    // Convert Beta priors to probabilities (using mean)
    let useful_prob = priors.useful.as_ref().map_or(0.25, |b| b.mean());
    let useful_bad_prob = priors.useful_bad.as_ref().map_or(0.25, |b| b.mean());
    let abandoned_prob = priors.abandoned.as_ref().map_or(0.25, |b| b.mean());
    let zombie_prob = priors.zombie.as_ref().map_or(0.25, |b| b.mean());

    // Normalize probabilities to sum to 1.0
    let total = useful_prob + useful_bad_prob + abandoned_prob + zombie_prob;
    let posterior = ClassScores {
        useful: useful_prob / total,
        useful_bad: useful_bad_prob / total,
        abandoned: abandoned_prob / total,
        zombie: zombie_prob / total,
    };

    // Determine classification from highest probability
    let classification = if posterior.zombie > posterior.abandoned
        && posterior.zombie > posterior.useful
        && posterior.zombie > posterior.useful_bad
    {
        Classification::Zombie
    } else if posterior.abandoned > posterior.useful && posterior.abandoned > posterior.useful_bad {
        Classification::Abandoned
    } else if posterior.useful_bad > posterior.useful {
        Classification::UsefulBad
    } else {
        Classification::Useful
    };

    (classification, posterior)
}

/// Convert probability to confidence level.
fn prob_to_confidence(prob: f64) -> Confidence {
    if prob > 0.99 {
        Confidence::VeryHigh
    } else if prob > 0.95 {
        Confidence::High
    } else if prob > 0.80 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Build an evidence ledger explaining the fast-path decision.
fn build_fast_path_ledger(
    signature_name: &str,
    match_score: f64,
    classification: Classification,
    confidence: Confidence,
    posterior: &ClassScores,
    _pid: u32,
) -> EvidenceLedger {
    let why_summary = format!(
        "Fast-path classification: matched signature '{}' with score {:.2}. \
         Classified as {:?} with {} confidence. \
         Full Bayesian inference was bypassed.",
        signature_name, match_score, classification, confidence
    );

    let mut evidence_glyphs = std::collections::HashMap::new();
    evidence_glyphs.insert("signature_match".to_string(), "\u{1F50D}".to_string()); // magnifying glass
    evidence_glyphs.insert("fast_path".to_string(), "\u{26A1}".to_string()); // lightning bolt

    // Compute log posteriors for the ledger
    let log_posterior = ClassScores {
        useful: posterior.useful.ln(),
        useful_bad: posterior.useful_bad.ln(),
        abandoned: posterior.abandoned.ln(),
        zombie: posterior.zombie.ln(),
    };
    let log_odds = log_posterior.abandoned - log_posterior.useful;

    EvidenceLedger {
        posterior: PosteriorResult {
            posterior: posterior.clone(),
            log_posterior,
            log_odds_abandoned_useful: log_odds,
            evidence_terms: vec![],
        },
        classification,
        confidence,
        bayes_factors: vec![
            BayesFactorEntry {
                feature: "signature_match".to_string(),
                bf: 1.0,
                log_bf: 0.0,
                delta_bits: 0.0,
                direction: "fast_path".to_string(),
                strength: format!("Matched '{}' (score={:.2})", signature_name, match_score),
            },
        ],
        top_evidence: vec![
            format!("Signature match: {} (score={:.2})", signature_name, match_score),
            "Fast-path classification used".to_string(),
        ],
        why_summary,
        evidence_glyphs,
    }
}

/// Check if fast-path can potentially apply (quick pre-check).
///
/// This is a lightweight check that can be used to decide whether to
/// even attempt signature matching. If fast-path is disabled, there's
/// no benefit to matching signatures just for fast-path purposes.
pub fn fast_path_potentially_applicable(config: &FastPathConfig) -> bool {
    config.enabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervision::signature::{
        MatchDetails, MatchLevel, SignaturePatterns, SupervisorSignature,
    };
    use crate::supervision::SupervisorCategory;
    use crate::config::priors::BetaParams;

    fn make_test_signature(name: &str, priors: SignaturePriors) -> SupervisorSignature {
        SupervisorSignature {
            name: name.to_string(),
            category: SupervisorCategory::Agent,
            patterns: SignaturePatterns::default(),
            confidence_weight: 0.95,
            notes: None,
            builtin: false,
            priors,
            expectations: Default::default(),
            priority: 100,
        }
    }

    #[test]
    fn test_fast_path_disabled() {
        let config = FastPathConfig::disabled();
        let result = try_signature_fast_path(&config, None, 1234);
        assert!(matches!(result, Err(FastPathSkipReason::Disabled)));
    }

    #[test]
    fn test_fast_path_no_match() {
        let config = FastPathConfig::default();
        let result = try_signature_fast_path(&config, None, 1234);
        assert!(matches!(result, Err(FastPathSkipReason::NoMatch)));
    }

    #[test]
    fn test_fast_path_score_below_threshold() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "test-sig",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        // CommandOnly has base score 0.5, * 0.95 confidence = 0.475
        let sig_match = SignatureMatch::new(&sig, MatchLevel::CommandOnly, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(matches!(result, Err(FastPathSkipReason::ScoreBelowThreshold)));
    }

    #[test]
    fn test_fast_path_no_priors() {
        let config = FastPathConfig::default();
        let sig = make_test_signature("test-sig", SignaturePriors::default());
        let details = MatchDetails::default();
        // MultiPattern has base score 0.95, * 0.95 confidence = 0.9025
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(matches!(result, Err(FastPathSkipReason::NoPriors)));
    }

    #[test]
    fn test_fast_path_success() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "jest-worker",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)), // 80% abandoned
                useful: Some(BetaParams::new(2.0, 8.0)),    // 20% useful
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        // MultiPattern has base score 0.95, * 0.95 confidence = 0.9025
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(result.is_ok());

        let fast_path = result.unwrap();
        assert!(fast_path.is_some());

        let fast_path = fast_path.unwrap();
        assert_eq!(fast_path.signature_name, "jest-worker");
        assert_eq!(fast_path.classification, Classification::Abandoned);
        assert!(fast_path.bypassed_inference);
        assert!(fast_path.match_score >= 0.9);
    }

    #[test]
    fn test_fast_path_with_custom_threshold() {
        let config = FastPathConfig::with_threshold(0.8);
        let sig = make_test_signature(
            "test-sig",
            SignaturePriors {
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        // ExactCommand has base score 0.85, * 0.95 confidence = 0.8075
        let sig_match = SignatureMatch::new(&sig, MatchLevel::ExactCommand, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_derive_classification_abandoned() {
        let priors = SignaturePriors {
            abandoned: Some(BetaParams::new(9.0, 1.0)), // 90% abandoned
            useful: Some(BetaParams::new(1.0, 9.0)),   // 10% useful
            ..Default::default()
        };

        let (classification, _) = derive_classification_from_priors(&priors);
        assert_eq!(classification, Classification::Abandoned);
    }

    #[test]
    fn test_derive_classification_useful() {
        let priors = SignaturePriors {
            abandoned: Some(BetaParams::new(1.0, 9.0)), // 10% abandoned
            useful: Some(BetaParams::new(9.0, 1.0)),   // 90% useful
            ..Default::default()
        };

        let (classification, _) = derive_classification_from_priors(&priors);
        assert_eq!(classification, Classification::Useful);
    }

    #[test]
    fn test_prob_to_confidence() {
        assert_eq!(prob_to_confidence(0.995), Confidence::VeryHigh);
        assert_eq!(prob_to_confidence(0.96), Confidence::High);
        assert_eq!(prob_to_confidence(0.85), Confidence::Medium);
        assert_eq!(prob_to_confidence(0.7), Confidence::Low);
    }

    #[test]
    fn test_ledger_has_signature_info() {
        let config = FastPathConfig::default();
        let sig = make_test_signature(
            "vscode-server",
            SignaturePriors {
                useful: Some(BetaParams::new(9.0, 1.0)),
                abandoned: Some(BetaParams::new(1.0, 9.0)),
                ..Default::default()
            },
        );
        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&sig, MatchLevel::MultiPattern, details);

        let result = try_signature_fast_path(&config, Some(&sig_match), 1234).unwrap().unwrap();

        // Check ledger contains signature information
        assert!(result.ledger.why_summary.contains("vscode-server"));
        assert!(result.ledger.why_summary.contains("Fast-path"));
        assert!(result.ledger.top_evidence.iter().any(|e| e.contains("vscode-server")));
    }
}
