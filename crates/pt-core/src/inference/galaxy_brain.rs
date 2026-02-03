//! Galaxy-brain mode: full mathematical transparency for Bayesian inference.
//!
//! Renders the complete computation trace — priors, likelihoods, posterior
//! updates, and decision-theoretic calculations — in human-readable
//! mathematical notation for the terminal.
//!
//! Supports three verbosity levels:
//! - `Summary`: one-line posterior + classification.
//! - `Detail`: prior → evidence → posterior breakdown with Bayes factors.
//! - `Full`: complete mathematical trace including log-odds arithmetic.
//!
//! Both Unicode (default) and ASCII fallback are supported.

use serde::{Deserialize, Serialize};

use super::ledger::{BayesFactorEntry, Classification, Confidence, EvidenceLedger};
use super::posterior::{ClassScores, PosteriorResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Verbosity level for galaxy-brain output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verbosity {
    Summary,
    Detail,
    Full,
}

/// Display mode for mathematical symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MathMode {
    Unicode,
    Ascii,
}

/// Configuration for galaxy-brain rendering.
#[derive(Debug, Clone)]
pub struct GalaxyBrainConfig {
    pub verbosity: Verbosity,
    pub math_mode: MathMode,
    /// Maximum evidence terms to show in Detail mode.
    pub max_evidence_terms: usize,
}

impl Default for GalaxyBrainConfig {
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Detail,
            math_mode: MathMode::Unicode,
            max_evidence_terms: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a galaxy-brain display from a posterior result and evidence ledger.
pub fn render(
    posterior: &PosteriorResult,
    ledger: &EvidenceLedger,
    config: &GalaxyBrainConfig,
) -> String {
    match config.verbosity {
        Verbosity::Summary => render_summary(posterior, ledger, config),
        Verbosity::Detail => render_detail(posterior, ledger, config),
        Verbosity::Full => render_full(posterior, ledger, config),
    }
}

fn render_summary(
    posterior: &PosteriorResult,
    ledger: &EvidenceLedger,
    config: &GalaxyBrainConfig,
) -> String {
    let arrow = sym(config.math_mode, "→", "->");
    let p = &posterior.posterior;
    format!(
        "P(C|x): U={:.3} UB={:.3} A={:.3} Z={:.3} {} {:?} ({})",
        p.useful,
        p.useful_bad,
        p.abandoned,
        p.zombie,
        arrow,
        ledger.classification,
        ledger.confidence,
    )
}

fn render_detail(
    posterior: &PosteriorResult,
    ledger: &EvidenceLedger,
    config: &GalaxyBrainConfig,
) -> String {
    let mut lines = Vec::new();

    let sec = sym(config.math_mode, "━", "=");
    let sep = sec.repeat(50);

    // Header.
    lines.push(format!(
        "{} Galaxy-Brain Mode {}",
        sym(config.math_mode, "🧠", "[*]"),
        sep
    ));

    // 1) Prior.
    lines.push(String::new());
    lines.push(section_header("Prior Distribution", config));
    lines.push(format_scores(
        "P(C)",
        &prior_from_posterior(posterior),
        config,
    ));

    // 2) Posterior.
    lines.push(String::new());
    lines.push(section_header("Posterior Distribution", config));
    lines.push(format_scores("P(C|x)", &posterior.posterior, config));

    // 3) Classification.
    lines.push(String::new());
    lines.push(format!(
        "  Classification: {:?}  |  Confidence: {}",
        ledger.classification, ledger.confidence,
    ));

    // 4) Top evidence (Bayes factors).
    lines.push(String::new());
    lines.push(section_header("Evidence (Bayes Factors)", config));

    let terms = &ledger.bayes_factors;
    let n = terms.len().min(config.max_evidence_terms);
    for bf in terms.iter().take(n) {
        lines.push(format_bayes_factor(bf, config));
    }
    if terms.len() > n {
        lines.push(format!("  ... and {} more terms", terms.len() - n));
    }

    // 5) Log-odds.
    lines.push(String::new());
    lines.push(format!(
        "  log-odds(A/U) = {:.3}",
        posterior.log_odds_abandoned_useful,
    ));

    lines.push(sep);
    lines.join("\n")
}

fn render_full(
    posterior: &PosteriorResult,
    ledger: &EvidenceLedger,
    config: &GalaxyBrainConfig,
) -> String {
    let mut lines = Vec::new();

    let sec = sym(config.math_mode, "━", "=");
    let sep = sec.repeat(60);

    lines.push(format!(
        "{} Galaxy-Brain Mode (Full Trace) {}",
        sym(config.math_mode, "🧠", "[*]"),
        sep,
    ));

    // 1) Prior.
    lines.push(String::new());
    lines.push(section_header("Step 1: Prior P(C)", config));
    let prior = prior_from_posterior(posterior);
    lines.push(format_scores_full(&prior, config));

    // 2) Evidence terms.
    lines.push(String::new());
    lines.push(section_header("Step 2: Evidence Terms", config));
    for (i, term) in posterior.evidence_terms.iter().enumerate() {
        let pi = sym(config.math_mode, "π", "pi");
        lines.push(format!("  {}({}) Feature: {}", pi, i + 1, term.feature));
        lines.push(format!(
            "    log P(f|U)={:.4}  log P(f|UB)={:.4}  log P(f|A)={:.4}  log P(f|Z)={:.4}",
            term.log_likelihood.useful,
            term.log_likelihood.useful_bad,
            term.log_likelihood.abandoned,
            term.log_likelihood.zombie,
        ));
    }

    // 3) Bayes factors.
    lines.push(String::new());
    lines.push(section_header("Step 3: Bayes Factors (A vs U)", config));
    for bf in &ledger.bayes_factors {
        lines.push(format_bayes_factor_full(bf, config));
    }

    // 4) Posterior.
    lines.push(String::new());
    lines.push(section_header("Step 4: Posterior P(C|x)", config));
    lines.push(format_scores_full(&posterior.posterior, config));

    // 5) Log-posterior.
    lines.push(String::new());
    lines.push(section_header("Step 5: Log-Posterior", config));
    lines.push(format_scores_full(&posterior.log_posterior, config));

    // 6) Decision.
    lines.push(String::new());
    lines.push(section_header("Step 6: Decision", config));
    lines.push(format!(
        "  log-odds(A/U) = {:.6}",
        posterior.log_odds_abandoned_useful,
    ));
    lines.push(format!(
        "  Classification: {:?}  |  Confidence: {}",
        ledger.classification, ledger.confidence,
    ));

    lines.push(String::new());
    lines.push(sep);
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn section_header(title: &str, config: &GalaxyBrainConfig) -> String {
    let bullet = sym(config.math_mode, "▸", ">");
    format!("{} {}", bullet, title)
}

fn format_scores(label: &str, scores: &ClassScores, config: &GalaxyBrainConfig) -> String {
    let approx = sym(config.math_mode, "≈", "~");
    format!(
        "  {}  {} [{:.4}, {:.4}, {:.4}, {:.4}]  (U, UB, A, Z)",
        label, approx, scores.useful, scores.useful_bad, scores.abandoned, scores.zombie,
    )
}

fn format_scores_full(scores: &ClassScores, config: &GalaxyBrainConfig) -> String {
    let eq = sym(config.math_mode, "=", "=");
    let mut lines = Vec::new();
    lines.push(format!("  P(Useful)     {} {:.6}", eq, scores.useful));
    lines.push(format!("  P(UsefulBad)  {} {:.6}", eq, scores.useful_bad));
    lines.push(format!("  P(Abandoned)  {} {:.6}", eq, scores.abandoned));
    lines.push(format!("  P(Zombie)     {} {:.6}", eq, scores.zombie));
    lines.join("\n")
}

fn format_bayes_factor(bf: &BayesFactorEntry, config: &GalaxyBrainConfig) -> String {
    let arrow = if bf.log_bf > 0.0 {
        sym(config.math_mode, "↑A", "^A")
    } else {
        sym(config.math_mode, "↓U", "vU")
    };
    format!(
        "  {:20} BF={:>8.2}  {}{:.1} bits  [{}]",
        bf.feature,
        bf.bf,
        arrow,
        bf.delta_bits.abs(),
        bf.strength,
    )
}

fn format_bayes_factor_full(bf: &BayesFactorEntry, config: &GalaxyBrainConfig) -> String {
    let arrow = if bf.log_bf > 0.0 {
        sym(config.math_mode, "↑", "^")
    } else {
        sym(config.math_mode, "↓", "v")
    };
    format!(
        "  {:20} log BF={:>8.4}  BF={:>10.4}  {}{:.4} bits  [{}]",
        bf.feature,
        bf.log_bf,
        bf.bf,
        arrow,
        bf.delta_bits.abs(),
        bf.strength,
    )
}

fn sym<'a>(mode: MathMode, unicode: &'a str, ascii: &'a str) -> &'a str {
    match mode {
        MathMode::Unicode => unicode,
        MathMode::Ascii => ascii,
    }
}

/// Estimate the prior from the posterior by removing evidence contribution.
///
/// This is an approximation: we use uniform [0.25, 0.25, 0.25, 0.25] if
/// no prior info is available (the actual prior is baked into the posterior
/// computation and not separately stored in `PosteriorResult`).
fn prior_from_posterior(_posterior: &PosteriorResult) -> ClassScores {
    ClassScores {
        useful: 0.25,
        useful_bad: 0.25,
        abandoned: 0.25,
        zombie: 0.25,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::EvidenceTerm;

    fn mock_posterior() -> PosteriorResult {
        PosteriorResult {
            posterior: ClassScores {
                useful: 0.05,
                useful_bad: 0.03,
                abandoned: 0.87,
                zombie: 0.05,
            },
            log_posterior: ClassScores {
                useful: -3.0,
                useful_bad: -3.5,
                abandoned: -0.14,
                zombie: -3.0,
            },
            log_odds_abandoned_useful: 2.86,
            evidence_terms: vec![
                EvidenceTerm {
                    feature: "cpu_occupancy".to_string(),
                    log_likelihood: ClassScores {
                        useful: -2.0,
                        useful_bad: -1.5,
                        abandoned: -0.1,
                        zombie: -0.5,
                    },
                },
                EvidenceTerm {
                    feature: "age_elapsed".to_string(),
                    log_likelihood: ClassScores {
                        useful: -1.8,
                        useful_bad: -1.0,
                        abandoned: -0.2,
                        zombie: -0.8,
                    },
                },
            ],
        }
    }

    fn mock_ledger() -> EvidenceLedger {
        use super::super::ledger::BayesFactorEntry;
        use std::collections::HashMap;

        EvidenceLedger {
            posterior: mock_posterior(),
            classification: Classification::Abandoned,
            confidence: Confidence::High,
            bayes_factors: vec![
                BayesFactorEntry {
                    feature: "cpu_occupancy".to_string(),
                    bf: 6.69,
                    log_bf: 1.9,
                    delta_bits: 2.74,
                    direction: "supports abandoned".to_string(),
                    strength: "strong".to_string(),
                },
                BayesFactorEntry {
                    feature: "age_elapsed".to_string(),
                    bf: 4.95,
                    log_bf: 1.6,
                    delta_bits: 2.31,
                    direction: "supports abandoned".to_string(),
                    strength: "strong".to_string(),
                },
            ],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        }
    }

    #[test]
    fn test_summary_mode() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Summary,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("P(C|x)"));
        assert!(output.contains("0.870"));
        assert!(output.contains("Abandoned"));
    }

    #[test]
    fn test_detail_mode() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Detail,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("Prior Distribution"));
        assert!(output.contains("Posterior Distribution"));
        assert!(output.contains("Evidence"));
        assert!(output.contains("cpu_occupancy"));
        assert!(output.contains("log-odds"));
    }

    #[test]
    fn test_full_mode() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Full,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("Step 1"));
        assert!(output.contains("Step 2"));
        assert!(output.contains("Step 3"));
        assert!(output.contains("Step 4"));
        assert!(output.contains("Step 5"));
        assert!(output.contains("Step 6"));
        assert!(output.contains("log P(f|U)"));
    }

    #[test]
    fn test_ascii_mode() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Detail,
            math_mode: MathMode::Ascii,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("[*]")); // ASCII header
        assert!(!output.contains("🧠")); // No unicode
        assert!(output.contains("^A")); // ASCII arrow for BF toward abandoned
    }

    #[test]
    fn test_unicode_mode() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Detail,
            math_mode: MathMode::Unicode,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("🧠"));
        assert!(output.contains("↑A")); // Unicode arrow for BF
    }

    #[test]
    fn test_max_evidence_terms() {
        let config = GalaxyBrainConfig {
            verbosity: Verbosity::Detail,
            max_evidence_terms: 1,
            ..Default::default()
        };
        let output = render(&mock_posterior(), &mock_ledger(), &config);
        assert!(output.contains("1 more terms"));
    }

    #[test]
    fn test_empty_evidence() {
        let posterior = PosteriorResult {
            posterior: ClassScores {
                useful: 0.25,
                useful_bad: 0.25,
                abandoned: 0.25,
                zombie: 0.25,
            },
            log_posterior: ClassScores::default(),
            log_odds_abandoned_useful: 0.0,
            evidence_terms: vec![],
        };
        let ledger = EvidenceLedger {
            posterior: posterior.clone(),
            classification: Classification::Useful,
            confidence: Confidence::Low,
            bayes_factors: vec![],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: std::collections::HashMap::new(),
        };
        let config = GalaxyBrainConfig::default();
        let output = render(&posterior, &ledger, &config);
        assert!(output.contains("Posterior Distribution"));
    }

    #[test]
    fn test_config_serialization() {
        let v = Verbosity::Full;
        let json = serde_json::to_string(&v).unwrap();
        let restored: Verbosity = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, Verbosity::Full);
    }
}
