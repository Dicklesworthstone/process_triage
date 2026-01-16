//! Evidence ledger for explainability.
//!
//! Provides structures and helpers for human-readable evidence summaries
//! and Bayes factor breakdowns.

use super::posterior::PosteriorResult;
use crate::collect::ProcessRecord;
use crate::config::priors::Priors;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BayesFactorEntry {
    pub feature: String,
    pub bf: f64,
    pub log_bf: f64,
    pub delta_bits: f64,
    pub direction: String,
    pub strength: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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

        Self {
            posterior: result.clone(),
            classification,
            confidence,
            bayes_factors: vec![],
            top_evidence: vec![],
            why_summary: summary,
            evidence_glyphs: HashMap::new(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

pub fn get_glyph(_feature: &str) -> char {
    '?'
}

pub fn default_glyph_map() -> std::collections::HashMap<String, char> {
    std::collections::HashMap::new()
}

pub fn build_process_explanation(
    proc: &ProcessRecord,
    priors: &Priors,
) -> serde_json::Value {
    // 1. Convert ProcessRecord to Evidence
    // This requires mapping logic which is likely in decision/mod.rs or inference/mod.rs
    // For now, we'll construct minimal evidence based on the record
    use crate::inference::{compute_posterior, CpuEvidence, Evidence};

    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction {
            occupancy: proc.cpu_percent / 100.0,
        }),
        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
        orphan: Some(proc.ppid.0 == 1),
        tty: Some(proc.tty.is_some()),
        // Other fields would come from deep scan if available
        net: None,
        io_active: None,
        state_flag: None,       // Needs state mapping
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

    // 4. Calculate Bayes Factors (simplified for now)
    let bfs: Vec<BayesFactorEntry> = vec![]; // TODO: Implement per-feature BF calculation

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
    serde_json::json!({
        "cpu_occupancy": match evidence.cpu {
            Some(crate::inference::CpuEvidence::Fraction { occupancy }) => Some(occupancy),
            _ => None
        },
        "runtime_seconds": evidence.runtime_seconds,
        "orphan": evidence.orphan,
        "tty": evidence.tty,
    })
}

// Re-export Classification if needed by other modules
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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