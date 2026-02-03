//! Confidence and uncertainty visualization for decisions.
//!
//! Maps numeric posterior summaries, expected loss values, and robustness
//! gate statuses to discrete badge/indicator states for display in the
//! TUI or agent output. Separates belief (posterior), decision (expected
//! loss), and permission (gates) into independent visual channels.

use serde::{Deserialize, Serialize};

use super::ledger::{Classification, Confidence, EvidenceLedger};

// ---------------------------------------------------------------------------
// Badge types
// ---------------------------------------------------------------------------

/// Safety badge indicating overall recommendation risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyBadge {
    Safe,
    Caution,
    Danger,
}

impl SafetyBadge {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Caution => "CAUTION",
            Self::Danger => "DANGER",
        }
    }

    pub fn glyph(&self) -> &'static str {
        match self {
            Self::Safe => "✓",
            Self::Caution => "⚠",
            Self::Danger => "✗",
        }
    }
}

/// Confidence badge for posterior concentration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfidenceBadge {
    High,
    Med,
    Low,
}

impl ConfidenceBadge {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Med => "MED",
            Self::Low => "LOW",
        }
    }
}

/// Calibration status indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationStatus {
    /// Model is in a calibrated regime.
    Calibrated,
    /// Outside calibrated regime — exercise caution.
    Uncalibrated,
    /// No calibration data available.
    Unknown,
}

/// Robustness gate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// All gates passed.
    Clear,
    /// Some gates raised warnings.
    Warning,
    /// Gates are blocking the recommendation.
    Blocked,
}

// ---------------------------------------------------------------------------
// Evidence contribution summary
// ---------------------------------------------------------------------------

/// Top evidence contributor for visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceContributor {
    pub feature: String,
    pub bits: f64,
    pub direction: String,
}

// ---------------------------------------------------------------------------
// Decision visualisation composite
// ---------------------------------------------------------------------------

/// Input parameters for computing the confidence visualization.
#[derive(Debug, Clone, Default)]
pub struct ConfidenceVizInput {
    /// Top-class posterior probability.
    pub top_posterior: f64,
    /// Confidence from ledger.
    pub confidence: Option<Confidence>,
    /// Whether the decision is knife-edge (sensitive to small changes).
    pub knife_edge: bool,
    /// Calibration status for this host/profile.
    pub calibration: CalibrationStatus,
    /// Robustness gate status.
    pub gate_status: GateStatus,
    /// Expected losses for each action (if available).
    pub expected_losses: Option<ExpectedLosses>,
}

impl Default for CalibrationStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl Default for GateStatus {
    fn default() -> Self {
        Self::Clear
    }
}

/// Expected loss values for possible actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedLosses {
    pub keep: f64,
    pub pause: f64,
    pub kill: f64,
}

/// Complete confidence visualization output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceViz {
    /// Overall safety badge.
    pub safety: SafetyBadge,
    /// Posterior confidence badge.
    pub confidence: ConfidenceBadge,
    /// Calibration indicator.
    pub calibration: CalibrationStatus,
    /// Gate status.
    pub gates: GateStatus,
    /// Top evidence contributors.
    pub top_evidence: Vec<EvidenceContributor>,
    /// Human-readable status line.
    pub status_line: String,
    /// Whether the decision is knife-edge.
    pub knife_edge: bool,
}

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

/// Compute confidence visualization from a ledger and optional input parameters.
pub fn compute_confidence_viz(
    ledger: &EvidenceLedger,
    input: &ConfidenceVizInput,
) -> ConfidenceViz {
    let confidence_badge = compute_confidence_badge(input);
    let safety_badge = compute_safety_badge(input, confidence_badge);

    let top_evidence: Vec<EvidenceContributor> = ledger
        .bayes_factors
        .iter()
        .take(3)
        .map(|bf| EvidenceContributor {
            feature: bf.feature.clone(),
            bits: bf.delta_bits,
            direction: bf.direction.clone(),
        })
        .collect();

    let status_line =
        build_status_line(safety_badge, confidence_badge, input, ledger.classification);

    ConfidenceViz {
        safety: safety_badge,
        confidence: confidence_badge,
        calibration: input.calibration,
        gates: input.gate_status,
        top_evidence,
        status_line,
        knife_edge: input.knife_edge,
    }
}

fn compute_confidence_badge(input: &ConfidenceVizInput) -> ConfidenceBadge {
    // Use the ledger confidence if available, else derive from posterior.
    if let Some(conf) = input.confidence {
        return match conf {
            Confidence::VeryHigh | Confidence::High => ConfidenceBadge::High,
            Confidence::Medium => ConfidenceBadge::Med,
            Confidence::Low => ConfidenceBadge::Low,
        };
    }

    if input.top_posterior > 0.95 {
        ConfidenceBadge::High
    } else if input.top_posterior > 0.80 {
        ConfidenceBadge::Med
    } else {
        ConfidenceBadge::Low
    }
}

fn compute_safety_badge(input: &ConfidenceVizInput, confidence: ConfidenceBadge) -> SafetyBadge {
    // Gates override everything.
    if input.gate_status == GateStatus::Blocked {
        return SafetyBadge::Danger;
    }

    // Knife-edge decisions are always cautionary.
    if input.knife_edge {
        return SafetyBadge::Caution;
    }

    // Uncalibrated models get a caution.
    if input.calibration == CalibrationStatus::Uncalibrated {
        return SafetyBadge::Caution;
    }

    // Gate warnings + low confidence → caution.
    if input.gate_status == GateStatus::Warning || confidence == ConfidenceBadge::Low {
        return SafetyBadge::Caution;
    }

    SafetyBadge::Safe
}

fn build_status_line(
    safety: SafetyBadge,
    confidence: ConfidenceBadge,
    input: &ConfidenceVizInput,
    classification: Classification,
) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "{} {:?} (P={:.0}%)",
        safety.glyph(),
        classification,
        input.top_posterior * 100.0,
    ));

    parts.push(format!("Confidence: {}", confidence.label()));

    if let Some(ref losses) = input.expected_losses {
        parts.push(format!(
            "E[loss]: keep={:.1} pause={:.1} kill={:.1}",
            losses.keep, losses.pause, losses.kill,
        ));
    }

    if input.knife_edge {
        parts.push("⚠ knife-edge".to_string());
    }

    match input.calibration {
        CalibrationStatus::Uncalibrated => parts.push("⚠ uncalibrated".to_string()),
        CalibrationStatus::Unknown => parts.push("calibration: n/a".to_string()),
        CalibrationStatus::Calibrated => {}
    }

    if input.gate_status == GateStatus::Warning {
        parts.push("gates: warning".to_string());
    } else if input.gate_status == GateStatus::Blocked {
        parts.push("gates: BLOCKED".to_string());
    }

    parts.join("  |  ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::ledger::BayesFactorEntry;
    use crate::inference::posterior::{ClassScores, PosteriorResult};
    use std::collections::HashMap;

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
    fn test_safe_high_confidence() {
        let input = ConfidenceVizInput {
            top_posterior: 0.87,
            confidence: Some(Confidence::High),
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert_eq!(viz.safety, SafetyBadge::Safe);
        assert_eq!(viz.confidence, ConfidenceBadge::High);
        assert!(!viz.knife_edge);
    }

    #[test]
    fn test_caution_low_confidence() {
        let input = ConfidenceVizInput {
            top_posterior: 0.55,
            confidence: Some(Confidence::Low),
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert_eq!(viz.safety, SafetyBadge::Caution);
        assert_eq!(viz.confidence, ConfidenceBadge::Low);
    }

    #[test]
    fn test_danger_gates_blocked() {
        let input = ConfidenceVizInput {
            top_posterior: 0.99,
            confidence: Some(Confidence::VeryHigh),
            gate_status: GateStatus::Blocked,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert_eq!(viz.safety, SafetyBadge::Danger);
        assert!(viz.status_line.contains("BLOCKED"));
    }

    #[test]
    fn test_caution_knife_edge() {
        let input = ConfidenceVizInput {
            top_posterior: 0.92,
            confidence: Some(Confidence::High),
            knife_edge: true,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert_eq!(viz.safety, SafetyBadge::Caution);
        assert!(viz.knife_edge);
        assert!(viz.status_line.contains("knife-edge"));
    }

    #[test]
    fn test_caution_uncalibrated() {
        let input = ConfidenceVizInput {
            top_posterior: 0.92,
            confidence: Some(Confidence::High),
            calibration: CalibrationStatus::Uncalibrated,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert_eq!(viz.safety, SafetyBadge::Caution);
        assert!(viz.status_line.contains("uncalibrated"));
    }

    #[test]
    fn test_expected_losses_in_status() {
        let input = ConfidenceVizInput {
            top_posterior: 0.87,
            confidence: Some(Confidence::High),
            expected_losses: Some(ExpectedLosses {
                keep: 28.2,
                pause: 15.1,
                kill: 6.4,
            }),
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        assert!(viz.status_line.contains("keep=28.2"));
        assert!(viz.status_line.contains("kill=6.4"));
    }

    #[test]
    fn test_top_evidence_limited() {
        let viz = compute_confidence_viz(
            &mock_ledger(),
            &ConfidenceVizInput {
                top_posterior: 0.87,
                ..Default::default()
            },
        );
        assert_eq!(viz.top_evidence.len(), 2); // Only 2 factors in mock
    }

    #[test]
    fn test_confidence_from_posterior() {
        // No explicit confidence — derive from posterior.
        let input = ConfidenceVizInput {
            top_posterior: 0.97,
            confidence: None,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);
        assert_eq!(viz.confidence, ConfidenceBadge::High);
    }

    #[test]
    fn test_medium_confidence_from_posterior() {
        let input = ConfidenceVizInput {
            top_posterior: 0.85,
            confidence: None,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);
        assert_eq!(viz.confidence, ConfidenceBadge::Med);
    }

    #[test]
    fn test_badge_labels() {
        assert_eq!(SafetyBadge::Safe.label(), "SAFE");
        assert_eq!(SafetyBadge::Caution.label(), "CAUTION");
        assert_eq!(SafetyBadge::Danger.label(), "DANGER");
        assert_eq!(ConfidenceBadge::High.label(), "HIGH");
        assert_eq!(ConfidenceBadge::Med.label(), "MED");
        assert_eq!(ConfidenceBadge::Low.label(), "LOW");
    }

    #[test]
    fn test_serialization() {
        let input = ConfidenceVizInput {
            top_posterior: 0.87,
            confidence: Some(Confidence::High),
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);

        let json = serde_json::to_string(&viz).unwrap();
        let restored: ConfidenceViz = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.safety, SafetyBadge::Safe);
        assert_eq!(restored.confidence, ConfidenceBadge::High);
    }

    #[test]
    fn test_gate_warning_in_status() {
        let input = ConfidenceVizInput {
            top_posterior: 0.92,
            confidence: Some(Confidence::High),
            gate_status: GateStatus::Warning,
            ..Default::default()
        };
        let viz = compute_confidence_viz(&mock_ledger(), &input);
        assert_eq!(viz.safety, SafetyBadge::Caution);
        assert!(viz.status_line.contains("gates: warning"));
    }
}
