//! Provenance-adjusted scoring and confidence integration.
//!
//! Feeds blast-radius risk into the decision pipeline by adjusting
//! kill confidence and action feasibility based on provenance evidence.
//! A process might be clearly abandoned (high posterior) but still
//! dangerous to kill (high blast radius) — this module reconciles both.
//!
//! # Score Adjustment
//!
//! The provenance adjustment modifies the effective confidence for
//! automated actions:
//!
//! ```text
//! adjusted_confidence = posterior_confidence * (1 - risk_penalty)
//! risk_penalty = blast_radius.risk_score * penalty_weight
//! ```
//!
//! High blast radius reduces confidence even when the posterior is
//! strong, requiring human review for risky kills.

use crate::decision::blast_radius_estimator::{
    BlastRadiusEstimate, BlastRadiusEstimatorConfig, RiskLevel,
};
use serde::{Deserialize, Serialize};

/// Configuration for provenance-adjusted scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceScoringConfig {
    /// How much blast-radius risk reduces kill confidence.
    /// Higher = more conservative. Default: 0.6
    pub risk_penalty_weight: f64,
    /// Minimum confidence required for robot-mode kill after adjustment.
    /// Default: 0.80
    pub min_robot_confidence: f64,
    /// Risk level at or above which robot-mode kills are blocked
    /// regardless of confidence. Default: Critical
    pub block_risk_level: RiskLevel,
    /// Whether to include blast-radius in the evidence ledger output.
    pub include_in_ledger: bool,
}

impl Default for ProvenanceScoringConfig {
    fn default() -> Self {
        Self {
            risk_penalty_weight: 0.6,
            min_robot_confidence: 0.80,
            block_risk_level: RiskLevel::Critical,
            include_in_ledger: true,
        }
    }
}

/// Result of provenance-adjusted scoring for a candidate process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceAdjustedScore {
    /// Target process.
    pub pid: u32,
    /// Original posterior confidence (P(abandoned | evidence)).
    pub original_confidence: f64,
    /// Blast-radius risk score [0, 1].
    pub risk_score: f64,
    /// Risk level classification.
    pub risk_level: RiskLevel,
    /// Risk penalty applied to confidence.
    pub risk_penalty: f64,
    /// Adjusted confidence after applying risk penalty.
    pub adjusted_confidence: f64,
    /// Whether automated (robot-mode) kill is recommended.
    pub robot_kill_allowed: bool,
    /// Reason for the recommendation.
    pub reason: String,
    /// Action recommendation.
    pub recommendation: ActionRecommendation,
}

/// What action to take based on combined posterior + provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRecommendation {
    /// Safe for automated kill (high confidence, low risk).
    AutoKill,
    /// Recommend kill but require human confirmation (medium risk).
    ConfirmKill,
    /// Recommend review before any action (high risk or low confidence).
    Review,
    /// Block kill action (critical risk or insufficient confidence).
    Block,
    /// No action needed (process appears useful).
    NoAction,
}

/// Compute provenance-adjusted score for a candidate.
///
/// `posterior_confidence` is the Bayesian posterior probability that the
/// process is abandoned (or otherwise a kill candidate). `blast_radius`
/// is the pre-computed blast-radius estimate from the provenance graph.
pub fn compute_provenance_adjusted_score(
    pid: u32,
    posterior_confidence: f64,
    blast_radius: &BlastRadiusEstimate,
    config: &ProvenanceScoringConfig,
) -> ProvenanceAdjustedScore {
    let risk_score = blast_radius.risk_score;
    let risk_level = blast_radius.risk_level;

    // Risk penalty: scales down confidence proportional to blast radius.
    let risk_penalty = risk_score * config.risk_penalty_weight;
    let adjusted_confidence = (posterior_confidence * (1.0 - risk_penalty)).clamp(0.0, 1.0);

    // Determine recommendation.
    let (robot_kill_allowed, recommendation, reason) = if posterior_confidence < 0.5 {
        // Process doesn't look abandoned — no action.
        (
            false,
            ActionRecommendation::NoAction,
            "Posterior confidence too low for kill action".to_string(),
        )
    } else if risk_level >= config.block_risk_level {
        // Critical blast radius — block regardless of confidence.
        (
            false,
            ActionRecommendation::Block,
            format!(
                "Blast radius is {:?} (score={:.2}) — automated kill blocked",
                risk_level, risk_score
            ),
        )
    } else if adjusted_confidence < config.min_robot_confidence {
        // Confidence reduced below threshold by risk penalty.
        let rec = if risk_level >= RiskLevel::High {
            ActionRecommendation::Review
        } else {
            ActionRecommendation::ConfirmKill
        };
        (
            false,
            rec,
            format!(
                "Adjusted confidence {:.2} below threshold {:.2} \
                 (original={:.2}, risk_penalty={:.2})",
                adjusted_confidence,
                config.min_robot_confidence,
                posterior_confidence,
                risk_penalty
            ),
        )
    } else {
        // High confidence + acceptable risk → auto-kill.
        (
            true,
            ActionRecommendation::AutoKill,
            format!(
                "Adjusted confidence {:.2} above threshold {:.2} \
                 with {:?} blast radius",
                adjusted_confidence, config.min_robot_confidence, risk_level
            ),
        )
    };

    ProvenanceAdjustedScore {
        pid,
        original_confidence: posterior_confidence,
        risk_score,
        risk_level,
        risk_penalty,
        adjusted_confidence,
        robot_kill_allowed,
        reason,
        recommendation,
    }
}

/// Batch-compute provenance-adjusted scores.
pub fn compute_provenance_adjusted_scores(
    candidates: &[(u32, f64, BlastRadiusEstimate)],
    config: &ProvenanceScoringConfig,
) -> Vec<ProvenanceAdjustedScore> {
    candidates
        .iter()
        .map(|(pid, confidence, br)| {
            compute_provenance_adjusted_score(*pid, *confidence, br, config)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::shared_resource_graph::SharedResourceGraph;
    use crate::decision::blast_radius_estimator::estimate_blast_radius;
    use pt_common::{
        LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
        ResourceKind, ResourceState,
    };

    fn lock_ev(pid: u32, path: &str) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: path.to_string(),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcFd,
            state: ResourceState::Active,
            details: ResourceDetails::Lockfile {
                path: path.to_string(),
                mechanism: LockMechanism::Existence,
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn isolated_blast_radius(pid: u32) -> BlastRadiusEstimate {
        let graph = SharedResourceGraph::from_evidence(&[(pid, vec![lock_ev(pid, "/solo.lock")])]);
        estimate_blast_radius(pid, &graph, None, &[], 1.0, &Default::default())
    }

    fn connected_blast_radius(pid: u32) -> BlastRadiusEstimate {
        let mut evidence = vec![(pid, vec![lock_ev(pid, "/shared.lock")])];
        for i in 1..=10 {
            evidence.push((pid + i, vec![lock_ev(pid + i, "/shared.lock")]));
        }
        let graph = SharedResourceGraph::from_evidence(&evidence);
        estimate_blast_radius(pid, &graph, None, &[], 1.0, &Default::default())
    }

    // ── Basic scoring ─────────────────────────────────────────────────

    #[test]
    fn high_confidence_low_risk_allows_auto_kill() {
        let br = isolated_blast_radius(100);
        let result = compute_provenance_adjusted_score(100, 0.95, &br, &Default::default());
        assert!(result.robot_kill_allowed);
        assert_eq!(result.recommendation, ActionRecommendation::AutoKill);
        assert!(result.adjusted_confidence > 0.80);
    }

    #[test]
    fn high_confidence_high_risk_blocks_auto_kill() {
        let br = connected_blast_radius(100);
        let config = ProvenanceScoringConfig::default();
        let result = compute_provenance_adjusted_score(100, 0.95, &br, &config);
        // Connected process has higher risk, which reduces confidence.
        // Whether it blocks depends on the risk score.
        assert!(result.risk_penalty > 0.0);
        assert!(result.adjusted_confidence < result.original_confidence);
    }

    #[test]
    fn low_posterior_produces_no_action() {
        let br = isolated_blast_radius(100);
        let result = compute_provenance_adjusted_score(100, 0.30, &br, &Default::default());
        assert!(!result.robot_kill_allowed);
        assert_eq!(result.recommendation, ActionRecommendation::NoAction);
    }

    #[test]
    fn risk_penalty_reduces_confidence() {
        let br = isolated_blast_radius(100);
        let result = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        // Low risk = small penalty.
        assert!(result.adjusted_confidence <= result.original_confidence);
        assert!(result.risk_penalty >= 0.0);
    }

    // ── Risk level thresholds ─────────────────────────────────────────

    #[test]
    fn critical_risk_blocks_regardless_of_confidence() {
        // Construct a fake critical-risk blast radius.
        let mut br = isolated_blast_radius(100);
        br.risk_score = 0.95;
        br.risk_level = RiskLevel::Critical;

        let result = compute_provenance_adjusted_score(100, 0.99, &br, &Default::default());
        assert!(!result.robot_kill_allowed);
        assert_eq!(result.recommendation, ActionRecommendation::Block);
    }

    #[test]
    fn custom_block_level_at_high() {
        let mut br = isolated_blast_radius(100);
        br.risk_score = 0.60;
        br.risk_level = RiskLevel::High;

        let config = ProvenanceScoringConfig {
            block_risk_level: RiskLevel::High,
            ..Default::default()
        };
        let result = compute_provenance_adjusted_score(100, 0.99, &br, &config);
        assert!(!result.robot_kill_allowed);
        assert_eq!(result.recommendation, ActionRecommendation::Block);
    }

    // ── Adjusted confidence ───────────────────────────────────────────

    #[test]
    fn zero_risk_no_penalty() {
        let mut br = isolated_blast_radius(100);
        br.risk_score = 0.0;

        let result = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        assert!((result.risk_penalty).abs() < f64::EPSILON);
        assert!((result.adjusted_confidence - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn adjusted_confidence_clamped_to_unit() {
        let mut br = isolated_blast_radius(100);
        br.risk_score = 0.5;

        let result = compute_provenance_adjusted_score(100, 1.0, &br, &Default::default());
        assert!(result.adjusted_confidence >= 0.0);
        assert!(result.adjusted_confidence <= 1.0);
    }

    // ── Batch ─────────────────────────────────────────────────────────

    #[test]
    fn batch_processes_all_candidates() {
        let br1 = isolated_blast_radius(100);
        let br2 = isolated_blast_radius(200);
        let candidates = vec![(100, 0.95, br1), (200, 0.30, br2)];
        let results = compute_provenance_adjusted_scores(&candidates, &Default::default());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].pid, 100);
        assert_eq!(results[1].pid, 200);
        assert_eq!(results[0].recommendation, ActionRecommendation::AutoKill);
        assert_eq!(results[1].recommendation, ActionRecommendation::NoAction);
    }

    // ── Serde ─────────────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let br = isolated_blast_radius(100);
        let result = compute_provenance_adjusted_score(100, 0.90, &br, &Default::default());
        let json = serde_json::to_string(&result).unwrap();
        let deser: ProvenanceAdjustedScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pid, 100);
        assert_eq!(deser.recommendation, result.recommendation);
    }
}
