//! Graph-based blast-radius estimation and uncertainty handling.
//!
//! Combines direct impact (ownership, shared resources, supervision),
//! indirect impact (transitive propagation with confidence decay), and
//! provenance continuity (trend analysis) into a unified blast-radius
//! score that predicts the likely consequences of killing a process.
//!
//! The estimator produces a [`BlastRadiusEstimate`] with:
//! - A scalar risk score in [0, 1]
//! - A human-readable risk level (Low / Medium / High / Critical)
//! - Component breakdown for explainability
//! - Confidence assessment based on evidence completeness

use crate::collect::shared_resource_graph::SharedResourceGraph;
use crate::decision::direct_impact::{
    compute_direct_impact, DirectImpactConfig, DirectImpactResult,
};
use crate::decision::indirect_impact::{
    compute_indirect_impact, IndirectImpactConfig, IndirectImpactResult,
};
use pt_common::RawLineageEvidence;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for the unified blast-radius estimator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusEstimatorConfig {
    /// Weight for direct impact component.
    pub direct_weight: f64,
    /// Weight for indirect (transitive) impact component.
    pub indirect_weight: f64,
    /// Thresholds for risk levels.
    pub risk_thresholds: RiskThresholds,
    /// Direct impact configuration.
    pub direct_config: DirectImpactConfig,
    /// Indirect impact configuration.
    pub indirect_config: IndirectImpactConfig,
}

/// Risk level thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Score above which risk is Medium. Default: 0.2
    pub medium: f64,
    /// Score above which risk is High. Default: 0.5
    pub high: f64,
    /// Score above which risk is Critical. Default: 0.8
    pub critical: f64,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            medium: 0.2,
            high: 0.5,
            critical: 0.8,
        }
    }
}

impl Default for BlastRadiusEstimatorConfig {
    fn default() -> Self {
        Self {
            direct_weight: 0.6,
            indirect_weight: 0.4,
            risk_thresholds: RiskThresholds::default(),
            direct_config: DirectImpactConfig::default(),
            indirect_config: IndirectImpactConfig::default(),
        }
    }
}

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Score < medium threshold. Safe for automated action.
    Low,
    /// Score in [medium, high). Worth reviewing.
    Medium,
    /// Score in [high, critical). Requires confirmation.
    High,
    /// Score >= critical. Block automated action.
    Critical,
}

/// Unified blast-radius estimate for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusEstimate {
    /// Target process.
    pub pid: u32,
    /// Combined risk score in [0, 1].
    pub risk_score: f64,
    /// Risk level classification.
    pub risk_level: RiskLevel,
    /// Direct impact details.
    pub direct: DirectImpactResult,
    /// Indirect impact details.
    pub indirect: IndirectImpactResult,
    /// Total affected processes (direct + transitive, deduplicated).
    pub total_affected: usize,
    /// Confidence in the estimate [0, 1].
    pub confidence: f64,
    /// Human-readable summary.
    pub summary: String,
}

/// Estimate blast radius for a single process.
pub fn estimate_blast_radius(
    pid: u32,
    graph: &SharedResourceGraph,
    lineage: Option<&RawLineageEvidence>,
    child_pids: &[u32],
    evidence_completeness: f64,
    config: &BlastRadiusEstimatorConfig,
) -> BlastRadiusEstimate {
    let direct = compute_direct_impact(pid, graph, lineage, child_pids, &config.direct_config);

    let indirect =
        compute_indirect_impact(pid, graph, evidence_completeness, &config.indirect_config);

    // Weighted combination.
    let risk_score = (direct.score * config.direct_weight
        + indirect.adjusted_score * config.indirect_weight)
        .clamp(0.0, 1.0);

    let risk_level = classify_risk(risk_score, &config.risk_thresholds);

    // Total affected = transitive_affected (already includes direct).
    let total_affected = indirect.transitive_affected;

    // Confidence: higher when evidence is complete and we have many data points.
    let confidence = evidence_completeness.clamp(0.0, 1.0);

    let summary = build_summary(pid, risk_score, risk_level, &direct, &indirect, confidence);

    BlastRadiusEstimate {
        pid,
        risk_score,
        risk_level,
        direct,
        indirect,
        total_affected,
        confidence,
        summary,
    }
}

/// Estimate blast radius for a batch of processes.
pub fn estimate_blast_radius_batch(
    pids: &[u32],
    graph: &SharedResourceGraph,
    lineages: &HashMap<u32, RawLineageEvidence>,
    children: &HashMap<u32, Vec<u32>>,
    evidence_completeness: f64,
    config: &BlastRadiusEstimatorConfig,
) -> Vec<BlastRadiusEstimate> {
    pids.iter()
        .map(|&pid| {
            estimate_blast_radius(
                pid,
                graph,
                lineages.get(&pid),
                children.get(&pid).map(|c| c.as_slice()).unwrap_or(&[]),
                evidence_completeness,
                config,
            )
        })
        .collect()
}

fn classify_risk(score: f64, thresholds: &RiskThresholds) -> RiskLevel {
    if score >= thresholds.critical {
        RiskLevel::Critical
    } else if score >= thresholds.high {
        RiskLevel::High
    } else if score >= thresholds.medium {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn build_summary(
    pid: u32,
    score: f64,
    level: RiskLevel,
    direct: &DirectImpactResult,
    indirect: &IndirectImpactResult,
    confidence: f64,
) -> String {
    let level_str = match level {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    };

    let confidence_str = if confidence >= 0.9 {
        "high confidence"
    } else if confidence >= 0.5 {
        "moderate confidence"
    } else {
        "low confidence (incomplete evidence)"
    };

    let affected = if indirect.transitive_affected == 0 {
        "no other processes affected".to_string()
    } else if indirect.transitive_affected == indirect.direct_affected {
        format!("{} directly affected", indirect.direct_affected)
    } else {
        format!(
            "{} directly + {} transitively affected",
            indirect.direct_affected,
            indirect.transitive_affected - indirect.direct_affected
        )
    };

    // Extract the detail portion after " — " from the direct summary.
    // If there's no " — " separator (isolated process), omit the detail
    // to avoid duplicating the PID prefix.
    let detail = direct
        .summary
        .split_once(" — ")
        .map(|(_, detail)| format!(". {detail}"))
        .unwrap_or_default();

    format!("PID {pid}: {level_str} risk (score={score:.2}, {confidence_str}) — {affected}{detail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::shared_resource_graph::SharedResourceGraph;
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

    fn listener_ev(pid: u32, port: u16) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: format!("tcp:{port}"),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn web_stack_graph() -> SharedResourceGraph {
        SharedResourceGraph::from_evidence(&[
            (
                100,
                vec![listener_ev(100, 80), lock_ev(100, "/run/app.lock")],
            ),
            (
                200,
                vec![
                    listener_ev(200, 3000),
                    lock_ev(200, "/run/app.lock"),
                    lock_ev(200, "/run/db.lock"),
                ],
            ),
            (
                300,
                vec![listener_ev(300, 5432), lock_ev(300, "/run/db.lock")],
            ),
            (400, vec![lock_ev(400, "/run/app.lock")]),
            (500, vec![lock_ev(500, "/tmp/orphan.lock")]),
        ])
    }

    #[test]
    fn isolated_process_low_risk() {
        let graph = web_stack_graph();
        let est = estimate_blast_radius(500, &graph, None, &[], 1.0, &Default::default());
        assert_eq!(est.risk_level, RiskLevel::Low);
        assert!(est.risk_score < 0.1);
        assert_eq!(est.total_affected, 0);
    }

    #[test]
    fn connected_process_higher_risk() {
        let graph = web_stack_graph();
        let est_app = estimate_blast_radius(200, &graph, None, &[], 1.0, &Default::default());
        let est_orphan = estimate_blast_radius(500, &graph, None, &[], 1.0, &Default::default());
        assert!(est_app.risk_score > est_orphan.risk_score);
    }

    #[test]
    fn risk_level_classification() {
        assert_eq!(
            classify_risk(0.1, &RiskThresholds::default()),
            RiskLevel::Low
        );
        assert_eq!(
            classify_risk(0.3, &RiskThresholds::default()),
            RiskLevel::Medium
        );
        assert_eq!(
            classify_risk(0.6, &RiskThresholds::default()),
            RiskLevel::High
        );
        assert_eq!(
            classify_risk(0.9, &RiskThresholds::default()),
            RiskLevel::Critical
        );
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn incomplete_evidence_increases_risk() {
        let graph = web_stack_graph();
        let full = estimate_blast_radius(200, &graph, None, &[], 1.0, &Default::default());
        let partial = estimate_blast_radius(200, &graph, None, &[], 0.2, &Default::default());
        assert!(
            partial.risk_score >= full.risk_score,
            "partial={} should >= full={}",
            partial.risk_score,
            full.risk_score
        );
        assert!(partial.confidence < full.confidence);
    }

    #[test]
    fn batch_estimation() {
        let graph = web_stack_graph();
        let results = estimate_blast_radius_batch(
            &[100, 200, 500],
            &graph,
            &HashMap::new(),
            &HashMap::new(),
            1.0,
            &Default::default(),
        );
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].pid, 100);
        assert_eq!(results[1].pid, 200);
        assert_eq!(results[2].pid, 500);
    }

    #[test]
    fn score_bounded() {
        let graph = web_stack_graph();
        for pid in [100, 200, 300, 400, 500] {
            let est = estimate_blast_radius(pid, &graph, None, &[], 0.1, &Default::default());
            assert!(est.risk_score >= 0.0 && est.risk_score <= 1.0, "PID {pid}");
        }
    }

    #[test]
    fn summary_contains_risk_level() {
        let graph = web_stack_graph();
        let est = estimate_blast_radius(500, &graph, None, &[], 1.0, &Default::default());
        assert!(est.summary.contains("LOW"), "summary: {}", est.summary);
    }

    #[test]
    fn summary_mentions_affected_count() {
        let graph = web_stack_graph();
        let est = estimate_blast_radius(200, &graph, None, &[], 1.0, &Default::default());
        assert!(
            est.summary.contains("affected") || est.summary.contains("no other"),
            "summary: {}",
            est.summary
        );
    }

    #[test]
    fn serde_roundtrip() {
        let graph = web_stack_graph();
        let est = estimate_blast_radius(200, &graph, None, &[], 0.8, &Default::default());
        let json = serde_json::to_string(&est).unwrap();
        let deser: BlastRadiusEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pid, 200);
        assert_eq!(deser.risk_level, est.risk_level);
        assert!((deser.risk_score - est.risk_score).abs() < f64::EPSILON);
    }
}
