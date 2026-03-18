//! Indirect-impact and uncertainty propagation over the provenance graph.
//!
//! Extends blast-radius reasoning beyond direct edges:
//! - **Transitive impact**: if A shares a resource with B, and B shares
//!   with C, killing A may indirectly affect C.
//! - **Missing evidence penalty**: when the graph is incomplete (few
//!   probes, partial scans), apply a conservative inflation to the
//!   estimated blast radius.
//! - **Uncertainty propagation**: confidence decays with graph distance,
//!   reflecting decreasing certainty about indirect effects.

use crate::collect::shared_resource_graph::SharedResourceGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// Configuration for indirect impact propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectImpactConfig {
    /// Maximum graph hops to consider for transitive impact.
    /// Default: 2 (direct + one-hop neighbors).
    pub max_hops: usize,
    /// Decay factor per hop: confidence = decay^hops.
    /// Default: 0.5 (50% decay per hop).
    pub decay_per_hop: f64,
    /// Penalty multiplier when evidence is incomplete (graph is sparse).
    /// Applied as: score *= 1 + penalty * (1 - evidence_completeness).
    /// Default: 0.3
    pub missing_evidence_penalty: f64,
    /// Minimum evidence completeness (fraction of expected probes that
    /// actually ran) below which the penalty is maximum. Default: 0.1
    pub min_completeness: f64,
}

impl Default for IndirectImpactConfig {
    fn default() -> Self {
        Self {
            max_hops: 2,
            decay_per_hop: 0.5,
            missing_evidence_penalty: 0.3,
            min_completeness: 0.1,
        }
    }
}

/// Result of indirect impact analysis for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectImpactResult {
    /// Target process.
    pub pid: u32,
    /// Direct co-holders (hop 0).
    pub direct_affected: usize,
    /// Transitive co-holders (all hops up to max_hops).
    pub transitive_affected: usize,
    /// Per-hop breakdown: hop distance → (count, confidence).
    pub per_hop: Vec<HopBreakdown>,
    /// Raw transitive impact score before uncertainty penalty.
    pub raw_score: f64,
    /// Evidence completeness fraction [0, 1].
    pub evidence_completeness: f64,
    /// Uncertainty penalty applied.
    pub uncertainty_penalty: f64,
    /// Final adjusted impact score [0, 1].
    pub adjusted_score: f64,
}

/// Impact breakdown for a single hop distance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopBreakdown {
    /// Hop distance (0 = direct neighbors).
    pub hop: usize,
    /// Number of processes at this distance.
    pub count: usize,
    /// Confidence at this distance (decay^hop).
    pub confidence: f64,
    /// Weighted contribution to the score.
    pub contribution: f64,
}

/// Compute indirect impact for a process via BFS over the resource graph.
///
/// `evidence_completeness` is the fraction of expected probes/scans that
/// actually ran (1.0 = full evidence, 0.0 = no probes ran). When evidence
/// is incomplete, a conservative penalty inflates the score.
pub fn compute_indirect_impact(
    pid: u32,
    graph: &SharedResourceGraph,
    evidence_completeness: f64,
    config: &IndirectImpactConfig,
) -> IndirectImpactResult {
    let completeness = evidence_completeness.clamp(config.min_completeness, 1.0);

    // BFS from the target PID to find transitive co-holders.
    let mut visited: HashSet<u32> = HashSet::new();
    visited.insert(pid);
    let mut queue: VecDeque<(u32, usize)> = VecDeque::new();
    let mut per_hop: Vec<HopBreakdown> = Vec::new();

    // Seed with direct neighbors.
    let direct = graph.co_holders(pid);
    for &neighbor in &direct {
        if visited.insert(neighbor) {
            queue.push_back((neighbor, 1));
        }
    }

    // Initialize hop 0 (direct neighbors).
    let hop0_confidence = 1.0;
    let hop0_count = direct.len();
    per_hop.push(HopBreakdown {
        hop: 0,
        count: hop0_count,
        confidence: hop0_confidence,
        contribution: hop0_count as f64 * hop0_confidence,
    });

    // BFS for transitive hops.
    let mut current_hop = 1;
    let mut hop_pids: Vec<u32> = Vec::new();

    while !queue.is_empty() && current_hop <= config.max_hops {
        hop_pids.clear();

        // Drain all entries at the current hop level.
        while let Some(&(next_pid, hop)) = queue.front() {
            if hop != current_hop {
                break;
            }
            queue.pop_front();
            hop_pids.push(next_pid);

            // Enqueue next-hop neighbors.
            if current_hop < config.max_hops {
                for &neighbor in &graph.co_holders(next_pid) {
                    if visited.insert(neighbor) {
                        queue.push_back((neighbor, current_hop + 1));
                    }
                }
            }
        }

        let confidence = config.decay_per_hop.powi(current_hop as i32);
        let count = hop_pids.len();
        per_hop.push(HopBreakdown {
            hop: current_hop,
            count,
            confidence,
            contribution: count as f64 * confidence,
        });

        current_hop += 1;
    }

    let direct_affected = hop0_count;
    let transitive_affected = visited.len() - 1; // Exclude the target itself.

    // Raw score: sum of contributions (count * confidence per hop).
    let raw_score: f64 = per_hop.iter().map(|h| h.contribution).sum();

    // Normalize raw score to [0, 1] using a saturating function.
    // At 10+ weighted affected processes, the score approaches 1.0.
    let normalized = 1.0 - (-raw_score / 10.0).exp();

    // Uncertainty penalty: inflate when evidence is incomplete.
    let uncertainty_penalty = config.missing_evidence_penalty * (1.0 - completeness);
    let adjusted_score = (normalized + uncertainty_penalty).min(1.0);

    IndirectImpactResult {
        pid,
        direct_affected,
        transitive_affected,
        per_hop,
        raw_score,
        evidence_completeness: completeness,
        uncertainty_penalty,
        adjusted_score,
    }
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

    #[test]
    fn isolated_process_zero_impact() {
        let graph = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/solo.lock")])]);
        let result = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        assert_eq!(result.direct_affected, 0);
        assert_eq!(result.transitive_affected, 0);
        assert!(result.adjusted_score < 0.01);
    }

    #[test]
    fn direct_neighbors_counted_at_hop_zero() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let result = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        assert_eq!(result.direct_affected, 1);
        assert_eq!(result.per_hop[0].count, 1);
        assert!((result.per_hop[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn transitive_neighbors_at_hop_one() {
        // Chain: 100 → 200 → 300 (via shared locks).
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/a.lock")]),
            (200, vec![lock_ev(200, "/a.lock"), lock_ev(200, "/b.lock")]),
            (300, vec![lock_ev(300, "/b.lock")]),
        ]);
        let result = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        assert_eq!(result.direct_affected, 1); // 200
        assert_eq!(result.transitive_affected, 2); // 200 + 300
        assert!(result.per_hop.len() >= 2);
        // Hop 1 should have count 1 (PID 300) with decayed confidence.
        assert_eq!(result.per_hop[1].count, 1);
        assert!((result.per_hop[1].confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn max_hops_limits_traversal() {
        // Long chain: 100 → 200 → 300 → 400 → 500.
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/a.lock")]),
            (200, vec![lock_ev(200, "/a.lock"), lock_ev(200, "/b.lock")]),
            (300, vec![lock_ev(300, "/b.lock"), lock_ev(300, "/c.lock")]),
            (400, vec![lock_ev(400, "/c.lock"), lock_ev(400, "/d.lock")]),
            (500, vec![lock_ev(500, "/d.lock")]),
        ]);
        let config = IndirectImpactConfig {
            max_hops: 2,
            ..Default::default()
        };
        let result = compute_indirect_impact(100, &graph, 1.0, &config);
        // With max_hops=2: direct=200, hop1=300, stops before 400/500.
        assert_eq!(result.direct_affected, 1);
        assert_eq!(result.transitive_affected, 2); // 200 + 300 only.
    }

    #[test]
    fn missing_evidence_inflates_score() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let full_evidence = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        let partial_evidence = compute_indirect_impact(100, &graph, 0.3, &Default::default());

        assert!(
            partial_evidence.adjusted_score > full_evidence.adjusted_score,
            "partial={} should exceed full={}",
            partial_evidence.adjusted_score,
            full_evidence.adjusted_score
        );
        assert!(partial_evidence.uncertainty_penalty > 0.0);
    }

    #[test]
    fn full_evidence_no_penalty() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let result = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        assert!((result.uncertainty_penalty).abs() < f64::EPSILON);
    }

    #[test]
    fn score_bounded_to_unit_interval() {
        // Large fan-out graph.
        let mut evidence: Vec<(u32, Vec<RawResourceEvidence>)> = Vec::new();
        let mut ev_100 = Vec::new();
        for i in 0..50 {
            let path = format!("/lock/{i}");
            ev_100.push(lock_ev(100, &path));
            evidence.push((200 + i, vec![lock_ev(200 + i, &path)]));
        }
        evidence.push((100, ev_100));

        let graph = SharedResourceGraph::from_evidence(&evidence);
        let result = compute_indirect_impact(100, &graph, 0.1, &Default::default());
        assert!(result.adjusted_score <= 1.0);
        assert!(result.adjusted_score >= 0.0);
    }

    #[test]
    fn decay_reduces_contribution_per_hop() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/a.lock")]),
            (200, vec![lock_ev(200, "/a.lock"), lock_ev(200, "/b.lock")]),
            (300, vec![lock_ev(300, "/b.lock")]),
        ]);
        let result = compute_indirect_impact(100, &graph, 1.0, &Default::default());
        // Hop 0 contribution should be higher than hop 1.
        assert!(result.per_hop[0].contribution >= result.per_hop[1].contribution);
    }
}
