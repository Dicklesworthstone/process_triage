//! Direct-impact heuristics from ownership and resource edges.
//!
//! Computes a provenance-aware blast radius using ownership (lineage),
//! shared resources (lockfiles, listeners), and supervision edges to
//! estimate what breaks if a process is killed.
//!
//! Unlike the existing `ImpactScorer` (which uses raw FD/socket counts),
//! this module reasons about *relationships* between processes.

use crate::collect::shared_resource_graph::{BlastRadius, SharedResourceGraph};
use pt_common::{RawLineageEvidence, ResourceKind, ResourceState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Configuration for direct-impact scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectImpactConfig {
    /// Weight for co-holder count (processes sharing resources).
    pub co_holder_weight: f64,
    /// Weight for contested resource count.
    pub contested_weight: f64,
    /// Weight for active listener ownership.
    pub listener_weight: f64,
    /// Weight for supervision (supervised processes are higher impact).
    pub supervision_weight: f64,
    /// Weight for child count from lineage.
    pub child_count_weight: f64,
    /// Penalty for being an orphan (lower impact — already detached).
    pub orphan_discount: f64,
    /// Maximum co-holders for normalization.
    pub max_co_holders: usize,
    /// Maximum listeners for normalization.
    pub max_listeners: usize,
}

impl Default for DirectImpactConfig {
    fn default() -> Self {
        Self {
            co_holder_weight: 0.25,
            contested_weight: 0.20,
            listener_weight: 0.20,
            supervision_weight: 0.20,
            child_count_weight: 0.15,
            orphan_discount: 0.5,
            max_co_holders: 20,
            max_listeners: 10,
        }
    }
}

/// Direct-impact assessment for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectImpactResult {
    /// The target process.
    pub pid: u32,
    /// Overall impact score in [0, 1]. Higher = more impact.
    pub score: f64,
    /// Breakdown of individual components.
    pub components: DirectImpactComponents,
    /// Blast radius from shared resources.
    pub blast_radius: BlastRadius,
    /// Human-readable impact summary.
    pub summary: String,
}

/// Individual components contributing to direct impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectImpactComponents {
    /// Number of processes sharing resources with this one.
    pub co_holder_count: usize,
    /// Normalized co-holder score [0, 1].
    pub co_holder_score: f64,
    /// Number of contested resources (multiple active holders).
    pub contested_count: usize,
    /// Normalized contested score [0, 1].
    pub contested_score: f64,
    /// Number of active listeners owned by this process.
    pub listener_count: usize,
    /// Normalized listener score [0, 1].
    pub listener_score: f64,
    /// Whether the process is supervised (systemd, etc.).
    pub is_supervised: bool,
    /// Supervision score [0, 1].
    pub supervision_score: f64,
    /// Number of direct child processes.
    pub child_count: usize,
    /// Normalized child score [0, 1].
    pub child_score: f64,
    /// Whether the process is an orphan (PPID=1).
    pub is_orphan: bool,
}

/// Compute direct impact for a process using provenance evidence.
pub fn compute_direct_impact(
    pid: u32,
    resource_graph: &SharedResourceGraph,
    lineage: Option<&RawLineageEvidence>,
    child_pids: &[u32],
    config: &DirectImpactConfig,
) -> DirectImpactResult {
    let blast_radius = resource_graph.blast_radius(pid);
    let co_holder_count = blast_radius.affected_pids.len();
    let contested_count = blast_radius.contested_resource_count;

    // Count active listeners.
    let listener_count = resource_graph
        .process_resources
        .get(&pid)
        .map(|keys| {
            keys.iter()
                .filter(|k| {
                    resource_graph
                        .resources
                        .get(*k)
                        .map(|r| {
                            r.kind == ResourceKind::Listener
                                && r.holder_states
                                    .iter()
                                    .any(|h| h.pid == pid && h.state == ResourceState::Active)
                        })
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    let is_supervised = lineage
        .map(|l| l.supervisor.is_some())
        .unwrap_or(false);

    let is_orphan = lineage.map(|l| l.ppid == 1).unwrap_or(false);

    let child_count = child_pids.len();

    // Normalize each component to [0, 1].
    let co_holder_score = normalize(co_holder_count, config.max_co_holders);
    let contested_score = normalize(contested_count, config.max_co_holders);
    let listener_score = normalize(listener_count, config.max_listeners);
    let supervision_score = if is_supervised { 1.0 } else { 0.0 };
    let child_score = normalize(child_count, config.max_co_holders);

    // Weighted sum.
    let mut score = co_holder_score * config.co_holder_weight
        + contested_score * config.contested_weight
        + listener_score * config.listener_weight
        + supervision_score * config.supervision_weight
        + child_score * config.child_count_weight;

    // Orphan discount: orphaned processes are already detached from their
    // parent, so killing them has less collateral impact.
    if is_orphan {
        score *= config.orphan_discount;
    }

    score = score.clamp(0.0, 1.0);

    let components = DirectImpactComponents {
        co_holder_count,
        co_holder_score,
        contested_count,
        contested_score,
        listener_count,
        listener_score,
        is_supervised,
        supervision_score,
        child_count,
        child_score,
        is_orphan,
    };

    let summary = build_summary(pid, &components, score);

    DirectImpactResult {
        pid,
        score,
        components,
        blast_radius,
        summary,
    }
}

/// Compute direct impact for a batch of processes.
pub fn compute_direct_impact_batch(
    pids: &[u32],
    resource_graph: &SharedResourceGraph,
    lineages: &HashMap<u32, RawLineageEvidence>,
    children: &HashMap<u32, Vec<u32>>,
    config: &DirectImpactConfig,
) -> Vec<DirectImpactResult> {
    pids.iter()
        .map(|&pid| {
            compute_direct_impact(
                pid,
                resource_graph,
                lineages.get(&pid),
                children.get(&pid).map(|c| c.as_slice()).unwrap_or(&[]),
                config,
            )
        })
        .collect()
}

fn normalize(value: usize, max: usize) -> f64 {
    if max == 0 {
        return 0.0;
    }
    (value as f64 / max as f64).min(1.0)
}

fn build_summary(pid: u32, c: &DirectImpactComponents, score: f64) -> String {
    let mut parts = Vec::new();

    if c.co_holder_count > 0 {
        parts.push(format!(
            "shares {} resource(s) with {} process(es)",
            c.co_holder_count + c.contested_count,
            c.co_holder_count
        ));
    }
    if c.listener_count > 0 {
        parts.push(format!("owns {} active listener(s)", c.listener_count));
    }
    if c.is_supervised {
        parts.push("supervised".to_string());
    }
    if c.child_count > 0 {
        parts.push(format!("{} child process(es)", c.child_count));
    }
    if c.is_orphan {
        parts.push("orphaned (impact discounted)".to_string());
    }

    if parts.is_empty() {
        format!("PID {pid}: low impact (score={score:.2}), no shared resources or dependents")
    } else {
        format!(
            "PID {pid}: impact={score:.2} — {}",
            parts.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::shared_resource_graph::SharedResourceGraph;
    use pt_common::{
        LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
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

    fn minimal_lineage(pid: u32, ppid: u32, supervised: bool) -> RawLineageEvidence {
        use pt_common::{LineageCollectionMethod, SupervisorEvidence, SupervisorKind};
        RawLineageEvidence {
            pid,
            ppid,
            pgid: pid,
            sid: pid,
            uid: 1000,
            user: None,
            tty: None,
            supervisor: if supervised {
                Some(SupervisorEvidence {
                    kind: SupervisorKind::Systemd,
                    unit_name: Some("test.service".to_string()),
                    auto_restart: None,
                    confidence: pt_common::ProvenanceConfidence::High,
                })
            } else {
                None
            },
            ancestors: Vec::new(),
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    // ── Basic scoring ─────────────────────────────────────────────────

    #[test]
    fn isolated_process_has_zero_impact() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/solo.lock")]),
        ]);
        let result = compute_direct_impact(100, &graph, None, &[], &Default::default());
        assert_eq!(result.components.co_holder_count, 0);
        assert_eq!(result.components.listener_count, 0);
        assert!(result.score < 0.01);
    }

    #[test]
    fn shared_resource_increases_impact() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let result = compute_direct_impact(100, &graph, None, &[], &Default::default());
        assert_eq!(result.components.co_holder_count, 1);
        assert!(result.score > 0.0);
    }

    #[test]
    fn listener_increases_impact() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![listener_ev(100, 8080)]),
        ]);
        let result = compute_direct_impact(100, &graph, None, &[], &Default::default());
        assert_eq!(result.components.listener_count, 1);
        assert!(result.score > 0.0);
    }

    #[test]
    fn supervision_increases_impact() {
        let graph = SharedResourceGraph::default();
        let lineage = minimal_lineage(100, 1, true);
        let result = compute_direct_impact(
            100,
            &graph,
            Some(&lineage),
            &[],
            &Default::default(),
        );
        assert!(result.components.is_supervised);
        assert!(result.score > 0.0);
    }

    #[test]
    fn children_increase_impact() {
        let graph = SharedResourceGraph::default();
        let result = compute_direct_impact(
            100,
            &graph,
            None,
            &[200, 300, 400],
            &Default::default(),
        );
        assert_eq!(result.components.child_count, 3);
        assert!(result.score > 0.0);
    }

    #[test]
    fn orphan_discount_reduces_score() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![listener_ev(100, 8080)]),
        ]);
        let non_orphan = minimal_lineage(100, 500, false);
        let orphan = minimal_lineage(100, 1, false);

        let score_non_orphan = compute_direct_impact(
            100, &graph, Some(&non_orphan), &[], &Default::default(),
        )
        .score;
        let score_orphan = compute_direct_impact(
            100, &graph, Some(&orphan), &[], &Default::default(),
        )
        .score;

        assert!(
            score_orphan < score_non_orphan,
            "orphan={score_orphan} should be less than non-orphan={score_non_orphan}"
        );
    }

    // ── Score bounds ──────────────────────────────────────────────────

    #[test]
    fn score_clamped_to_unit_interval() {
        // Max out everything.
        let mut evidence: Vec<(u32, Vec<RawResourceEvidence>)> = Vec::new();
        let mut ev_100 = vec![listener_ev(100, 8080)];
        for i in 0..30 {
            let path = format!("/lock/{i}");
            ev_100.push(lock_ev(100, &path));
        }
        evidence.push((100, ev_100));
        // 30 other processes sharing those locks.
        for i in 0..30 {
            let path = format!("/lock/{i}");
            evidence.push((200 + i as u32, vec![lock_ev(200 + i as u32, &path)]));
        }

        let graph = SharedResourceGraph::from_evidence(&evidence);
        let lineage = minimal_lineage(100, 500, true);
        let children: Vec<u32> = (300..330).collect();

        let result = compute_direct_impact(
            100,
            &graph,
            Some(&lineage),
            &children,
            &Default::default(),
        );
        assert!(result.score <= 1.0);
        assert!(result.score >= 0.0);
    }

    // ── Batch ─────────────────────────────────────────────────────────

    #[test]
    fn batch_computes_for_all_pids() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/a.lock")]),
            (200, vec![lock_ev(200, "/a.lock")]),
        ]);
        let results = compute_direct_impact_batch(
            &[100, 200],
            &graph,
            &HashMap::new(),
            &HashMap::new(),
            &Default::default(),
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].pid, 100);
        assert_eq!(results[1].pid, 200);
    }

    // ── Summary ───────────────────────────────────────────────────────

    #[test]
    fn summary_mentions_shared_resources() {
        let graph = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock"), listener_ev(100, 80)]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let result = compute_direct_impact(100, &graph, None, &[], &Default::default());
        assert!(result.summary.contains("shares"));
        assert!(result.summary.contains("listener"));
    }

    #[test]
    fn summary_for_isolated_mentions_low_impact() {
        let graph = SharedResourceGraph::default();
        let result = compute_direct_impact(999, &graph, None, &[], &Default::default());
        assert!(result.summary.contains("low impact"));
    }
}
