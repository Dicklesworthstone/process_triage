//! Direct-impact heuristics from ownership and resource edges.
//!
//! Computes a provenance-aware blast radius using ownership (lineage),
//! shared resources (lockfiles, listeners), and supervision edges to
//! estimate what breaks if a process is killed.
//!
//! Unlike the existing `ImpactScorer` (which uses raw FD/socket counts),
//! this module reasons about *relationships* between processes.

use crate::collect::shared_resource_graph::{BlastRadius, SharedResourceGraph};
use pt_common::{
    ProvenanceConfidence, RawLineageEvidence, ResourceKind, ResourceState, SupervisorKind,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for direct-impact scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectImpactConfig {
    /// Weight for high-value resource ownership (listeners, pidfiles, dbus).
    pub resource_criticality_weight: f64,
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
    /// Maximum critical resource score for normalization.
    pub max_resource_criticality: f64,
}

impl Default for DirectImpactConfig {
    fn default() -> Self {
        Self {
            resource_criticality_weight: 0.20,
            co_holder_weight: 0.25,
            contested_weight: 0.15,
            listener_weight: 0.15,
            supervision_weight: 0.15,
            child_count_weight: 0.10,
            orphan_discount: 0.5,
            max_co_holders: 20,
            max_listeners: 10,
            max_resource_criticality: 6.0,
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
    /// Sum of criticality for directly owned resources.
    pub resource_criticality: f64,
    /// Normalized critical resource score [0, 1].
    pub resource_criticality_score: f64,
    /// Number of active listeners owned by this process.
    pub listener_count: usize,
    /// Normalized listener score [0, 1].
    pub listener_score: f64,
    /// Whether the process is supervised (systemd, etc.).
    pub is_supervised: bool,
    /// Supervision score [0, 1].
    pub supervision_score: f64,
    /// Short explanation of supervision impact.
    pub supervision_reason: Option<String>,
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
    let (resource_criticality, listener_count) = resource_criticality(resource_graph, pid);

    let (is_supervised, supervision_score, supervision_reason) = supervision_impact(lineage);

    let is_orphan = lineage.map(|l| l.ppid == 1).unwrap_or(false);

    let child_count = child_pids.len();

    // Normalize each component to [0, 1].
    let co_holder_score = normalize(co_holder_count, config.max_co_holders);
    let contested_score = normalize(contested_count, config.max_co_holders);
    let resource_criticality_score =
        normalize_f64(resource_criticality, config.max_resource_criticality);
    let listener_score = normalize(listener_count, config.max_listeners);
    let child_score = normalize(child_count, config.max_co_holders);

    // Weighted sum.
    let mut score = resource_criticality_score * config.resource_criticality_weight
        + co_holder_score * config.co_holder_weight
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
        resource_criticality,
        resource_criticality_score,
        listener_count,
        listener_score,
        is_supervised,
        supervision_score,
        supervision_reason,
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

fn normalize_f64(value: f64, max: f64) -> f64 {
    if max <= 0.0 {
        return 0.0;
    }
    (value / max).clamp(0.0, 1.0)
}

fn resource_criticality(resource_graph: &SharedResourceGraph, pid: u32) -> (f64, usize) {
    let mut score = 0.0;
    let mut listener_count = 0;

    if let Some(keys) = resource_graph.process_resources.get(&pid) {
        for key in keys {
            let Some(resource) = resource_graph.resources.get(key) else {
                continue;
            };
            let Some(holder_state) = resource.holder_states.iter().find(|h| h.pid == pid) else {
                continue;
            };

            let base = match resource.kind {
                ResourceKind::Listener => {
                    listener_count += usize::from(holder_state.state == ResourceState::Active);
                    2.0
                }
                ResourceKind::Pidfile => 1.75,
                ResourceKind::DbusName => 1.5,
                ResourceKind::UnixSocket => 1.25,
                ResourceKind::SharedMemory | ResourceKind::NamedPipe => 1.0,
                ResourceKind::GpuDevice => 0.9,
                ResourceKind::Lockfile => 0.75,
            };

            let state_multiplier = match holder_state.state {
                ResourceState::Active => 1.0,
                ResourceState::Conflicted => 1.25,
                ResourceState::Partial => 0.6,
                ResourceState::Stale => 0.35,
                ResourceState::Missing => 0.0,
            };

            score += base * state_multiplier;
        }
    }

    (score, listener_count)
}

fn supervision_impact(lineage: Option<&RawLineageEvidence>) -> (bool, f64, Option<String>) {
    let Some(lineage) = lineage else {
        return (false, 0.0, None);
    };
    let Some(supervisor) = &lineage.supervisor else {
        return (false, 0.0, None);
    };

    let base: f64 = match supervisor.kind {
        SupervisorKind::Systemd | SupervisorKind::Launchd | SupervisorKind::Container => 1.0,
        SupervisorKind::Supervisord => 0.9,
        SupervisorKind::TerminalMultiplexer => 0.7,
        SupervisorKind::ShellJob => 0.45,
        SupervisorKind::Init => 0.35,
        SupervisorKind::Unknown => 0.2,
    };

    let confidence_multiplier = match supervisor.confidence {
        ProvenanceConfidence::High => 1.0,
        ProvenanceConfidence::Medium => 0.8,
        ProvenanceConfidence::Low => 0.55,
        ProvenanceConfidence::Unknown => 0.35,
    };

    let score: f64 = (base * confidence_multiplier).clamp(0.0_f64, 1.0_f64);
    let reason = Some(format!(
        "{} supervision ({:?} confidence)",
        supervisor.kind.slug(),
        supervisor.confidence
    ));
    (score > 0.0, score, reason)
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
    if c.resource_criticality > 0.0 {
        parts.push(format!(
            "critical resource score {:.2}",
            c.resource_criticality
        ));
    }
    if c.listener_count > 0 {
        parts.push(format!("owns {} active listener(s)", c.listener_count));
    }
    if c.is_supervised {
        parts.push(
            c.supervision_reason
                .clone()
                .unwrap_or_else(|| "supervised".to_string()),
        );
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
        format!("PID {pid}: impact={score:.2} — {}", parts.join(", "))
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
        let graph = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/solo.lock")])]);
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
        let graph = SharedResourceGraph::from_evidence(&[(100, vec![listener_ev(100, 8080)])]);
        let result = compute_direct_impact(100, &graph, None, &[], &Default::default());
        assert_eq!(result.components.listener_count, 1);
        assert!(result.components.resource_criticality >= 2.0);
        assert!(result.score > 0.0);
    }

    #[test]
    fn supervision_increases_impact() {
        let graph = SharedResourceGraph::default();
        let lineage = minimal_lineage(100, 1, true);
        let result = compute_direct_impact(100, &graph, Some(&lineage), &[], &Default::default());
        assert!(result.components.is_supervised);
        assert!(result.components.supervision_score > 0.9);
        assert_eq!(
            result.components.supervision_reason.as_deref(),
            Some("systemd supervision (High confidence)")
        );
        assert!(result.score > 0.0);
    }

    #[test]
    fn shell_job_supervision_is_weaker_than_systemd() {
        use pt_common::{LineageCollectionMethod, SupervisorEvidence, SupervisorKind};

        let graph = SharedResourceGraph::default();
        let systemd = minimal_lineage(100, 1, true);
        let shell_job = RawLineageEvidence {
            pid: 100,
            ppid: 99,
            pgid: 100,
            sid: 100,
            uid: 1000,
            user: None,
            tty: None,
            supervisor: Some(SupervisorEvidence {
                kind: SupervisorKind::ShellJob,
                unit_name: None,
                auto_restart: Some(false),
                confidence: ProvenanceConfidence::Medium,
            }),
            ancestors: Vec::new(),
            collection_method: LineageCollectionMethod::Synthetic,
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        };

        let systemd_result =
            compute_direct_impact(100, &graph, Some(&systemd), &[], &Default::default());
        let shell_result =
            compute_direct_impact(100, &graph, Some(&shell_job), &[], &Default::default());

        assert!(
            systemd_result.components.supervision_score > shell_result.components.supervision_score
        );
        assert!(systemd_result.score > shell_result.score);
    }

    #[test]
    fn stale_resource_has_lower_criticality_than_active() {
        let active_graph = SharedResourceGraph::from_evidence(&[(
            100,
            vec![RawResourceEvidence {
                state: ResourceState::Active,
                ..listener_ev(100, 8080)
            }],
        )]);
        let stale_graph = SharedResourceGraph::from_evidence(&[(
            100,
            vec![RawResourceEvidence {
                state: ResourceState::Stale,
                ..listener_ev(100, 8080)
            }],
        )]);

        let active_result =
            compute_direct_impact(100, &active_graph, None, &[], &Default::default());
        let stale_result = compute_direct_impact(100, &stale_graph, None, &[], &Default::default());

        assert!(
            active_result.components.resource_criticality
                > stale_result.components.resource_criticality
        );
        assert!(active_result.score > stale_result.score);
    }

    #[test]
    fn children_increase_impact() {
        let graph = SharedResourceGraph::default();
        let result =
            compute_direct_impact(100, &graph, None, &[200, 300, 400], &Default::default());
        assert_eq!(result.components.child_count, 3);
        assert!(result.score > 0.0);
    }

    #[test]
    fn orphan_discount_reduces_score() {
        let graph = SharedResourceGraph::from_evidence(&[(100, vec![listener_ev(100, 8080)])]);
        let non_orphan = minimal_lineage(100, 500, false);
        let orphan = minimal_lineage(100, 1, false);

        let score_non_orphan =
            compute_direct_impact(100, &graph, Some(&non_orphan), &[], &Default::default()).score;
        let score_orphan =
            compute_direct_impact(100, &graph, Some(&orphan), &[], &Default::default()).score;

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

        let result =
            compute_direct_impact(100, &graph, Some(&lineage), &children, &Default::default());
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
            (
                100,
                vec![lock_ev(100, "/shared.lock"), listener_ev(100, 80)],
            ),
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
