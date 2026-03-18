//! Process provenance continuity tracking across scan snapshots.
//!
//! Compares two [`SharedResourceGraph`] snapshots to detect lifecycle
//! events: newly orphaned processes, disappearing parents, processes
//! gaining or losing shared resources, and changing blast radius.
//!
//! This enables the triage system to reason about *trends* rather than
//! single-point observations: a process whose blast radius is growing
//! is more concerning than one that's stable.

use crate::collect::shared_resource_graph::SharedResourceGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Lifecycle delta between two scan snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceDelta {
    /// Processes present in current but not previous scan (new).
    pub new_pids: Vec<u32>,
    /// Processes present in previous but not current scan (exited).
    pub exited_pids: Vec<u32>,
    /// Processes that gained new shared resources.
    pub gained_resources: Vec<ResourceChange>,
    /// Processes that lost shared resources.
    pub lost_resources: Vec<ResourceChange>,
    /// Processes whose blast radius increased.
    pub blast_radius_increased: Vec<BlastRadiusDelta>,
    /// Processes whose blast radius decreased.
    pub blast_radius_decreased: Vec<BlastRadiusDelta>,
    /// Resources that became newly contested (multiple active holders).
    pub new_contests: Vec<String>,
    /// Resources that were contested but are no longer.
    pub resolved_contests: Vec<String>,
}

/// A change in resource ownership for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    /// The affected process.
    pub pid: u32,
    /// Resource keys gained or lost.
    pub resource_keys: Vec<String>,
}

/// Change in blast radius between scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusDelta {
    /// The process.
    pub pid: u32,
    /// Previous blast radius (co-holder count).
    pub previous_affected: usize,
    /// Current blast radius (co-holder count).
    pub current_affected: usize,
    /// Delta (positive = growing, negative = shrinking).
    pub delta: i64,
}

/// Compute the lifecycle delta between two scan snapshots.
pub fn compute_provenance_delta(
    previous: &SharedResourceGraph,
    current: &SharedResourceGraph,
) -> ProvenanceDelta {
    let prev_pids: HashSet<u32> = previous.process_resources.keys().copied().collect();
    let curr_pids: HashSet<u32> = current.process_resources.keys().copied().collect();

    let new_pids: Vec<u32> = curr_pids.difference(&prev_pids).copied().collect();
    let exited_pids: Vec<u32> = prev_pids.difference(&curr_pids).copied().collect();

    // Resource changes for continuing processes.
    let continuing: HashSet<u32> = prev_pids.intersection(&curr_pids).copied().collect();
    let mut gained_resources = Vec::new();
    let mut lost_resources = Vec::new();
    let mut blast_radius_increased = Vec::new();
    let mut blast_radius_decreased = Vec::new();

    for &pid in &continuing {
        let prev_keys = previous
            .process_resources
            .get(&pid)
            .cloned()
            .unwrap_or_default();
        let curr_keys = current
            .process_resources
            .get(&pid)
            .cloned()
            .unwrap_or_default();

        let gained: Vec<String> = curr_keys.difference(&prev_keys).cloned().collect();
        let lost: Vec<String> = prev_keys.difference(&curr_keys).cloned().collect();

        if !gained.is_empty() {
            gained_resources.push(ResourceChange {
                pid,
                resource_keys: gained,
            });
        }
        if !lost.is_empty() {
            lost_resources.push(ResourceChange {
                pid,
                resource_keys: lost,
            });
        }

        // Blast radius delta.
        let prev_br = previous.blast_radius(pid);
        let curr_br = current.blast_radius(pid);
        let prev_count = prev_br.affected_pids.len();
        let curr_count = curr_br.affected_pids.len();

        if curr_count != prev_count {
            let delta = BlastRadiusDelta {
                pid,
                previous_affected: prev_count,
                current_affected: curr_count,
                delta: curr_count as i64 - prev_count as i64,
            };
            if curr_count > prev_count {
                blast_radius_increased.push(delta);
            } else {
                blast_radius_decreased.push(delta);
            }
        }
    }

    // Contest changes.
    let prev_contested: HashSet<&String> = previous
        .contested_resources()
        .iter()
        .map(|r| &r.key)
        .collect();
    let curr_contested: HashSet<&String> = current
        .contested_resources()
        .iter()
        .map(|r| &r.key)
        .collect();

    let new_contests: Vec<String> = curr_contested
        .difference(&prev_contested)
        .map(|k| (*k).clone())
        .collect();
    let resolved_contests: Vec<String> = prev_contested
        .difference(&curr_contested)
        .map(|k| (*k).clone())
        .collect();

    ProvenanceDelta {
        new_pids,
        exited_pids,
        gained_resources,
        lost_resources,
        blast_radius_increased,
        blast_radius_decreased,
        new_contests,
        resolved_contests,
    }
}

/// Summarize a provenance delta for logging/display.
pub fn summarize_delta(delta: &ProvenanceDelta) -> String {
    let mut parts = Vec::new();

    if !delta.new_pids.is_empty() {
        parts.push(format!("{} new process(es)", delta.new_pids.len()));
    }
    if !delta.exited_pids.is_empty() {
        parts.push(format!("{} exited", delta.exited_pids.len()));
    }
    if !delta.gained_resources.is_empty() {
        let total: usize = delta
            .gained_resources
            .iter()
            .map(|r| r.resource_keys.len())
            .sum();
        parts.push(format!("{total} resource(s) gained"));
    }
    if !delta.lost_resources.is_empty() {
        let total: usize = delta
            .lost_resources
            .iter()
            .map(|r| r.resource_keys.len())
            .sum();
        parts.push(format!("{total} resource(s) lost"));
    }
    if !delta.blast_radius_increased.is_empty() {
        parts.push(format!(
            "{} process(es) with growing blast radius",
            delta.blast_radius_increased.len()
        ));
    }
    if !delta.new_contests.is_empty() {
        parts.push(format!("{} new contest(s)", delta.new_contests.len()));
    }

    if parts.is_empty() {
        "No provenance changes detected".to_string()
    } else {
        parts.join(", ")
    }
}

/// Track continuity for a specific PID across snapshots.
pub fn pid_continuity(
    pid: u32,
    previous: &SharedResourceGraph,
    current: &SharedResourceGraph,
) -> PidContinuity {
    let was_present = previous.process_resources.contains_key(&pid);
    let is_present = current.process_resources.contains_key(&pid);

    match (was_present, is_present) {
        (false, true) => PidContinuity::New,
        (true, false) => PidContinuity::Exited,
        (false, false) => PidContinuity::Unknown,
        (true, true) => {
            let prev_br = previous.blast_radius(pid);
            let curr_br = current.blast_radius(pid);
            PidContinuity::Continuing {
                blast_radius_delta: curr_br.affected_pids.len() as i64
                    - prev_br.affected_pids.len() as i64,
                resources_gained: current
                    .process_resources
                    .get(&pid)
                    .unwrap_or(&HashSet::new())
                    .difference(
                        previous
                            .process_resources
                            .get(&pid)
                            .unwrap_or(&HashSet::new()),
                    )
                    .count(),
                resources_lost: previous
                    .process_resources
                    .get(&pid)
                    .unwrap_or(&HashSet::new())
                    .difference(
                        current
                            .process_resources
                            .get(&pid)
                            .unwrap_or(&HashSet::new()),
                    )
                    .count(),
            }
        }
    }
}

/// Continuity status for a single PID across scan snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PidContinuity {
    /// Process appeared in this scan (not in previous).
    New,
    /// Process was in previous scan but not this one.
    Exited,
    /// Process not seen in either scan.
    Unknown,
    /// Process present in both scans.
    Continuing {
        /// Change in blast radius (positive = growing).
        blast_radius_delta: i64,
        /// Number of new resources gained.
        resources_gained: usize,
        /// Number of resources lost.
        resources_lost: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // ── Delta computation ─────────────────────────────────────────────

    #[test]
    fn empty_snapshots_produce_empty_delta() {
        let prev = SharedResourceGraph::default();
        let curr = SharedResourceGraph::default();
        let delta = compute_provenance_delta(&prev, &curr);
        assert!(delta.new_pids.is_empty());
        assert!(delta.exited_pids.is_empty());
    }

    #[test]
    fn detects_new_processes() {
        let prev = SharedResourceGraph::default();
        let curr = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let delta = compute_provenance_delta(&prev, &curr);
        assert!(delta.new_pids.contains(&100));
        assert!(delta.exited_pids.is_empty());
    }

    #[test]
    fn detects_exited_processes() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let curr = SharedResourceGraph::default();
        let delta = compute_provenance_delta(&prev, &curr);
        assert!(delta.exited_pids.contains(&100));
        assert!(delta.new_pids.is_empty());
    }

    #[test]
    fn detects_gained_resources() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let curr = SharedResourceGraph::from_evidence(&[(
            100,
            vec![lock_ev(100, "/a.lock"), lock_ev(100, "/b.lock")],
        )]);
        let delta = compute_provenance_delta(&prev, &curr);
        assert_eq!(delta.gained_resources.len(), 1);
        assert_eq!(delta.gained_resources[0].pid, 100);
        assert!(delta.gained_resources[0]
            .resource_keys
            .contains(&"/b.lock".to_string()));
    }

    #[test]
    fn detects_lost_resources() {
        let prev = SharedResourceGraph::from_evidence(&[(
            100,
            vec![lock_ev(100, "/a.lock"), lock_ev(100, "/b.lock")],
        )]);
        let curr = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let delta = compute_provenance_delta(&prev, &curr);
        assert_eq!(delta.lost_resources.len(), 1);
        assert!(delta.lost_resources[0]
            .resource_keys
            .contains(&"/b.lock".to_string()));
    }

    #[test]
    fn detects_blast_radius_increase() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/shared.lock")])]);
        let curr = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/shared.lock")]),
            (200, vec![lock_ev(200, "/shared.lock")]),
        ]);
        let delta = compute_provenance_delta(&prev, &curr);
        assert_eq!(delta.blast_radius_increased.len(), 1);
        assert_eq!(delta.blast_radius_increased[0].pid, 100);
        assert_eq!(delta.blast_radius_increased[0].delta, 1);
    }

    #[test]
    fn detects_new_contest() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/x.lock")])]);
        let curr = SharedResourceGraph::from_evidence(&[
            (100, vec![lock_ev(100, "/x.lock")]),
            (200, vec![lock_ev(200, "/x.lock")]),
        ]);
        let delta = compute_provenance_delta(&prev, &curr);
        assert!(delta.new_contests.contains(&"/x.lock".to_string()));
    }

    // ── PID continuity ────────────────────────────────────────────────

    #[test]
    fn pid_continuity_new() {
        let prev = SharedResourceGraph::default();
        let curr = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        assert_eq!(pid_continuity(100, &prev, &curr), PidContinuity::New);
    }

    #[test]
    fn pid_continuity_exited() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let curr = SharedResourceGraph::default();
        assert_eq!(pid_continuity(100, &prev, &curr), PidContinuity::Exited);
    }

    #[test]
    fn pid_continuity_stable() {
        let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let curr = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        match pid_continuity(100, &prev, &curr) {
            PidContinuity::Continuing {
                blast_radius_delta,
                resources_gained,
                resources_lost,
            } => {
                assert_eq!(blast_radius_delta, 0);
                assert_eq!(resources_gained, 0);
                assert_eq!(resources_lost, 0);
            }
            other => panic!("expected Continuing, got {other:?}"),
        }
    }

    // ── Summary ───────────────────────────────────────────────────────

    #[test]
    fn summary_empty_delta() {
        let delta = ProvenanceDelta::default();
        assert_eq!(summarize_delta(&delta), "No provenance changes detected");
    }

    #[test]
    fn summary_with_changes() {
        let prev = SharedResourceGraph::default();
        let curr = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
        let delta = compute_provenance_delta(&prev, &curr);
        let summary = summarize_delta(&delta);
        assert!(summary.contains("new process"));
    }
}
