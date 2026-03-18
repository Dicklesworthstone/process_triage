//! Shared-resource relationship graph for provenance-aware triage.
//!
//! Aggregates per-process resource evidence (lockfiles, pidfiles, network
//! listeners, sockets) into a graph of processes linked by shared resources.
//! This enables blast-radius estimation: killing one process may affect
//! others that share the same coordination surface.
//!
//! # Architecture
//!
//! ```text
//! Per-process evidence (RawResourceEvidence)
//!   ↓ aggregate_shared_resources()
//! SharedResourceGraph
//!   ├── resources: key → SharedResource (resource metadata + holder list)
//!   └── process_resources: pid → list of resource keys
//! ```

use pt_common::{RawResourceEvidence, ResourceKind, ResourceState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A shared resource held by one or more processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedResource {
    /// Canonical resource key (e.g., file path or "tcp:port").
    pub key: String,
    /// Resource kind.
    pub kind: ResourceKind,
    /// PIDs currently holding this resource.
    pub holder_pids: Vec<u32>,
    /// Per-holder state information.
    pub holder_states: Vec<HolderState>,
    /// Whether this resource is contested (multiple active holders).
    pub contested: bool,
    /// Whether any holder is in a conflicted state.
    pub has_conflict: bool,
}

/// Per-holder state for a shared resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderState {
    /// Process ID.
    pub pid: u32,
    /// Resource state for this holder.
    pub state: ResourceState,
    /// When observed.
    pub observed_at: String,
}

/// Graph of processes linked by shared resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedResourceGraph {
    /// Resource key → shared resource info.
    pub resources: HashMap<String, SharedResource>,
    /// PID → set of resource keys held by this process.
    pub process_resources: HashMap<u32, HashSet<String>>,
}

impl SharedResourceGraph {
    /// Build a shared-resource graph from per-process evidence.
    ///
    /// Each `(pid, evidence_list)` pair represents one process's
    /// collected resource evidence.
    pub fn from_evidence(per_process: &[(u32, Vec<RawResourceEvidence>)]) -> Self {
        let mut graph = SharedResourceGraph::default();

        for (pid, evidence_list) in per_process {
            for ev in evidence_list {
                let resource =
                    graph
                        .resources
                        .entry(ev.key.clone())
                        .or_insert_with(|| SharedResource {
                            key: ev.key.clone(),
                            kind: ev.kind,
                            holder_pids: Vec::new(),
                            holder_states: Vec::new(),
                            contested: false,
                            has_conflict: false,
                        });

                // Only add each PID once per resource.
                if !resource.holder_pids.contains(pid) {
                    resource.holder_pids.push(*pid);
                    resource.holder_states.push(HolderState {
                        pid: *pid,
                        state: ev.state,
                        observed_at: ev.observed_at.clone(),
                    });
                }

                if ev.state == ResourceState::Conflicted {
                    resource.has_conflict = true;
                }

                graph
                    .process_resources
                    .entry(*pid)
                    .or_default()
                    .insert(ev.key.clone());
            }
        }

        // Mark contested resources (multiple active holders).
        for resource in graph.resources.values_mut() {
            let active_count = resource
                .holder_states
                .iter()
                .filter(|h| h.state == ResourceState::Active)
                .count();
            resource.contested = active_count > 1;
        }

        graph
    }

    /// Find all processes that share at least one resource with the given PID.
    pub fn co_holders(&self, pid: u32) -> HashSet<u32> {
        let mut result = HashSet::new();
        if let Some(keys) = self.process_resources.get(&pid) {
            for key in keys {
                if let Some(resource) = self.resources.get(key) {
                    for &holder_pid in &resource.holder_pids {
                        if holder_pid != pid {
                            result.insert(holder_pid);
                        }
                    }
                }
            }
        }
        result
    }

    /// Count of shared resources held by a process.
    pub fn resource_count(&self, pid: u32) -> usize {
        self.process_resources
            .get(&pid)
            .map(|keys| keys.len())
            .unwrap_or(0)
    }

    /// All contested resources (multiple active holders).
    pub fn contested_resources(&self) -> Vec<&SharedResource> {
        self.resources.values().filter(|r| r.contested).collect()
    }

    /// All resources with conflict state.
    pub fn conflicted_resources(&self) -> Vec<&SharedResource> {
        self.resources.values().filter(|r| r.has_conflict).collect()
    }

    /// Estimate blast radius: how many other processes would be affected
    /// if the given PID is killed?
    pub fn blast_radius(&self, pid: u32) -> BlastRadius {
        let co_holders = self.co_holders(pid);
        let resource_count = self.resource_count(pid);
        let contested_count = self
            .process_resources
            .get(&pid)
            .map(|keys| {
                keys.iter()
                    .filter(|k| self.resources.get(*k).map(|r| r.contested).unwrap_or(false))
                    .count()
            })
            .unwrap_or(0);

        BlastRadius {
            target_pid: pid,
            affected_pids: co_holders.into_iter().collect(),
            shared_resource_count: resource_count,
            contested_resource_count: contested_count,
        }
    }
}

/// Blast radius estimate for killing a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// The process being considered for termination.
    pub target_pid: u32,
    /// Other processes that share resources with the target.
    pub affected_pids: Vec<u32>,
    /// Total shared resources held by the target.
    pub shared_resource_count: usize,
    /// Resources where the target is one of multiple active holders.
    pub contested_resource_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::{LockMechanism, ResourceCollectionMethod, ResourceDetails};

    fn lock_ev(pid: u32, path: &str, state: ResourceState) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: path.to_string(),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcFd,
            state,
            details: ResourceDetails::Lockfile {
                path: path.to_string(),
                mechanism: LockMechanism::Existence,
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn listener_ev(pid: u32, port: u16, state: ResourceState) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: format!("tcp:{port}"),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcNet,
            state,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    // ── Graph Construction ────────────────────────────────────────────

    #[test]
    fn empty_evidence_produces_empty_graph() {
        let graph = SharedResourceGraph::from_evidence(&[]);
        assert!(graph.resources.is_empty());
        assert!(graph.process_resources.is_empty());
    }

    #[test]
    fn single_process_single_resource() {
        let evidence = vec![(
            100,
            vec![lock_ev(100, "/var/lock/test", ResourceState::Active)],
        )];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        assert_eq!(graph.resources.len(), 1);
        assert_eq!(graph.resource_count(100), 1);

        let resource = graph.resources.get("/var/lock/test").unwrap();
        assert_eq!(resource.holder_pids, vec![100]);
        assert!(!resource.contested);
    }

    #[test]
    fn two_processes_share_lockfile() {
        let evidence = vec![
            (
                100,
                vec![lock_ev(100, "/tmp/.X0-lock", ResourceState::Active)],
            ),
            (
                200,
                vec![lock_ev(200, "/tmp/.X0-lock", ResourceState::Active)],
            ),
        ];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let resource = graph.resources.get("/tmp/.X0-lock").unwrap();
        assert_eq!(resource.holder_pids.len(), 2);
        assert!(resource.contested); // Both active.

        assert!(graph.co_holders(100).contains(&200));
        assert!(graph.co_holders(200).contains(&100));
    }

    #[test]
    fn contested_only_when_multiple_active() {
        let evidence = vec![
            (
                100,
                vec![lock_ev(100, "/tmp/test.lock", ResourceState::Active)],
            ),
            (
                200,
                vec![lock_ev(200, "/tmp/test.lock", ResourceState::Stale)],
            ),
        ];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let resource = graph.resources.get("/tmp/test.lock").unwrap();
        assert!(!resource.contested); // Only one active.
    }

    #[test]
    fn conflict_state_detected() {
        let evidence = vec![(
            100,
            vec![lock_ev(100, "/run/nginx.pid", ResourceState::Conflicted)],
        )];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let resource = graph.resources.get("/run/nginx.pid").unwrap();
        assert!(resource.has_conflict);
        assert_eq!(graph.conflicted_resources().len(), 1);
    }

    // ── Co-holders ────────────────────────────────────────────────────

    #[test]
    fn co_holders_across_multiple_resources() {
        let evidence = vec![
            (
                100,
                vec![
                    lock_ev(100, "/lock/a", ResourceState::Active),
                    lock_ev(100, "/lock/b", ResourceState::Active),
                ],
            ),
            (200, vec![lock_ev(200, "/lock/a", ResourceState::Active)]),
            (300, vec![lock_ev(300, "/lock/b", ResourceState::Active)]),
        ];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let co = graph.co_holders(100);
        assert!(co.contains(&200));
        assert!(co.contains(&300));
        assert!(!co.contains(&100)); // Doesn't include self.
    }

    #[test]
    fn co_holders_empty_for_unknown_pid() {
        let graph = SharedResourceGraph::from_evidence(&[]);
        assert!(graph.co_holders(999).is_empty());
    }

    // ── Blast Radius ──────────────────────────────────────────────────

    #[test]
    fn blast_radius_counts_affected() {
        let evidence = vec![
            (
                100,
                vec![
                    lock_ev(100, "/lock/db", ResourceState::Active),
                    listener_ev(100, 5432, ResourceState::Active),
                ],
            ),
            (200, vec![lock_ev(200, "/lock/db", ResourceState::Active)]),
            (300, vec![listener_ev(300, 5432, ResourceState::Active)]),
        ];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let br = graph.blast_radius(100);
        assert_eq!(br.target_pid, 100);
        assert_eq!(br.shared_resource_count, 2);
        assert!(br.affected_pids.contains(&200));
        assert!(br.affected_pids.contains(&300));
        assert_eq!(br.affected_pids.len(), 2);
        assert_eq!(br.contested_resource_count, 2); // Both contested.
    }

    #[test]
    fn blast_radius_zero_for_isolated_process() {
        let evidence = vec![(100, vec![lock_ev(100, "/solo.lock", ResourceState::Active)])];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let br = graph.blast_radius(100);
        assert!(br.affected_pids.is_empty());
        assert_eq!(br.contested_resource_count, 0);
    }

    // ── Mixed Resource Types ──────────────────────────────────────────

    #[test]
    fn lockfile_and_listener_coexist() {
        let evidence = vec![(
            100,
            vec![
                lock_ev(100, "/run/app.lock", ResourceState::Active),
                listener_ev(100, 8080, ResourceState::Active),
            ],
        )];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        assert_eq!(graph.resource_count(100), 2);
        assert!(graph.resources.contains_key("/run/app.lock"));
        assert!(graph.resources.contains_key("tcp:8080"));
    }

    // ── Deduplication ─────────────────────────────────────────────────

    #[test]
    fn duplicate_evidence_for_same_pid_deduped() {
        let evidence = vec![(
            100,
            vec![
                lock_ev(100, "/lock/x", ResourceState::Active),
                lock_ev(100, "/lock/x", ResourceState::Active), // Duplicate.
            ],
        )];
        let graph = SharedResourceGraph::from_evidence(&evidence);

        let resource = graph.resources.get("/lock/x").unwrap();
        assert_eq!(resource.holder_pids.len(), 1); // Not 2.
    }
}
