//! Distributed causal snapshots for fleet-wide triage safety.
//!
//! Implements a Chandy-Lamport–inspired marker protocol that captures a
//! consistent cut of the global process state across multiple hosts.
//! This prevents triage cascades where killing a process on Host A
//! breaks a dependency on Host B.
//!
//! # Protocol
//!
//! 1. The **initiator** broadcasts a `Marker` to all hosts in the fleet.
//! 2. Each host records its **local state** (process snapshot) upon
//!    receiving the marker and forwards it on all outgoing channels.
//! 3. Once all markers are collected, the initiator assembles a
//!    **consistent cut** — a global snapshot where no message is "in
//!    flight" across the cut boundary.
//!
//! # Tentative Cuts
//!
//! In high-latency environments a host may not respond within the
//! snapshot budget.  Rather than blocking forever the protocol uses a
//! **tentative cut**: remote processes that lack a confirmed snapshot
//! are marked `Tentative` and excluded from automatic kill decisions.
//!
//! # Causal Safety Gate
//!
//! Before any kill action the gate checks whether the target process is
//! a causal dependency for any `Useful` process in the fleet snapshot.
//! If so the action is blocked and a `CausalViolation` is returned.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ── Marker ────────────────────────────────────────────────────────────

/// A snapshot marker broadcast to all fleet hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    /// Unique identifier for this snapshot round.
    pub snapshot_id: String,
    /// Host that initiated the snapshot.
    pub initiator_host: String,
    /// When the marker was created.
    pub created_at: DateTime<Utc>,
    /// Maximum time to wait for all hosts to respond.
    pub timeout_ms: u64,
}

impl Marker {
    /// Create a new snapshot marker.
    pub fn new(initiator_host: &str, timeout_ms: u64) -> Self {
        Self {
            snapshot_id: Uuid::new_v4().to_string(),
            initiator_host: initiator_host.to_string(),
            created_at: Utc::now(),
            timeout_ms,
        }
    }

    /// Whether the marker has expired.
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.created_at)
            .num_milliseconds();
        elapsed >= self.timeout_ms as i64
    }
}

// ── Host Snapshot ─────────────────────────────────────────────────────

/// Confirmation state for a host's snapshot response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotState {
    /// Host has confirmed its local state.
    Confirmed,
    /// Marker was sent but no response received yet.
    Pending,
    /// Marker timed out — host state is unknown.
    Tentative,
    /// Host reported an error during snapshot.
    Failed,
}

/// A single host's local state captured during a snapshot round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    /// Host identifier.
    pub host_id: String,
    /// Confirmation state.
    pub state: SnapshotState,
    /// When the snapshot was recorded (if confirmed).
    pub recorded_at: Option<DateTime<Utc>>,
    /// Process dependency graph: pid → set of remote dependencies.
    /// Each dependency is `(remote_host, remote_pid)`.
    pub process_deps: HashMap<u32, Vec<RemoteDependency>>,
    /// Set of PIDs classified as Useful on this host.
    pub useful_pids: HashSet<u32>,
    /// Set of PIDs classified as Useful-Bad on this host.
    pub useful_bad_pids: HashSet<u32>,
}

impl HostSnapshot {
    /// Create a confirmed snapshot.
    pub fn confirmed(host_id: &str) -> Self {
        Self {
            host_id: host_id.to_string(),
            state: SnapshotState::Confirmed,
            recorded_at: Some(Utc::now()),
            process_deps: HashMap::new(),
            useful_pids: HashSet::new(),
            useful_bad_pids: HashSet::new(),
        }
    }

    /// Create a tentative snapshot (timed out).
    pub fn tentative(host_id: &str) -> Self {
        Self {
            host_id: host_id.to_string(),
            state: SnapshotState::Tentative,
            recorded_at: None,
            process_deps: HashMap::new(),
            useful_pids: HashSet::new(),
            useful_bad_pids: HashSet::new(),
        }
    }
}

/// A remote process dependency: this local process depends on a process
/// running on another host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RemoteDependency {
    /// Remote host identifier.
    pub remote_host: String,
    /// Remote process PID.
    pub remote_pid: u32,
    /// Type of dependency (network connection, shared resource, etc.).
    pub dep_type: DependencyType,
}

/// How two processes across hosts are related.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    /// TCP connection (client → server).
    TcpConnection,
    /// Shared network port / service.
    SharedService,
    /// Shared filesystem / NFS mount.
    SharedFilesystem,
    /// Named pipe / Unix socket (cross-host via NFS).
    SharedIpc,
    /// Application-level dependency (detected via config/env).
    ApplicationLevel,
}

// ── Consistent Cut ────────────────────────────────────────────────────

/// Result of assembling host snapshots into a consistent cut.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistentCut {
    /// The marker that initiated this snapshot round.
    pub snapshot_id: String,
    /// Per-host snapshots.
    pub host_snapshots: HashMap<String, HostSnapshot>,
    /// Overall cut validity.
    pub validity: CutValidity,
    /// When the cut was assembled.
    pub assembled_at: DateTime<Utc>,
    /// Number of hosts that confirmed.
    pub confirmed_count: usize,
    /// Number of hosts that timed out (tentative).
    pub tentative_count: usize,
    /// Number of hosts that failed.
    pub failed_count: usize,
}

/// Whether the cut is valid for making kill decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CutValidity {
    /// All hosts confirmed — safe for automated decisions.
    Complete,
    /// Some hosts are tentative — safe for interactive, conservative for robot.
    Partial,
    /// Too many hosts failed — must revert to safe mode (no auto-kills).
    Invalid,
}

// ── Snapshot Coordinator ──────────────────────────────────────────────

/// Configuration for the snapshot coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Maximum time to wait for marker responses (ms).
    /// Default: 5000
    pub marker_timeout_ms: u64,
    /// Maximum fraction of hosts that can be tentative before the cut
    /// is declared invalid. Default: 0.3 (30%)
    pub max_tentative_fraction: f64,
    /// Whether to allow kill actions when the cut is partial.
    /// Default: false (conservative)
    pub allow_kills_on_partial_cut: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            marker_timeout_ms: 5000,
            max_tentative_fraction: 0.3,
            allow_kills_on_partial_cut: false,
        }
    }
}

/// Coordinates the Chandy-Lamport snapshot protocol across fleet hosts.
#[derive(Debug, Clone)]
pub struct SnapshotCoordinator {
    config: SnapshotConfig,
    /// The local host identifier.
    local_host: String,
    /// Current active marker (if any).
    active_marker: Option<Marker>,
    /// Collected host snapshots for the current round.
    snapshots: HashMap<String, HostSnapshot>,
    /// Known fleet hosts.
    fleet_hosts: Vec<String>,
}

impl SnapshotCoordinator {
    /// Create a new coordinator for the given local host.
    pub fn new(local_host: &str, fleet_hosts: Vec<String>, config: SnapshotConfig) -> Self {
        Self {
            config,
            local_host: local_host.to_string(),
            active_marker: None,
            snapshots: HashMap::new(),
            fleet_hosts,
        }
    }

    /// Initiate a new snapshot round by creating and broadcasting a marker.
    ///
    /// Returns the marker to broadcast to all fleet hosts.
    pub fn initiate_snapshot(&mut self) -> Marker {
        let marker = Marker::new(&self.local_host, self.config.marker_timeout_ms);
        self.active_marker = Some(marker.clone());
        self.snapshots.clear();
        marker
    }

    /// Record a host's snapshot response.
    pub fn record_snapshot(&mut self, snapshot: HostSnapshot) {
        self.snapshots.insert(snapshot.host_id.clone(), snapshot);
    }

    /// Check if all expected hosts have responded.
    pub fn all_hosts_responded(&self) -> bool {
        self.fleet_hosts
            .iter()
            .all(|h| self.snapshots.contains_key(h))
    }

    /// Assemble the consistent cut from collected snapshots.
    ///
    /// Hosts that haven't responded are marked as tentative.
    pub fn assemble_cut(&mut self) -> ConsistentCut {
        // Fill in tentative snapshots for non-responding hosts.
        for host in &self.fleet_hosts {
            self.snapshots
                .entry(host.clone())
                .or_insert_with(|| HostSnapshot::tentative(host));
        }

        let confirmed_count = self
            .snapshots
            .values()
            .filter(|s| s.state == SnapshotState::Confirmed)
            .count();
        let tentative_count = self
            .snapshots
            .values()
            .filter(|s| s.state == SnapshotState::Tentative)
            .count();
        let failed_count = self
            .snapshots
            .values()
            .filter(|s| s.state == SnapshotState::Failed)
            .count();

        let total = self.fleet_hosts.len().max(1);
        let tentative_fraction = tentative_count as f64 / total as f64;

        let validity = if tentative_count == 0 && failed_count == 0 {
            CutValidity::Complete
        } else if tentative_fraction <= self.config.max_tentative_fraction && failed_count == 0 {
            CutValidity::Partial
        } else {
            CutValidity::Invalid
        };

        let snapshot_id = self
            .active_marker
            .as_ref()
            .map(|m| m.snapshot_id.clone())
            .unwrap_or_default();

        ConsistentCut {
            snapshot_id,
            host_snapshots: self.snapshots.clone(),
            validity,
            assembled_at: Utc::now(),
            confirmed_count,
            tentative_count,
            failed_count,
        }
    }
}

// ── Causal Safety Gate ────────────────────────────────────────────────

/// Result of checking a kill action against the causal snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalCheckResult {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Violations that block the action (if any).
    pub violations: Vec<CausalViolation>,
    /// The cut validity at the time of the check.
    pub cut_validity: CutValidity,
}

/// A causal violation that blocks a kill action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalViolation {
    /// The target process that was proposed for killing.
    pub target_host: String,
    /// Target PID.
    pub target_pid: u32,
    /// The dependent process that would be affected.
    pub dependent_host: String,
    /// Dependent PID.
    pub dependent_pid: u32,
    /// Type of causal relationship.
    pub dep_type: DependencyType,
    /// Why the action is blocked.
    pub reason: String,
}

/// Check whether a proposed kill action is safe given the causal snapshot.
///
/// A kill is blocked if:
/// 1. The cut is invalid (reverts to safe mode — no auto-kills).
/// 2. The target process is a dependency of any `Useful` process on
///    any host in the fleet snapshot.
/// 3. The cut is partial and `allow_kills_on_partial_cut` is false.
pub fn check_causal_safety(
    cut: &ConsistentCut,
    target_host: &str,
    target_pid: u32,
    config: &SnapshotConfig,
) -> CausalCheckResult {
    let mut violations = Vec::new();

    // Gate 1: Invalid cut → block all kills.
    if cut.validity == CutValidity::Invalid {
        violations.push(CausalViolation {
            target_host: target_host.to_string(),
            target_pid,
            dependent_host: String::new(),
            dependent_pid: 0,
            dep_type: DependencyType::ApplicationLevel,
            reason: format!(
                "Snapshot cut is invalid ({} tentative, {} failed hosts) — \
                 reverting to safe mode, no auto-kills allowed",
                cut.tentative_count, cut.failed_count
            ),
        });
        return CausalCheckResult {
            allowed: false,
            violations,
            cut_validity: cut.validity,
        };
    }

    // Gate 2: Partial cut with conservative config → block.
    if cut.validity == CutValidity::Partial && !config.allow_kills_on_partial_cut {
        violations.push(CausalViolation {
            target_host: target_host.to_string(),
            target_pid,
            dependent_host: String::new(),
            dependent_pid: 0,
            dep_type: DependencyType::ApplicationLevel,
            reason: format!(
                "Snapshot cut is partial ({} tentative hosts) and \
                 allow_kills_on_partial_cut is false",
                cut.tentative_count
            ),
        });
        return CausalCheckResult {
            allowed: false,
            violations,
            cut_validity: cut.validity,
        };
    }

    // Gate 3: Check if target is a dependency of any Useful process.
    for (host_id, snapshot) in &cut.host_snapshots {
        if snapshot.state != SnapshotState::Confirmed {
            continue;
        }

        for (&pid, deps) in &snapshot.process_deps {
            // Only check if the local process is classified as Useful.
            if !snapshot.useful_pids.contains(&pid) {
                continue;
            }

            for dep in deps {
                if dep.remote_host == target_host && dep.remote_pid == target_pid {
                    violations.push(CausalViolation {
                        target_host: target_host.to_string(),
                        target_pid,
                        dependent_host: host_id.clone(),
                        dependent_pid: pid,
                        dep_type: dep.dep_type,
                        reason: format!(
                            "Process {}:{} is a {:?} dependency of Useful process {}:{}",
                            target_host, target_pid, dep.dep_type, host_id, pid
                        ),
                    });
                }
            }
        }
    }

    CausalCheckResult {
        allowed: violations.is_empty(),
        violations,
        cut_validity: cut.validity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Marker ────────────────────────────────────────────────────────

    #[test]
    fn marker_not_expired_immediately() {
        let m = Marker::new("host-a", 5000);
        assert!(!m.is_expired());
    }

    #[test]
    fn marker_has_unique_id() {
        let m1 = Marker::new("host-a", 1000);
        let m2 = Marker::new("host-a", 1000);
        assert_ne!(m1.snapshot_id, m2.snapshot_id);
    }

    #[test]
    fn marker_zero_timeout_expires() {
        let m = Marker::new("host-a", 0);
        // Zero timeout means immediately expired.
        assert!(m.is_expired());
    }

    // ── HostSnapshot ──────────────────────────────────────────────────

    #[test]
    fn confirmed_snapshot_has_timestamp() {
        let s = HostSnapshot::confirmed("host-a");
        assert_eq!(s.state, SnapshotState::Confirmed);
        assert!(s.recorded_at.is_some());
    }

    #[test]
    fn tentative_snapshot_has_no_timestamp() {
        let s = HostSnapshot::tentative("host-b");
        assert_eq!(s.state, SnapshotState::Tentative);
        assert!(s.recorded_at.is_none());
    }

    // ── SnapshotCoordinator ───────────────────────────────────────────

    #[test]
    fn coordinator_initiates_snapshot() {
        let hosts = vec!["host-a".to_string(), "host-b".to_string()];
        let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
        let marker = coord.initiate_snapshot();
        assert_eq!(marker.initiator_host, "host-a");
        assert!(!coord.all_hosts_responded());
    }

    #[test]
    fn coordinator_tracks_responses() {
        let hosts = vec!["host-a".to_string(), "host-b".to_string()];
        let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
        coord.initiate_snapshot();

        coord.record_snapshot(HostSnapshot::confirmed("host-a"));
        assert!(!coord.all_hosts_responded());

        coord.record_snapshot(HostSnapshot::confirmed("host-b"));
        assert!(coord.all_hosts_responded());
    }

    #[test]
    fn complete_cut_when_all_confirmed() {
        let hosts = vec!["host-a".to_string(), "host-b".to_string()];
        let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
        coord.initiate_snapshot();
        coord.record_snapshot(HostSnapshot::confirmed("host-a"));
        coord.record_snapshot(HostSnapshot::confirmed("host-b"));

        let cut = coord.assemble_cut();
        assert_eq!(cut.validity, CutValidity::Complete);
        assert_eq!(cut.confirmed_count, 2);
        assert_eq!(cut.tentative_count, 0);
    }

    #[test]
    fn partial_cut_with_one_tentative() {
        let hosts = vec![
            "host-a".to_string(),
            "host-b".to_string(),
            "host-c".to_string(),
            "host-d".to_string(),
        ];
        let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
        coord.initiate_snapshot();
        coord.record_snapshot(HostSnapshot::confirmed("host-a"));
        coord.record_snapshot(HostSnapshot::confirmed("host-b"));
        coord.record_snapshot(HostSnapshot::confirmed("host-c"));
        // host-d doesn't respond → tentative

        let cut = coord.assemble_cut();
        assert_eq!(cut.validity, CutValidity::Partial);
        assert_eq!(cut.confirmed_count, 3);
        assert_eq!(cut.tentative_count, 1);
    }

    #[test]
    fn invalid_cut_when_too_many_tentative() {
        let hosts = vec!["host-a".to_string(), "host-b".to_string()];
        let config = SnapshotConfig {
            max_tentative_fraction: 0.3,
            ..Default::default()
        };
        let mut coord = SnapshotCoordinator::new("host-a", hosts, config);
        coord.initiate_snapshot();
        // Neither host responds → 100% tentative.

        let cut = coord.assemble_cut();
        assert_eq!(cut.validity, CutValidity::Invalid);
        assert_eq!(cut.tentative_count, 2);
    }

    #[test]
    fn invalid_cut_when_host_fails() {
        let hosts = vec!["host-a".to_string(), "host-b".to_string()];
        let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
        coord.initiate_snapshot();
        coord.record_snapshot(HostSnapshot::confirmed("host-a"));
        let mut failed = HostSnapshot::tentative("host-b");
        failed.state = SnapshotState::Failed;
        coord.record_snapshot(failed);

        let cut = coord.assemble_cut();
        assert_eq!(cut.validity, CutValidity::Invalid);
        assert_eq!(cut.failed_count, 1);
    }

    // ── Causal Safety Gate ────────────────────────────────────────────

    fn build_test_cut() -> ConsistentCut {
        let mut host_a = HostSnapshot::confirmed("host-a");
        let mut host_b = HostSnapshot::confirmed("host-b");

        // host-a has a web server (pid 100, Useful) that depends on
        // host-b's database (pid 200).
        host_a.useful_pids.insert(100);
        host_a.process_deps.insert(
            100,
            vec![RemoteDependency {
                remote_host: "host-b".to_string(),
                remote_pid: 200,
                dep_type: DependencyType::TcpConnection,
            }],
        );

        // host-b has the database (pid 200, Useful-Bad — slow but needed).
        host_b.useful_bad_pids.insert(200);

        let mut snapshots = HashMap::new();
        snapshots.insert("host-a".to_string(), host_a);
        snapshots.insert("host-b".to_string(), host_b);

        ConsistentCut {
            snapshot_id: "test-snapshot".to_string(),
            host_snapshots: snapshots,
            validity: CutValidity::Complete,
            assembled_at: Utc::now(),
            confirmed_count: 2,
            tentative_count: 0,
            failed_count: 0,
        }
    }

    #[test]
    fn blocks_kill_of_dependency() {
        let cut = build_test_cut();
        let config = SnapshotConfig::default();

        // Try to kill host-b:200 (the database).
        let result = check_causal_safety(&cut, "host-b", 200, &config);
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].dependent_host, "host-a");
        assert_eq!(result.violations[0].dependent_pid, 100);
        assert_eq!(result.violations[0].dep_type, DependencyType::TcpConnection);
    }

    #[test]
    fn allows_kill_of_non_dependency() {
        let cut = build_test_cut();
        let config = SnapshotConfig::default();

        // Kill a process that nobody depends on.
        let result = check_causal_safety(&cut, "host-b", 999, &config);
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn blocks_all_kills_on_invalid_cut() {
        let mut cut = build_test_cut();
        cut.validity = CutValidity::Invalid;
        cut.tentative_count = 1;
        cut.failed_count = 1;
        let config = SnapshotConfig::default();

        // Even a harmless kill is blocked.
        let result = check_causal_safety(&cut, "host-b", 999, &config);
        assert!(!result.allowed);
    }

    #[test]
    fn blocks_kills_on_partial_cut_by_default() {
        let mut cut = build_test_cut();
        cut.validity = CutValidity::Partial;
        cut.tentative_count = 1;
        let config = SnapshotConfig {
            allow_kills_on_partial_cut: false,
            ..Default::default()
        };

        let result = check_causal_safety(&cut, "host-b", 999, &config);
        assert!(!result.allowed);
    }

    #[test]
    fn allows_kills_on_partial_cut_when_configured() {
        let mut cut = build_test_cut();
        cut.validity = CutValidity::Partial;
        cut.tentative_count = 1;
        let config = SnapshotConfig {
            allow_kills_on_partial_cut: true,
            ..Default::default()
        };

        // Non-dependency kill is allowed on partial cut.
        let result = check_causal_safety(&cut, "host-b", 999, &config);
        assert!(result.allowed);
    }

    #[test]
    fn dependency_of_non_useful_process_allowed() {
        let mut cut = build_test_cut();
        // Reclassify the web server as Abandoned (not Useful).
        let host_a = cut.host_snapshots.get_mut("host-a").unwrap();
        host_a.useful_pids.clear();
        let config = SnapshotConfig::default();

        // Killing the database is now OK — the web server isn't Useful.
        let result = check_causal_safety(&cut, "host-b", 200, &config);
        assert!(result.allowed);
    }

    #[test]
    fn multiple_violations_collected() {
        let mut host_a = HostSnapshot::confirmed("host-a");
        let mut host_c = HostSnapshot::confirmed("host-c");

        // Two Useful processes on different hosts depend on host-b:200.
        host_a.useful_pids.insert(100);
        host_a.process_deps.insert(
            100,
            vec![RemoteDependency {
                remote_host: "host-b".to_string(),
                remote_pid: 200,
                dep_type: DependencyType::TcpConnection,
            }],
        );

        host_c.useful_pids.insert(300);
        host_c.process_deps.insert(
            300,
            vec![RemoteDependency {
                remote_host: "host-b".to_string(),
                remote_pid: 200,
                dep_type: DependencyType::SharedService,
            }],
        );

        let mut snapshots = HashMap::new();
        snapshots.insert("host-a".to_string(), host_a);
        snapshots.insert("host-b".to_string(), HostSnapshot::confirmed("host-b"));
        snapshots.insert("host-c".to_string(), host_c);

        let cut = ConsistentCut {
            snapshot_id: "test".to_string(),
            host_snapshots: snapshots,
            validity: CutValidity::Complete,
            assembled_at: Utc::now(),
            confirmed_count: 3,
            tentative_count: 0,
            failed_count: 0,
        };

        let result = check_causal_safety(&cut, "host-b", 200, &SnapshotConfig::default());
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 2);
    }

    // ── SnapshotConfig ────────────────────────────────────────────────

    #[test]
    fn default_config_is_conservative() {
        let config = SnapshotConfig::default();
        assert!(!config.allow_kills_on_partial_cut);
        assert_eq!(config.marker_timeout_ms, 5000);
        assert!((config.max_tentative_fraction - 0.3).abs() < f64::EPSILON);
    }
}
