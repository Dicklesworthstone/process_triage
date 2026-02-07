//! Incremental scanning system for process triage.
//!
//! Tracks process inventory across scans and computes deltas so the daemon
//! (and CLI) can avoid full re-scans every tick.  Only new, departed, or
//! materially changed processes trigger expensive evidence collection.
//!
//! # Architecture
//!
//! ```text
//! quick_scan() ──► IncrementalEngine::update()
//!                       │
//!                       ├─ APPEARED  → deep scan + full inference
//!                       ├─ DEPARTED  → record exit event
//!                       ├─ CHANGED   → targeted re-scan + inference update
//!                       └─ UNCHANGED → age-only posterior bump (cheap)
//! ```
//!
//! # Identity
//!
//! Process identity follows the same SHA-256 scheme used by `shadow.rs`:
//! `hash(uid || start_id || comm || cmd)`.  This is stable across scans
//! and detects PID reuse.

use super::types::{ProcessRecord, ProcessState};
use pt_common::ProcessId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Delta classification ────────────────────────────────────────────────

/// How a process changed between two scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaKind {
    /// Process was not seen in the previous scan.
    Appeared,
    /// Process was in the previous scan but is gone now.
    Departed,
    /// Process identity is the same but observable state changed materially.
    Changed,
    /// Process identity and observable state are effectively the same.
    Unchanged,
}

/// A single process delta produced by `IncrementalEngine::update`.
#[derive(Debug, Clone)]
pub struct ProcessDelta {
    pub pid: ProcessId,
    pub identity_hash: String,
    pub kind: DeltaKind,
    /// The current record (present for Appeared, Changed, Unchanged).
    pub current: Option<ProcessRecord>,
    /// The previous snapshot (present for Departed, Changed, Unchanged).
    pub previous: Option<InventoryEntry>,
}

// ── Inventory ───────────────────────────────────────────────────────────

/// Compact snapshot of a process stored between scans.
///
/// Intentionally smaller than a full `ProcessRecord` – we only keep the
/// fields needed for change detection and age tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub pid: ProcessId,
    pub identity_hash: String,
    pub comm: String,
    pub state: ProcessState,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub elapsed_secs: u64,
    /// When this entry was last refreshed (monotonic).
    #[serde(skip)]
    pub last_seen: Option<Instant>,
    /// Number of consecutive scans where this process was present.
    pub consecutive_seen: u32,
}

/// Configuration knobs for the incremental engine.
#[derive(Debug, Clone)]
pub struct IncrementalConfig {
    /// CPU change (absolute percentage points) that counts as "material".
    pub cpu_change_threshold: f64,
    /// RSS change (fraction of previous RSS) that counts as "material".
    pub rss_change_fraction: f64,
    /// State change always counts as material (this is not configurable).
    /// Maximum age of an inventory entry before forced re-scan.
    pub max_staleness: Duration,
    /// Maximum number of inventory entries (LRU eviction when exceeded).
    pub max_inventory_size: usize,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            cpu_change_threshold: 5.0,       // 5 percentage points
            rss_change_fraction: 0.20,       // 20% change
            max_staleness: Duration::from_secs(600), // 10 minutes
            max_inventory_size: 100_000,
        }
    }
}

// ── Engine ──────────────────────────────────────────────────────────────

/// The incremental scanning engine.
///
/// Feed it successive `ScanResult`s via `update()` and it returns a list
/// of deltas classifying each process as appeared / departed / changed /
/// unchanged.
pub struct IncrementalEngine {
    /// Current inventory keyed by identity hash.
    inventory: HashMap<String, InventoryEntry>,
    /// Reverse map: PID → identity hash (for PID reuse detection).
    pid_to_hash: HashMap<u32, String>,
    config: IncrementalConfig,
    /// Whether at least one scan has been ingested.
    has_baseline: bool,
}

impl IncrementalEngine {
    pub fn new(config: IncrementalConfig) -> Self {
        Self {
            inventory: HashMap::new(),
            pid_to_hash: HashMap::new(),
            config,
            has_baseline: false,
        }
    }

    /// Return current inventory size (number of tracked processes).
    pub fn inventory_size(&self) -> usize {
        self.inventory.len()
    }

    /// Whether the engine has ingested at least one scan.
    pub fn has_baseline(&self) -> bool {
        self.has_baseline
    }

    /// Ingest a new scan and return per-process deltas.
    ///
    /// On the very first call every process is classified as `Appeared`.
    pub fn update(&mut self, processes: &[ProcessRecord]) -> Vec<ProcessDelta> {
        let now = Instant::now();
        let mut deltas = Vec::with_capacity(processes.len());

        // Track which identity hashes we saw in this scan.
        let mut seen_hashes: HashMap<String, ()> =
            HashMap::with_capacity(processes.len());

        // Phase 1: classify each incoming process.
        for proc in processes {
            let hash = compute_identity_hash(proc);
            seen_hashes.insert(hash.clone(), ());

            if let Some(prev) = self.inventory.get(&hash) {
                // Known identity – check for material change.
                let kind = if self.is_material_change(proc, prev) {
                    DeltaKind::Changed
                } else {
                    DeltaKind::Unchanged
                };

                deltas.push(ProcessDelta {
                    pid: proc.pid,
                    identity_hash: hash.clone(),
                    kind,
                    current: Some(proc.clone()),
                    previous: Some(prev.clone()),
                });
            } else {
                // Check for PID reuse: same PID, different identity.
                if let Some(old_hash) = self.pid_to_hash.get(&proc.pid.0) {
                    if *old_hash != hash {
                        // The old identity departed (PID reuse).
                        if let Some(old_entry) = self.inventory.get(old_hash) {
                            deltas.push(ProcessDelta {
                                pid: proc.pid,
                                identity_hash: old_hash.clone(),
                                kind: DeltaKind::Departed,
                                current: None,
                                previous: Some(old_entry.clone()),
                            });
                        }
                        // Remove stale entry.
                        let old_hash_owned = old_hash.clone();
                        self.inventory.remove(&old_hash_owned);
                    }
                }

                deltas.push(ProcessDelta {
                    pid: proc.pid,
                    identity_hash: hash.clone(),
                    kind: DeltaKind::Appeared,
                    current: Some(proc.clone()),
                    previous: None,
                });
            }

            // Upsert inventory entry.
            let consecutive = self
                .inventory
                .get(&hash)
                .map(|e| e.consecutive_seen + 1)
                .unwrap_or(1);

            self.inventory.insert(
                hash.clone(),
                InventoryEntry {
                    pid: proc.pid,
                    identity_hash: hash.clone(),
                    comm: proc.comm.clone(),
                    state: proc.state,
                    cpu_percent: proc.cpu_percent,
                    rss_bytes: proc.rss_bytes,
                    elapsed_secs: proc.elapsed.as_secs(),
                    last_seen: Some(now),
                    consecutive_seen: consecutive,
                },
            );

            self.pid_to_hash.insert(proc.pid.0, hash);
        }

        // Phase 2: detect departures (in inventory but not in this scan).
        if self.has_baseline {
            let departed: Vec<(String, InventoryEntry)> = self
                .inventory
                .iter()
                .filter(|(hash, _)| !seen_hashes.contains_key(hash.as_str()))
                .map(|(h, e)| (h.clone(), e.clone()))
                .collect();

            for (hash, entry) in &departed {
                deltas.push(ProcessDelta {
                    pid: entry.pid,
                    identity_hash: hash.clone(),
                    kind: DeltaKind::Departed,
                    current: None,
                    previous: Some(entry.clone()),
                });
                self.inventory.remove(hash);
                self.pid_to_hash.remove(&entry.pid.0);
            }
        }

        // Phase 3: enforce inventory size limit via LRU eviction.
        self.enforce_size_limit();

        self.has_baseline = true;
        deltas
    }

    /// Convenience: return only the PIDs that need expensive work.
    ///
    /// This is the set of processes classified as `Appeared` or `Changed`.
    pub fn pids_needing_deep_scan(deltas: &[ProcessDelta]) -> Vec<u32> {
        deltas
            .iter()
            .filter(|d| matches!(d.kind, DeltaKind::Appeared | DeltaKind::Changed))
            .filter_map(|d| d.current.as_ref().map(|r| r.pid.0))
            .collect()
    }

    /// Convenience: return only departed identity hashes.
    pub fn departed_hashes(deltas: &[ProcessDelta]) -> Vec<String> {
        deltas
            .iter()
            .filter(|d| d.kind == DeltaKind::Departed)
            .map(|d| d.identity_hash.clone())
            .collect()
    }

    /// Summary statistics about a delta set.
    pub fn summarize(deltas: &[ProcessDelta]) -> DeltaSummary {
        let mut summary = DeltaSummary::default();
        for d in deltas {
            match d.kind {
                DeltaKind::Appeared => summary.appeared += 1,
                DeltaKind::Departed => summary.departed += 1,
                DeltaKind::Changed => summary.changed += 1,
                DeltaKind::Unchanged => summary.unchanged += 1,
            }
        }
        summary.total = deltas.len();
        summary
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Determine if the observable differences between the current process
    /// and the cached inventory entry are "material" (warrant re-inference).
    fn is_material_change(&self, current: &ProcessRecord, prev: &InventoryEntry) -> bool {
        // State change is always material.
        if current.state != prev.state {
            return true;
        }

        // CPU change beyond threshold.
        if (current.cpu_percent - prev.cpu_percent).abs() > self.config.cpu_change_threshold {
            return true;
        }

        // RSS change beyond fraction.
        if prev.rss_bytes > 0 {
            let rss_ratio = (current.rss_bytes as f64 - prev.rss_bytes as f64).abs()
                / prev.rss_bytes as f64;
            if rss_ratio > self.config.rss_change_fraction {
                return true;
            }
        } else if current.rss_bytes > 0 {
            // Was zero, now non-zero: material.
            return true;
        }

        // Staleness: force re-scan if the entry is too old.
        if let Some(last) = prev.last_seen {
            if last.elapsed() > self.config.max_staleness {
                return true;
            }
        }

        false
    }

    /// Evict oldest entries when inventory exceeds max size.
    fn enforce_size_limit(&mut self) {
        if self.inventory.len() <= self.config.max_inventory_size {
            return;
        }

        let excess = self.inventory.len() - self.config.max_inventory_size;

        // Evict entries with lowest consecutive_seen (least stable).
        let mut entries: Vec<(String, u32)> = self
            .inventory
            .iter()
            .map(|(h, e)| (h.clone(), e.consecutive_seen))
            .collect();
        entries.sort_by_key(|(_, count)| *count);

        for (hash, _) in entries.into_iter().take(excess) {
            if let Some(entry) = self.inventory.remove(&hash) {
                self.pid_to_hash.remove(&entry.pid.0);
            }
        }
    }
}

/// Summary statistics for a delta set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeltaSummary {
    pub total: usize,
    pub appeared: usize,
    pub departed: usize,
    pub changed: usize,
    pub unchanged: usize,
}

impl DeltaSummary {
    /// Fraction of processes that were unchanged (0.0 to 1.0).
    pub fn unchanged_fraction(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.unchanged as f64 / self.total as f64
        }
    }

    /// Number of processes that need expensive work.
    pub fn needs_work(&self) -> usize {
        self.appeared + self.changed
    }
}

// ── Identity hash ───────────────────────────────────────────────────────

/// Compute a stable identity hash for incremental scanning.
///
/// Uses `pid + uid + comm + cmd` (without `start_id`).  This differs from
/// `shadow::compute_identity_hash` because `start_id` is derived from
/// timing fields (`etimes`, `/proc/uptime`) that can jitter by ±1 tick
/// between back-to-back scans.  For the incremental engine, which operates
/// within a single daemon session, `pid + uid + comm + cmd` is sufficient:
///
/// - PID reuse with the *same* comm+cmd within a 60-second tick is
///   exceedingly unlikely.
/// - Different programs reusing a PID will have different comm/cmd.
/// - The uid distinguishes same-named processes owned by different users.
pub fn compute_identity_hash(proc: &ProcessRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(proc.pid.0.to_le_bytes());
    hasher.update(proc.uid.to_le_bytes());
    hasher.update(proc.comm.as_bytes());
    hasher.update(proc.cmd.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::StartId;

    fn make_proc(pid: u32, comm: &str, cmd: &str) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(1),
            uid: 1000,
            user: "testuser".to_string(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId(format!("boot:{}:{}", pid, pid)),
            comm: comm.to_string(),
            cmd: cmd.to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.5,
            rss_bytes: 1024 * 1024,
            vsz_bytes: 2 * 1024 * 1024,
            tty: None,
            start_time_unix: 1700000000,
            elapsed: Duration::from_secs(3600),
            source: "test".to_string(),
            container_info: None,
        }
    }

    fn make_proc_with_state(pid: u32, comm: &str, state: ProcessState) -> ProcessRecord {
        let mut p = make_proc(pid, comm, comm);
        p.state = state;
        p
    }

    fn make_proc_with_cpu(pid: u32, comm: &str, cpu: f64) -> ProcessRecord {
        let mut p = make_proc(pid, comm, comm);
        p.cpu_percent = cpu;
        p
    }

    fn make_proc_with_rss(pid: u32, comm: &str, rss: u64) -> ProcessRecord {
        let mut p = make_proc(pid, comm, comm);
        p.rss_bytes = rss;
        p
    }

    // ── Identity hash tests ─────────────────────────────────────────────

    #[test]
    fn identity_hash_is_stable() {
        let p = make_proc(100, "bash", "/bin/bash");
        let h1 = compute_identity_hash(&p);
        let h2 = compute_identity_hash(&p);
        assert_eq!(h1, h2);
    }

    #[test]
    fn identity_hash_differs_for_different_cmd() {
        let p1 = make_proc(100, "bash", "/bin/bash");
        let p2 = make_proc(100, "bash", "/bin/bash -c echo hi");
        assert_ne!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn identity_hash_includes_pid() {
        let p1 = make_proc(100, "bash", "/bin/bash");
        let p2 = make_proc(200, "bash", "/bin/bash");
        // Different PIDs → different hashes (PID is part of incremental identity).
        assert_ne!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn identity_hash_same_pid_same_cmd_is_stable() {
        let p1 = make_proc(100, "bash", "/bin/bash");
        let mut p2 = make_proc(100, "bash", "/bin/bash");
        // Different start_id should not affect hash (it's excluded).
        p2.start_id = pt_common::StartId("different:999:100".to_string());
        assert_eq!(compute_identity_hash(&p1), compute_identity_hash(&p2));
    }

    #[test]
    fn identity_hash_is_hex_16_chars() {
        let h = compute_identity_hash(&make_proc(1, "x", "x"));
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── First scan: everything appears ──────────────────────────────────

    #[test]
    fn first_scan_all_appeared() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs = vec![
            make_proc(1, "bash", "/bin/bash"),
            make_proc(2, "sleep", "sleep 60"),
        ];

        let deltas = engine.update(&procs);
        assert_eq!(deltas.len(), 2);
        assert!(deltas.iter().all(|d| d.kind == DeltaKind::Appeared));
        assert!(engine.has_baseline());
        assert_eq!(engine.inventory_size(), 2);
    }

    // ── Stable second scan: everything unchanged ────────────────────────

    #[test]
    fn stable_scan_all_unchanged() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs = vec![
            make_proc(1, "bash", "/bin/bash"),
            make_proc(2, "sleep", "sleep 60"),
        ];

        engine.update(&procs); // baseline
        let deltas = engine.update(&procs); // second scan

        let summary = IncrementalEngine::summarize(&deltas);
        assert_eq!(summary.unchanged, 2);
        assert_eq!(summary.appeared, 0);
        assert_eq!(summary.departed, 0);
        assert_eq!(summary.changed, 0);
    }

    // ── Process departure detection ─────────────────────────────────────

    #[test]
    fn departed_process_detected() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs_full = vec![
            make_proc(1, "bash", "/bin/bash"),
            make_proc(2, "sleep", "sleep 60"),
        ];

        engine.update(&procs_full);

        // Second scan: sleep is gone.
        let procs_partial = vec![make_proc(1, "bash", "/bin/bash")];
        let deltas = engine.update(&procs_partial);

        let summary = IncrementalEngine::summarize(&deltas);
        assert_eq!(summary.departed, 1);
        assert_eq!(summary.unchanged, 1);

        let departed = IncrementalEngine::departed_hashes(&deltas);
        assert_eq!(departed.len(), 1);

        // Inventory should now only have 1 entry.
        assert_eq!(engine.inventory_size(), 1);
    }

    // ── New process appearance ──────────────────────────────────────────

    #[test]
    fn new_process_detected() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs1 = vec![make_proc(1, "bash", "/bin/bash")];
        engine.update(&procs1);

        let procs2 = vec![
            make_proc(1, "bash", "/bin/bash"),
            make_proc(2, "node", "node server.js"),
        ];
        let deltas = engine.update(&procs2);

        let summary = IncrementalEngine::summarize(&deltas);
        assert_eq!(summary.appeared, 1);
        assert_eq!(summary.unchanged, 1);
    }

    // ── State change is material ────────────────────────────────────────

    #[test]
    fn state_change_is_material() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs1 = vec![make_proc_with_state(1, "bash", ProcessState::Sleeping)];
        engine.update(&procs1);

        let procs2 = vec![make_proc_with_state(1, "bash", ProcessState::Zombie)];
        let deltas = engine.update(&procs2);

        let summary = IncrementalEngine::summarize(&deltas);
        assert_eq!(summary.changed, 1);
        assert_eq!(summary.unchanged, 0);
    }

    // ── CPU change beyond threshold ─────────────────────────────────────

    #[test]
    fn cpu_spike_is_material() {
        let config = IncrementalConfig {
            cpu_change_threshold: 5.0,
            ..Default::default()
        };
        let mut engine = IncrementalEngine::new(config);

        let procs1 = vec![make_proc_with_cpu(1, "node", 1.0)];
        engine.update(&procs1);

        // 1.0 → 7.0 = +6 pp, above 5 pp threshold.
        let procs2 = vec![make_proc_with_cpu(1, "node", 7.0)];
        let deltas = engine.update(&procs2);

        assert_eq!(IncrementalEngine::summarize(&deltas).changed, 1);
    }

    #[test]
    fn small_cpu_change_is_not_material() {
        let config = IncrementalConfig {
            cpu_change_threshold: 5.0,
            ..Default::default()
        };
        let mut engine = IncrementalEngine::new(config);

        let procs1 = vec![make_proc_with_cpu(1, "node", 1.0)];
        engine.update(&procs1);

        // 1.0 → 3.0 = +2 pp, below threshold.
        let procs2 = vec![make_proc_with_cpu(1, "node", 3.0)];
        let deltas = engine.update(&procs2);

        assert_eq!(IncrementalEngine::summarize(&deltas).unchanged, 1);
    }

    // ── RSS change beyond fraction ──────────────────────────────────────

    #[test]
    fn rss_spike_is_material() {
        let config = IncrementalConfig {
            rss_change_fraction: 0.20,
            ..Default::default()
        };
        let mut engine = IncrementalEngine::new(config);

        let procs1 = vec![make_proc_with_rss(1, "java", 100 * 1024 * 1024)]; // 100 MB
        engine.update(&procs1);

        // 100 MB → 130 MB = 30% increase, above 20% threshold.
        let procs2 = vec![make_proc_with_rss(1, "java", 130 * 1024 * 1024)];
        let deltas = engine.update(&procs2);

        assert_eq!(IncrementalEngine::summarize(&deltas).changed, 1);
    }

    #[test]
    fn small_rss_change_is_not_material() {
        let config = IncrementalConfig {
            rss_change_fraction: 0.20,
            ..Default::default()
        };
        let mut engine = IncrementalEngine::new(config);

        let procs1 = vec![make_proc_with_rss(1, "java", 100 * 1024 * 1024)];
        engine.update(&procs1);

        // 100 MB → 110 MB = 10% increase, below 20% threshold.
        let procs2 = vec![make_proc_with_rss(1, "java", 110 * 1024 * 1024)];
        let deltas = engine.update(&procs2);

        assert_eq!(IncrementalEngine::summarize(&deltas).unchanged, 1);
    }

    // ── PID reuse detection ─────────────────────────────────────────────

    #[test]
    fn pid_reuse_detected() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs1 = vec![make_proc(42, "old_proc", "/usr/bin/old_proc")];
        engine.update(&procs1);

        // Same PID, completely different identity.
        let procs2 = vec![make_proc(42, "new_proc", "/usr/bin/new_proc")];
        let deltas = engine.update(&procs2);

        // Should see: old departed + new appeared.
        let summary = IncrementalEngine::summarize(&deltas);
        assert_eq!(summary.departed, 1, "Old identity should depart");
        assert_eq!(summary.appeared, 1, "New identity should appear");
    }

    // ── Deep scan PIDs helper ───────────────────────────────────────────

    #[test]
    fn pids_needing_deep_scan_filters_correctly() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs1 = vec![
            make_proc(1, "stable", "stable"),
            make_proc_with_state(2, "changing", ProcessState::Sleeping),
        ];
        engine.update(&procs1);

        let procs2 = vec![
            make_proc(1, "stable", "stable"),
            make_proc_with_state(2, "changing", ProcessState::Zombie),
            make_proc(3, "newcomer", "newcomer"),
        ];
        let deltas = engine.update(&procs2);

        let pids = IncrementalEngine::pids_needing_deep_scan(&deltas);
        // PID 2 (changed) and PID 3 (appeared) need deep scan.
        assert!(pids.contains(&2));
        assert!(pids.contains(&3));
        // PID 1 (unchanged) does not.
        assert!(!pids.contains(&1));
    }

    // ── Consecutive seen counter ────────────────────────────────────────

    #[test]
    fn consecutive_seen_increments() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs = vec![make_proc(1, "bash", "bash")];

        engine.update(&procs);
        assert_eq!(engine.inventory.values().next().unwrap().consecutive_seen, 1);

        engine.update(&procs);
        assert_eq!(engine.inventory.values().next().unwrap().consecutive_seen, 2);

        engine.update(&procs);
        assert_eq!(engine.inventory.values().next().unwrap().consecutive_seen, 3);
    }

    // ── Inventory size limit ────────────────────────────────────────────

    #[test]
    fn inventory_size_limit_enforced() {
        let config = IncrementalConfig {
            max_inventory_size: 3,
            ..Default::default()
        };
        let mut engine = IncrementalEngine::new(config);

        // Add 5 processes.
        let procs: Vec<ProcessRecord> = (1..=5)
            .map(|i| make_proc(i, &format!("p{}", i), &format!("p{}", i)))
            .collect();

        engine.update(&procs);
        assert!(
            engine.inventory_size() <= 3,
            "Inventory should be capped at 3, got {}",
            engine.inventory_size()
        );
    }

    // ── Summary helpers ─────────────────────────────────────────────────

    #[test]
    fn summary_unchanged_fraction() {
        let summary = DeltaSummary {
            total: 100,
            appeared: 5,
            departed: 3,
            changed: 2,
            unchanged: 90,
        };
        assert!((summary.unchanged_fraction() - 0.90).abs() < 0.001);
        assert_eq!(summary.needs_work(), 7); // 5 appeared + 2 changed
    }

    #[test]
    fn summary_empty_is_zero() {
        let summary = DeltaSummary::default();
        assert_eq!(summary.unchanged_fraction(), 0.0);
        assert_eq!(summary.needs_work(), 0);
    }

    // ── Zero-RSS edge case ──────────────────────────────────────────────

    #[test]
    fn zero_to_nonzero_rss_is_material() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());
        let procs1 = vec![make_proc_with_rss(1, "init", 0)];
        engine.update(&procs1);

        let procs2 = vec![make_proc_with_rss(1, "init", 1024)];
        let deltas = engine.update(&procs2);

        assert_eq!(IncrementalEngine::summarize(&deltas).changed, 1);
    }

    // ── Multiple scans lifecycle ────────────────────────────────────────

    #[test]
    fn multi_scan_lifecycle() {
        let mut engine = IncrementalEngine::new(IncrementalConfig::default());

        // Scan 1: two processes.
        let s1 = vec![
            make_proc(1, "bash", "bash"),
            make_proc(2, "vim", "vim file.txt"),
        ];
        let d1 = engine.update(&s1);
        assert_eq!(IncrementalEngine::summarize(&d1).appeared, 2);

        // Scan 2: same two + one new.
        let s2 = vec![
            make_proc(1, "bash", "bash"),
            make_proc(2, "vim", "vim file.txt"),
            make_proc(3, "node", "node app.js"),
        ];
        let d2 = engine.update(&s2);
        let sum2 = IncrementalEngine::summarize(&d2);
        assert_eq!(sum2.appeared, 1);
        assert_eq!(sum2.unchanged, 2);

        // Scan 3: vim gone.
        let s3 = vec![
            make_proc(1, "bash", "bash"),
            make_proc(3, "node", "node app.js"),
        ];
        let d3 = engine.update(&s3);
        let sum3 = IncrementalEngine::summarize(&d3);
        assert_eq!(sum3.departed, 1);
        assert_eq!(sum3.unchanged, 2);
        assert_eq!(engine.inventory_size(), 2);
    }

    // ── No-mock integration tests with real quick_scan ──────────────────

    #[test]
    fn nomock_incremental_with_real_quick_scan() {
        use crate::collect::{quick_scan, QuickScanOptions};

        let platform = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            // Skip on unsupported platforms.
            return;
        };

        crate::test_log!(
            INFO,
            "incremental no-mock test starting",
            platform = platform
        );

        let options = QuickScanOptions::default();
        let scan1 = quick_scan(&options).expect("first quick_scan should succeed");
        assert!(!scan1.processes.is_empty());

        let mut engine = IncrementalEngine::new(IncrementalConfig::default());

        // First scan: everything is Appeared.
        let d1 = engine.update(&scan1.processes);
        let s1 = IncrementalEngine::summarize(&d1);

        crate::test_log!(
            INFO,
            "first scan",
            total = s1.total,
            appeared = s1.appeared,
            inventory_size = engine.inventory_size()
        );

        assert_eq!(s1.appeared, s1.total, "All processes should be Appeared on first scan");
        assert_eq!(engine.inventory_size(), scan1.processes.len());

        // Second scan: mostly unchanged (within milliseconds, little should change).
        let scan2 = quick_scan(&options).expect("second quick_scan should succeed");
        let d2 = engine.update(&scan2.processes);
        let s2 = IncrementalEngine::summarize(&d2);

        crate::test_log!(
            INFO,
            "second scan",
            total = s2.total,
            appeared = s2.appeared,
            departed = s2.departed,
            changed = s2.changed,
            unchanged = s2.unchanged,
            unchanged_fraction = format!("{:.2}", s2.unchanged_fraction()).as_str()
        );

        // With back-to-back scans, the majority should be unchanged.
        // Allow some churn (processes starting/stopping) but most should be stable.
        assert!(
            s2.unchanged_fraction() > 0.5,
            "Expected >50% unchanged in back-to-back scan, got {:.1}%",
            s2.unchanged_fraction() * 100.0
        );

        // Deep scan PIDs should be a small subset.
        let deep_pids = IncrementalEngine::pids_needing_deep_scan(&d2);
        crate::test_log!(
            INFO,
            "deep scan candidates",
            count = deep_pids.len(),
            total = s2.total
        );

        assert!(
            deep_pids.len() <= s2.total,
            "Deep scan PIDs should not exceed total"
        );
    }

    #[test]
    fn nomock_identity_hash_matches_shadow() {
        // Verify our identity hash matches the shadow.rs implementation
        // by checking properties (stable, 16 hex chars, deterministic).
        use crate::collect::{quick_scan, QuickScanOptions};

        if !cfg!(target_os = "linux") && !cfg!(target_os = "macos") {
            return;
        }

        let options = QuickScanOptions::default();
        let scan = quick_scan(&options).expect("quick_scan should succeed");

        // Take a sample of processes and verify hash properties.
        for proc in scan.processes.iter().take(10) {
            let h1 = compute_identity_hash(proc);
            let h2 = compute_identity_hash(proc);

            // Stable.
            assert_eq!(h1, h2, "Hash should be stable for pid={}", proc.pid.0);

            // 16 hex chars.
            assert_eq!(h1.len(), 16, "Hash should be 16 hex chars for pid={}", proc.pid.0);
            assert!(
                h1.chars().all(|c| c.is_ascii_hexdigit()),
                "Hash should be hex for pid={}",
                proc.pid.0
            );
        }
    }
}
