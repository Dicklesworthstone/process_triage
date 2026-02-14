//! CPU tick-delta feature computation for process triage.
//!
//! This module computes canonical CPU occupancy features from Plan §3.2:
//! - `k_ticks`: CPU time consumed (utime + stime delta)
//! - `n_ticks`: Tick budget for the sample window
//! - `u`: CPU occupancy ratio (k_ticks / n_ticks), clamped to \[0,1\]
//! - `u_cores`: CPU cores worth of utilization
//! - `n_eff`: Effective sample size (correlation-corrected)
//!
//! These features feed directly into the Beta-Binomial CPU occupancy model.
//!
//! # Data Sources
//! - `/proc/[pid]/stat`: utime, stime, num_threads
//! - System CLK_TCK via sysconf(_SC_CLK_TCK)

use super::cgroup::collect_cgroup_details;
use super::cpu_capacity::{compute_cpu_capacity, CpuCapacity};
use pt_common::{IdentityQuality, ProcessIdentity, StartId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// System clock ticks per second.
/// On Linux, typically 100 (USER_HZ).
#[cfg(unix)]
pub fn clk_tck() -> u64 {
    static CLK_TCK: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CLK_TCK.get_or_init(|| {
        let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if tck > 0 {
            tck as u64
        } else {
            100 // Default fallback
        }
    })
}

#[cfg(not(unix))]
pub fn clk_tck() -> u64 {
    100 // Fallback for non-Unix
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> Option<String> {
    static BOOT_ID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .clone()
}

#[cfg(not(target_os = "linux"))]
fn read_boot_id() -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn read_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut parts = rest.split_whitespace();
            if let Some(uid_str) = parts.next() {
                return uid_str.parse::<u32>().ok();
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_uid(_pid: u32) -> Option<u32> {
    None
}

fn system_time_to_unix_us(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_micros() as u64)
}

fn build_identity(pid: u32, starttime: u64) -> ProcessIdentity {
    let boot_id = read_boot_id();
    let uid = read_uid(pid);
    let uid_known = uid.is_some();
    let uid = uid.unwrap_or(0);
    let boot = boot_id.as_deref().unwrap_or("unknown");
    #[cfg(target_os = "linux")]
    let start_id = StartId::from_linux(boot, starttime, pid);
    #[cfg(not(target_os = "linux"))]
    let start_id = StartId::from_macos(boot, starttime, pid);

    let mut identity = ProcessIdentity::new(pid, start_id, uid);
    identity.quality = match (boot_id.is_some(), uid_known) {
        (true, true) => IdentityQuality::Full,
        (false, true) => IdentityQuality::NoBootId,
        _ => IdentityQuality::PidOnly,
    };
    identity
}

/// Raw tick data from /proc/\[pid\]/stat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickSnapshot {
    /// Process ID.
    pub pid: u32,

    /// Process identity tuple (pid, start_id, uid).
    pub identity: ProcessIdentity,

    /// User time in clock ticks.
    pub utime: u64,

    /// System time in clock ticks.
    pub stime: u64,

    /// Combined utime + stime.
    pub total_ticks: u64,

    /// Number of threads.
    pub num_threads: u32,

    /// Timestamp when snapshot was taken.
    pub timestamp: std::time::SystemTime,

    /// Monotonic timestamp for precise duration calculation (not serialized).
    #[serde(skip, default)]
    pub monotonic: Option<std::time::Instant>,

    /// Process start time (for identity validation).
    pub starttime: u64,
}

/// CPU tick-delta features for a sample window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickDeltaFeatures {
    /// CPU ticks consumed in the window (Δ(utime + stime)).
    pub k_ticks: u64,

    /// Tick budget for the window (CLK_TCK * Δt * min(N_eff_cores, threads)).
    pub n_ticks: u64,

    /// CPU occupancy ratio: k_ticks / n_ticks, clamped to [0, 1].
    pub u: f64,

    /// CPU cores worth of utilization: k_ticks / (CLK_TCK * Δt).
    pub u_cores: f64,

    /// Effective sample size (correlation-corrected n_ticks).
    pub n_eff: u64,

    /// Sample window duration in seconds.
    pub delta_t_secs: f64,

    /// Process identity tuple for the sample window.
    pub identity: ProcessIdentity,

    /// CPU capacity information.
    pub cpu_capacity: CpuCapacity,

    /// Provenance tracking.
    pub provenance: TickDeltaProvenance,
}

/// Provenance for tick-delta computation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TickDeltaProvenance {
    /// System CLK_TCK value used.
    pub clk_tck: u64,

    /// Number of threads at sample end.
    pub threads: u32,

    /// N_eff_cores used in computation.
    pub n_eff_cores: f64,

    /// The constraint that limited n_ticks (threads vs N_eff_cores).
    pub budget_constraint: BudgetConstraint,

    /// n_eff correction policy applied.
    pub n_eff_policy: NEffPolicy,

    /// Optional parameter for n_eff policy (e.g., reduction factor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_eff_param: Option<f64>,

    /// Sample start timestamp in Unix microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_start_unix_us: Option<u64>,

    /// Sample end timestamp in Unix microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_end_unix_us: Option<u64>,

    /// Source of tick counts (k_ticks).
    pub tick_source: String,

    /// Source of thread count.
    pub thread_source: String,

    /// Any warnings during computation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// What limited the tick budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetConstraint {
    /// Limited by number of threads.
    Threads,
    /// Limited by effective CPU cores (N_eff_cores).
    Cores,
    /// Both constraints equal.
    #[default]
    Equal,
}

/// Policy for n_eff (effective sample size) correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NEffPolicy {
    /// No correction: n_eff = n_ticks.
    #[default]
    Identity,
    /// Fixed reduction factor (e.g., n_eff = n_ticks / 2).
    FixedReduction,
    /// Autocorrelation-based correction (future).
    Autocorrelation,
}

/// Configuration for tick-delta computation.
#[derive(Debug, Clone)]
pub struct TickDeltaConfig {
    /// Policy for computing n_eff.
    pub n_eff_policy: NEffPolicy,

    /// Fixed reduction factor for FixedReduction policy.
    pub reduction_factor: f64,
}

impl Default for TickDeltaConfig {
    fn default() -> Self {
        Self {
            n_eff_policy: NEffPolicy::Identity,
            reduction_factor: 2.0,
        }
    }
}

/// Collect a tick snapshot for a process.
///
/// # Arguments
/// * `pid` - Process ID to snapshot
///
/// # Returns
/// * `Option<TickSnapshot>` - Snapshot or None if process not accessible
pub fn collect_tick_snapshot(pid: u32) -> Option<TickSnapshot> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).ok()?;
    let timestamp = std::time::SystemTime::now();
    let monotonic = std::time::Instant::now();

    let mut snapshot = parse_tick_snapshot(&content, pid, timestamp)?;
    snapshot.monotonic = Some(monotonic);
    Some(snapshot)
}

/// Parse tick snapshot from /proc/\[pid\]/stat content.
pub fn parse_tick_snapshot(
    content: &str,
    pid: u32,
    timestamp: std::time::SystemTime,
) -> Option<TickSnapshot> {
    // Find comm field (surrounded by parentheses)
    let comm_end = content.rfind(')')?;
    let after_comm = content.get(comm_end + 2..)?;

    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }

    // Field indices (0-indexed after comm):
    // 11: utime, 12: stime, 17: num_threads, 19: starttime
    let utime: u64 = fields[11].parse().ok()?;
    let stime: u64 = fields[12].parse().ok()?;
    let num_threads: u32 = fields[17].parse().ok()?;
    let starttime: u64 = fields[19].parse().ok()?;
    let identity = build_identity(pid, starttime);

    Some(TickSnapshot {
        pid,
        identity,
        utime,
        stime,
        total_ticks: utime + stime,
        num_threads,
        timestamp,
        monotonic: None,
        starttime,
    })
}

/// Compute tick-delta features from two snapshots.
///
/// # Arguments
/// * `before` - Earlier snapshot
/// * `after` - Later snapshot
/// * `config` - Configuration for computation
///
/// # Returns
/// * `Option<TickDeltaFeatures>` - Features or None if invalid
pub fn compute_tick_delta(
    before: &TickSnapshot,
    after: &TickSnapshot,
    config: &TickDeltaConfig,
) -> Option<TickDeltaFeatures> {
    // Validate same process identity (PID reuse protection)
    if before.identity != after.identity {
        return None;
    }

    // Compute delta_t using monotonic time if available, otherwise SystemTime
    let delta_t_secs = match (before.monotonic, after.monotonic) {
        (Some(start), Some(end)) => {
            if end <= start {
                return None;
            }
            end.duration_since(start).as_secs_f64()
        }
        _ => {
            // Fallback to SystemTime
            if after.timestamp <= before.timestamp {
                return None;
            }
            after
                .timestamp
                .duration_since(before.timestamp)
                .ok()?
                .as_secs_f64()
        }
    };

    if delta_t_secs <= 0.0 {
        return None;
    }

    // Compute k_ticks
    let k_ticks = after.total_ticks.saturating_sub(before.total_ticks);

    // Get CPU capacity
    let cgroup = collect_cgroup_details(after.pid);
    let cpu_capacity = compute_cpu_capacity(after.pid, cgroup.as_ref());
    let n_eff_cores = cpu_capacity.n_eff_cores;

    // Compute n_ticks
    let tck = clk_tck();
    let threads = after.num_threads as f64;
    let (effective_parallelism, budget_constraint) = if threads < n_eff_cores {
        (threads, BudgetConstraint::Threads)
    } else if n_eff_cores < threads {
        (n_eff_cores, BudgetConstraint::Cores)
    } else {
        (threads, BudgetConstraint::Equal)
    };

    let n_ticks_float = (tck as f64) * delta_t_secs * effective_parallelism;
    let n_ticks = n_ticks_float.round().max(1.0) as u64;

    // Compute u (clamped to [0, 1])
    let u = if n_ticks > 0 {
        (k_ticks as f64 / n_ticks as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Compute u_cores
    let u_cores = k_ticks as f64 / ((tck as f64) * delta_t_secs);

    let mut warnings = Vec::new();
    // Compute n_eff based on policy
    let n_eff = match config.n_eff_policy {
        NEffPolicy::Identity => n_ticks,
        NEffPolicy::FixedReduction => {
            let factor = config.reduction_factor;
            if !factor.is_finite() || factor <= 0.0 {
                warnings.push(format!(
                    "invalid reduction_factor {:.3}; using identity n_eff",
                    factor
                ));
                n_ticks
            } else {
                ((n_ticks as f64) / factor).round().max(1.0) as u64
            }
        }
        NEffPolicy::Autocorrelation => {
            // Placeholder for future autocorrelation-based correction
            n_ticks
        }
    };
    if after.identity.quality != IdentityQuality::Full {
        warnings.push(format!("identity quality is {}", after.identity.quality));
    }

    let n_eff_param = match config.n_eff_policy {
        NEffPolicy::FixedReduction => Some(config.reduction_factor),
        _ => None,
    };

    let provenance = TickDeltaProvenance {
        clk_tck: tck,
        threads: after.num_threads,
        n_eff_cores,
        budget_constraint,
        n_eff_policy: config.n_eff_policy,
        n_eff_param,
        sample_start_unix_us: system_time_to_unix_us(before.timestamp),
        sample_end_unix_us: system_time_to_unix_us(after.timestamp),
        tick_source: "proc_stat:utime+stime".to_string(),
        thread_source: "proc_stat:num_threads".to_string(),
        warnings,
    };

    Some(TickDeltaFeatures {
        k_ticks,
        n_ticks,
        u,
        u_cores,
        n_eff,
        delta_t_secs,
        identity: after.identity.clone(),
        cpu_capacity,
        provenance,
    })
}

/// Single-call convenience function to sample and compute tick-delta.
///
/// Takes a snapshot, waits for the specified duration, takes another snapshot,
/// and computes the features.
///
/// # Arguments
/// * `pid` - Process ID
/// * `sample_duration` - Duration to wait between snapshots
/// * `config` - Configuration for computation
pub fn sample_tick_delta(
    pid: u32,
    sample_duration: Duration,
    config: &TickDeltaConfig,
) -> Option<TickDeltaFeatures> {
    let before = collect_tick_snapshot(pid)?;
    std::thread::sleep(sample_duration);
    let after = collect_tick_snapshot(pid)?;
    compute_tick_delta(&before, &after, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(pid: u32, starttime: u64) -> ProcessIdentity {
        let mut identity =
            ProcessIdentity::new(pid, StartId::from_linux("test-boot", starttime, pid), 1000);
        identity.quality = IdentityQuality::Full;
        identity
    }

    #[test]
    fn test_clk_tck() {
        let tck = clk_tck();
        // Should be a reasonable value (typically 100 on Linux)
        assert!(tck >= 1);
        assert!(tck <= 10000);
    }

    #[test]
    fn test_parse_tick_snapshot() {
        // Real-looking /proc/PID/stat content
        let content = "1234 (test_proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 \
                       500 200 0 0 20 0 4 0 12345 1234567 890 18446744073709551615 \
                       1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

        let timestamp = std::time::SystemTime::now();
        let snapshot = parse_tick_snapshot(content, 1234, timestamp).unwrap();

        assert_eq!(snapshot.pid, 1234);
        assert_eq!(snapshot.utime, 500);
        assert_eq!(snapshot.stime, 200);
        assert_eq!(snapshot.total_ticks, 700);
        assert_eq!(snapshot.num_threads, 4);
        assert_eq!(snapshot.starttime, 12345);
    }

    #[test]
    fn test_parse_tick_snapshot_with_spaces_in_comm() {
        let content = "5678 (My Process Name) R 1 5678 5678 0 -1 4194304 50 0 0 0 \
                       1000 500 0 0 20 0 8 0 67890 2345678 1234 18446744073709551615 \
                       1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

        let timestamp = std::time::SystemTime::now();
        let snapshot = parse_tick_snapshot(content, 5678, timestamp).unwrap();

        assert_eq!(snapshot.utime, 1000);
        assert_eq!(snapshot.stime, 500);
        assert_eq!(snapshot.num_threads, 8);
    }

    #[test]
    fn test_parse_tick_snapshot_truncated() {
        let content = "1234 (proc) S 1 2 3";
        let timestamp = std::time::SystemTime::now();
        let result = parse_tick_snapshot(content, 1234, timestamp);
        assert!(result.is_none());
    }

    #[test]
    fn test_compute_tick_delta_basic() {
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 100,
            stime: 50,
            total_ticks: 150,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 200,
            stime: 100,
            total_ticks: 300,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1001),
            starttime: 12345,
            monotonic: None,
        };

        let config = TickDeltaConfig::default();
        let features = compute_tick_delta(&before, &after, &config).unwrap();

        assert_eq!(features.k_ticks, 150);
        assert!(features.delta_t_secs > 0.99 && features.delta_t_secs < 1.01);
        assert!(features.u >= 0.0 && features.u <= 1.0);
        assert!(features.u_cores >= 0.0);
    }

    #[test]
    fn test_compute_tick_delta_different_starttime() {
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 100,
            stime: 50,
            total_ticks: 150,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 99999),
            utime: 200,
            stime: 100,
            total_ticks: 300,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1001),
            starttime: 99999, // Different starttime (PID reused)
            monotonic: None,
        };

        let config = TickDeltaConfig::default();
        let result = compute_tick_delta(&before, &after, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_compute_tick_delta_u_clamped() {
        // Create a scenario where k_ticks > n_ticks (shouldn't happen in reality)
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 0,
            stime: 0,
            total_ticks: 0,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        // Very high tick consumption for short window
        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 10000,
            stime: 10000,
            total_ticks: 20000,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH
                + Duration::from_secs(1000)
                + Duration::from_millis(10),
            starttime: 12345,
            monotonic: None,
        };

        let config = TickDeltaConfig::default();
        let features = compute_tick_delta(&before, &after, &config).unwrap();

        // u should be clamped to 1.0
        assert_eq!(features.u, 1.0);
    }

    #[test]
    fn test_n_eff_policies() {
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 100,
            stime: 50,
            total_ticks: 150,
            num_threads: 4,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 200,
            stime: 100,
            total_ticks: 300,
            num_threads: 4,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1001),
            starttime: 12345,
            monotonic: None,
        };

        // Identity policy
        let config_identity = TickDeltaConfig {
            n_eff_policy: NEffPolicy::Identity,
            ..Default::default()
        };
        let features_identity = compute_tick_delta(&before, &after, &config_identity).unwrap();
        assert_eq!(features_identity.n_eff, features_identity.n_ticks);

        // FixedReduction policy
        let config_reduced = TickDeltaConfig {
            n_eff_policy: NEffPolicy::FixedReduction,
            reduction_factor: 2.0,
        };
        let features_reduced = compute_tick_delta(&before, &after, &config_reduced).unwrap();
        let expected_n_eff = ((features_reduced.n_ticks as f64) / 2.0).round() as u64;
        assert_eq!(features_reduced.n_eff, expected_n_eff);
    }

    #[test]
    fn test_fixed_reduction_invalid_factor_falls_back() {
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 10,
            stime: 10,
            total_ticks: 20,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 20,
            stime: 20,
            total_ticks: 40,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1001),
            starttime: 12345,
            monotonic: None,
        };

        let config = TickDeltaConfig {
            n_eff_policy: NEffPolicy::FixedReduction,
            reduction_factor: 0.0,
        };
        let features = compute_tick_delta(&before, &after, &config).unwrap();
        assert_eq!(features.n_eff, features.n_ticks);
        assert!(features
            .provenance
            .warnings
            .iter()
            .any(|w| w.contains("invalid reduction_factor")));
    }

    #[test]
    fn test_budget_constraint_tracking() {
        // When threads < N_eff_cores, threads should be the constraint
        let before = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 100,
            stime: 50,
            total_ticks: 150,
            num_threads: 1, // Single thread
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            starttime: 12345,
            monotonic: None,
        };

        let after = TickSnapshot {
            pid: 1234,
            identity: test_identity(1234, 12345),
            utime: 200,
            stime: 100,
            total_ticks: 300,
            num_threads: 1,
            timestamp: std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1001),
            starttime: 12345,
            monotonic: None,
        };

        let config = TickDeltaConfig::default();
        let features = compute_tick_delta(&before, &after, &config).unwrap();

        // On a multi-core system, single thread should be the constraint
        if features.cpu_capacity.n_eff_cores > 1.0 {
            assert_eq!(
                features.provenance.budget_constraint,
                BudgetConstraint::Threads
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore] // Integration test - run with --ignored
    fn test_collect_tick_snapshot_self() {
        let pid = std::process::id();
        let snapshot = collect_tick_snapshot(pid);

        assert!(snapshot.is_some());
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.pid, pid);
        assert!(snapshot.total_ticks > 0); // We've consumed some CPU time
        assert!(snapshot.num_threads >= 1);
    }
}
