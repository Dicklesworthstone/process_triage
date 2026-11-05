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
use super::proc_parsers::{
    parse_io_content, parse_process_memory_status, parse_schedstat_content, IoStats, SchedStats,
};
use super::{ProcessActivity, ProcessMemoryUsage, ProcessPressureActivity, ProcessRecord};
use pt_common::{IdentityQuality, ProcessIdentity, StartId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let bytes = fs::read(&path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
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
    collect_tick_sample(pid).map(|(ticks, _)| ticks)
}

#[derive(Debug, Clone)]
struct PressureStatCounters {
    major_faults: Option<u64>,
    leader_blkio_delay_ticks: Option<u64>,
}

fn parse_pressure_stat_counters(content: &str) -> Option<PressureStatCounters> {
    let after_comm = content.get(content.rfind(')')? + 1..)?;
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    Some(PressureStatCounters {
        // proc_pid_stat(5): fields 12 and 42; this slice starts at field 3.
        major_faults: fields.get(9).and_then(|value| value.parse().ok()),
        leader_blkio_delay_ticks: fields.get(39).and_then(|value| value.parse().ok()),
    })
}

fn collect_tick_sample(pid: u32) -> Option<(TickSnapshot, PressureStatCounters)> {
    let path = format!("/proc/{}/stat", pid);
    let bytes = fs::read(&path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let timestamp = std::time::SystemTime::now();
    let monotonic = std::time::Instant::now();

    let mut snapshot = parse_tick_snapshot(&content, pid, timestamp)?;
    snapshot.monotonic = Some(monotonic);
    Some((snapshot, parse_pressure_stat_counters(&content)?))
}

/// Parse tick snapshot from /proc/\[pid\]/stat content.
pub fn parse_tick_snapshot(
    content: &str,
    pid: u32,
    timestamp: std::time::SystemTime,
) -> Option<TickSnapshot> {
    // Find comm field (surrounded by parentheses)
    let comm_start = content.find('(')?;
    if content[..comm_start].trim().parse::<u32>().ok()? != pid {
        return None;
    }
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
        total_ticks: utime.checked_add(stime)?,
        num_threads,
        timestamp,
        monotonic: None,
        starttime,
    })
}

/// A counter reset or invalid window is unavailable evidence, never zero activity.
/// Kept independent of OS reads so replay fixtures exercise the production math.
fn counter_rate(before: u64, after: u64, seconds: f64) -> Result<(u64, f64), &'static str> {
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("sampling duration is not positive and finite");
    }
    let delta = after.checked_sub(before).ok_or("counter moved backwards")?;
    let rate = delta as f64 / seconds;
    if !rate.is_finite() {
        return Err("counter rate is not finite");
    }
    Ok((delta, rate))
}

fn tick_window(before: &TickSnapshot, after: &TickSnapshot) -> Result<(u64, f64), &'static str> {
    if before.pid != after.pid
        || before.pid != before.identity.pid.0
        || after.pid != after.identity.pid.0
        || before.starttime != after.starttime
        || !before.identity.matches(&after.identity)
    {
        return Err("process identity changed between CPU samples");
    }
    let seconds = match (before.monotonic, after.monotonic) {
        (Some(start), Some(end)) => end
            .checked_duration_since(start)
            .ok_or("monotonic sample clock moved backwards")?
            .as_secs_f64(),
        (None, None) => after
            .timestamp
            .duration_since(before.timestamp)
            .map_err(|_| "sample clock moved backwards")?
            .as_secs_f64(),
        _ => return Err("CPU samples use different clocks"),
    };
    // Checking both components prevents an increase in one from concealing a
    // reset/wrap in the other. Totals are checked when the stat file is parsed.
    if after.utime < before.utime || after.stime < before.stime {
        return Err("CPU tick counter moved backwards");
    }
    let (ticks, _) = counter_rate(before.total_ticks, after.total_ticks, seconds)?;
    Ok((ticks, seconds))
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
    let (k_ticks, delta_t_secs) = tick_window(before, after).ok()?;

    // Get CPU capacity
    let cgroup = collect_cgroup_details(after.pid);
    let cpu_capacity = compute_cpu_capacity(after.pid, cgroup.as_ref());
    let mut n_eff_cores = cpu_capacity.n_eff_cores;

    // Guard against NaN / non-finite / non-positive n_eff_cores which would
    // propagate through all downstream arithmetic and produce garbage results.
    let threads = after.num_threads as f64;
    if !n_eff_cores.is_finite() || n_eff_cores <= 0.0 {
        n_eff_cores = threads;
    }

    // Compute n_ticks
    let tck = clk_tck();
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

#[derive(Debug, Clone)]
struct ActivitySnapshot {
    ticks: TickSnapshot,
    io: Result<IoStats, String>,
    io_observed_at: Instant,
    counters: PressureStatCounters,
    scheduler: Result<SchedStats, String>,
    scheduler_observed_at: Instant,
    memory: Result<ProcessMemoryUsage, String>,
    delay_accounting: Result<(), String>,
}

/// Read accounting switches once per batch endpoint, never modify them. Kernel
/// builds with missing/disabled accounting must not supply fabricated zeros.
struct ActivityAccounting {
    scheduler: Result<(), String>,
    delay: Result<(), String>,
}

fn read_accounting_switch(name: &str) -> Result<(), String> {
    let path = format!("/proc/sys/kernel/{name}");
    match fs::read_to_string(&path) {
        Ok(value) if value.trim() == "1" => Ok(()),
        Ok(value) if value.trim() == "0" => Err(format!("kernel {name} accounting is disabled")),
        Ok(_) => Err(format!("invalid kernel {name} accounting switch")),
        Err(error) => Err(format!("cannot read {path}: {error}")),
    }
}

impl ActivityAccounting {
    fn read() -> Self {
        Self {
            scheduler: read_accounting_switch("sched_schedstats"),
            delay: read_accounting_switch("task_delayacct"),
        }
    }
}

fn parse_activity_io(content: &str) -> Result<IoStats, String> {
    let stats = parse_io_content(content)
        .ok_or_else(|| "invalid or incomplete I/O counters".to_string())?;
    // The shared write-safety parser requires wchar/write_bytes, but permits a
    // missing read counter. Activity sampling must not turn that absence into 0.
    if !content.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(key, _)| key.trim() == "read_bytes")
    }) {
        return Err("missing read_bytes counter".to_string());
    }
    Ok(stats)
}

fn ticks_match_process(ticks: &TickSnapshot, process: &ProcessRecord) -> bool {
    ticks.pid == process.pid.0
        && ticks.identity.pid == process.pid
        && ticks.identity.start_id == process.start_id
        && ticks.identity.uid == process.uid
        && ticks.identity.quality.is_automatable()
}

fn collect_activity_snapshot(
    process: &ProcessRecord,
    accounting: &ActivityAccounting,
) -> Result<ActivitySnapshot, String> {
    let pid = process.pid.0;
    let before = collect_tick_snapshot(pid)
        .ok_or_else(|| "CPU stat/identity is unreadable or invalid".to_string())?;
    if !ticks_match_process(&before, process) {
        return Err("process identity does not match the scanned incarnation".to_string());
    }

    let io = fs::read(format!("/proc/{pid}/io"))
        .map_err(|error| format!("cannot read /proc/{pid}/io: {error}"))
        .and_then(|bytes| parse_activity_io(&String::from_utf8_lossy(&bytes)));
    let io_observed_at = Instant::now();

    let scheduler = accounting.scheduler.clone().and_then(|()| {
        fs::read_to_string(format!("/proc/{pid}/schedstat"))
            .map_err(|error| format!("cannot read /proc/{pid}/schedstat: {error}"))
            .and_then(|content| {
                parse_schedstat_content(&content)
                    .ok_or_else(|| "invalid scheduler counters".to_string())
            })
    });
    let scheduler_observed_at = Instant::now();
    let memory = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("cannot read /proc/{pid}/status: {error}"))
        .and_then(|content| parse_process_memory_status(&content));

    // All these files are addressed by numeric PID. Bracket them with identity
    // reads so a replacement cannot donate counters or memory to the old record.
    let (after, counters) = collect_tick_sample(pid).ok_or_else(|| {
        "CPU stat/identity became unreadable while collecting activity".to_string()
    })?;
    if !ticks_match_process(&after, process) || !before.identity.matches(&after.identity) {
        return Err("process identity changed while collecting activity".to_string());
    }
    Ok(ActivitySnapshot {
        ticks: after,
        io,
        io_observed_at,
        counters,
        scheduler,
        scheduler_observed_at,
        memory,
        delay_accounting: accounting.delay.clone(),
    })
}

fn pressure_from_snapshots(
    before: &ActivitySnapshot,
    after: &ActivitySnapshot,
    clock_ticks_per_second: u64,
) -> ProcessPressureActivity {
    let mut pressure = ProcessPressureActivity::default();
    match &after.memory {
        Ok(memory) => pressure.memory = Some(memory.clone()),
        Err(error) => pressure.memory_error = Some(error.clone()),
    }
    let stat_seconds = tick_window(&before.ticks, &after.ticks).map(|(_, seconds)| seconds);
    pressure.stat_window_seconds = stat_seconds.ok();
    let faults = || -> Result<(u64, f64), String> {
        let first = before
            .counters
            .major_faults
            .ok_or("first major-fault counter unavailable")?;
        let second = after
            .counters
            .major_faults
            .ok_or("second major-fault counter unavailable")?;
        counter_rate(first, second, stat_seconds?).map_err(str::to_string)
    };
    match faults() {
        Ok((count, rate)) => {
            pressure.major_faults = Some(count);
            pressure.major_faults_per_second = Some(rate);
        }
        Err(error) => pressure.faults_error = Some(error),
    }
    let scheduler_rate = || -> Result<(f64, f64), String> {
        let first = before
            .scheduler
            .as_ref()
            .map_err(|error| format!("first scheduler sample: {error}"))?;
        let second = after
            .scheduler
            .as_ref()
            .map_err(|error| format!("second scheduler sample: {error}"))?;
        let seconds = after
            .scheduler_observed_at
            .checked_duration_since(before.scheduler_observed_at)
            .ok_or("scheduler sample clock moved backwards")?
            .as_secs_f64();
        // Guard every counter so a reset cannot hide behind an unchanged wait.
        counter_rate(first.cpu_time_ns, second.cpu_time_ns, seconds)?;
        counter_rate(first.timeslices, second.timeslices, seconds)?;
        let (_, nanos_per_second) = counter_rate(first.wait_time_ns, second.wait_time_ns, seconds)?;
        Ok((seconds, nanos_per_second / 1_000_000_000.0 * 100.0))
    };
    match scheduler_rate() {
        Ok((seconds, percent)) => {
            pressure.scheduler_window_seconds = Some(seconds);
            pressure.leader_run_queue_wait_percent = Some(percent);
        }
        Err(error) => pressure.scheduler_error = Some(error),
    }
    let blkio_rate = || -> Result<f64, String> {
        before
            .delay_accounting
            .as_ref()
            .map_err(|error| format!("first sample: {error}"))?;
        after
            .delay_accounting
            .as_ref()
            .map_err(|error| format!("second sample: {error}"))?;
        if clock_ticks_per_second == 0 {
            return Err("clock ticks per second is zero".to_string());
        }
        let first = before
            .counters
            .leader_blkio_delay_ticks
            .ok_or("first block-I/O delay counter unavailable")?;
        let second = after
            .counters
            .leader_blkio_delay_ticks
            .ok_or("second block-I/O delay counter unavailable")?;
        // Enabling delayacct only instruments newly created tasks. An all-zero
        // field cannot establish that this task has accounting, even with the
        // global switch on (kernel delay-accounting documentation).
        if first == 0 && second == 0 {
            return Err(
                "zero block-I/O counters cannot establish per-task delay accounting".to_string(),
            );
        }
        let (_, ticks_per_second) = counter_rate(first, second, stat_seconds?)?;
        Ok(ticks_per_second / clock_ticks_per_second as f64 * 100.0)
    };
    match blkio_rate() {
        Ok(percent) => pressure.leader_blkio_delay_percent = Some(percent),
        Err(error) => pressure.blkio_error = Some(error),
    }
    pressure
}

fn activity_from_snapshots(
    process: &ProcessRecord,
    before: &ActivitySnapshot,
    after: &ActivitySnapshot,
    window: Duration,
    clock_ticks_per_second: u64,
) -> ProcessActivity {
    let mut activity = ProcessActivity::unavailable(process, window, "no usable samples");
    if !ticks_match_process(&before.ticks, process) || !ticks_match_process(&after.ticks, process) {
        return ProcessActivity::unavailable(
            process,
            window,
            "activity samples do not match the scanned process incarnation",
        );
    }

    match tick_window(&before.ticks, &after.ticks) {
        Ok((ticks, seconds)) if clock_ticks_per_second > 0 => {
            activity.cpu_ticks = Some(ticks);
            activity.cpu_window_seconds = Some(seconds);
            activity.cpu_percent =
                Some(ticks as f64 / clock_ticks_per_second as f64 / seconds * 100.0);
            activity.cpu_error = None;
        }
        Ok(_) => activity.cpu_error = Some("clock ticks per second is zero".to_string()),
        Err(error) => activity.cpu_error = Some(error.to_string()),
    }

    let io_rates = || -> Result<(f64, f64, f64, bool), String> {
        let first = before
            .io
            .as_ref()
            .map_err(|error| format!("first I/O sample: {error}"))?;
        let second = after
            .io
            .as_ref()
            .map_err(|error| format!("second I/O sample: {error}"))?;
        let seconds = after
            .io_observed_at
            .checked_duration_since(before.io_observed_at)
            .ok_or_else(|| "I/O sample clock moved backwards".to_string())?
            .as_secs_f64();
        let (read, read_rate) = counter_rate(first.read_bytes, second.read_bytes, seconds)
            .map_err(|error| format!("read_bytes: {error}"))?;
        let (written, write_rate) = counter_rate(first.write_bytes, second.write_bytes, seconds)
            .map_err(|error| format!("write_bytes: {error}"))?;
        Ok((seconds, read_rate, write_rate, read > 0 || written > 0))
    };
    match io_rates() {
        Ok((seconds, read_rate, write_rate, active)) => {
            activity.io_window_seconds = Some(seconds);
            activity.read_bytes_per_second = Some(read_rate);
            activity.write_bytes_per_second = Some(write_rate);
            activity.io_active = Some(active);
            activity.io_error = None;
        }
        Err(error) => activity.io_error = Some(error),
    }
    activity.pressure = Some(pressure_from_snapshots(
        before,
        after,
        clock_ticks_per_second,
    ));
    activity
}

/// Measure CPU, storage I/O, memory and pressure in one shared sampling window.
///
/// Every sample is bound to the quick-scan PID/start ID/UID. The actual elapsed
/// time is recorded per signal and process; batch collection overhead is never
/// mistaken for the requested sleep duration. Empty batches and wholly
/// unavailable first samples return without sleeping. Only procfs is read.
pub fn sample_process_activity(
    processes: &[&ProcessRecord],
    window: Duration,
) -> BTreeMap<u32, ProcessActivity> {
    if window.is_zero() {
        return BTreeMap::new();
    }
    let accounting_before = ActivityAccounting::read();
    let first: Vec<_> = processes
        .iter()
        .copied()
        .map(|process| {
            (
                process,
                collect_activity_snapshot(process, &accounting_before),
            )
        })
        .collect();
    if first.iter().any(|(_, snapshot)| snapshot.is_ok()) {
        std::thread::sleep(window);
    }
    let tck = clk_tck();
    let accounting_after = ActivityAccounting::read();
    first
        .into_iter()
        .map(|(process, before)| {
            let activity = match before {
                Err(error) => {
                    ProcessActivity::unavailable(process, window, format!("first sample: {error}"))
                }
                Ok(before) => match collect_activity_snapshot(process, &accounting_after) {
                    Ok(after) => activity_from_snapshots(process, &before, &after, window, tck),
                    Err(error) => ProcessActivity::unavailable(
                        process,
                        window,
                        format!("second sample: {error}"),
                    ),
                },
            };
            (process.pid.0, activity)
        })
        .collect()
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

    fn activity_fixture() -> (ProcessRecord, ActivitySnapshot, ActivitySnapshot) {
        let identity = test_identity(1234, 12345);
        let process = ProcessRecord {
            pid: identity.pid,
            ppid: pt_common::ProcessId(1),
            uid: identity.uid,
            user: "fixture".to_string(),
            pgid: Some(1234),
            sid: Some(1234),
            start_id: identity.start_id.clone(),
            comm: "worker".to_string(),
            cmd: "worker".to_string(),
            state: super::super::ProcessState::Sleeping,
            cpu_percent: 75.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: Duration::from_secs(3600),
            source: "test".to_string(),
            container_info: None,
        };
        let instant = Instant::now();
        let first = ActivitySnapshot {
            ticks: TickSnapshot {
                pid: 1234,
                identity,
                utime: 10_000,
                stime: 5_000,
                total_ticks: 15_000,
                num_threads: 1,
                timestamp: UNIX_EPOCH + Duration::from_secs(1000),
                monotonic: Some(instant),
                starttime: 12345,
            },
            io: Ok(IoStats {
                read_bytes: 8_000_000_000,
                write_bytes: 4_000_000_000,
                ..IoStats::default()
            }),
            io_observed_at: instant,
            counters: PressureStatCounters {
                major_faults: Some(10_000),
                leader_blkio_delay_ticks: Some(100),
            },
            scheduler: Ok(SchedStats {
                cpu_time_ns: 9_000_000_000,
                wait_time_ns: 8_000_000_000,
                timeslices: 1_000,
            }),
            scheduler_observed_at: instant,
            memory: Ok(ProcessMemoryUsage {
                rss_bytes: 4096,
                rss_anon_bytes: 2048,
                rss_file_bytes: 1024,
                rss_shmem_bytes: 1024,
                swap_bytes: 8192,
                threads: 1,
            }),
            delay_accounting: Ok(()),
        };
        let mut second = first.clone();
        second.ticks.timestamp += Duration::from_millis(500);
        second.ticks.monotonic = Some(instant + Duration::from_millis(500));
        second.io_observed_at += Duration::from_millis(500);
        second.scheduler_observed_at += Duration::from_millis(500);
        (process, first, second)
    }

    #[test]
    fn pressure_rates_measure_deltas_and_latest_memory_without_another_window() {
        let (process, first, mut second) = activity_fixture();
        second.counters.major_faults = Some(10_003);
        second.counters.leader_blkio_delay_ticks = Some(125);
        second.scheduler.as_mut().unwrap().wait_time_ns += 125_000_000;
        // Each source uses its observed time, not the requested batch sleep.
        second.scheduler_observed_at = first.scheduler_observed_at + Duration::from_secs(1);
        second.memory.as_mut().unwrap().swap_bytes = 16384;
        let activity =
            activity_from_snapshots(&process, &first, &second, Duration::from_millis(50), 100);
        let pressure = activity.pressure.unwrap();
        assert_eq!(pressure.major_faults, Some(3));
        assert_eq!(pressure.major_faults_per_second, Some(6.0));
        assert_eq!(pressure.stat_window_seconds, Some(0.5));
        assert_eq!(pressure.leader_run_queue_wait_percent, Some(12.5));
        assert_eq!(pressure.scheduler_window_seconds, Some(1.0));
        assert_eq!(pressure.leader_blkio_delay_percent, Some(50.0));
        assert_eq!(pressure.memory.unwrap().swap_bytes, 16384);
        assert!(pressure.faults_error.is_none());
        assert!(pressure.scheduler_error.is_none());
        assert!(pressure.blkio_error.is_none());
        assert!(pressure.memory_error.is_none());
    }

    #[test]
    fn unavailable_pressure_does_not_erase_cpu_or_io_and_never_means_idle() {
        for failure in ["unreadable", "reset", "disabled", "zero_delay"] {
            let (process, mut first, mut second) = activity_fixture();
            match failure {
                "unreadable" => {
                    second.counters.major_faults = None;
                    second.counters.leader_blkio_delay_ticks = None;
                    second.scheduler = Err("permission denied".to_string());
                    second.memory = Err("status is unreadable".to_string());
                }
                "reset" => {
                    second.counters.major_faults = Some(0);
                    second.counters.leader_blkio_delay_ticks = Some(0);
                    second.scheduler.as_mut().unwrap().wait_time_ns = 0;
                }
                "disabled" => {
                    first.scheduler = Err("scheduler accounting is disabled".to_string());
                    first.delay_accounting = Err("delay accounting is disabled".to_string());
                }
                "zero_delay" => {
                    first.counters.leader_blkio_delay_ticks = Some(0);
                    second.counters.leader_blkio_delay_ticks = Some(0);
                }
                _ => unreachable!(),
            }
            let activity =
                activity_from_snapshots(&process, &first, &second, Duration::from_millis(500), 100);
            assert_eq!(activity.cpu_percent, Some(0.0), "{failure}");
            assert_eq!(activity.io_active, Some(false), "{failure}");
            let pressure = activity.pressure.unwrap();
            assert!(pressure.leader_blkio_delay_percent.is_none(), "{failure}");
            assert!(pressure.blkio_error.is_some(), "{failure}");
            if failure != "zero_delay" {
                assert!(
                    pressure.leader_run_queue_wait_percent.is_none(),
                    "{failure}"
                );
                assert!(pressure.scheduler_error.is_some(), "{failure}");
            }
            if matches!(failure, "unreadable" | "reset") {
                assert!(pressure.major_faults_per_second.is_none(), "{failure}");
                assert!(pressure.faults_error.is_some(), "{failure}");
            }
            if failure == "unreadable" {
                assert!(pressure.memory.is_none());
                assert!(pressure.memory_error.is_some());
            }
        }
    }

    #[test]
    fn pressure_stat_fields_are_not_child_faults_or_guest_cpu_ticks() {
        // Field 12 (majflt) is 7, 13 (cmajflt) is 900, 42 (delayacct_blkio_ticks)
        // is 25, and the following guest_time field is 800.
        let content = "42 (worker (thread)) S 1 42 42 0 -1 0 0 0 7 900 100 50 0 0 20 0 1 0 123 4096 1 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 25 800";
        let counters = parse_pressure_stat_counters(content).unwrap();
        assert_eq!(counters.major_faults, Some(7));
        assert_eq!(counters.leader_blkio_delay_ticks, Some(25));
        let truncated = parse_pressure_stat_counters("42 (worker) S 1").unwrap();
        assert!(truncated.major_faults.is_none());
        assert!(truncated.leader_blkio_delay_ticks.is_none());
    }

    #[test]
    fn activity_rates_use_actual_window_and_preserve_multicore_units() {
        let (process, first, mut second) = activity_fixture();
        second.ticks.utime += 50;
        second.ticks.total_ticks += 50;
        second.io.as_mut().unwrap().read_bytes += 8192;
        second.io.as_mut().unwrap().write_bytes += 4096;
        // A scheduling delay makes the actual window differ from the request.
        let activity =
            activity_from_snapshots(&process, &first, &second, Duration::from_millis(250), 100);
        assert_eq!(activity.requested_window_ms, 250);
        assert_eq!(activity.cpu_ticks, Some(50));
        assert_eq!(activity.cpu_window_seconds, Some(0.5));
        assert_eq!(activity.cpu_percent, Some(100.0));
        assert_eq!(activity.io_window_seconds, Some(0.5));
        assert_eq!(activity.read_bytes_per_second, Some(16384.0));
        assert_eq!(activity.write_bytes_per_second, Some(8192.0));
        assert_eq!(activity.io_active, Some(true));
        assert!(activity.cpu_error.is_none());
        assert!(activity.io_error.is_none());

        second.ticks.utime += 50;
        second.ticks.total_ticks += 50;
        let two_cores =
            activity_from_snapshots(&process, &first, &second, Duration::from_millis(500), 100);
        assert_eq!(two_cores.cpu_percent, Some(200.0));
    }

    #[test]
    fn historical_cpu_and_io_totals_do_not_mean_current_activity() {
        let (process, first, second) = activity_fixture();
        let activity =
            activity_from_snapshots(&process, &first, &second, Duration::from_millis(500), 100);
        assert_eq!(activity.cpu_percent, Some(0.0));
        assert_eq!(activity.cpu_ticks, Some(0));
        assert_eq!(activity.read_bytes_per_second, Some(0.0));
        assert_eq!(activity.write_bytes_per_second, Some(0.0));
        assert_eq!(activity.io_active, Some(false));
    }

    #[test]
    fn unavailable_and_regressing_io_remain_unknown_without_losing_cpu() {
        for failure in ["unreadable", "read_reset", "write_reset"] {
            let (process, first, mut second) = activity_fixture();
            second.ticks.utime += 50;
            second.ticks.total_ticks += 50;
            match failure {
                "unreadable" => second.io = Err("permission denied".to_string()),
                "read_reset" => second.io.as_mut().unwrap().read_bytes = 0,
                "write_reset" => second.io.as_mut().unwrap().write_bytes = 0,
                _ => unreachable!(),
            }
            let activity =
                activity_from_snapshots(&process, &first, &second, Duration::from_millis(500), 100);
            assert_eq!(activity.cpu_percent, Some(100.0), "{failure}");
            assert!(activity.io_active.is_none(), "{failure}");
            assert!(activity.read_bytes_per_second.is_none(), "{failure}");
            assert!(activity.write_bytes_per_second.is_none(), "{failure}");
            let reason = activity.io_error.unwrap();
            assert!(
                reason.contains("permission denied") || reason.contains("moved backwards"),
                "{failure}: {reason}"
            );
        }
    }

    #[test]
    fn activity_rejects_reused_pid_changed_owner_and_unknown_identity() {
        for changed in ["start", "owner", "unknown"] {
            let (process, first, mut second) = activity_fixture();
            match changed {
                "start" => second.ticks.identity.start_id = StartId::from_linux("b", 999, 1234),
                "owner" => second.ticks.identity.uid += 1,
                "unknown" => second.ticks.identity.quality = IdentityQuality::PidOnly,
                _ => unreachable!(),
            }
            let activity =
                activity_from_snapshots(&process, &first, &second, Duration::from_millis(500), 100);
            assert!(activity.cpu_percent.is_none(), "{changed}");
            assert!(activity.io_active.is_none(), "{changed}");
            assert!(activity.cpu_error.unwrap().contains("incarnation"));
            assert!(activity.io_error.unwrap().contains("incarnation"));
            let pressure = activity.pressure.unwrap();
            assert!(pressure.memory.is_none(), "{changed}");
            assert!(pressure.major_faults.is_none(), "{changed}");
            assert!(
                pressure.leader_run_queue_wait_percent.is_none(),
                "{changed}"
            );
            assert!(pressure.leader_blkio_delay_percent.is_none(), "{changed}");
            assert!(pressure.memory_error.unwrap().contains("incarnation"));
        }
    }

    #[test]
    fn counter_and_tick_windows_reject_resets_invalid_time_and_clock_mixing() {
        assert_eq!(counter_rate(100, 150, 0.5), Ok((50, 100.0)));
        assert_eq!(counter_rate(u64::MAX, u64::MAX, 0.5), Ok((0, 0.0)));
        assert!(counter_rate(u64::MAX, 0, 1.0).is_err());
        for seconds in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(counter_rate(0, 1, seconds).is_err());
        }
        let (_, first, mut second) = activity_fixture();
        second.ticks.utime -= 1;
        second.ticks.stime += 2;
        second.ticks.total_ticks += 1;
        assert!(tick_window(&first.ticks, &second.ticks).is_err());
        let (_, first, mut second) = activity_fixture();
        second.ticks.monotonic = first.ticks.monotonic;
        assert!(tick_window(&first.ticks, &second.ticks).is_err());
        second.ticks.monotonic = None;
        assert!(tick_window(&first.ticks, &second.ticks).is_err());
    }

    #[test]
    fn activity_io_requires_read_counters_and_valid_complete_values() {
        assert!(parse_activity_io("wchar: 0\nwrite_bytes: 0\n")
            .unwrap_err()
            .contains("read_bytes"));
        assert!(parse_activity_io("wchar: 0\nwrite_bytes: 1\nread_bytes: bad\n").is_err());
        assert!(parse_activity_io("wchar: 0\nread_bytes: 0\n").is_err());
        assert!(
            parse_activity_io("wchar: 0\nwrite_bytes: 0\nread_bytes: 0\nread_bytes: 1\n").is_err()
        );
        let zero = parse_activity_io("wchar: 0\nwrite_bytes: 0\nread_bytes: 0\n").unwrap();
        assert_eq!(zero.read_bytes, 0);
        assert_eq!(zero.write_bytes, 0);
    }

    #[test]
    fn unavailable_process_and_empty_batch_never_reuse_lifetime_cpu() {
        let (mut process, _, _) = activity_fixture();
        process.pid = pt_common::ProcessId(u32::MAX);
        process.start_id = StartId::from_linux("unavailable", 1, u32::MAX);
        let window = Duration::from_millis(500);
        assert!(sample_process_activity(&[], window).is_empty());
        let measured = sample_process_activity(&[&process], window);
        let activity = &measured[&u32::MAX];
        assert!(activity.cpu_percent.is_none());
        assert!(activity.io_active.is_none());
        assert!(activity
            .cpu_error
            .as_ref()
            .unwrap()
            .contains("first sample"));
        assert_eq!(activity.start_id, process.start_id);
        assert!(sample_process_activity(&[&process], Duration::ZERO).is_empty());
    }

    #[test]
    fn owned_busy_and_sleeping_processes_are_sampled_together() {
        use std::process::{Command, Stdio};

        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let spawn = |program: &str, args: &[&str]| {
            OwnedChild(
                Command::new(program)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn owned CPU fixture"),
            )
        };
        let busy = spawn("sh", &["-c", "while :; do :; done"]);
        let idle = spawn("sleep", &["300"]);
        let scan = super::super::quick_scan(&super::super::QuickScanOptions {
            pids: vec![busy.0.id(), idle.0.id()],
            timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        })
        .expect("scan actual owned fixtures");
        assert_eq!(scan.processes.len(), 2);
        let processes: Vec<_> = scan.processes.iter().collect();
        let activity = sample_process_activity(&processes, Duration::from_millis(500));
        let busy = &activity[&busy.0.id()];
        let idle = &activity[&idle.0.id()];
        let busy_cpu = busy.cpu_percent.expect("busy CPU sample is available");
        let idle_cpu = idle.cpu_percent.expect("sleeping CPU sample is available");
        // Shared/limited CI hosts may grant much less than a whole core; the
        // collector must still distinguish actual progress from an idle sleeper.
        assert!(busy_cpu > idle_cpu, "busy={busy:?}, idle={idle:?}");
        assert!(idle_cpu < 10.0, "idle={idle:?}");
        for sample in [busy, idle] {
            assert_eq!(sample.source, "procfs_window");
            assert!(sample.cpu_window_seconds.unwrap() >= 0.5);
            assert!(sample.io_window_seconds.unwrap() >= 0.5);
            let pressure = sample
                .pressure
                .as_ref()
                .expect("pressure evidence is attached");
            assert!(pressure.major_faults.is_some(), "{pressure:?}");
            assert!(pressure.memory.as_ref().unwrap().threads >= 1);
            // CI may disable task accounting; absence must remain explained.
            assert!(
                pressure.leader_run_queue_wait_percent.is_some()
                    || pressure.scheduler_error.is_some()
            );
            assert!(
                pressure.leader_blkio_delay_percent.is_some() || pressure.blkio_error.is_some()
            );
        }
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
    fn tick_parser_rejects_wrong_pid_and_overflowing_totals() {
        let content = format!(
            "1234 (worker) S 1 1234 1234 0 -1 4194304 100 0 0 0 {} 1 0 0 20 0 1 0 12345",
            u64::MAX
        );
        assert!(parse_tick_snapshot(&content, 1234, UNIX_EPOCH).is_none());
        let valid = "1234 (worker) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 1 0 0 20 0 1 0 12345";
        assert!(parse_tick_snapshot(valid, 5678, UNIX_EPOCH).is_none());
        assert!(parse_tick_snapshot(valid, 1234, UNIX_EPOCH).is_some());
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
