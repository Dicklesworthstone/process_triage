//! Measured host resource changes around an action run.
//!
//! An exited process and its planned footprint do not prove host resource relief.
//! Keep the before/after observations, measure CPU and PSI over separate windows,
//! and bind persisted measurements to the actual execution records. These are
//! host-wide observations, not causal attribution to an individual action.
//!
//! Source semantics: <https://docs.kernel.org/accounting/psi.html> and
//! <https://man7.org/linux/man-pages/man5/proc_stat.5.html>. In particular, CPU
//! `full` is undefined at host scope and iowait counters can regress.

use super::resource_prediction::{
    attach_prediction_comparison, ResourcePredictionSnapshot, RunResourcePredictionComparison,
    ValidatedResourcePredictions,
};
use super::{ExecutionClock, SavedActionOutcome};
use crate::collect::pressure::{
    read_pressure_snapshot, PressureSnapshot, PressureWindow, PsiLine, PsiResource, StallFractions,
    Unavailable, VmStat,
};
use crate::decision::Action;
use crate::plan::Plan;
use chrono::{DateTime, Utc};
use pt_common::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const DEFAULT_SETTLE_MS: u64 = 15_000;
pub const MAX_RESOURCE_WINDOW_MS: u64 = 300_000;
pub const RESOURCE_OBSERVATION_SCHEMA_VERSION: u32 = 1;
/// Bound per-tick procfs work and the size of a full five-minute artifact. If a
/// selection exceeds this limit, host observations remain available, but no
/// arbitrary subset is presented as the complete process observation set.
pub const MAX_PROCESS_RESOURCE_TARGETS: usize = 32;
const SAMPLE_INTERVAL_MS: u64 = 1_000;
const MAX_WINDOW_SAMPLES: usize = (MAX_RESOURCE_WINDOW_MS / SAMPLE_INTERVAL_MS) as usize + 1;

/// Aggregate `/proc/stat` counters in USER_HZ ticks. Guest counters are already
/// included in user/nice and must not be added to the total a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl HostCpuTimes {
    fn counters(self) -> [u64; 8] {
        [
            self.user,
            self.nice,
            self.system,
            self.idle,
            self.iowait,
            self.irq,
            self.softirq,
            self.steal,
        ]
    }
}

/// One read-only host observation. CLOCK_BOOTTIME brackets the whole read on
/// Linux; wall-clock timestamps are retained for display, never for rate math.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub boot_id: Option<String>,
    pub clock_ticks_per_second: Option<u64>,
    pub monotonic_start_ns: Option<u64>,
    pub monotonic_end_ns: Option<u64>,
    pub pressure: PressureSnapshot,
    pub cpu_times: Option<HostCpuTimes>,
    /// Exact selected process incarnations, never service/cgroup aggregates.
    /// Counters are present only after identity and UID were checked around a
    /// read through a pinned proc directory. Missing/exited targets are errors,
    /// not observations of zero CPU or zero resident memory.
    #[serde(default)]
    pub processes: Vec<ProcessResourceObservation>,
    #[serde(default)]
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResourceObservation {
    pub target: ProcessIdentity,
    pub monotonic_start_ns: Option<u64>,
    pub monotonic_end_ns: Option<u64>,
    pub user_ticks: Option<u64>,
    pub system_ticks: Option<u64>,
    /// Resident footprint, including shared pages. This is not private memory
    /// and must not be described as reclaimable or freed memory.
    pub rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObservationWindow {
    pub requested_duration_ms: u64,
    pub sample_interval_ms: u64,
    pub samples: Vec<ResourceObservation>,
}

/// Positive deltas mean the value increased. For memory availability that is an
/// improvement; for utilization or pressure it is a worsening, not "freed CPU".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservedMetricDelta {
    pub before: Option<f64>,
    pub after: Option<f64>,
    pub delta: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HostCpuUsage {
    /// On-CPU time: user, nice, system, irq and softirq; excludes idle, iowait and steal.
    pub busy_percent: f64,
    pub idle_percent: f64,
    pub iowait_percent: f64,
    pub steal_percent: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuResourceDelta {
    pub busy_percent: ObservedMetricDelta,
    pub idle_percent: ObservedMetricDelta,
    pub iowait_percent: ObservedMetricDelta,
    pub steal_percent: ObservedMetricDelta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PsiResourceDelta {
    pub some_avg10_percent: ObservedMetricDelta,
    pub full_avg10_percent: ObservedMetricDelta,
    pub some_window_percent: ObservedMetricDelta,
    pub full_window_percent: ObservedMetricDelta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceWindowSummary {
    pub requested_duration_ms: u64,
    pub observed_duration_ms: Option<f64>,
    pub sample_count: usize,
    /// The requested observation interval completed; this does not prove the host settled.
    pub complete: bool,
    pub cpu_usage: Option<HostCpuUsage>,
    pub pressure_rates: Option<PressureWindow>,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessResourceWindowSummary {
    pub sample_count: usize,
    pub complete: bool,
    pub first_read_start_ns: Option<u64>,
    pub first_read_end_ns: Option<u64>,
    pub last_read_start_ns: Option<u64>,
    pub last_read_end_ns: Option<u64>,
    /// Midpoint-to-midpoint time between this process's own read brackets.
    /// The bounds retain read skew; the host sample cadence is not substituted.
    pub observed_duration_ms: Option<f64>,
    pub minimum_duration_ms: Option<f64>,
    pub maximum_duration_ms: Option<f64>,
    /// (user + system) tick delta / USER_HZ / observed process interval.
    pub cpu_cores: Option<f64>,
    /// 100% means all observed online logical CPUs, not one core.
    pub cpu_host_percent: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResourceDelta {
    pub target: ProcessIdentity,
    /// All actual attempts on this incarnation in this run. A combined window
    /// does not establish the efficacy of any one action in a staged sequence.
    pub action_ids: Vec<String>,
    pub scope: String,
    pub attribution: String,
    pub comparable: bool,
    pub before_window: ProcessResourceWindowSummary,
    pub after_window: ProcessResourceWindowSummary,
    pub cpu_cores: ObservedMetricDelta,
    pub cpu_host_percent: ObservedMetricDelta,
    pub rss_bytes: ObservedMetricDelta,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEvidenceBinding {
    pub run_id: String,
    pub action_ids: Vec<String>,
    pub boot_id: String,
    /// Execution clocks have whole-tick precision, not nanosecond precision.
    pub execution_clock_resolution_ns: u64,
    pub timing_validation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDelta {
    pub scope: String,
    pub attribution: String,
    pub delta_convention: String,
    pub comparable: bool,
    /// CPU-normalized comparisons require the same observed online capacity.
    pub cpu_capacity_comparable: bool,
    /// Common capacity of the validated execution windows; legacy evidence may lack it.
    #[serde(default)]
    pub observed_logical_cpus: Option<u32>,
    pub before_at_ms: Option<u64>,
    pub after_at_ms: Option<u64>,
    pub interval_ms: Option<f64>,
    pub before_window: ResourceWindowSummary,
    pub after_window: ResourceWindowSummary,
    pub available_memory_bytes: ObservedMetricDelta,
    pub swap_used_bytes: ObservedMetricDelta,
    pub allocated_file_handles: ObservedMetricDelta,
    pub load1: ObservedMetricDelta,
    pub load5: ObservedMetricDelta,
    pub load15: ObservedMetricDelta,
    pub load_ratio: ObservedMetricDelta,
    pub cpu: CpuResourceDelta,
    pub cpu_pressure: PsiResourceDelta,
    pub memory_pressure: PsiResourceDelta,
    pub io_pressure: PsiResourceDelta,
    /// Populated only after the saved observations have been bound to actual
    /// canonical execution attempts; unexecuted selected targets are excluded.
    #[serde(default)]
    pub processes: Vec<ProcessResourceDelta>,
    pub binding: Option<ResourceEvidenceBinding>,
    #[serde(default)]
    pub prediction_comparison: Option<RunResourcePredictionComparison>,
    pub unavailable: Vec<Unavailable>,
    pub limitations: Vec<String>,
}

fn unavailable(
    sources: &mut Vec<Unavailable>,
    source: impl Into<String>,
    reason: impl Into<String>,
) {
    sources.push(Unavailable {
        source: source.into(),
        reason: reason.into(),
    });
}

/// Parse only the aggregate `cpu` row, strictly. At least the eight counters
/// supported since Linux 2.6.11 are required; a cpuN row is never a substitute.
pub fn parse_host_cpu_times(content: &str) -> Result<HostCpuTimes, String> {
    let mut rows = content
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("cpu"));
    let row = rows.next().ok_or("aggregate CPU row is missing")?;
    if rows.next().is_some() {
        return Err("duplicate aggregate CPU rows".into());
    }
    let values = row
        .split_whitespace()
        .skip(1)
        .map(|value| value.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid aggregate CPU counter: {error}"))?;
    if values.len() < 8 {
        return Err("aggregate CPU row is missing required counters".into());
    }
    Ok(HostCpuTimes {
        user: values[0],
        nice: values[1],
        system: values[2],
        idle: values[3],
        iowait: values[4],
        irq: values[5],
        softirq: values[6],
        steal: values[7],
    })
}

#[cfg(target_os = "linux")]
fn boot_clock_ns() -> Result<u64, String> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into the valid stack-allocated timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let seconds = u64::try_from(clock.tv_sec).map_err(|_| "negative boot clock")?;
    let nanos = u64::try_from(clock.tv_nsec).map_err(|_| "negative boot nanoseconds")?;
    if nanos >= 1_000_000_000 {
        return Err("invalid boot clock nanoseconds".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| "boot clock overflow".into())
}

fn target_belongs_to_boot(target: &ProcessIdentity, boot_id: &str) -> bool {
    if target.quality != pt_common::IdentityQuality::Full || target.pid.0 == 0 {
        return false;
    }
    let mut parts = target.start_id.0.split(':');
    let (Some(boot), Some(ticks), Some(pid), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(ticks) = ticks.parse::<u64>().ok() else {
        return false;
    };
    boot == boot_id
        && pid.parse::<u32>() == Ok(target.pid.0)
        && target.start_id == pt_common::StartId::from_linux(boot_id, ticks, target.pid.0)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessCounters {
    start_ticks: u64,
    user_ticks: u64,
    system_ticks: u64,
    rss_bytes: u64,
}

/// Parse exactly the required process counters. The general process parser's
/// defaults are inappropriate for measured relief: a missing counter is unknown.
#[cfg(any(target_os = "linux", test))]
fn parse_process_counters(
    content: &str,
    expected_pid: u32,
    page_size: u64,
) -> Result<ProcessCounters, String> {
    let open = content.find('(').ok_or("process stat command is missing")?;
    let close = content
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or("process stat command is malformed")?;
    let parse_count = |text: &str, field: &str| -> Result<u64, String> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("process stat {field} is not an unsigned count"));
        }
        text.parse::<u64>()
            .map_err(|_| format!("process stat {field} overflows u64"))
    };
    if parse_count(content[..open].trim(), "PID")? != u64::from(expected_pid) {
        return Err("process stat PID differs from the selected target".into());
    }
    let fields: Vec<_> = content[close + 1..].split_whitespace().collect();
    match fields.first().copied() {
        Some("Z" | "X" | "x") => {
            return Err(
                "selected process has exited or is a zombie; no zero footprint inferred".into(),
            );
        }
        Some("R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I") => {}
        _ => return Err("process stat state is missing or invalid".into()),
    }
    let count = |index: usize, field: &str| -> Result<u64, String> {
        parse_count(
            fields
                .get(index)
                .ok_or_else(|| format!("process stat {field} is missing"))?,
            field,
        )
    };
    let user_ticks = count(11, "utime")?;
    let system_ticks = count(12, "stime")?;
    user_ticks
        .checked_add(system_ticks)
        .ok_or("process CPU counter total overflows u64")?;
    let start_ticks = count(19, "starttime")?;
    let rss_pages = count(21, "rss")?;
    if page_size == 0 {
        return Err("process page size is unavailable".into());
    }
    let rss_bytes = rss_pages
        .checked_mul(page_size)
        .ok_or("process RSS byte count overflows u64")?;
    Ok(ProcessCounters {
        start_ticks,
        user_ticks,
        system_ticks,
        rss_bytes,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_process_uids(content: &str) -> Result<[u32; 4], String> {
    let mut rows = content.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let row = rows.next().ok_or("process UID field is unavailable")?;
    if rows.next().is_some() {
        return Err("process UID field is duplicated".into());
    }
    let mut values = row.split_whitespace();
    let mut uids = [0; 4];
    for uid in &mut uids {
        let value = values.next().ok_or("process UID field is incomplete")?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("process UID field is invalid".into());
        }
        *uid = value.parse().map_err(|_| "process UID exceeds u32")?;
    }
    if values.next().is_some() {
        return Err("process UID field has extra values".into());
    }
    Ok(uids)
}

#[cfg(any(target_os = "linux", test))]
fn require_process_leader(content: &str, expected_pid: u32) -> Result<(), String> {
    // /proc/TID/stat is also readable for nonleader threads, but its CPU counters
    // describe one thread. Do not label that as the selected process's total.
    for field in ["Pid:", "Tgid:"] {
        let mut rows = content.lines().filter_map(|line| line.strip_prefix(field));
        let value = rows
            .next()
            .ok_or_else(|| format!("selected process {field} is unavailable"))?
            .trim();
        if rows.next().is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.parse::<u32>() != Ok(expected_pid)
        {
            return Err("selected identity is not the observed process/thread-group leader".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct ResourceProcDirectory(std::fs::File);

#[cfg(target_os = "linux")]
impl ResourceProcDirectory {
    fn open(pid: u32) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .map(Self)
            .map_err(|error| format!("cannot pin selected process directory: {error}"))
    }

    fn read(&self, field: &str) -> Result<String, String> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        const MAX_PROC_FIELD_BYTES: u64 = 64 * 1024;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}/{field}", self.0.as_raw_fd()))
            .map_err(|error| format!("cannot read selected process {field}: {error}"))?;
        let mut content = String::new();
        file.take(MAX_PROC_FIELD_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("cannot read selected process {field}: {error}"))?;
        if content.len() as u64 > MAX_PROC_FIELD_BYTES {
            return Err(format!("selected process {field} exceeds the read bound"));
        }
        Ok(content)
    }
}

#[cfg(target_os = "linux")]
fn read_process_resources(
    target: &ProcessIdentity,
    boot_id: &str,
    page_size: u64,
) -> Result<ProcessCounters, String> {
    if !target_belongs_to_boot(target, boot_id) {
        return Err("selected process lacks a full identity from the observed boot".into());
    }
    let directory = ResourceProcDirectory::open(target.pid.0)?;
    let before_status = directory.read("status")?;
    require_process_leader(&before_status, target.pid.0)?;
    let before_uids = parse_process_uids(&before_status)?;
    let counters = parse_process_counters(&directory.read("stat")?, target.pid.0, page_size)?;
    let after_status = directory.read("status")?;
    require_process_leader(&after_status, target.pid.0)?;
    let after_uids = parse_process_uids(&after_status)?;
    let after = parse_process_counters(&directory.read("stat")?, target.pid.0, page_size)?;
    if before_uids != after_uids
        || before_uids[0] != target.uid
        || target.start_id
            != pt_common::StartId::from_linux(boot_id, counters.start_ticks, target.pid.0)
        || after.start_ticks != counters.start_ticks
    {
        return Err("selected process identity or credentials changed during observation".into());
    }
    if after.user_ticks < counters.user_ticks || after.system_ticks < counters.system_ticks {
        return Err("selected process CPU counters decreased during observation".into());
    }
    Ok(counters)
}

fn capture_process_resources(
    target: &ProcessIdentity,
    boot_id: Option<&str>,
) -> ProcessResourceObservation {
    let mut sample = ProcessResourceObservation {
        target: target.clone(),
        monotonic_start_ns: None,
        monotonic_end_ns: None,
        user_ticks: None,
        system_ticks: None,
        rss_bytes: None,
        unavailable: Vec::new(),
    };
    #[cfg(target_os = "linux")]
    {
        sample.monotonic_start_ns = boot_clock_ns()
            .map_err(|reason| unavailable(&mut sample.unavailable, "process_clock", reason))
            .ok();
        // SAFETY: sysconf reads the kernel's base page size; no memory is accessed.
        let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size > 0);
        let result = boot_id
            .zip(page_size)
            .ok_or_else(|| "process boot identity or page size is unavailable".to_string())
            .and_then(|(boot, page_size)| read_process_resources(target, boot, page_size));
        match result {
            Ok(counters) => {
                sample.user_ticks = Some(counters.user_ticks);
                sample.system_ticks = Some(counters.system_ticks);
                sample.rss_bytes = Some(counters.rss_bytes);
            }
            Err(reason) => unavailable(&mut sample.unavailable, "process_counters", reason),
        }
        sample.monotonic_end_ns = boot_clock_ns()
            .map_err(|reason| unavailable(&mut sample.unavailable, "process_clock", reason))
            .ok();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = boot_id;
        unavailable(
            &mut sample.unavailable,
            "process_counters",
            "identity-bound CPU/RSS observations require Linux procfs",
        );
    }
    sample
}

/// Capture errors as unavailable evidence, so missing sensors do not turn into zero relief.
pub fn capture_resource_observation() -> ResourceObservation {
    capture_resource_observation_for_targets(&[])
}

/// Capture selected process counters inside the host sample's clock bracket.
/// A pinned process directory prevents numeric PID reuse from redirecting reads.
pub fn capture_resource_observation_for_targets(
    targets: &[ProcessIdentity],
) -> ResourceObservation {
    let mut errors = Vec::new();
    #[cfg(target_os = "linux")]
    let (start, boot_id, hz) = {
        let start = boot_clock_ns()
            .map_err(|reason| unavailable(&mut errors, "CLOCK_BOOTTIME", reason))
            .ok();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())
            .and_then(|value| {
                let value = value.trim();
                if uuid::Uuid::parse_str(value).is_err() {
                    Err("invalid kernel boot UUID".into())
                } else {
                    Ok(value.to_string())
                }
            })
            .map_err(|reason| unavailable(&mut errors, "boot_id", reason))
            .ok();
        // SAFETY: sysconf reads the kernel's USER_HZ conversion factor.
        let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
            .ok()
            .filter(|hz| *hz > 0);
        if hz.is_none() {
            unavailable(
                &mut errors,
                "clock_ticks_per_second",
                "USER_HZ is unavailable",
            );
        }
        (start, boot, hz)
    };
    #[cfg(not(target_os = "linux"))]
    let (start, boot_id, hz) = {
        unavailable(&mut errors, "resource_observation", "boot-bound host CPU and pressure-window measurements are currently supported only on Linux");
        (None, None, None)
    };
    let processes = if targets.len() > MAX_PROCESS_RESOURCE_TARGETS {
        unavailable(
            &mut errors,
            "process_observations",
            format!("selection exceeds the {MAX_PROCESS_RESOURCE_TARGETS}-process observation bound; no partial subset was sampled"),
        );
        Vec::new()
    } else {
        targets
            .iter()
            .map(|target| capture_process_resources(target, boot_id.as_deref()))
            .collect()
    };
    let pressure = read_pressure_snapshot();
    #[cfg(target_os = "linux")]
    let cpu_times = std::fs::read_to_string("/proc/stat")
        .map_err(|error| error.to_string())
        .and_then(|text| parse_host_cpu_times(&text))
        .map_err(|reason| unavailable(&mut errors, "/proc/stat", reason))
        .ok();
    #[cfg(not(target_os = "linux"))]
    let cpu_times = None;
    #[cfg(target_os = "linux")]
    let end = boot_clock_ns()
        .map_err(|reason| unavailable(&mut errors, "CLOCK_BOOTTIME", reason))
        .ok();
    #[cfg(not(target_os = "linux"))]
    let end = None;
    ResourceObservation {
        boot_id,
        clock_ticks_per_second: hz,
        monotonic_start_ns: start,
        monotonic_end_ns: end,
        pressure,
        cpu_times,
        processes,
        unavailable: errors,
    }
}

/// Observe a bounded window at up to one-second intervals. Zero duration emits
/// one point sample and no invented rate. The callback can persist each raw
/// sample with its apply run ID; callback failures should be retained by the caller.
pub fn collect_resource_window(
    duration: Duration,
    targets: &[ProcessIdentity],
    on_sample: impl FnMut(&ResourceObservation),
) -> Result<ResourceObservationWindow, String> {
    let clock = Instant::now();
    collect_window_with(
        duration,
        || capture_resource_observation_for_targets(targets),
        std::thread::sleep,
        || clock.elapsed(),
        on_sample,
    )
}

fn collect_window_with(
    duration: Duration,
    mut capture: impl FnMut() -> ResourceObservation,
    mut sleep: impl FnMut(Duration),
    mut elapsed: impl FnMut() -> Duration,
    mut on_sample: impl FnMut(&ResourceObservation),
) -> Result<ResourceObservationWindow, String> {
    let millis = duration.as_nanos().div_ceil(1_000_000);
    if millis > u128::from(MAX_RESOURCE_WINDOW_MS) {
        return Err(format!(
            "resource window exceeds maximum {MAX_RESOURCE_WINDOW_MS} milliseconds"
        ));
    }
    let requested_duration_ms = millis as u64;
    let duration = Duration::from_millis(requested_duration_ms);
    let first = capture();
    on_sample(&first);
    let mut samples = vec![first];
    // Start the waiting interval after the first read/callback, so collector
    // latency cannot silently shorten the promised baseline or settle window.
    let started = elapsed();
    loop {
        let spent = elapsed()
            .checked_sub(started)
            .ok_or("resource sampling clock moved backwards")?;
        if spent >= duration {
            break;
        }
        if samples.len() >= MAX_WINDOW_SAMPLES {
            return Err("resource sampling exceeded its sample bound".into());
        }
        sleep((duration - spent).min(Duration::from_millis(SAMPLE_INTERVAL_MS)));
        let sample = capture();
        on_sample(&sample);
        samples.push(sample);
    }
    Ok(ResourceObservationWindow {
        requested_duration_ms,
        sample_interval_ms: SAMPLE_INTERVAL_MS,
        samples,
    })
}

struct ValidWindow<'a> {
    first: &'a ResourceObservation,
    last: &'a ResourceObservation,
    boot_id: &'a str,
    elapsed_ns: u64,
    complete: bool,
}

fn validate_window(window: &ResourceObservationWindow) -> Result<ValidWindow<'_>, String> {
    if window.requested_duration_ms > MAX_RESOURCE_WINDOW_MS
        || window.sample_interval_ms != SAMPLE_INTERVAL_MS
        || window.samples.is_empty()
        || window.samples.len() > MAX_WINDOW_SAMPLES
    {
        return Err("missing or oversized resource observation window".into());
    }
    let first = &window.samples[0];
    let last = &window.samples[window.samples.len() - 1];
    let boot_id = first
        .boot_id
        .as_deref()
        .filter(|boot| uuid::Uuid::parse_str(boot).is_ok_and(|id| !id.is_nil()))
        .ok_or("a valid observed boot identity is required")?;
    let mut previous_end = None;
    for sample in &window.samples {
        if sample.processes.len() > MAX_PROCESS_RESOURCE_TARGETS {
            return Err("resource sample exceeds the process observation bound".into());
        }
        if sample.boot_id.as_deref() != Some(boot_id) {
            return Err("boot identity changed or is missing inside the window".into());
        }
        let start = sample
            .monotonic_start_ns
            .ok_or("monotonic observation start is missing")?;
        let end = sample
            .monotonic_end_ns
            .ok_or("monotonic observation end is missing")?;
        if end < start || previous_end.is_some_and(|previous| start < previous) {
            return Err("resource reads overlap or the monotonic clock moved backwards".into());
        }
        previous_end = Some(end);
    }
    let elapsed_ns = last
        .monotonic_end_ns
        .unwrap()
        .checked_sub(first.monotonic_end_ns.unwrap())
        .ok_or("resource observation clock moved backwards")?;
    let complete = if window.requested_duration_ms == 0 {
        // A deliberate point comparison is not an interval, even if supplied
        // with extra samples from an unrelated caller.
        window.samples.len() == 1
    } else {
        window.samples.len() >= 2 && elapsed_ns >= window.requested_duration_ms * 1_000_000
    };
    Ok(ValidWindow {
        first,
        last,
        boot_id,
        elapsed_ns,
        complete,
    })
}

fn counter_delta(
    samples: &[ResourceObservation],
    source: &str,
    read: impl Fn(&ResourceObservation) -> Option<u64>,
    errors: &mut Vec<Unavailable>,
) -> Option<u64> {
    let mut first = None;
    let mut previous = None;
    for (index, sample) in samples.iter().enumerate() {
        let Some(value) = read(sample) else {
            unavailable(
                errors,
                source,
                format!("counter unavailable in sample {index}"),
            );
            return None;
        };
        if previous.is_some_and(|previous| value < previous) {
            unavailable(
                errors,
                source,
                format!("counter regressed at sample {index}; no rate inferred"),
            );
            return None;
        }
        first.get_or_insert(value);
        previous = Some(value);
    }
    previous?.checked_sub(first?)
}

fn cpu_usage(
    window: &ResourceObservationWindow,
    errors: &mut Vec<Unavailable>,
) -> Option<HostCpuUsage> {
    let cpus = window.samples.first()?.pressure.cpus;
    if cpus == 0
        || window
            .samples
            .iter()
            .any(|sample| sample.pressure.cpus != cpus)
    {
        unavailable(
            errors,
            "cpu_usage",
            "online CPU capacity is unavailable or changed during the window",
        );
        return None;
    }
    let mut deltas = [0u64; 8];
    for (index, delta) in deltas.iter_mut().enumerate() {
        *delta = counter_delta(
            &window.samples,
            "cpu_usage",
            |sample| sample.cpu_times.map(|times| times.counters()[index]),
            errors,
        )?;
    }
    let total: u128 = deltas.iter().map(|delta| u128::from(*delta)).sum();
    if total == 0 {
        unavailable(
            errors,
            "cpu_usage",
            "aggregate CPU counters did not advance; no utilization inferred",
        );
        return None;
    }
    let percent = |ticks: u128| ticks as f64 / total as f64 * 100.0;
    let idle = u128::from(deltas[3]);
    let iowait = u128::from(deltas[4]);
    let steal = u128::from(deltas[7]);
    Some(HostCpuUsage {
        busy_percent: percent(total - idle - iowait - steal),
        idle_percent: percent(idle),
        iowait_percent: percent(iowait),
        steal_percent: percent(steal),
    })
}

fn psi_fractions(
    window: &ResourceObservationWindow,
    seconds: f64,
    name: &str,
    resource: fn(&PressureSnapshot) -> Option<PsiResource>,
    include_full: bool,
    errors: &mut Vec<Unavailable>,
) -> Option<StallFractions> {
    let mut fraction = |full: bool| {
        let source = format!("psi.{name}.{}.window", if full { "full" } else { "some" });
        let delta = counter_delta(
            &window.samples,
            &source,
            |sample| {
                resource(&sample.pressure)
                    .and_then(|resource| if full { resource.full } else { resource.some })
                    .map(|line| line.total_us)
            },
            errors,
        )?;
        let fraction = delta as f64 / (seconds * 1_000_000.0);
        if !(0.0..=1.0).contains(&fraction) {
            unavailable(
                errors,
                source,
                "stall counter exceeds the measured interval; sample timing is not comparable",
            );
            return None;
        }
        Some(fraction)
    };
    let some = fraction(false);
    let full = if include_full { fraction(true) } else { None };
    (some.is_some() || full.is_some()).then_some(StallFractions { some, full })
}

fn pressure_rates(
    window: &ResourceObservationWindow,
    seconds: f64,
    errors: &mut Vec<Unavailable>,
) -> PressureWindow {
    let cpu = psi_fractions(
        window,
        seconds,
        "cpu",
        |snapshot| snapshot.cpu,
        false,
        errors,
    );
    let memory = psi_fractions(
        window,
        seconds,
        "memory",
        |snapshot| snapshot.memory,
        true,
        errors,
    );
    let io = psi_fractions(window, seconds, "io", |snapshot| snapshot.io, true, errors);
    let mut vm = |name: &str, field: fn(&VmStat) -> Option<u64>| {
        counter_delta(
            &window.samples,
            name,
            |sample| sample.pressure.vmstat.as_ref().and_then(field),
            errors,
        )
    };
    PressureWindow {
        seconds,
        cpu,
        memory,
        io,
        swap_in_per_s: vm("vmstat.pswpin", |vm| vm.pswpin).map(|delta| delta as f64 / seconds),
        swap_out_per_s: vm("vmstat.pswpout", |vm| vm.pswpout).map(|delta| delta as f64 / seconds),
        major_faults_per_s: vm("vmstat.pgmajfault", |vm| vm.pgmajfault)
            .map(|delta| delta as f64 / seconds),
        direct_reclaim_scans_per_s: vm("vmstat.pgscan_direct", |vm| vm.pgscan_direct)
            .map(|delta| delta as f64 / seconds),
        alloc_stalls_per_s: vm("vmstat.allocstall", |vm| vm.allocstall)
            .map(|delta| delta as f64 / seconds),
        oom_kills: vm("vmstat.oom_kill", |vm| vm.oom_kill),
    }
}

pub(super) fn summarize_window(window: &ResourceObservationWindow) -> ResourceWindowSummary {
    let mut report = ResourceWindowSummary {
        requested_duration_ms: window.requested_duration_ms,
        observed_duration_ms: None,
        sample_count: window.samples.len(),
        complete: false,
        cpu_usage: None,
        pressure_rates: None,
        unavailable: Vec::new(),
    };
    // Keep platform/read errors even when a required clock or boot ID is absent.
    // Bound inspection of deserialized windows before iterating their samples.
    if window.samples.len() <= MAX_WINDOW_SAMPLES {
        for sample in &window.samples {
            report
                .unavailable
                .extend(sample.unavailable.iter().cloned());
            report
                .unavailable
                .extend(sample.pressure.unavailable.iter().cloned());
        }
    }
    let evidence = match validate_window(window) {
        Ok(evidence) => evidence,
        Err(reason) => {
            unavailable(&mut report.unavailable, "window", reason);
            deduplicate_unavailable(&mut report.unavailable);
            return report;
        }
    };
    report.observed_duration_ms = Some(evidence.elapsed_ns as f64 / 1_000_000.0);
    report.complete = evidence.complete;
    unavailable(&mut report.unavailable, "psi.cpu.full", "CPU full pressure is undefined at host scope; the kernel's compatibility zero is not a relief measurement");
    if !evidence.complete {
        unavailable(
            &mut report.unavailable,
            "window",
            "the requested observation window did not complete",
        );
    } else if window.requested_duration_ms == 0 {
        unavailable(
            &mut report.unavailable,
            "window_rates",
            "zero-duration point sample: CPU/PSI rates and settling are unobserved",
        );
    } else {
        report.cpu_usage = cpu_usage(window, &mut report.unavailable);
        report.pressure_rates = Some(pressure_rates(
            window,
            evidence.elapsed_ns as f64 / 1_000_000_000.0,
            &mut report.unavailable,
        ));
    }
    deduplicate_unavailable(&mut report.unavailable);
    report
}

fn deduplicate_unavailable(errors: &mut Vec<Unavailable>) {
    let mut seen = HashSet::new();
    errors.retain(|error| seen.insert((error.source.clone(), error.reason.clone())));
}

fn summarize_process_window(
    window: &ResourceObservationWindow,
    target: &ProcessIdentity,
) -> ProcessResourceWindowSummary {
    let mut summary = ProcessResourceWindowSummary::default();
    let valid = match validate_window(window) {
        Ok(valid) if target_belongs_to_boot(target, valid.boot_id) => valid,
        Ok(_) => {
            unavailable(
                &mut summary.unavailable,
                "process_identity",
                "selected target lacks a full identity from this observation boot",
            );
            return summary;
        }
        Err(reason) => {
            unavailable(&mut summary.unavailable, "process_window", reason);
            return summary;
        }
    };
    let mut observations = Vec::new();
    let mut previous_end = None;
    let mut complete = valid.complete;
    for sample in &window.samples {
        let mut matches = sample
            .processes
            .iter()
            .filter(|process| process.target.matches(target));
        let Some(process) = matches.next() else {
            unavailable(&mut summary.unavailable, "process_identity", "an exact selected process observation is missing; exit, PID reuse or omitted data are not zero usage");
            complete = false;
            continue;
        };
        if matches.next().is_some() {
            unavailable(
                &mut summary.unavailable,
                "process_identity",
                "a sample repeats the selected process incarnation",
            );
            complete = false;
            continue;
        }
        observations.push(process);
        summary.unavailable.extend(process.unavailable.clone());
        if !target_belongs_to_boot(&process.target, valid.boot_id)
            || process.user_ticks.is_none()
            || process.system_ticks.is_none()
            || process
                .user_ticks
                .zip(process.system_ticks)
                .is_none_or(|(user, system)| user.checked_add(system).is_none())
            || process.rss_bytes.is_none()
            || !process.unavailable.is_empty()
        {
            unavailable(
                &mut summary.unavailable,
                "process_counters",
                "identity-checked CPU and RSS counters are required for every process sample",
            );
            complete = false;
        }
        match process.monotonic_start_ns.zip(process.monotonic_end_ns) {
            Some((start, end))
                if start <= end
                    && sample
                        .monotonic_start_ns
                        .is_some_and(|outer| start >= outer)
                    && sample.monotonic_end_ns.is_some_and(|outer| end <= outer)
                    && previous_end.is_none_or(|previous| start >= previous) =>
            {
                previous_end = Some(end);
            }
            _ => {
                unavailable(
                    &mut summary.unavailable,
                    "process_clock",
                    "process read brackets are missing, overlap, or escape their host observation",
                );
                complete = false;
            }
        }
    }
    summary.sample_count = observations.len();
    if let (Some(first), Some(last)) = (observations.first(), observations.last()) {
        summary.first_read_start_ns = first.monotonic_start_ns;
        summary.first_read_end_ns = first.monotonic_end_ns;
        summary.last_read_start_ns = last.monotonic_start_ns;
        summary.last_read_end_ns = last.monotonic_end_ns;
    }
    deduplicate_unavailable(&mut summary.unavailable);
    summary.complete = complete && observations.len() == window.samples.len();
    if !summary.complete {
        return summary;
    }
    let first = observations[0];
    let last = observations[observations.len() - 1];
    summary.rss_bytes = last.rss_bytes;
    if window.requested_duration_ms == 0 || observations.len() < 2 {
        unavailable(
            &mut summary.unavailable,
            "process_cpu",
            "a point observation cannot establish a process CPU rate",
        );
        return summary;
    }
    let first_start = first.monotonic_start_ns.unwrap();
    let first_end = first.monotonic_end_ns.unwrap();
    let last_start = last.monotonic_start_ns.unwrap();
    let last_end = last.monotonic_end_ns.unwrap();
    let Some(minimum_ns) = last_start.checked_sub(first_end).filter(|ns| *ns > 0) else {
        unavailable(
            &mut summary.unavailable,
            "process_cpu",
            "process read skew leaves no strictly positive observation interval",
        );
        return summary;
    };
    let maximum_ns = last_end - first_start;
    let midpoint_ns = ((u128::from(last_start) + u128::from(last_end))
        - (u128::from(first_start) + u128::from(first_end))) as f64
        / 2.0;
    summary.observed_duration_ms = Some(midpoint_ns / 1_000_000.0);
    summary.minimum_duration_ms = Some(minimum_ns as f64 / 1_000_000.0);
    summary.maximum_duration_ms = Some(maximum_ns as f64 / 1_000_000.0);
    let cpus = valid.first.pressure.cpus;
    let hz = valid
        .first
        .clock_ticks_per_second
        .filter(|hz| (1..=1_000_000_000).contains(hz));
    if cpus == 0
        || hz.is_none()
        || window
            .samples
            .iter()
            .any(|sample| sample.pressure.cpus != cpus || sample.clock_ticks_per_second != hz)
    {
        unavailable(&mut summary.unavailable, "process_cpu", "stable observed online CPU capacity and USER_HZ are required throughout the process window");
        return summary;
    }
    for pair in observations.windows(2) {
        if pair[1].user_ticks < pair[0].user_ticks || pair[1].system_ticks < pair[0].system_ticks {
            unavailable(
                &mut summary.unavailable,
                "process_cpu",
                "process CPU counters decreased within the observation window",
            );
            return summary;
        }
    }
    let ticks = last
        .user_ticks
        .unwrap()
        .checked_sub(first.user_ticks.unwrap())
        .and_then(|user| {
            last.system_ticks
                .unwrap()
                .checked_sub(first.system_ticks.unwrap())
                .and_then(|system| user.checked_add(system))
        });
    let Some(ticks) = ticks else {
        unavailable(
            &mut summary.unavailable,
            "process_cpu",
            "process CPU tick delta overflows u64",
        );
        return summary;
    };
    let hz = hz.unwrap();
    // Even all host CPUs cannot deliver more than this over the widest read
    // interval. Permit USER_HZ rounding of each CPU's user/system counters; do
    // not clamp impossible input into a plausible measured utilization.
    let maximum_ticks = (u128::from(maximum_ns) * u128::from(hz) * u128::from(cpus))
        .div_ceil(1_000_000_000)
        + 2 * u128::from(cpus);
    if u128::from(ticks) > maximum_ticks {
        unavailable(
            &mut summary.unavailable,
            "process_cpu",
            "process CPU tick delta exceeds the observed host capacity and read-skew bound",
        );
        return summary;
    }
    let cores = ticks as f64 / hz as f64 / (midpoint_ns / 1_000_000_000.0);
    summary.cpu_cores = Some(cores);
    summary.cpu_host_percent = Some(100.0 * cores / f64::from(cpus));
    summary
}

fn process_resource_deltas(
    artifact: &ResourceObservationArtifact,
    host: &ResourceDelta,
) -> Result<Vec<ProcessResourceDelta>, String> {
    let mut selected: Vec<(&ProcessIdentity, Vec<String>)> = Vec::new();
    for binding in &artifact.actions {
        if let Some((_, ids)) = selected
            .iter_mut()
            .find(|(target, _)| target.matches(&binding.target))
        {
            ids.push(binding.action_id.clone());
        } else {
            if selected.len() >= MAX_PROCESS_RESOURCE_TARGETS {
                return Err(format!("executed selection exceeds the {MAX_PROCESS_RESOURCE_TARGETS}-process observation bound; no partial subset is reported"));
            }
            selected.push((&binding.target, vec![binding.action_id.clone()]));
        }
    }
    Ok(selected
        .into_iter()
        .map(|(target, action_ids)| {
            let before = summarize_process_window(&artifact.before, target);
            let after = summarize_process_window(&artifact.after, target);
            let comparable = host.comparable && before.complete && after.complete;
            let cpu_comparable = comparable && host.cpu_capacity_comparable;
            let mut errors = Vec::new();
            let cpu_cores = metric_delta(
                "cpu_cores",
                before.cpu_cores,
                after.cpu_cores,
                cpu_comparable,
                &mut errors,
            );
            let cpu_host_percent = metric_delta(
                "cpu_host_percent",
                before.cpu_host_percent,
                after.cpu_host_percent,
                cpu_comparable,
                &mut errors,
            );
            let rss_bytes = metric_delta(
                "rss_bytes",
                before.rss_bytes.map(|bytes| bytes as f64),
                after.rss_bytes.map(|bytes| bytes as f64),
                comparable,
                &mut errors,
            );
            for (label, window) in [("before", &before), ("after", &after)] {
                errors.extend(window.unavailable.iter().map(|error| Unavailable {
                    source: format!("{label}.{}", error.source),
                    reason: error.reason.clone(),
                }));
            }
            deduplicate_unavailable(&mut errors);
            ProcessResourceDelta {
                target: target.clone(),
                action_ids,
                scope: "single_process".into(),
                attribution: "combined_action_window_observation_not_per_action_efficacy".into(),
                comparable,
                before_window: before,
                after_window: after,
                cpu_cores,
                cpu_host_percent,
                rss_bytes,
                unavailable: errors,
            }
        })
        .collect())
}

fn metric_delta(
    name: &str,
    before: Option<f64>,
    after: Option<f64>,
    comparable: bool,
    errors: &mut Vec<Unavailable>,
) -> ObservedMetricDelta {
    let before = before.filter(|value| value.is_finite());
    let after = after.filter(|value| value.is_finite());
    if before.is_none() {
        unavailable(errors, name, "before value unavailable or invalid");
    }
    if after.is_none() {
        unavailable(errors, name, "after value unavailable or invalid");
    }
    let delta = comparable
        .then_some(())
        .and_then(|()| before.zip(after))
        .map(|(before, after)| after - before)
        .filter(|delta| delta.is_finite());
    ObservedMetricDelta {
        before,
        after,
        delta,
    }
}

fn psi_delta(
    name: &str,
    before: Option<PsiResource>,
    after: Option<PsiResource>,
    before_rate: Option<StallFractions>,
    after_rate: Option<StallFractions>,
    comparable: bool,
    errors: &mut Vec<Unavailable>,
) -> PsiResourceDelta {
    let percent = |line: Option<PsiLine>| {
        line.map(|line| line.avg10)
            .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
    };
    let full_supported = name != "cpu";
    PsiResourceDelta {
        some_avg10_percent: metric_delta(
            &format!("psi.{name}.some.avg10"),
            percent(before.and_then(|r| r.some)),
            percent(after.and_then(|r| r.some)),
            comparable,
            errors,
        ),
        full_avg10_percent: if full_supported {
            metric_delta(
                &format!("psi.{name}.full.avg10"),
                percent(before.and_then(|r| r.full)),
                percent(after.and_then(|r| r.full)),
                comparable,
                errors,
            )
        } else {
            ObservedMetricDelta::default()
        },
        some_window_percent: metric_delta(
            &format!("psi.{name}.some.window"),
            before_rate.and_then(|r| r.some).map(|v| v * 100.0),
            after_rate.and_then(|r| r.some).map(|v| v * 100.0),
            comparable,
            errors,
        ),
        full_window_percent: if full_supported {
            metric_delta(
                &format!("psi.{name}.full.window"),
                before_rate.and_then(|r| r.full).map(|v| v * 100.0),
                after_rate.and_then(|r| r.full).map(|v| v * 100.0),
                comparable,
                errors,
            )
        } else {
            ObservedMetricDelta::default()
        },
    }
}

/// Compare independent pre-action and post-action windows. Changes in host
/// availability, load or pressure are observations, never per-target recovery.
pub fn compare_resource_windows(
    before: &ResourceObservationWindow,
    after: &ResourceObservationWindow,
) -> ResourceDelta {
    let before_window = summarize_window(before);
    let after_window = summarize_window(after);
    let mut errors = Vec::new();
    let before_evidence = validate_window(before).ok();
    let after_evidence = validate_window(after).ok();
    let comparable = match (&before_evidence, &after_evidence) {
        (Some(before), Some(after)) if before.boot_id != after.boot_id => {
            unavailable(
                &mut errors,
                "comparison",
                "before and after belong to different boots",
            );
            false
        }
        (Some(before), Some(after))
            if before.last.monotonic_end_ns > after.first.monotonic_start_ns
                || before.last.monotonic_end_ns >= after.last.monotonic_end_ns =>
        {
            unavailable(
                &mut errors,
                "comparison",
                "before/after windows overlap or are not chronologically ordered",
            );
            false
        }
        (Some(before), Some(after)) if before.complete && after.complete => true,
        _ => {
            unavailable(
                &mut errors,
                "comparison",
                "complete boot-bound before/after evidence is unavailable",
            );
            false
        }
    };
    let before_point = before.samples.last().map(|sample| &sample.pressure);
    let after_point = after.samples.last().map(|sample| &sample.pressure);
    let capacity = before_point
        .map(|point| point.cpus)
        .filter(|cpus| *cpus > 0);
    let cpu_capacity_comparable = comparable
        && capacity.is_some_and(|cpus| {
            before
                .samples
                .iter()
                .chain(&after.samples)
                .all(|sample| sample.pressure.cpus == cpus)
        });
    if !cpu_capacity_comparable {
        unavailable(&mut errors, "cpu_capacity", "stable matching online CPU capacity across both windows is required for CPU and load-ratio deltas");
    }
    let point = |pick: fn(&PressureSnapshot) -> Option<f64>| {
        (before_point.and_then(pick), after_point.and_then(pick))
    };
    let mut delta = |name: &str, pick: fn(&PressureSnapshot) -> Option<f64>| {
        let (b, a) = point(pick);
        metric_delta(name, b, a, comparable, &mut errors)
    };
    let available_memory_bytes = delta("available_memory_bytes", |sample| {
        sample
            .meminfo
            .and_then(|memory| {
                memory
                    .available
                    .filter(|available| memory.total.is_none_or(|total| *available <= total))
            })
            .map(|bytes| bytes as f64)
    });
    let swap_used_bytes = delta("swap_used_bytes", |sample| {
        sample
            .meminfo
            .and_then(|memory| memory.swap_total.zip(memory.swap_free))
            .and_then(|(total, free)| total.checked_sub(free))
            .map(|bytes| bytes as f64)
    });
    let allocated_file_handles = delta("allocated_file_handles", |sample| {
        sample.file_handles.map(|handles| handles.allocated as f64)
    });
    let load1 = delta("load1", |sample| {
        sample
            .load
            .map(|load| load.one)
            .filter(|value| *value >= 0.0)
    });
    let load5 = delta("load5", |sample| {
        sample
            .load
            .map(|load| load.five)
            .filter(|value| *value >= 0.0)
    });
    let load15 = delta("load15", |sample| {
        sample
            .load
            .map(|load| load.fifteen)
            .filter(|value| *value >= 0.0)
    });
    let (before_ratio, after_ratio) =
        point(|sample| sample.load_ratio().filter(|value| *value >= 0.0));
    let load_ratio = metric_delta(
        "load_ratio",
        before_ratio,
        after_ratio,
        cpu_capacity_comparable,
        &mut errors,
    );
    let cpu = CpuResourceDelta {
        busy_percent: metric_delta(
            "cpu.busy_percent",
            before_window.cpu_usage.map(|cpu| cpu.busy_percent),
            after_window.cpu_usage.map(|cpu| cpu.busy_percent),
            cpu_capacity_comparable,
            &mut errors,
        ),
        idle_percent: metric_delta(
            "cpu.idle_percent",
            before_window.cpu_usage.map(|cpu| cpu.idle_percent),
            after_window.cpu_usage.map(|cpu| cpu.idle_percent),
            cpu_capacity_comparable,
            &mut errors,
        ),
        iowait_percent: metric_delta(
            "cpu.iowait_percent",
            before_window.cpu_usage.map(|cpu| cpu.iowait_percent),
            after_window.cpu_usage.map(|cpu| cpu.iowait_percent),
            cpu_capacity_comparable,
            &mut errors,
        ),
        steal_percent: metric_delta(
            "cpu.steal_percent",
            before_window.cpu_usage.map(|cpu| cpu.steal_percent),
            after_window.cpu_usage.map(|cpu| cpu.steal_percent),
            cpu_capacity_comparable,
            &mut errors,
        ),
    };
    let cpu_pressure = psi_delta(
        "cpu",
        before_point.and_then(|s| s.cpu),
        after_point.and_then(|s| s.cpu),
        before_window.pressure_rates.and_then(|w| w.cpu),
        after_window.pressure_rates.and_then(|w| w.cpu),
        comparable,
        &mut errors,
    );
    let memory_pressure = psi_delta(
        "memory",
        before_point.and_then(|s| s.memory),
        after_point.and_then(|s| s.memory),
        before_window.pressure_rates.and_then(|w| w.memory),
        after_window.pressure_rates.and_then(|w| w.memory),
        comparable,
        &mut errors,
    );
    let io_pressure = psi_delta(
        "io",
        before_point.and_then(|s| s.io),
        after_point.and_then(|s| s.io),
        before_window.pressure_rates.and_then(|w| w.io),
        after_window.pressure_rates.and_then(|w| w.io),
        comparable,
        &mut errors,
    );
    for (label, window) in [("before", &before_window), ("after", &after_window)] {
        errors.extend(window.unavailable.iter().map(|error| Unavailable {
            source: format!("{label}.{}", error.source),
            reason: error.reason.clone(),
        }));
    }
    deduplicate_unavailable(&mut errors);
    let interval_ms = comparable
        .then_some(())
        .and_then(|()| {
            after_evidence
                .as_ref()?
                .last
                .monotonic_end_ns?
                .checked_sub(before_evidence.as_ref()?.last.monotonic_end_ns?)
        })
        .map(|ns| ns as f64 / 1_000_000.0);
    ResourceDelta {
        scope: "host".into(), attribution: "observed_host_change_not_per_action_recovery".into(),
        delta_convention: "after_minus_before".into(), comparable, cpu_capacity_comparable,
        observed_logical_cpus: cpu_capacity_comparable.then_some(capacity).flatten(),
        before_at_ms: before_point.map(|point| point.sampled_at_ms), after_at_ms: after_point.map(|point| point.sampled_at_ms), interval_ms,
        before_window, after_window, available_memory_bytes, swap_used_bytes, allocated_file_handles,
        load1, load5, load15, load_ratio, cpu, cpu_pressure, memory_pressure, io_pressure,
        processes: Vec::new(), binding: None, prediction_comparison: None, unavailable: errors,
        limitations: vec![
            "Host changes can include unrelated workloads, caches, reclaim and changing capacity; they are not causal proof of per-action recovery.".into(),
            "The observation duration is a settle opportunity, not proof that the system reached a stable state.".into(),
            "PSI rates use cumulative counters and measured boot-clock intervals; raw read start/end times retain collection latency.".into(),
            "Host CPU full pressure is undefined; kernel compatibility zeros are not interpreted as relief.".into(),
            "CPU busy excludes idle, iowait and steal; guest time is already included in user/nice.".into(),
        ],
    }
}

/// The exact saved attempt to which a resource observation run belongs.
/// Precheck refusals and dry runs have no execution timestamp and cannot bind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceActionBinding {
    pub action_id: String,
    pub action: Action,
    pub target: ProcessIdentity,
    pub status: String,
    pub executed_at: DateTime<Utc>,
    pub execution_clock: ExecutionClock,
}

impl ResourceActionBinding {
    pub fn from_saved(outcome: &SavedActionOutcome) -> Result<Self, String> {
        if outcome.status != "success" && !super::is_failed_attempt(&outcome.status) {
            return Err(format!(
                "{} is not an executed action attempt",
                outcome.action_id
            ));
        }
        let action = outcome
            .action
            .filter(|action| *action != Action::Keep)
            .ok_or_else(|| {
                format!(
                    "{} lacks a non-Keep executed action kind",
                    outcome.action_id
                )
            })?;
        let target = outcome
            .target
            .as_ref()
            .filter(|target| target.pid.0 == outcome.pid && target.can_safely_revalidate())
            .ok_or_else(|| {
                format!(
                    "{} lacks a trustworthy executed target identity",
                    outcome.action_id
                )
            })?;
        Ok(Self {
            action_id: outcome.action_id.clone(),
            action,
            target: target.clone(),
            status: outcome.status.clone(),
            executed_at: outcome
                .executed_at
                .ok_or_else(|| format!("{} lacks an execution timestamp", outcome.action_id))?,
            execution_clock: outcome.execution_clock.clone().ok_or_else(|| {
                format!(
                    "{} lacks a boot-relative execution clock",
                    outcome.action_id
                )
            })?,
        })
    }
}

/// Save one separate artifact per apply run. `plan_sha256` hashes the complete
/// bytes of the saved canonical plan, not a reduced subset of its target fields.
/// `run_id` is a fresh UUID, also attached to the raw sample JSONL records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObservationArtifact {
    pub schema_version: u32,
    pub session_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub run_id: String,
    pub actions: Vec<ResourceActionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_predictions: Option<ResourcePredictionSnapshot>,
    pub before: ResourceObservationWindow,
    pub after: ResourceObservationWindow,
}

fn execution_overlaps_gap(
    clock: &ExecutionClock,
    hz: u64,
    before_end: u64,
    after_start: u64,
) -> bool {
    // capture_execution_clock floors the kernel boot time to USER_HZ. Compare
    // its whole-tick interval with the gap, allowing a genuine same-tick action.
    // Tick precision cannot establish the exact order of events within that tick.
    let lower = u128::from(clock.ticks) * 1_000_000_000 / u128::from(hz);
    let upper = ((u128::from(clock.ticks) + 1) * 1_000_000_000).div_ceil(u128::from(hz));
    lower <= u128::from(after_start) && upper > u128::from(before_end)
}

/// Replay measurements only when they still bind to the current canonical plan
/// and the latest substantive outcome for each recorded action. A stale/missing
/// artifact is a resource-evidence gap, not proof that the action itself failed.
/// The current observation prevents cross-boot and future-timeline replay.
pub fn replay_resource_artifact(
    artifact: &ResourceObservationArtifact,
    plan: &Plan,
    current_plan_sha256: &str,
    saved_outcomes: &[SavedActionOutcome],
    current_observation: &ResourceObservation,
    predictions: Option<&ValidatedResourcePredictions>,
) -> Result<ResourceDelta, String> {
    let valid_digest =
        |digest: &str| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    if artifact.schema_version != RESOURCE_OBSERVATION_SCHEMA_VERSION
        || artifact.session_id != plan.session_id
        || artifact.plan_id != plan.plan_id
        || !valid_digest(&artifact.plan_sha256)
        || !valid_digest(current_plan_sha256)
        || !artifact
            .plan_sha256
            .eq_ignore_ascii_case(current_plan_sha256)
    {
        return Err(
            "resource observation artifact does not match the complete canonical plan".into(),
        );
    }
    if !uuid::Uuid::parse_str(&artifact.run_id).is_ok_and(|id| !id.is_nil()) {
        return Err("resource observation artifact lacks a valid unique apply run ID".into());
    }
    if artifact.actions.is_empty() || artifact.actions.len() > plan.actions.len() {
        return Err("resource observation artifact has no bounded executed-action binding".into());
    }
    let before = validate_window(&artifact.before)?;
    let after = validate_window(&artifact.after)?;
    if !before.complete || !after.complete || before.boot_id != after.boot_id {
        return Err(
            "resource observation windows are incomplete or belong to different boots".into(),
        );
    }
    let before_end = before.last.monotonic_end_ns.unwrap();
    let after_start = after.first.monotonic_start_ns.unwrap();
    let after_end = after.last.monotonic_end_ns.unwrap();
    if before_end > after_start || before_end >= after_end {
        return Err(
            "resource observation windows overlap or are not chronologically ordered".into(),
        );
    }
    if current_observation.boot_id.as_deref() != Some(before.boot_id) {
        return Err("resource observation artifact is not from the current observed boot; unsupported or missing boot evidence cannot establish relief".into());
    }
    let current_start = current_observation
        .monotonic_start_ns
        .ok_or("current monotonic observation start is missing")?;
    let current_end = current_observation
        .monotonic_end_ns
        .ok_or("current monotonic observation end is missing")?;
    if current_start < after_end || current_end < current_start {
        return Err("resource artifact has an invalid or future monotonic timeline".into());
    }
    let hz = before
        .first
        .clock_ticks_per_second
        .filter(|hz| (1..=1_000_000_000).contains(hz))
        .ok_or("resource observation lacks a valid execution-clock tick rate")?;
    if current_observation.clock_ticks_per_second != Some(hz)
        || artifact
            .before
            .samples
            .iter()
            .chain(&artifact.after.samples)
            .any(|sample| sample.clock_ticks_per_second != Some(hz))
    {
        return Err(
            "resource observation execution-clock tick rates are inconsistent or missing".into(),
        );
    }
    let now = i64::try_from(current_observation.pressure.sampled_at_ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        // The host wall clock is recorded with millisecond precision, while an
        // execution timestamp retains nanoseconds. Compare at the observation's
        // actual resolution so a later sample in the same millisecond is valid.
        .and_then(|at| at.checked_add_signed(chrono::Duration::nanoseconds(999_999)))
        .ok_or("current wall-clock observation is invalid")?;
    super::validate_execution_timestamps(saved_outcomes, now).map_err(|error| error.to_string())?;
    let canonical: HashMap<_, _> = super::recorded_plan_actions(plan, saved_outcomes)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|(action, outcome)| (action.action_id.as_str(), (action, outcome)))
        .collect();
    let mut ids = HashSet::new();
    for binding in &artifact.actions {
        if !ids.insert(binding.action_id.as_str()) {
            return Err("resource artifact repeats an executed action ID".into());
        }
        let (action, saved) = canonical.get(binding.action_id.as_str()).ok_or_else(|| {
            format!(
                "resource action {} has no canonical execution outcome",
                binding.action_id
            )
        })?;
        if action.action != binding.action
            || !action.target.matches(&binding.target)
            || saved.action != Some(binding.action)
            || saved.target.as_ref() != Some(&binding.target)
            || saved.status != binding.status
            || saved.executed_at != Some(binding.executed_at)
            || ResourceActionBinding::from_saved(saved).is_err()
        {
            return Err(format!(
                "resource action {} does not match its latest exact saved execution",
                binding.action_id
            ));
        }
        let clock = saved.execution_clock.as_ref().ok_or_else(|| {
            format!(
                "resource action {} has no boot-relative execution clock",
                binding.action_id
            )
        })?;
        if clock.boot_id != before.boot_id
            || clock.boot_id != binding.execution_clock.boot_id
            || clock.ticks != binding.execution_clock.ticks
            || !execution_overlaps_gap(clock, hz, before_end, after_start)
        {
            return Err(format!(
                "resource action {} was not observed between the before/after windows",
                binding.action_id
            ));
        }
    }
    let mut report = compare_resource_windows(&artifact.before, &artifact.after);
    match process_resource_deltas(artifact, &report) {
        Ok(processes) => report.processes = processes,
        Err(reason) => unavailable(&mut report.unavailable, "process_observations", reason),
    }
    report.binding = Some(ResourceEvidenceBinding {
        run_id: artifact.run_id.clone(),
        action_ids: artifact
            .actions
            .iter()
            .map(|binding| binding.action_id.clone())
            .collect(),
        boot_id: before.boot_id.to_string(),
        execution_clock_resolution_ns: 1_000_000_000u64.div_ceil(hz),
        timing_validation: "execution_tick_interval_overlaps_inter_window_gap".into(),
    });
    attach_prediction_comparison(
        &mut report,
        artifact.resource_predictions.as_ref(),
        predictions,
        plan,
        &artifact.actions,
    );
    report.limitations.push("Saved execution timestamps and target identities bind this apply run; boot-clock ordering is validated only to USER_HZ tick precision, not atomically within a tick. Wall-clock future checks use the host observation's millisecond resolution.".into());
    report.limitations.push("This is the historical observation window for the named apply run and bound action IDs, not a fresh verify-time measurement or an aggregate over every plan action.".into());
    report.limitations.push("Process rows cover only the exact executed PID incarnations, including their threads; they exclude child processes and whole service/cgroup workloads. RSS includes shared pages and is not reclaimable memory. CPU rates use each process's own read brackets; observed changes do not prove individual-action efficacy.".into());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::pressure::{FileHandles, LoadAvg, MemInfo};
    use pt_common::StartId;
    use sha2::Digest;
    use std::cell::{Cell, RefCell};

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_BOOT: &str = "22222222-2222-4222-8222-222222222222";
    const RUN: &str = "33333333-3333-4333-8333-333333333333";

    fn sample(ms: u64, user: u64, idle: u64, stalled_us: u64) -> ResourceObservation {
        let line = PsiLine {
            avg10: 10.0,
            avg60: 5.0,
            avg300: 2.0,
            total_us: stalled_us,
        };
        ResourceObservation {
            boot_id: Some(BOOT.into()),
            clock_ticks_per_second: Some(100),
            monotonic_start_ns: Some(ms * 1_000_000),
            monotonic_end_ns: Some(ms * 1_000_000),
            pressure: PressureSnapshot {
                sampled_at_ms: ms,
                cpus: 2,
                cpu: Some(PsiResource {
                    some: Some(line),
                    full: Some(line),
                }),
                memory: Some(PsiResource {
                    some: Some(line),
                    full: Some(line),
                }),
                io: Some(PsiResource {
                    some: Some(line),
                    full: Some(line),
                }),
                irq: None,
                load: Some(LoadAvg {
                    one: 4.0,
                    five: 3.0,
                    fifteen: 2.0,
                    runnable: Some(2),
                    total: Some(100),
                }),
                meminfo: Some(MemInfo {
                    total: Some(8_000_000),
                    available: Some(2_000_000),
                    swap_total: Some(1_000_000),
                    swap_free: Some(500_000),
                    ..MemInfo::default()
                }),
                vmstat: Some(VmStat {
                    pswpin: Some(ms),
                    pswpout: Some(ms),
                    pgmajfault: Some(ms),
                    pgscan_direct: Some(ms),
                    allocstall: Some(ms),
                    compact_stall: Some(ms),
                    oom_kill: Some(0),
                }),
                file_handles: Some(FileHandles {
                    allocated: 1000,
                    max: 100_000,
                }),
                unavailable: Vec::new(),
            },
            cpu_times: Some(HostCpuTimes {
                user,
                nice: 0,
                system: 0,
                idle,
                iowait: 0,
                irq: 0,
                softirq: 0,
                steal: 0,
            }),
            processes: Vec::new(),
            unavailable: Vec::new(),
        }
    }

    fn window(samples: Vec<ResourceObservation>) -> ResourceObservationWindow {
        let span = samples.last().unwrap().monotonic_end_ns.unwrap()
            - samples[0].monotonic_end_ns.unwrap();
        ResourceObservationWindow {
            requested_duration_ms: span / 1_000_000,
            sample_interval_ms: SAMPLE_INTERVAL_MS,
            samples,
        }
    }

    fn pair() -> (ResourceObservationWindow, ResourceObservationWindow) {
        let before = window(vec![
            sample(1000, 100, 100, 100_000),
            sample(2000, 180, 120, 500_000),
        ]);
        let mut after = window(vec![
            sample(3000, 200, 200, 600_000),
            sample(4000, 220, 280, 700_000),
        ]);
        let last = &mut after.samples[1].pressure;
        last.meminfo.as_mut().unwrap().available = Some(3_000_000);
        last.meminfo.as_mut().unwrap().swap_free = Some(600_000);
        last.load.as_mut().unwrap().one = 1.0;
        last.file_handles.as_mut().unwrap().allocated = 900;
        last.cpu.as_mut().unwrap().some.as_mut().unwrap().avg10 = 4.0;
        (before, after)
    }

    fn process_sample(
        target: &ProcessIdentity,
        ms: u64,
        user_ticks: u64,
        rss_bytes: u64,
    ) -> ProcessResourceObservation {
        ProcessResourceObservation {
            target: target.clone(),
            monotonic_start_ns: Some(ms * 1_000_000),
            monotonic_end_ns: Some(ms * 1_000_000),
            user_ticks: Some(user_ticks),
            system_ticks: Some(0),
            rss_bytes: Some(rss_bytes),
            unavailable: Vec::new(),
        }
    }

    fn process_window(target: &ProcessIdentity) -> ResourceObservationWindow {
        window(
            [(1000, 100), (1500, 150), (2000, 200)]
                .into_iter()
                .map(|(ms, ticks)| {
                    let mut host = sample(ms, ticks, ticks, 0);
                    host.processes = vec![process_sample(target, ms, ticks, 2_097_152)];
                    host
                })
                .collect(),
        )
    }

    #[test]
    fn process_parser_requires_live_identity_and_complete_checked_counters() {
        let stat = |pid: u32, state: &str, user: &str, system: &str, birth: &str, rss: &str| {
            format!("{pid} (worker with ) parentheses) {state} 1 2 3 0 -1 0 0 0 0 0 {user} {system} 0 0 20 0 1 0 {birth} 1000 {rss}\n")
        };
        let good = stat(42, "S", "120", "30", "10", "512");
        assert_eq!(
            parse_process_counters(&good, 42, 4096).unwrap(),
            ProcessCounters {
                start_ticks: 10,
                user_ticks: 120,
                system_ticks: 30,
                rss_bytes: 2_097_152,
            }
        );
        for bad in [
            stat(43, "S", "120", "30", "10", "512"),
            stat(42, "Z", "120", "30", "10", "0"),
            stat(42, "X", "120", "30", "10", "0"),
            stat(42, "?", "120", "30", "10", "512"),
            stat(42, "S", "+120", "30", "10", "512"),
            stat(42, "S", "120", "unknown", "10", "512"),
            stat(42, "S", "120", "30", "?", "512"),
            stat(42, "S", "120", "30", "10", "-1"),
            stat(42, "S", "120", "30", "10", "18446744073709551615"),
            stat(42, "S", "18446744073709551615", "1", "10", "512"),
            good.split_whitespace()
                .take(15)
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            assert!(parse_process_counters(&bad, 42, 4096).is_err(), "{bad}");
        }
        assert!(parse_process_counters(&good, 42, 0).is_err());
        assert_eq!(
            parse_process_uids("Name:\tworker\nUid:\t1000 1000 1000 1000\n").unwrap(),
            [1000; 4]
        );
        for bad in [
            "",
            "Uid: 1000 1000 1000\n",
            "Uid: 1000 1000 1000 1000 1000\n",
            "Uid: +1000 1000 1000 1000\n",
            "Uid: 4294967296 1000 1000 1000\n",
            "Uid: 1000 1000 1000 1000\nUid: 1000 1000 1000 1000\n",
        ] {
            assert!(parse_process_uids(bad).is_err(), "{bad}");
        }
        require_process_leader("Pid:\t42\nTgid:\t42\n", 42).unwrap();
        for bad in [
            "Pid: 42\nTgid: 1\n",
            "Pid: 43\nTgid: 42\n",
            "Pid: 42\n",
            "Pid: 42\nTgid: 42\nTgid: 42\n",
            "Pid: +42\nTgid: 42\n",
        ] {
            assert!(require_process_leader(bad, 42).is_err(), "{bad}");
        }
    }

    #[test]
    fn process_cpu_uses_its_own_read_brackets_and_rss_is_a_resident_point() {
        let target = ProcessIdentity::new(42, StartId::from_linux(BOOT, 10, 42), 1000);
        let mut first = sample(1000, 100, 100, 0);
        first.monotonic_end_ns = Some(1_200_000_000);
        first.processes = vec![process_sample(&target, 1050, 100, 1_048_576)];
        first.processes[0].monotonic_end_ns = Some(1_060_000_000);
        let mut last = sample(2000, 200, 200, 0);
        last.monotonic_end_ns = Some(2_600_000_000);
        last.processes = vec![process_sample(&target, 2050, 200, 2_097_152)];
        last.processes[0].monotonic_end_ns = Some(2_060_000_000);
        let measured = window(vec![first, last]);
        assert_eq!(measured.requested_duration_ms, 1400);
        let summary = summarize_process_window(&measured, &target);
        assert!(summary.complete);
        assert_eq!(summary.observed_duration_ms, Some(1000.0));
        assert_eq!(summary.minimum_duration_ms, Some(990.0));
        assert_eq!(summary.maximum_duration_ms, Some(1010.0));
        assert_eq!(summary.cpu_cores, Some(1.0));
        assert_eq!(summary.cpu_host_percent, Some(50.0));
        assert_eq!(summary.rss_bytes, Some(2_097_152));
        assert!(summary.unavailable.is_empty());
    }

    #[test]
    fn process_windows_refuse_missing_reused_and_unbounded_identity_evidence() {
        let target = ProcessIdentity::new(42, StartId::from_linux(BOOT, 10, 42), 1000);
        for bad in [
            "missing",
            "birth",
            "uid",
            "quality",
            "duplicate",
            "clock",
            "exited",
            "overflow",
        ] {
            let mut measured = process_window(&target);
            let middle = &mut measured.samples[1];
            match bad {
                "missing" => middle.processes.clear(),
                "birth" => middle.processes[0].target.start_id = StartId::from_linux(BOOT, 11, 42),
                "uid" => middle.processes[0].target.uid = 1001,
                "quality" => {
                    middle.processes[0].target.quality = pt_common::IdentityQuality::NoBootId
                }
                "duplicate" => middle.processes.push(middle.processes[0].clone()),
                "clock" => middle.processes[0].monotonic_end_ns = Some(1_500_000_001),
                "exited" => {
                    let process = &mut middle.processes[0];
                    process.user_ticks = None;
                    process.system_ticks = None;
                    process.rss_bytes = None;
                    unavailable(
                        &mut process.unavailable,
                        "process_counters",
                        "process is absent",
                    );
                }
                "overflow" => {
                    middle.processes[0].user_ticks = Some(u64::MAX);
                    middle.processes[0].system_ticks = Some(1);
                }
                _ => unreachable!(),
            }
            let summary = summarize_process_window(&measured, &target);
            assert!(!summary.complete, "{bad}");
            assert_eq!(summary.cpu_cores, None, "{bad}");
            assert_eq!(summary.cpu_host_percent, None, "{bad}");
            assert_eq!(summary.rss_bytes, None, "{bad}");
            assert!(!summary.unavailable.is_empty(), "{bad}");
        }
    }

    #[test]
    fn process_cpu_resets_and_capacity_changes_are_unknown_without_erasing_rss() {
        let target = ProcessIdentity::new(42, StartId::from_linux(BOOT, 10, 42), 1000);
        for bad in [
            "user_reset",
            "system_reset",
            "impossible_rate",
            "capacity",
            "hz",
        ] {
            let mut measured = process_window(&target);
            match bad {
                "user_reset" => measured.samples[1].processes[0].user_ticks = Some(50),
                "system_reset" => measured.samples[0].processes[0].system_ticks = Some(1),
                "impossible_rate" => measured.samples[2].processes[0].user_ticks = Some(1_000_000),
                "capacity" => measured.samples[1].pressure.cpus = 3,
                "hz" => measured.samples[1].clock_ticks_per_second = Some(1000),
                _ => unreachable!(),
            }
            let summary = summarize_process_window(&measured, &target);
            assert!(summary.complete, "{bad}");
            assert_eq!(summary.cpu_cores, None, "{bad}");
            assert_eq!(summary.cpu_host_percent, None, "{bad}");
            assert_eq!(summary.rss_bytes, Some(2_097_152), "{bad}");
            assert!(!summary.unavailable.is_empty(), "{bad}");
        }
    }

    #[test]
    fn cpu_parser_requires_aggregate_counters_and_does_not_double_count_guests() {
        let first =
            parse_host_cpu_times("cpu 100 10 20 200 3 4 5 6 80 8\ncpu0 1 2 3 4 5 6 7 8\n").unwrap();
        let second = parse_host_cpu_times("cpu 180 10 20 220 3 4 5 6 160 8\n").unwrap();
        let mut measured = window(vec![sample(1000, 0, 0, 0), sample(2000, 0, 0, 0)]);
        measured.samples[0].cpu_times = Some(first);
        measured.samples[1].cpu_times = Some(second);
        let summary = summarize_window(&measured);
        assert_eq!(summary.cpu_usage.unwrap().busy_percent, 80.0);
        for text in [
            "cpu0 1 2 3 4 5 6 7 8",
            "cpu 1 2 3",
            "cpu 1 2 3 4 bad 6 7 8",
            "cpu 1 2 3 4 5 6 7 8\ncpu 1 2 3 4 5 6 7 8",
        ] {
            assert!(parse_host_cpu_times(text).is_err(), "{text}");
        }
    }

    #[test]
    fn before_after_relief_uses_independent_real_windows_and_explicit_units() {
        let (before, after) = pair();
        let delta = compare_resource_windows(&before, &after);
        assert!(delta.comparable);
        assert_eq!(delta.scope, "host");
        assert_eq!(
            delta.attribution,
            "observed_host_change_not_per_action_recovery"
        );
        assert_eq!(
            delta.cpu.busy_percent,
            ObservedMetricDelta {
                before: Some(80.0),
                after: Some(20.0),
                delta: Some(-60.0)
            }
        );
        assert_eq!(delta.cpu.idle_percent.delta, Some(60.0));
        assert_eq!(delta.cpu_pressure.some_window_percent.delta, Some(-30.0));
        assert_eq!(delta.cpu_pressure.some_avg10_percent.delta, Some(-6.0));
        assert_eq!(delta.memory_pressure.full_window_percent.delta, Some(-30.0));
        assert_eq!(
            delta.cpu_pressure.full_avg10_percent,
            ObservedMetricDelta::default()
        );
        assert_eq!(
            delta.cpu_pressure.full_window_percent,
            ObservedMetricDelta::default()
        );
        assert_eq!(delta.available_memory_bytes.delta, Some(1_000_000.0));
        assert_eq!(delta.swap_used_bytes.delta, Some(-100_000.0));
        assert_eq!(delta.allocated_file_handles.delta, Some(-100.0));
        assert_eq!(delta.load_ratio.delta, Some(-1.5));
        let json = serde_json::to_value(&delta).unwrap();
        assert!(json.get("resources_freed").is_none());
        assert!(json["cpu_pressure"]["full_window_percent"]["after"].is_null());
        assert!(delta
            .unavailable
            .iter()
            .any(|error| error.reason.contains("undefined at host scope")));
    }

    #[test]
    fn monotonic_windows_survive_wall_clock_adjustments_and_different_durations() {
        let before = window(vec![
            sample(1000, 100, 100, 100_000),
            sample(3000, 260, 140, 900_000),
        ]);
        let mut after = window(vec![
            sample(4000, 300, 300, 1_000_000),
            sample(5000, 320, 380, 1_100_000),
        ]);
        for sample in &mut after.samples {
            sample.pressure.sampled_at_ms = 1;
        }
        let delta = compare_resource_windows(&before, &after);
        assert!(delta.comparable);
        assert_eq!(delta.before_window.observed_duration_ms, Some(2000.0));
        assert_eq!(delta.after_window.observed_duration_ms, Some(1000.0));
        assert_eq!(delta.cpu_pressure.some_window_percent.before, Some(40.0));
        assert_eq!(delta.cpu_pressure.some_window_percent.after, Some(10.0));
        assert_eq!(delta.interval_ms, Some(2000.0));
    }

    #[test]
    fn settle_zero_compares_points_without_inventing_cpu_or_psi_rates() {
        let (before, after) = pair();
        let before = window(vec![before.samples[1].clone()]);
        let after = window(vec![after.samples[1].clone()]);
        let delta = compare_resource_windows(&before, &after);
        assert!(delta.comparable);
        assert!(delta.after_window.complete);
        assert_eq!(delta.after_window.requested_duration_ms, 0);
        assert_eq!(delta.available_memory_bytes.delta, Some(1_000_000.0));
        assert!(delta.cpu.busy_percent.after.is_none());
        assert!(delta.memory_pressure.some_window_percent.after.is_none());
        assert!(delta
            .unavailable
            .iter()
            .any(|error| error.reason.contains("zero-duration point sample")));
    }

    #[test]
    fn different_boots_overlapping_or_incomplete_windows_do_not_produce_relief() {
        let (before, after) = pair();
        let mut other_boot = after.clone();
        for sample in &mut other_boot.samples {
            sample.boot_id = Some(OTHER_BOOT.into());
        }
        let mut overlap = after.clone();
        overlap.samples[0].monotonic_start_ns = Some(1_900_000_000);
        let mut incomplete = after.clone();
        incomplete.requested_duration_ms = 1500;
        let mut missing = after.clone();
        missing.samples[0].monotonic_end_ns = None;
        let mut empty = after.clone();
        empty.samples.clear();
        for invalid in [other_boot, overlap, incomplete, missing, empty] {
            let delta = compare_resource_windows(&before, &invalid);
            assert!(!delta.comparable);
            assert!(delta.available_memory_bytes.delta.is_none());
            assert!(delta.cpu.busy_percent.delta.is_none());
            assert!(!delta.unavailable.is_empty());
        }
    }

    #[test]
    fn missing_and_regressed_counters_are_unknown_even_if_endpoints_increase() {
        let mut measured = window(vec![
            sample(1000, 100, 100, 100_000),
            sample(1500, 50, 150, 50_000),
            sample(2000, 200, 200, 200_000),
        ]);
        let report = summarize_window(&measured);
        assert!(report.cpu_usage.is_none());
        assert!(report.pressure_rates.unwrap().cpu.is_none());
        assert!(report
            .unavailable
            .iter()
            .any(|error| error.reason.contains("regressed")));
        measured.samples[1] = sample(1500, 150, 150, 150_000);
        measured.samples[0].cpu_times.as_mut().unwrap().iowait = 10;
        measured.samples[1].cpu_times.as_mut().unwrap().iowait = 9;
        measured.samples[2].cpu_times.as_mut().unwrap().iowait = 20;
        assert!(
            summarize_window(&measured).cpu_usage.is_none(),
            "iowait regression must not become increased CPU busy time"
        );
        measured.samples[1].cpu_times = None;
        assert!(summarize_window(&measured).cpu_usage.is_none());
        measured.samples[1].pressure.memory = None;
        assert!(summarize_window(&measured)
            .pressure_rates
            .unwrap()
            .memory
            .is_none());
    }

    #[test]
    fn invalid_pressure_swap_and_capacity_values_are_not_clamped_into_success() {
        let (before, mut after) = pair();
        after.samples[1]
            .pressure
            .cpu
            .as_mut()
            .unwrap()
            .some
            .as_mut()
            .unwrap()
            .total_us = 9_000_000;
        after.samples[1]
            .pressure
            .meminfo
            .as_mut()
            .unwrap()
            .swap_free = Some(2_000_000);
        after.samples[1].pressure.load.as_mut().unwrap().one = f64::NAN;
        after.samples[1].pressure.cpus = 1;
        let delta = compare_resource_windows(&before, &after);
        assert!(
            delta.comparable,
            "valid timing does not imply every metric is available"
        );
        assert!(delta.cpu_pressure.some_window_percent.after.is_none());
        assert!(delta.swap_used_bytes.after.is_none());
        assert!(delta.load1.after.is_none());
        assert!(delta.cpu.busy_percent.after.is_none());
        assert!(delta
            .unavailable
            .iter()
            .any(|error| error.reason.contains("exceeds the measured interval")));
    }

    #[test]
    fn capacity_change_between_stable_windows_is_not_cpu_relief() {
        let (before, mut after) = pair();
        for sample in &mut after.samples {
            sample.pressure.cpus = 4;
        }
        let delta = compare_resource_windows(&before, &after);
        assert!(delta.comparable);
        assert!(!delta.cpu_capacity_comparable);
        assert_eq!(delta.cpu.busy_percent.before, Some(80.0));
        assert_eq!(delta.cpu.busy_percent.after, Some(20.0));
        assert!(delta.cpu.busy_percent.delta.is_none());
        assert!(delta.load_ratio.delta.is_none());
        assert_eq!(delta.available_memory_bytes.delta, Some(1_000_000.0));
        assert!(delta
            .unavailable
            .iter()
            .any(|error| error.source == "cpu_capacity"));
    }

    #[test]
    fn unsupported_platform_evidence_keeps_the_reason_and_never_reports_zero() {
        let (mut before, mut after) = pair();
        for sample in before.samples.iter_mut().chain(&mut after.samples) {
            sample.boot_id = None;
            sample.cpu_times = None;
            sample.unavailable.push(Unavailable {
                source: "platform".into(),
                reason: "Linux-only resource window unsupported here".into(),
            });
        }
        let delta = compare_resource_windows(&before, &after);
        assert!(!delta.comparable);
        assert!(delta.cpu.busy_percent.before.is_none());
        assert!(delta.available_memory_bytes.delta.is_none());
        assert!(delta
            .unavailable
            .iter()
            .any(|error| error.reason.contains("Linux-only")));
    }

    #[test]
    fn sampling_honors_zero_final_remainder_callbacks_and_hard_bounds() {
        let clock = Cell::new(1000u64);
        let seen = RefCell::new(Vec::new());
        let captured = collect_window_with(
            Duration::from_millis(2500),
            || sample(clock.get(), 0, clock.get(), 0),
            |duration| clock.set(clock.get() + duration.as_millis() as u64),
            || Duration::from_millis(clock.get()),
            |sample| seen.borrow_mut().push(sample.monotonic_end_ns.unwrap()),
        )
        .unwrap();
        assert_eq!(
            *seen.borrow(),
            vec![1_000_000_000, 2_000_000_000, 3_000_000_000, 3_500_000_000]
        );
        assert_eq!(captured.samples.len(), 4);
        assert!(summarize_window(&captured).complete);
        let zero = collect_window_with(
            Duration::ZERO,
            || sample(0, 0, 0, 0),
            |_| panic!("zero must not sleep"),
            || Duration::ZERO,
            |_| {},
        )
        .unwrap();
        assert_eq!(zero.samples.len(), 1);
        assert!(collect_window_with(
            Duration::from_millis(MAX_RESOURCE_WINDOW_MS + 1),
            || panic!("invalid duration must not capture"),
            |_| {},
            || Duration::ZERO,
            |_| {}
        )
        .is_err());
        assert!(collect_window_with(
            Duration::from_millis(1),
            || sample(0, 0, 0, 0),
            |_| {},
            || Duration::ZERO,
            |_| {}
        )
        .unwrap_err()
        .contains("sample bound"));
    }

    fn plan_digest(plan: &Plan) -> String {
        format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(plan).unwrap())
        )
    }

    fn artifact_fixture() -> (
        ResourceObservationArtifact,
        Plan,
        Vec<SavedActionOutcome>,
        ResourceObservation,
    ) {
        let target = ProcessIdentity::new(42, StartId::from_linux(BOOT, 10, 42), 1000);
        let plan: Plan = serde_json::from_value(serde_json::json!({
            "plan_id": "relief-plan", "session_id": "relief-session", "generated_at": "1970-01-01T00:00:00Z", "policy_version": "test", "pre_toggled": [],
            "gates_summary": {"total_candidates": 1, "blocked_candidates": 0, "pre_toggled_actions": 0},
            "actions": [{"action_id": "renice-42", "target": target, "action": "renice", "order": 0, "stage": 1, "timeouts": crate::plan::ActionTimeouts::default(), "pre_checks": [], "rationale": {}, "on_success": [], "on_failure": [], "blocked": false}]
        })).unwrap();
        let saved: SavedActionOutcome = serde_json::from_value(serde_json::json!({
            "action_id": "renice-42", "pid": 42, "action": "renice", "target": target, "status": "success",
            "executed_at": DateTime::<Utc>::from_timestamp_millis(2500).unwrap(), "execution_clock": {"boot_id": BOOT, "ticks": 250},
        })).unwrap();
        let (before, after) = pair();
        let artifact = ResourceObservationArtifact {
            schema_version: RESOURCE_OBSERVATION_SCHEMA_VERSION,
            session_id: plan.session_id.clone(),
            plan_id: plan.plan_id.clone(),
            plan_sha256: plan_digest(&plan),
            run_id: RUN.into(),
            actions: vec![ResourceActionBinding::from_saved(&saved).unwrap()],
            resource_predictions: None,
            before,
            after,
        };
        (
            artifact,
            plan,
            vec![saved],
            sample(5000, 300, 300, 1_000_000),
        )
    }

    fn attach_process_evidence(artifact: &mut ResourceObservationArtifact) {
        let target = artifact.actions[0].target.clone();
        for (index, sample) in artifact.before.samples.iter_mut().enumerate() {
            sample.processes = vec![process_sample(
                &target,
                sample.pressure.sampled_at_ms,
                100 + index as u64 * 100,
                2_097_152,
            )];
        }
        for (index, sample) in artifact.after.samples.iter_mut().enumerate() {
            sample.processes = vec![process_sample(
                &target,
                sample.pressure.sampled_at_ms,
                250 + index as u64 * 25,
                1_048_576,
            )];
        }
    }

    #[test]
    fn replay_reports_only_executed_processes_once_for_combined_action_windows() {
        let (mut artifact, mut plan, mut saved, current) = artifact_fixture();
        attach_process_evidence(&mut artifact);
        let mut second = plan.actions[0].clone();
        second.action_id = "pause-42".into();
        second.action = Action::Pause;
        second.order = 1;
        plan.actions.push(second);
        let mut execution = saved[0].clone();
        execution.action_id = "pause-42".into();
        execution.action = Some(Action::Pause);
        execution.executed_at = DateTime::<Utc>::from_timestamp_millis(2600);
        execution.execution_clock.as_mut().unwrap().ticks = 260;
        artifact
            .actions
            .push(ResourceActionBinding::from_saved(&execution).unwrap());
        saved.push(execution);

        let other = ProcessIdentity::new(43, StartId::from_linux(BOOT, 10, 43), 1000);
        let mut unexecuted = plan.actions[0].clone();
        unexecuted.action_id = "renice-43".into();
        unexecuted.target = other.clone();
        unexecuted.order = 2;
        plan.actions.push(unexecuted);
        for sample in artifact
            .before
            .samples
            .iter_mut()
            .chain(&mut artifact.after.samples)
        {
            sample.processes.push(process_sample(
                &other,
                sample.pressure.sampled_at_ms,
                0,
                1 << 30,
            ));
        }
        artifact.plan_sha256 = plan_digest(&plan);
        let report = replay_resource_artifact(
            &artifact,
            &plan,
            &artifact.plan_sha256,
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert_eq!(report.processes.len(), 1);
        let row = &report.processes[0];
        assert_eq!(row.target, plan.actions[0].target);
        assert_eq!(row.action_ids, ["renice-42", "pause-42"]);
        assert_eq!(row.scope, "single_process");
        assert_eq!(
            row.attribution,
            "combined_action_window_observation_not_per_action_efficacy"
        );
        assert!(row.comparable);
        assert_eq!(
            row.cpu_cores,
            ObservedMetricDelta {
                before: Some(1.0),
                after: Some(0.25),
                delta: Some(-0.75)
            }
        );
        assert_eq!(row.cpu_host_percent.delta, Some(-37.5));
        assert_eq!(row.rss_bytes.delta, Some(-1_048_576.0));
        // Host available memory is its own observation; neither a second action
        // nor an unexecuted 1 GiB process multiplies either measurement.
        assert_eq!(report.available_memory_bytes.delta, Some(1_000_000.0));
        assert_eq!(row.before_window.rss_bytes, Some(2_097_152));
        assert_eq!(row.after_window.rss_bytes, Some(1_048_576));

        for sample in &mut artifact.after.samples {
            sample
                .processes
                .retain(|process| process.target.pid == other.pid);
        }
        let missing = replay_resource_artifact(
            &artifact,
            &plan,
            &artifact.plan_sha256,
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert_eq!(missing.processes.len(), 1);
        assert!(!missing.processes[0].comparable);
        assert_eq!(missing.processes[0].rss_bytes.before, Some(2_097_152.0));
        assert_eq!(missing.processes[0].rss_bytes.after, None);
        assert_eq!(missing.processes[0].rss_bytes.delta, None);
        assert_eq!(missing.processes[0].cpu_cores.delta, None);
    }

    #[test]
    fn replay_keeps_point_rss_and_capacity_changes_separate_from_cpu_relief() {
        let (mut artifact, plan, saved, current) = artifact_fixture();
        attach_process_evidence(&mut artifact);
        for sample in &mut artifact.after.samples {
            sample.pressure.cpus = 4;
        }
        let report = replay_resource_artifact(
            &artifact,
            &plan,
            &artifact.plan_sha256,
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert!(!report.cpu_capacity_comparable);
        let row = &report.processes[0];
        assert_eq!(row.cpu_cores.before, Some(1.0));
        assert_eq!(row.cpu_cores.after, Some(0.25));
        assert_eq!(row.cpu_cores.delta, None);
        assert_eq!(row.cpu_host_percent.delta, None);
        assert_eq!(row.rss_bytes.delta, Some(-1_048_576.0));

        artifact.before = window(vec![artifact.before.samples[0].clone()]);
        artifact.after = window(vec![artifact.after.samples[0].clone()]);
        let point = replay_resource_artifact(
            &artifact,
            &plan,
            &artifact.plan_sha256,
            &saved,
            &current,
            None,
        )
        .unwrap();
        let row = &point.processes[0];
        assert!(row.comparable);
        assert_eq!(row.cpu_cores.before, None);
        assert_eq!(row.cpu_cores.after, None);
        assert_eq!(row.cpu_cores.delta, None);
        assert_eq!(row.rss_bytes.delta, Some(-1_048_576.0));
        assert!(row
            .unavailable
            .iter()
            .any(|error| error.reason.contains("point observation")));
    }

    #[test]
    fn historical_host_only_artifacts_do_not_invent_process_observations() {
        let (artifact, plan, saved, current) = artifact_fixture();
        let mut serialized = serde_json::to_value(&artifact).unwrap();
        for phase in ["before", "after"] {
            for sample in serialized[phase]["samples"].as_array_mut().unwrap() {
                sample.as_object_mut().unwrap().remove("processes");
            }
        }
        let old: ResourceObservationArtifact = serde_json::from_value(serialized).unwrap();
        let report =
            replay_resource_artifact(&old, &plan, &old.plan_sha256, &saved, &current, None)
                .unwrap();
        assert_eq!(report.available_memory_bytes.delta, Some(1_000_000.0));
        assert_eq!(report.processes.len(), 1);
        assert!(!report.processes[0].comparable);
        assert_eq!(report.processes[0].rss_bytes.delta, None);
        assert_eq!(report.processes[0].cpu_cores.delta, None);
    }

    #[test]
    fn oversized_process_sample_cannot_replay_as_complete_evidence() {
        let (mut artifact, plan, saved, current) = artifact_fixture();
        attach_process_evidence(&mut artifact);
        let repeated = artifact.before.samples[0].processes[0].clone();
        artifact.before.samples[0].processes = vec![repeated; MAX_PROCESS_RESOURCE_TARGETS + 1];
        let error = replay_resource_artifact(
            &artifact,
            &plan,
            &artifact.plan_sha256,
            &saved,
            &current,
            None,
        )
        .unwrap_err();
        assert!(error.contains("process observation bound"), "{error}");
    }

    #[test]
    fn artifact_roundtrip_replays_only_exact_current_execution_bindings() {
        let (artifact, plan, mut saved, current) = artifact_fixture();
        let restored: ResourceObservationArtifact =
            serde_json::from_slice(&serde_json::to_vec(&artifact).unwrap()).unwrap();
        let report = replay_resource_artifact(
            &restored,
            &plan,
            &plan_digest(&plan),
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert_eq!(report.available_memory_bytes.delta, Some(1_000_000.0));
        let binding = report.binding.unwrap();
        assert_eq!(binding.run_id, RUN);
        assert_eq!(binding.execution_clock_resolution_ns, 10_000_000);
        let mut skipped = saved[0].clone();
        skipped.status = "already_completed".into();
        skipped.executed_at = None;
        saved.push(skipped);
        assert!(
            replay_resource_artifact(
                &artifact,
                &plan,
                &plan_digest(&plan),
                &saved,
                &current,
                None
            )
            .is_ok(),
            "a resume skip must not erase the actual prior execution"
        );
    }

    #[test]
    fn point_replay_uses_the_observed_wall_clock_millisecond_resolution() {
        let (mut artifact, plan, mut saved, mut current) = artifact_fixture();
        let mut before = sample(2500, 100, 100, 0);
        before.monotonic_start_ns = Some(2_500_100_000);
        before.monotonic_end_ns = Some(2_500_200_000);
        let mut after = sample(2500, 100, 100, 0);
        after.monotonic_start_ns = Some(2_500_700_000);
        after.monotonic_end_ns = Some(2_500_800_000);
        artifact.before = window(vec![before]);
        artifact.after = window(vec![after]);
        current.pressure.sampled_at_ms = 2500;
        current.monotonic_start_ns = Some(2_500_900_000);
        current.monotonic_end_ns = Some(2_500_950_000);
        saved[0].executed_at = DateTime::<Utc>::from_timestamp(2, 500_500_000);
        artifact.actions[0] = ResourceActionBinding::from_saved(&saved[0]).unwrap();
        let report = replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &saved,
            &current,
            None,
        )
        .expect("a later observation in the same millisecond is not a future execution");
        assert!(report.comparable);
        assert!(report.cpu.busy_percent.delta.is_none());
        saved[0].executed_at = DateTime::<Utc>::from_timestamp_millis(2501);
        artifact.actions[0] = ResourceActionBinding::from_saved(&saved[0]).unwrap();
        assert!(
            replay_resource_artifact(
                &artifact,
                &plan,
                &plan_digest(&plan),
                &saved,
                &current,
                None
            )
            .is_err(),
            "the next millisecond remains in the future"
        );
    }

    #[test]
    fn artifact_refuses_changed_plan_latest_attempt_boot_and_missing_evidence() {
        let (artifact, plan, saved, current) = artifact_fixture();
        let mut changed_plan = plan.clone();
        changed_plan.policy_version = "changed-policy".into();
        assert!(replay_resource_artifact(
            &artifact,
            &changed_plan,
            &plan_digest(&changed_plan),
            &saved,
            &current,
            None,
        )
        .is_err());
        let mut wrong_session = artifact.clone();
        wrong_session.session_id = "other".into();
        assert!(replay_resource_artifact(
            &wrong_session,
            &plan,
            &plan_digest(&plan),
            &saved,
            &current,
            None,
        )
        .is_err());
        let mut latest = saved.clone();
        let mut newer = saved[0].clone();
        newer.executed_at = DateTime::<Utc>::from_timestamp_millis(2600);
        newer.execution_clock.as_mut().unwrap().ticks = 260;
        latest.push(newer);
        assert!(replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &latest,
            &current,
            None
        )
        .is_err());
        let mut new_boot = current.clone();
        new_boot.boot_id = Some(OTHER_BOOT.into());
        assert!(replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &saved,
            &new_boot,
            None
        )
        .is_err());
        let mut missing_clock = saved.clone();
        missing_clock[0].execution_clock = None;
        assert!(replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &missing_clock,
            &current,
            None,
        )
        .is_err());
        let mut changed_clock = saved.clone();
        changed_clock[0].execution_clock.as_mut().unwrap().ticks = 251;
        assert!(replay_resource_artifact(&artifact, &plan, &plan_digest(&plan), &changed_clock, &current, None).is_err(),
            "an edited clock inside the same gap must not replace the original bound execution clock");
        let mut dry_run = saved[0].clone();
        dry_run.status = "dry_run".into();
        assert!(ResourceActionBinding::from_saved(&dry_run).is_err());
        let mut precheck_failure = saved[0].clone();
        precheck_failure.status = "identity_check_failed".into();
        precheck_failure.executed_at = None;
        assert!(ResourceActionBinding::from_saved(&precheck_failure).is_err());
        let mut duplicate = artifact.clone();
        duplicate.actions.push(duplicate.actions[0].clone());
        let mut larger_plan = plan.clone();
        let mut unattempted = plan.actions[0].clone();
        unattempted.action_id = "unattempted-43".into();
        unattempted.target = ProcessIdentity::new(43, StartId::from_linux(BOOT, 10, 43), 1000);
        larger_plan.actions.push(unattempted);
        duplicate.plan_sha256 = plan_digest(&larger_plan);
        assert!(replay_resource_artifact(
            &duplicate,
            &larger_plan,
            &plan_digest(&larger_plan),
            &saved,
            &current,
            None,
        )
        .is_err());
    }

    #[test]
    fn artifact_keeps_actual_failed_attempts_without_claiming_they_succeeded() {
        let (mut artifact, plan, mut saved, current) = artifact_fixture();
        saved[0].status = "failed".into();
        artifact.actions[0] = ResourceActionBinding::from_saved(&saved[0]).unwrap();
        let report = replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert_eq!(artifact.actions[0].status, "failed");
        assert!(
            report.comparable,
            "host observations survive partial action failure without certifying action success"
        );
        assert_eq!(
            report.attribution,
            "observed_host_change_not_per_action_recovery"
        );
    }

    #[test]
    fn execution_clock_validation_accepts_overlap_at_declared_tick_precision() {
        let (mut artifact, plan, mut saved, current) = artifact_fixture();
        artifact.before = window(vec![sample(2005, 100, 100, 0)]);
        artifact.after = window(vec![sample(2009, 100, 100, 0)]);
        saved[0].executed_at = DateTime::<Utc>::from_timestamp_millis(2007);
        saved[0].execution_clock.as_mut().unwrap().ticks = 200; // [2000ms, 2010ms)
        artifact.actions[0] = ResourceActionBinding::from_saved(&saved[0]).unwrap();
        let report = replay_resource_artifact(
            &artifact,
            &plan,
            &plan_digest(&plan),
            &saved,
            &current,
            None,
        )
        .unwrap();
        assert_eq!(
            report.binding.unwrap().execution_clock_resolution_ns,
            10_000_000
        );
        assert!(report.cpu.busy_percent.delta.is_none());
        for ticks in [199, 201] {
            saved[0].execution_clock.as_mut().unwrap().ticks = ticks;
            artifact.actions[0].execution_clock = saved[0].execution_clock.clone().unwrap();
            assert!(replay_resource_artifact(
                &artifact,
                &plan,
                &plan_digest(&plan),
                &saved,
                &current,
                None,
            )
            .is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn live_observation_reads_kernel_identity_clock_and_aggregate_cpu() {
        let observation = capture_resource_observation();
        assert!(observation
            .boot_id
            .as_deref()
            .is_some_and(|boot| uuid::Uuid::parse_str(boot).is_ok()));
        assert!(observation.clock_ticks_per_second.is_some_and(|hz| hz > 0));
        let start = observation
            .monotonic_start_ns
            .expect("kernel CLOCK_BOOTTIME start");
        let end = observation
            .monotonic_end_ns
            .expect("kernel CLOCK_BOOTTIME end");
        assert!(end >= start);
        assert!(
            observation.cpu_times.is_some(),
            "real aggregate /proc/stat counters: {:?}",
            observation.unavailable
        );
        let point = ResourceObservationWindow {
            requested_duration_ms: 0,
            sample_interval_ms: SAMPLE_INTERVAL_MS,
            samples: vec![observation],
        };
        assert!(
            summarize_window(&point).cpu_usage.is_none(),
            "one real reading cannot prove a CPU rate"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn live_process_observation_tracks_an_owned_child_and_refuses_reuse_or_exit() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        // Read the child's own proc identity before exec. The mounted procfs
        // PID can differ from Child::id() in a PID namespace, and guessing the
        // latter could inspect an unrelated host process.
        let mut child = OwnedChild(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "IFS= read -r stat < /proc/self/stat; printf '%s\\n' \"$stat\"; exec sleep 30",
                ])
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn disposable observer child"),
        );
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let pid: u32 = line.split_whitespace().next().unwrap().parse().unwrap();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let counters = parse_process_counters(&line, pid, 4096).unwrap();
        let directory = ResourceProcDirectory::open(pid).unwrap();
        let uid = parse_process_uids(&directory.read("status").unwrap()).unwrap()[0];
        let target = ProcessIdentity::new(
            pid,
            StartId::from_linux(boot.trim(), counters.start_ticks, pid),
            uid,
        );
        let observed = collect_resource_window(
            Duration::from_millis(20),
            std::slice::from_ref(&target),
            |_| {},
        )
        .unwrap();
        let summary = summarize_process_window(&observed, &target);
        assert!(summary.complete, "{:?}", summary.unavailable);
        assert!(summary.cpu_cores.is_some(), "{:?}", summary.unavailable);
        assert!(summary.rss_bytes.is_some());
        for sample in &observed.samples {
            assert_eq!(sample.processes[0].target, target);
            assert!(sample.processes[0].monotonic_start_ns >= sample.monotonic_start_ns);
            assert!(sample.processes[0].monotonic_end_ns <= sample.monotonic_end_ns);
        }
        let mut wrong_birth = target.clone();
        wrong_birth.start_id = StartId::from_linux(boot.trim(), counters.start_ticks + 1, pid);
        let mut wrong_user = target.clone();
        wrong_user.uid = uid.wrapping_add(1);
        for invalid in [wrong_birth, wrong_user] {
            let failed = capture_resource_observation_for_targets(&[invalid]);
            assert_eq!(failed.processes[0].user_ticks, None);
            assert_eq!(failed.processes[0].rss_bytes, None);
            assert!(!failed.processes[0].unavailable.is_empty());
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let gone = capture_resource_observation_for_targets(std::slice::from_ref(&target));
        assert_eq!(gone.processes[0].rss_bytes, None);
        assert_eq!(gone.processes[0].user_ticks, None);
        assert!(!gone.processes[0].unavailable.is_empty());
    }
}
