//! System pressure sensing: how loaded the machine is, not which process is abandoned.
//!
//! Reads Pressure Stall Information (`/proc/pressure/{cpu,memory,io,irq}`, both the
//! `some` and `full` lines with avg10/avg60/avg300 and the cumulative `total`), the
//! load average with the runnable/total task counts, the memory picture
//! (`/proc/meminfo`, including cache, slab and swap), cumulative VM counters
//! (`/proc/vmstat`: swapping, major faults, direct reclaim, compaction stalls, OOM
//! kills) and the file-handle table (`/proc/sys/fs/file-nr`).
//!
//! Two snapshots taken some time apart give exact rates over that window
//! ([`PressureWindow`]): the PSI `total` counters (microseconds stalled) turn into the
//! fraction of the window some/all tasks stalled, which is more precise than `avg10`
//! for short windows; vmstat counters turn into per-second rates.
//!
//! A source that cannot be read is reported as unavailable with the reason. It never
//! reads as zero: "no PSI on this kernel" is not "no pressure".
//!
//! Linux sources read from a root directory (`/` on a live system) so the parsers
//! and window math are testable against recorded files. macOS obtains native load
//! averages, VM counters, RAM/swap sizes and the kernel's qualitative memory
//! pressure level. Linux-only PSI and MemAvailable remain unavailable there.

use super::types::{ProcessActivity, ProcessRecord};
use pt_common::StartId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

/// Aggregate CPU accounting from `/proc/stat`, with the observed online CPU IDs.
/// The first eight counters include guest time through user/nice already; adding
/// the separate guest counters would count that work twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCpuCounters {
    ticks: [u64; 8],
    cpu_ids: BTreeSet<u32>,
}

/// CPU capacity observed over the same interval as process tick deltas.
/// Percentages use the whole host as 100%, including unselected processes and
/// kernel work. Idle and I/O-wait ticks are excluded from busy time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HostCpuWindow {
    pub total_ticks: u64,
    pub busy_ticks: u64,
    pub logical_cpus: u32,
    pub window_seconds: f64,
}

impl HostCpuWindow {
    /// Whole-host busy percentage, or unknown for an invalid observation.
    pub fn busy_percent(&self) -> Option<f64> {
        self.process_percent(self.busy_ticks)
    }

    /// A process's measured share of host capacity, using its raw tick delta.
    /// A contribution larger than all observed busy time cannot be trusted.
    pub fn process_percent(&self, process_ticks: u64) -> Option<f64> {
        if self.total_ticks == 0
            || self.busy_ticks > self.total_ticks
            || self.logical_cpus == 0
            || !self.window_seconds.is_finite()
            || self.window_seconds <= 0.0
            || process_ticks > self.busy_ticks
        {
            return None;
        }
        Some(100.0 * (process_ticks as f64 / self.total_ticks as f64))
    }
}

const HOST_CPU_FIELDS: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

fn parse_host_cpu_row(
    label: &str,
    mut values: std::str::SplitWhitespace<'_>,
) -> Result<[u64; 8], String> {
    let mut ticks = [0; 8];
    for (index, field) in HOST_CPU_FIELDS.iter().enumerate() {
        let value = values
            .next()
            .ok_or_else(|| format!("{label}: missing {field} counter"))?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("{label}: invalid {field} counter"));
        }
        ticks[index] = value
            .parse()
            .map_err(|_| format!("{label}: {field} counter exceeds u64"))?;
    }
    // Guest columns and future extensions are not additional CPU capacity, but
    // malformed counters still invalidate the reading rather than disappearing.
    for value in values {
        if !value.bytes().all(|byte| byte.is_ascii_digit()) || value.parse::<u64>().is_err() {
            return Err(format!("{label}: invalid trailing CPU counter"));
        }
    }
    ticks
        .iter()
        .try_fold(0_u64, |sum, tick| sum.checked_add(*tick))
        .ok_or_else(|| format!("{label}: accounting counter sum exceeds u64"))?;
    Ok(ticks)
}

/// Parse aggregate accounting and online CPU identities from `/proc/stat`.
/// Missing, duplicate, malformed or overflowing CPU rows are unavailable.
pub fn parse_host_cpu_counters(text: &str) -> Result<HostCpuCounters, String> {
    let mut aggregate = None;
    let mut cpu_ids = BTreeSet::new();
    for line in text.lines() {
        let mut values = line.split_whitespace();
        let Some(label) = values.next() else {
            continue;
        };
        if label == "cpu" {
            if aggregate.is_some() {
                return Err("duplicate aggregate cpu row".to_string());
            }
            aggregate = Some(parse_host_cpu_row(label, values)?);
        } else if let Some(id) = label.strip_prefix("cpu") {
            if !id.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("invalid CPU identifier: {label}"));
            }
            let id = id
                .parse::<u32>()
                .map_err(|_| format!("CPU identifier exceeds u32: {label}"))?;
            if !cpu_ids.insert(id) {
                return Err(format!("duplicate CPU identifier: {label}"));
            }
            parse_host_cpu_row(label, values)?;
        }
    }
    let ticks = aggregate.ok_or_else(|| "missing aggregate cpu row".to_string())?;
    if cpu_ids.is_empty() {
        return Err("no online CPU rows in /proc/stat".to_string());
    }
    Ok(HostCpuCounters { ticks, cpu_ids })
}

/// Read CPU accounting from a filesystem root (`/` on the live machine).
pub fn read_host_cpu_counters_from(root: &Path) -> Result<HostCpuCounters, String> {
    let path = root.join("proc/stat");
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_host_cpu_counters(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Read the live host's CPU accounting without substituting load averages.
#[cfg(target_os = "linux")]
pub fn read_host_cpu_counters() -> Result<HostCpuCounters, String> {
    read_host_cpu_counters_from(Path::new("/"))
}

#[cfg(not(target_os = "linux"))]
pub fn read_host_cpu_counters() -> Result<HostCpuCounters, String> {
    Err("host CPU accounting requires Linux /proc/stat".to_string())
}

/// Measure host capacity over a monotonic interval. A reset in any accounting
/// component (including the kernel's occasionally decreasing iowait) or a change
/// in online CPU identities makes the window unknown instead of a zero baseline.
pub fn host_cpu_window(
    before: &HostCpuCounters,
    after: &HostCpuCounters,
    elapsed: Duration,
) -> Result<HostCpuWindow, String> {
    if elapsed.is_zero() {
        return Err("host CPU sampling interval is zero".to_string());
    }
    if before.cpu_ids != after.cpu_ids {
        return Err("online CPU topology changed during sampling".to_string());
    }
    let logical_cpus = u32::try_from(after.cpu_ids.len())
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| "online CPU count is unavailable".to_string())?;
    let mut deltas = [0; 8];
    for (index, field) in HOST_CPU_FIELDS.iter().enumerate() {
        deltas[index] = after.ticks[index]
            .checked_sub(before.ticks[index])
            .ok_or_else(|| format!("host CPU {field} counter decreased during sampling"))?;
    }
    let total_ticks = deltas
        .iter()
        .try_fold(0_u64, |sum, tick| sum.checked_add(*tick))
        .filter(|total| *total > 0)
        .ok_or_else(|| "host CPU tick delta is zero or exceeds u64".to_string())?;
    let idle_ticks = deltas[3]
        .checked_add(deltas[4])
        .ok_or_else(|| "host idle CPU tick delta exceeds u64".to_string())?;
    let busy_ticks = total_ticks
        .checked_sub(idle_ticks)
        .ok_or_else(|| "host idle CPU ticks exceed total ticks".to_string())?;
    Ok(HostCpuWindow {
        total_ticks,
        busy_ticks,
        logical_cpus,
        window_seconds: elapsed.as_secs_f64(),
    })
}

const PROCESS_IO_SOURCE: &str = "procfs_window";
const PROCESS_IO_SCOPE: &str = "observed_census_process_io";
const PROCESS_IO_LIMITATIONS: [&str; 4] = [
    "Shares compare accounted I/O rates within the observed process cohort, not host device capacity or responsibility for PSI stalls.",
    "Each process uses its own measured interval; enumeration staggers interval endpoints and transient processes outside the census are not represented.",
    "Kernel I/O outside process accounting is excluded, and process accounting can include waited-for children.",
    "Write bytes are accounted when pages are dirtied; pending or cancelled writes need not become completed device writes.",
];

/// I/O accounting for every process in one complete observed census.
///
/// The denominator is the sum of each process's `read_bytes` and `write_bytes`
/// deltas divided by that process's actual monotonic sampling duration. It is
/// deliberately **not** disk throughput, device utilization, or a causal share
/// of host I/O stalls. In particular, unequal per-process durations must not be
/// turned into a share by dividing raw byte sums.
///
/// Every census member, including protected and unselected processes, must have
/// a complete identity-bound sample. A failed read or incomplete census makes
/// the entire denominator unavailable. New and short-lived processes outside
/// the census remain a limitation even when every observed member is readable.
///
/// Fields are immutable outside this module so validation can be cached once,
/// including after deserialization, without rescanning the census for every
/// candidate. Serialized summaries retain the member measurements for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIoWindow {
    source: String,
    scope: String,
    census_complete: bool,
    requested_window_ms: u64,
    sampled_processes: usize,
    read_bytes: u64,
    write_bytes: u64,
    read_bytes_per_second: f64,
    write_bytes_per_second: f64,
    min_window_seconds: f64,
    max_window_seconds: f64,
    limitations: Vec<String>,
    members: BTreeMap<u32, ProcessIoMember>,
    #[serde(skip)]
    validation: OnceLock<Result<(), String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ProcessIoMember {
    start_id: StartId,
    uid: u32,
    read_bytes: u64,
    write_bytes: u64,
    window_seconds: f64,
}

#[derive(Debug)]
struct ProcessIoTotals {
    read_bytes: u64,
    write_bytes: u64,
    read_bytes_per_second: f64,
    write_bytes_per_second: f64,
    min_window_seconds: f64,
    max_window_seconds: f64,
}

fn process_io_boot_id(pid: u32, start_id: &StartId) -> Result<&str, String> {
    let mut parts = start_id.0.split(':');
    let boot_id = parts.next().unwrap_or_default();
    let start_ticks = parts.next().unwrap_or_default();
    let identity_pid = parts.next().unwrap_or_default();
    if pid == 0
        || boot_id.is_empty()
        || matches!(boot_id, "unknown" | "synthetic")
        || start_ticks.is_empty()
        || !start_ticks.bytes().all(|byte| byte.is_ascii_digit())
        || start_ticks.parse::<u64>().is_err()
        || identity_pid.parse::<u32>().ok() != Some(pid)
        || parts.next().is_some()
    {
        return Err(format!(
            "PID {pid}: complete Linux process identity is unavailable"
        ));
    }
    // A process born in the first boot tick may legitimately have start tick 0.
    Ok(boot_id)
}

fn same_io_rate(observed: f64, expected: f64) -> bool {
    observed.is_finite()
        && observed >= 0.0
        && expected.is_finite()
        && expected >= 0.0
        && (observed == expected
            || (observed - expected).abs() <= expected.abs() * (16.0 * f64::EPSILON))
}

impl ProcessIoMember {
    fn from_activity(activity: &ProcessActivity, requested_window_ms: u64) -> Result<Self, String> {
        let pid = activity.pid;
        if activity.source != PROCESS_IO_SOURCE {
            return Err(format!(
                "PID {pid}: I/O source is not a measured procfs window"
            ));
        }
        if let Some(error) = &activity.io_error {
            return Err(format!("PID {pid}: I/O sample unavailable: {error}"));
        }
        if requested_window_ms == 0 || activity.requested_window_ms != requested_window_ms {
            return Err(format!(
                "PID {pid}: I/O samples have different or zero requested intervals"
            ));
        }
        let member = Self {
            start_id: activity.start_id.clone(),
            uid: activity.uid,
            read_bytes: activity
                .io_read_bytes
                .ok_or_else(|| format!("PID {pid}: measured I/O read byte delta is unavailable"))?,
            write_bytes: activity.io_write_bytes.ok_or_else(|| {
                format!("PID {pid}: measured I/O write byte delta is unavailable")
            })?,
            window_seconds: activity
                .io_window_seconds
                .ok_or_else(|| format!("PID {pid}: measured I/O interval is unavailable"))?,
        };
        member.validate(pid, requested_window_ms)?;
        let read_rate = activity
            .read_bytes_per_second
            .ok_or_else(|| format!("PID {pid}: measured I/O read rate is unavailable"))?;
        let write_rate = activity
            .write_bytes_per_second
            .ok_or_else(|| format!("PID {pid}: measured I/O write rate is unavailable"))?;
        if !same_io_rate(read_rate, member.read_rate())
            || !same_io_rate(write_rate, member.write_rate())
            || activity.io_active != Some(member.read_bytes > 0 || member.write_bytes > 0)
        {
            return Err(format!(
                "PID {pid}: I/O rates or activity do not match the measured byte deltas"
            ));
        }
        Ok(member)
    }

    fn validate(&self, pid: u32, requested_window_ms: u64) -> Result<(), String> {
        process_io_boot_id(pid, &self.start_id)?;
        if requested_window_ms == 0
            || !self.window_seconds.is_finite()
            || self.window_seconds <= 0.0
            || self.window_seconds < Duration::from_millis(requested_window_ms).as_secs_f64()
        {
            return Err(format!(
                "PID {pid}: I/O interval is invalid or shorter than requested"
            ));
        }
        if !self.read_rate().is_finite() || !self.write_rate().is_finite() {
            return Err(format!("PID {pid}: measured I/O rate is not finite"));
        }
        Ok(())
    }

    fn read_rate(&self) -> f64 {
        self.read_bytes as f64 / self.window_seconds
    }

    fn write_rate(&self) -> f64 {
        self.write_bytes as f64 / self.window_seconds
    }
}

fn process_io_totals(
    members: &BTreeMap<u32, ProcessIoMember>,
    requested_window_ms: u64,
) -> Result<ProcessIoTotals, String> {
    if members.is_empty() {
        return Err("observed process I/O census is empty".to_string());
    }
    let mut totals = ProcessIoTotals {
        read_bytes: 0,
        write_bytes: 0,
        read_bytes_per_second: 0.0,
        write_bytes_per_second: 0.0,
        min_window_seconds: f64::INFINITY,
        max_window_seconds: 0.0,
    };
    let mut boot_id = None;
    for (&pid, member) in members {
        member.validate(pid, requested_window_ms)?;
        let member_boot = process_io_boot_id(pid, &member.start_id)?;
        if boot_id.is_some_and(|boot| boot != member_boot) {
            return Err("observed process I/O samples have different boot identities".to_string());
        }
        boot_id = Some(member_boot);
        totals.read_bytes = totals
            .read_bytes
            .checked_add(member.read_bytes)
            .ok_or_else(|| "observed process I/O read byte sum exceeds u64".to_string())?;
        totals.write_bytes = totals
            .write_bytes
            .checked_add(member.write_bytes)
            .ok_or_else(|| "observed process I/O write byte sum exceeds u64".to_string())?;
        totals.read_bytes_per_second += member.read_rate();
        totals.write_bytes_per_second += member.write_rate();
        totals.min_window_seconds = totals.min_window_seconds.min(member.window_seconds);
        totals.max_window_seconds = totals.max_window_seconds.max(member.window_seconds);
    }
    if !(totals.read_bytes_per_second + totals.write_bytes_per_second).is_finite() {
        return Err("observed process I/O rate sum is not finite".to_string());
    }
    Ok(totals)
}

impl ProcessIoWindow {
    /// Source of every sample in this window.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Scope of the denominator; this is a process cohort, not host throughput.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Validate the full serialized accounting once before it can be used.
    pub fn validate(&self) -> Result<(), String> {
        self.validation
            .get_or_init(|| self.validate_uncached())
            .clone()
    }

    fn validate_uncached(&self) -> Result<(), String> {
        if self.source != PROCESS_IO_SOURCE
            || self.scope != PROCESS_IO_SCOPE
            || !self.census_complete
            || self.sampled_processes != self.members.len()
            || self
                .limitations
                .iter()
                .map(String::as_str)
                .ne(PROCESS_IO_LIMITATIONS)
        {
            return Err(
                "observed process I/O source, scope, or census coverage is invalid".to_string(),
            );
        }
        let totals = process_io_totals(&self.members, self.requested_window_ms)?;
        if self.read_bytes != totals.read_bytes
            || self.write_bytes != totals.write_bytes
            || !same_io_rate(self.read_bytes_per_second, totals.read_bytes_per_second)
            || !same_io_rate(self.write_bytes_per_second, totals.write_bytes_per_second)
            || self.min_window_seconds != totals.min_window_seconds
            || self.max_window_seconds != totals.max_window_seconds
        {
            return Err(
                "observed process I/O summary does not match its member measurements".to_string(),
            );
        }
        Ok(())
    }

    /// Share of measured accounted byte rates within the observed cohort.
    ///
    /// The sample must match the exact process incarnation, byte deltas and
    /// measured interval used in the denominator. All-zero cohort activity is
    /// unknown, not a denominator from which a zero contribution can be inferred.
    pub fn share(&self, activity: &ProcessActivity) -> Option<f64> {
        self.validate().ok()?;
        let member = self.members.get(&activity.pid)?;
        if *member != ProcessIoMember::from_activity(activity, self.requested_window_ms).ok()? {
            return None;
        }
        let total_rate = self.read_bytes_per_second + self.write_bytes_per_second;
        if total_rate <= 0.0 {
            return None;
        }
        let share = (member.read_rate() + member.write_rate()) / total_rate;
        (share.is_finite() && (0.0..=1.0).contains(&share)).then_some(share)
    }
}

/// Aggregate a complete census's already collected, bounded process I/O samples.
///
/// This performs no additional reads or waits. Call it before candidate filters,
/// supplying every census process and exactly one sample for each incarnation.
/// Missing, failed, extra or duplicate samples make the denominator unavailable.
pub fn process_io_window(
    population: &[ProcessRecord],
    samples: impl IntoIterator<Item = ProcessActivity>,
    census_complete: bool,
) -> Result<ProcessIoWindow, String> {
    if !census_complete {
        return Err(
            "observed process I/O denominator requires a complete process census".to_string(),
        );
    }
    if population.is_empty() {
        return Err("observed process I/O census is empty".to_string());
    }
    let mut expected = BTreeMap::new();
    for process in population {
        if expected.insert(process.pid.0, process).is_some() {
            return Err(format!(
                "PID {}: duplicate process in I/O census",
                process.pid.0
            ));
        }
    }
    let mut members = BTreeMap::new();
    let mut requested_window_ms = None;
    for activity in samples {
        let pid = activity.pid;
        let process = expected
            .get(&pid)
            .ok_or_else(|| format!("PID {pid}: I/O sample is outside the process census"))?;
        if !activity.matches_record(process) {
            return Err(format!(
                "PID {pid}: I/O sample does not match the census process incarnation"
            ));
        }
        let requested = *requested_window_ms.get_or_insert(activity.requested_window_ms);
        let member = ProcessIoMember::from_activity(&activity, requested)?;
        if members.insert(pid, member).is_some() {
            return Err(format!("PID {pid}: duplicate I/O sample"));
        }
    }
    if members.len() != expected.len() {
        return Err(format!(
            "observed process I/O samples are incomplete: {} of {} census processes",
            members.len(),
            expected.len()
        ));
    }
    let requested_window_ms = requested_window_ms
        .ok_or_else(|| "observed process I/O samples are unavailable".to_string())?;
    let totals = process_io_totals(&members, requested_window_ms)?;
    let window = ProcessIoWindow {
        source: PROCESS_IO_SOURCE.to_string(),
        scope: PROCESS_IO_SCOPE.to_string(),
        census_complete,
        requested_window_ms,
        sampled_processes: members.len(),
        read_bytes: totals.read_bytes,
        write_bytes: totals.write_bytes,
        read_bytes_per_second: totals.read_bytes_per_second,
        write_bytes_per_second: totals.write_bytes_per_second,
        min_window_seconds: totals.min_window_seconds,
        max_window_seconds: totals.max_window_seconds,
        limitations: PROCESS_IO_LIMITATIONS
            .iter()
            .map(|text| (*text).to_string())
            .collect(),
        members,
        validation: OnceLock::new(),
    };
    window.validate()?;
    Ok(window)
}

/// One PSI line (`some` or `full`): running averages in percent and the cumulative
/// stall time in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

impl PsiLine {
    /// Whether every average is a measured percentage, including a real zero.
    /// Apply the same check to deserialized snapshots as to procfs readings.
    pub fn is_valid(&self) -> bool {
        [self.avg10, self.avg60, self.avg300]
            .iter()
            .all(|value| value.is_finite() && (0.0..=100.0).contains(value))
    }
}

/// PSI for one resource. `full` is absent for CPU on older kernels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiResource {
    pub some: Option<PsiLine>,
    pub full: Option<PsiLine>,
}

/// System load averages and task counts when the source provides them.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    /// Runnable scheduling entities right now. Not reported by macOS getloadavg.
    #[serde(default)]
    pub runnable: Option<u32>,
    /// Scheduling entities that exist. Not reported by macOS getloadavg.
    #[serde(default)]
    pub total: Option<u32>,
}

/// The dispatch pressure level reported by macOS's
/// `kern.memorystatus_vm_pressure_level`. These are qualitative kernel states,
/// not PSI percentages or estimates of available RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosPressureLevel {
    Normal,
    Warning,
    Critical,
}

/// Memory accounting, in bytes. Fields a kernel does not report are `None`.
/// On macOS `free` includes speculative pages and `cached` reports file-backed
/// pages; neither is a Linux MemAvailable estimate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct MemInfo {
    pub total: Option<u64>,
    pub free: Option<u64>,
    pub available: Option<u64>,
    pub buffers: Option<u64>,
    pub cached: Option<u64>,
    pub swap_cached: Option<u64>,
    pub anon: Option<u64>,
    pub shmem: Option<u64>,
    pub slab: Option<u64>,
    pub slab_reclaimable: Option<u64>,
    pub slab_unreclaimable: Option<u64>,
    pub dirty: Option<u64>,
    pub writeback: Option<u64>,
    pub swap_total: Option<u64>,
    pub swap_free: Option<u64>,
    pub committed_as: Option<u64>,
    pub commit_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_pressure: Option<MacosPressureLevel>,
}

impl MemInfo {
    /// Swap in use (bytes).
    pub fn swap_used(&self) -> Option<u64> {
        self.swap_total?.checked_sub(self.swap_free?)
    }

    /// Fraction of RAM not available for new allocations without reclaim.
    pub fn used_fraction(&self) -> Option<f64> {
        let total = self.total.filter(|t| *t > 0)?;
        let used = total.checked_sub(self.available?)?;
        Some(used as f64 / total as f64)
    }
}

/// The cumulative `/proc/vmstat` counters pressure diagnosis uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct VmStat {
    /// Pages swapped in / out since boot.
    pub pswpin: Option<u64>,
    pub pswpout: Option<u64>,
    /// Major page faults since boot.
    pub pgmajfault: Option<u64>,
    /// Pages scanned by direct reclaim (allocating tasks doing reclaim themselves).
    pub pgscan_direct: Option<u64>,
    /// Times an allocation stalled for direct reclaim (sum over zones).
    pub allocstall: Option<u64>,
    /// Times an allocation stalled for compaction.
    pub compact_stall: Option<u64>,
    /// Kernel OOM kills since boot.
    pub oom_kill: Option<u64>,
}

/// Allocated entries and configured capacity of the system-wide open file table.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FileHandles {
    pub allocated: u64,
    pub max: u64,
}

impl FileHandles {
    pub fn used_fraction(&self) -> Option<f64> {
        (self.max > 0).then_some(self.allocated as f64 / self.max as f64)
    }
}

/// A source that could not be read, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unavailable {
    pub source: String,
    pub reason: String,
}

/// One reading of system pressure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureSnapshot {
    /// Unix time of the reading, milliseconds.
    pub sampled_at_ms: u64,
    /// Online logical CPUs (the capacity the load average is compared with).
    /// Zero means unavailable, with the reason recorded in `unavailable`.
    pub cpus: u32,
    pub cpu: Option<PsiResource>,
    pub memory: Option<PsiResource>,
    pub io: Option<PsiResource>,
    pub irq: Option<PsiResource>,
    pub load: Option<LoadAvg>,
    pub meminfo: Option<MemInfo>,
    pub vmstat: Option<VmStat>,
    pub file_handles: Option<FileHandles>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<Unavailable>,
}

impl PressureSnapshot {
    /// Load average over CPU count (1-minute), the playbook's "load ratio".
    pub fn load_ratio(&self) -> Option<f64> {
        let load = self.load?;
        (self.cpus > 0
            && [load.one, load.five, load.fifteen]
                .iter()
                .all(|value| value.is_finite() && *value >= 0.0))
        .then(|| load.one / f64::from(self.cpus))
    }
}

/// Parse one PSI file. Malformed or duplicate resource lines make the source
/// unavailable; they cannot be hidden by another valid line from the same file.
pub fn parse_psi(text: &str) -> Option<PsiResource> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let slot = match parts.next() {
            Some("some") => &mut some,
            Some("full") => &mut full,
            _ => continue,
        };
        if slot.is_some() {
            return None;
        }
        let (mut avg10, mut avg60, mut avg300, mut total) = (None, None, None, None);
        for field in parts {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "avg10" if avg10.is_none() => avg10 = Some(value.parse::<f64>().ok()?),
                "avg60" if avg60.is_none() => avg60 = Some(value.parse::<f64>().ok()?),
                "avg300" if avg300.is_none() => avg300 = Some(value.parse::<f64>().ok()?),
                "total" if total.is_none() => total = Some(value.parse::<u64>().ok()?),
                "avg10" | "avg60" | "avg300" | "total" => return None,
                _ => {}
            }
        }
        let reading = PsiLine {
            avg10: avg10?,
            avg60: avg60?,
            avg300: avg300?,
            total_us: total?,
        };
        if !reading.is_valid() {
            return None;
        }
        *slot = Some(reading);
    }
    (some.is_some() || full.is_some()).then_some(PsiResource { some, full })
}

/// Parse `/proc/loadavg` (`0.52 0.58 0.59 3/811 12345`).
pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut parts = text.split_whitespace();
    let one = parts.next()?.parse::<f64>().ok()?;
    let five = parts.next()?.parse::<f64>().ok()?;
    let fifteen = parts.next()?.parse::<f64>().ok()?;
    if [one, five, fifteen]
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        return None;
    }
    let (runnable, total) = parts.next()?.split_once('/')?;
    let runnable = runnable.parse().ok()?;
    let total = total.parse().ok()?;
    if total == 0 || runnable > total {
        return None;
    }
    Some(LoadAvg {
        one,
        five,
        fifteen,
        runnable: Some(runnable),
        total: Some(total),
    })
}

/// Parse `/proc/meminfo` (values in kB) into bytes. Missing, malformed or
/// impossible accounting is unavailable, rather than saturated into healthy RAM.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut info = MemInfo::default();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let slot = match key.trim() {
            "MemTotal" => &mut info.total,
            "MemFree" => &mut info.free,
            "MemAvailable" => &mut info.available,
            "Buffers" => &mut info.buffers,
            "Cached" => &mut info.cached,
            "SwapCached" => &mut info.swap_cached,
            "AnonPages" => &mut info.anon,
            "Shmem" => &mut info.shmem,
            "Slab" => &mut info.slab,
            "SReclaimable" => &mut info.slab_reclaimable,
            "SUnreclaim" => &mut info.slab_unreclaimable,
            "Dirty" => &mut info.dirty,
            "Writeback" => &mut info.writeback,
            "SwapTotal" => &mut info.swap_total,
            "SwapFree" => &mut info.swap_free,
            "Committed_AS" => &mut info.committed_as,
            "CommitLimit" => &mut info.commit_limit,
            _ => continue,
        };
        let mut parts = rest.split_whitespace();
        let kb = parts.next()?.parse::<u64>().ok()?;
        if slot.is_some() || parts.next() != Some("kB") || parts.next().is_some() {
            return None;
        }
        *slot = Some(kb.checked_mul(1024)?);
    }
    let total = info.total.filter(|total| *total > 0)?;
    if info.available.is_some_and(|available| available > total)
        || info.free.is_some_and(|free| free > total)
        || info
            .swap_total
            .zip(info.swap_free)
            .is_some_and(|(total, free)| free > total)
    {
        return None;
    }
    Some(info)
}

/// Parse the counters of `/proc/vmstat` used for diagnosis. `allocstall` sums the
/// per-zone `allocstall_*` counters (kernels >= 4.10) or takes the old single one.
pub fn parse_vmstat(text: &str) -> Option<VmStat> {
    let mut stat = VmStat::default();
    let mut any = false;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        any = true;
        match key {
            "pswpin" => stat.pswpin = Some(value),
            "pswpout" => stat.pswpout = Some(value),
            "pgmajfault" => stat.pgmajfault = Some(value),
            "pgscan_direct" => stat.pgscan_direct = Some(value),
            "compact_stall" => stat.compact_stall = Some(value),
            "oom_kill" => stat.oom_kill = Some(value),
            k if k == "allocstall" || k.starts_with("allocstall_") => {
                stat.allocstall = Some(stat.allocstall.unwrap_or(0).saturating_add(value));
            }
            _ => {}
        }
    }
    any.then_some(stat)
}

/// Parse `/proc/sys/fs/file-nr` (`allocated  free  max`).
pub fn parse_file_nr(text: &str) -> Option<FileHandles> {
    let mut parts = text.split_whitespace();
    let allocated = parts.next()?.parse().ok()?;
    let _free: u64 = parts.next()?.parse().ok()?;
    let max = parts.next()?.parse().ok()?;
    Some(FileHandles { allocated, max })
}

fn read(root: &Path, rel: &str, unavailable: &mut Vec<Unavailable>) -> Option<String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(text) => Some(text),
        Err(err) => {
            unavailable.push(Unavailable {
                source: format!("/{rel}"),
                reason: err.to_string(),
            });
            None
        }
    }
}

fn parsed<T>(
    text: Option<String>,
    rel: &str,
    parse: impl Fn(&str) -> Option<T>,
    unavailable: &mut Vec<Unavailable>,
) -> Option<T> {
    let text = text?;
    let value = parse(&text);
    if value.is_none() {
        unavailable.push(Unavailable {
            source: format!("/{rel}"),
            reason: "unrecognized format".to_string(),
        });
    }
    value
}

/// Read a pressure snapshot from `root` (`/` on a live system).
pub fn read_pressure_snapshot_from(root: &Path, cpus: u32) -> PressureSnapshot {
    let mut unavailable = Vec::new();
    if cpus == 0 {
        unavailable.push(Unavailable {
            source: "online_cpu_count".to_string(),
            reason: "online CPU capacity could not be observed".to_string(),
        });
    }
    let psi = |name: &str, unavailable: &mut Vec<Unavailable>| {
        let rel = format!("proc/pressure/{name}");
        let text = read(root, &rel, unavailable);
        parsed(text, &rel, parse_psi, unavailable)
    };
    let cpu = psi("cpu", &mut unavailable);
    let memory = psi("memory", &mut unavailable);
    let io = psi("io", &mut unavailable);
    // irq pressure exists only on kernels built with CONFIG_IRQ_TIME_ACCOUNTING (>= 6.1);
    // its absence is normal and not worth reporting.
    let irq = std::fs::read_to_string(root.join("proc/pressure/irq"))
        .ok()
        .and_then(|t| parse_psi(&t));

    let single = |rel: &str, unavailable: &mut Vec<Unavailable>| read(root, rel, unavailable);
    let load_text = single("proc/loadavg", &mut unavailable);
    let load = parsed(load_text, "proc/loadavg", parse_loadavg, &mut unavailable);
    let mem_text = single("proc/meminfo", &mut unavailable);
    let meminfo = parsed(mem_text, "proc/meminfo", parse_meminfo, &mut unavailable);
    let vm_text = single("proc/vmstat", &mut unavailable);
    let vmstat = parsed(vm_text, "proc/vmstat", parse_vmstat, &mut unavailable);
    let fnr_text = single("proc/sys/fs/file-nr", &mut unavailable);
    let file_handles = parsed(
        fnr_text,
        "proc/sys/fs/file-nr",
        parse_file_nr,
        &mut unavailable,
    );

    PressureSnapshot {
        sampled_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        cpus,
        cpu,
        memory,
        io,
        irq,
        load,
        meminfo,
        vmstat,
        file_handles,
        unavailable,
    }
}

/// Read a pressure snapshot of this machine.
#[cfg(target_os = "linux")]
pub fn read_pressure_snapshot() -> PressureSnapshot {
    read_pressure_snapshot_from(
        Path::new("/"),
        super::cpu_capacity::observed_logical_cpus().unwrap_or(0),
    )
}

#[cfg(any(target_os = "macos", test))]
fn checked_native_loadavg(sample_count: i32, values: [f64; 3]) -> Result<LoadAvg, String> {
    if sample_count != 3 {
        return Err(format!(
            "getloadavg returned {sample_count} averages; all 3 are required"
        ));
    }
    if values
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err("getloadavg returned a non-finite or negative load average".to_string());
    }
    let [one, five, fifteen] = values;
    Ok(LoadAvg {
        one,
        five,
        fifteen,
        runnable: None,
        total: None,
    })
}

#[cfg(any(target_os = "macos", test))]
fn apply_native_loadavg(snapshot: &mut PressureSnapshot, load: Result<LoadAvg, String>) {
    // Native load replaces the unsupported Linux source, including its failure
    // report. Other unavailable pressure sensors retain their own explanations.
    snapshot
        .unavailable
        .retain(|source| source.source != "/proc/loadavg");
    snapshot.load = match load {
        Ok(load) => Some(load),
        Err(reason) => {
            snapshot.unavailable.push(Unavailable {
                source: "getloadavg".to_string(),
                reason,
            });
            None
        }
    };
    snapshot.unavailable.push(Unavailable {
        source: "load_task_counts".to_string(),
        reason: "macOS getloadavg does not report runnable or total scheduling-entity counts"
            .to_string(),
    });
}

#[cfg(any(target_os = "macos", test))]
fn native_reading<T>(
    result: Result<T, String>,
    source: &str,
    unavailable: &mut Vec<Unavailable>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(reason) => {
            unavailable.push(Unavailable {
                source: source.to_string(),
                reason,
            });
            None
        }
    }
}

/// Keep the native probe boundary injectable so recorded output and individual
/// command failures exercise the same assembly path as a live macOS scan.
#[cfg(any(target_os = "macos", test))]
fn read_macos_pressure_snapshot_with(
    mut run: impl FnMut(&str, &[&str]) -> Result<String, String>,
    load: Result<LoadAvg, String>,
) -> PressureSnapshot {
    use super::pressure_macos::{
        parse_file_handles, parse_logical_cpus, parse_memsize, parse_pressure_level,
        parse_swap_usage, parse_vm_stat,
    };

    let mut unavailable = Vec::new();
    let cpus = native_reading(
        run("/usr/sbin/sysctl", &["-n", "hw.logicalcpu"])
            .and_then(|text| parse_logical_cpus(&text)),
        "hw.logicalcpu",
        &mut unavailable,
    )
    .unwrap_or(0);
    // Read severity early: a later missing accounting source must not conceal a
    // kernel-reported critical state or turn it into a healthy observation.
    let level = native_reading(
        run(
            "/usr/sbin/sysctl",
            &["-n", "kern.memorystatus_vm_pressure_level"],
        )
        .and_then(|text| parse_pressure_level(&text)),
        "kern.memorystatus_vm_pressure_level",
        &mut unavailable,
    );
    let total = native_reading(
        run("/usr/sbin/sysctl", &["-n", "hw.memsize"]).and_then(|text| parse_memsize(&text)),
        "hw.memsize",
        &mut unavailable,
    );
    let vm = native_reading(
        run("/usr/bin/vm_stat", &[]).and_then(|text| parse_vm_stat(&text)),
        "vm_stat",
        &mut unavailable,
    );
    let swap = native_reading(
        run("/usr/sbin/sysctl", &["-n", "vm.swapusage"]).and_then(|text| parse_swap_usage(&text)),
        "vm.swapusage",
        &mut unavailable,
    );
    let file_handles = native_reading(
        run("/usr/sbin/sysctl", &["kern.num_files", "kern.maxfiles"])
            .and_then(|text| parse_file_handles(&text)),
        "kern.num_files/kern.maxfiles",
        &mut unavailable,
    );
    let macos_pressure = level.and_then(|value| match value {
        1 => Some(MacosPressureLevel::Normal),
        2 => Some(MacosPressureLevel::Warning),
        4 => Some(MacosPressureLevel::Critical),
        _ => None, // The native parser refuses unknown dispatch flags.
    });
    let mut memory = MemInfo {
        total,
        free: vm.as_ref().map(|vm| vm.free),
        cached: vm.as_ref().and_then(|vm| vm.file_backed),
        anon: vm.as_ref().and_then(|vm| vm.anonymous),
        swap_total: swap.as_ref().map(|swap| swap.total),
        swap_free: swap.as_ref().map(|swap| swap.free),
        macos_pressure,
        ..MemInfo::default()
    };
    if let Some(total) = total {
        for (name, value) in [
            ("free", &mut memory.free),
            ("file_backed", &mut memory.cached),
            ("anonymous", &mut memory.anon),
        ] {
            if value.is_some_and(|bytes| bytes > total) {
                *value = None;
                unavailable.push(Unavailable {
                    source: format!("vm_stat.{name}"),
                    reason: "observed page count exceeds hw.memsize".to_string(),
                });
            }
        }
    }
    let meminfo = (total.is_some() || vm.is_some() || swap.is_some() || macos_pressure.is_some())
        .then_some(memory);
    let vmstat = vm.as_ref().and_then(|vm| {
        (vm.swapins.is_some() || vm.swapouts.is_some()).then_some(VmStat {
            pswpin: vm.swapins,
            pswpout: vm.swapouts,
            ..VmStat::default()
        })
    });
    for source in [
        "/proc/pressure/cpu",
        "/proc/pressure/memory",
        "/proc/pressure/io",
    ] {
        unavailable.push(Unavailable {
            source: source.to_string(),
            reason: "macOS does not expose Linux Pressure Stall Information".to_string(),
        });
    }
    unavailable.push(Unavailable {
        source: "meminfo.available".to_string(),
        reason: "macOS has no Linux MemAvailable equivalent; free, inactive and compressed pages are not substituted for available RAM".to_string(),
    });
    if vm
        .as_ref()
        .is_some_and(|vm| vm.swapins.is_none() || vm.swapouts.is_none())
    {
        unavailable.push(Unavailable {
            source: "vm_stat.swap_counters".to_string(),
            reason: "vm_stat did not report both cumulative swap counters".to_string(),
        });
    }
    let mut snapshot = PressureSnapshot {
        sampled_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64),
        cpus,
        cpu: None,
        memory: None,
        io: None,
        irq: None,
        load: None,
        meminfo,
        vmstat,
        file_handles,
        unavailable,
    };
    apply_native_loadavg(&mut snapshot, load);
    snapshot
}

/// Read native macOS load, VM accounting and qualitative memory pressure.
/// Every external read has a deadline/output cap and shares a one-second budget.
#[cfg(target_os = "macos")]
pub fn read_pressure_snapshot() -> PressureSnapshot {
    use super::tool_runner::{ToolConfig, ToolRunner, ToolSpec};

    let mut values = [f64::NAN; 3];
    // SAFETY: values has space for exactly the three doubles requested, and
    // getloadavg writes only within that buffer for the duration of this call.
    let sample_count = unsafe { libc::getloadavg(values.as_mut_ptr(), 3) };
    let load = if sample_count < 0 {
        Err(format!(
            "getloadavg failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        checked_native_loadavg(sample_count, values)
    };
    let runner = ToolRunner::new(ToolConfig {
        default_timeout: Duration::from_millis(250),
        max_output_bytes: 32 * 1024,
        budget_ms: 1_000,
        use_nice: false,
        ..ToolConfig::default()
    });
    read_macos_pressure_snapshot_with(
        |program, args| {
            let spec = ToolSpec::new(program, args.iter().map(|arg| (*arg).to_string()).collect())
                .with_env("LC_ALL", "C");
            let output = runner.run(&spec).map_err(|error| error.to_string())?;
            if !output.success() {
                return Err(format!(
                    "native probe incomplete (exit {:?}, timed_out {}, truncated {})",
                    output.exit_code, output.timed_out, output.truncated
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|_| "native probe output is not UTF-8".to_string())
        },
        load,
    )
}

/// Read a pressure snapshot on other platforms. Without procfs every source
/// reports unavailable; CPU capacity is retained only when observed.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn read_pressure_snapshot() -> PressureSnapshot {
    let cpus = std::thread::available_parallelism()
        .ok()
        .and_then(|n| u32::try_from(n.get()).ok())
        .unwrap_or(0);
    read_pressure_snapshot_from(Path::new("/"), cpus)
}

/// Stall fractions (0..1) of one resource over a window, from PSI `total` counters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StallFractions {
    pub some: Option<f64>,
    pub full: Option<f64>,
}

/// Exact rates between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PressureWindow {
    pub seconds: f64,
    pub cpu: Option<StallFractions>,
    pub memory: Option<StallFractions>,
    pub io: Option<StallFractions>,
    /// Pages swapped in / out per second.
    pub swap_in_per_s: Option<f64>,
    pub swap_out_per_s: Option<f64>,
    pub major_faults_per_s: Option<f64>,
    pub direct_reclaim_scans_per_s: Option<f64>,
    pub alloc_stalls_per_s: Option<f64>,
    /// OOM kills during the window.
    pub oom_kills: Option<u64>,
}

fn counter_rate(before: Option<u64>, after: Option<u64>, seconds: f64) -> Option<f64> {
    // A counter that went backwards (reset, different machine) gives no rate.
    let delta = after?.checked_sub(before?)?;
    Some(delta as f64 / seconds)
}

fn stall_fractions(
    before: Option<PsiResource>,
    after: Option<PsiResource>,
    seconds: f64,
) -> Option<StallFractions> {
    let (before, after) = (before?, after?);
    let fraction = |b: Option<PsiLine>, a: Option<PsiLine>| {
        let delta_us = a?.total_us.checked_sub(b?.total_us)?;
        Some((delta_us as f64 / (seconds * 1e6)).clamp(0.0, 1.0))
    };
    Some(StallFractions {
        some: fraction(before.some, after.some),
        full: fraction(before.full, after.full),
    })
}

/// Rates between two snapshots of the same machine; `None` unless `after` is later.
pub fn pressure_window(
    before: &PressureSnapshot,
    after: &PressureSnapshot,
) -> Option<PressureWindow> {
    let millis = after.sampled_at_ms.checked_sub(before.sampled_at_ms)?;
    pressure_window_with_elapsed(before, after, Duration::from_millis(millis))
}

/// Rates between live snapshots using the observed monotonic interval. Wall-clock
/// adjustments must not inflate, suppress or reverse rates during a scan. Use
/// [`pressure_window`] for recorded snapshots that have only wall timestamps.
pub fn pressure_window_with_elapsed(
    before: &PressureSnapshot,
    after: &PressureSnapshot,
    elapsed: Duration,
) -> Option<PressureWindow> {
    if elapsed.is_zero() {
        return None;
    }
    let seconds = elapsed.as_secs_f64();
    let vm = |f: fn(&VmStat) -> Option<u64>| {
        counter_rate(
            before.vmstat.as_ref().and_then(f),
            after.vmstat.as_ref().and_then(f),
            seconds,
        )
    };
    Some(PressureWindow {
        seconds,
        cpu: stall_fractions(before.cpu, after.cpu, seconds),
        memory: stall_fractions(before.memory, after.memory, seconds),
        io: stall_fractions(before.io, after.io, seconds),
        swap_in_per_s: vm(|v| v.pswpin),
        swap_out_per_s: vm(|v| v.pswpout),
        major_faults_per_s: vm(|v| v.pgmajfault),
        direct_reclaim_scans_per_s: vm(|v| v.pgscan_direct),
        alloc_stalls_per_s: vm(|v| v.allocstall),
        oom_kills: before
            .vmstat
            .and_then(|v| v.oom_kill)
            .zip(after.vmstat.and_then(|v| v.oom_kill))
            .and_then(|(b, a)| a.checked_sub(b)),
    })
}

#[cfg(test)]
mod process_io_tests {
    use super::*;
    use crate::collect::ProcessState;
    use pt_common::ProcessId;

    fn process(pid: u32) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(1),
            uid: 1000,
            user: "fixture".to_string(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId::from_linux("test-boot", u64::from(pid), pid),
            comm: "worker".to_string(),
            cmd: "worker".to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: Duration::from_secs(3600),
            source: "test".to_string(),
            container_info: None,
        }
    }

    fn activity(process: &ProcessRecord, read: u64, written: u64, seconds: f64) -> ProcessActivity {
        let mut activity =
            ProcessActivity::unavailable(process, Duration::from_millis(500), "CPU unavailable");
        activity.source = PROCESS_IO_SOURCE.to_string();
        activity.io_error = None;
        activity.io_read_bytes = Some(read);
        activity.io_write_bytes = Some(written);
        activity.io_window_seconds = Some(seconds);
        activity.read_bytes_per_second = Some(read as f64 / seconds);
        activity.write_bytes_per_second = Some(written as f64 / seconds);
        activity.io_active = Some(read > 0 || written > 0);
        activity
    }

    #[test]
    fn observed_io_shares_normalize_each_actual_interval_before_summing() {
        let population = [process(10), process(20)];
        let a = activity(&population[0], 100, 100, 0.5);
        let b = activity(&population[1], 400, 400, 2.0);
        let window = process_io_window(&population, [a.clone(), b.clone()], true).unwrap();
        assert_eq!(window.read_bytes, 500);
        assert_eq!(window.write_bytes, 500);
        assert_eq!(window.read_bytes_per_second, 400.0);
        assert_eq!(window.write_bytes_per_second, 400.0);
        assert_eq!(window.min_window_seconds, 0.5);
        assert_eq!(window.max_window_seconds, 2.0);
        assert_eq!(window.share(&a), Some(0.5));
        assert_eq!(window.share(&b), Some(0.5));
        assert_eq!(window.source(), "procfs_window");
        assert_eq!(window.scope(), "observed_census_process_io");
        let reordered = process_io_window(&population, [b.clone(), a.clone()], true).unwrap();
        assert_eq!(window.share(&a), reordered.share(&a));
        assert_eq!(window.share(&b), reordered.share(&b));
        assert!(window
            .limitations
            .iter()
            .any(|text| text.contains("waited-for children")));
        assert!(window
            .limitations
            .iter()
            .any(|text| text.contains("not host device capacity")));
    }

    #[test]
    fn observed_io_denominator_retains_young_and_protected_processes() {
        let candidate = process(10);
        let mut protected = process(1);
        protected.uid = 0;
        protected.elapsed = Duration::from_secs(1);
        let a = activity(&candidate, 100, 0, 0.5);
        let b = activity(&protected, 900, 0, 0.5);
        let window = process_io_window(&[candidate, protected], [a.clone(), b], true).unwrap();
        assert_eq!(window.sampled_processes, 2);
        assert_eq!(window.share(&a), Some(0.1));
    }

    #[test]
    fn observed_io_refuses_partial_missing_extra_and_duplicate_censuses() {
        let population = [process(10), process(20)];
        let a = activity(&population[0], 100, 0, 0.5);
        let b = activity(&population[1], 900, 0, 0.5);
        assert!(process_io_window(&population, [a.clone(), b.clone()], false).is_err());
        assert!(process_io_window(&[], [], true).is_err());
        assert!(process_io_window(&population, [], true).is_err());
        assert!(process_io_window(&population, [a.clone()], true).is_err());
        assert!(process_io_window(&population[..1], [a.clone(), b.clone()], true).is_err());
        assert!(process_io_window(&population, [a.clone(), a.clone()], true).is_err());
        assert!(process_io_window(
            &[population[0].clone(), population[0].clone()],
            [a.clone(), a.clone()],
            true
        )
        .is_err());
        let mut different_request = b;
        different_request.requested_window_ms = 250;
        assert!(process_io_window(&population, [a, different_request], true).is_err());
    }

    #[test]
    fn observed_io_refuses_incomplete_invalid_and_inconsistent_measurements() {
        let process = process(10);
        let valid = activity(&process, 100, 50, 0.5);
        let invalidators: &[fn(&mut ProcessActivity)] = &[
            |a| a.pid += 1,
            |a| a.uid += 1,
            |a| a.start_id = StartId::from_linux("test-boot", 99, a.pid),
            |a| a.source = "ps_lifetime_fallback".to_string(),
            |a| a.io_error = Some("permission denied".to_string()),
            |a| a.requested_window_ms = 0,
            |a| a.io_window_seconds = None,
            |a| a.io_read_bytes = None,
            |a| a.io_write_bytes = None,
            |a| a.read_bytes_per_second = None,
            |a| a.write_bytes_per_second = None,
            |a| a.read_bytes_per_second = Some(0.0),
            |a| a.write_bytes_per_second = Some(1.0),
            |a| a.io_active = None,
            |a| a.io_active = Some(false),
        ];
        for invalidate in invalidators {
            let mut invalid = valid.clone();
            invalidate(&mut invalid);
            assert!(
                process_io_window(std::slice::from_ref(&process), [invalid.clone()], true).is_err(),
                "{invalid:?}"
            );
        }
        for value in [0.0, 0.499, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut invalid = valid.clone();
            invalid.io_window_seconds = Some(value);
            assert!(process_io_window(std::slice::from_ref(&process), [invalid], true).is_err());
        }
        for value in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for read in [true, false] {
                let mut invalid = valid.clone();
                if read {
                    invalid.read_bytes_per_second = Some(value);
                } else {
                    invalid.write_bytes_per_second = Some(value);
                }
                assert!(
                    process_io_window(std::slice::from_ref(&process), [invalid], true).is_err()
                );
            }
        }
    }

    #[test]
    fn observed_io_requires_full_identity_and_one_boot() {
        for start_id in [
            "unknown:10:10",
            "synthetic:10:10",
            ":10:10",
            "test-boot:x:10",
            "test-boot:10:11",
            "test-boot:10:10:extra",
        ] {
            let mut process = process(10);
            process.start_id = StartId(start_id.to_string());
            let sample = activity(&process, 1, 0, 0.5);
            assert!(
                process_io_window(&[process], [sample], true).is_err(),
                "{start_id}"
            );
        }
        let a = process(10);
        let mut b = process(20);
        b.start_id = StartId::from_linux("different-boot", 20, 20);
        let samples = [activity(&a, 1, 0, 0.5), activity(&b, 1, 0, 0.5)];
        assert!(process_io_window(&[a, b], samples, true).is_err());
        let mut boot_process = process(1);
        boot_process.start_id = StartId::from_linux("test-boot", 0, 1);
        let sample = activity(&boot_process, 1, 0, 0.5);
        assert!(process_io_window(&[boot_process], [sample], true).is_ok());
    }

    #[test]
    fn observed_io_share_requires_the_exact_denominator_sample() {
        let process = process(10);
        let sample = activity(&process, 100, 50, 0.5);
        let window = process_io_window(&[process], [sample.clone()], true).unwrap();
        assert_eq!(window.share(&sample), Some(1.0));
        let invalidators: &[fn(&mut ProcessActivity)] = &[
            |a| a.pid += 1,
            |a| a.uid += 1,
            |a| a.start_id = StartId::from_linux("test-boot", 999, a.pid),
            |a| a.io_read_bytes = Some(99),
            |a| a.io_write_bytes = Some(51),
            |a| a.io_window_seconds = Some(1.0),
            |a| a.requested_window_ms = 250,
            |a| a.source = "ps_lifetime_fallback".to_string(),
            |a| a.io_error = Some("process exited".to_string()),
        ];
        for invalidate in invalidators {
            let mut other_sample = sample.clone();
            invalidate(&mut other_sample);
            assert_eq!(window.share(&other_sample), None, "{other_sample:?}");
        }
        // A different interval with identical rates is still a different sample.
        let mut different_interval = sample;
        different_interval.io_window_seconds = Some(1.0);
        different_interval.io_read_bytes = Some(200);
        different_interval.io_write_bytes = Some(100);
        assert_eq!(window.share(&different_interval), None);
    }

    #[test]
    fn observed_io_idle_cohort_has_no_share_but_idle_member_can_have_zero() {
        let population = [process(10), process(20)];
        let a = activity(&population[0], 0, 0, 0.5);
        let b = activity(&population[1], 0, 0, 1.0);
        let idle = process_io_window(&population, [a.clone(), b], true).unwrap();
        assert!(idle.validate().is_ok());
        assert_eq!(idle.share(&a), None);
        let busy = activity(&population[1], 100, 0, 1.0);
        let mixed = process_io_window(&population, [a.clone(), busy.clone()], true).unwrap();
        assert_eq!(mixed.share(&a), Some(0.0));
        assert_eq!(mixed.share(&busy), Some(1.0));
    }

    #[test]
    fn observed_io_refuses_overflow_in_either_raw_counter_sum() {
        let population = [process(10), process(20)];
        for read in [true, false] {
            let a = activity(
                &population[0],
                if read { u64::MAX } else { 0 },
                if read { 0 } else { u64::MAX },
                0.5,
            );
            let b = activity(&population[1], u64::from(read), u64::from(!read), 0.5);
            assert!(process_io_window(&population, [a, b], true).is_err());
        }
    }

    #[test]
    fn observed_io_roundtrip_and_invalid_saved_summaries_fail_closed() {
        let population = [process(10), process(20)];
        let a = activity(&population[0], 4096, 2048, 0.512345678);
        let b = activity(&population[1], 8192, 0, 0.612345678);
        let window = process_io_window(&population, [a.clone(), b], true).unwrap();
        let encoded = serde_json::to_value(&window).unwrap();
        assert!(encoded.get("validation").is_none());
        let roundtrip: ProcessIoWindow = serde_json::from_value(encoded.clone()).unwrap();
        assert!(roundtrip.validate().is_ok());
        assert_eq!(window.share(&a), roundtrip.share(&a));
        for (field, value) in [
            ("source", serde_json::json!("diskstats")),
            ("scope", serde_json::json!("host_io")),
            ("census_complete", serde_json::json!(false)),
            ("sampled_processes", serde_json::json!(1)),
            ("requested_window_ms", serde_json::json!(1000)),
            ("read_bytes", serde_json::json!(0)),
            ("write_bytes", serde_json::json!(0)),
            ("read_bytes_per_second", serde_json::json!(1.0)),
            ("write_bytes_per_second", serde_json::json!(-1.0)),
            ("min_window_seconds", serde_json::json!(0.1)),
            ("max_window_seconds", serde_json::json!(2.0)),
            ("limitations", serde_json::json!([])),
            ("members", serde_json::json!({})),
        ] {
            let mut invalid = encoded.clone();
            invalid[field] = value;
            let invalid: ProcessIoWindow = serde_json::from_value(invalid).unwrap();
            assert!(invalid.validate().is_err(), "{field}");
            assert_eq!(invalid.share(&a), None, "{field}");
        }
    }
}

#[cfg(test)]
mod host_cpu_tests {
    use super::*;

    const BEFORE: &str = "cpu 100 20 30 800 20 10 10 10 7 3\n\
                         cpu0 60 10 20 390 10 5 3 2 4 2\n\
                         cpu3 40 10 10 410 10 5 7 8 3 1\n\
                         intr 1000 0 0\n";
    // Reversed, noncontiguous CPU IDs still describe the same two online CPUs.
    const AFTER: &str = "cpu 140 30 50 860 60 20 20 20 37 8\n\
                        cpu3 60 15 20 440 30 10 12 13 18 3\n\
                        cpu0 80 15 30 420 30 10 8 7 19 5\n\
                        intr 1200 0 0\n";

    #[test]
    fn host_window_uses_observed_ticks_without_double_counting_guests() {
        let before = parse_host_cpu_counters(BEFORE).unwrap();
        let after = parse_host_cpu_counters(AFTER).unwrap();
        let window = host_cpu_window(&before, &after, Duration::from_secs(1)).unwrap();
        // 200 total ticks, with 60 idle and 40 iowait. The 35 guest ticks are
        // already in user/nice and do not increase either total or busy time.
        assert_eq!(window.total_ticks, 200);
        assert_eq!(window.busy_ticks, 100);
        assert_eq!(window.logical_cpus, 2);
        assert_eq!(window.window_seconds, 1.0);
        assert_eq!(window.busy_percent(), Some(50.0));
        assert_eq!(window.process_percent(40), Some(20.0));
        assert_eq!(window.process_percent(100), Some(50.0));
        assert_eq!(window.process_percent(101), None);
        assert_eq!(window.process_percent(0), Some(0.0));
    }

    #[test]
    fn host_parser_accepts_eight_counters_without_guest_columns() {
        let bare =
            parse_host_cpu_counters("cpu 10 2 3 40 5 6 7 8\ncpu0 10 2 3 40 5 6 7 8\n").unwrap();
        let guest =
            parse_host_cpu_counters("cpu 10 2 3 40 5 6 7 8 8 1\ncpu0 10 2 3 40 5 6 7 8 8 1\n")
                .unwrap();
        assert_eq!(bare, guest);
    }

    #[test]
    fn host_parser_refuses_incomplete_duplicate_and_invalid_cpu_rows() {
        let row = "1 2 3 4 5 6 7 8";
        let cpu = format!("cpu {row}\n");
        let cpu0 = format!("cpu0 {row}\n");
        for invalid in [
            String::new(),
            cpu0.clone(),
            cpu.clone(),
            format!("{cpu}{cpu}{cpu0}"),
            format!("{cpu}{cpu0}{cpu0}"),
            format!("{cpu}cpu0 1 2 3 4 5 6 7\n"),
            format!("cpu 1 2 3 4 5 6 7\n{cpu0}"),
            format!("cpu +1 2 3 4 5 6 7 8\n{cpu0}"),
            format!("cpu 1 2 3 -4 5 6 7 8\n{cpu0}"),
            format!("cpu 1 2 3 4 5 6 7 8 broken\n{cpu0}"),
            format!("{cpu}cpuwrong {row}\n"),
            format!("{cpu}cpu4294967296 {row}\n"),
            format!("cpu 18446744073709551616 0 0 0 0 0 0 0\n{cpu0}"),
            format!("cpu {} 1 0 0 0 0 0 0\n{cpu0}", u64::MAX),
        ] {
            assert!(parse_host_cpu_counters(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn host_window_refuses_each_counter_reset_even_when_other_counters_advance() {
        let before = parse_host_cpu_counters(BEFORE).unwrap();
        for (index, field) in HOST_CPU_FIELDS.iter().enumerate() {
            let mut after = parse_host_cpu_counters(AFTER).unwrap();
            after.ticks[index] = before.ticks[index] - 1;
            let error = host_cpu_window(&before, &after, Duration::from_secs(1)).unwrap_err();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn host_window_refuses_zero_observation_and_changed_cpu_identity_sets() {
        let before = parse_host_cpu_counters(BEFORE).unwrap();
        let after = parse_host_cpu_counters(AFTER).unwrap();
        assert!(host_cpu_window(&before, &after, Duration::ZERO).is_err());
        assert!(host_cpu_window(&before, &before, Duration::from_secs(1)).is_err());
        for cpu_ids in [
            BTreeSet::from([0, 7]),
            BTreeSet::from([0]),
            BTreeSet::from([0, 3, 7]),
        ] {
            let changed = HostCpuCounters {
                cpu_ids,
                ..after.clone()
            };
            assert!(host_cpu_window(&before, &changed, Duration::from_secs(1)).is_err());
        }
        let short = host_cpu_window(&before, &after, Duration::from_nanos(1)).unwrap();
        assert_eq!(short.window_seconds, 1e-9);
        assert_eq!(short.busy_percent(), Some(50.0));
    }

    #[test]
    fn host_percentages_refuse_invalid_window_fields() {
        let valid = HostCpuWindow {
            total_ticks: 200,
            busy_ticks: 100,
            logical_cpus: 2,
            window_seconds: 0.5,
        };
        for invalid in [
            HostCpuWindow {
                total_ticks: 0,
                ..valid
            },
            HostCpuWindow {
                busy_ticks: 201,
                ..valid
            },
            HostCpuWindow {
                logical_cpus: 0,
                ..valid
            },
        ] {
            assert_eq!(invalid.busy_percent(), None);
            assert_eq!(invalid.process_percent(0), None);
        }
        for window_seconds in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let invalid = HostCpuWindow {
                window_seconds,
                ..valid
            };
            assert_eq!(invalid.busy_percent(), None);
            assert_eq!(invalid.process_percent(0), None);
        }
        let idle = HostCpuWindow {
            busy_ticks: 0,
            ..valid
        };
        assert_eq!(idle.busy_percent(), Some(0.0));
        assert_eq!(idle.process_percent(0), Some(0.0));
        assert_eq!(idle.process_percent(1), None);
        let large = HostCpuWindow {
            total_ticks: u64::MAX,
            busy_ticks: u64::MAX - 1,
            ..valid
        };
        assert!(large.busy_percent().unwrap().is_finite());
        assert_eq!(large.process_percent(u64::MAX), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_cpu_live_reader_keeps_real_observations_and_io_errors() {
        let live = read_host_cpu_counters().expect("live /proc/stat is readable");
        assert!(!live.cpu_ids.is_empty());
        assert!(live.ticks.iter().any(|ticks| *ticks > 0));
        let error = read_host_cpu_counters_from(Path::new("/dev/null")).unwrap_err();
        assert!(error.contains("/dev/null/proc/stat"), "{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSI_CPU: &str = "some avg10=57.18 avg60=58.76 avg300=54.02 total=39231816941\n\
                           full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    const MEMINFO: &str = "MemTotal:       32000000 kB\nMemFree:         1000000 kB\n\
                           MemAvailable:    8000000 kB\nCached:         20000000 kB\n\
                           Slab:            7000000 kB\nSReclaimable:    6000000 kB\n\
                           SUnreclaim:      1000000 kB\nSwapTotal:      16000000 kB\n\
                           SwapFree:       15000000 kB\nDirty:              1234 kB\n";

    #[test]
    fn parses_psi_some_and_full() {
        let psi = parse_psi(PSI_CPU).expect("psi");
        let some = psi.some.expect("some");
        assert_eq!(some.avg10, 57.18);
        assert_eq!(some.avg300, 54.02);
        assert_eq!(some.total_us, 39_231_816_941);
        assert_eq!(psi.full.expect("full").total_us, 0);
        // Older kernels have no `full` line for CPU.
        let some_only = parse_psi("some avg10=1.00 avg60=2.00 avg300=3.00 total=42\n").unwrap();
        assert!(some_only.full.is_none());
        assert!(parse_psi("garbage\n").is_none());
        assert!(parse_psi("some avg10=x avg60=1 avg300=1 total=1\n").is_none());
    }

    #[test]
    fn pressure_parsers_reject_invalid_averages_without_inventing_zero() {
        for index in 0..3 {
            for invalid in ["NaN", "inf", "-inf", "-0.01", "100.01", "1e999"] {
                let mut values = ["0.0", "1.0", "100.0"];
                values[index] = invalid;
                let line = format!(
                    "some avg10={} avg60={} avg300={} total=1\n",
                    values[0], values[1], values[2]
                );
                assert!(parse_psi(&line).is_none(), "{line}");
                // A valid full line cannot conceal a malformed some line.
                let mixed = format!("{line}full avg10=0 avg60=0 avg300=0 total=0\n");
                assert!(parse_psi(&mixed).is_none(), "{mixed}");
            }
            for invalid in ["NaN", "inf", "-inf", "-0.01", "1e999"] {
                let mut values = ["0.0", "1.0", "1000.0"];
                values[index] = invalid;
                let line = format!("{} {} {} 1/100 42\n", values[0], values[1], values[2]);
                assert!(parse_loadavg(&line).is_none(), "{line}");
            }
        }
        let endpoints = parse_psi("some avg10=0 avg60=100 avg300=0 total=0\n").unwrap();
        assert!(endpoints.some.unwrap().is_valid());
        for duplicate in ["avg10=NaN", "avg10=0", "avg60=0", "avg300=0", "total=0"] {
            let line = format!("some avg10=0 avg60=0 avg300=0 total=0 {duplicate}\n");
            assert!(parse_psi(&line).is_none(), "{line}");
        }
        assert!(parse_psi("some avg10=NaN avg10=0 avg60=0 avg300=0 total=0\n").is_none());
        assert!(parse_psi(&format!("{PSI_CPU}{PSI_CPU}")).is_none());
        assert!(parse_psi(&format!(
            "{PSI_CPU}full avg10=NaN avg60=0 avg300=0 total=0\n"
        ))
        .is_none());
        assert!(parse_loadavg("0 1 1000 1/100 42\n").is_some());
        assert!(parse_loadavg("0 0 0 0/0 42\n").is_none());
        assert!(parse_loadavg("0 0 0 2/1 42\n").is_none());
    }

    #[test]
    fn meminfo_rejects_impossible_counts_units_and_overflow() {
        for text in [
            "MemTotal: 0 kB\n",
            "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
            "MemTotal: 1 kB\nMemFree: 2 kB\n",
            "MemTotal: 4 kB\nSwapTotal: 1 kB\nSwapFree: 2 kB\n",
            "MemTotal: 4 kB\nSwapTotal: 0 kB\nSwapFree: 1 kB\n",
            "MemTotal: 18446744073709551615 kB\n",
            "MemTotal: 4 kB\nMemAvailable: 18446744073709551615 kB\n",
            "MemTotal: 4 MB\n",
            "MemTotal: 4 kB\nMemAvailable: invalid kB\n",
            "MemTotal: 4 kB\nMemAvailable: 2\n",
            "MemTotal: 4 kB\nMemTotal: 4 kB\n",
        ] {
            assert!(parse_meminfo(text).is_none(), "{text}");
        }
        // Optional counters remain unknown, and overcommit is not physical usage.
        let memory = parse_meminfo(
            "MemTotal: 4 kB\nCommitted_AS: 10 kB\nCommitLimit: 8 kB\nHugePages_Total: 0\n",
        )
        .unwrap();
        assert_eq!(memory.used_fraction(), None);
        assert_eq!(memory.swap_used(), None);
        assert_eq!(memory.committed_as, Some(10 * 1024));
        let zero =
            parse_meminfo("MemTotal: 4 kB\nMemAvailable: 4 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
                .unwrap();
        assert_eq!(zero.used_fraction(), Some(0.0));
        assert_eq!(zero.swap_used(), Some(0));
    }

    #[test]
    fn deserialized_memory_accounting_cannot_saturate_into_healthy_values() {
        let impossible = MemInfo {
            total: Some(4),
            available: Some(5),
            swap_total: Some(2),
            swap_free: Some(3),
            ..MemInfo::default()
        };
        let restored: MemInfo =
            serde_json::from_value(serde_json::to_value(impossible).unwrap()).unwrap();
        assert_eq!(restored.used_fraction(), None);
        assert_eq!(restored.swap_used(), None);
        let large = MemInfo {
            total: Some(u64::MAX),
            available: Some(u64::MAX - 1),
            swap_total: Some(u64::MAX),
            swap_free: Some(u64::MAX - 1),
            ..MemInfo::default()
        };
        assert!(large.used_fraction().unwrap() > 0.0);
        assert_eq!(large.swap_used(), Some(1));
    }

    #[test]
    fn parses_loadavg_meminfo_vmstat_file_nr() {
        let load = parse_loadavg("4.71 2.61 1.19 3/811 290046\n").unwrap();
        assert_eq!(
            (load.one, load.runnable, load.total),
            (4.71, Some(3), Some(811))
        );
        // Existing Linux snapshots retain numeric task counts on the wire.
        let json = serde_json::to_value(load).unwrap();
        assert_eq!(json["runnable"], 3);
        assert_eq!(json["total"], 811);
        assert_eq!(serde_json::from_value::<LoadAvg>(json).unwrap(), load);
        assert!(parse_loadavg("1.0 2.0\n").is_none());

        let mem = parse_meminfo(MEMINFO).unwrap();
        assert_eq!(mem.total, Some(32_000_000 * 1024));
        assert_eq!(mem.swap_used(), Some(1_000_000 * 1024));
        assert!((mem.used_fraction().unwrap() - 0.75).abs() < 1e-9);
        assert_eq!(mem.slab_reclaimable, Some(6_000_000 * 1024));
        assert!(mem.committed_as.is_none());
        assert!(
            parse_meminfo("MemFree: 1 kB\n").is_none(),
            "MemTotal required"
        );

        let vm = parse_vmstat(
            "pswpin 10\npswpout 20\npgmajfault 300\nallocstall_dma32 4\nallocstall_normal 5\n\
             compact_stall 6\noom_kill 1\npgscan_direct 77\n",
        )
        .unwrap();
        assert_eq!(vm.allocstall, Some(9));
        assert_eq!(vm.oom_kill, Some(1));
        assert_eq!(vm.pgscan_direct, Some(77));

        let fnr = parse_file_nr("12345\t0\t9223372036854775807\n").unwrap();
        assert_eq!(fnr.allocated, 12345);
        assert!(fnr.used_fraction().unwrap() < 1e-9);
    }

    fn fake_root(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    #[test]
    fn host_cpu_window_round_trip_retains_capacity_and_validation() {
        let window = HostCpuWindow {
            total_ticks: 200,
            busy_ticks: 100,
            logical_cpus: 2,
            window_seconds: 1.0,
        };
        let mut json = serde_json::to_value(window).unwrap();
        assert_eq!(json["total_ticks"], 200);
        assert_eq!(json["busy_ticks"], 100);
        assert_eq!(json["logical_cpus"], 2);
        assert_eq!(json["window_seconds"], 1.0);
        assert_eq!(
            serde_json::from_value::<HostCpuWindow>(json.clone()).unwrap(),
            window
        );
        json["busy_ticks"] = serde_json::json!(201);
        let invalid = serde_json::from_value::<HostCpuWindow>(json).unwrap();
        assert_eq!(invalid.busy_percent(), None);
        assert_eq!(invalid.process_percent(1), None);
    }

    #[test]
    fn host_cpu_root_reader_reports_missing_and_malformed_accounting() {
        let text = "cpu 10 2 3 40 5 6 7 8\ncpu0 10 2 3 40 5 6 7 8\n";
        let root = fake_root(&[("proc/stat", text)]);
        assert_eq!(
            read_host_cpu_counters_from(root.path()).unwrap(),
            parse_host_cpu_counters(text).unwrap()
        );
        let missing = fake_root(&[]);
        let error = read_host_cpu_counters_from(missing.path()).unwrap_err();
        assert!(error.contains("proc/stat"), "{error}");
        let malformed = fake_root(&[("proc/stat", "cpu 1 2\n")]);
        let error = read_host_cpu_counters_from(malformed.path()).unwrap_err();
        assert!(
            error.contains("proc/stat") && error.contains("missing system"),
            "{error}"
        );
    }

    #[test]
    fn native_loadavg_requires_complete_finite_nonnegative_readings() {
        let values = [0.0, 1.5, 2.25];
        let load = checked_native_loadavg(3, values).unwrap();
        assert_eq!([load.one, load.five, load.fifteen], values);
        assert_eq!(load.runnable, None);
        assert_eq!(load.total, None);
        let json = serde_json::to_value(load).unwrap();
        assert!(json["runnable"].is_null());
        assert!(json["total"].is_null());
        assert_eq!(serde_json::from_value::<LoadAvg>(json).unwrap(), load);

        for received in [-1, 0, 1, 2, 4] {
            assert!(checked_native_loadavg(received, values).is_err());
        }
        for index in 0..3 {
            for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1] {
                let mut invalid_values = values;
                invalid_values[index] = invalid;
                assert!(checked_native_loadavg(3, invalid_values).is_err());
            }
        }
    }

    #[test]
    fn native_loadavg_reports_its_own_availability_without_inventing_task_counts() {
        let root = fake_root(&[]);
        let missing = read_pressure_snapshot_from(root.path(), 8);
        let mut observed = missing.clone();
        apply_native_loadavg(&mut observed, checked_native_loadavg(3, [2.0, 1.0, 0.5]));
        assert_eq!(observed.load_ratio(), Some(0.25));
        let load = observed.load.unwrap();
        assert_eq!(load.runnable, None);
        assert_eq!(load.total, None);
        assert!(!observed
            .unavailable
            .iter()
            .any(|source| source.source == "/proc/loadavg" || source.source == "getloadavg"));
        assert!(observed
            .unavailable
            .iter()
            .any(|source| source.source == "load_task_counts"));
        assert!(observed.meminfo.is_none());
        assert!(observed
            .unavailable
            .iter()
            .any(|source| source.source == "/proc/meminfo"));

        let mut failed = missing;
        apply_native_loadavg(&mut failed, checked_native_loadavg(2, [2.0, 1.0, f64::NAN]));
        assert!(failed.load.is_none());
        assert!(failed.load_ratio().is_none());
        assert!(!failed
            .unavailable
            .iter()
            .any(|source| source.source == "/proc/loadavg"));
        assert!(failed
            .unavailable
            .iter()
            .any(|source| source.source == "getloadavg" && source.reason.contains("all 3")));
    }

    fn macos_probe_fixture(program: &str, args: &[&str]) -> Result<String, String> {
        let output = match (program, args) {
            ("/usr/sbin/sysctl", ["-n", "hw.logicalcpu"]) => "8\n",
            ("/usr/sbin/sysctl", ["-n", "hw.memsize"]) => "17179869184\n",
            ("/usr/sbin/sysctl", ["-n", "kern.memorystatus_vm_pressure_level"]) => "4\n",
            ("/usr/sbin/sysctl", ["kern.num_files", "kern.maxfiles"]) => {
                "kern.num_files: 96000\nkern.maxfiles: 100000\n"
            }
            ("/usr/sbin/sysctl", ["-n", "vm.swapusage"]) => {
                "total = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)\n"
            }
            ("/usr/bin/vm_stat", []) => {
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
                 Pages free: 100.\nPages speculative: 20.\nPages inactive: 500000.\n\
                 Pages purgeable: 400000.\nFile-backed pages: 300.\n\
                 Anonymous pages: 400.\nSwapins: 10.\nSwapouts: 25.\n"
            }
            _ => return Err(format!("unexpected native probe: {program} {args:?}")),
        };
        Ok(output.to_string())
    }

    #[test]
    fn macos_snapshot_preserves_native_accounting_without_inventing_availability() {
        let snapshot = read_macos_pressure_snapshot_with(
            macos_probe_fixture,
            checked_native_loadavg(3, [2.0, 1.0, 0.5]),
        );
        assert_eq!(snapshot.cpus, 8);
        assert_eq!(
            snapshot.file_handles,
            Some(FileHandles {
                allocated: 96_000,
                max: 100_000
            })
        );
        assert_eq!(snapshot.load_ratio(), Some(0.25));
        let memory = snapshot.meminfo.unwrap();
        assert_eq!(memory.total, Some(16 * 1024 * 1024 * 1024));
        assert_eq!(memory.free, Some(120 * 16384));
        assert_eq!(memory.cached, Some(300 * 16384));
        assert_eq!(memory.anon, Some(400 * 16384));
        assert_eq!(memory.available, None);
        assert_eq!(memory.used_fraction(), None);
        assert_eq!(memory.swap_used(), Some(512 * 1024 * 1024));
        assert_eq!(memory.macos_pressure, Some(MacosPressureLevel::Critical));
        let vm = snapshot.vmstat.unwrap();
        assert_eq!(vm.pswpin, Some(10));
        assert_eq!(vm.pswpout, Some(25));
        assert_eq!(vm.pgmajfault, None);
        assert_eq!(vm.oom_kill, None);
        assert_eq!(snapshot.memory, None);
        assert!(snapshot
            .unavailable
            .iter()
            .any(|entry| entry.source == "meminfo.available"));
        assert!(!snapshot
            .unavailable
            .iter()
            .any(|entry| { matches!(entry.source.as_str(), "/proc/meminfo" | "/proc/vmstat") }));
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["meminfo"]["macos_pressure"], "critical");
        assert_eq!(
            serde_json::from_value::<PressureSnapshot>(json).unwrap(),
            snapshot
        );

        let legacy = serde_json::to_value(MemInfo::default()).unwrap();
        assert!(legacy.get("macos_pressure").is_none());
        assert_eq!(
            serde_json::from_value::<MemInfo>(legacy)
                .unwrap()
                .macos_pressure,
            None
        );
    }

    #[test]
    fn macos_file_pressure_requires_both_native_counts() {
        use crate::decision::pressure_regime::{assess, PressureThresholds, RegimeKind, Severity};

        for (output, expected) in [
            ("kern.num_files: 0\nkern.maxfiles: 100\n", Some(None)),
            (
                "kern.num_files: 80\nkern.maxfiles: 100\n",
                Some(Some(Severity::Warn)),
            ),
            (
                "kern.num_files: 101\nkern.maxfiles: 100\n",
                Some(Some(Severity::Crit)),
            ),
            ("kern.num_files: 80\n", None),
            ("kern.num_files: 10\nkern.maxfiles: 0\n", None),
            ("kern.num_files: 10\nkern.maxfilesperproc: 100\n", None),
            ("kern.num_files: -1\nkern.maxfiles: 100\n", None),
            ("kern.num_files: 10\nkern.maxfiles: 2147483648\n", None),
            (
                "kern.num_files: 10\nkern.maxfiles: 100\nkern.num_files: 0\n",
                None,
            ),
        ] {
            let snapshot = read_macos_pressure_snapshot_with(
                |program, args| {
                    if args == ["kern.num_files", "kern.maxfiles"] {
                        Ok(output.to_string())
                    } else {
                        macos_probe_fixture(program, args)
                    }
                },
                checked_native_loadavg(3, [0.0; 3]),
            );
            assert_eq!(
                snapshot.file_handles.is_some(),
                expected.is_some(),
                "{output}"
            );
            assert_eq!(
                snapshot
                    .unavailable
                    .iter()
                    .any(|e| e.source == "kern.num_files/kern.maxfiles"),
                expected.is_none(),
                "{output}"
            );
            let assessment = assess(&snapshot, None, None, &PressureThresholds::default());
            let fd = assessment
                .regimes
                .iter()
                .find(|r| r.kind == RegimeKind::FdExhaustion);
            assert_eq!(fd.map(|r| r.severity), expected.flatten(), "{output}");
            assert_eq!(
                snapshot.meminfo.unwrap().macos_pressure,
                Some(MacosPressureLevel::Critical)
            );
        }
    }

    #[test]
    fn macos_snapshot_retains_independent_evidence_after_probe_failure() {
        for failed in [
            "hw.logicalcpu",
            "hw.memsize",
            "vm_stat",
            "vm.swapusage",
            "kern.memorystatus_vm_pressure_level",
        ] {
            let snapshot = read_macos_pressure_snapshot_with(
                |program, args| {
                    let source = args.last().copied().unwrap_or("vm_stat");
                    if source == failed {
                        Err("native probe timed out".to_string())
                    } else {
                        macos_probe_fixture(program, args)
                    }
                },
                checked_native_loadavg(3, [2.0, 1.0, 0.5]),
            );
            assert!(snapshot
                .unavailable
                .iter()
                .any(|entry| { entry.source == failed && entry.reason.contains("timed out") }));
            let memory = snapshot.meminfo.unwrap();
            assert_eq!(
                memory.macos_pressure,
                (failed != "kern.memorystatus_vm_pressure_level")
                    .then_some(MacosPressureLevel::Critical)
            );
            match failed {
                "hw.logicalcpu" => assert_eq!(snapshot.load_ratio(), None),
                "hw.memsize" => assert_eq!(memory.total, None),
                "vm_stat" => {
                    assert_eq!(memory.free, None);
                    assert_eq!(snapshot.vmstat, None);
                }
                "vm.swapusage" => assert_eq!(memory.swap_used(), None),
                _ => {}
            }
        }
        let missing = read_macos_pressure_snapshot_with(
            |_, _| Err("budget exhausted".to_string()),
            Err("getloadavg failed".to_string()),
        );
        assert_eq!(missing.cpus, 0);
        assert!(missing.load.is_none() && missing.meminfo.is_none() && missing.vmstat.is_none());
    }

    #[test]
    fn macos_snapshot_rejects_impossible_ram_counts_without_hiding_pressure() {
        let snapshot = read_macos_pressure_snapshot_with(
            |program, args| {
                if args.last() == Some(&"hw.memsize") {
                    Ok("1\n".to_string())
                } else {
                    macos_probe_fixture(program, args)
                }
            },
            checked_native_loadavg(3, [2.0, 1.0, 0.5]),
        );
        let memory = snapshot.meminfo.unwrap();
        assert_eq!(
            (memory.free, memory.cached, memory.anon),
            (None, None, None)
        );
        assert_eq!(memory.macos_pressure, Some(MacosPressureLevel::Critical));
        assert_eq!(
            snapshot
                .unavailable
                .iter()
                .filter(|entry| entry.reason.contains("exceeds hw.memsize"))
                .count(),
            3
        );
    }

    #[test]
    fn missing_sources_are_unavailable_never_zero() {
        // A kernel without PSI: pressure is unknown, not 0.
        let root = fake_root(&[
            ("proc/loadavg", "0.10 0.20 0.30 1/100 42\n"),
            ("proc/meminfo", MEMINFO),
        ]);
        let snap = read_pressure_snapshot_from(root.path(), 8);
        assert!(snap.cpu.is_none() && snap.memory.is_none() && snap.io.is_none());
        let sources: Vec<&str> = snap.unavailable.iter().map(|u| u.source.as_str()).collect();
        assert!(sources.contains(&"/proc/pressure/cpu"), "{sources:?}");
        assert!(sources.contains(&"/proc/vmstat"), "{sources:?}");
        assert!(
            !sources.contains(&"/proc/pressure/irq"),
            "irq absence is normal"
        );
        assert!((snap.load_ratio().unwrap() - 0.1 / 8.0).abs() < 1e-12);

        // A valid load reading cannot imply one CPU when capacity is unknown.
        let unknown_capacity = read_pressure_snapshot_from(root.path(), 0);
        assert_eq!(unknown_capacity.load.unwrap().one, 0.1);
        assert_eq!(unknown_capacity.cpus, 0);
        assert_eq!(unknown_capacity.load_ratio(), None);
        assert!(unknown_capacity
            .unavailable
            .iter()
            .any(|source| source.source == "online_cpu_count"));

        // An unparseable file is reported, not silently dropped.
        let root = fake_root(&[("proc/loadavg", "nonsense\n")]);
        let snap = read_pressure_snapshot_from(root.path(), 8);
        assert!(snap
            .unavailable
            .iter()
            .any(|u| u.source == "/proc/loadavg" && u.reason == "unrecognized format"));
    }

    #[test]
    fn invalid_pressure_sources_report_unavailable_and_keep_valid_sources() {
        let root = fake_root(&[
            (
                "proc/pressure/cpu",
                "some avg10=NaN avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
            ),
            ("proc/pressure/memory", PSI_CPU),
            ("proc/loadavg", "-1 0 0 1/100 42\n"),
            ("proc/meminfo", "MemTotal: 4 kB\nMemAvailable: 5 kB\n"),
        ]);
        let mut snapshot = read_pressure_snapshot_from(root.path(), 8);
        assert_eq!(snapshot.cpu, None);
        assert_eq!(snapshot.load, None);
        assert_eq!(snapshot.meminfo, None);
        assert_eq!(snapshot.load_ratio(), None);
        assert_eq!(snapshot.memory, parse_psi(PSI_CPU));
        for source in ["/proc/pressure/cpu", "/proc/loadavg", "/proc/meminfo"] {
            assert!(snapshot
                .unavailable
                .iter()
                .any(|entry| entry.source == source && entry.reason == "unrecognized format"));
        }
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json["cpu"].is_null());
        assert!(json["load"].is_null());
        assert!(json["meminfo"].is_null());

        // Directly supplied snapshots must obey the same load-ratio contract.
        let valid = parse_loadavg("0 1 2 1/100 42\n").unwrap();
        snapshot.load = Some(valid);
        assert_eq!(snapshot.load_ratio(), Some(0.0));
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1] {
            for index in 0..3 {
                let mut load = valid;
                match index {
                    0 => load.one = value,
                    1 => load.five = value,
                    _ => load.fifteen = value,
                }
                snapshot.load = Some(load);
                assert_eq!(snapshot.load_ratio(), None);
            }
        }
    }

    #[test]
    fn window_turns_counters_into_exact_fractions_and_rates() {
        let psi = |total: u64| PsiResource {
            some: Some(PsiLine {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total_us: total,
            }),
            full: None,
        };
        let snap = |ms: u64, cpu_total: u64, pswpin: u64, oom: u64| PressureSnapshot {
            sampled_at_ms: ms,
            cpus: 8,
            cpu: Some(psi(cpu_total)),
            memory: None,
            io: None,
            irq: None,
            load: None,
            meminfo: None,
            vmstat: Some(VmStat {
                pswpin: Some(pswpin),
                oom_kill: Some(oom),
                ..VmStat::default()
            }),
            file_handles: None,
            unavailable: Vec::new(),
        };
        // 2 s window, 600 ms of CPU stall: 30 %.
        let before = snap(10_000, 1_000_000, 100, 3);
        let after = snap(12_000, 1_600_000, 500, 4);
        let window = pressure_window(&before, &after).unwrap();
        assert_eq!(window.seconds, 2.0);
        let cpu = window.cpu.unwrap();
        assert!((cpu.some.unwrap() - 0.3).abs() < 1e-12);
        assert!(cpu.full.is_none());
        assert!(
            window.memory.is_none(),
            "missing on both sides stays missing"
        );
        assert_eq!(window.swap_in_per_s, Some(200.0));
        assert_eq!(window.oom_kills, Some(1));

        // Not later, or counters going backwards: no rates.
        assert!(pressure_window(&after, &before).is_none());
        let reset = snap(14_000, 10, 0, 0);
        let window = pressure_window(&after, &reset).unwrap();
        assert!(window.cpu.unwrap().some.is_none());
        assert!(window.swap_in_per_s.is_none());
    }

    #[test]
    fn live_window_uses_elapsed_time_despite_wall_clock_adjustments() {
        let before_root = fake_root(&[
            (
                "proc/pressure/cpu",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n",
            ),
            ("proc/vmstat", "pswpin 100\npswpout 200\noom_kill 3\n"),
        ]);
        let after_root = fake_root(&[
            (
                "proc/pressure/cpu",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=1600000\n",
            ),
            ("proc/vmstat", "pswpin 500\npswpout 300\noom_kill 4\n"),
        ]);
        let mut before = read_pressure_snapshot_from(before_root.path(), 8);
        let mut after = read_pressure_snapshot_from(after_root.path(), 8);
        before.sampled_at_ms = 10_000;
        for wall_time in [1, 10_000, 1_000_000] {
            after.sampled_at_ms = wall_time;
            let window = pressure_window_with_elapsed(&before, &after, Duration::from_secs(2))
                .expect("monotonic observation does not depend on the wall clock");
            assert_eq!(window.seconds, 2.0);
            assert_eq!(window.cpu.unwrap().some, Some(0.3));
            assert_eq!(window.swap_in_per_s, Some(200.0));
            assert_eq!(window.swap_out_per_s, Some(50.0));
            assert_eq!(window.oom_kills, Some(1));
            assert!(window.memory.is_none());
            assert!(window.major_faults_per_s.is_none());
        }
        assert!(pressure_window_with_elapsed(&before, &after, Duration::ZERO).is_none());

        // Keep real sub-millisecond precision rather than a nominal delay.
        let mut short_after = before.clone();
        short_after
            .cpu
            .as_mut()
            .unwrap()
            .some
            .as_mut()
            .unwrap()
            .total_us += 250;
        let short = pressure_window_with_elapsed(&before, &short_after, Duration::from_micros(500))
            .unwrap();
        assert_eq!(short.seconds, 0.0005);
        assert_eq!(short.cpu.unwrap().some, Some(0.5));
    }

    #[test]
    fn live_window_preserves_missing_and_reset_counters() {
        let before_root = fake_root(&[
            (
                "proc/pressure/cpu",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n",
            ),
            ("proc/vmstat", "pswpin 100\npswpout 200\noom_kill 3\n"),
        ]);
        let after_root = fake_root(&[
            (
                "proc/pressure/cpu",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n",
            ),
            ("proc/vmstat", "pswpin 0\noom_kill 0\n"),
        ]);
        let before = read_pressure_snapshot_from(before_root.path(), 8);
        let after = read_pressure_snapshot_from(after_root.path(), 8);
        let window = pressure_window_with_elapsed(&before, &after, Duration::from_secs(1)).unwrap();
        assert_eq!(window.cpu.unwrap().some, None);
        assert_eq!(window.cpu.unwrap().full, None);
        assert_eq!(window.memory, None);
        assert_eq!(window.swap_in_per_s, None);
        assert_eq!(window.swap_out_per_s, None);
        assert_eq!(window.oom_kills, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_snapshot_is_plausible() {
        let snap = read_pressure_snapshot();
        assert!(snap.cpus >= 1);
        let load = snap.load.expect("/proc/loadavg is always readable");
        assert!(load.one >= 0.0 && load.total.is_some_and(|total| total >= 1));
        let mem = snap.meminfo.expect("/proc/meminfo is always readable");
        assert!(mem.total.unwrap() > 0);
        if let Some(cpu) = snap.cpu {
            let some = cpu.some.expect("PSI cpu has a some line");
            assert!((0.0..=100.0).contains(&some.avg10));
        } else {
            assert!(snap
                .unavailable
                .iter()
                .any(|u| u.source == "/proc/pressure/cpu"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_live_load_snapshot_is_plausible() {
        let snapshot = read_pressure_snapshot();
        assert!(snapshot.cpus > 0);
        let load = snapshot
            .load
            .expect("native macOS load average is readable");
        assert!([load.one, load.five, load.fifteen]
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0));
        assert_eq!(load.runnable, None);
        assert_eq!(load.total, None);
        assert!(!snapshot
            .unavailable
            .iter()
            .any(|source| source.source == "getloadavg" || source.source == "/proc/loadavg"));
        assert!(snapshot
            .unavailable
            .iter()
            .any(|source| source.source == "load_task_counts"));
    }
}
