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

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
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

/// One PSI line (`some` or `full`): running averages in percent and the cumulative
/// stall time in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
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
        Some(self.swap_total?.saturating_sub(self.swap_free?))
    }

    /// Fraction of RAM not available for new allocations without reclaim.
    pub fn used_fraction(&self) -> Option<f64> {
        let total = self.total.filter(|t| *t > 0)? as f64;
        Some((1.0 - self.available? as f64 / total).clamp(0.0, 1.0))
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

/// `/proc/sys/fs/file-nr`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FileHandles {
    pub allocated: u64,
    pub max: u64,
}

impl FileHandles {
    pub fn used_fraction(&self) -> Option<f64> {
        (self.max > 0).then(|| self.allocated as f64 / self.max as f64)
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
        (self.cpus > 0).then(|| load.one / f64::from(self.cpus))
    }
}

/// Parse one PSI file. Returns `None` when neither line parses.
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
        let (mut avg10, mut avg60, mut avg300, mut total) = (None, None, None, None);
        for field in parts {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "avg10" => avg10 = value.parse::<f64>().ok(),
                "avg60" => avg60 = value.parse::<f64>().ok(),
                "avg300" => avg300 = value.parse::<f64>().ok(),
                "total" => total = value.parse::<u64>().ok(),
                _ => {}
            }
        }
        if let (Some(avg10), Some(avg60), Some(avg300), Some(total_us)) =
            (avg10, avg60, avg300, total)
        {
            *slot = Some(PsiLine {
                avg10,
                avg60,
                avg300,
                total_us,
            });
        }
    }
    (some.is_some() || full.is_some()).then_some(PsiResource { some, full })
}

/// Parse `/proc/loadavg` (`0.52 0.58 0.59 3/811 12345`).
pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut parts = text.split_whitespace();
    let one = parts.next()?.parse().ok()?;
    let five = parts.next()?.parse().ok()?;
    let fifteen = parts.next()?.parse().ok()?;
    let (runnable, total) = parts.next()?.split_once('/')?;
    Some(LoadAvg {
        one,
        five,
        fifteen,
        runnable: Some(runnable.parse().ok()?),
        total: Some(total.parse().ok()?),
    })
}

/// Parse `/proc/meminfo` (values in kB) into bytes. `None` if MemTotal is missing.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut info = MemInfo::default();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(kb) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        let bytes = Some(kb.saturating_mul(1024));
        match key.trim() {
            "MemTotal" => info.total = bytes,
            "MemFree" => info.free = bytes,
            "MemAvailable" => info.available = bytes,
            "Buffers" => info.buffers = bytes,
            "Cached" => info.cached = bytes,
            "SwapCached" => info.swap_cached = bytes,
            "AnonPages" => info.anon = bytes,
            "Shmem" => info.shmem = bytes,
            "Slab" => info.slab = bytes,
            "SReclaimable" => info.slab_reclaimable = bytes,
            "SUnreclaim" => info.slab_unreclaimable = bytes,
            "Dirty" => info.dirty = bytes,
            "Writeback" => info.writeback = bytes,
            "SwapTotal" => info.swap_total = bytes,
            "SwapFree" => info.swap_free = bytes,
            "Committed_AS" => info.committed_as = bytes,
            "CommitLimit" => info.commit_limit = bytes,
            _ => {}
        }
    }
    info.total.map(|_| info)
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
        parse_logical_cpus, parse_memsize, parse_pressure_level, parse_swap_usage, parse_vm_stat,
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
    unavailable.push(Unavailable {
        source: "/proc/sys/fs/file-nr".to_string(),
        reason: "system file-handle table is not collected on macOS".to_string(),
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
        file_handles: None,
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
