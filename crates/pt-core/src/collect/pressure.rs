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
//! averages with `getloadavg`; unsupported pressure sensors remain unavailable.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

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

/// `/proc/meminfo`, in bytes. Fields a kernel does not report are `None`.
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

/// Read native macOS load averages and observed online CPU capacity. Other
/// pressure sources that require Linux procfs remain explicitly unavailable.
#[cfg(target_os = "macos")]
pub fn read_pressure_snapshot() -> PressureSnapshot {
    let mut snapshot = read_pressure_snapshot_from(
        Path::new("/"),
        super::cpu_capacity::observed_logical_cpus().unwrap_or(0),
    );
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
    apply_native_loadavg(&mut snapshot, load);
    snapshot
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
        short_after.cpu.as_mut().unwrap().some.as_mut().unwrap().total_us += 250;
        let short =
            pressure_window_with_elapsed(&before, &short_after, Duration::from_micros(500)).unwrap();
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
