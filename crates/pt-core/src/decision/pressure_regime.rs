//! Pressure regimes: what kind of trouble the machine is in, from a pressure snapshot.
//!
//! The rules are the operator playbook's (system-performance-remediation), as data
//! with the playbook's numbers as defaults:
//!
//! * PSI `some` avg10 is the sluggishness metric: CPU warn 10 % / crit 30 %, IO 5 / 15,
//!   memory 5 / 20. Load average is read against CPU count (warn 1.5x, crit 2x).
//! * Load vs CPU pressure: high load with low CPU pressure means tasks are blocked
//!   (I/O, D-state), not competing for CPU; both high is CPU contention.
//! * Available RAM vs memory pressure: little available and stalling is real
//!   exhaustion (find the hog); plenty available and still stalling is cache/slab
//!   bloat (VM tuning; dropping caches only treats the symptom).
//! * Swap: pages moving in/out fast is thrashing; lots of swap used while RAM is
//!   plentiful is the "swap paradox" (latency on fault-back); swap nearly full means
//!   the next spike ends in an OOM kill.
//! * File handles near the limit, zombie build-up, many tasks in uninterruptible sleep.
//!
//! Classification is deterministic and stateless; [`RegimeTracker`] adds hysteresis
//! for repeated sampling (the daemon) so a regime neither flaps nor lingers.

use crate::collect::pressure::{PressureSnapshot, PressureWindow};
use serde::{Deserialize, Serialize};

/// How bad a regime is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Warn,
    Crit,
}

/// The kinds of trouble pt recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegimeKind {
    CpuContention,
    IoBound,
    MemoryExhaustion,
    CacheBloat,
    SwapThrash,
    SwapParadox,
    SwapExhaustion,
    OomKills,
    FdExhaustion,
    ZombieLeak,
    DstateStorm,
}

/// A warn/crit threshold pair (crit > warn).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Band {
    pub warn: f64,
    pub crit: f64,
}

impl Band {
    fn severity(self, value: f64) -> Severity {
        if value >= self.crit {
            Severity::Crit
        } else if value >= self.warn {
            Severity::Warn
        } else {
            Severity::Ok
        }
    }

    /// 0 below warn, rising linearly to 1 at crit.
    fn scale(self, value: f64) -> f64 {
        if value < self.warn {
            0.0
        } else if self.crit <= self.warn {
            1.0
        } else {
            ((value - self.warn) / (self.crit - self.warn)).clamp(0.0, 1.0)
        }
    }
}

/// Thresholds (policy data). Defaults are the playbook's.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PressureThresholds {
    /// PSI `some` avg10, percent.
    pub cpu_psi: Band,
    pub io_psi: Band,
    pub memory_psi: Band,
    /// 1-minute load average / CPU count.
    pub load_ratio: Band,
    /// Below this CPU stall (percent) high load is not CPU contention.
    pub cpu_psi_quiet: f64,
    /// Fraction of RAM in use (not available): real exhaustion above this.
    pub memory_used_exhausted: f64,
    /// Fraction of RAM in use below which stalling points at caches, not processes.
    pub memory_used_plentiful: f64,
    /// Swapped pages per second (in + out).
    pub swap_pages_per_s: Band,
    /// Swap in use as a fraction of swap configured.
    pub swap_used: Band,
    /// Swap in use (bytes) above which the paradox is worth reporting.
    pub swap_paradox_min_bytes: u64,
    /// File handles allocated / max.
    pub file_handles: Band,
    pub zombies: Band,
    /// Tasks in uninterruptible sleep per CPU.
    pub dstate_per_cpu: Band,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            cpu_psi: Band {
                warn: 10.0,
                crit: 30.0,
            },
            io_psi: Band {
                warn: 5.0,
                crit: 15.0,
            },
            memory_psi: Band {
                warn: 5.0,
                crit: 20.0,
            },
            load_ratio: Band {
                warn: 1.5,
                crit: 2.0,
            },
            cpu_psi_quiet: 10.0,
            memory_used_exhausted: 0.90,
            memory_used_plentiful: 0.80,
            swap_pages_per_s: Band {
                warn: 1_000.0,
                crit: 10_000.0,
            },
            swap_used: Band {
                warn: 0.80,
                crit: 0.95,
            },
            swap_paradox_min_bytes: 1 << 30,
            file_handles: Band {
                warn: 0.80,
                crit: 0.95,
            },
            zombies: Band {
                warn: 20.0,
                crit: 200.0,
            },
            dstate_per_cpu: Band {
                warn: 0.5,
                crit: 2.0,
            },
        }
    }
}

/// Process-state counts from a scan (optional input).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCensus {
    pub zombies: u32,
    pub dstate: u32,
}

/// One recognized regime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Regime {
    pub kind: RegimeKind,
    pub severity: Severity,
    /// The 1-minute average agrees (PSI regimes), i.e. not a momentary spike.
    pub sustained: bool,
    /// Plain-language diagnosis with the numbers that support it.
    pub explanation: String,
}

/// Per-resource severity in [0, 1] (0 = healthy, 1 = at or past crit), the input to
/// pressure-conditioned decisions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceSeverity {
    pub cpu: f64,
    pub memory: f64,
    pub io: f64,
    pub fd: f64,
}

/// The diagnosis of one snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureAssessment {
    pub worst: Severity,
    pub regimes: Vec<Regime>,
    pub severity: ResourceSeverity,
    /// Figures the regimes were read from (absent when the source was unavailable).
    pub load_ratio: Option<f64>,
    pub cpu_some: Option<f64>,
    pub memory_some: Option<f64>,
    pub io_some: Option<f64>,
    pub memory_used_fraction: Option<f64>,
}

const GIB: f64 = (1u64 << 30) as f64;

/// PSI `some` stall percent for a resource: the exact window fraction when there is a
/// window, else avg10; and whether avg60 is past the warn line too.
fn stall(
    resource: Option<crate::collect::pressure::PsiResource>,
    window_some: Option<f64>,
    band: Band,
) -> Option<(f64, bool)> {
    let some = resource?.some?;
    let now = window_some.map_or(some.avg10, |f| f * 100.0);
    Some((now, some.avg60 >= band.warn))
}

fn push(regimes: &mut Vec<Regime>, kind: RegimeKind, severity: Severity, sustained: bool, explanation: String) {
    if severity > Severity::Ok {
        regimes.push(Regime {
            kind,
            severity,
            sustained,
            explanation,
        });
    }
}

/// Classify one snapshot (optionally with the window ending at it and a census).
pub fn assess(
    snapshot: &PressureSnapshot,
    window: Option<&PressureWindow>,
    census: Option<&ProcessCensus>,
    t: &PressureThresholds,
) -> PressureAssessment {
    let mut regimes = Vec::new();
    let mut severity = ResourceSeverity::default();
    let load_ratio = snapshot.load_ratio();

    // CPU: stall with load as corroboration; high load alone is not contention.
    let cpu = stall(snapshot.cpu, window.and_then(|w| w.cpu?.some), t.cpu_psi);
    if let Some((cpu_some, sustained)) = cpu {
        let level = t.cpu_psi.severity(cpu_some);
        severity.cpu = t.cpu_psi.scale(cpu_some);
        let load_text = load_ratio.map_or(String::new(), |r| format!("; load {r:.1}x the CPU count"));
        push(
            &mut regimes,
            RegimeKind::CpuContention,
            level,
            sustained,
            format!(
                "CPU contention: some task waited for a CPU {cpu_some:.0}% of the time{load_text}"
            ),
        );
    } else if let Some(ratio) = load_ratio {
        // No PSI: fall back to the load ratio alone.
        let level = t.load_ratio.severity(ratio);
        severity.cpu = t.load_ratio.scale(ratio);
        push(
            &mut regimes,
            RegimeKind::CpuContention,
            level,
            false,
            format!("Load {ratio:.1}x the CPU count (no CPU pressure data to confirm contention)"),
        );
    }

    // IO, including "high load but CPU quiet" (blocked tasks, not CPU demand).
    let io = stall(snapshot.io, window.and_then(|w| w.io?.some), t.io_psi);
    let cpu_quiet = cpu.is_some_and(|(c, _)| c < t.cpu_psi_quiet);
    let high_load = load_ratio.is_some_and(|r| r >= t.load_ratio.warn);
    if let Some((io_some, sustained)) = io {
        let level = t.io_psi.severity(io_some);
        severity.io = t.io_psi.scale(io_some);
        let why = if high_load && cpu_quiet {
            format!(
                " (load {:.1}x the CPU count while CPU stall is low: tasks are waiting on I/O, not CPU)",
                load_ratio.unwrap_or_default()
            )
        } else {
            String::new()
        };
        push(
            &mut regimes,
            RegimeKind::IoBound,
            level,
            sustained,
            format!("I/O pressure: some task waited on I/O {io_some:.0}% of the time{why}"),
        );
    }

    // Memory: stall, read against how much RAM is actually available.
    let mem_used = snapshot.meminfo.and_then(|m| m.used_fraction());
    let memory = stall(snapshot.memory, window.and_then(|w| w.memory?.some), t.memory_psi);
    if let Some((mem_some, sustained)) = memory {
        let level = t.memory_psi.severity(mem_some);
        severity.memory = t.memory_psi.scale(mem_some);
        let meminfo = snapshot.meminfo.unwrap_or_default();
        let gib = |b: Option<u64>| b.map_or(0.0, |v| v as f64 / GIB);
        let (kind, explanation) = match mem_used {
            Some(used) if used >= t.memory_used_exhausted => (
                RegimeKind::MemoryExhaustion,
                format!(
                    "Memory exhaustion: tasks stalled on memory {mem_some:.0}% of the time with only {:.0}% of RAM available; find the largest consumers",
                    (1.0 - used) * 100.0
                ),
            ),
            Some(used) if used < t.memory_used_plentiful => (
                RegimeKind::CacheBloat,
                format!(
                    "Cache bloat: tasks stalled on memory {mem_some:.0}% of the time although {:.0}% of RAM is available (page cache {:.1} GiB, slab {:.1} GiB): reclaim is stalling on caches. Fix VM tuning (vm.vfs_cache_pressure, vm.min_free_kbytes); dropping caches only treats the symptom",
                    (1.0 - used) * 100.0,
                    gib(meminfo.cached),
                    gib(meminfo.slab)
                ),
            ),
            _ => (
                RegimeKind::MemoryExhaustion,
                format!(
                    "Memory pressure: tasks stalled on memory {mem_some:.0}% of the time{}",
                    mem_used.map_or(String::new(), |u| format!(
                        " with {:.0}% of RAM available",
                        (1.0 - u) * 100.0
                    ))
                ),
            ),
        };
        push(&mut regimes, kind, level, sustained, explanation);
    }

    // Kernel OOM kills during the window are memory crit whatever the averages say.
    if let Some(kills) = window.and_then(|w| w.oom_kills).filter(|k| *k > 0) {
        severity.memory = 1.0;
        push(
            &mut regimes,
            RegimeKind::OomKills,
            Severity::Crit,
            true,
            format!("The kernel OOM killer fired {kills} time(s) during the sample window"),
        );
    }

    // Swap.
    if let Some(rate) = window.and_then(|w| Some(w.swap_in_per_s? + w.swap_out_per_s?)) {
        push(
            &mut regimes,
            RegimeKind::SwapThrash,
            t.swap_pages_per_s.severity(rate),
            true,
            format!("Swap thrashing: {rate:.0} pages/s moving between RAM and swap"),
        );
    }
    if let Some(meminfo) = snapshot.meminfo {
        if let (Some(swap_used), Some(swap_total)) = (meminfo.swap_used(), meminfo.swap_total) {
            if swap_total > 0 {
                let fraction = swap_used as f64 / swap_total as f64;
                push(
                    &mut regimes,
                    RegimeKind::SwapExhaustion,
                    t.swap_used.severity(fraction),
                    true,
                    format!(
                        "Swap {:.0}% full ({:.1} of {:.1} GiB): the next memory spike ends in an OOM kill",
                        fraction * 100.0,
                        swap_used as f64 / GIB,
                        swap_total as f64 / GIB
                    ),
                );
            }
            if let Some(available) = meminfo.available {
                if swap_used >= t.swap_paradox_min_bytes
                    && available >= swap_used.saturating_mul(2)
                    && mem_used.is_some_and(|u| u < t.memory_used_plentiful)
                {
                    push(
                        &mut regimes,
                        RegimeKind::SwapParadox,
                        Severity::Warn,
                        true,
                        format!(
                            "Swap paradox: {:.1} GiB in swap while {:.1} GiB of RAM is available; swapped-out pages fault back slowly (swapoff -a && swapon -a moves them back)",
                            swap_used as f64 / GIB,
                            available as f64 / GIB
                        ),
                    );
                }
            }
        }
    }

    // File handles.
    if let Some(fraction) = snapshot.file_handles.and_then(|f| f.used_fraction()) {
        severity.fd = t.file_handles.scale(fraction);
        push(
            &mut regimes,
            RegimeKind::FdExhaustion,
            t.file_handles.severity(fraction),
            true,
            format!("File handles {:.0}% of the system limit", fraction * 100.0),
        );
    }

    // Census.
    if let Some(census) = census {
        push(
            &mut regimes,
            RegimeKind::ZombieLeak,
            t.zombies.severity(f64::from(census.zombies)),
            true,
            format!(
                "{} zombie processes: their parents are not reaping them",
                census.zombies
            ),
        );
        if snapshot.cpus > 0 {
            let per_cpu = f64::from(census.dstate) / f64::from(snapshot.cpus);
            push(
                &mut regimes,
                RegimeKind::DstateStorm,
                t.dstate_per_cpu.severity(per_cpu),
                true,
                format!(
                    "{} tasks in uninterruptible sleep (D state): stuck in the kernel, usually on storage or a hung mount",
                    census.dstate
                ),
            );
        }
    }

    regimes.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
    PressureAssessment {
        worst: regimes.first().map_or(Severity::Ok, |r| r.severity),
        regimes,
        severity,
        load_ratio,
        cpu_some: cpu.map(|(v, _)| v),
        memory_some: memory.map(|(v, _)| v),
        io_some: io.map(|(v, _)| v),
        memory_used_fraction: mem_used,
    }
}

/// Hysteresis for repeated assessments: a regime is reported only after it was seen in
/// `enter_after` consecutive samples, and stays until it was absent for `exit_after`.
#[derive(Debug, Clone)]
pub struct RegimeTracker {
    enter_after: u32,
    exit_after: u32,
    state: std::collections::BTreeMap<RegimeKind, TrackedRegime>,
}

#[derive(Debug, Clone, Copy)]
struct TrackedRegime {
    /// Consecutive samples it was seen in / missing from.
    seen: u32,
    missed: u32,
    severity: Severity,
    active: bool,
}

impl RegimeTracker {
    pub fn new(enter_after: u32, exit_after: u32) -> Self {
        Self {
            enter_after: enter_after.max(1),
            exit_after: exit_after.max(1),
            state: std::collections::BTreeMap::new(),
        }
    }

    /// Feed one assessment; returns the regimes currently active after hysteresis,
    /// each at the severity of its latest sighting.
    pub fn update(&mut self, assessment: &PressureAssessment) -> Vec<(RegimeKind, Severity)> {
        for (kind, tracked) in self.state.iter_mut() {
            match assessment.regimes.iter().find(|r| r.kind == *kind) {
                Some(regime) => {
                    tracked.seen += 1;
                    tracked.missed = 0;
                    tracked.severity = regime.severity;
                }
                None => {
                    tracked.missed += 1;
                    tracked.seen = 0;
                }
            }
        }
        for regime in &assessment.regimes {
            self.state.entry(regime.kind).or_insert(TrackedRegime {
                seen: 1,
                missed: 0,
                severity: regime.severity,
                active: false,
            });
        }
        let (enter_after, exit_after) = (self.enter_after, self.exit_after);
        let mut active = Vec::new();
        self.state.retain(|kind, tracked| {
            if tracked.seen >= enter_after {
                tracked.active = true;
            }
            if tracked.missed >= exit_after {
                // Gone long enough (or never entered and gone): forget it.
                return false;
            }
            if tracked.active {
                active.push((*kind, tracked.severity));
            }
            // A regime seen once and then missing never entered: drop it.
            tracked.active || tracked.missed == 0
        });
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::pressure::{
        FileHandles, LoadAvg, MemInfo, PsiLine, PsiResource, StallFractions,
    };

    const GB: u64 = 1 << 30;

    fn psi(avg10: f64, avg60: f64) -> Option<PsiResource> {
        Some(PsiResource {
            some: Some(PsiLine {
                avg10,
                avg60,
                avg300: avg60,
                total_us: 0,
            }),
            full: None,
        })
    }

    fn snapshot(cpus: u32, load: f64) -> PressureSnapshot {
        PressureSnapshot {
            sampled_at_ms: 0,
            cpus,
            cpu: psi(0.0, 0.0),
            memory: psi(0.0, 0.0),
            io: psi(0.0, 0.0),
            irq: None,
            load: Some(LoadAvg {
                one: load,
                five: load,
                fifteen: load,
                runnable: 1,
                total: 100,
            }),
            meminfo: Some(MemInfo {
                total: Some(32 * GB),
                available: Some(24 * GB),
                cached: Some(8 * GB),
                slab: Some(GB),
                swap_total: Some(16 * GB),
                swap_free: Some(16 * GB),
                ..MemInfo::default()
            }),
            vmstat: None,
            file_handles: None,
            unavailable: Vec::new(),
        }
    }

    fn kinds(a: &PressureAssessment) -> Vec<RegimeKind> {
        a.regimes.iter().map(|r| r.kind).collect()
    }

    #[test]
    fn healthy_agent_box_is_healthy() {
        // hetzner1 2026-10-04: load 4.71 on 8 CPUs, PSI cpu some 2.67 %, 23 of 30 GiB available.
        let mut snap = snapshot(8, 4.71);
        snap.cpu = psi(2.67, 3.80);
        let a = assess(&snap, None, Some(&ProcessCensus::default()), &PressureThresholds::default());
        assert_eq!(a.worst, Severity::Ok, "{:?}", a.regimes);
        assert!(a.regimes.is_empty());
        assert_eq!(a.severity, ResourceSeverity::default());
    }

    #[test]
    fn cpu_contention_needs_cpu_stall_not_just_load() {
        let t = PressureThresholds::default();
        let mut snap = snapshot(64, 200.0);
        snap.cpu = psi(57.18, 58.76);
        let a = assess(&snap, None, None, &t);
        assert_eq!(kinds(&a), vec![RegimeKind::CpuContention]);
        assert_eq!(a.worst, Severity::Crit);
        assert!(a.regimes[0].sustained);
        assert_eq!(a.severity.cpu, 1.0);

        // Same load, CPU quiet, IO stalling: I/O bound, said in words.
        snap.cpu = psi(3.0, 3.0);
        snap.io = psi(22.0, 18.0);
        let a = assess(&snap, None, None, &t);
        assert_eq!(kinds(&a), vec![RegimeKind::IoBound]);
        assert!(a.regimes[0].explanation.contains("not CPU"), "{}", a.regimes[0].explanation);

        // A momentary spike: avg10 high, avg60 not.
        snap.io = psi(0.0, 0.0);
        snap.cpu = psi(35.0, 4.0);
        let a = assess(&snap, None, None, &t);
        assert!(!a.regimes[0].sustained);
    }

    #[test]
    fn trj_cache_bloat_incident_is_cache_bloat() {
        // trj 2026-02-23 (499 GB btrfs host): memory some avg10 18.78 %, 388 GB page
        // cache + 40 GB slab; RAM was largely reclaimable ("available").
        let mut snap = snapshot(128, 20.0);
        snap.memory = psi(18.78, 16.49);
        snap.meminfo = Some(MemInfo {
            total: Some(499 * GB),
            available: Some(300 * GB),
            cached: Some(388 * GB),
            slab: Some(40 * GB),
            swap_total: Some(0),
            swap_free: Some(0),
            ..MemInfo::default()
        });
        let a = assess(&snap, None, None, &PressureThresholds::default());
        assert_eq!(kinds(&a), vec![RegimeKind::CacheBloat]);
        assert_eq!(a.regimes[0].severity, Severity::Warn);
        assert!(a.regimes[0].explanation.contains("vfs_cache_pressure"));
        assert!(a.severity.memory > 0.8);

        // The same stall with RAM actually gone is exhaustion.
        snap.meminfo.as_mut().unwrap().available = Some(20 * GB);
        let a = assess(&snap, None, None, &PressureThresholds::default());
        assert_eq!(kinds(&a), vec![RegimeKind::MemoryExhaustion]);
    }

    #[test]
    fn swap_paradox_thrash_and_exhaustion() {
        let t = PressureThresholds::default();
        let mut snap = snapshot(16, 1.0);
        snap.meminfo = Some(MemInfo {
            total: Some(256 * GB),
            available: Some(189 * GB),
            swap_total: Some(64 * GB),
            swap_free: Some(34 * GB),
            ..MemInfo::default()
        });
        let a = assess(&snap, None, None, &t);
        assert_eq!(kinds(&a), vec![RegimeKind::SwapParadox]);

        snap.meminfo = Some(MemInfo {
            total: Some(32 * GB),
            available: Some(GB),
            swap_total: Some(16 * GB),
            swap_free: Some(GB / 2),
            ..MemInfo::default()
        });
        let window = PressureWindow {
            seconds: 1.0,
            cpu: None,
            memory: Some(StallFractions {
                some: Some(0.4),
                full: Some(0.2),
            }),
            io: None,
            swap_in_per_s: Some(9_000.0),
            swap_out_per_s: Some(4_000.0),
            major_faults_per_s: None,
            direct_reclaim_scans_per_s: None,
            alloc_stalls_per_s: None,
            oom_kills: Some(2),
        };
        snap.memory = psi(10.0, 10.0);
        let a = assess(&snap, Some(&window), None, &t);
        let k = kinds(&a);
        for expected in [
            RegimeKind::MemoryExhaustion,
            RegimeKind::OomKills,
            RegimeKind::SwapThrash,
            RegimeKind::SwapExhaustion,
        ] {
            assert!(k.contains(&expected), "{expected:?} missing from {k:?}");
        }
        assert!(!k.contains(&RegimeKind::SwapParadox));
        // The window's exact fraction (40 %) wins over avg10 (10 %).
        assert_eq!(a.memory_some, Some(40.0));
        assert_eq!(a.worst, Severity::Crit);
    }

    #[test]
    fn no_psi_falls_back_to_load_and_says_so() {
        let mut snap = snapshot(8, 20.0);
        snap.cpu = None;
        snap.memory = None;
        snap.io = None;
        let a = assess(&snap, None, None, &PressureThresholds::default());
        assert_eq!(kinds(&a), vec![RegimeKind::CpuContention]);
        assert!(a.regimes[0].explanation.contains("no CPU pressure data"));
        assert_eq!(a.cpu_some, None);
    }

    #[test]
    fn fd_and_census_regimes() {
        let mut snap = snapshot(8, 1.0);
        snap.file_handles = Some(FileHandles {
            allocated: 96,
            max: 100,
        });
        let census = ProcessCensus {
            zombies: 25,
            dstate: 20,
        };
        let a = assess(&snap, None, Some(&census), &PressureThresholds::default());
        let k = kinds(&a);
        assert!(k.contains(&RegimeKind::FdExhaustion));
        assert!(k.contains(&RegimeKind::ZombieLeak));
        assert!(k.contains(&RegimeKind::DstateStorm));
        assert_eq!(a.regimes[0].severity, Severity::Crit, "crit sorted first");
    }

    #[test]
    fn tracker_neither_flaps_nor_lingers() {
        let t = PressureThresholds::default();
        let hot = {
            let mut s = snapshot(8, 1.0);
            s.cpu = psi(40.0, 40.0);
            assess(&s, None, None, &t)
        };
        let cool = assess(&snapshot(8, 1.0), None, None, &t);
        let mut tracker = RegimeTracker::new(2, 2);
        assert!(tracker.update(&hot).is_empty(), "one sample is not enough");
        assert_eq!(
            tracker.update(&hot),
            vec![(RegimeKind::CpuContention, Severity::Crit)]
        );
        assert_eq!(tracker.update(&cool).len(), 1, "one quiet sample keeps it");
        assert!(tracker.update(&cool).is_empty(), "two quiet samples clear it");
        // Oscillating hot/cool never enters.
        let mut tracker = RegimeTracker::new(2, 2);
        for _ in 0..5 {
            assert!(tracker.update(&hot).is_empty());
            assert!(tracker.update(&cool).is_empty());
        }
    }
}
