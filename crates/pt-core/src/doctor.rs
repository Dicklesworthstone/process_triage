//! `pt doctor`: a read-only host hygiene audit.
//!
//! Much of what keeps a busy machine healthy is host configuration rather than any one
//! process: VM tuning that lets kernel caches balloon, swap or zram that silently went
//! missing after a reboot, systemd-oomd limits that a later drop-in quietly negates,
//! journald settings that lose the logs of an OOM kill, file-handle and inotify limits,
//! zombie leaks. These checks come from the system-performance remediation playbook and
//! the incidents behind it (each finding states its rationale).
//!
//! Everything is read from files under a root directory (`/` on a live system), so every
//! check is testable against recorded files. Nothing is written and nothing is run:
//! suggested commands are printed for a person to review ([`fix_script`]).

use crate::collect::pressure::{
    parse_file_nr, parse_meminfo, read_pressure_snapshot_from, FileHandles, MemInfo,
};
use crate::decision::pressure_regime::{
    assess, PressureAssessment, PressureThresholds, ProcessCensus, RegimeKind, Severity,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

const KIB: u64 = 1 << 10;
const GIB: u64 = 1 << 30;

/// How bad a finding is. The report's `worst` carries it; the CLI exit code only says
/// whether anything needs attention (pt's contract reserves 2 for ActionsOk).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
    Crit,
}

/// One check's result.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `vm.vfs_cache_pressure`.
    pub id: &'static str,
    pub level: Level,
    /// One line: what was found.
    pub summary: String,
    /// The values the verdict was read from.
    pub observed: serde_json::Value,
    /// What the value should be, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended: Option<String>,
    /// Why it matters (the incident or mechanism behind the check).
    pub rationale: String,
    /// Commands a person may run to fix it. pt never runs them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
}

/// A line of `/proc/swaps`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SwapDevice {
    pub name: String,
    pub kind: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub priority: i64,
}

impl SwapDevice {
    pub fn is_zram(&self) -> bool {
        self.name.contains("/zram") || self.name.starts_with("zram")
    }
}

/// A drop-in that sets a memory limit on the user slice / user manager.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DropIn {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_high: Option<String>,
}

/// The effective journald settings that decide whether OOM post-mortems survive.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct JournaldConf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_max_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retention_sec: Option<String>,
}

/// Zombies sharing one parent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ZombieParent {
    pub ppid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_age_seconds: Option<u64>,
    pub zombies: u32,
}

/// A process holding many file descriptors.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FdHolder {
    pub pid: u32,
    pub comm: String,
    pub fds: u32,
}

/// What the process table says about host health.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ProcTable {
    pub zombie_parents: Vec<ZombieParent>,
    pub zombies: u32,
    pub dstate: u32,
    pub oomd_running: bool,
    /// Largest descriptor holders among the processes whose fd table is readable.
    pub top_fd_holders: Vec<FdHolder>,
    /// Bytes of deleted regular files still held open (each file counted once).
    pub deleted_open_bytes: u64,
    /// The largest of those files, with a process holding each.
    pub deleted_open: Vec<DeletedOpenFile>,
}

/// A file deleted while a process still holds it open: its space is not freed until
/// the process closes it or exits.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeletedOpenFile {
    pub pid: u32,
    pub comm: String,
    pub path: String,
    pub bytes: u64,
}

/// Deleted regular files among the open descriptors in `fd_dir`, as `(path, bytes,
/// (dev, inode))`. memfd and /dev (tmpfs/shm) objects hold memory, not disk, and are
/// skipped.
fn deleted_open_files(fd_dir: &[std::fs::DirEntry]) -> Vec<(String, u64, (u64, u64))> {
    let mut out = Vec::new();
    for fd in fd_dir {
        let Ok(target) = std::fs::read_link(fd.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let Some(path) = target.strip_suffix(" (deleted)") else {
            continue;
        };
        if !path.starts_with('/') || path.starts_with("/memfd:") || path.starts_with("/dev/") {
            continue;
        }
        // Follows the link to the open file itself (it has no name any more).
        let Ok(meta) = std::fs::metadata(fd.path()) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        let key = {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        };
        #[cfg(not(unix))]
        let key = (0, 0);
        out.push((path.to_string(), meta.len(), key));
    }
    out
}

/// Everything the checks read, gathered once.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostFacts {
    pub meminfo: Option<MemInfo>,
    pub vfs_cache_pressure: Option<u64>,
    pub min_free_kbytes: Option<u64>,
    pub swappiness: Option<u64>,
    pub dirty_ratio: Option<u64>,
    pub dirty_background_ratio: Option<u64>,
    /// Absolute dirty limit; when set the kernel reports dirty_ratio as 0.
    pub dirty_bytes: Option<u64>,
    /// Mounted filesystem types (deduplicated).
    pub fs_types: Vec<String>,
    /// `None` when `/proc/swaps` could not be read.
    pub swaps: Option<Vec<SwapDevice>>,
    /// Whether a zram setup survives a reboot (zram-generator config or an enabled
    /// zram service).
    pub zram_persisted: bool,
    pub user_slice_drop_ins: Vec<DropIn>,
    pub user_manager_drop_ins: Vec<DropIn>,
    pub journald: JournaldConf,
    pub file_handles: Option<FileHandles>,
    pub inotify_max_user_watches: Option<u64>,
    pub inotify_max_user_instances: Option<u64>,
    pub procs: ProcTable,
    /// pt's own session store (filled by [`run_doctor`]; fixtures pass it explicitly).
    pub pt_sessions: Option<SessionUsage>,
    /// Whether Pressure Stall Information (/proc/pressure) could be read.
    pub psi_available: bool,
}

/// Size of pt's session store.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SessionUsage {
    pub root: String,
    pub sessions: u64,
    /// Allocated bytes.
    pub bytes: u64,
    /// `PROCESS_TRIAGE_RETENTION` as set (unset = the 7-day default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
}

fn allocated_bytes(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    let own = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.blocks() * 512
        }
        #[cfg(not(unix))]
        {
            meta.len()
        }
    };
    if meta.is_dir() {
        own + std::fs::read_dir(path).map_or(0, |entries| {
            entries.flatten().map(|e| allocated_bytes(&e.path())).sum()
        })
    } else {
        own
    }
}

/// Count and size the session directories under `sessions_root` (read-only).
pub fn read_session_usage(sessions_root: &Path, retention: Option<String>) -> Option<SessionUsage> {
    let entries = std::fs::read_dir(sessions_root).ok()?;
    let mut usage = SessionUsage {
        root: sessions_root.display().to_string(),
        retention,
        ..SessionUsage::default()
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with("pt-") && path.is_dir() {
            usage.sessions += 1;
            usage.bytes += allocated_bytes(&path);
        }
    }
    Some(usage)
}

/// The whole audit.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub worst: Level,
    pub pressure: PressureAssessment,
    pub findings: Vec<Finding>,
    pub facts: HostFacts,
}

// ── Reading ─────────────────────────────────────────────────────────────

fn read_text(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

fn read_u64(root: &Path, rel: &str) -> Option<u64> {
    read_text(root, rel)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Parse `/proc/swaps` (sizes in KiB).
pub fn parse_swaps(text: &str) -> Vec<SwapDevice> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 {
                return None;
            }
            Some(SwapDevice {
                name: f[0].to_string(),
                kind: f[1].to_string(),
                size_bytes: f[2].parse::<u64>().ok()?.saturating_mul(KIB),
                used_bytes: f[3].parse::<u64>().ok()?.saturating_mul(KIB),
                priority: f[4].parse().ok()?,
            })
        })
        .collect()
}

/// Filesystem types from `/proc/mounts`.
pub fn parse_mount_types(text: &str) -> Vec<String> {
    let mut types: Vec<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2).map(str::to_string))
        .collect();
    types.sort();
    types.dedup();
    types
}

/// `Key=Value` assignments of an INI-style systemd file, with their section.
fn parse_ini(text: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push((section.clone(), k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// `*.conf` files of a drop-in directory across the unit search path, in the order
/// systemd applies them: by file name, a name in /etc hiding the same name in /run,
/// which hides it in /usr/lib (and /lib).
fn drop_in_files(root: &Path, dir_name: &str) -> Vec<(String, std::path::PathBuf)> {
    let mut by_name: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
    // Lowest precedence first, so higher ones overwrite.
    for base in [
        "lib/systemd/system",
        "usr/lib/systemd/system",
        "run/systemd/system",
        "etc/systemd/system",
    ] {
        let dir = root.join(base).join(dir_name);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".conf") {
                by_name.insert(name, entry.path());
            }
        }
    }
    by_name.into_iter().collect()
}

fn memory_drop_ins(root: &Path, dir_name: &str) -> Vec<DropIn> {
    drop_in_files(root, dir_name)
        .into_iter()
        .filter_map(|(_, path)| {
            let text = std::fs::read_to_string(&path).ok()?;
            let mut d = DropIn {
                path: format!("/{}", path.strip_prefix(root).unwrap_or(&path).display()),
                ..DropIn::default()
            };
            for (_, key, value) in parse_ini(&text) {
                match key.as_str() {
                    "MemoryMax" => d.memory_max = Some(value),
                    "MemoryHigh" => d.memory_high = Some(value),
                    _ => {}
                }
            }
            (d.memory_max.is_some() || d.memory_high.is_some()).then_some(d)
        })
        .collect()
}

fn journald_conf(root: &Path) -> JournaldConf {
    let mut files = Vec::new();
    if let Some(text) = read_text(root, "etc/systemd/journald.conf") {
        files.push(text);
    }
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    for base in [
        "usr/lib/systemd/journald.conf.d",
        "run/systemd/journald.conf.d",
        "etc/systemd/journald.conf.d",
    ] {
        if let Ok(entries) = std::fs::read_dir(root.join(base)) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".conf") {
                    if let Ok(text) = std::fs::read_to_string(entry.path()) {
                        drop_ins.insert(name, text);
                    }
                }
            }
        }
    }
    files.extend(drop_ins.into_values());
    let mut conf = JournaldConf::default();
    for text in files {
        for (section, key, value) in parse_ini(&text) {
            if section != "Journal" {
                continue;
            }
            let value = (!value.is_empty()).then_some(value);
            match key.as_str() {
                "Storage" => conf.storage = value,
                "SystemMaxUse" => conf.system_max_use = value,
                "MaxRetentionSec" => conf.max_retention_sec = value,
                _ => {}
            }
        }
    }
    conf
}

fn zram_persisted(root: &Path) -> bool {
    let exists = |rel: &str| root.join(rel).exists();
    let dir_has_conf = |rel: &str| {
        std::fs::read_dir(root.join(rel)).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".conf"))
        })
    };
    // An enabled unit with zram in its name, whatever the setup calls it (zramswap,
    // zram-config, a hand-written zram-swap.service, ...): a link in some *.wants dir.
    let enabled_zram_unit = std::fs::read_dir(root.join("etc/systemd/system")).is_ok_and(|dirs| {
        dirs.flatten()
            .filter(|d| d.file_name().to_string_lossy().ends_with(".wants"))
            .any(|d| {
                std::fs::read_dir(d.path()).is_ok_and(|units| {
                    units
                        .flatten()
                        .any(|u| u.file_name().to_string_lossy().contains("zram"))
                })
            })
    });
    exists("etc/systemd/zram-generator.conf")
        || exists("usr/lib/systemd/zram-generator.conf")
        || dir_has_conf("etc/systemd/zram-generator.conf.d")
        || enabled_zram_unit
        || std::fs::read_dir(root.join("etc/udev/rules.d")).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains("zram"))
        })
}

/// `(pid, comm, state, ppid, starttime_ticks)` from a `/proc/<pid>/stat` line.
fn parse_stat(text: &str) -> Option<(u32, String, char, u32, u64)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let pid = text[..open].trim().parse().ok()?;
    let comm = text[open + 1..close].to_string();
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    let state = rest.first()?.chars().next()?;
    let ppid = rest.get(1)?.parse().ok()?;
    // Field 22 (starttime) is the 20th after the comm.
    let start = rest.get(19)?.parse().ok()?;
    Some((pid, comm, state, ppid, start))
}

fn read_proc_table(root: &Path, clk_tck: u64) -> ProcTable {
    let uptime = read_text(root, "proc/uptime")
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok());
    let mut table = ProcTable::default();
    let mut comms: BTreeMap<u32, (String, u64)> = BTreeMap::new();
    let mut zombies: BTreeMap<u32, u32> = BTreeMap::new();
    let mut fd_counts: Vec<FdHolder> = Vec::new();
    let mut deleted: Vec<DeletedOpenFile> = Vec::new();
    let mut seen_deleted: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(root.join("proc")) else {
        return table;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Some((pid, comm, state, ppid, start)) =
            std::fs::read_to_string(entry.path().join("stat"))
                .ok()
                .and_then(|t| parse_stat(&t))
                .filter(|s| s.0 == pid)
        else {
            continue;
        };
        match state {
            'Z' => {
                table.zombies += 1;
                *zombies.entry(ppid).or_default() += 1;
            }
            'D' => table.dstate += 1,
            _ => {}
        }
        if comm == "systemd-oomd" {
            table.oomd_running = true;
        }
        if let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) {
            let fds: Vec<std::fs::DirEntry> = fds.flatten().collect();
            for (path, bytes, key) in deleted_open_files(&fds) {
                if seen_deleted.insert(key) {
                    deleted.push(DeletedOpenFile {
                        pid,
                        comm: comm.clone(),
                        path,
                        bytes,
                    });
                }
            }
            fd_counts.push(FdHolder {
                pid,
                comm: comm.clone(),
                fds: fds.len() as u32,
            });
        }
        comms.insert(pid, (comm, start));
    }
    table.deleted_open_bytes = deleted.iter().map(|d| d.bytes).sum();
    deleted.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.pid.cmp(&b.pid)));
    deleted.truncate(10);
    table.deleted_open = deleted;
    table.zombie_parents = zombies
        .into_iter()
        .map(|(ppid, count)| {
            let parent = comms.get(&ppid);
            ZombieParent {
                ppid,
                parent_comm: parent.map(|(c, _)| c.clone()),
                parent_age_seconds: parent.and_then(|(_, start)| {
                    let up = uptime?;
                    (clk_tck > 0).then(|| (up - *start as f64 / clk_tck as f64).max(0.0) as u64)
                }),
                zombies: count,
            }
        })
        .collect();
    table
        .zombie_parents
        .sort_by(|a, b| b.zombies.cmp(&a.zombies).then(a.ppid.cmp(&b.ppid)));
    fd_counts.sort_by(|a, b| b.fds.cmp(&a.fds).then(a.pid.cmp(&b.pid)));
    fd_counts.truncate(5);
    table.top_fd_holders = fd_counts;
    table
}

/// Gather the facts under `root` (`/` on a live system). Read-only.
pub fn read_host_facts_from(root: &Path, clk_tck: u64) -> HostFacts {
    HostFacts {
        meminfo: read_text(root, "proc/meminfo").and_then(|t| parse_meminfo(&t)),
        vfs_cache_pressure: read_u64(root, "proc/sys/vm/vfs_cache_pressure"),
        min_free_kbytes: read_u64(root, "proc/sys/vm/min_free_kbytes"),
        swappiness: read_u64(root, "proc/sys/vm/swappiness"),
        dirty_ratio: read_u64(root, "proc/sys/vm/dirty_ratio"),
        dirty_background_ratio: read_u64(root, "proc/sys/vm/dirty_background_ratio"),
        dirty_bytes: read_u64(root, "proc/sys/vm/dirty_bytes"),
        fs_types: read_text(root, "proc/mounts")
            .map(|t| parse_mount_types(&t))
            .unwrap_or_default(),
        swaps: read_text(root, "proc/swaps").map(|t| parse_swaps(&t)),
        zram_persisted: zram_persisted(root),
        user_slice_drop_ins: memory_drop_ins(root, "user-.slice.d"),
        user_manager_drop_ins: memory_drop_ins(root, "user@.service.d"),
        journald: journald_conf(root),
        file_handles: read_text(root, "proc/sys/fs/file-nr").and_then(|t| parse_file_nr(&t)),
        inotify_max_user_watches: read_u64(root, "proc/sys/fs/inotify/max_user_watches"),
        inotify_max_user_instances: read_u64(root, "proc/sys/fs/inotify/max_user_instances"),
        procs: read_proc_table(root, clk_tck),
        pt_sessions: None,
        psi_available: false,
    }
}

// ── Checks ──────────────────────────────────────────────────────────────

fn finding(id: &'static str, level: Level, summary: impl Into<String>) -> Finding {
    Finding {
        id,
        level,
        summary: summary.into(),
        observed: serde_json::Value::Null,
        recommended: None,
        rationale: String::new(),
        commands: Vec::new(),
    }
}

impl Finding {
    fn observed(mut self, v: serde_json::Value) -> Self {
        self.observed = v;
        self
    }
    fn recommended(mut self, v: impl Into<String>) -> Self {
        self.recommended = Some(v.into());
        self
    }
    fn rationale(mut self, v: impl Into<String>) -> Self {
        self.rationale = v.into();
        self
    }
    fn commands(mut self, v: &[&str]) -> Self {
        self.commands = v.iter().map(|c| c.to_string()).collect();
        self
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

/// `vm.min_free_kbytes` the playbook recommends for a machine with `ram` bytes
/// (15 GB -> 256 MB, 29-58 GB -> 512 MB, ~251 GB -> 1 GB, ~499 GB -> 2 GB).
pub fn recommended_min_free_kbytes(ram: u64) -> u64 {
    let mib = if ram < 24 * GIB {
        256
    } else if ram < 128 * GIB {
        512
    } else if ram < 384 * GIB {
        1024
    } else {
        2048
    };
    mib * 1024
}

const TRJ_CACHE_BLOAT: &str = "A low vfs_cache_pressure keeps dentry/inode caches the kernel could reclaim. On a 499 GB btrfs host (trj, 2026-02-23) vfs_cache_pressure=50 let caches grow to 388 GB plus 40 GB of slab; systemd-oomd then killed user@1000.service and all 382 sessions. The fix was vfs_cache_pressure=200 and min_free_kbytes=2 GB. Dropping caches only treats the symptom: the cache rebuilds unless the tuning is fixed.";

fn check_vm(f: &HostFacts, cache_bloat: bool, out: &mut Vec<Finding>) {
    let ram = f.meminfo.as_ref().and_then(|m| m.total);
    let btrfs = f.fs_types.iter().any(|t| t == "btrfs");
    if let Some(vfs) = f.vfs_cache_pressure {
        let big = ram.is_some_and(|r| r >= 64 * GIB);
        let level = if vfs < 100 && btrfs && big {
            Level::Crit
        } else if vfs < 100 || (vfs == 100 && btrfs && ram.is_some_and(|r| r >= 128 * GIB)) {
            Level::Warn
        } else {
            Level::Ok
        };
        let level = if cache_bloat {
            level.max(Level::Warn)
        } else {
            level
        };
        let mut summary = format!("vm.vfs_cache_pressure = {vfs}");
        if btrfs {
            summary.push_str(" on a btrfs host");
        }
        if let Some(r) = ram {
            summary.push_str(&format!(" with {} RAM", gib(r)));
        }
        if cache_bloat {
            summary.push_str("; caches are bloated now: fix the tuning first, dropping caches only treats the symptom");
        }
        out.push(
            finding("vm.vfs_cache_pressure", level, summary)
                .observed(json!({"vfs_cache_pressure": vfs, "btrfs": btrfs, "ram_bytes": ram}))
                .recommended(if btrfs && big { "200" } else { ">= 100" })
                .rationale(TRJ_CACHE_BLOAT)
                .commands(if level >= Level::Warn {
                    &[
                        "sudo sysctl -w vm.vfs_cache_pressure=200",
                        "printf 'vm.vfs_cache_pressure = 200\\n' | sudo tee /etc/sysctl.d/90-vm-cache.conf",
                    ][..]
                } else {
                    &[][..]
                }),
        );
    }
    if let (Some(min_free), Some(ram)) = (f.min_free_kbytes, ram) {
        let want = recommended_min_free_kbytes(ram);
        let level = if min_free * 2 < want {
            Level::Warn
        } else if min_free < want {
            Level::Info
        } else {
            Level::Ok
        };
        let cmd_now = format!("sudo sysctl -w vm.min_free_kbytes={want}");
        let cmd_persist = format!(
            "printf 'vm.min_free_kbytes = {want}\\n' | sudo tee /etc/sysctl.d/90-vm-minfree.conf"
        );
        let mut fnd = finding(
            "vm.min_free_kbytes",
            level,
            format!(
                "vm.min_free_kbytes = {} MiB with {} RAM (recommended {} MiB)",
                min_free / 1024,
                gib(ram),
                want / 1024
            ),
        )
        .observed(json!({"min_free_kbytes": min_free, "ram_bytes": ram}))
        .recommended(format!("{want}"))
        .rationale("Too small a free-memory reserve on a large machine makes allocations stall in direct reclaim and compaction under load (kcompactd burning CPU) instead of being served from the reserve.");
        if level >= Level::Info {
            fnd.commands = vec![cmd_now, cmd_persist];
        }
        out.push(fnd);
    }
    if let (Some(dirty), Some(ram)) = (f.dirty_ratio, ram) {
        // An absolute vm.dirty_bytes takes precedence (dirty_ratio then reads 0).
        let absolute = f.dirty_bytes.filter(|&b| b > 0);
        let limit = absolute.unwrap_or(ram / 100 * dirty);
        let level = if limit > 32 * GIB {
            Level::Info
        } else {
            Level::Ok
        };
        let summary = match absolute {
            Some(b) => format!(
                "vm.dirty_bytes = {} bounds dirty page cache before writers block",
                gib(b)
            ),
            None => format!(
                "vm.dirty_ratio = {dirty}% allows {} of dirty page cache before writers block",
                gib(limit)
            ),
        };
        out.push(
            finding("vm.dirty_ratio", level, summary)
            .observed(json!({
                "dirty_ratio": dirty,
                "dirty_bytes": f.dirty_bytes,
                "dirty_background_ratio": f.dirty_background_ratio,
                "ram_bytes": ram,
            }))
            .rationale("On large-RAM hosts a percentage-based dirty limit lets tens of GB queue for writeback, which then stalls writers for a long time; vm.dirty_bytes / vm.dirty_background_bytes bound it absolutely."),
        );
    }
}

fn check_swap(f: &HostFacts, out: &mut Vec<Finding>) {
    let Some(swaps) = &f.swaps else {
        return;
    };
    let total: u64 = swaps.iter().map(|s| s.size_bytes).sum();
    let used: u64 = swaps.iter().map(|s| s.used_bytes).sum();
    let zram: Vec<&SwapDevice> = swaps.iter().filter(|s| s.is_zram()).collect();
    let observed = json!({
        "devices": swaps,
        "swappiness": f.swappiness,
        "zram_persisted": f.zram_persisted,
    });
    if swaps.is_empty() {
        out.push(
            finding("swap.present", Level::Warn, "no swap configured")
                .observed(observed)
                .recommended("zram swap (e.g. half of RAM, priority 100), persisted")
                .rationale("Without any swap, memory exhaustion goes straight to the OOM killer; compressed zram swap absorbs bursts and gives pressure-based tools time to act.")
                .commands(&[
                    "printf '[zram0]\\nzram-size = ram / 2\\ncompression-algorithm = zstd\\nswap-priority = 100\\n' | sudo tee /etc/systemd/zram-generator.conf",
                    "sudo systemctl daemon-reload && sudo systemctl start systemd-zram-setup@zram0.service",
                ]),
        );
        return;
    }
    let used_fraction = used as f64 / total.max(1) as f64;
    let level = if used_fraction > 0.9 {
        Level::Crit
    } else if used_fraction > 0.75 {
        Level::Warn
    } else {
        Level::Ok
    };
    out.push(
        finding(
            "swap.usage",
            level,
            format!(
                "swap {} of {} used ({:.0}%)",
                gib(used),
                gib(total),
                used_fraction * 100.0
            ),
        )
        .observed(observed.clone())
        .rationale("Swap nearly full means the next burst has nowhere to go but the OOM killer."),
    );
    if !zram.is_empty() && !f.zram_persisted {
        out.push(
            finding(
                "swap.zram_persisted",
                Level::Warn,
                "zram swap is active but nothing recreates it at boot",
            )
            .observed(observed.clone())
            .rationale("Machines silently lose zram after a reboot when it was set up by hand; persist it with zram-generator (or the distribution's zram service).")
            .commands(&[
                "printf '[zram0]\\nzram-size = ram / 2\\ncompression-algorithm = zstd\\nswap-priority = 100\\n' | sudo tee /etc/systemd/zram-generator.conf",
            ]),
        );
    }
    // The swap paradox: pages sit in swap while plenty of RAM is free, so touching them
    // costs a major fault every time.
    let available = f.meminfo.as_ref().and_then(|m| m.available);
    if let Some(available) = available {
        if used >= GIB && available > 2 * used {
            out.push(
                finding(
                    "swap.paradox",
                    Level::Warn,
                    format!(
                        "{} sits in swap while {} of RAM is available",
                        gib(used),
                        gib(available)
                    ),
                )
                .observed(json!({"swap_used_bytes": used, "mem_available_bytes": available}))
                .recommended("pull swapped pages back into RAM")
                .rationale("Swapped-out pages of live processes fault back in one by one (latency spikes) although RAM is free. swapoff/swapon moves them back at once; it can take minutes and is only safe because available RAM is more than twice the swapped amount.")
                .commands(&["sudo swapoff -a && sudo swapon -a"]),
            );
        }
    }
}

/// A limit value that bounds memory (`infinity` and an empty reset do not).
fn is_finite_limit(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && !v.eq_ignore_ascii_case("infinity")
}

fn check_negated_limits(id: &'static str, unit: &str, drop_ins: &[DropIn], out: &mut Vec<Finding>) {
    for (key, pick) in [
        (
            "MemoryMax",
            (|d: &DropIn| d.memory_max.clone()) as fn(&DropIn) -> Option<String>,
        ),
        ("MemoryHigh", |d: &DropIn| d.memory_high.clone()),
    ] {
        let settings: Vec<(&DropIn, String)> = drop_ins
            .iter()
            .filter_map(|d| pick(d).map(|v| (d, v)))
            .collect();
        let Some(limit_at) = settings.iter().position(|(_, v)| is_finite_limit(v)) else {
            continue;
        };
        if let Some((later, value)) = settings[limit_at + 1..]
            .iter()
            .find(|(_, v)| !is_finite_limit(v))
        {
            let (first, first_value) = &settings[limit_at];
            out.push(
                finding(
                    id,
                    Level::Crit,
                    format!(
                        "{unit}: {key}={first_value} in {} is negated by {key}={} in {}, which sorts later",
                        first.path,
                        if value.is_empty() { "(reset)" } else { value.as_str() },
                        later.path
                    ),
                )
                .observed(json!({"drop_ins": drop_ins}))
                .recommended(format!("remove the later {key} assignment or rename the drop-ins so the limit sorts last"))
                .rationale("systemd applies drop-ins in file-name order, so a later MemoryMax=infinity silently removes the per-user memory limit that protects the machine (and the oomd protection built on it).")
                .commands(&[&format!("systemctl cat {unit}")]),
            );
        }
    }
}

fn check_oomd(f: &HostFacts, out: &mut Vec<Finding>) {
    out.push(
        finding(
            "oomd.running",
            if f.procs.oomd_running {
                Level::Ok
            } else {
                Level::Info
            },
            if f.procs.oomd_running {
                "systemd-oomd is running"
            } else {
                "systemd-oomd is not running: memory pressure is only acted on by the kernel OOM killer (and pt's own pressure regimes)"
            },
        )
        .observed(json!({"oomd_running": f.procs.oomd_running}))
        .rationale("systemd-oomd kills by cgroup under sustained memory pressure before the kernel OOM killer picks a victim; whether that is wanted is a host policy decision."),
    );
    check_negated_limits(
        "oomd.user_slice_limits",
        "user-.slice",
        &f.user_slice_drop_ins,
        out,
    );
    check_negated_limits(
        "oomd.user_manager_limits",
        "user@.service",
        &f.user_manager_drop_ins,
        out,
    );
}

fn check_journald(f: &HostFacts, out: &mut Vec<Finding>) {
    let j = &f.journald;
    let volatile = j
        .storage
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("volatile") || s.eq_ignore_ascii_case("none"));
    let short_retention = j
        .max_retention_sec
        .as_deref()
        .and_then(parse_systemd_seconds)
        .is_some_and(|s| s < 86_400);
    let level = if volatile || short_retention {
        Level::Warn
    } else {
        Level::Ok
    };
    out.push(
        finding(
            "journald.retention",
            level,
            if volatile {
                "journald keeps logs only in memory: OOM kills cannot be investigated after a reboot".to_string()
            } else if short_retention {
                format!(
                    "journald keeps logs for less than a day (MaxRetentionSec={})",
                    j.max_retention_sec.as_deref().unwrap_or_default()
                )
            } else {
                "journald retention keeps OOM post-mortems".to_string()
            },
        )
        .observed(json!(j))
        .rationale("After an OOM kill or an oomd action the journal is the only record of what was killed and why."),
    );
}

/// Seconds in a systemd time span such as `1d`, `12h`, `3600`, `2week` (whole units).
fn parse_systemd_seconds(text: &str) -> Option<u64> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let n: u64 = t[..split].parse().ok()?;
    let unit = t[split..].trim();
    let mult = match unit {
        "" | "s" | "sec" | "second" | "seconds" => 1,
        "m" | "min" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        "month" | "months" => 2_629_800,
        "y" | "year" | "years" => 31_557_600,
        _ => return None,
    };
    Some(n * mult)
}

fn check_files(f: &HostFacts, out: &mut Vec<Finding>) {
    if let Some(fh) = &f.file_handles {
        let frac = fh.used_fraction().unwrap_or(0.0);
        let level = if frac > 0.9 {
            Level::Crit
        } else if frac > 0.75 {
            Level::Warn
        } else {
            Level::Ok
        };
        out.push(
            finding(
                "fs.file_handles",
                level,
                format!(
                    "{} of {} system file handles allocated ({:.0}%)",
                    fh.allocated,
                    fh.max,
                    frac * 100.0
                ),
            )
            .observed(json!({"file_handles": fh, "top_holders": f.procs.top_fd_holders}))
            .rationale("When the system file table fills, every open() fails (EMFILE/ENFILE) for every program at once."),
        );
    }
    if let Some(watches) = f.inotify_max_user_watches {
        let level = if watches < 65_536 {
            Level::Warn
        } else if watches < 524_288 {
            Level::Info
        } else {
            Level::Ok
        };
        let mut fnd = finding(
            "fs.inotify",
            level,
            format!(
                "fs.inotify.max_user_watches = {watches}, max_user_instances = {}",
                f.inotify_max_user_instances
                    .map_or("?".to_string(), |v| v.to_string())
            ),
        )
        .observed(json!({
            "max_user_watches": watches,
            "max_user_instances": f.inotify_max_user_instances,
        }))
        .recommended("524288 watches, 1024 instances")
        .rationale("File watchers of editors, dev servers and agents fail (\"no space left on device\") once the per-user inotify watch limit is reached; agent swarms run many of them.");
        if level >= Level::Info {
            fnd = fnd.commands(&[
                "sudo sysctl -w fs.inotify.max_user_watches=524288 fs.inotify.max_user_instances=1024",
                "printf 'fs.inotify.max_user_watches = 524288\\nfs.inotify.max_user_instances = 1024\\n' | sudo tee /etc/sysctl.d/90-inotify.conf",
            ]);
        }
        out.push(fnd);
    }
}

fn check_procs(f: &HostFacts, out: &mut Vec<Finding>) {
    let p = &f.procs;
    if p.zombies > 0 {
        let leaking: Vec<&ZombieParent> =
            p.zombie_parents.iter().filter(|z| z.zombies >= 5).collect();
        let level = if leaking.is_empty() {
            Level::Info
        } else {
            Level::Warn
        };
        let summary = match leaking.first() {
            Some(z) => format!(
                "{} zombies; {} (pid {}) has {} unreaped children",
                p.zombies,
                z.parent_comm.as_deref().unwrap_or("?"),
                z.ppid,
                z.zombies
            ),
            None => format!("{} zombie processes", p.zombies),
        };
        out.push(
            finding("procs.zombies", level, summary)
                .observed(json!({"zombie_parents": p.zombie_parents}))
                .rationale("Zombies hold only a PID, but a parent that never reaps its children leaks them until the PID space runs out; the fix is the parent (restart it), never the zombies."),
        );
    }
    if p.dstate > 0 {
        out.push(
            finding(
                "procs.dstate",
                if p.dstate >= 10 {
                    Level::Warn
                } else {
                    Level::Info
                },
                format!("{} processes in uninterruptible sleep (D state)", p.dstate),
            )
            .observed(json!({"dstate": p.dstate}))
            .rationale("Many D-state tasks mean storage or a filesystem is stalling; they cannot be killed until the I/O completes."),
        );
    }
}

fn check_pt(f: &HostFacts, out: &mut Vec<Finding>) {
    if !f.psi_available {
        out.push(
            finding(
                "pt.psi",
                Level::Info,
                "Pressure Stall Information (/proc/pressure) is unavailable: pt's pressure regimes fall back to load and memory figures",
            )
            .recommended("a kernel with CONFIG_PSI, booted with psi=1 where it defaults to off")
            .rationale("PSI measures how long tasks actually wait for CPU, memory and I/O; load average and memory use only hint at it.")
            .commands(&[
                "cat /proc/pressure/cpu",
                "grep -o 'psi=[01]' /proc/cmdline",
            ]),
        );
    }
    let Some(u) = &f.pt_sessions else {
        return;
    };
    let retention_off = u.retention.as_deref().is_some_and(|r| {
        matches!(
            r.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "never"
        )
    });
    let level = if u.sessions > 1000 || u.bytes > GIB {
        Level::Warn
    } else if retention_off && u.sessions > 200 {
        Level::Info
    } else {
        Level::Ok
    };
    let mut fnd = finding(
        "pt.sessions",
        level,
        format!(
            "{} pt sessions using {:.1} MiB in {} (retention: {})",
            u.sessions,
            u.bytes as f64 / (1u64 << 20) as f64,
            u.root,
            u.retention.as_deref().unwrap_or("default, 7 days")
        ),
    )
    .observed(json!(u))
    .rationale("Every `agent plan` leaves a session directory. Before automatic retention a dev box accumulated 3,017 of them (289 MB) from one test burst; retention (PROCESS_TRIAGE_RETENTION, default 7 days) now runs at most hourly when a session is created.");
    if level >= Level::Info {
        fnd = fnd.commands(&["pt agent sessions --cleanup --older-than 7d"]);
    }
    out.push(fnd);
}

fn check_deleted_open(f: &HostFacts, out: &mut Vec<Finding>) {
    let p = &f.procs;
    let Some(largest) = p.deleted_open.first() else {
        return;
    };
    let level = if p.deleted_open_bytes >= GIB {
        Level::Warn
    } else {
        Level::Info
    };
    out.push(
        finding(
            "disk.deleted_open_files",
            level,
            format!(
                "{} held by deleted files that are still open; largest: {} ({}) held by {} (pid {})",
                gib(p.deleted_open_bytes),
                largest.path,
                gib(largest.bytes),
                largest.comm,
                largest.pid
            ),
        )
        .observed(json!({"bytes": p.deleted_open_bytes, "largest": p.deleted_open}))
        .recommended("restart or stop the holding process to release the space")
        .rationale("A file deleted while a process holds it open keeps its disk space until the process closes it or exits: the classic \"disk full but du finds nothing\". Restarting the holder releases it; truncating through /proc also works but discards data the process may still use.")
        .commands(&[&format!("ls -l /proc/{}/fd | grep deleted", largest.pid)]),
    );
}

fn pressure_findings(a: &PressureAssessment, out: &mut Vec<Finding>) {
    for r in &a.regimes {
        // The swap check reports the paradox itself, with its safety condition and
        // command; the regime would only repeat it.
        if r.kind == RegimeKind::SwapParadox {
            continue;
        }
        let level = match r.severity {
            Severity::Ok => Level::Info,
            Severity::Warn => Level::Warn,
            Severity::Crit => Level::Crit,
        };
        let rationale = if r.kind == RegimeKind::CacheBloat {
            TRJ_CACHE_BLOAT
        } else {
            "Read now from PSI, load, /proc/meminfo, vmstat and the file table: the same assessment `agent plan` reports as system_state. A transient spike is not sustained; a sustained regime is worth acting on."
        };
        out.push(
            finding("pressure.regime", level, r.explanation.clone())
                .observed(json!({"kind": r.kind, "sustained": r.sustained}))
                .rationale(rationale),
        );
    }
}

/// Run every check over gathered facts and a pressure assessment.
pub fn audit(facts: &HostFacts, pressure: &PressureAssessment) -> Vec<Finding> {
    let mut out = Vec::new();
    pressure_findings(pressure, &mut out);
    let cache_bloat = pressure
        .regimes
        .iter()
        .any(|r| r.kind == RegimeKind::CacheBloat);
    check_vm(facts, cache_bloat, &mut out);
    check_swap(facts, &mut out);
    check_oomd(facts, &mut out);
    check_journald(facts, &mut out);
    check_files(facts, &mut out);
    check_procs(facts, &mut out);
    check_deleted_open(facts, &mut out);
    check_pt(facts, &mut out);
    out
}

/// The full read-only audit of the machine under `root`.
pub fn run_doctor_from(root: &Path, cpus: u32, clk_tck: u64) -> DoctorReport {
    run_doctor_with(root, cpus, clk_tck, None)
}

/// [`run_doctor_from`] plus pt's own session store.
pub fn run_doctor_with(
    root: &Path,
    cpus: u32,
    clk_tck: u64,
    sessions: Option<SessionUsage>,
) -> DoctorReport {
    let mut facts = read_host_facts_from(root, clk_tck);
    let snapshot = read_pressure_snapshot_from(root, cpus);
    facts.psi_available =
        snapshot.cpu.is_some() || snapshot.memory.is_some() || snapshot.io.is_some();
    facts.pt_sessions = sessions;
    let census = ProcessCensus {
        zombies: facts.procs.zombies,
        dstate: facts.procs.dstate,
    };
    let pressure = assess(
        &snapshot,
        None,
        Some(&census),
        &PressureThresholds::default(),
    );
    let findings = audit(&facts, &pressure);
    let worst = findings.iter().map(|f| f.level).max().unwrap_or(Level::Ok);
    DoctorReport {
        worst,
        pressure,
        findings,
        facts,
    }
}

/// The audit of this machine.
pub fn run_doctor() -> DoctorReport {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    // SAFETY: sysconf has no preconditions.
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let sessions = crate::session::SessionStore::from_env()
        .ok()
        .and_then(|store| {
            read_session_usage(
                store.sessions_root(),
                std::env::var("PROCESS_TRIAGE_RETENTION").ok(),
            )
        });
    let mut report = run_doctor_with(
        Path::new("/"),
        cpus,
        if tck > 0 { tck as u64 } else { 100 },
        sessions,
    );
    if !cfg!(target_os = "linux") {
        // The checks read /proc, sysctls and systemd files; elsewhere their absence would
        // read as findings ("oomd not running").
        report.findings = vec![finding(
            "platform",
            Level::Info,
            "pt doctor checks Linux hosts (/proc, sysctls, systemd); this platform is not covered yet",
        )];
        report.worst = Level::Info;
    }
    report
}

/// A shell script of the suggested commands, commented with their findings. It is
/// printed for review; pt never runs it.
pub fn fix_script(report: &DoctorReport) -> String {
    let mut s = String::from(
        "#!/bin/sh\n# Suggested by `pt doctor`. Review every line before running anything.\n# pt never runs these commands itself.\n",
    );
    for f in report.findings.iter().filter(|f| f.level >= Level::Info) {
        if f.commands.is_empty() {
            continue;
        }
        s.push_str(&format!("\n# [{:?}] {}: {}\n", f.level, f.id, f.summary));
        for c in &f.commands {
            s.push_str(c);
            s.push('\n');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A fake root with the files a test writes.
    struct Root(tempfile::TempDir);

    impl Root {
        fn new() -> Self {
            Root(tempfile::tempdir().unwrap())
        }
        fn path(&self) -> PathBuf {
            self.0.path().to_path_buf()
        }
        fn write(&self, rel: &str, text: &str) -> &Self {
            let p = self.0.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
            self
        }
        fn meminfo(&self, total_gib: u64, available_gib: u64) -> &Self {
            self.write(
                "proc/meminfo",
                &format!(
                    "MemTotal: {} kB\nMemFree: {} kB\nMemAvailable: {} kB\nCached: 1048576 kB\nSlab: 1048576 kB\nSReclaimable: 524288 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
                    total_gib * 1024 * 1024,
                    available_gib * 1024 * 1024,
                    available_gib * 1024 * 1024
                ),
            )
        }
        fn sysctl(&self, name: &str, value: u64) -> &Self {
            self.write(&format!("proc/sys/{name}"), &format!("{value}\n"))
        }
        fn proc(&self, pid: u32, comm: &str, state: char, ppid: u32) -> &Self {
            self.write(
                &format!("proc/{pid}/stat"),
                &format!("{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 1000 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"),
            )
        }
        fn report(&self) -> DoctorReport {
            run_doctor_from(&self.path(), 8, 100)
        }
    }

    fn find<'a>(r: &'a DoctorReport, id: &str) -> Option<&'a Finding> {
        r.findings.iter().find(|f| f.id == id)
    }

    /// hetzner1-like: tuned VM, persisted zram, oomd off. Nothing to warn about.
    fn healthy() -> Root {
        let root = Root::new();
        root.meminfo(64, 40)
            .sysctl("vm/vfs_cache_pressure", 200)
            .sysctl("vm/min_free_kbytes", 524_288)
            .sysctl("vm/swappiness", 10)
            .sysctl("vm/dirty_ratio", 20)
            .sysctl("vm/dirty_background_ratio", 10)
            .sysctl("fs/inotify/max_user_watches", 524_288)
            .sysctl("fs/inotify/max_user_instances", 1024)
            .write("proc/sys/fs/file-nr", "12000\t0\t9223372036854775807\n")
            .write("proc/mounts", "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n")
            .write(
                "proc/swaps",
                "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 16777212 1024 100\n",
            )
            .write(
                "etc/systemd/zram-generator.conf",
                "[zram0]\nzram-size = 16384\n",
            )
            .write("proc/uptime", "100000.0 50000.0\n")
            .write(
                "proc/pressure/cpu",
                "some avg10=0.10 avg60=0.05 avg300=0.01 total=1000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            )
            .write(
                "proc/pressure/memory",
                "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            )
            .write(
                "proc/pressure/io",
                "some avg10=0.20 avg60=0.10 avg300=0.05 total=2000\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=900\n",
            )
            .proc(1, "systemd", 'S', 0)
            .proc(400, "bash", 'S', 1);
        root
    }

    #[test]
    fn healthy_host_has_no_warnings() {
        let r = healthy().report();
        let loud: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.level >= Level::Warn)
            .collect();
        assert!(loud.is_empty(), "{loud:#?}");
        assert!(r.worst <= Level::Info);
        // oomd off is reported, not alarmed about.
        assert_eq!(find(&r, "oomd.running").unwrap().level, Level::Info);
    }

    #[test]
    fn trj_cache_tuning_on_large_btrfs_is_critical() {
        let root = healthy();
        root.meminfo(499, 100)
            .sysctl("vm/vfs_cache_pressure", 50)
            .sysctl("vm/min_free_kbytes", 65_536)
            .write(
                "proc/mounts",
                "/dev/nvme0n1p2 / btrfs rw 0 0\n/dev/nvme1n1 /data btrfs rw 0 0\n",
            );
        let r = root.report();
        let vfs = find(&r, "vm.vfs_cache_pressure").unwrap();
        assert_eq!(vfs.level, Level::Crit);
        assert!(vfs.rationale.contains("trj"), "{}", vfs.rationale);
        assert_eq!(vfs.recommended.as_deref(), Some("200"));
        assert!(vfs
            .commands
            .iter()
            .any(|c| c.contains("vfs_cache_pressure=200")));
        let mf = find(&r, "vm.min_free_kbytes").unwrap();
        assert_eq!(mf.level, Level::Warn, "64 MiB on 499 GiB (want 2 GiB)");
        assert_eq!(mf.recommended.as_deref(), Some("2097152"));
        assert_eq!(r.worst, Level::Crit);
    }

    #[test]
    fn missing_psi_is_reported_as_info() {
        let root = Root::new();
        root.meminfo(16, 8);
        assert_eq!(find(&root.report(), "pt.psi").unwrap().level, Level::Info);
        assert!(find(&healthy().report(), "pt.psi").is_none());
    }

    /// The 3,017-session burst: a store past 1000 sessions warns and suggests the
    /// cleanup command; a few hundred with retention switched off is worth knowing.
    #[test]
    fn session_store_growth_warns_and_suggests_cleanup() {
        let root = healthy();
        let store = tempfile::tempdir().unwrap();
        for i in 0..1001 {
            std::fs::create_dir(store.path().join(format!("pt-20260101-000000-{i:04}"))).unwrap();
        }
        std::fs::create_dir(store.path().join("not-a-session")).unwrap();
        let usage = read_session_usage(store.path(), None).unwrap();
        assert_eq!(usage.sessions, 1001);

        let r = run_doctor_with(&root.path(), 8, 100, Some(usage));
        let f = find(&r, "pt.sessions").unwrap();
        assert_eq!(f.level, Level::Warn);
        assert_eq!(
            f.commands,
            vec!["pt agent sessions --cleanup --older-than 7d"]
        );

        let unbounded = SessionUsage {
            sessions: 250,
            retention: Some("off".to_string()),
            ..SessionUsage::default()
        };
        let r = run_doctor_with(&root.path(), 8, 100, Some(unbounded));
        assert_eq!(find(&r, "pt.sessions").unwrap().level, Level::Info);

        let fine = SessionUsage {
            sessions: 40,
            ..SessionUsage::default()
        };
        let r = run_doctor_with(&root.path(), 8, 100, Some(fine));
        assert_eq!(find(&r, "pt.sessions").unwrap().level, Level::Ok);
    }

    /// With vm.dirty_bytes set the kernel reports dirty_ratio 0 (seen on a real build
    /// worker); the absolute limit is what bounds dirty cache.
    #[test]
    fn dirty_bytes_overrides_a_zero_dirty_ratio() {
        let root = healthy();
        root.sysctl("vm/dirty_ratio", 0)
            .sysctl("vm/dirty_bytes", GIB);
        let f = find(&root.report(), "vm.dirty_ratio").unwrap().clone();
        assert_eq!(f.level, Level::Ok);
        assert!(
            f.summary.contains("vm.dirty_bytes = 1.0 GiB"),
            "{}",
            f.summary
        );

        // A 40% ratio on 512 GiB is ~205 GiB of dirty cache: worth knowing.
        let root = healthy();
        root.meminfo(512, 400).sysctl("vm/dirty_ratio", 40);
        assert_eq!(
            find(&root.report(), "vm.dirty_ratio").unwrap().level,
            Level::Info
        );
    }

    #[test]
    fn min_free_table_follows_the_playbook() {
        assert_eq!(recommended_min_free_kbytes(15 * GIB), 256 * 1024);
        assert_eq!(recommended_min_free_kbytes(31 * GIB), 512 * 1024);
        assert_eq!(recommended_min_free_kbytes(58 * GIB), 512 * 1024);
        assert_eq!(recommended_min_free_kbytes(251 * GIB), 1024 * 1024);
        assert_eq!(recommended_min_free_kbytes(499 * GIB), 2048 * 1024);
    }

    #[test]
    fn later_infinity_drop_in_negating_a_limit_is_critical() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user-.slice.d/10-limit.conf",
            "[Slice]\nMemoryMax=80%\nMemoryHigh=70%\n",
        )
        .write(
            "usr/lib/systemd/system/user-.slice.d/99-defaults.conf",
            "[Slice]\nMemoryMax=infinity\n",
        );
        let r = root.report();
        let f = find(&r, "oomd.user_slice_limits").unwrap();
        assert_eq!(f.level, Level::Crit);
        assert!(f.summary.contains("10-limit.conf"), "{}", f.summary);
        assert!(f.summary.contains("99-defaults.conf"), "{}", f.summary);
        // MemoryHigh is not negated, so exactly one finding.
        assert_eq!(
            r.findings
                .iter()
                .filter(|f| f.id == "oomd.user_slice_limits")
                .count(),
            1
        );
    }

    #[test]
    fn limit_sorting_last_or_overridden_by_etc_is_fine() {
        let root = healthy();
        // The infinity sorts first, the limit last: effective limit holds.
        root.write(
            "usr/lib/systemd/system/user-.slice.d/05-defaults.conf",
            "[Slice]\nMemoryMax=infinity\n",
        )
        .write(
            "etc/systemd/system/user-.slice.d/50-limit.conf",
            "[Slice]\nMemoryMax=80%\n",
        )
        // Same file name in /usr/lib and /etc: /etc hides /usr/lib.
        .write(
            "usr/lib/systemd/system/user-.slice.d/90-x.conf",
            "[Slice]\nMemoryMax=infinity\n",
        )
        .write(
            "etc/systemd/system/user-.slice.d/90-x.conf",
            "[Slice]\nMemoryMax=75%\n",
        );
        let r = root.report();
        assert!(
            find(&r, "oomd.user_slice_limits").is_none(),
            "{:#?}",
            r.findings
        );
    }

    #[test]
    fn missing_swap_warns_and_unpersisted_zram_warns() {
        let root = healthy();
        root.write("proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n");
        let r = root.report();
        assert_eq!(find(&r, "swap.present").unwrap().level, Level::Warn);

        let root = Root::new();
        root.meminfo(32, 20).write(
            "proc/swaps",
            "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 8388604 0 100\n",
        );
        let r = root.report();
        assert_eq!(find(&r, "swap.zram_persisted").unwrap().level, Level::Warn);

        // A hand-written unit, enabled (this is how hetzner1 does it).
        root.write(
            "etc/systemd/system/multi-user.target.wants/zram-swap.service",
            "[Service]\nExecStart=/usr/local/sbin/zram-swap start\n",
        );
        assert!(find(&root.report(), "swap.zram_persisted").is_none());
    }

    /// The swap check owns the paradox finding; the regime does not repeat it.
    #[test]
    fn swap_paradox_reported_once() {
        let root = healthy();
        // 8 GiB of 32 GiB swap used, 200 of 256 GiB RAM available (meminfo is what the
        // regime classifier reads; /proc/swaps is what the swap check reads).
        root.write(
            "proc/meminfo",
            "MemTotal: 268435456 kB\nMemFree: 209715200 kB\nMemAvailable: 209715200 kB\nCached: 1048576 kB\nSwapTotal: 33554432 kB\nSwapFree: 25165824 kB\n",
        )
        .write(
            "proc/swaps",
            "Filename\tType\tSize\tUsed\tPriority\n/swapfile file 33554428 8388608 -2\n",
        );
        let r = root.report();
        assert!(
            r.pressure
                .regimes
                .iter()
                .any(|g| g.kind == RegimeKind::SwapParadox),
            "fixture must trigger the regime for this test to mean anything"
        );
        assert!(r
            .findings
            .iter()
            .all(|f| f.observed.get("kind") != Some(&json!("swap_paradox"))));
        assert_eq!(
            r.findings.iter().filter(|f| f.id == "swap.paradox").count(),
            1
        );
        assert!(r
            .findings
            .iter()
            .filter(|f| f.id == "pressure.regime")
            .all(|f| !f.rationale.is_empty()));
    }

    #[test]
    fn swap_paradox_only_when_available_ram_exceeds_twice_the_swapped() {
        let root = healthy();
        root.meminfo(256, 200).write(
            "proc/swaps",
            "Filename\tType\tSize\tUsed\tPriority\n/swapfile file 33554428 8388608 -2\n",
        );
        let r = root.report();
        let f = find(&r, "swap.paradox").unwrap();
        assert_eq!(f.level, Level::Warn);
        assert_eq!(f.commands, vec!["sudo swapoff -a && sudo swapon -a"]);

        // 8 GiB swapped, 12 GiB available: swapoff could itself exhaust memory.
        root.meminfo(256, 12);
        assert!(find(&root.report(), "swap.paradox").is_none());
    }

    #[test]
    fn volatile_journal_warns() {
        let root = healthy();
        root.write(
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        )
        .write(
            "etc/systemd/journald.conf.d/50-volatile.conf",
            "[Journal]\nStorage=volatile\n",
        );
        assert_eq!(
            find(&root.report(), "journald.retention").unwrap().level,
            Level::Warn
        );
        root.write(
            "etc/systemd/journald.conf.d/50-volatile.conf",
            "[Journal]\nMaxRetentionSec=6h\n",
        );
        assert_eq!(
            find(&root.report(), "journald.retention").unwrap().level,
            Level::Warn
        );
        assert_eq!(parse_systemd_seconds("2week"), Some(1_209_600));
        assert_eq!(parse_systemd_seconds("3600"), Some(3600));
    }

    #[test]
    fn zombie_leak_names_the_parent() {
        let root = healthy();
        root.proc(900, "leaky-server", 'S', 1);
        for pid in 901..913 {
            root.proc(pid, "worker", 'Z', 900);
        }
        root.proc(950, "other", 'Z', 400);
        let r = root.report();
        let f = find(&r, "procs.zombies").unwrap();
        assert_eq!(f.level, Level::Warn);
        assert!(
            f.summary.contains("leaky-server (pid 900) has 12"),
            "{}",
            f.summary
        );
        assert_eq!(r.facts.procs.zombies, 13);
        assert_eq!(
            r.facts.procs.zombie_parents[0].parent_age_seconds,
            Some(99_990)
        );
    }

    #[test]
    fn file_table_and_inotify_limits() {
        let root = healthy();
        root.write("proc/sys/fs/file-nr", "95000\t0\t100000\n")
            .sysctl("fs/inotify/max_user_watches", 8192);
        let r = root.report();
        assert_eq!(find(&r, "fs.file_handles").unwrap().level, Level::Crit);
        assert_eq!(find(&r, "fs.inotify").unwrap().level, Level::Warn);
    }

    /// Space held by deleted-but-open files: each file once, memfd skipped, the holder
    /// named. (A 2 GiB sparse file stands in for the open log.)
    #[cfg(unix)]
    #[test]
    fn deleted_open_files_are_found_and_counted_once() {
        use std::os::unix::fs::symlink;
        let root = healthy();
        root.proc(500, "logger", 'S', 1)
            .proc(501, "logger-child", 'S', 500);
        let held = root.path().join("var/log/app.log (deleted)");
        std::fs::create_dir_all(held.parent().unwrap()).unwrap();
        std::fs::File::create(&held)
            .unwrap()
            .set_len(2 * GIB)
            .unwrap();
        let kept = root.path().join("var/log/current.log");
        std::fs::write(&kept, "live").unwrap();
        for (pid, fd, target) in [
            (500, 3, held.clone()),
            (501, 4, held.clone()),
            (500, 5, PathBuf::from("/memfd:shm (deleted)")),
            (500, 6, kept.clone()),
        ] {
            let dir = root.path().join(format!("proc/{pid}/fd"));
            std::fs::create_dir_all(&dir).unwrap();
            symlink(&target, dir.join(fd.to_string())).unwrap();
        }

        let r = root.report();
        assert_eq!(r.facts.procs.deleted_open_bytes, 2 * GIB);
        assert_eq!(r.facts.procs.deleted_open.len(), 1);
        let f = find(&r, "disk.deleted_open_files").unwrap();
        assert_eq!(f.level, Level::Warn);
        assert!(f.summary.contains("app.log"), "{}", f.summary);
        assert!(f.summary.contains("(pid 500)"), "{}", f.summary);
        assert_eq!(f.commands, vec!["ls -l /proc/500/fd | grep deleted"]);
    }

    #[test]
    fn oomd_seen_in_the_process_table() {
        let root = healthy();
        root.proc(300, "systemd-oomd", 'S', 1);
        assert_eq!(
            find(&root.report(), "oomd.running").unwrap().level,
            Level::Ok
        );
    }

    #[test]
    fn stat_with_spaces_and_parens_in_comm() {
        let (pid, comm, state, ppid, _) =
            parse_stat("77 (tmux: server (x)) Z 12 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0")
                .unwrap();
        assert_eq!(
            (pid, comm.as_str(), state, ppid),
            (77, "tmux: server (x)", 'Z', 12)
        );
    }

    /// The audit reads only: a read-only root works and is left unchanged.
    #[cfg(unix)]
    #[test]
    fn audit_never_writes() {
        use std::os::unix::fs::PermissionsExt;
        let root = healthy();
        let listing = |p: &Path| {
            let mut v: Vec<String> = walk(p);
            v.sort();
            v
        };
        fn walk(p: &Path) -> Vec<String> {
            let mut out = Vec::new();
            for e in std::fs::read_dir(p).unwrap().flatten() {
                let path = e.path();
                out.push(format!(
                    "{} {}",
                    path.display(),
                    std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
                ));
                if path.is_dir() {
                    out.extend(walk(&path));
                }
            }
            out
        }
        let before = listing(&root.path());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = root.report();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!r.findings.is_empty());
        assert_eq!(before, listing(&root.path()));
    }

    #[test]
    fn fix_script_prints_commands_and_never_claims_to_run_them() {
        let root = healthy();
        root.sysctl("vm/vfs_cache_pressure", 50);
        let script = fix_script(&root.report());
        assert!(script.contains("never runs"));
        assert!(script.contains("vm.vfs_cache_pressure=200"));
        assert!(script.starts_with("#!/bin/sh"));
    }
}
