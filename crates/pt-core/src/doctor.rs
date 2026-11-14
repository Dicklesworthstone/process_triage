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
//! check is testable against recorded files. Live filesystem checks also inspect
//! kernel capacity and a read-only process census. Suggested remedies are never
//! run: commands are printed for a person to review ([`fix_script`]).

use crate::collect::disk::DiskResourceSnapshot;
use crate::collect::pressure::{
    parse_file_nr, parse_meminfo, read_pressure_snapshot_from, FileHandles, MemInfo,
};
use crate::decision::pressure_regime::{
    assess, PressureAssessment, PressureThresholds, ProcessCensus, RegimeKind, Severity,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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

/// Memory-limit assignments from a unit file or a selected drop-in.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DropIn {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_high: Option<String>,
}

/// On-disk memory configuration for an actual user unit, or its defaults when no
/// user instances can be found. These are the unit's own settings: parent cgroup
/// limits and the running manager's state may differ from the files on disk.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UserMemoryConfig {
    pub unit: String,
    pub defaults_only: bool,
    pub masked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_path: Option<String>,
    /// Ordered assignments: the selected fragment first, then sorted drop-ins.
    /// A source may appear repeatedly when it assigns several memory settings.
    pub sources: Vec<DropIn>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub masked_drop_ins: Vec<String>,
    /// Final configured values, absent when masked or inspection is incomplete.
    pub memory_max: Option<String>,
    pub memory_high: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,
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
    /// Allocated bytes of deleted regular files still open (each inode counted once).
    pub deleted_open_bytes: u64,
    /// Logical file lengths; sparse files may have much less allocated storage.
    pub deleted_open_logical_bytes: u64,
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
    /// Allocated storage observed through the open descriptor, not measured relief.
    pub bytes: u64,
    pub logical_bytes: u64,
}

/// Deleted regular files among the open descriptors in `fd_dir`, as `(path, bytes,
/// (dev, inode))`. memfd and /dev (tmpfs/shm) objects hold memory, not disk, and are
/// skipped.
fn deleted_open_files(
    fd_dir: &[std::fs::DirEntry],
    #[cfg(target_os = "linux")] filesystems: Option<&crate::collect::procfs::FilesystemGuard>,
) -> Vec<(String, u64, u64, (u64, u64))> {
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
        // Inspect the held inode only after its kernel mount identity is known
        // to be local. A direct stat can itself wait on a stalled FUSE server.
        #[cfg(target_os = "linux")]
        let meta = {
            use std::os::unix::fs::OpenOptionsExt;
            let Some(filesystems) = filesystems else {
                continue;
            };
            let Ok(file) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(fd.path())
            else {
                continue;
            };
            if !filesystems.permits(&file) {
                continue;
            }
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            metadata
        };
        #[cfg(not(target_os = "linux"))]
        let Ok(meta) = std::fs::metadata(fd.path()) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        let (bytes, key) = {
            use std::os::unix::fs::MetadataExt;
            (meta.blocks().saturating_mul(512), (meta.dev(), meta.ino()))
        };
        #[cfg(not(unix))]
        let (bytes, key) = (0, (0, 0));
        out.push((path.to_string(), bytes, meta.len(), key));
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
    pub user_memory: Vec<UserMemoryConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_memory_unavailable: Vec<String>,
    pub journald: JournaldConf,
    pub file_handles: Option<FileHandles>,
    pub inotify_max_user_watches: Option<u64>,
    pub inotify_max_user_instances: Option<u64>,
    pub procs: ProcTable,
    /// Live filesystem capacity and deleted-file holder evidence. Capacity
    /// remains independently useful when complete ownership is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskResourceSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_error: Option<String>,
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
    let mut continued = String::new();
    let mut parse_line = |line: &str| {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
        } else if let Some((key, value)) = line.split_once('=') {
            out.push((
                section.clone(),
                key.trim().to_string(),
                value.trim().to_string(),
            ));
        }
    };
    for physical_line in text.lines() {
        let line = physical_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(prefix) = line.strip_suffix('\\') {
            continued.push_str(prefix);
            continued.push(' ');
            continue;
        }
        continued.push_str(line);
        parse_line(&continued);
        continued.clear();
    }
    if !continued.is_empty() {
        parse_line(&continued);
    }
    out
}

// Highest precedence first, as documented by systemd.unit(5). /lib is the
// legacy vendor location; on merged-/usr systems it aliases /usr/lib.
const SYSTEM_UNIT_PATHS: &[&str] = &[
    "etc/systemd/system.control",
    "run/systemd/system.control",
    "run/systemd/transient",
    "run/systemd/generator.early",
    "etc/systemd/system",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.attached",
    "run/systemd/generator",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "run/systemd/generator.late",
];

/// Validate directory traversal before inspecting an alternate root. A fixture's
/// absolute symlink must never make its audit read the evaluator's live host.
fn config_directory(root: &Path, rel: &str, unavailable: &mut Vec<String>) -> Option<PathBuf> {
    let path = root.join(rel);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            unavailable.push(format!("/{rel}: {error}"));
            return None;
        }
        Ok(_) => {}
    }
    match std::fs::canonicalize(&path).and_then(|resolved| {
        let root = std::fs::canonicalize(root)?;
        if resolved.starts_with(root) && resolved.is_dir() {
            Ok(path)
        } else {
            Err(std::io::Error::other(
                "configuration directory leaves the inspected root or is not a directory",
            ))
        }
    }) {
        Ok(path) => Some(path),
        Err(error) => {
            unavailable.push(format!("/{rel}: {error}"));
            None
        }
    }
}

fn user_unit_uid(name: &str) -> Option<u32> {
    let name = name.strip_suffix(".d").unwrap_or(name);
    let digits = name
        .strip_prefix("user-")
        .and_then(|rest| rest.strip_suffix(".slice"))
        .or_else(|| {
            name.strip_prefix("user@")
                .and_then(|rest| rest.strip_suffix(".service"))
        })?;
    let uid = digits.parse::<u32>().ok()?;
    (uid.to_string() == digits).then_some(uid)
}

fn read_user_memory_configs(root: &Path) -> (Vec<UserMemoryConfig>, Vec<String>) {
    let mut unavailable = Vec::new();
    let mut uids = BTreeSet::new();
    // logind keeps one state file per live user. Configured instances are also
    // useful when that user is logged out, including systemctl set-property.
    for rel in std::iter::once("run/systemd/users").chain(SYSTEM_UNIT_PATHS.iter().copied()) {
        let Some(dir) = config_directory(root, rel, &mut unavailable) else {
            continue;
        };
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            unavailable.push(format!("/{rel}: {error}"));
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    let uid = if rel == "run/systemd/users" {
                        name.parse::<u32>()
                            .ok()
                            .filter(|uid| uid.to_string() == name)
                    } else {
                        user_unit_uid(name)
                    };
                    if let Some(uid) = uid {
                        uids.insert(uid);
                    }
                }
            }
            Err(error) => unavailable.push(format!("/{rel}: {error}")),
        }
    }
    let mut units = Vec::new();
    if uids.is_empty() {
        // Retain the useful defaults audit on hosts without a logged-in user,
        // while explicitly distinguishing it from an instantiated unit.
        for unit in ["user-.slice", "user@.service"] {
            let mut config = read_user_memory_config(root, unit, true);
            if !unavailable.is_empty() {
                config.unavailable.extend(unavailable.iter().cloned());
                config.memory_max = None;
                config.memory_high = None;
            }
            units.push(config);
        }
    } else {
        for uid in uids {
            for unit in [format!("user-{uid}.slice"), format!("user@{uid}.service")] {
                units.push(read_user_memory_config(root, &unit, false));
            }
        }
    }
    (units, unavailable)
}

/// A conservative subset of systemd's size syntax. None means the static audit
/// cannot establish this assignment's meaning, not that it is unlimited.
fn finite_memory_limit(value: &str) -> Option<bool> {
    if value.is_empty() || value == "infinity" {
        return Some(false);
    }
    let (number, scale, percentage) = if let Some(number) = value.strip_suffix('%') {
        (number, 100_u128, true)
    } else {
        let suffix = value.as_bytes().last().copied()?;
        match b"KMGTPE".iter().position(|candidate| *candidate == suffix) {
            Some(index) => (
                &value[..value.len() - 1],
                1024_u128.pow(index as u32 + 1),
                false,
            ),
            None => (value, 1, false),
        }
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 18
        || (number.contains('.') && fraction.is_empty())
        || (percentage && fraction.len() > 2)
    {
        return None;
    }
    let divisor = 10_u128.checked_pow(fraction.len() as u32)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>().ok()?
    };
    let scaled = whole
        .parse::<u128>()
        .ok()?
        .checked_mul(scale)?
        .checked_add(fraction.checked_mul(scale)? / divisor)?;
    if percentage {
        (scaled > 0 && scaled <= 10_000).then_some(true)
    } else {
        (scaled > 0 && scaled < u128::from(u64::MAX)).then_some(true)
    }
}

fn memory_config_file(
    root: &Path,
    path: &Path,
    section: &str,
    unavailable: &mut Vec<String>,
) -> Vec<DropIn> {
    let display = format!("/{}", path.strip_prefix(root).unwrap_or(path).display());
    let result = (|| {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            if std::fs::read_link(path)? == Path::new("/dev/null") {
                return Ok(None);
            }
            // Aliases have their own drop-in hierarchy. Do not interpret their
            // target as a plain fragment or follow fixture links out of root.
            return Err(std::io::Error::other(
                "non-mask symlink needs systemd alias/link resolution",
            ));
        }
        if !metadata.is_file() {
            return Err(std::io::Error::other("configuration is not a regular file"));
        }
        let text = std::fs::read_to_string(path)?;
        Ok(Some(text))
    })();
    let text = match result {
        Ok(Some(text)) => text,
        Ok(None) => return Vec::new(),
        Err(error) => {
            unavailable.push(format!("{display}: {error}"));
            return Vec::new();
        }
    };
    let mut assignments = Vec::new();
    for (actual_section, key, value) in parse_ini(&text) {
        if actual_section != section || !matches!(key.as_str(), "MemoryMax" | "MemoryHigh") {
            continue;
        }
        if finite_memory_limit(&value).is_none() {
            unavailable.push(format!(
                "{display}: {key}={value:?} cannot be resolved by the static memory-limit audit"
            ));
        }
        let mut assignment = DropIn {
            path: display.clone(),
            ..DropIn::default()
        };
        match key.as_str() {
            "MemoryMax" => assignment.memory_max = Some(value),
            "MemoryHigh" => assignment.memory_high = Some(value),
            _ => unreachable!(),
        }
        assignments.push(assignment);
    }
    assignments
}

fn config_file_is_masked(metadata: &std::fs::Metadata, path: &Path) -> bool {
    (metadata.is_file() && metadata.len() == 0)
        || (metadata.file_type().is_symlink()
            && std::fs::read_link(path).ok().as_deref() == Some(Path::new("/dev/null")))
}

fn read_user_memory_config(root: &Path, unit: &str, defaults_only: bool) -> UserMemoryConfig {
    let mut result = UserMemoryConfig {
        unit: unit.into(),
        defaults_only,
        ..UserMemoryConfig::default()
    };
    let (section, type_name, generic) = if unit.ends_with(".slice") {
        ("Slice", "slice", "user-.slice")
    } else {
        ("Service", "service", "user@.service")
    };
    let names = if unit == generic {
        vec![unit]
    } else {
        vec![unit, generic]
    };

    // A literal instance fragment wins over its template across the whole load
    // path. Prefix slice names contribute drop-ins only, never base fragments.
    let fragment_count = if type_name == "service" {
        names.len()
    } else {
        1
    };
    'fragment: for name in names.iter().take(fragment_count) {
        for base in SYSTEM_UNIT_PATHS {
            let Some(dir) = config_directory(root, base, &mut result.unavailable) else {
                continue;
            };
            let path = dir.join(name);
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    result
                        .unavailable
                        .push(format!("{}: {error}", path.display()));
                    break 'fragment;
                }
            };
            result.fragment_path = Some(format!(
                "/{}",
                path.strip_prefix(root).unwrap_or(&path).display()
            ));
            if config_file_is_masked(&metadata, &path) {
                result.masked = true;
                return result;
            }
            result.sources.extend(memory_config_file(
                root,
                &path,
                section,
                &mut result.unavailable,
            ));
            break 'fragment;
        }
    }

    let mut by_name = BTreeMap::new();
    // systemd's src/shared/dropin.c searches load paths before expanding each
    // instance/template/prefix name. Type-wide defaults come after ALL names.
    let dirs = SYSTEM_UNIT_PATHS
        .iter()
        .flat_map(|base| names.iter().map(move |name| format!("{base}/{name}.d")))
        .chain(
            SYSTEM_UNIT_PATHS
                .iter()
                .map(|base| format!("{base}/{type_name}.d")),
        );
    for rel in dirs {
        let Some(dir) = config_directory(root, &rel, &mut result.unavailable) else {
            continue;
        };
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => {
                result.unavailable.push(format!("/{rel}: {error}"));
                continue;
            }
        };
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    // systemd ignores hidden drop-ins, including names which
                    // cannot be represented as UTF-8.
                    if name.as_encoded_bytes().starts_with(b".") {
                        continue;
                    }
                    match name.to_str() {
                        Some(text) if text.ends_with(".conf") => {
                            // A /dev/null or empty-file mask occupies its name too.
                            by_name.entry(name).or_insert_with(|| entry.path());
                        }
                        Some(_) => {}
                        None => result.unavailable.push(format!(
                            "/{rel}: a drop-in filename is not valid UTF-8"
                        )),
                    }
                }
                Err(error) => result.unavailable.push(format!("/{rel}: {error}")),
            }
        }
    }
    for path in by_name.into_values() {
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|metadata| config_file_is_masked(&metadata, &path))
        {
            result.masked_drop_ins.push(format!(
                "/{}",
                path.strip_prefix(root).unwrap_or(&path).display()
            ));
            continue;
        }
        result.sources.extend(memory_config_file(
            root,
            &path,
            section,
            &mut result.unavailable,
        ));
    }
    if result.unavailable.is_empty() {
        result.memory_max = Some("infinity".into());
        result.memory_high = Some("infinity".into());
        for source in &result.sources {
            if let Some(value) = &source.memory_max {
                result.memory_max = Some(if value.is_empty() { "infinity" } else { value }.into());
            }
            if let Some(value) = &source.memory_high {
                result.memory_high = Some(if value.is_empty() { "infinity" } else { value }.into());
            }
        }
    }
    result
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
    #[cfg(target_os = "linux")]
    let filesystems = crate::collect::procfs::FilesystemGuard::load().ok();
    let Ok(entries) = std::fs::read_dir(root.join("proc")) else {
        return table;
    };
    // Pick the same representative for a shared inode independently of read_dir order.
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_unstable_by_key(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .unwrap_or(u32::MAX)
    });
    for entry in entries {
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
            #[cfg(target_os = "linux")]
            let held_files = deleted_open_files(&fds, filesystems.as_ref());
            #[cfg(not(target_os = "linux"))]
            let held_files = deleted_open_files(&fds);
            for (path, bytes, logical_bytes, key) in held_files {
                if seen_deleted.insert(key) {
                    deleted.push(DeletedOpenFile {
                        pid,
                        comm: comm.clone(),
                        path,
                        bytes,
                        logical_bytes,
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
    table.deleted_open_logical_bytes = deleted.iter().map(|d| d.logical_bytes).sum();
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
    let (user_memory, user_memory_unavailable) = read_user_memory_configs(root);
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
        user_memory,
        user_memory_unavailable,
        journald: journald_conf(root),
        file_handles: read_text(root, "proc/sys/fs/file-nr").and_then(|t| parse_file_nr(&t)),
        inotify_max_user_watches: read_u64(root, "proc/sys/fs/inotify/max_user_watches"),
        inotify_max_user_instances: read_u64(root, "proc/sys/fs/inotify/max_user_instances"),
        procs: read_proc_table(root, clk_tck),
        disk: None,
        disk_error: None,
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
fn check_negated_limits(id: &'static str, config: &UserMemoryConfig, out: &mut Vec<Finding>) {
    let unit = &config.unit;
    if !config.unavailable.is_empty() {
        out.push(
            finding(
                id,
                Level::Info,
                format!("{unit}: on-disk memory limits are unavailable or incomplete"),
            )
            .observed(json!({"configuration": config}))
            .rationale("An unreadable file, alias or unsupported assignment cannot establish the final unit configuration. This audit does not infer the running manager's limits from incomplete files.")
            .commands(&[
                &format!("systemctl cat {unit}"),
                &format!("systemctl show {unit} -p MemoryMax -p MemoryHigh -p EffectiveMemoryMax -p EffectiveMemoryHigh"),
            ]),
        );
        return;
    }
    if config.masked {
        return;
    }
    for (key, pick) in [
        (
            "MemoryMax",
            (|d: &DropIn| d.memory_max.clone()) as fn(&DropIn) -> Option<String>,
        ),
        ("MemoryHigh", |d: &DropIn| d.memory_high.clone()),
    ] {
        let settings: Vec<(&DropIn, String)> = config
            .sources
            .iter()
            .filter_map(|d| pick(d).map(|v| (d, v)))
            .collect();
        let Some((last, last_value)) = settings.last() else {
            continue;
        };
        // Only the final assignment matters. An intermediate reset followed
        // by another finite limit is not a loss of configured protection.
        if finite_memory_limit(last_value) != Some(false) {
            continue;
        }
        if let Some((first, first_value)) = settings
            .iter()
            .find(|(_, value)| finite_memory_limit(value) == Some(true))
        {
            let scope = if config.defaults_only { " defaults" } else { "" };
            out.push(
                finding(
                    id,
                    Level::Crit,
                    format!(
                        "{unit}{scope}: {key}={first_value} in {} is negated by the final {key}={} in {}",
                        first.path,
                        if last_value.is_empty() { "(reset)" } else { last_value.as_str() },
                        last.path
                    ),
                )
                .observed(json!({"configuration": config, "setting": key, "final_value": "infinity"}))
                .recommended(format!("review the final {key} assignment and restore the intended limit for {unit}"))
                .rationale("systemd applies the selected unit fragment and then drop-ins in file-name order. A final infinity or empty reset removes this unit's configured memory limit; parent limits may still apply, and running values need separate verification.")
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
    if !f.user_memory_unavailable.is_empty() {
        out.push(
            finding("oomd.user_units", Level::Info, "User-unit discovery is incomplete")
                .observed(json!({"unavailable": f.user_memory_unavailable}))
                .rationale("Some user units or configuration directories could not be inspected; unobserved instances are not assumed to have memory limits."),
        );
    }
    for config in &f.user_memory {
        let id = if config.unit.ends_with(".slice") {
            "oomd.user_slice_limits"
        } else {
            "oomd.user_manager_limits"
        };
        check_negated_limits(id, config, out);
    }
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
                "{} allocated to deleted files that are still open ({} logical); largest: {} ({}) held by {} (pid {})",
                gib(p.deleted_open_bytes),
                gib(p.deleted_open_logical_bytes),
                largest.path,
                gib(largest.bytes),
                largest.comm,
                largest.pid
            ),
        )
        .observed(json!({"bytes": p.deleted_open_bytes, "logical_bytes": p.deleted_open_logical_bytes, "largest": p.deleted_open}))
        .recommended("inspect all holders before restarting or stopping processes")
        .rationale("Deleted regular files remain open until every holder closes its descriptors. Allocated blocks can be much smaller than logical length for sparse files; the reported allocation is potential reclaim, not measured freed space. The named process is one representative and other processes may hold the same inode.")
        .commands(&[&format!("ls -l /proc/{}/fd | grep deleted", largest.pid)]),
    );
}

fn check_disk_space(f: &HostFacts, out: &mut Vec<Finding>) {
    if let Some(error) = &f.disk_error {
        out.push(
            finding(
                "disk.observation_unavailable",
                Level::Info,
                "The process census for deleted-file ownership could not be collected",
            )
            .observed(json!({"error": error}))
            .rationale("An unavailable process observation cannot establish zero allocation or exclusive ownership. Independently valid filesystem capacity readings remain available."),
        );
    }
    let Some(snapshot) = &f.disk else {
        return;
    };
    for mount in &snapshot.mounts {
        if mount.validate_capacity().is_err() {
            continue;
        }
        let Some((total, available)) = mount.total_bytes.zip(mount.available_bytes) else {
            continue;
        };
        let available_percent = 100.0 * available as f64 / total as f64;
        let allocated = mount.deleted_allocated_bytes.unwrap_or(0);
        let level = if u128::from(available) * 100 <= u128::from(total) * 5 {
            Level::Crit
        } else if u128::from(available) * 100 <= u128::from(total) * 10 {
            Level::Warn
        } else if allocated > 0 {
            Level::Info
        } else {
            continue;
        };
        let key = mount.identity.key();
        let mut files: Vec<_> = snapshot
            .files
            .iter()
            .filter(|file| file.mount_keys.contains(&key))
            .collect();
        files.sort_by(|left, right| {
            right
                .allocated_bytes
                .unwrap_or(0)
                .cmp(&left.allocated_bytes.unwrap_or(0))
                .then(left.id.cmp(&right.id))
        });
        let observed_files = files.len();
        files.truncate(10);
        let allocation_detail = mount
            .deleted_allocated_bytes
            .map(|bytes| format!("; {} allocated to observed deleted files", gib(bytes)))
            .unwrap_or_else(|| "; deleted-file allocation is unavailable".into());
        out.push(
            finding(
                "disk.filesystem_space",
                level,
                format!(
                    "{}: {available_percent:.1}% available ({} of {}){allocation_detail}",
                    mount.mount_point.escape_debug(),
                    gib(available),
                    gib(total),
                ),
            )
            .observed(json!({
                "mount": mount,
                "available_percent": available_percent,
                "ownership_complete": mount.ownership_complete,
                "largest_deleted_files": files,
                "omitted_deleted_files": observed_files.saturating_sub(10),
                "allocation_scope": "observed_deleted_inodes_not_guaranteed_recovery",
            }))
            .recommended("Inspect the holders and other writers on this filesystem before choosing a process action")
            .rationale("Capacity uses filesystem blocks available to the current user. Deleted files retain allocation until every descriptor and mapping is released. Shared holders and incomplete observations do not establish exclusive recovery; other filesystem activity can change the actual space available."),
        );
    }
    if !snapshot.complete || !snapshot.diagnostics.is_empty() || snapshot.omitted_diagnostics > 0 {
        out.push(
            finding(
                "disk.ownership_incomplete",
                Level::Info,
                "Some disk ownership observations are unavailable; complete recovery forecasts may be unavailable",
            )
            .observed(json!({
                "complete": snapshot.complete,
                "diagnostics": snapshot.diagnostics,
                "omitted_diagnostics": snapshot.omitted_diagnostics,
            }))
            .rationale("Permission failures, process changes, inspection limits, or unsupported filesystems remain unknown. Independently valid capacity readings still identify full filesystems."),
        );
    }
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
    check_disk_space(facts, &mut out);
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
    // Fixtures supply typed disk observations to audit() directly. Never use
    // the evaluator's live filesystems while inspecting an alternate root.
    #[cfg(target_os = "linux")]
    if root == Path::new("/") {
        match crate::collect::quick_scan(&crate::collect::QuickScanOptions::default()) {
            Ok(scan) => {
                let mut disk = crate::collect::disk::collect_disk_resources(&scan.processes);
                if !scan.metadata.warnings.is_empty() {
                    disk.mark_census_incomplete();
                }
                facts.disk = Some(disk);
            }
            Err(error) => {
                let mut disk = crate::collect::disk::collect_disk_resources(&[]);
                disk.mark_census_incomplete();
                facts.disk = Some(disk);
                facts.disk_error = Some(error.to_string());
            }
        }
    }
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
        assert!(
            r.facts.disk.is_none(),
            "fixture roots must not inspect live mounts"
        );
        assert!(r.facts.disk_error.is_none());
        // oomd off is reported, not alarmed about.
        assert_eq!(find(&r, "oomd.running").unwrap().level, Level::Info);
    }

    fn disk_mount(id: u64, available: u64) -> crate::collect::disk::DiskMountObservation {
        use crate::collect::disk::{DiskMountIdentity, DiskMountObservation};
        DiskMountObservation {
            identity: DiskMountIdentity {
                boot_id: "11111111-1111-4111-8111-111111111111".into(),
                mount_namespace_device: 1,
                mount_namespace_inode: 2,
                mount_id: id,
                device_major: 8,
                device_minor: id as u32,
                filesystem_type: "ext4".into(),
                mount_root_sha256: "1".repeat(64),
                mount_source_sha256: "2".repeat(64),
                mount_options_sha256: "3".repeat(64),
            },
            mount_point: format!("/disk-{id}"),
            total_bytes: Some(1000),
            free_bytes: Some(available),
            available_bytes: Some(available),
            deleted_allocated_bytes: Some(0),
            known_holder_count: Some(0),
            ownership_complete: true,
            ..DiskMountObservation::default()
        }
    }

    #[test]
    fn disk_capacity_thresholds_use_available_space_and_keep_mounts_separate() {
        let mut report = healthy().report();
        report.facts.disk = Some(DiskResourceSnapshot {
            mounts: vec![
                disk_mount(1, 50),
                disk_mount(2, 51),
                disk_mount(3, 100),
                disk_mount(4, 101),
            ],
            complete: true,
            ..DiskResourceSnapshot::default()
        });
        // Reserved blocks do not make space available to the observing user.
        report.facts.disk.as_mut().unwrap().mounts[0].free_bytes = Some(900);
        let findings = audit(&report.facts, &report.pressure);
        let disk: Vec<_> = findings
            .iter()
            .filter(|finding| finding.id == "disk.filesystem_space")
            .collect();
        assert_eq!(disk.len(), 3);
        for (finding, id, level) in [
            (disk[0], 1, Level::Crit),
            (disk[1], 2, Level::Warn),
            (disk[2], 3, Level::Warn),
        ] {
            assert_eq!(finding.level, level);
            assert_eq!(finding.observed["mount"]["identity"]["mount_id"], id);
            assert!(finding.commands.is_empty());
        }
    }

    #[test]
    fn disk_findings_preserve_shared_holders_and_observation_scope() {
        use crate::collect::disk::DeletedFileObservation;
        use pt_common::{ProcessIdentity, StartId};
        let mut mount = disk_mount(1, 50);
        mount.deleted_allocated_bytes = Some(80);
        mount.known_holder_count = Some(2);
        let shared = DeletedFileObservation {
            id: "shared-inode".into(),
            allocated_bytes: Some(80),
            logical_bytes: Some(10_000),
            unlinked: Some(true),
            holders: [500, 501]
                .into_iter()
                .map(|pid| {
                    ProcessIdentity::new(
                        pid,
                        StartId::from_linux(&mount.identity.boot_id, 1000, pid),
                        1000,
                    )
                })
                .collect(),
            mount_keys: vec![mount.identity.key()],
            allocation_stable: true,
            holders_complete: true,
            ..DeletedFileObservation::default()
        };
        let other = disk_mount(2, 20);
        let unrelated = DeletedFileObservation {
            id: "another-mount-inode".into(),
            allocated_bytes: Some(100),
            mount_keys: vec![other.identity.key()],
            ..DeletedFileObservation::default()
        };
        let facts = HostFacts {
            disk: Some(DiskResourceSnapshot {
                mounts: vec![mount, other],
                files: vec![shared, unrelated],
                complete: true,
                ..DiskResourceSnapshot::default()
            }),
            ..HostFacts::default()
        };
        let mut findings = Vec::new();
        check_disk_space(&facts, &mut findings);
        assert_eq!(findings.len(), 2);
        let finding = &findings[0];
        assert_eq!(finding.observed["mount"]["deleted_allocated_bytes"], 80);
        assert_eq!(
            finding.observed["largest_deleted_files"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            finding.observed["largest_deleted_files"][0]["id"],
            "shared-inode"
        );
        assert_eq!(
            finding.observed["largest_deleted_files"][0]["holders"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            finding.observed["allocation_scope"],
            "observed_deleted_inodes_not_guaranteed_recovery"
        );
        assert!(finding.rationale.contains("every descriptor and mapping"));
        assert!(finding.commands.is_empty());
    }

    #[test]
    fn disk_capacity_remains_useful_when_ownership_or_other_mounts_are_unknown() {
        let mut invalid = disk_mount(2, 0);
        invalid.available_bytes = None;
        invalid.error = Some("disk_capacity_unavailable".into());
        let mut snapshot = DiskResourceSnapshot {
            mounts: vec![disk_mount(1, 50), invalid],
            complete: true,
            ..DiskResourceSnapshot::default()
        };
        snapshot.mark_census_incomplete();
        let facts = HostFacts {
            disk: Some(snapshot),
            disk_error: Some("process census unavailable".into()),
            ..HostFacts::default()
        };
        let mut findings = Vec::new();
        check_disk_space(&facts, &mut findings);
        let disk: Vec<_> = findings
            .iter()
            .filter(|finding| finding.id == "disk.filesystem_space")
            .collect();
        assert_eq!(
            disk.len(),
            1,
            "unknown capacity is not observed zero available space"
        );
        assert_eq!(disk[0].level, Level::Crit);
        assert_eq!(disk[0].observed["ownership_complete"], false);
        assert!(findings
            .iter()
            .any(|finding| finding.id == "disk.ownership_incomplete"));
        assert!(findings
            .iter()
            .any(|finding| finding.id == "disk.observation_unavailable"));
        assert!(findings.iter().all(|finding| finding.commands.is_empty()));
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

    fn user_memory<'a>(report: &'a DoctorReport, unit: &str) -> &'a UserMemoryConfig {
        report
            .facts
            .user_memory
            .iter()
            .find(|config| config.unit == unit)
            .unwrap_or_else(|| panic!("missing memory configuration for {unit}"))
    }

    #[test]
    fn actual_user_instances_report_only_the_unit_whose_limit_is_removed() {
        let root = healthy();
        root.write("run/systemd/users/1000", "UID=1000\n")
            .write("run/systemd/users/1001", "UID=1001\n")
            .write(
                "etc/systemd/system/user-.slice.d/10-limit.conf",
                "[Slice]\nMemoryMax=80%\nMemoryHigh=70%\n",
            )
            .write(
                "etc/systemd/system/user-1000.slice.d/90-unbounded.conf",
                "[Slice]\nMemoryMax=infinity\n",
            )
            .write(
                "etc/systemd/system/user-1001.slice.d/90-local.conf",
                "[Slice]\nMemoryMax=60%\n",
            );
        let report = root.report();
        let failures: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.id == "oomd.user_slice_limits")
            .collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].level, Level::Crit);
        assert!(failures[0].summary.starts_with("user-1000.slice:"));
        assert_eq!(
            failures[0].commands,
            vec!["systemctl cat user-1000.slice"]
        );
        let affected = user_memory(&report, "user-1000.slice");
        assert!(!affected.defaults_only);
        assert_eq!(affected.memory_max.as_deref(), Some("infinity"));
        assert_eq!(affected.memory_high.as_deref(), Some("70%"));
        assert_eq!(
            user_memory(&report, "user-1001.slice").memory_max.as_deref(),
            Some("60%")
        );
        assert_eq!(report.facts.user_memory.len(), 4);
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["facts"]["user_memory"][0]["unit"],
            "user-1000.slice"
        );
    }

    #[test]
    fn user_manager_template_and_instance_resets_respect_resource_sections() {
        let root = healthy();
        root.write(
            "usr/lib/systemd/system/user@.service",
            "[Service]\nMemoryMax=16G\nMemoryHigh=8G\n",
        )
        .write(
            "etc/systemd/system/user@1000.service.d/90-instance.conf",
            "[Unit]\nMemoryMax=infinity\n[Service]\nMemoryHigh=\n[Install]\nMemoryMax=infinity\n",
        );
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert_eq!(
            config.fragment_path.as_deref(),
            Some("/usr/lib/systemd/system/user@.service")
        );
        assert_eq!(config.memory_max.as_deref(), Some("16G"));
        assert_eq!(config.memory_high.as_deref(), Some("infinity"));
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.id == "oomd.user_manager_limits")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, Level::Crit);
        assert!(findings[0].summary.contains("MemoryHigh"));
        assert!(findings[0].summary.contains("(reset)"));
    }

    #[test]
    fn restored_finite_limit_after_an_intermediate_reset_is_not_a_regression() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user-.slice.d/10-limit.conf",
            "[Slice]\nMemoryMax=80%\n",
        )
        .write(
            "etc/systemd/system/user-1000.slice.d/50-reset.conf",
            "[Slice]\nMemoryMax=infinity\n",
        )
        .write(
            "usr/lib/systemd/system/user-1000.slice.d/99-restored.conf",
            "[Slice]\nMemoryMax=60%\n",
        );
        let report = root.report();
        assert!(find(&report, "oomd.user_slice_limits").is_none());
        assert_eq!(
            user_memory(&report, "user-1000.slice").memory_max.as_deref(),
            Some("60%")
        );
    }

    #[test]
    fn repeated_assignments_in_one_source_preserve_the_effective_reset() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user@1000.service.d/50-limit.conf",
            "[Service]\nMemoryMax=16G\nMemoryHigh=8G\nMemoryMax=infinity\n",
        );
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert_eq!(config.memory_max.as_deref(), Some("infinity"));
        assert_eq!(config.memory_high.as_deref(), Some("8G"));
        let finding = find(&report, "oomd.user_manager_limits").unwrap();
        assert_eq!(finding.level, Level::Crit);
        assert!(finding.summary.contains("MemoryMax=16G"));
        assert!(finding.summary.contains("final MemoryMax=infinity"));
    }

    #[test]
    fn user_unit_drop_in_precedence_matches_load_path_specificity_and_type_defaults() {
        let pairs = [
            (
                "usr/lib/systemd/system/user-1000.slice.d/50-limit.conf",
                "run/systemd/system/user-1000.slice.d/50-limit.conf",
            ),
            (
                "run/systemd/system/user-1000.slice.d/50-limit.conf",
                "etc/systemd/system/user-.slice.d/50-limit.conf",
            ),
            (
                "etc/systemd/system/user-.slice.d/50-limit.conf",
                "etc/systemd/system/user-1000.slice.d/50-limit.conf",
            ),
            (
                "etc/systemd/system/slice.d/50-limit.conf",
                "usr/lib/systemd/system/user-.slice.d/50-limit.conf",
            ),
            (
                "etc/systemd/system/user-1000.slice.d/50-limit.conf",
                "run/systemd/system.control/user-1000.slice.d/50-limit.conf",
            ),
        ];
        for (lower, higher) in pairs {
            let root = healthy();
            root.write(lower, "[Slice]\nMemoryMax=infinity\n")
                .write(higher, "[Slice]\nMemoryMax=8G\n");
            let config = read_user_memory_config(&root.path(), "user-1000.slice", false);
            assert!(config.unavailable.is_empty(), "{config:?}");
            assert_eq!(config.memory_max.as_deref(), Some("8G"), "{higher}");
            assert_eq!(config.sources.len(), 1, "{config:?}");
            assert_eq!(config.sources[0].path, format!("/{higher}"));
        }
    }

    #[test]
    fn hidden_drop_ins_cannot_override_observed_memory_limits() {
        let root = healthy();
        root.write(
            "usr/lib/systemd/system/user@.service",
            "[Service]\nMemoryMax=16G\n",
        )
        .write(
            "etc/systemd/system/user@1000.service.d/.ignored.conf",
            "[Service]\nMemoryMax=infinity\n",
        )
        .write(
            "etc/systemd/system/service.d/.type-ignored.conf",
            "[Service]\nMemoryMax=0\n",
        );
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert!(config.unavailable.is_empty());
        assert_eq!(config.memory_max.as_deref(), Some("16G"));
        assert_eq!(config.sources.len(), 1);
        assert!(find(&report, "oomd.user_manager_limits").is_none());
    }

    #[test]
    fn literal_user_manager_fragment_wins_before_template_lookup() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user@.service",
            "[Service]\nMemoryMax=16G\n",
        )
        .write(
            "run/systemd/system/user@1000.service",
            "[Service]\nMemoryMax=4G\n",
        );
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert_eq!(
            config.fragment_path.as_deref(),
            Some("/run/systemd/system/user@1000.service")
        );
        assert_eq!(config.memory_max.as_deref(), Some("4G"));
        assert_eq!(config.sources.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn masked_drop_ins_hide_lower_files_and_masked_units_skip_their_configuration() {
        let root = healthy();
        root.write(
            "usr/lib/systemd/system/user@.service",
            "[Service]\nMemoryMax=16G\n",
        )
        .write(
            "run/systemd/system/user@1000.service.d/90-reset.conf",
            "[Service]\nMemoryMax=infinity\n",
        );
        let mask = root
            .path()
            .join("etc/systemd/system/user@1000.service.d/90-reset.conf");
        std::fs::create_dir_all(mask.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/dev/null", &mask).unwrap();
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert_eq!(config.memory_max.as_deref(), Some("16G"));
        assert_eq!(
            config.masked_drop_ins,
            vec!["/etc/systemd/system/user@1000.service.d/90-reset.conf"]
        );
        assert!(find(&report, "oomd.user_manager_limits").is_none());

        for empty_file in [false, true] {
            let root = healthy();
            root.write(
                "usr/lib/systemd/system/user@.service",
                "[Service]\nMemoryMax=16G\n",
            )
            .write(
                "etc/systemd/system/user@1000.service.d/90-reset.conf",
                "[Service]\nMemoryMax=infinity\n",
            );
            let mask = root.path().join("etc/systemd/system/user@1000.service");
            if empty_file {
                std::fs::write(&mask, "").unwrap();
            } else {
                std::os::unix::fs::symlink("/dev/null", &mask).unwrap();
            }
            let report = root.report();
            let config = user_memory(&report, "user@1000.service");
            assert!(config.masked, "{config:?}");
            assert_eq!(
                config.fragment_path.as_deref(),
                Some("/etc/systemd/system/user@1000.service")
            );
            assert!(config.sources.is_empty());
            assert!(config.memory_max.is_none());
            assert!(find(&report, "oomd.user_manager_limits").is_none());
        }
    }

    #[test]
    #[cfg(unix)]
    fn unit_aliases_and_links_outside_fixture_roots_are_explicitly_unavailable() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user@.service",
            "[Service]\nMemoryMax=16G\n",
        );
        std::os::unix::fs::symlink(
            "user@.service",
            root.path().join("etc/systemd/system/user@1000.service"),
        )
        .unwrap();
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert!(config.memory_max.is_none());
        assert!(config.unavailable.iter().any(|reason| reason.contains("alias")));
        assert_eq!(
            find(&report, "oomd.user_manager_limits").unwrap().level,
            Level::Info
        );

        let outside = Root::new();
        outside.write("50-limit.conf", "[Slice]\nMemoryMax=8G\n");
        let link = root.path().join("etc/systemd/system/user-1000.slice.d");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let config = read_user_memory_config(&root.path(), "user-1000.slice", false);
        assert!(config.memory_max.is_none());
        assert!(config
            .unavailable
            .iter()
            .any(|reason| reason.contains("leaves the inspected root")));
        assert!(config.sources.is_empty());
    }

    #[test]
    fn unknown_memory_assignments_do_not_claim_a_finite_or_unlimited_limit() {
        for value in ["nonsense", "INFINITY", "0", "101%", "18446744073709551615"] {
            let root = healthy();
            root.write(
                "usr/lib/systemd/system/user@.service",
                "[Service]\nMemoryMax=16G\n",
            )
            .write(
                "etc/systemd/system/user@1000.service.d/50-unsupported.conf",
                &format!("[Service]\nMemoryMax={value}\n"),
            );
            let report = root.report();
            let config = user_memory(&report, "user@1000.service");
            assert!(config.memory_max.is_none(), "{value}");
            assert!(!config.unavailable.is_empty(), "{value}");
            assert_eq!(
                find(&report, "oomd.user_manager_limits").unwrap().level,
                Level::Info
            );
        }
        for value in ["1", "1.5G", "80%", "0.01%", "18446744073709551614"] {
            assert_eq!(finite_memory_limit(value), Some(true), "{value}");
        }
        assert_eq!(finite_memory_limit("infinity"), Some(false));
        assert_eq!(finite_memory_limit(""), Some(false));
    }

    #[test]
    fn continued_memory_settings_and_unrecognized_unit_names_are_handled_conservatively() {
        let root = healthy();
        root.write(
            "etc/systemd/system/user@1000.service.d/50-limit.conf",
            "[Service]\nMemoryMax=\\\n# continued value\n 8G\nMemoryHigh=4G\n",
        );
        let report = root.report();
        let config = user_memory(&report, "user@1000.service");
        assert!(config.unavailable.is_empty());
        assert_eq!(config.memory_max.as_deref(), Some("8G"));
        assert_eq!(config.memory_high.as_deref(), Some("4G"));
        for name in [
            "user@.service",
            "user-.slice.d",
            "user@1000.service.wants",
            "user-+1000.slice",
            "user-1000.slice;false",
            "user-4294967296.slice",
        ] {
            assert_eq!(user_unit_uid(name), None, "{name}");
        }
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
    /// named. A large sparse fixture must not fabricate disk pressure.
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
        use std::os::unix::fs::MetadataExt;
        let allocated = std::fs::metadata(&held).unwrap().blocks() * 512;
        assert!(allocated < GIB, "the sparse fixture allocated {allocated}");
        assert_eq!(r.facts.procs.deleted_open_bytes, allocated);
        assert_eq!(r.facts.procs.deleted_open_logical_bytes, 2 * GIB);
        assert_eq!(r.facts.procs.deleted_open.len(), 1);
        let f = find(&r, "disk.deleted_open_files").unwrap();
        assert_eq!(f.level, Level::Info);
        assert!(f.summary.contains("app.log"), "{}", f.summary);
        assert!(f.summary.contains("(pid 500)"), "{}", f.summary);
        assert_eq!(f.commands, vec!["ls -l /proc/500/fd | grep deleted"]);

        // Real allocated blocks retain a positive reader/deduplication oracle.
        // This is a controlled proc-tree fixture, not live unlinked-file relief.
        std::fs::write(&held, vec![b'x'; 8192]).unwrap();
        let allocated = std::fs::metadata(&held).unwrap().blocks() * 512;
        assert!(allocated > 0);
        let r = root.report();
        assert_eq!(r.facts.procs.deleted_open_bytes, allocated);
        assert_eq!(r.facts.procs.deleted_open_logical_bytes, 8192);
        assert_eq!(r.facts.procs.deleted_open.len(), 1);
        let f = find(&r, "disk.deleted_open_files").unwrap();
        assert_eq!(f.level, Level::Info);
        assert!(f.summary.contains("(pid 500)"), "{}", f.summary);
        assert_eq!(f.observed["bytes"], allocated);
        assert_eq!(f.observed["logical_bytes"], 8192);

        // Classification-only boundary inputs preserve the original large-allocation
        // warning without presenting a sparse fixture as a measured GiB of storage.
        for (bytes, expected) in [(GIB - 1, Level::Info), (GIB, Level::Warn)] {
            let mut facts = r.facts.clone();
            facts.procs.deleted_open_bytes = bytes;
            facts.procs.deleted_open_logical_bytes = bytes;
            facts.procs.deleted_open[0].bytes = bytes;
            facts.procs.deleted_open[0].logical_bytes = bytes;
            let mut findings = Vec::new();
            check_deleted_open(&facts, &mut findings);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].level, expected);
            assert_eq!(findings[0].observed["bytes"], bytes);
            assert!(findings[0].rationale.contains("not measured freed space"));
            assert_eq!(
                findings[0].commands,
                vec!["ls -l /proc/500/fd | grep deleted"]
            );
        }
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
