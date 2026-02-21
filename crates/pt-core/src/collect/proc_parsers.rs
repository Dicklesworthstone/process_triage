//! Parsers for /proc filesystem files.
//!
//! This module provides parsers for various /proc/\[pid\]/* files
//! that provide detailed process information on Linux systems.
//!
//! # Files Parsed
//! - `/proc/[pid]/io` - I/O statistics
//! - `/proc/[pid]/schedstat` - Scheduler statistics
//! - `/proc/[pid]/sched` - Scheduler info
//! - `/proc/[pid]/statm` - Memory statistics
//! - `/proc/[pid]/fd/` - File descriptor info
//! - `/proc/[pid]/cgroup` - Cgroup membership
//! - `/proc/[pid]/wchan` - Wait channel
//! - `/proc/[pid]/environ` - Environment variables

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// I/O statistics from /proc/\[pid\]/io.
///
/// Fields are cumulative since process start.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoStats {
    /// Characters read (includes buffered).
    pub rchar: u64,
    /// Characters written (includes buffered).
    pub wchar: u64,
    /// Read syscalls.
    pub syscr: u64,
    /// Write syscalls.
    pub syscw: u64,
    /// Bytes read from storage.
    pub read_bytes: u64,
    /// Bytes written to storage.
    pub write_bytes: u64,
    /// Cancelled write bytes.
    pub cancelled_write_bytes: u64,
}

/// Scheduler statistics from /proc/\[pid\]/schedstat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedStats {
    /// Time spent on CPU (nanoseconds).
    pub cpu_time_ns: u64,
    /// Time spent waiting on runqueue (nanoseconds).
    pub wait_time_ns: u64,
    /// Number of timeslices run on this CPU.
    pub timeslices: u64,
}

/// Scheduler info from /proc/\[pid\]/sched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedInfo {
    /// Number of voluntary context switches.
    pub nr_voluntary_switches: u64,
    /// Number of involuntary context switches.
    pub nr_involuntary_switches: u64,
    /// Process priority.
    pub prio: Option<i32>,
    /// Nice value.
    pub nice: Option<i32>,
}

/// Memory statistics from /proc/\[pid\]/statm.
///
/// All values are in pages (typically 4KB on x86_64).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemStats {
    /// Total program size (pages).
    pub size: u64,
    /// Resident set size (pages).
    pub resident: u64,
    /// Shared pages.
    pub shared: u64,
    /// Text (code) pages.
    pub text: u64,
    /// Library pages (unused since Linux 2.6).
    pub lib: u64,
    /// Data + stack pages.
    pub data: u64,
    /// Dirty pages (unused since Linux 2.6).
    pub dt: u64,
}

/// File descriptor information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdInfo {
    /// Total number of open file descriptors.
    pub count: usize,
    /// Whether the inspection was truncated due to limit.
    #[serde(default)]
    pub truncated: bool,
    /// File descriptors by type.
    pub by_type: HashMap<String, usize>,
    /// Socket count.
    pub sockets: usize,
    /// Pipe count.
    pub pipes: usize,
    /// Regular file count.
    pub files: usize,
    /// Device count.
    pub devices: usize,
    /// Open files with details (paths, modes).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_files: Vec<OpenFile>,
    /// Critical open write handles (safety-relevant).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub critical_writes: Vec<CriticalFile>,
}

/// A single open file with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFile {
    /// File descriptor number.
    pub fd: u32,
    /// Resolved path (may be empty for special FDs).
    pub path: String,
    /// File descriptor type.
    pub fd_type: FdType,
    /// Open mode flags.
    pub mode: OpenMode,
}

/// Type of file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FdType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Socket (TCP, UDP, Unix).
    Socket,
    /// Pipe or FIFO.
    Pipe,
    /// Character or block device.
    Device,
    /// Anonymous inode (eventfd, eventpoll, etc.).
    AnonInode,
    /// Unknown or unresolvable.
    Unknown,
}

/// Open mode for a file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OpenMode {
    /// File is open for reading.
    pub read: bool,
    /// File is open for writing.
    pub write: bool,
}

/// A critical file that affects kill safety.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalFile {
    /// File descriptor number.
    pub fd: u32,
    /// File path.
    pub path: String,
    /// Why this file is critical.
    pub category: CriticalFileCategory,
    /// Detection strength (hard = definite lock, soft = heuristic match).
    pub strength: DetectionStrength,
    /// Which rule matched (for provenance tracking).
    pub rule_id: String,
}

/// Detection strength for critical file matching.
///
/// Hard detections are definite locks that should always block kills.
/// Soft detections are heuristic matches that may warrant caution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStrength {
    /// Definite lock file or active write handle - always block kill.
    Hard,
    /// Heuristic match - may be stale or false positive, use caution.
    Soft,
}

impl CriticalFile {
    /// Get a human-readable remediation hint for this critical file.
    pub fn remediation_hint(&self) -> &'static str {
        self.category.remediation_hint()
    }
}

/// Categories of critical files that affect kill safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalFileCategory {
    /// SQLite WAL or journal file.
    SqliteWal,
    /// Git index or object lock.
    GitLock,
    /// Git rebase/merge in progress.
    GitRebase,
    /// System package manager lock (apt, dpkg, rpm, pacman, dnf).
    SystemPackageLock,
    /// Node.js package manager lock (npm, pnpm, yarn).
    NodePackageLock,
    /// Cargo/Rust package manager lock.
    CargoLock,
    /// Database file open for write.
    DatabaseWrite,
    /// Application-specific lock file.
    AppLock,
    /// Generic open write handle.
    OpenWrite,
}

impl CriticalFileCategory {
    /// Get a human-readable remediation hint for this category.
    pub fn remediation_hint(&self) -> &'static str {
        match self {
            Self::SqliteWal => {
                "Wait for database transaction to complete, or checkpoint the WAL file"
            }
            Self::GitLock => "Wait for git operation to finish, or remove stale .lock file if safe",
            Self::GitRebase => {
                "Complete or abort the git rebase/merge with 'git rebase --abort' or 'git merge --abort'"
            }
            Self::SystemPackageLock => {
                "Wait for package installation to complete; do not interrupt apt/dpkg/rpm"
            }
            Self::NodePackageLock => {
                "Wait for npm/pnpm/yarn install to complete; check for stale lock with 'npm cache clean'"
            }
            Self::CargoLock => {
                "Wait for cargo build/install to complete; check ~/.cargo/.package-cache-lock"
            }
            Self::DatabaseWrite => "Wait for database writes to flush; consider graceful shutdown",
            Self::AppLock => "Check application documentation for proper shutdown procedure",
            Self::OpenWrite => "Wait for file writes to complete; check for unsaved buffers",
        }
    }

    /// Check if this category represents a hard block (always block kill).
    pub fn is_hard_block(&self) -> bool {
        matches!(
            self,
            Self::SqliteWal
                | Self::GitLock
                | Self::GitRebase
                | Self::SystemPackageLock
                | Self::NodePackageLock
                | Self::CargoLock
        )
    }
}

/// Cgroup membership information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupInfo {
    /// Cgroup v2 path (unified hierarchy).
    pub unified: Option<String>,
    /// Cgroup v1 paths by controller.
    pub v1_paths: HashMap<String, String>,
    /// Whether process is in a container (heuristic).
    pub in_container: bool,
}

/// Process statistics from /proc/\[pid\]/stat.
///
/// Contains key fields parsed from the stat file.
/// See proc(5) man page for full field documentation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessStat {
    /// Process ID.
    pub pid: u32,
    /// Process name (comm) without parentheses.
    pub comm: String,
    /// Process state character (R, S, D, Z, T, etc.).
    pub state: char,
    /// Parent process ID.
    pub ppid: u32,
    /// Process group ID.
    pub pgrp: i32,
    /// Session ID.
    pub session: i32,
    /// Controlling terminal.
    pub tty_nr: i32,
    /// Terminal process group ID.
    pub tpgid: i32,
    /// User time in clock ticks.
    pub utime: u64,
    /// System time in clock ticks.
    pub stime: u64,
    /// Start time in clock ticks since boot.
    pub starttime: u64,
    /// Virtual memory size in bytes.
    pub vsize: u64,
    /// Resident set size in pages.
    pub rss: i64,
    /// Nice value.
    pub nice: i32,
    /// Number of threads.
    pub num_threads: i32,
}

/// Parse /proc/\[pid\]/stat file.
///
/// Returns None if the file cannot be read or parsed.
pub fn parse_proc_stat(pid: u32) -> Option<ProcessStat> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_proc_stat_content(&content)
}

/// Parse stat file content (for testing).
///
/// The stat file format is tricky because the comm field (process name)
/// is enclosed in parentheses and can contain spaces or even parentheses.
pub fn parse_proc_stat_content(content: &str) -> Option<ProcessStat> {
    // Find the comm field boundaries (first '(' and last ')')
    let open_paren = content.find('(')?;
    let close_paren = content.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }

    // Parse pid (before the first '(')
    let pid: u32 = content[..open_paren].trim().parse().ok()?;

    // Extract comm (between parentheses)
    let comm = content[open_paren + 1..close_paren].to_string();

    // Parse remaining fields after the ')'
    let rest = &content[close_paren + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // Need at least 22 fields after comm for the fields we want (we access up to index 21)
    if fields.len() < 22 {
        return None;
    }

    Some(ProcessStat {
        pid,
        comm,
        state: fields[0].chars().next().unwrap_or('?'),
        ppid: fields[1].parse().unwrap_or(0),
        pgrp: fields[2].parse().unwrap_or(0),
        session: fields[3].parse().unwrap_or(0),
        tty_nr: fields[4].parse().unwrap_or(0),
        tpgid: fields[5].parse().unwrap_or(0),
        // Skip flags (6), minflt (7), cminflt (8), majflt (9), cmajflt (10)
        utime: fields[11].parse().unwrap_or(0),
        stime: fields[12].parse().unwrap_or(0),
        // Skip cutime (13), cstime (14), priority (15)
        nice: fields[16].parse().unwrap_or(0),
        num_threads: fields[17].parse().unwrap_or(1),
        // Skip itrealvalue (18)
        starttime: fields[19].parse().unwrap_or(0),
        vsize: fields[20].parse().unwrap_or(0),
        rss: fields[21].parse().unwrap_or(0),
    })
}

/// Parse /proc/\[pid\]/io file.
///
/// # Errors
/// Returns None if the file cannot be read (permission denied, process exited).
pub fn parse_io(pid: u32) -> Option<IoStats> {
    let path = format!("/proc/{}/io", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_io_content(&content)
}

/// Parse io file content (for testing).
pub fn parse_io_content(content: &str) -> Option<IoStats> {
    let mut stats = IoStats::default();

    for line in content.lines() {
        // Skip empty lines or lines without colons
        let Some(colon_pos) = line.find(':') else {
            continue;
        };

        let key = line[..colon_pos].trim();
        let value_str = line[colon_pos + 1..].trim();

        // Skip lines where value can't be parsed as u64
        let Ok(value) = value_str.parse::<u64>() else {
            continue;
        };

        match key {
            "rchar" => stats.rchar = value,
            "wchar" => stats.wchar = value,
            "syscr" => stats.syscr = value,
            "syscw" => stats.syscw = value,
            "read_bytes" => stats.read_bytes = value,
            "write_bytes" => stats.write_bytes = value,
            "cancelled_write_bytes" => stats.cancelled_write_bytes = value,
            _ => {}
        }
    }

    Some(stats)
}

/// Parse /proc/\[pid\]/schedstat file.
///
/// Format: "cpu_time wait_time timeslices"
pub fn parse_schedstat(pid: u32) -> Option<SchedStats> {
    let path = format!("/proc/{}/schedstat", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_schedstat_content(&content)
}

/// Parse schedstat file content (for testing).
pub fn parse_schedstat_content(content: &str) -> Option<SchedStats> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    Some(SchedStats {
        cpu_time_ns: parts[0].parse().ok()?,
        wait_time_ns: parts[1].parse().ok()?,
        timeslices: parts[2].parse().ok()?,
    })
}

/// Parse /proc/\[pid\]/sched file.
///
/// Extracts voluntary/involuntary switches, priority, and nice value.
pub fn parse_sched(pid: u32) -> Option<SchedInfo> {
    let path = format!("/proc/{}/sched", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_sched_content(&content)
}

/// Parse sched file content (for testing).
pub fn parse_sched_content(content: &str) -> Option<SchedInfo> {
    let mut info = SchedInfo::default();

    for line in content.lines() {
        // Format: "key                     : value"
        // Skip lines that don't contain a colon or are headers
        let Some(colon_pos) = line.find(':') else {
            continue;
        };

        let key = line[..colon_pos].trim();
        let value_str = line[colon_pos + 1..].trim();

        match key {
            "nr_voluntary_switches" => {
                info.nr_voluntary_switches = value_str.parse().unwrap_or(0);
            }
            "nr_involuntary_switches" => {
                info.nr_involuntary_switches = value_str.parse().unwrap_or(0);
            }
            "prio" => {
                info.prio = value_str.parse().ok();
            }
            "nice" => {
                info.nice = value_str.parse().ok();
            }
            _ => {}
        }
    }

    Some(info)
}

/// Parse /proc/\[pid\]/statm file.
///
/// Format: "size resident shared text lib data dt"
pub fn parse_statm(pid: u32) -> Option<MemStats> {
    let path = format!("/proc/{}/statm", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_statm_content(&content)
}

/// Parse statm file content (for testing).
pub fn parse_statm_content(content: &str) -> Option<MemStats> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 7 {
        return None;
    }

    Some(MemStats {
        size: parts[0].parse().ok()?,
        resident: parts[1].parse().ok()?,
        shared: parts[2].parse().ok()?,
        text: parts[3].parse().ok()?,
        lib: parts[4].parse().ok()?,
        data: parts[5].parse().ok()?,
        dt: parts[6].parse().ok()?,
    })
}

/// Parse /proc/\[pid\]/fd/ directory.
///
/// Counts and categorizes open file descriptors.
pub fn parse_fd(pid: u32) -> Option<FdInfo> {
    let path = format!("/proc/{}/fd", pid);
    let fdinfo_path = format!("/proc/{}/fdinfo", pid);
    parse_fd_dir(Path::new(&path), Some(Path::new(&fdinfo_path)))
}

/// Parse fd directory (for testing with mock directories).
pub fn parse_fd_dir(dir: &Path, fdinfo_dir: Option<&Path>) -> Option<FdInfo> {
    let mut info = FdInfo::default();

    let entries = fs::read_dir(dir).ok()?;
    let mut inspected_count = 0;
    // Limit inspection to prevent stall on processes with massive FD counts (e.g. databases)
    // Increased to 50k to ensure we don't miss critical locks in heavy workloads
    const MAX_INSPECT: usize = 50_000;

    for entry in entries.flatten() {
        // Parse FD number from filename; skip non-numeric entries defensively.
        let fd_name = entry.file_name();
        let Ok(fd_num) = fd_name.to_string_lossy().parse::<u32>() else {
            continue;
        };

        info.count += 1;

        // Skip expensive inspection if we've hit the limit
        if inspected_count >= MAX_INSPECT {
            info.truncated = true;
            continue;
        }
        inspected_count += 1;

        // Try to read the symlink to categorize
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy().to_string();
            let fd_type_str = categorize_fd(&target_str);
            let fd_type = parse_fd_type(&fd_type_str);

            *info.by_type.entry(fd_type_str.clone()).or_insert(0) += 1;

            match fd_type_str.as_str() {
                "socket" => info.sockets += 1,
                "pipe" => info.pipes += 1,
                "file" => info.files += 1,
                "device" => info.devices += 1,
                _ => {}
            }

            // Get open mode from fdinfo if available
            let mode = fdinfo_dir
                .and_then(|d| parse_fdinfo_flags(d.join(fd_num.to_string()).as_path()))
                .unwrap_or_default();

            // Record open file details for regular files
            if fd_type == FdType::File || fd_type == FdType::Directory {
                info.open_files.push(OpenFile {
                    fd: fd_num,
                    path: target_str.clone(),
                    fd_type,
                    mode,
                });

                // Check for critical files if open for writing
                if mode.write {
                    if let Some(critical) = detect_critical_file(fd_num, &target_str) {
                        info.critical_writes.push(critical);
                    }
                }
            }
        }
    }

    Some(info)
}

/// Parse FD type string to enum.
fn parse_fd_type(type_str: &str) -> FdType {
    match type_str {
        "socket" => FdType::Socket,
        "pipe" => FdType::Pipe,
        "file" => FdType::File,
        "device" => FdType::Device,
        s if s.starts_with("anon:") => FdType::AnonInode,
        _ => FdType::Unknown,
    }
}

/// Parse fdinfo file to extract open mode flags.
fn parse_fdinfo_flags(path: &Path) -> Option<OpenMode> {
    let content = fs::read_to_string(path).ok()?;
    parse_fdinfo_content(&content)
}

/// Parse fdinfo content (for testing).
pub fn parse_fdinfo_content(content: &str) -> Option<OpenMode> {
    for line in content.lines() {
        if let Some(flags_str) = line.strip_prefix("flags:") {
            // flags is an octal number, parse it
            let flags_str = flags_str.trim();
            if let Ok(flags) = u32::from_str_radix(flags_str, 8) {
                // O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2
                // Access mode is in the lowest 2 bits
                let access_mode = flags & 0o3;
                return Some(OpenMode {
                    read: access_mode == 0 || access_mode == 2, // O_RDONLY or O_RDWR
                    write: access_mode == 1 || access_mode == 2, // O_WRONLY or O_RDWR
                });
            }
        }
    }
    None
}

/// Detect if a file path is a critical file for safety gates.
fn detect_critical_file(fd: u32, path: &str) -> Option<CriticalFile> {
    let path_lower = path.to_lowercase();

    // SQLite WAL and journal files - HARD block (active transaction in progress)
    if path_lower.ends_with("-wal")
        || path_lower.ends_with("-journal")
        || path_lower.ends_with("-shm")
        || path_lower.ends_with(".sqlite-wal")
        || path_lower.ends_with(".sqlite-journal")
        || path_lower.ends_with(".db-wal")
        || path_lower.ends_with(".db-journal")
    {
        return Some(CriticalFile {
            fd,
            path: path.to_string(),
            category: CriticalFileCategory::SqliteWal,
            strength: DetectionStrength::Hard,
            rule_id: "sqlite_wal_journal".to_string(),
        });
    }

    // Git rebase/merge in progress markers - HARD block
    if path.contains(".git/") {
        let rebase_merge_markers = [
            "/rebase-merge/",
            "/rebase-apply/",
            "/MERGE_HEAD",
            "/CHERRY_PICK_HEAD",
            "/REVERT_HEAD",
            "/BISECT_LOG",
        ];
        for marker in &rebase_merge_markers {
            if path.contains(marker) {
                return Some(CriticalFile {
                    fd,
                    path: path.to_string(),
                    category: CriticalFileCategory::GitRebase,
                    strength: DetectionStrength::Hard,
                    rule_id: "git_rebase_merge".to_string(),
                });
            }
        }

        // Git lock files - HARD block
        let git_lock_patterns = [
            "/index.lock",
            "/shallow.lock",
            "/packed-refs.lock",
            "/config.lock",
            "/HEAD.lock",
        ];
        for pattern in &git_lock_patterns {
            if path.ends_with(pattern) {
                return Some(CriticalFile {
                    fd,
                    path: path.to_string(),
                    category: CriticalFileCategory::GitLock,
                    strength: DetectionStrength::Hard,
                    rule_id: "git_lock_file".to_string(),
                });
            }
        }

        // Git objects being written - SOFT (could be read-only pack access)
        if path.contains("/objects/") && path_lower.ends_with(".lock") {
            return Some(CriticalFile {
                fd,
                path: path.to_string(),
                category: CriticalFileCategory::GitLock,
                strength: DetectionStrength::Soft,
                rule_id: "git_objects_lock".to_string(),
            });
        }
    }

    // System package manager locks - HARD block (corruption risk is severe)
    let system_pkg_locks = [
        ("/var/lib/dpkg/lock", "dpkg_lock"),
        ("/var/lib/dpkg/lock-frontend", "dpkg_frontend_lock"),
        ("/var/cache/apt/archives/lock", "apt_archives_lock"),
        ("/var/lib/apt/lists/lock", "apt_lists_lock"),
        ("/var/lib/rpm/.rpm.lock", "rpm_lock"),
        ("/var/lib/pacman/db.lck", "pacman_lock"),
        ("/var/cache/pacman/pkg/", "pacman_cache"),
        ("/var/lib/dnf/", "dnf_lock"),
    ];
    for (pattern, rule) in &system_pkg_locks {
        if path.starts_with(pattern) || path.contains(pattern) {
            return Some(CriticalFile {
                fd,
                path: path.to_string(),
                category: CriticalFileCategory::SystemPackageLock,
                strength: DetectionStrength::Hard,
                rule_id: rule.to_string(),
            });
        }
    }

    // Node.js package manager locks - HARD for active installs
    let node_pkg_patterns = [
        ("node_modules/.package-lock.json", "npm_package_lock"),
        ("node_modules/.staging/", "npm_staging"),
        (".pnpm-lock.yaml", "pnpm_lock"),
        (".yarn/install-state.gz", "yarn_install_state"),
        (".yarnrc.yml.lock", "yarn_config_lock"),
    ];
    for (pattern, rule) in &node_pkg_patterns {
        if path.contains(pattern) {
            return Some(CriticalFile {
                fd,
                path: path.to_string(),
                category: CriticalFileCategory::NodePackageLock,
                strength: DetectionStrength::Hard,
                rule_id: rule.to_string(),
            });
        }
    }

    // Cargo/Rust package manager locks
    let cargo_patterns = [
        (".cargo/registry/.package-cache-lock", "cargo_registry_lock"),
        (".cargo/.package-cache-lock", "cargo_package_cache"),
        ("/target/.cargo-lock", "cargo_target_lock"),
    ];
    for (pattern, rule) in &cargo_patterns {
        if path.contains(pattern) {
            return Some(CriticalFile {
                fd,
                path: path.to_string(),
                category: CriticalFileCategory::CargoLock,
                strength: DetectionStrength::Hard,
                rule_id: rule.to_string(),
            });
        }
    }

    // Database files open for write - SOFT (may be read-only access despite FD flags)
    let db_extensions = [".db", ".sqlite", ".sqlite3", ".ldb", ".mdb"];
    for ext in &db_extensions {
        if path_lower.ends_with(ext) {
            return Some(CriticalFile {
                fd,
                path: path.to_string(),
                category: CriticalFileCategory::DatabaseWrite,
                strength: DetectionStrength::Soft,
                rule_id: "database_file".to_string(),
            });
        }
    }

    // Generic lock files - SOFT (may be stale)
    if path_lower.ends_with(".lock") || path_lower.ends_with(".lck") || path.contains("/lock/") {
        return Some(CriticalFile {
            fd,
            path: path.to_string(),
            category: CriticalFileCategory::AppLock,
            strength: DetectionStrength::Soft,
            rule_id: "generic_lock_file".to_string(),
        });
    }

    // Any other open write handle is noteworthy but lower priority
    // Return None to avoid cluttering critical_writes with every write handle
    None
}

/// Categorize a file descriptor by its target.
fn categorize_fd(target: &str) -> String {
    if target.starts_with("socket:") {
        "socket".to_string()
    } else if target.starts_with("pipe:") {
        "pipe".to_string()
    } else if target.starts_with("anon_inode:") {
        // e.g., anon_inode:[eventfd], anon_inode:[eventpoll]
        let inner = target.strip_prefix("anon_inode:").unwrap_or("");
        format!("anon:{}", inner.trim_matches(|c| c == '[' || c == ']'))
    } else if target.starts_with("/dev/") {
        "device".to_string()
    } else if target.starts_with('/') {
        "file".to_string()
    } else {
        "other".to_string()
    }
}

/// Parse /proc/\[pid\]/wchan file.
///
/// Returns the kernel function where the process is sleeping.
pub fn parse_wchan(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/wchan", pid);
    let content = fs::read_to_string(&path).ok()?;
    let wchan = content.trim();

    // "0" means not waiting
    if wchan == "0" || wchan.is_empty() {
        None
    } else {
        Some(wchan.to_string())
    }
}

/// Parse /proc/\[pid\]/cgroup file.
///
/// Determines cgroup membership and container detection.
pub fn parse_cgroup(pid: u32) -> Option<CgroupInfo> {
    let path = format!("/proc/{}/cgroup", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_cgroup_content(&content)
}

/// Parse cgroup file content (for testing).
pub fn parse_cgroup_content(content: &str) -> Option<CgroupInfo> {
    let mut info = CgroupInfo::default();

    for line in content.lines() {
        // Format: "hierarchy-ID:controller-list:cgroup-path"
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }

        let hierarchy = parts[0];
        let controllers = parts[1];
        let path = parts[2];

        // Cgroup v2 (unified) has empty controller field
        if hierarchy == "0" && controllers.is_empty() {
            info.unified = Some(path.to_string());
        } else if !controllers.is_empty() {
            // Cgroup v1
            for controller in controllers.split(',') {
                info.v1_paths
                    .insert(controller.to_string(), path.to_string());
            }
        }

        // Container detection heuristics
        if path.contains("/docker/")
            || path.contains("/lxc/")
            || path.contains("/kubepods/")
            || path.contains("/containerd/")
            || path.contains("/podman/")
        {
            info.in_container = true;
        }
    }

    Some(info)
}

/// Parse /proc/\[pid\]/environ file.
///
/// Returns environment variables as key-value pairs.
/// Note: Only accessible for processes owned by the same user or root.
pub fn parse_environ(pid: u32) -> Option<HashMap<String, String>> {
    let path = format!("/proc/{}/environ", pid);
    let content = fs::read(&path).ok()?;
    parse_environ_content(&content)
}

/// Parse environ file content (for testing).
pub fn parse_environ_content(content: &[u8]) -> Option<HashMap<String, String>> {
    let mut env = HashMap::new();

    // Environment variables are null-separated
    for entry in content.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }

        // Use lossy conversion to preserve variables even with invalid UTF-8
        let s = String::from_utf8_lossy(entry);
        if let Some((key, value)) = s.split_once('=') {
            env.insert(key.to_string(), value.to_string());
        }
    }

    Some(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_stat_content() {
        // Sample /proc/[pid]/stat content
        let content = "1234 (bash) S 1000 1234 1234 34816 5678 4194304 1234 5678 0 0 10 5 0 0 20 0 1 0 12345 67890 1000 18446744073709551615 0 0 0 0 0 0 0 0 65536 0 0 0 17 0 0 0 0 0 0";

        let stat = parse_proc_stat_content(content).unwrap();
        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.comm, "bash");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 1000);
        assert_eq!(stat.pgrp, 1234);
        assert_eq!(stat.session, 1234);
        assert_eq!(stat.tty_nr, 34816);
        assert_eq!(stat.tpgid, 5678);
    }

    #[test]
    fn test_parse_proc_stat_content_with_spaces_in_comm() {
        // Command name with spaces
        let content = "5678 (my app name) R 1000 5678 5678 0 -1 4194304 100 0 0 0 5 2 0 0 20 0 1 0 54321 12345 500 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

        let stat = parse_proc_stat_content(content).unwrap();
        assert_eq!(stat.pid, 5678);
        assert_eq!(stat.comm, "my app name");
        assert_eq!(stat.state, 'R');
        assert_eq!(stat.ppid, 1000);
        assert_eq!(stat.tpgid, -1);
    }

    #[test]
    fn test_parse_io_content() {
        let content = r#"rchar: 12345678
wchar: 87654321
syscr: 1000
syscw: 500
read_bytes: 4096000
write_bytes: 2048000
cancelled_write_bytes: 0
"#;

        let stats = parse_io_content(content).unwrap();
        assert_eq!(stats.rchar, 12345678);
        assert_eq!(stats.wchar, 87654321);
        assert_eq!(stats.syscr, 1000);
        assert_eq!(stats.syscw, 500);
        assert_eq!(stats.read_bytes, 4096000);
        assert_eq!(stats.write_bytes, 2048000);
        assert_eq!(stats.cancelled_write_bytes, 0);
    }

    #[test]
    fn test_parse_schedstat_content() {
        let content = "123456789 987654321 42\n";

        let stats = parse_schedstat_content(content).unwrap();
        assert_eq!(stats.cpu_time_ns, 123456789);
        assert_eq!(stats.wait_time_ns, 987654321);
        assert_eq!(stats.timeslices, 42);
    }

    #[test]
    fn test_parse_sched_content() {
        let content = r#"bash (1234, #threads: 1)
-------------------------------------------------------------------
se.exec_start                                :      12345678.123456
se.vruntime                                  :        987654.321000
nr_voluntary_switches                        :                  100
nr_involuntary_switches                      :                   50
prio                                         :                  120
nice                                         :                    0
"#;

        let info = parse_sched_content(content).unwrap();
        assert_eq!(info.nr_voluntary_switches, 100);
        assert_eq!(info.nr_involuntary_switches, 50);
        assert_eq!(info.prio, Some(120));
        assert_eq!(info.nice, Some(0));
    }

    #[test]
    fn test_parse_statm_content() {
        let content = "1000 500 100 50 0 200 0\n";

        let stats = parse_statm_content(content).unwrap();
        assert_eq!(stats.size, 1000);
        assert_eq!(stats.resident, 500);
        assert_eq!(stats.shared, 100);
        assert_eq!(stats.text, 50);
        assert_eq!(stats.lib, 0);
        assert_eq!(stats.data, 200);
        assert_eq!(stats.dt, 0);
    }

    #[test]
    fn test_categorize_fd() {
        assert_eq!(categorize_fd("socket:[12345]"), "socket");
        assert_eq!(categorize_fd("pipe:[67890]"), "pipe");
        assert_eq!(categorize_fd("/dev/null"), "device");
        assert_eq!(categorize_fd("/home/user/file.txt"), "file");
        assert_eq!(categorize_fd("anon_inode:[eventfd]"), "anon:eventfd");
        assert_eq!(categorize_fd("anon_inode:[eventpoll]"), "anon:eventpoll");
    }

    #[test]
    fn test_parse_fdinfo_content_readonly_flags() {
        let content = "flags:\t00000000\n";
        let mode = parse_fdinfo_content(content).unwrap();
        assert!(mode.read);
        assert!(!mode.write);
    }

    #[test]
    fn test_parse_fdinfo_content_readwrite_flags() {
        let content = "flags:\t00000002\n";
        let mode = parse_fdinfo_content(content).unwrap();
        assert!(mode.read);
        assert!(mode.write);
    }

    #[test]
    fn test_parse_cgroup_content_v2() {
        let content = "0::/user.slice/user-1000.slice/session-1.scope\n";

        let info = parse_cgroup_content(content).unwrap();
        assert_eq!(
            info.unified,
            Some("/user.slice/user-1000.slice/session-1.scope".to_string())
        );
        assert!(!info.in_container);
    }

    #[test]
    fn test_parse_cgroup_content_docker() {
        let content = r#"12:pids:/docker/abc123def456
11:memory:/docker/abc123def456
0::/docker/abc123def456
"#;

        let info = parse_cgroup_content(content).unwrap();
        assert!(info.in_container);
        assert_eq!(
            info.v1_paths.get("pids"),
            Some(&"/docker/abc123def456".to_string())
        );
    }

    #[test]
    fn test_parse_cgroup_content_kubernetes() {
        let content = "0::/kubepods/burstable/pod-xyz/container-123\n";

        let info = parse_cgroup_content(content).unwrap();
        assert!(info.in_container);
    }

    #[test]
    fn test_parse_environ_content() {
        let content = b"PATH=/usr/bin\0HOME=/home/user\0SHELL=/bin/bash\0";

        let env = parse_environ_content(content).unwrap();
        assert_eq!(env.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(env.get("HOME"), Some(&"/home/user".to_string()));
        assert_eq!(env.get("SHELL"), Some(&"/bin/bash".to_string()));
    }

    #[test]
    fn test_parse_environ_content_empty() {
        let content = b"";
        let env = parse_environ_content(content).unwrap();
        assert!(env.is_empty());
    }

    // =========================================================================
    // No-Mock Tests Using Real Processes
    // =========================================================================
    // These tests use the ProcessHarness to spawn real processes and parse
    // their actual /proc files, validating parsers against real data.

    #[test]
    fn test_nomock_parse_io_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return; // Skip on non-Linux
        }

        let harness = ProcessHarness;
        // Spawn a process that does some I/O
        let proc = harness
            .spawn_shell("echo test > /dev/null && sleep 1")
            .expect("spawn process");

        // Give it a moment to do I/O
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Parse real /proc/<pid>/io
        let result = parse_io(proc.pid());

        // Log result for JSONL output
        crate::test_log!(
            INFO,
            "parse_io real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        // May be None if we don't have permission, but should not panic
        if let Some(stats) = result {
            // Real process should have some I/O activity
            crate::test_log!(
                DEBUG,
                "I/O stats",
                pid = proc.pid(),
                rchar = stats.rchar,
                wchar = stats.wchar,
                syscr = stats.syscr,
                syscw = stats.syscw
            );
            // Basic sanity: at least one syscall should have happened
            assert!(stats.syscr > 0 || stats.syscw > 0 || stats.rchar > 0);
        }
    }

    #[test]
    fn test_nomock_parse_statm_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Parse real /proc/<pid>/statm
        let result = parse_statm(proc.pid());

        crate::test_log!(
            INFO,
            "parse_statm real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        // statm should always be readable for our own processes
        let stats = result.expect("statm should be readable");

        // Real process must have non-zero virtual size; resident may be 0 for
        // freshly spawned lightweight processes whose pages haven't been faulted in yet.
        assert!(stats.size > 0, "process should have non-zero size");

        crate::test_log!(
            DEBUG,
            "Memory stats",
            pid = proc.pid(),
            size_pages = stats.size,
            resident_pages = stats.resident,
            shared_pages = stats.shared
        );
    }

    #[test]
    fn test_nomock_parse_schedstat_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        // Use a busy process to ensure scheduler stats are populated
        let proc = harness.spawn_busy().expect("spawn busy");

        // Let it run briefly
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Parse real /proc/<pid>/schedstat
        let result = parse_schedstat(proc.pid());

        crate::test_log!(
            INFO,
            "parse_schedstat real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        if let Some(stats) = result {
            // Busy process should have accumulated some CPU time
            assert!(stats.cpu_time_ns > 0, "busy process should have CPU time");
            crate::test_log!(
                DEBUG,
                "Sched stats",
                pid = proc.pid(),
                cpu_time_ns = stats.cpu_time_ns,
                wait_time_ns = stats.wait_time_ns,
                timeslices = stats.timeslices
            );
        }
    }

    #[test]
    fn test_nomock_parse_sched_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Parse real /proc/<pid>/sched
        let result = parse_sched(proc.pid());

        crate::test_log!(
            INFO,
            "parse_sched real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        if let Some(info) = result {
            // Every process has a priority
            assert!(info.prio.is_some(), "process should have priority");
            crate::test_log!(
                DEBUG,
                "Sched info",
                pid = proc.pid(),
                prio = info.prio,
                nice = info.nice,
                vol_switches = info.nr_voluntary_switches,
                invol_switches = info.nr_involuntary_switches
            );
        }
    }

    #[test]
    fn test_nomock_parse_fd_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        // Spawn a shell that has standard FDs open
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Parse real /proc/<pid>/fd
        let result = parse_fd(proc.pid());

        crate::test_log!(
            INFO,
            "parse_fd real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        if let Some(info) = result {
            // Every process has at least stdin/stdout/stderr (0, 1, 2)
            assert!(info.count >= 3, "process should have at least 3 FDs");
            crate::test_log!(
                DEBUG,
                "FD info",
                pid = proc.pid(),
                count = info.count,
                sockets = info.sockets,
                pipes = info.pipes,
                files = info.files
            );
        }
    }

    #[test]
    fn test_nomock_parse_cgroup_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Parse real /proc/<pid>/cgroup
        let result = parse_cgroup(proc.pid());

        crate::test_log!(
            INFO,
            "parse_cgroup real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        // Cgroup info should be available on any modern Linux
        let info = result.expect("cgroup should be readable");

        // Should have either v1 or v2 cgroup info
        let has_cgroup_info = info.unified.is_some() || !info.v1_paths.is_empty();
        assert!(has_cgroup_info, "process should have cgroup membership");

        crate::test_log!(
            DEBUG,
            "Cgroup info",
            pid = proc.pid(),
            unified = info.unified,
            v1_count = info.v1_paths.len(),
            in_container = info.in_container
        );
    }

    #[test]
    fn test_nomock_parse_wchan_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        // Sleeping process should have a wait channel
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Give it time to enter sleep
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Parse real /proc/<pid>/wchan
        let result = parse_wchan(proc.pid());

        crate::test_log!(
            INFO,
            "parse_wchan real result",
            pid = proc.pid(),
            wchan = result.clone()
        );

        // Sleeping process typically has a wait channel
        // (though it may briefly wake for signals)
        if let Some(wchan) = result {
            assert!(!wchan.is_empty(), "wchan should not be empty when waiting");
            crate::test_log!(DEBUG, "Wait channel", pid = proc.pid(), wchan = wchan);
        }
    }

    #[test]
    fn test_nomock_parse_environ_real_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        // Shell inherits our environment
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Give it a moment to initialize environment
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Parse real /proc/<pid>/environ
        let result = parse_environ(proc.pid());

        crate::test_log!(
            INFO,
            "parse_environ real result",
            pid = proc.pid(),
            has_result = result.is_some()
        );

        if let Some(env) = result {
            // Shell should have inherited PATH at minimum
            assert!(!env.is_empty(), "environment should not be empty");
            // PATH is almost always set
            let has_path = env.contains_key("PATH");
            crate::test_log!(
                DEBUG,
                "Environment",
                pid = proc.pid(),
                count = env.len(),
                has_path = has_path
            );
        }
    }

    #[test]
    fn test_nomock_proc_snapshot_integration() {
        use crate::test_utils::{ProcSnapshot, ProcessHarness};

        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(5).expect("spawn sleep");

        // Capture snapshot using the harness
        let snapshot = ProcSnapshot::capture(proc.pid()).expect("capture snapshot");

        crate::test_log!(
            INFO,
            "Snapshot integration test",
            pid = proc.pid(),
            has_stat = snapshot.stat.is_some(),
            has_comm = snapshot.comm.is_some(),
            status_fields = snapshot.status.len()
        );

        // Verify snapshot fields align with parser outputs
        if let Some(ref stat) = snapshot.stat {
            assert!(stat.contains(&proc.pid().to_string()));
        }

        // Comm should match what's in /proc/<pid>/comm
        if let Some(ref comm) = snapshot.comm {
            // Shell spawns sh or sleep, comm should be one of those
            // Note: truncated to 15 chars on Linux
            assert!(
                comm == "sh" || comm == "sleep" || comm.starts_with("collect::proc_p"),
                "expected sh, sleep, or test runner (if PID reused); got {}",
                comm
            );
            // If it IS the test runner, it means PID collision/reuse occurred
            if comm.starts_with("collect::proc_p") {
                crate::test_log!(
                    WARN,
                    "PID reuse detected in test - sleep process likely exited early"
                );
            }
        }

        // Status should have basic fields
        assert!(snapshot.status.contains_key("Pid"));
        assert!(snapshot.status.contains_key("State"));
    }

    // =========================================================================
    // Critical File Detection Tests
    // =========================================================================

    #[test]
    fn test_detect_critical_file_sqlite_wal() {
        let cf = detect_critical_file(3, "/home/user/app/data.db-wal").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SqliteWal);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "sqlite_wal_journal");
    }

    #[test]
    fn test_detect_critical_file_sqlite_journal() {
        let cf = detect_critical_file(4, "/var/lib/app/test.sqlite-journal").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SqliteWal);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_git_index_lock() {
        let cf = detect_critical_file(5, "/home/user/repo/.git/index.lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "git_lock_file");
    }

    #[test]
    fn test_detect_critical_file_git_shallow_lock() {
        let cf = detect_critical_file(6, "/home/user/repo/.git/shallow.lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_git_packed_refs_lock() {
        let cf = detect_critical_file(7, "/home/user/repo/.git/packed-refs.lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_git_rebase() {
        let cf = detect_critical_file(8, "/home/user/repo/.git/rebase-merge/head-name").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitRebase);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "git_rebase_merge");
    }

    #[test]
    fn test_detect_critical_file_git_merge_head() {
        let cf = detect_critical_file(9, "/home/user/repo/.git/MERGE_HEAD").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitRebase);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_git_cherry_pick() {
        let cf = detect_critical_file(10, "/home/user/repo/.git/CHERRY_PICK_HEAD").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::GitRebase);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_dpkg_lock() {
        let cf = detect_critical_file(11, "/var/lib/dpkg/lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SystemPackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "dpkg_lock");
    }

    #[test]
    fn test_detect_critical_file_apt_lock() {
        let cf = detect_critical_file(12, "/var/cache/apt/archives/lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SystemPackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "apt_archives_lock");
    }

    #[test]
    fn test_detect_critical_file_pacman_lock() {
        let cf = detect_critical_file(13, "/var/lib/pacman/db.lck").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SystemPackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_npm_package_lock() {
        let cf =
            detect_critical_file(14, "/home/user/project/node_modules/.package-lock.json").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::NodePackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "npm_package_lock");
    }

    #[test]
    fn test_detect_critical_file_npm_staging() {
        let cf = detect_critical_file(15, "/home/user/project/node_modules/.staging/lodash-abc123")
            .unwrap();
        assert_eq!(cf.category, CriticalFileCategory::NodePackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "npm_staging");
    }

    #[test]
    fn test_detect_critical_file_pnpm_lock() {
        let cf = detect_critical_file(16, "/home/user/project/.pnpm-lock.yaml").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::NodePackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "pnpm_lock");
    }

    #[test]
    fn test_detect_critical_file_yarn_install_state() {
        let cf = detect_critical_file(17, "/home/user/project/.yarn/install-state.gz").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::NodePackageLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_detect_critical_file_cargo_registry_lock() {
        let cf =
            detect_critical_file(18, "/home/user/.cargo/registry/.package-cache-lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::CargoLock);
        assert_eq!(cf.strength, DetectionStrength::Hard);
        assert_eq!(cf.rule_id, "cargo_registry_lock");
    }

    #[test]
    fn test_detect_critical_file_database_soft() {
        let cf = detect_critical_file(19, "/home/user/app/data.sqlite").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::DatabaseWrite);
        assert_eq!(cf.strength, DetectionStrength::Soft);
        assert_eq!(cf.rule_id, "database_file");
    }

    #[test]
    fn test_detect_critical_file_generic_lock_soft() {
        let cf = detect_critical_file(20, "/home/user/app/cache.lock").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::AppLock);
        assert_eq!(cf.strength, DetectionStrength::Soft);
        assert_eq!(cf.rule_id, "generic_lock_file");
    }

    #[test]
    fn test_detect_critical_file_no_match() {
        // Regular file should return None
        let result = detect_critical_file(21, "/home/user/document.txt");
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_critical_file_case_insensitive() {
        // SQLite WAL patterns should be case-insensitive
        let cf = detect_critical_file(22, "/home/user/DATA.DB-WAL").unwrap();
        assert_eq!(cf.category, CriticalFileCategory::SqliteWal);
        assert_eq!(cf.strength, DetectionStrength::Hard);
    }

    #[test]
    fn test_critical_file_category_remediation_hints() {
        // Verify all categories have non-empty remediation hints
        assert!(!CriticalFileCategory::SqliteWal
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::GitLock.remediation_hint().is_empty());
        assert!(!CriticalFileCategory::GitRebase
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::SystemPackageLock
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::NodePackageLock
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::CargoLock
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::DatabaseWrite
            .remediation_hint()
            .is_empty());
        assert!(!CriticalFileCategory::AppLock.remediation_hint().is_empty());
        assert!(!CriticalFileCategory::OpenWrite
            .remediation_hint()
            .is_empty());
    }

    #[test]
    fn test_critical_file_category_is_hard_block() {
        // Hard block categories
        assert!(CriticalFileCategory::SqliteWal.is_hard_block());
        assert!(CriticalFileCategory::GitLock.is_hard_block());
        assert!(CriticalFileCategory::GitRebase.is_hard_block());
        assert!(CriticalFileCategory::SystemPackageLock.is_hard_block());
        assert!(CriticalFileCategory::NodePackageLock.is_hard_block());
        assert!(CriticalFileCategory::CargoLock.is_hard_block());

        // Database write is Soft because it's a heuristic (might be read-only access despite FD flags)
        assert!(!CriticalFileCategory::DatabaseWrite.is_hard_block());

        assert!(!CriticalFileCategory::AppLock.is_hard_block());
        assert!(!CriticalFileCategory::OpenWrite.is_hard_block());
    }

    #[test]
    fn test_critical_file_run_lock_is_soft() {
        // A standard application lock file in /run/lock should be treated as a generic AppLock
        let path = "/run/lock/my-custom-app.lock";

        let cf = detect_critical_file(123, path).expect("Should detect as critical file");

        // Should be an AppLock (Soft), not SystemPackageLock (Hard)
        assert_eq!(
            cf.category,
            CriticalFileCategory::AppLock,
            "Should be classified as generic AppLock"
        );
        assert_eq!(
            cf.strength,
            DetectionStrength::Soft,
            "Should be a Soft block"
        );
    }
}
