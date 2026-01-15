//! Parsers for /proc filesystem files.
//!
//! This module provides parsers for various /proc/[pid]/* files
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

/// I/O statistics from /proc/[pid]/io.
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

/// Scheduler statistics from /proc/[pid]/schedstat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedStats {
    /// Time spent on CPU (nanoseconds).
    pub cpu_time_ns: u64,
    /// Time spent waiting on runqueue (nanoseconds).
    pub wait_time_ns: u64,
    /// Number of timeslices run on this CPU.
    pub timeslices: u64,
}

/// Scheduler info from /proc/[pid]/sched.
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

/// Memory statistics from /proc/[pid]/statm.
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

/// Parse /proc/[pid]/io file.
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

/// Parse /proc/[pid]/schedstat file.
///
/// Format: "cpu_time wait_time timeslices"
pub fn parse_schedstat(pid: u32) -> Option<SchedStats> {
    let path = format!("/proc/{}/schedstat", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_schedstat_content(&content)
}

/// Parse schedstat file content (for testing).
pub fn parse_schedstat_content(content: &str) -> Option<SchedStats> {
    let parts: Vec<&str> = content.trim().split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    Some(SchedStats {
        cpu_time_ns: parts[0].parse().ok()?,
        wait_time_ns: parts[1].parse().ok()?,
        timeslices: parts[2].parse().ok()?,
    })
}

/// Parse /proc/[pid]/sched file.
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

/// Parse /proc/[pid]/statm file.
///
/// Format: "size resident shared text lib data dt"
pub fn parse_statm(pid: u32) -> Option<MemStats> {
    let path = format!("/proc/{}/statm", pid);
    let content = fs::read_to_string(&path).ok()?;
    parse_statm_content(&content)
}

/// Parse statm file content (for testing).
pub fn parse_statm_content(content: &str) -> Option<MemStats> {
    let parts: Vec<&str> = content.trim().split_whitespace().collect();
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

/// Parse /proc/[pid]/fd/ directory.
///
/// Counts and categorizes open file descriptors.
pub fn parse_fd(pid: u32) -> Option<FdInfo> {
    let path = format!("/proc/{}/fd", pid);
    parse_fd_dir(Path::new(&path))
}

/// Parse fd directory (for testing with mock directories).
pub fn parse_fd_dir(dir: &Path) -> Option<FdInfo> {
    let mut info = FdInfo::default();

    let entries = fs::read_dir(dir).ok()?;

    for entry in entries.flatten() {
        info.count += 1;

        // Try to read the symlink to categorize
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();
            let fd_type = categorize_fd(&target_str);

            *info.by_type.entry(fd_type.clone()).or_insert(0) += 1;

            match fd_type.as_str() {
                "socket" => info.sockets += 1,
                "pipe" => info.pipes += 1,
                "file" => info.files += 1,
                "device" => info.devices += 1,
                _ => {}
            }
        }
    }

    Some(info)
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

/// Parse /proc/[pid]/wchan file.
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

/// Parse /proc/[pid]/cgroup file.
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
                info.v1_paths.insert(controller.to_string(), path.to_string());
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

/// Parse /proc/[pid]/environ file.
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

        if let Ok(s) = std::str::from_utf8(entry) {
            if let Some((key, value)) = s.split_once('=') {
                env.insert(key.to_string(), value.to_string());
            }
        }
    }

    Some(env)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(info.v1_paths.get("pids"), Some(&"/docker/abc123def456".to_string()));
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
}
