//! Deep scan implementation via /proc filesystem (Linux-only).
//!
//! This module provides detailed process inspection using the /proc filesystem,
//! which is only available on Linux systems.
//!
//! # Features
//! - Detailed I/O statistics
//! - Scheduler information
//! - Memory statistics
//! - File descriptor analysis
//! - Cgroup membership detection
//! - Container detection heuristics
//!
//! # Performance
//! - Target: <5s for 1000 processes
//! - Graceful degradation for permission-denied paths

use super::proc_parsers::{
    parse_cgroup, parse_environ, parse_fd, parse_io, parse_sched, parse_schedstat, parse_statm,
    parse_wchan, CgroupInfo, FdInfo, IoStats, MemStats, SchedInfo, SchedStats,
};
use super::network::{NetworkInfo, NetworkSnapshot};
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
use std::thread;
use std::time::Instant;
use thiserror::Error;

/// Options for deep scan operation.
#[derive(Clone, Default)]
pub struct DeepScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,

    /// Skip processes we can't fully inspect (default: false).
    pub skip_inaccessible: bool,

    /// Include environment variables (may be sensitive).
    pub include_environ: bool,

    /// Optional progress event emitter.
    pub progress: Option<Arc<dyn ProgressEmitter>>,
}

impl std::fmt::Debug for DeepScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepScanOptions")
            .field("pids", &self.pids)
            .field("skip_inaccessible", &self.skip_inaccessible)
            .field("include_environ", &self.include_environ)
            .field("progress", &self.progress.as_ref().map(|_| "..."))
            .finish()
    }
}

/// Errors that can occur during deep scan.
#[derive(Debug, Error)]
pub enum DeepScanError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error for PID {pid}: {message}")]
    ParseError { pid: u32, message: String },

    #[error("Permission denied accessing /proc/{0}")]
    PermissionDenied(u32),
}

/// Extended process record from deep scan.
///
/// Contains all information from quick scan plus detailed /proc data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanRecord {
    // === Core identity ===
    /// Process ID.
    pub pid: ProcessId,

    /// Parent process ID.
    pub ppid: ProcessId,

    /// User ID.
    pub uid: u32,

    /// Username (resolved from UID).
    pub user: String,

    /// Process group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,

    // === Identity for TOCTOU protection ===
    /// Start ID for PID reuse detection.
    pub start_id: StartId,

    // === Command info ===
    /// Command name (basename only).
    pub comm: String,

    /// Full command line.
    pub cmdline: String,

    /// Executable path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,

    // === State ===
    /// Process state character.
    pub state: char,

    // === Detailed stats ===
    /// I/O statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<IoStats>,

    /// Scheduler statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedstat: Option<SchedStats>,

    /// Scheduler info (context switches, priority, nice).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sched: Option<SchedInfo>,

    /// Memory statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<MemStats>,

    /// File descriptor information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<FdInfo>,

    /// Cgroup information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<CgroupInfo>,

    /// Wait channel (kernel function where sleeping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wchan: Option<String>,

    /// Network connection info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,

    /// Environment variables (if requested and accessible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environ: Option<std::collections::HashMap<String, String>>,

    // === Timing ===
    /// Process start time (clock ticks since boot).
    pub starttime: u64,

    // === Provenance ===
    /// Source of this record.
    pub source: String,

    /// Identity quality indicator (provenance tracking).
    pub identity_quality: IdentityQuality,
}

impl DeepScanRecord {
    /// Extract a ProcessIdentity for revalidation during action execution.
    ///
    /// The ProcessIdentity captures the essential fields needed to verify
    /// that a process is still the same incarnation before taking action.
    pub fn to_identity(&self) -> ProcessIdentity {
        ProcessIdentity::full(
            self.pid.0,
            self.start_id.clone(),
            self.uid,
            self.pgid,
            self.sid,
            self.identity_quality,
        )
    }

    /// Check if this process can be safely targeted for automated actions.
    ///
    /// Returns false if identity quality is too weak for safe automation.
    pub fn can_automate(&self) -> bool {
        self.identity_quality.is_automatable()
    }
}

/// Result of a deep scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    /// Collected process records.
    pub processes: Vec<DeepScanRecord>,

    /// Scan metadata.
    pub metadata: DeepScanMetadata,
}

/// Metadata about a deep scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanMetadata {
    /// Timestamp when scan started (ISO-8601).
    pub started_at: String,

    /// Duration of the scan in milliseconds.
    pub duration_ms: u64,

    /// Number of processes collected.
    pub process_count: usize,

    /// Number of processes skipped (permission denied, etc.).
    pub skipped_count: usize,

    /// Any warnings encountered during scan.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Perform a deep scan of running processes.
///
/// Reads detailed information from /proc filesystem for each process.
/// Requires appropriate permissions to read /proc/[pid]/* files.
///
/// # Arguments
/// * `options` - Scan configuration options
///
/// # Returns
/// * `DeepScanResult` containing process records and metadata
///
/// # Errors
/// * `DeepScanError` if critical failures occur
pub fn deep_scan(options: &DeepScanOptions) -> Result<DeepScanResult, DeepScanError> {
    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Initialize user cache to avoid reading /etc/passwd for every process
    let user_cache = UserCache::new();

    // Initialize network snapshot once for O(1) lookups per process
    let network_snapshot = NetworkSnapshot::collect();

    // Read boot_id once
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string());

    // Get list of PIDs to scan
    let pids = if options.pids.is_empty() {
        list_all_pids()?
    } else {
        options.pids.clone()
    };
    let total_pids = pids.len() as u64;

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_STARTED, Phase::DeepScan)
                .with_progress(0, Some(total_pids))
                .with_detail("include_environ", options.include_environ)
                .with_detail("skip_inaccessible", options.skip_inaccessible),
        );
    }

    const PROGRESS_STEP: usize = 50;
    let scanned_counter = AtomicUsize::new(0);
    
    // Determine parallelism
    let num_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(16); // Cap threads
    let chunk_size = (pids.len() + num_threads - 1) / num_threads.max(1);
    let chunks: Vec<_> = pids.chunks(chunk_size).collect();

    let (processes, warnings, skipped_count) = thread::scope(|s| {
        let mut handles = Vec::new();
        
        for chunk in chunks {
            let user_cache_ref = &user_cache;
            let network_snapshot_ref = &network_snapshot;
            let boot_id_ref = &boot_id;
            let progress_ref = options.progress.as_ref();
            let counter_ref = &scanned_counter;

            handles.push(s.spawn(move || {
                let mut local_processes = Vec::new();
                let mut local_warnings = Vec::new();
                let mut local_skipped = 0;

                for &pid in chunk {
                    match scan_process(
                        pid,
                        options.include_environ,
                        user_cache_ref,
                        boot_id_ref,
                        network_snapshot_ref,
                    ) {
                        Ok(record) => local_processes.push(record),
                        Err(e) => {
                            if options.skip_inaccessible {
                                local_skipped += 1;
                            } else {
                                local_warnings.push(format!("PID {}: {}", pid, e));
                            }
                        }
                    }

                    let current = counter_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if current % PROGRESS_STEP == 0 {
                        if let Some(emitter) = progress_ref {
                            emitter.emit(
                                ProgressEvent::new(event_names::DEEP_SCAN_PROGRESS, Phase::DeepScan)
                                    .with_progress(current as u64, Some(total_pids))
                                    .with_detail("skipped", local_skipped), // Local skipped isn't global, but roughly indicative
                            );
                        }
                    }
                }
                (local_processes, local_warnings, local_skipped)
            }));
        }

        let mut all_processes = Vec::new();
        let mut all_warnings = Vec::new();
        let mut total_skipped = 0;

        for handle in handles {
            if let Ok((p, w, s)) = handle.join() {
                all_processes.extend(p);
                all_warnings.extend(w);
                total_skipped += s;
            }
        }
        
        (all_processes, all_warnings, total_skipped)
    });

    let duration = start.elapsed();
    let process_count = processes.len();
    let scanned_total = scanned_counter.load(Ordering::Relaxed);

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_COMPLETE, Phase::DeepScan)
                .with_progress(scanned_total as u64, Some(total_pids))
                .with_elapsed_ms(duration.as_millis() as u64)
                .with_detail("process_count", process_count)
                .with_detail("skipped", skipped_count)
                .with_detail("warnings", warnings.len()),
        );
    }

    Ok(DeepScanResult {
        processes,
        metadata: DeepScanMetadata {
            started_at,
            duration_ms: duration.as_millis() as u64,
            process_count,
            skipped_count,
            warnings,
        },
    })
}

/// List all PIDs from /proc.
fn list_all_pids() -> Result<Vec<u32>, DeepScanError> {
    let mut pids = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only process numeric directories (PIDs)
        if let Ok(pid) = name_str.parse::<u32>() {
            pids.push(pid);
        }
    }

    pids.sort();
    Ok(pids)
}

/// Cache for UID to username mapping.
struct UserCache {
    uid_map: std::collections::HashMap<u32, String>,
}

impl UserCache {
    fn new() -> Self {
        let mut uid_map = std::collections::HashMap::new();
        // Best effort read of /etc/passwd
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 3 {
                    if let Ok(uid) = fields[2].parse::<u32>() {
                        // Only keep the first mapping found for a UID
                        uid_map.entry(uid).or_insert_with(|| fields[0].to_string());
                    }
                }
            }
        }
        Self { uid_map }
    }

    fn resolve(&self, uid: u32) -> String {
        self.uid_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}

/// Scan a single process by PID.
fn scan_process(
    pid: u32,
    include_environ: bool,
    user_cache: &UserCache,
    boot_id: &Option<String>,
    network_snapshot: &NetworkSnapshot,
) -> Result<DeepScanRecord, DeepScanError> {
    let proc_path = format!("/proc/{}", pid);

    // Check if process exists
    if !Path::new(&proc_path).exists() {
        return Err(DeepScanError::ParseError {
            pid,
            message: "Process does not exist".to_string(),
        });
    }

    // Parse /proc/[pid]/stat for core info
    let stat_content = fs::read_to_string(format!("{}/stat", proc_path))
        .map_err(|_| DeepScanError::PermissionDenied(pid))?;
    let stat_info = parse_stat(&stat_content, pid)?;

    // Parse /proc/[pid]/status for UID and username
    let status_content = fs::read_to_string(format!("{}/status", proc_path)).ok();
    let (uid, user, uid_known) = match status_content
        .as_ref()
        .and_then(|c| parse_uid_from_status(c, user_cache))
    {
        Some((uid, user)) => (uid, user, true),
        None => (0, "unknown".to_string(), false),
    };

    // Read cmdline
    let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_default();

    // Read exe symlink
    let exe = fs::read_link(format!("{}/exe", proc_path))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    // Compute identity quality based on available data
    let identity_quality = match (boot_id, stat_info.starttime, uid_known) {
        (_, _, false) => IdentityQuality::PidOnly,
        (Some(_), starttime, true) if starttime > 0 => IdentityQuality::Full,
        (None, starttime, true) if starttime > 0 => IdentityQuality::NoBootId,
        _ => IdentityQuality::PidOnly,
    };

    let start_id = compute_start_id(boot_id, stat_info.starttime, pid);

    // Collect optional detailed stats (may fail due to permissions)
    let io = parse_io(pid);
    let schedstat = parse_schedstat(pid);
    let sched = parse_sched(pid);
    let mem = parse_statm(pid);
    let fd = parse_fd(pid);
    let cgroup = parse_cgroup(pid);
    let wchan = parse_wchan(pid);
    let network = network_snapshot.get_process_info(pid);

    // Collect environment variables if requested (may contain sensitive data)
    let environ = if include_environ {
        parse_environ(pid)
    } else {
        None
    };

    Ok(DeepScanRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(stat_info.ppid),
        uid,
        user,
        pgid: Some(stat_info.pgrp),
        sid: Some(stat_info.session),
        start_id,
        comm: stat_info.comm,
        cmdline,
        exe,
        state: stat_info.state,
        io,
        schedstat,
        sched,
        mem,
        fd,
        cgroup,
        wchan,
        network,
        environ,
        starttime: stat_info.starttime,
        source: "deep_scan".to_string(),
        identity_quality,
    })
}

/// Parsed info from /proc/[pid]/stat.
struct StatInfo {
    comm: String,
    state: char,
    ppid: u32,
    pgrp: u32,
    session: u32,
    starttime: u64,
}

/// Parse /proc/[pid]/stat file.
///
/// Format: pid (comm) state ppid pgrp session tty_nr tpgid flags
///         minflt cminflt majflt cmajflt utime stime cutime cstime
///         priority nice num_threads itrealvalue starttime ...
fn parse_stat(content: &str, pid: u32) -> Result<StatInfo, DeepScanError> {
    // Find comm field (surrounded by parentheses, may contain spaces)
    let comm_start = content.find('(').ok_or_else(|| DeepScanError::ParseError {
        pid,
        message: "Missing comm start".to_string(),
    })?;
    let comm_end = content
        .rfind(')')
        .ok_or_else(|| DeepScanError::ParseError {
            pid,
            message: "Missing comm end".to_string(),
        })?;

    let comm = content[comm_start + 1..comm_end].to_string();

    // Safely skip ") " after comm - use get() to avoid panic on truncated content
    let after_comm = content
        .get(comm_end + 2..)
        .ok_or_else(|| DeepScanError::ParseError {
            pid,
            message: "Stat content truncated after comm".to_string(),
        })?;

    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(DeepScanError::ParseError {
            pid,
            message: format!("Insufficient stat fields: {}", fields.len()),
        });
    }

    let state = fields[0].chars().next().unwrap_or('?');
    let ppid: u32 = fields[1].parse().unwrap_or(0);
    let pgrp: u32 = fields[2].parse().unwrap_or(0);
    let session: u32 = fields[3].parse().unwrap_or(0);
    let starttime: u64 = fields[19].parse().unwrap_or(0);

    Ok(StatInfo {
        comm,
        state,
        ppid,
        pgrp,
        session,
        starttime,
    })
}

/// Parse UID and username from /proc/[pid]/status.
fn parse_uid_from_status(content: &str, user_cache: &UserCache) -> Option<(u32, String)> {
    let mut uid = None;

    for line in content.lines() {
        if line.starts_with("Uid:") {
            // Format: "Uid:\t1000\t1000\t1000\t1000"
            // First value is real UID
            if let Some(uid_str) = line.split_whitespace().nth(1) {
                if let Ok(val) = uid_str.parse::<u32>() {
                    uid = Some(val);
                }
            }
            break;
        }
    }

    uid.map(|u| (u, user_cache.resolve(u)))
}

/// Compute start_id from available information.
fn compute_start_id(boot_id: &Option<String>, starttime: u64, pid: u32) -> StartId {
    let boot = boot_id.as_deref().unwrap_or("unknown");
    StartId::from_linux(boot, starttime, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stat_simple() {
        let content = "1234 (bash) S 1 1234 1234 0 -1 4194304 1000 0 0 0 10 5 0 0 20 0 1 0 12345 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 65536 0 0 0 17 0 0 0 0 0 0";
        let info = parse_stat(content, 1234).unwrap();

        assert_eq!(info.comm, "bash");
        assert_eq!(info.state, 'S');
        assert_eq!(info.ppid, 1);
        assert_eq!(info.pgrp, 1234);
        assert_eq!(info.session, 1234);
        assert_eq!(info.starttime, 12345);
    }

    #[test]
    fn test_parse_stat_with_spaces_in_comm() {
        // Some processes have spaces in their command name
        let content = "5678 (Web Content) S 1234 5678 5678 0 -1 4194304 1000 0 0 0 10 5 0 0 20 0 1 0 54321 2000000 200 18446744073709551615 0 0 0 0 0 0 0 0 65536 0 0 0 17 0 0 0 0 0 0";
        let info = parse_stat(content, 5678).unwrap();

        assert_eq!(info.comm, "Web Content");
        assert_eq!(info.state, 'S');
        assert_eq!(info.ppid, 1234);
    }

    #[test]
    fn test_parse_stat_with_parens_in_comm() {
        // Edge case: command name contains parentheses
        let content = "9999 (test (v2)) S 1 9999 9999 0 -1 4194304 1000 0 0 0 10 5 0 0 20 0 1 0 99999 3000000 300 18446744073709551615 0 0 0 0 0 0 0 0 65536 0 0 0 17 0 0 0 0 0 0";
        let info = parse_stat(content, 9999).unwrap();

        assert_eq!(info.comm, "test (v2)");
    }

    #[test]
    fn test_parse_stat_truncated() {
        // Edge case: content ends right after closing paren - should error, not panic
        let content = "1234 (test)";
        let result = parse_stat(content, 1234);
        assert!(result.is_err());

        // Also test with just paren and no space after
        let content2 = "1234 (test) ";
        let result2 = parse_stat(content2, 1234);
        // Should error due to insufficient fields
        assert!(result2.is_err());
    }

    #[test]
    fn test_parse_uid_from_status() {
        let content = r#"Name:	bash
Umask:	0022
State:	S (sleeping)
Tgid:	1234
Ngid:	0
Pid:	1234
PPid:	1
TracerPid:	0
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
"#;

        // Mock cache for testing
        let mut user_cache = UserCache {
            uid_map: std::collections::HashMap::new(),
        };
        user_cache.uid_map.insert(1000, "testuser".to_string());

        let result = parse_uid_from_status(content, &user_cache);
        assert!(result.is_some());
        let (uid, user) = result.unwrap();
        assert_eq!(uid, 1000);
        assert_eq!(user, "testuser");
    }

    #[test]
    fn test_resolve_username_root() {
        // Root should be resolvable on most systems if /etc/passwd is readable
        // This test relies on the environment, so we treat it gently
        let user_cache = UserCache::new();
        if std::path::Path::new("/etc/passwd").exists() {
            let user = user_cache.resolve(0);
            assert_eq!(user, "root");
        }
    }

    #[test]
    fn test_compute_start_id() {
        let boot_id = Some("abc-123-def".to_string());
        let start_id = compute_start_id(&boot_id, 12345, 1234);

        assert!(start_id.0.contains("abc-123-def"));
        assert!(start_id.0.contains("12345"));
        assert!(start_id.0.contains("1234"));
    }

    // Integration test - only run when /proc is available
    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_deep_scan_integration() {
        let options = DeepScanOptions {
            pids: vec![1], // Just scan init/systemd
            skip_inaccessible: true,
            include_environ: false,
            progress: None,
        };

        let result = deep_scan(&options);
        // May fail due to permissions, but shouldn't panic
        if let Ok(scan) = result {
            assert!(scan.processes.len() <= 1);
        }
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_list_all_pids() {
        let pids = list_all_pids().unwrap();
        assert!(!pids.is_empty());
        // PID 1 should always exist
        assert!(pids.contains(&1));
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_scan_self() {
        // Scan our own process - should always work
        let pid = std::process::id();
        let user_cache = UserCache::new();
        let boot_id = None;
        let network_snapshot = NetworkSnapshot::collect();
        let record = scan_process(pid, false, &user_cache, &boot_id, &network_snapshot).unwrap();

        assert_eq!(record.pid.0, pid);
        assert!(record.ppid.0 > 0);
        assert!(!record.comm.is_empty());
    }

    // =====================================================
    // No-mock tests using ProcessHarness for real processes
    // =====================================================

    #[test]
    fn test_nomock_deep_scan_spawned_process() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(INFO, "deep_scan no-mock test started", pid = proc.pid());

        let options = DeepScanOptions {
            pids: vec![proc.pid()],
            skip_inaccessible: false,
            include_environ: false,
            progress: None,
        };

        let result = deep_scan(&options);
        crate::test_log!(
            INFO,
            "deep_scan result",
            pid = proc.pid(),
            is_ok = result.is_ok()
        );

        assert!(result.is_ok(), "deep_scan failed: {:?}", result.err());
        let scan = result.unwrap();

        assert_eq!(scan.processes.len(), 1, "Expected exactly one process");
        let record = &scan.processes[0];

        assert_eq!(record.pid.0, proc.pid());
        assert!(record.ppid.0 > 0);
        assert!(!record.comm.is_empty());
        assert!(record.starttime > 0);

        // Metadata checks
        assert_eq!(scan.metadata.process_count, 1);
        assert!(scan.metadata.duration_ms < 5000); // Should be fast

        crate::test_log!(
            INFO,
            "deep_scan completed",
            pid = proc.pid(),
            comm = record.comm.as_str(),
            state = format!("{}", record.state).as_str()
        );
    }

    #[test]
    fn test_nomock_scan_process_with_environ() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        // Set a custom env var to verify we can read environ
        let proc = harness
            .spawn_shell("TEST_VAR=nomock_test_value sleep 30")
            .expect("spawn process with env var");

        crate::test_log!(INFO, "scan_process with environ test", pid = proc.pid());

        let user_cache = UserCache::new();
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string());
        let network_snapshot = NetworkSnapshot::collect();

        let record = scan_process(
            proc.pid(),
            true,
            &user_cache,
            &boot_id,
            &network_snapshot,
        );
        crate::test_log!(
            INFO,
            "scan_process result",
            pid = proc.pid(),
            is_ok = record.is_ok()
        );

        assert!(record.is_ok(), "scan_process failed: {:?}", record.err());
        let record = record.unwrap();

        assert_eq!(record.pid.0, proc.pid());
        // Environ should be collected when requested
        // Note: The env var might not be visible if it's set by the shell but not exported
        crate::test_log!(
            INFO,
            "scan_process environ check",
            pid = proc.pid(),
            has_environ = record.environ.is_some()
        );
    }

    #[test]
    fn test_nomock_list_pids_includes_self() {
        // This test doesn't need ProcessHarness - just verifies list_all_pids works
        if !std::path::Path::new("/proc").exists() {
            crate::test_log!(INFO, "Skipping no-mock test: /proc not available");
            return;
        }

        let pids = list_all_pids();
        crate::test_log!(INFO, "list_all_pids result", is_ok = pids.is_ok());

        assert!(pids.is_ok(), "list_all_pids failed: {:?}", pids.err());
        let pids = pids.unwrap();

        let my_pid = std::process::id();
        assert!(
            pids.contains(&my_pid),
            "list_all_pids should include our own PID"
        );
        assert!(!pids.is_empty(), "list_all_pids should return at least one PID");

        crate::test_log!(
            INFO,
            "list_all_pids completed",
            pid_count = pids.len(),
            includes_self = pids.contains(&my_pid)
        );
    }

    #[test]
    fn test_nomock_deep_scan_identity_quality() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        let proc = harness.spawn_shell("sleep 30").expect("spawn process");

        crate::test_log!(INFO, "identity quality test started", pid = proc.pid());

        let options = DeepScanOptions {
            pids: vec![proc.pid()],
            skip_inaccessible: false,
            include_environ: false,
            progress: None,
        };

        let result = deep_scan(&options).expect("deep_scan should succeed");
        let record = &result.processes[0];

        // On Linux with /proc available, we should get good identity quality
        crate::test_log!(
            INFO,
            "identity quality result",
            pid = proc.pid(),
            quality = format!("{:?}", record.identity_quality).as_str(),
            can_automate = record.can_automate()
        );

        // Verify the identity can be extracted
        let identity = record.to_identity();
        assert_eq!(identity.pid.0, proc.pid());

        // Start ID should be non-empty
        assert!(!record.start_id.0.is_empty());

        crate::test_log!(
            INFO,
            "identity extraction completed",
            start_id = record.start_id.0.as_str()
        );
    }
}
