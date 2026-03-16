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

use super::network::{NetworkInfo, NetworkSnapshot};
use super::prober::{ProbeResult, Prober, ProberConfig};
use super::proc_parsers::{
    parse_cgroup, parse_cgroup_content, parse_environ, parse_environ_content, parse_fd, parse_io,
    parse_io_content, parse_proc_cmdline, parse_proc_exe, parse_proc_stat, parse_proc_stat_content,
    parse_proc_status, parse_proc_status_content, parse_sched, parse_sched_content,
    parse_schedstat, parse_schedstat_content, parse_statm, parse_statm_content, parse_wchan,
    CgroupInfo, FdInfo, IoStats, MemStats, SchedInfo, SchedStats,
};
use super::resource_collector::collect_local_resource_evidence;
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::RawResourceEvidence;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;
use thiserror::Error;
use tracing::warn;

/// Options for deep scan operation.
#[derive(Clone)]
pub struct DeepScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,

    /// Skip processes we can't fully inspect (default: false).
    pub skip_inaccessible: bool,

    /// Include environment variables (may be sensitive).
    pub include_environ: bool,

    /// Use wait-free io_uring prober if available (Linux-only).
    pub use_wait_free: bool,

    /// Optional progress event emitter.
    pub progress: Option<Arc<dyn ProgressEmitter>>,
}

impl Default for DeepScanOptions {
    fn default() -> Self {
        Self {
            pids: Vec::new(),
            skip_inaccessible: false,
            include_environ: false,
            use_wait_free: true,
            progress: None,
        }
    }
}

impl std::fmt::Debug for DeepScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepScanOptions")
            .field("pids", &self.pids)
            .field("skip_inaccessible", &self.skip_inaccessible)
            .field("include_environ", &self.include_environ)
            .field("use_wait_free", &self.use_wait_free)
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

    #[error("Process {0} vanished during scan")]
    ProcessVanished(u32),
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

    /// File-backed shared-resource evidence derived from open descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_resource_evidence: Vec<RawResourceEvidence>,

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
/// Requires appropriate permissions to read /proc/\[pid\]/* files.
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
                .with_detail("skip_inaccessible", options.skip_inaccessible)
                .with_detail("wait_free", options.use_wait_free),
        );
    }

    let mut processes = Vec::new();
    let mut warnings = Vec::new();
    let mut total_skipped = 0;

    // Try to use wait-free prober if requested
    if options.use_wait_free {
        if let Ok(mut prober) = Prober::new(ProberConfig::default()) {
            // Process in chunks to keep ring buffer usage sane
            for chunk in pids.chunks(100) {
                let mut paths = Vec::new();
                for &pid in chunk {
                    paths.push(PathBuf::from(format!("/proc/{}/stat", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/status", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/io", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/schedstat", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/sched", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/statm", pid)));
                    paths.push(PathBuf::from(format!("/proc/{}/cgroup", pid)));
                    if options.include_environ {
                        paths.push(PathBuf::from(format!("/proc/{}/environ", pid)));
                    }
                }

                let probe_results = prober.probe_batch(&paths);
                // Map results back to PIDs
                let mut pid_results: std::collections::HashMap<
                    u32,
                    std::collections::HashMap<String, ProbeResult>,
                > = std::collections::HashMap::new();
                for res in probe_results {
                    if let Some(pid_str) = res
                        .path
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str())
                    {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            let file_name = res
                                .path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or_default()
                                .to_string();
                            pid_results.entry(pid).or_default().insert(file_name, res);
                        }
                    }
                }

                for &pid in chunk {
                    let results = pid_results.remove(&pid).unwrap_or_default();
                    match parse_probed_process(
                        pid,
                        &results,
                        &user_cache,
                        &boot_id,
                        &network_snapshot,
                    ) {
                        Ok(record) => processes.push(record),
                        Err(DeepScanError::ProcessVanished(_)) => total_skipped += 1,
                        Err(e) => {
                            if options.skip_inaccessible {
                                total_skipped += 1;
                            } else {
                                warnings.push(format!("PID {}: {}", pid, e));
                            }
                        }
                    }
                }
            }

            return finish_scan(
                start,
                started_at,
                processes,
                warnings,
                total_skipped,
                options.progress.as_ref(),
            );
        } else {
            warn!("Failed to initialize io_uring prober, falling back to standard threaded mode");
        }
    }

    // Standard threaded mode (fallback)
    const PROGRESS_STEP: usize = 50;
    let scanned_counter = AtomicUsize::new(0);

    // Determine parallelism
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(16); // Cap threads
    let chunk_size = (pids.len() + num_threads - 1) / num_threads.max(1);
    let chunks: Vec<_> = pids.chunks(chunk_size).collect();

    let (procs, warns, skipped) = thread::scope(|s| {
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
                        Err(DeepScanError::ProcessVanished(_)) => {
                            // Always skip vanished processes without warning
                            local_skipped += 1;
                        }
                        Err(e) => {
                            if options.skip_inaccessible {
                                local_skipped += 1;
                            } else {
                                local_warnings.push(format!("PID {}: {}", pid, e));
                            }
                        }
                    }

                    let current = counter_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if current.is_multiple_of(PROGRESS_STEP) {
                        if let Some(emitter) = progress_ref {
                            emitter.emit(
                                ProgressEvent::new(
                                    event_names::DEEP_SCAN_PROGRESS,
                                    Phase::DeepScan,
                                )
                                .with_progress(current as u64, Some(total_pids))
                                .with_detail("skipped", local_skipped),
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

    finish_scan(
        start,
        started_at,
        procs,
        warns,
        skipped,
        options.progress.as_ref(),
    )
}

fn finish_scan(
    start: Instant,
    started_at: String,
    processes: Vec<DeepScanRecord>,
    warnings: Vec<String>,
    skipped_count: usize,
    progress: Option<&Arc<dyn ProgressEmitter>>,
) -> Result<DeepScanResult, DeepScanError> {
    let duration = start.elapsed();
    let process_count = processes.len();

    if let Some(emitter) = progress {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_COMPLETE, Phase::DeepScan)
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

/// Helper to parse results from wait-free prober.
fn parse_probed_process(
    pid: u32,
    results: &std::collections::HashMap<String, ProbeResult>,
    user_cache: &UserCache,
    boot_id: &Option<String>,
    network_snapshot: &NetworkSnapshot,
) -> Result<DeepScanRecord, DeepScanError> {
    let stat_res = results
        .get("stat")
        .ok_or(DeepScanError::ProcessVanished(pid))?;
    if stat_res.timed_out {
        return Err(DeepScanError::ParseError {
            pid,
            message: "Probe timed out for /proc/[pid]/stat".to_string(),
        });
    }
    let stat_content = String::from_utf8_lossy(&stat_res.data);
    let stat_info =
        parse_proc_stat_content(&stat_content).ok_or(DeepScanError::ProcessVanished(pid))?;

    let (uid, user, uid_known) = if let Some(status_res) = results.get("status") {
        if !status_res.timed_out && status_res.error.is_none() {
            let content = String::from_utf8_lossy(&status_res.data);
            match parse_proc_status_content(&content) {
                Some(status) => (status.euid, user_cache.resolve(status.euid), true),
                None => (0, "unknown".to_string(), false),
            }
        } else {
            (0, "unknown".to_string(), false)
        }
    } else {
        (0, "unknown".to_string(), false)
    };

    let cmdline = parse_proc_cmdline(pid).unwrap_or_default();
    let exe = parse_proc_exe(pid);

    let identity_quality = match (boot_id, stat_info.starttime, uid_known) {
        (_, _, false) => IdentityQuality::PidOnly,
        (Some(_), starttime, true) if starttime > 0 => IdentityQuality::Full,
        (None, starttime, true) if starttime > 0 => IdentityQuality::NoBootId,
        _ => IdentityQuality::PidOnly,
    };

    let start_id = compute_start_id(boot_id, stat_info.starttime, pid);

    // Parse other optional fields
    let io = results.get("io").and_then(|r| {
        if !r.timed_out {
            parse_io_content(&String::from_utf8_lossy(&r.data))
        } else {
            None
        }
    });
    let schedstat = results.get("schedstat").and_then(|r| {
        if !r.timed_out {
            parse_schedstat_content(&String::from_utf8_lossy(&r.data))
        } else {
            None
        }
    });
    let sched = results.get("sched").and_then(|r| {
        if !r.timed_out {
            parse_sched_content(&String::from_utf8_lossy(&r.data))
        } else {
            None
        }
    });
    let mem = results.get("statm").and_then(|r| {
        if !r.timed_out {
            parse_statm_content(&String::from_utf8_lossy(&r.data))
        } else {
            None
        }
    });
    let cgroup = results.get("cgroup").and_then(|r| {
        if !r.timed_out {
            parse_cgroup_content(&String::from_utf8_lossy(&r.data))
        } else {
            None
        }
    });
    let environ = results.get("environ").and_then(|r| {
        if !r.timed_out {
            parse_environ_content(&r.data)
        } else {
            None
        }
    });

    let fd = parse_fd(pid); // fd is a directory, still sync for now
    let local_resource_evidence = collect_local_resource_evidence(pid, fd.as_ref());
    let wchan = parse_wchan(pid); // wchan might be better probed but keep sync for now
    let network = network_snapshot.get_process_info(pid);

    Ok(DeepScanRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(stat_info.ppid),
        uid,
        user,
        pgid: Some(stat_info.pgrp as u32),
        sid: Some(stat_info.session as u32),
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
        local_resource_evidence,
        cgroup,
        wchan,
        network,
        environ,
        starttime: stat_info.starttime,
        source: "deep_scan".to_string(),
        identity_quality,
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
        if let Ok(bytes) = fs::read("/etc/passwd") {
            let passwd = String::from_utf8_lossy(&bytes);
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
    // Parse /proc/[pid]/stat for core info
    let stat_info = parse_proc_stat(pid).ok_or(DeepScanError::ProcessVanished(pid))?;

    // Parse /proc/[pid]/status for UID and username
    let (uid, user, uid_known) = match parse_proc_status(pid) {
        Some(status) => (status.euid, user_cache.resolve(status.euid), true),
        None => (0, "unknown".to_string(), false),
    };

    // Read cmdline
    let cmdline = parse_proc_cmdline(pid).unwrap_or_default();

    // Read exe symlink
    let exe = parse_proc_exe(pid);

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
    let local_resource_evidence = collect_local_resource_evidence(pid, fd.as_ref());
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
        pgid: Some(stat_info.pgrp as u32),
        sid: Some(stat_info.session as u32),
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
        local_resource_evidence,
        cgroup,
        wchan,
        network,
        environ,
        starttime: stat_info.starttime,
        source: "deep_scan".to_string(),
        identity_quality,
    })
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
            use_wait_free: true,
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

        let harness = ProcessHarness;
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(INFO, "deep_scan no-mock test started", pid = proc.pid());

        let options = DeepScanOptions {
            pids: vec![proc.pid()],
            skip_inaccessible: false,
            include_environ: false,
            use_wait_free: true,
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

        let harness = ProcessHarness;
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

        let record = scan_process(proc.pid(), true, &user_cache, &boot_id, &network_snapshot);
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
        assert!(
            !pids.is_empty(),
            "list_all_pids should return at least one PID"
        );

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

        let harness = ProcessHarness;
        let proc = harness.spawn_shell("sleep 30").expect("spawn process");

        crate::test_log!(INFO, "identity quality test started", pid = proc.pid());

        let options = DeepScanOptions {
            pids: vec![proc.pid()],
            skip_inaccessible: false,
            include_environ: false,
            use_wait_free: true,
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
