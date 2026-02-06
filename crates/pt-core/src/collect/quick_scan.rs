//! Quick scan implementation via ps command.
//!
//! This module provides fast process collection using the ps command,
//! which is universally available across Unix systems.
//!
//! # Platform Support
//! - Linux: Uses procps-ng ps with extended format
//! - macOS: Uses BSD ps with compatible format
//!
//! # Performance
//! - Target: <1s for 1000 processes
//! - Single ps invocation with custom format string

use super::types::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::{ProcessId, StartId};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, span, Level};

/// Options for quick scan operation.
#[derive(Clone, Default)]
pub struct QuickScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,

    /// Include kernel threads (Linux only).
    pub include_kernel_threads: bool,

    /// Timeout for ps command (default: 10 seconds).
    pub timeout: Option<Duration>,

    /// Optional progress event emitter.
    pub progress: Option<Arc<dyn ProgressEmitter>>,
}

impl std::fmt::Debug for QuickScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuickScanOptions")
            .field("pids", &self.pids)
            .field("include_kernel_threads", &self.include_kernel_threads)
            .field("timeout", &self.timeout)
            .field("progress", &self.progress.as_ref().map(|_| "..."))
            .finish()
    }
}

/// Errors that can occur during quick scan.
#[derive(Debug, Error)]
pub enum QuickScanError {
    #[error("Failed to execute ps command: {0}")]
    CommandFailed(String),

    #[error("Failed to parse ps output: {message} at line {line_num}")]
    ParseError { message: String, line_num: usize },

    #[error("ps command timed out after {0:?}")]
    Timeout(Duration),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
}

/// Perform a quick scan of running processes.
///
/// Uses the ps command with a custom format string to collect process
/// information efficiently in a single invocation.
///
/// # Arguments
/// * `options` - Scan configuration options
///
/// # Returns
/// * `ScanResult` containing process records and metadata
///
/// # Errors
/// * `QuickScanError` if ps fails or output cannot be parsed
pub fn quick_scan(options: &QuickScanOptions) -> Result<ScanResult, QuickScanError> {
    let _span = span!(Level::DEBUG, "quick_scan").entered();
    debug!("Starting quick scan via ps");

    let start = Instant::now();
    let platform = detect_platform();
    let boot_id = read_boot_id();

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::QUICK_SCAN_STARTED, Phase::QuickScan)
                .with_detail("platform", &platform)
                .with_detail("boot_id", &boot_id),
        );
    }

    // Build ps command
    let mut cmd = build_ps_command(&platform, options)?;

    // Execute and capture output
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| QuickScanError::CommandFailed(e.to_string()))?;

    let pid = child.id();
    let timeout = options.timeout.unwrap_or(Duration::from_secs(10));
    let finished = Arc::new(AtomicBool::new(false));
    let finished_clone = finished.clone();
    let timed_out = Arc::new(AtomicBool::new(false));
    let timed_out_clone = timed_out.clone();

    // Spawn watchdog thread
    thread::spawn(move || {
        thread::sleep(timeout);
        if !finished_clone.load(Ordering::Relaxed) {
            timed_out_clone.store(true, Ordering::Relaxed);
            debug!("Quick scan timed out, killing ps process {}", pid);
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    });

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| QuickScanError::CommandFailed("Failed to capture stdout".to_string()))?;

    let reader = BufReader::new(stdout);
    let mut processes = Vec::new();
    let mut warnings = Vec::new();

    // Parse output
    let lines = reader.lines();
    let mut header_checked = false;

    let mut processed = 0usize;
    const PROGRESS_STEP: usize = 200;

    for (line_num, line_result) in lines.enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        if !header_checked {
            header_checked = true;
            if is_header_line(&line) {
                continue;
            }
        }

        match parse_ps_line(&line, &platform, &boot_id) {
            Ok(record) => {
                // Filter kernel threads if not requested AND not targeting specific PIDs.
                // If user explicitly asks for specific PIDs, we respect that even for kernel threads.
                let is_targeting_specific_pids = !options.pids.is_empty();
                if !options.include_kernel_threads
                    && !is_targeting_specific_pids
                    && is_kernel_thread(&record)
                {
                    debug!(
                        pid = record.pid.0,
                        ppid = record.ppid.0,
                        comm = %record.comm,
                        "Filtered kernel thread from scan"
                    );
                    continue;
                }
                processes.push(record);
            }
            Err(e) => {
                warnings.push(format!("Line {}: {}", line_num + 1, e));
            }
        }

        processed += 1;
        if processed % PROGRESS_STEP == 0 {
            if let Some(emitter) = options.progress.as_ref() {
                emitter.emit(
                    ProgressEvent::new(event_names::QUICK_SCAN_PROGRESS, Phase::QuickScan)
                        .with_progress(processed as u64, None)
                        .with_detail("pids_scanned", processed),
                );
            }
        }
    }

    // Mark as finished before waiting, so we don't race with PID reuse
    finished.store(true, Ordering::Relaxed);

    // Wait for child process to avoid leaving zombies
    let _ = child.wait();

    let duration = start.elapsed();
    let process_count = processes.len();

    if timed_out.load(Ordering::Relaxed) {
        debug!(
            duration_ms = duration.as_millis(),
            process_count, "Quick scan timed out"
        );
        return Err(QuickScanError::Timeout(timeout));
    }

    debug!(
        process_count = processes.len(),
        duration_ms = duration.as_millis(),
        "Quick scan completed"
    );

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::QUICK_SCAN_COMPLETE, Phase::QuickScan)
                .with_progress(process_count as u64, Some(process_count as u64))
                .with_elapsed_ms(duration.as_millis() as u64)
                .with_detail("warnings", warnings.len()),
        );
    }

    Ok(ScanResult {
        processes,
        metadata: ScanMetadata {
            scan_type: "quick".to_string(),
            platform,
            boot_id,
            started_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: duration.as_millis() as u64,
            process_count,
            warnings,
        },
    })
}

fn is_header_line(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    matches!(
        (parts.next(), parts.next()),
        (Some("PID"), Some("PPID")) | (Some("pid"), Some("ppid"))
    )
}

// ---------------------------------------------------------------------------
// Deterministic parsing helpers (bench + tests)
// ---------------------------------------------------------------------------

/// Deterministically parse Linux `ps` output into `ProcessRecord`s without
/// consulting `/proc` for boot_id/uptime-derived ticks.
///
/// This exists to support **CI-stable benchmarks** (and potential fixture-based
/// tests). It is not part of the end-user CLI surface.
#[doc(hidden)]
pub fn parse_ps_output_synthetic_linux(output: &str) -> Result<Vec<ProcessRecord>, QuickScanError> {
    // A fixed reference time makes elapsed/start_time values deterministic.
    const NOW_UNIX: i64 = 1_700_000_000;
    const PLATFORM: &str = "linux";
    let boot_id = Some("synthetic".to_string());

    let mut processes = Vec::new();
    let mut header_checked = false;

    for (line_num, line) in output.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if !header_checked {
            header_checked = true;
            if is_header_line(line) {
                continue;
            }
        }

        let record = parse_ps_line_synthetic(line, PLATFORM, &boot_id, NOW_UNIX).map_err(|e| {
            QuickScanError::ParseError {
                message: e,
                line_num: line_num + 1,
            }
        })?;
        processes.push(record);
    }

    Ok(processes)
}

/// Detect the current platform.
fn detect_platform() -> String {
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::env::consts::OS.to_string()
    }
}

/// Read boot ID from /proc/sys/kernel/random/boot_id (Linux only).
fn read_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Build the ps command with platform-specific format string.
fn build_ps_command(platform: &str, options: &QuickScanOptions) -> Result<Command, QuickScanError> {
    let mut cmd = Command::new("ps");

    match platform {
        "linux" => {
            // Linux ps format: pid ppid uid user pgid sid state %cpu rss vsz tty start_time etimes comm cmd
            // Using -eo for custom format, -ww for wide output
            cmd.args([
                "-eo",
                "pid,ppid,uid,user,pgid,sid,state,%cpu,rss,vsz,tty,lstart,etimes,comm,args",
                "--no-headers",
                "-ww",
            ]);
        }
        "macos" => {
            // macOS ps format (BSD style)
            // Note: macOS ps has different field names
            cmd.args([
                "-eo",
                "pid,ppid,uid,user,pgid,sess,state,%cpu,rss,vsz,tty,lstart,etime,comm,args",
            ]);
        }
        other => {
            return Err(QuickScanError::UnsupportedPlatform(other.to_string()));
        }
    }

    // Filter to specific PIDs if requested
    if !options.pids.is_empty() {
        let pids: Vec<String> = options.pids.iter().map(|p| p.to_string()).collect();
        cmd.arg("-p");
        cmd.arg(pids.join(","));
    }

    Ok(cmd)
}

/// Parse a single line of ps output into a ProcessRecord.
fn parse_ps_line(
    line: &str,
    platform: &str,
    boot_id: &Option<String>,
) -> Result<ProcessRecord, String> {
    // Split line into fields, preserving command at the end
    let fields: Vec<&str> = line.split_whitespace().collect();

    let comm_idx = 17;
    if fields.len() <= comm_idx {
        return Err(format!(
            "Insufficient fields: expected {}+, got {}",
            comm_idx + 1,
            fields.len()
        ));
    }

    // Parse fixed-position fields
    let pid: u32 = fields[0].parse().map_err(|_| "Invalid PID")?;
    let ppid: u32 = fields[1].parse().map_err(|_| "Invalid PPID")?;
    let uid: u32 = fields[2].parse().map_err(|_| "Invalid UID")?;
    let user = fields[3].to_string();
    let pgid: u32 = fields[4].parse().map_err(|_| "Invalid PGID")?;
    let sid: u32 = fields[5].parse().map_err(|_| "Invalid SID")?;

    // State is single character (may have modifiers like S+, Ss, etc.)
    let state_char = fields[6].chars().next().unwrap_or('?');
    let state = ProcessState::from_char(state_char);

    let cpu_percent: f64 = fields[7].parse().unwrap_or(0.0);

    // RSS is in KB, convert to bytes
    let rss_kb: u64 = fields[8].parse().unwrap_or(0);
    let rss_bytes = rss_kb * 1024;

    // VSZ is in KB, convert to bytes
    let vsz_kb: u64 = fields[9].parse().unwrap_or(0);
    let vsz_bytes = vsz_kb * 1024;

    // TTY (? or - means no TTY)
    let tty_raw = fields[10];
    let tty = if tty_raw == "?" || tty_raw == "-" {
        None
    } else {
        Some(tty_raw.to_string())
    };

    // Parse lstart (platform-specific format)
    // Linux: "Tue Jan 14 10:30:00 2026"
    // macOS: "Tue Jan 14 10:30:00 2026"
    let (start_time_unix, elapsed) = parse_timing_fields(platform, &fields)?;

    let comm = fields.get(comm_idx).unwrap_or(&"").to_string();

    // Args/cmd is everything after comm (field 14+)
    let cmd = if fields.len() > comm_idx + 1 {
        fields[comm_idx + 1..].join(" ")
    } else {
        comm.clone()
    };

    // Compute start_id
    let start_id = compute_start_id(platform, boot_id, start_time_unix, elapsed, pid);

    Ok(ProcessRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(ppid),
        uid,
        user,
        pgid: Some(pgid),
        sid: Some(sid),
        start_id,
        comm,
        cmd,
        state,
        cpu_percent,
        rss_bytes,
        vsz_bytes,
        tty,
        start_time_unix,
        elapsed,
        source: "quick_scan".to_string(),
        container_info: None, // Container detection done as post-processing step
    })
}

/// Parse a single line of ps output like `parse_ps_line`, but with deterministic
/// timing + start_id derivation and no `/proc` reads (bench/test helper).
fn parse_ps_line_synthetic(
    line: &str,
    platform: &str,
    boot_id: &Option<String>,
    now_unix: i64,
) -> Result<ProcessRecord, String> {
    let fields: Vec<&str> = line.split_whitespace().collect();

    let comm_idx = 17;
    if fields.len() <= comm_idx {
        return Err(format!(
            "Insufficient fields: expected {}+, got {}",
            comm_idx + 1,
            fields.len()
        ));
    }

    let pid: u32 = fields[0].parse().map_err(|_| "Invalid PID")?;
    let ppid: u32 = fields[1].parse().map_err(|_| "Invalid PPID")?;
    let uid: u32 = fields[2].parse().map_err(|_| "Invalid UID")?;
    let user = fields[3].to_string();
    let pgid: u32 = fields[4].parse().map_err(|_| "Invalid PGID")?;
    let sid: u32 = fields[5].parse().map_err(|_| "Invalid SID")?;

    let state_char = fields[6].chars().next().unwrap_or('?');
    let state = ProcessState::from_char(state_char);

    let cpu_percent: f64 = fields[7].parse().unwrap_or(0.0);

    let rss_kb: u64 = fields[8].parse().unwrap_or(0);
    let rss_bytes = rss_kb * 1024;

    let vsz_kb: u64 = fields[9].parse().unwrap_or(0);
    let vsz_bytes = vsz_kb * 1024;

    let tty_raw = fields[10];
    let tty = if tty_raw == "?" || tty_raw == "-" {
        None
    } else {
        Some(tty_raw.to_string())
    };

    let (start_time_unix, elapsed) = parse_timing_fields_at(platform, &fields, now_unix)?;

    let comm = fields.get(comm_idx).unwrap_or(&"").to_string();
    let cmd = if fields.len() > comm_idx + 1 {
        fields[comm_idx + 1..].join(" ")
    } else {
        comm.clone()
    };

    let start_id = compute_start_id_synthetic(platform, boot_id, start_time_unix, pid);

    Ok(ProcessRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(ppid),
        uid,
        user,
        pgid: Some(pgid),
        sid: Some(sid),
        start_id,
        comm,
        cmd,
        state,
        cpu_percent,
        rss_bytes,
        vsz_bytes,
        tty,
        start_time_unix,
        elapsed,
        source: "quick_scan".to_string(),
        container_info: None,
    })
}

/// Parse timing fields from ps output.
fn parse_timing_fields(platform: &str, fields: &[&str]) -> Result<(i64, Duration), String> {
    // lstart is fields 11-15 (day month date time year) for Linux
    // etimes is field after that (seconds since start)

    // For simplicity, use etimes to compute elapsed time
    // and estimate start_time from current time - etimes

    let lstart_idx = 11;
    let etimes_idx = lstart_idx + 5;
    let etimes_str = fields
        .get(etimes_idx)
        .ok_or_else(|| format!("Missing etimes field for platform {platform}"))?;

    // Parse elapsed time
    let elapsed_secs: u64 = if etimes_str.contains(':') {
        // Format: [[dd-]hh:]mm:ss
        parse_etime_format(etimes_str).unwrap_or(0)
    } else {
        etimes_str.parse().unwrap_or(0)
    };

    let elapsed = Duration::from_secs(elapsed_secs);

    // Compute approximate start time
    let now = chrono::Utc::now().timestamp();
    let start_time_unix = now - elapsed_secs as i64;

    Ok((start_time_unix, elapsed))
}

fn parse_timing_fields_at(
    platform: &str,
    fields: &[&str],
    now_unix: i64,
) -> Result<(i64, Duration), String> {
    let lstart_idx = 11;
    let etimes_idx = lstart_idx + 5;
    let etimes_str = fields
        .get(etimes_idx)
        .ok_or_else(|| format!("Missing etimes field for platform {platform}"))?;

    let elapsed_secs: u64 = if etimes_str.contains(':') {
        parse_etime_format(etimes_str).unwrap_or(0)
    } else {
        etimes_str.parse().unwrap_or(0)
    };

    let elapsed = Duration::from_secs(elapsed_secs);
    let start_time_unix = now_unix - elapsed_secs as i64;
    Ok((start_time_unix, elapsed))
}

fn compute_start_id_synthetic(
    platform: &str,
    boot_id: &Option<String>,
    start_time_unix: i64,
    pid: u32,
) -> StartId {
    let boot = boot_id.as_deref().unwrap_or("synthetic");
    let ticks = start_time_unix.max(0) as u64;
    match platform {
        "linux" => StartId::from_linux(boot, ticks, pid),
        "macos" => StartId::from_macos(boot, ticks, pid),
        _ => StartId(format!("{boot}:{ticks}:{pid}")),
    }
}

/// Parse etime format: [[dd-]hh:]mm:ss
fn parse_etime_format(s: &str) -> Option<u64> {
    let mut total_secs = 0u64;

    // Check for days
    let (days_part, time_part) = if s.contains('-') {
        let mut parts = s.splitn(2, '-');
        let days: u64 = parts.next()?.parse().ok()?;
        (days, parts.next()?)
    } else {
        (0, s)
    };

    total_secs += days_part * 86400;

    // Parse time components
    let time_parts: Vec<&str> = time_part.split(':').collect();
    match time_parts.len() {
        3 => {
            // hh:mm:ss
            let hours: u64 = time_parts[0].parse().ok()?;
            let mins: u64 = time_parts[1].parse().ok()?;
            let secs: u64 = time_parts[2].parse().ok()?;
            total_secs += hours * 3600 + mins * 60 + secs;
        }
        2 => {
            // mm:ss
            let mins: u64 = time_parts[0].parse().ok()?;
            let secs: u64 = time_parts[1].parse().ok()?;
            total_secs += mins * 60 + secs;
        }
        1 => {
            // ss
            let secs: u64 = time_parts[0].parse().ok()?;
            total_secs += secs;
        }
        _ => return None,
    }

    Some(total_secs)
}

/// Compute start_id from available information.
fn compute_start_id(
    platform: &str,
    boot_id: &Option<String>,
    start_time_unix: i64,
    elapsed: Duration,
    pid: u32,
) -> StartId {
    match platform {
        "linux" => {
            let boot = boot_id.as_deref().unwrap_or("unknown");
            let start_ticks = linux_start_ticks_from_uptime(elapsed)
                .or_else(|| linux_start_ticks_from_btime(start_time_unix));
            let ticks = start_ticks.unwrap_or_else(|| start_time_unix.max(0) as u64);
            StartId::from_linux(boot, ticks, pid)
        }
        "macos" => {
            // macOS: use start_time:pid (no boot_id available easily)
            let boot = boot_id.as_deref().unwrap_or("unknown");
            StartId::from_macos(boot, start_time_unix as u64, pid)
        }
        _ => {
            // Fallback: use start_time:pid
            StartId(format!("unknown:{}:{}", start_time_unix, pid))
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_start_ticks_from_uptime(elapsed: Duration) -> Option<u64> {
    let uptime = read_uptime_seconds()?;
    let hz = clock_ticks_per_second()?;
    let elapsed_secs = elapsed.as_secs_f64();
    if uptime < elapsed_secs {
        return None;
    }
    let start_secs = uptime - elapsed_secs;
    let ticks = (start_secs * hz as f64).floor();
    if ticks.is_sign_negative() {
        return None;
    }
    Some(ticks as u64)
}

#[cfg(not(target_os = "linux"))]
fn linux_start_ticks_from_uptime(_elapsed: Duration) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn linux_start_ticks_from_btime(start_time_unix: i64) -> Option<u64> {
    let boot_time = read_boot_time_unix()?;
    let hz = clock_ticks_per_second()?;
    let delta = start_time_unix - boot_time;
    if delta < 0 {
        return None;
    }
    Some((delta as u64) * hz)
}

#[cfg(not(target_os = "linux"))]
fn linux_start_ticks_from_btime(_start_time_unix: i64) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_uptime_seconds() -> Option<f64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = content.split_whitespace().next()?;
    first.parse::<f64>().ok()
}

#[cfg(target_os = "linux")]
fn read_boot_time_unix() -> Option<i64> {
    let content = std::fs::read_to_string("/proc/stat").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime") {
            let value = rest.trim();
            if let Ok(parsed) = value.parse::<i64>() {
                return Some(parsed);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn clock_ticks_per_second() -> Option<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value <= 0 {
        None
    } else {
        Some(value as u64)
    }
}

/// Detect kernel threads by PPID.
///
/// On Linux, kernel threads are either:
/// - PPID 0: Direct children of the scheduler (swapper). Only kthreadd (PID 2) has PPID 0.
/// - PPID 2: Children of kthreadd (kernel thread daemon). This includes ALL other kernel threads.
///
/// CRITICAL: Do NOT use bracket pattern (e.g., [kthreadd]) because
/// zombie processes ALSO show bracketed names like [cat] <defunct>.
/// PPID is the ONLY reliable indicator.
///
/// Note: PID 0 (swapper) never appears in ps output.
/// Note: PID 1 (init/systemd) has PPID 0 but is NOT a kernel thread.
fn is_kernel_thread(record: &ProcessRecord) -> bool {
    let ppid = record.ppid.0;

    // Special case: PID 1 (init/systemd) has PPID 0 but is NOT a kernel thread
    if record.pid.0 == 1 {
        return false;
    }

    if ppid == 0 {
        return true;
    }

    #[cfg(target_os = "linux")]
    {
        if ppid == 2 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_etime_seconds() {
        assert_eq!(parse_etime_format("30"), Some(30));
        assert_eq!(parse_etime_format("00:30"), Some(30));
        assert_eq!(parse_etime_format("01:30"), Some(90));
    }

    #[test]
    fn test_parse_etime_minutes() {
        assert_eq!(parse_etime_format("10:30"), Some(630));
        assert_eq!(parse_etime_format("00:10:30"), Some(630));
    }

    #[test]
    fn test_parse_etime_hours() {
        assert_eq!(parse_etime_format("01:00:00"), Some(3600));
        assert_eq!(parse_etime_format("02:30:45"), Some(9045));
    }

    #[test]
    fn test_parse_etime_days() {
        assert_eq!(parse_etime_format("1-00:00:00"), Some(86400));
        assert_eq!(
            parse_etime_format("2-12:30:15"),
            Some(2 * 86400 + 12 * 3600 + 30 * 60 + 15)
        );
    }

    #[test]
    fn test_header_detection() {
        assert!(is_header_line("PID PPID UID USER"));
        assert!(is_header_line("pid ppid uid user"));
        assert!(!is_header_line("123 1 0 root"));
        assert!(!is_header_line("999 42 1000 alice"));
    }

    #[test]
    fn test_process_state_from_char() {
        assert_eq!(ProcessState::from_char('R'), ProcessState::Running);
        assert_eq!(ProcessState::from_char('S'), ProcessState::Sleeping);
        assert_eq!(ProcessState::from_char('Z'), ProcessState::Zombie);
    }

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        assert!(!platform.is_empty());
    }

    // Integration test - only run when ps is available
    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_quick_scan_integration() {
        let options = QuickScanOptions::default();
        let result = quick_scan(&options);
        assert!(result.is_ok());

        let scan = result.unwrap();
        assert!(!scan.processes.is_empty());
        assert_eq!(scan.metadata.scan_type, "quick");
        assert!(scan.metadata.process_count > 0);
    }

    #[test]
    fn test_parse_ps_line_linux() {
        // Sample Linux ps output line
        let line = "1234 1 1000 testuser 1234 1234 S 0.5 10240 20480 pts/0 Tue Jan 14 10:30:00 2026 3600 bash /bin/bash -c echo hello";
        let boot_id = Some("test-boot-id".to_string());

        let result = parse_ps_line(line, "linux", &boot_id);
        assert!(result.is_ok(), "Parse failed: {:?}", result);

        let record = result.unwrap();
        assert_eq!(record.pid.0, 1234);
        assert_eq!(record.ppid.0, 1);
        assert_eq!(record.uid, 1000);
        assert_eq!(record.user, "testuser");
        assert_eq!(record.state, ProcessState::Sleeping);
        assert_eq!(record.comm, "bash");
        assert!(record.cmd.contains("/bin/bash"));
        assert_eq!(record.elapsed.as_secs(), 3600);
    }

    // =====================================================
    // No-mock tests using real processes
    // =====================================================

    #[test]
    fn test_nomock_quick_scan_all_processes() {
        // This test doesn't need ProcessHarness - just verifies quick_scan works
        let platform = detect_platform();
        if platform != "linux" && platform != "macos" {
            crate::test_log!(
                INFO,
                "Skipping no-mock test: unsupported platform",
                platform = platform.as_str()
            );
            return;
        }

        crate::test_log!(
            INFO,
            "quick_scan no-mock test starting",
            platform = platform.as_str()
        );

        let options = QuickScanOptions::default();
        let result = quick_scan(&options);

        crate::test_log!(INFO, "quick_scan result", is_ok = result.is_ok());

        assert!(result.is_ok(), "quick_scan failed: {:?}", result.err());
        let scan = result.unwrap();

        // Should have at least a few processes
        assert!(
            scan.processes.len() > 0,
            "quick_scan should return at least one process"
        );

        // Our own process should be in the list
        let my_pid = std::process::id();
        let has_self = scan.processes.iter().any(|p| p.pid.0 == my_pid);

        crate::test_log!(
            INFO,
            "quick_scan completed",
            process_count = scan.processes.len(),
            includes_self = has_self,
            scan_type = scan.metadata.scan_type.as_str()
        );

        assert!(has_self, "quick_scan should include our own process");
        assert_eq!(scan.metadata.scan_type, "quick");
    }

    #[test]
    fn test_nomock_quick_scan_specific_pid() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(INFO, "quick_scan specific PID test", pid = proc.pid());

        // Run a full scan and filter results manually
        // (ps -p doesn't work reliably with -e on all systems)
        let options = QuickScanOptions::default();

        let result = quick_scan(&options);
        crate::test_log!(
            INFO,
            "quick_scan result",
            pid = proc.pid(),
            is_ok = result.is_ok()
        );

        assert!(result.is_ok(), "quick_scan failed: {:?}", result.err());
        let scan = result.unwrap();

        // Find our specific process in the results
        let target_record = scan.processes.iter().find(|p| p.pid.0 == proc.pid());
        assert!(target_record.is_some(), "Should find our spawned process");
        let record = target_record.unwrap();

        assert_eq!(record.pid.0, proc.pid());
        assert!(record.ppid.0 > 0);
        assert!(!record.comm.is_empty());

        crate::test_log!(
            INFO,
            "quick_scan specific PID completed",
            pid = proc.pid(),
            comm = record.comm.as_str(),
            state = format!("{:?}", record.state).as_str(),
            cpu_percent = record.cpu_percent
        );
    }

    #[test]
    fn test_nomock_quick_scan_metadata() {
        let platform = detect_platform();
        if platform != "linux" && platform != "macos" {
            crate::test_log!(INFO, "Skipping no-mock test: unsupported platform");
            return;
        }

        crate::test_log!(INFO, "quick_scan metadata test starting");

        let options = QuickScanOptions::default();
        let result = quick_scan(&options).expect("quick_scan should succeed");

        // Verify metadata fields
        assert_eq!(result.metadata.scan_type, "quick");
        assert!(!result.metadata.platform.is_empty());
        assert!(result.metadata.process_count > 0);
        assert!(result.metadata.duration_ms < 30000); // Should complete within 30s

        // On Linux, boot_id should be present
        if platform == "linux" {
            assert!(
                result.metadata.boot_id.is_some(),
                "Linux should have boot_id"
            );
        }

        crate::test_log!(
            INFO,
            "quick_scan metadata test completed",
            platform = result.metadata.platform.as_str(),
            process_count = result.metadata.process_count,
            duration_ms = result.metadata.duration_ms,
            has_boot_id = result.metadata.boot_id.is_some()
        );
    }

    #[test]
    fn test_nomock_quick_scan_process_fields() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        // Give the process a moment to settle
        std::thread::sleep(std::time::Duration::from_millis(100));

        crate::test_log!(INFO, "quick_scan process fields test", pid = proc.pid());

        // Run a full scan and filter results manually
        // (ps -p doesn't work reliably with -e on all systems)
        let options = QuickScanOptions::default();

        let scan = quick_scan(&options).expect("quick_scan should succeed");

        // Find our specific process in the results
        let record = scan
            .processes
            .iter()
            .find(|p| p.pid.0 == proc.pid())
            .expect("Should find our spawned process");

        // Verify all fields are populated correctly
        assert_eq!(record.pid.0, proc.pid());
        assert!(record.ppid.0 > 0);
        assert!(record.uid < u32::MAX); // Should be a valid UID
        assert!(!record.user.is_empty());
        assert!(record.pgid.is_some());
        assert!(record.sid.is_some());
        assert!(!record.start_id.0.is_empty());
        assert!(record.rss_bytes > 0 || record.vsz_bytes > 0); // At least one memory stat
        assert_eq!(record.source, "quick_scan");

        crate::test_log!(
            INFO,
            "quick_scan process fields completed",
            pid = proc.pid(),
            uid = record.uid,
            user = record.user.as_str(),
            rss_bytes = record.rss_bytes,
            vsz_bytes = record.vsz_bytes
        );
    }

    // =====================================================
    // Kernel thread detection tests
    // =====================================================

    fn make_record(pid: u32, ppid: u32, comm: &str, state: ProcessState) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(ppid),
            uid: 0,
            user: "root".to_string(),
            pgid: Some(0),
            sid: Some(0),
            start_id: StartId("test:0:0".to_string()),
            comm: comm.to_string(),
            cmd: comm.to_string(),
            state,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: Duration::from_secs(0),
            source: "test".to_string(),
            container_info: None,
        }
    }

    #[test]
    fn test_is_kernel_thread_kthreadd() {
        let kthreadd = make_record(2, 0, "[kthreadd]", ProcessState::Sleeping);
        assert!(
            is_kernel_thread(&kthreadd),
            "kthreadd should be detected as kernel thread"
        );
    }

    #[test]
    fn test_is_kernel_thread_kworker() {
        let kworker = make_record(42, 2, "[kworker/0:0-eve]", ProcessState::Idle);
        assert!(
            is_kernel_thread(&kworker),
            "kworker should be detected as kernel thread"
        );
    }

    #[test]
    fn test_is_kernel_thread_init_excluded() {
        // init (PID 1) has PPID 0 but is NOT a kernel thread
        let init = make_record(1, 0, "init", ProcessState::Sleeping);
        assert!(
            !is_kernel_thread(&init),
            "init should NOT be detected as kernel thread"
        );
    }

    #[test]
    fn test_zombie_not_kernel_thread() {
        // Zombie with bracketed name but user-process parent
        let zombie = make_record(9999, 1234, "[cat]", ProcessState::Zombie);
        assert!(
            !is_kernel_thread(&zombie),
            "Zombie should NOT be detected as kernel thread"
        );
    }

    #[test]
    fn test_orphan_not_kernel_thread() {
        // Orphaned process (PPID 1) is NOT a kernel thread
        let orphan = make_record(5000, 1, "defunct_daemon", ProcessState::Sleeping);
        assert!(
            !is_kernel_thread(&orphan),
            "Orphan should NOT be detected as kernel thread"
        );
    }

    #[test]
    fn test_normal_process_not_kernel_thread() {
        let normal = make_record(5000, 1500, "bash", ProcessState::Running);
        assert!(
            !is_kernel_thread(&normal),
            "Normal process should NOT be kernel thread"
        );
    }

    #[test]
    fn test_nomock_quick_scan_excludes_kernel_threads_by_default() {
        let platform = detect_platform();
        if platform != "linux" {
            crate::test_log!(INFO, "Skipping kernel thread test: Linux only");
            return;
        }

        let options = QuickScanOptions::default(); // include_kernel_threads: false
        let result = quick_scan(&options);
        assert!(result.is_ok(), "quick_scan failed: {:?}", result.err());
        let scan = result.unwrap();

        for proc in &scan.processes {
            // PID 1 is allowed even with PPID 0
            if proc.pid.0 == 1 {
                continue;
            }
            assert!(
                proc.ppid.0 != 0 && proc.ppid.0 != 2,
                "Found kernel thread PID {} (PPID {}) with default options",
                proc.pid.0,
                proc.ppid.0
            );
        }

        crate::test_log!(
            INFO,
            "quick_scan excludes kernel threads by default",
            process_count = scan.processes.len()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_nomock_quick_scan_includes_kernel_threads_when_requested() {
        let options = QuickScanOptions {
            include_kernel_threads: true,
            ..Default::default()
        };
        let result = quick_scan(&options);
        assert!(result.is_ok(), "quick_scan failed: {:?}", result.err());
        let scan = result.unwrap();

        let has_kthreads = scan.processes.iter().any(|p| p.ppid.0 == 2);
        assert!(
            has_kthreads,
            "Expected kernel threads when include_kernel_threads=true"
        );

        crate::test_log!(
            INFO,
            "quick_scan includes kernel threads when requested",
            process_count = scan.processes.len(),
            has_kernel_threads = has_kthreads
        );
    }
}
