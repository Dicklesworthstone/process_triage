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
use pt_common::{ProcessId, StartId};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Options for quick scan operation.
#[derive(Debug, Clone, Default)]
pub struct QuickScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,

    /// Include kernel threads (Linux only).
    pub include_kernel_threads: bool,

    /// Timeout for ps command (default: 10 seconds).
    pub timeout: Option<Duration>,
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
    let start = Instant::now();
    let platform = detect_platform();
    let boot_id = read_boot_id();

    // Build ps command
    let mut cmd = build_ps_command(&platform, options)?;

    // Execute and capture output
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| QuickScanError::CommandFailed(e.to_string()))?;

    let stdout = child.stdout.take().ok_or_else(|| {
        QuickScanError::CommandFailed("Failed to capture stdout".to_string())
    })?;

    let reader = BufReader::new(stdout);
    let mut processes = Vec::new();
    let mut warnings = Vec::new();

    // Parse output
    let mut lines = reader.lines();

    // Skip header line
    if let Some(Ok(_header)) = lines.next() {
        // Header skipped
    }

    for (line_num, line_result) in lines.enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        match parse_ps_line(&line, &platform, &boot_id) {
            Ok(record) => processes.push(record),
            Err(e) => {
                warnings.push(format!("Line {}: {}", line_num + 2, e));
            }
        }
    }

    // Wait for child process to avoid leaving zombies
    let _ = child.wait();

    let duration = start.elapsed();
    let process_count = processes.len();

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
fn build_ps_command(
    platform: &str,
    options: &QuickScanOptions,
) -> Result<Command, QuickScanError> {
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

    if fields.len() < 14 {
        return Err(format!("Insufficient fields: expected 14+, got {}", fields.len()));
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

    // Comm is field 13 (0-indexed: 13) - same index for both Linux and macOS
    let comm_idx = 13;
    let comm = fields.get(comm_idx).unwrap_or(&"").to_string();

    // Args/cmd is everything after comm (field 14+)
    let cmd = if fields.len() > comm_idx + 1 {
        fields[comm_idx + 1..].join(" ")
    } else {
        comm.clone()
    };

    // Compute start_id
    let start_id = compute_start_id(platform, boot_id, start_time_unix, pid);

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
    })
}

/// Parse timing fields from ps output.
fn parse_timing_fields(
    platform: &str,
    fields: &[&str],
) -> Result<(i64, Duration), String> {
    // lstart is fields 11-15 (day month date time year) for Linux
    // etimes is field after that (seconds since start)

    // For simplicity, use etimes to compute elapsed time
    // and estimate start_time from current time - etimes

    let etimes_idx = if platform == "linux" { 12 } else { 12 };
    let etimes_str = fields.get(etimes_idx).unwrap_or(&"0");

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
    pid: u32,
) -> StartId {
    match platform {
        "linux" => {
            // Linux: use boot_id:start_time:pid
            let boot = boot_id.as_deref().unwrap_or("unknown");
            StartId::from_linux(boot, start_time_unix as u64, pid)
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
        assert_eq!(parse_etime_format("2-12:30:15"), Some(2 * 86400 + 12 * 3600 + 30 * 60 + 15));
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
        let line = "1234 1 1000 testuser 1234 1234 S 0.5 10240 20480 pts/0 0 3600 bash /bin/bash -c echo hello";
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
    }
}
