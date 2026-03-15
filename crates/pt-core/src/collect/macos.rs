//! macOS-specific evidence collection.
//!
//! This module provides detailed process inspection for macOS systems,
//! using macOS-specific tools and APIs since /proc is not available.
//!
//! # Tools Used
//! - `ps` - BSD-style process listing (handled in quick_scan)
//! - `lsof` - Open files and network connections
//! - `netstat` - Network statistics
//! - `sysctl` - System/process information
//! - `csrutil` - SIP (System Integrity Protection) status
//! - `launchctl` - launchd service detection
//!
//! # SIP Considerations
//! Some tools require full disk access or SIP disabled:
//! - dtruss/dtrace may not work with SIP enabled
//! - Some lsof fields may be restricted
//! - Tool capabilities are auto-detected at startup
//!
//! # Platform Support
//! This module only compiles on macOS (target_os = "macos").

use super::tool_runner::run_tool;
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::{IdentityQuality, ProcessId, StartId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;

/// Minimal per-process snapshot from `ps` for action-time checks on macOS.
#[derive(Debug, Clone)]
pub struct MacOsPsSnapshot {
    pub uid: u32,
    pub ppid: u32,
    pub state: char,
    pub tty: Option<String>,
    pub elapsed: Duration,
    pub start_time_unix: u64,
    pub comm: String,
}

// ============================================================================
// SIP Detection
// ============================================================================

/// System Integrity Protection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SipStatus {
    /// SIP is enabled (default macOS configuration).
    Enabled,
    /// SIP is disabled (requires boot to Recovery Mode).
    Disabled,
    /// SIP status is partially enabled (custom configuration).
    CustomConfiguration,
    /// Unable to determine SIP status.
    Unknown,
}

impl Default for SipStatus {
    fn default() -> Self {
        SipStatus::Unknown
    }
}

/// Detect SIP status by running `csrutil status`.
///
/// # Returns
/// - `SipStatus::Enabled` if SIP is fully enabled
/// - `SipStatus::Disabled` if SIP is disabled
/// - `SipStatus::CustomConfiguration` if SIP is partially enabled
/// - `SipStatus::Unknown` if detection fails
pub fn detect_sip_status() -> SipStatus {
    match crate::collect::tool_runner::run_tool(
        "csrutil",
        &["status"],
        Some(std::time::Duration::from_secs(2)),
        None,
    ) {
        Ok(output) => {
            let stdout = output.stdout_str();
            parse_csrutil_output(&stdout)
        }
        Err(e) => {
            debug!("Failed to run csrutil: {}", e);
            SipStatus::Unknown
        }
    }
}

fn parse_csrutil_output(output: &str) -> SipStatus {
    let lower = output.to_lowercase();

    if lower.contains("enabled") && !lower.contains("disabled") {
        if lower.contains("custom configuration") {
            SipStatus::CustomConfiguration
        } else {
            SipStatus::Enabled
        }
    } else if lower.contains("disabled") {
        SipStatus::Disabled
    } else {
        SipStatus::Unknown
    }
}

// ============================================================================
// Capability Detection
// ============================================================================

/// Collection capabilities available on this macOS system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacOsCapabilities {
    /// SIP status.
    pub sip_status: SipStatus,

    /// Whether lsof is available and working.
    pub lsof_available: bool,

    /// Whether netstat is available.
    pub netstat_available: bool,

    /// Whether launchctl can list services.
    pub launchctl_available: bool,

    /// Whether we have elevated privileges (root or TCC entitlements).
    pub elevated_privileges: bool,

    /// macOS version string.
    pub macos_version: Option<String>,
}

impl MacOsCapabilities {
    /// Detect available capabilities on this system.
    pub fn detect() -> Self {
        let sip_status = detect_sip_status();
        let lsof_available = crate::collect::tool_runner::run_tool(
            "lsof",
            &["-v"],
            Some(std::time::Duration::from_secs(2)),
            None,
        )
        .map(|o| o.success() || !o.stderr.is_empty())
        .unwrap_or(false);

        let netstat_available = crate::collect::tool_runner::run_tool(
            "netstat",
            &["-h"],
            Some(std::time::Duration::from_secs(2)),
            None,
        )
        .map(|_| true)
        .unwrap_or(false);

        let launchctl_available = crate::collect::tool_runner::run_tool(
            "launchctl",
            &["list"],
            Some(std::time::Duration::from_secs(2)),
            None,
        )
        .map(|o| o.success())
        .unwrap_or(false);

        let elevated_privileges = unsafe { libc::geteuid() } == 0;

        let macos_version = crate::collect::tool_runner::run_tool(
            "sw_vers",
            &["-productVersion"],
            Some(std::time::Duration::from_secs(2)),
            None,
        )
        .ok()
        .map(|o| o.stdout_str().trim().to_string());

        Self {
            sip_status,
            lsof_available,
            netstat_available,
            launchctl_available,
            elevated_privileges,
            macos_version,
        }
    }

    /// Check if detailed collection is possible.
    pub fn can_collect_detailed(&self) -> bool {
        self.lsof_available
    }
}

// ============================================================================
// Data Types
// ============================================================================

/// Options for macOS deep scan operation.
#[derive(Clone, Default)]
pub struct MacOsScanOptions {
    /// Only scan specific PIDs (empty = all processes).
    pub pids: Vec<u32>,

    /// Skip processes we can't fully inspect.
    pub skip_inaccessible: bool,

    /// Include environment variables (may be sensitive).
    pub include_environ: bool,

    /// Timeout for individual tool commands.
    pub tool_timeout: Option<Duration>,

    /// Optional progress event emitter.
    pub progress: Option<Arc<dyn ProgressEmitter>>,
}

impl std::fmt::Debug for MacOsScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsScanOptions")
            .field("pids", &self.pids)
            .field("skip_inaccessible", &self.skip_inaccessible)
            .field("include_environ", &self.include_environ)
            .field("tool_timeout", &self.tool_timeout)
            .field("progress", &self.progress.as_ref().map(|_| "..."))
            .finish()
    }
}

/// Errors during macOS scan.
#[derive(Debug, Error)]
pub enum MacOsScanError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error for PID {pid}: {message}")]
    ParseError { pid: u32, message: String },

    #[error("Permission denied for PID {0}")]
    PermissionDenied(u32),

    #[error("Tool execution failed: {tool}: {message}")]
    ToolFailed { tool: String, message: String },

    #[error("Tool not available: {0}")]
    ToolNotAvailable(String),
}

/// Open file information from lsof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFile {
    /// File descriptor number (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,

    /// File type (REG, DIR, CHR, PIPE, UNIX, IPv4, IPv6, etc.).
    pub file_type: String,

    /// File path or socket address.
    pub name: String,

    /// File mode (r, w, u for read/write/read-write).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// Network connection from lsof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsNetworkConnection {
    /// Protocol (TCP, UDP).
    pub protocol: String,

    /// Local address and port.
    pub local_address: String,

    /// Remote address and port (for connected sockets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,

    /// Connection state (LISTEN, ESTABLISHED, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// launchd service information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchdService {
    /// Service label (e.g., "com.apple.Finder").
    pub label: String,

    /// PID of the service (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Last exit status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit_status: Option<i32>,
}

/// Extended process record from macOS deep scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsScanRecord {
    // === Core identity ===
    /// Process ID.
    pub pid: ProcessId,

    /// Parent process ID.
    pub ppid: ProcessId,

    /// User ID.
    pub uid: u32,

    /// Username.
    pub user: String,

    /// Process group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,

    // === Identity for TOCTOU protection ===
    /// Start ID for process reuse detection.
    pub start_id: StartId,

    // === Command info ===
    /// Command name.
    pub comm: String,

    /// Full command line.
    pub cmdline: String,

    /// Executable path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,

    // === State ===
    /// Process state (R, S, Z, etc.).
    pub state: char,

    // === Resource usage ===
    /// CPU usage percentage.
    pub cpu_percent: f64,

    /// Resident set size in bytes.
    pub rss_bytes: u64,

    /// Virtual memory size in bytes.
    pub vsz_bytes: u64,

    // === macOS-specific details ===
    /// Open files from lsof.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_files: Vec<OpenFile>,

    /// Network connections.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_connections: Vec<MacOsNetworkConnection>,

    /// launchd service info (if managed by launchd).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launchd_service: Option<LaunchdService>,

    /// Environment variables (if requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environ: Option<HashMap<String, String>>,

    // === Timing ===
    /// Process start time (Unix timestamp).
    pub start_time_unix: i64,

    /// Elapsed time since start.
    pub elapsed: Duration,

    // === Provenance ===
    /// Data source.
    pub source: String,

    /// Identity quality indicator.
    pub identity_quality: IdentityQuality,
}

/// Result of macOS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsScanResult {
    /// Collected process records.
    pub processes: Vec<MacOsScanRecord>,

    /// Scan metadata.
    pub metadata: MacOsScanMetadata,
}

/// Metadata about macOS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsScanMetadata {
    /// When scan started (ISO-8601).
    pub started_at: String,

    /// Duration in milliseconds.
    pub duration_ms: u64,

    /// Number of processes collected.
    pub process_count: usize,

    /// Number of processes skipped.
    pub skipped_count: usize,

    /// Detected capabilities.
    pub capabilities: MacOsCapabilities,

    /// Warnings encountered.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

// ============================================================================
// lsof Parsing
// ============================================================================

/// Parse lsof output for a specific PID.
///
/// Uses `-p <pid> -F` format for machine-parseable output.
fn parse_lsof_output(output: &str) -> (Vec<OpenFile>, Vec<MacOsNetworkConnection>) {
    let mut files = Vec::new();
    let mut connections = Vec::new();

    let mut current_fd: Option<i32> = None;
    let mut current_type: Option<String> = None;
    let mut current_name: Option<String> = None;
    let mut current_mode: Option<String> = None;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let (key, value) = (line.chars().next(), &line[1..]);

        match key {
            Some('f') => {
                // Flush previous entry
                flush_lsof_entry(
                    &mut files,
                    &mut connections,
                    current_fd,
                    current_type.take(),
                    current_name.take(),
                    current_mode.take(),
                );

                // Parse FD
                current_fd = value.parse().ok();
            }
            Some('t') => {
                current_type = Some(value.to_string());
            }
            Some('n') => {
                current_name = Some(value.to_string());
            }
            Some('a') => {
                current_mode = Some(value.to_string());
            }
            _ => {}
        }
    }

    // Flush final entry
    flush_lsof_entry(
        &mut files,
        &mut connections,
        current_fd,
        current_type,
        current_name,
        current_mode,
    );

    (files, connections)
}

fn flush_lsof_entry(
    files: &mut Vec<OpenFile>,
    connections: &mut Vec<MacOsNetworkConnection>,
    fd: Option<i32>,
    file_type: Option<String>,
    name: Option<String>,
    mode: Option<String>,
) {
    let Some(file_type) = file_type else { return };
    let name = name.unwrap_or_default();

    // Check if this is a network connection
    if file_type == "IPv4" || file_type == "IPv6" {
        // Parse network connection from name
        // Format: "localhost:8080->remote:443 (ESTABLISHED)"
        let (addresses, state) = if let Some(paren_pos) = name.rfind('(') {
            let state = name[paren_pos + 1..].trim_end_matches(')').to_string();
            (name[..paren_pos].trim(), Some(state))
        } else {
            (name.as_str(), None)
        };

        let (local, remote) = if let Some(arrow_pos) = addresses.find("->") {
            (
                addresses[..arrow_pos].to_string(),
                Some(addresses[arrow_pos + 2..].to_string()),
            )
        } else {
            (addresses.to_string(), None)
        };

        connections.push(MacOsNetworkConnection {
            protocol: if file_type == "IPv6" {
                "TCP6".to_string()
            } else {
                "TCP".to_string()
            },
            local_address: local,
            remote_address: remote,
            state,
        });
    } else {
        files.push(OpenFile {
            fd,
            file_type,
            name,
            mode,
        });
    }
}

/// Collect open files and network connections for a PID using lsof.
pub fn collect_lsof_info(
    pid: u32,
    timeout: Duration,
) -> Result<(Vec<OpenFile>, Vec<MacOsNetworkConnection>), MacOsScanError> {
    let output = match run_tool(
        "lsof",
        &["-p", &pid.to_string(), "-F", "ftna"],
        Some(timeout),
        None,
    ) {
        Ok(out) => out,
        Err(e) => {
            return Err(MacOsScanError::ToolFailed {
                tool: "lsof".to_string(),
                message: e.to_string(),
            });
        }
    };

    if !output.success() {
        // lsof returns non-zero for various reasons (process exited, permission denied)
        let stderr = output.stderr_str();
        if stderr.contains("Permission denied") {
            return Err(MacOsScanError::PermissionDenied(pid));
        }
        // Process may have exited - return empty
        return Ok((Vec::new(), Vec::new()));
    }

    Ok(parse_lsof_output(&output.stdout_str()))
}

// ============================================================================
// launchd Detection
// ============================================================================

/// Check if a PID is managed by launchd and get service info.
pub fn detect_launchd_service(pid: u32) -> Option<LaunchdService> {
    // Run `launchctl list` and find the service with matching PID
    let output = crate::collect::tool_runner::run_tool(
        "launchctl",
        &["list"],
        Some(std::time::Duration::from_secs(5)),
        None,
    )
    .ok()?;

    if !output.success() {
        return None;
    }

    let stdout = output.stdout_str();

    for line in stdout.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            // Format: PID Status Label
            if let Ok(service_pid) = parts[0].parse::<u32>() {
                if service_pid == pid {
                    let status = parts[1].parse().ok();
                    let label = parts[2..].join(" ");
                    return Some(LaunchdService {
                        label,
                        pid: Some(pid),
                        last_exit_status: status,
                    });
                }
            }
        }
    }

    None
}

// ============================================================================
// Environment Variables
// ============================================================================

/// Collect environment variables for a PID.
///
/// Uses `ps -p <pid> -E` on macOS.
pub fn collect_environ(pid: u32) -> Option<HashMap<String, String>> {
    let output = crate::collect::tool_runner::run_tool(
        "ps",
        &["-p", &pid.to_string(), "-E", "-o", "command="],
        Some(std::time::Duration::from_secs(5)),
        None,
    )
    .ok()?;

    if !output.success() {
        return None;
    }

    let stdout = output.stdout_str();

    // Parse environment variables from command line
    // macOS ps -E appends environment to command
    let mut environ = HashMap::new();
    let mut current_key = None;
    let mut current_value = String::new();

    for part in stdout.split_whitespace() {
        if let Some(eq_pos) = part.find('=') {
            let key_candidate = &part[..eq_pos];
            // Filter to likely environment variables
            if !key_candidate.is_empty()
                && key_candidate
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_')
            {
                if let Some(k) = current_key.take() {
                    environ.insert(k, current_value.trim().to_string());
                }
                current_key = Some(key_candidate.to_string());
                current_value = part[eq_pos + 1..].to_string();
                continue;
            }
        }

        if current_key.is_some() {
            current_value.push(' ');
            current_value.push_str(part);
        }
    }

    if let Some(k) = current_key {
        environ.insert(k, current_value.trim().to_string());
    }

    if environ.is_empty() {
        None
    } else {
        Some(environ)
    }
}

/// Read a minimal process snapshot using `ps`.
///
/// This avoids relying on unstable/private Darwin libc process structs while
/// still giving the action layer enough metadata for safety checks.
pub fn read_process_snapshot(pid: u32) -> Option<MacOsPsSnapshot> {
    let output = crate::collect::tool_runner::run_tool(
        "ps",
        &[
            "-p",
            &pid.to_string(),
            "-o",
            "uid=,ppid=,state=,tty=,etime=,comm=",
        ],
        Some(std::time::Duration::from_secs(5)),
        None,
    )
    .ok()?;

    if !output.success() {
        return None;
    }

    let stdout = output.stdout_str();
    let line = stdout.lines().find(|line| !line.trim().is_empty())?;
    parse_process_snapshot_line(line, chrono::Utc::now().timestamp())
}

fn parse_process_snapshot_line(line: &str, now_unix: i64) -> Option<MacOsPsSnapshot> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }

    let uid: u32 = fields[0].parse().ok()?;
    let ppid: u32 = fields[1].parse().ok()?;
    let state = fields[2].chars().next().unwrap_or('?');
    let tty = match fields[3] {
        "?" | "??" | "-" => None,
        tty => Some(tty.to_string()),
    };
    let elapsed_secs = parse_etime_macos(fields[4])?;
    let elapsed = Duration::from_secs(elapsed_secs);
    let start_time_unix = now_unix.saturating_sub(elapsed_secs as i64).max(0) as u64;
    let comm = fields[5..].join(" ");

    Some(MacOsPsSnapshot {
        uid,
        ppid,
        state,
        tty,
        elapsed,
        start_time_unix,
        comm,
    })
}

// ============================================================================
// Main Scan Function
// ============================================================================

/// Perform a macOS-specific deep scan.
///
/// Collects detailed process information using macOS tools (lsof, launchctl, etc.)
/// since /proc filesystem is not available.
pub fn macos_scan(options: &MacOsScanOptions) -> Result<MacOsScanResult, MacOsScanError> {
    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Detect capabilities
    let capabilities = MacOsCapabilities::detect();
    debug!(
        sip = ?capabilities.sip_status,
        lsof = capabilities.lsof_available,
        launchctl = capabilities.launchctl_available,
        "macOS scan capabilities detected"
    );

    let tool_timeout = options.tool_timeout.unwrap_or(Duration::from_secs(5));

    // Get list of PIDs from ps output
    let pids = if options.pids.is_empty() {
        list_all_pids_macos()?
    } else {
        options.pids.clone()
    };
    let total_pids = pids.len() as u64;

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_STARTED, Phase::DeepScan)
                .with_progress(0, Some(total_pids))
                .with_detail("capabilities", &format!("{:?}", capabilities.sip_status)),
        );
    }

    // Get base process info from ps first
    let base_info = collect_base_process_info(&pids)?;

    let mut processes = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped_count = 0usize;
    let scanned = AtomicUsize::new(0);
    const PROGRESS_STEP: usize = 50;

    for pid in &pids {
        let Some(base) = base_info.get(pid) else {
            // Process may have exited
            skipped_count += 1;
            continue;
        };

        // Collect detailed info
        let (open_files, network_connections) = if capabilities.lsof_available {
            match collect_lsof_info(*pid, tool_timeout) {
                Ok(info) => info,
                Err(MacOsScanError::PermissionDenied(_)) => {
                    if options.skip_inaccessible {
                        skipped_count += 1;
                        continue;
                    }
                    (Vec::new(), Vec::new())
                }
                Err(e) => {
                    warnings.push(format!("lsof failed for PID {}: {}", pid, e));
                    (Vec::new(), Vec::new())
                }
            }
        } else {
            (Vec::new(), Vec::new())
        };

        // Check launchd
        let launchd_service = if capabilities.launchctl_available {
            detect_launchd_service(*pid)
        } else {
            None
        };

        // Collect environment if requested
        let environ = if options.include_environ {
            collect_environ(*pid)
        } else {
            None
        };

        let record = MacOsScanRecord {
            pid: ProcessId(*pid),
            ppid: base.ppid,
            uid: base.uid,
            user: base.user.clone(),
            pgid: base.pgid,
            sid: base.sid,
            start_id: base.start_id.clone(),
            comm: base.comm.clone(),
            cmdline: base.cmdline.clone(),
            exe: base.exe.clone(),
            state: base.state,
            cpu_percent: base.cpu_percent,
            rss_bytes: base.rss_bytes,
            vsz_bytes: base.vsz_bytes,
            open_files,
            network_connections,
            launchd_service,
            environ,
            start_time_unix: base.start_time_unix,
            elapsed: base.elapsed,
            source: "macos_scan".to_string(),
            identity_quality: IdentityQuality::NoBootId, // macOS lacks /proc/boot_id TOCTOU protection
        };

        processes.push(record);

        let current = scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if current % PROGRESS_STEP == 0 {
            if let Some(emitter) = options.progress.as_ref() {
                emitter.emit(
                    ProgressEvent::new(event_names::DEEP_SCAN_PROGRESS, Phase::DeepScan)
                        .with_progress(current as u64, Some(total_pids)),
                );
            }
        }
    }

    let duration = start.elapsed();

    let process_count = processes.len();

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_COMPLETE, Phase::DeepScan)
                .with_progress(process_count as u64, Some(total_pids))
                .with_elapsed_ms(duration.as_millis() as u64),
        );
    }

    Ok(MacOsScanResult {
        processes,
        metadata: MacOsScanMetadata {
            started_at,
            duration_ms: duration.as_millis() as u64,
            process_count,
            skipped_count,
            capabilities,
            warnings,
        },
    })
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

/// Base process info collected from ps.
#[derive(Debug, Clone)]
struct BaseProcessInfo {
    ppid: ProcessId,
    uid: u32,
    user: String,
    pgid: Option<u32>,
    sid: Option<u32>,
    start_id: StartId,
    comm: String,
    cmdline: String,
    exe: Option<String>,
    state: char,
    cpu_percent: f64,
    rss_bytes: u64,
    vsz_bytes: u64,
    start_time_unix: i64,
    elapsed: Duration,
}

/// List all PIDs on macOS using ps.
fn list_all_pids_macos() -> Result<Vec<u32>, MacOsScanError> {
    let output = crate::collect::tool_runner::run_tool(
        "ps",
        &["-eo", "pid"],
        Some(std::time::Duration::from_secs(10)),
        None,
    )
    .map_err(|e| MacOsScanError::ToolFailed {
        tool: "ps".to_string(),
        message: e.to_string(),
    })?;

    if !output.success() {
        return Err(MacOsScanError::ToolFailed {
            tool: "ps".to_string(),
            message: "Failed to list processes".to_string(),
        });
    }

    let stdout = output.stdout_str();
    let mut pids = Vec::new();

    for line in stdout.lines().skip(1) {
        // Skip header
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }

    Ok(pids)
}

/// Collect base process info for a list of PIDs using a single ps command.
fn collect_base_process_info(
    pids: &[u32],
) -> Result<HashMap<u32, BaseProcessInfo>, MacOsScanError> {
    // Use ps with BSD format to get all needed fields
    let mut args = vec![
        "-eo".to_string(),
        "pid,ppid,uid,user,pgid,sess,state,%cpu,rss,vsz,lstart,etime,comm,args".to_string(),
    ];

    if !pids.is_empty() {
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        args.push("-p".to_string());
        args.push(pid_list);
    }

    let output = crate::collect::tool_runner::run_tool(
        "ps",
        &args.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
        Some(std::time::Duration::from_secs(10)),
        None,
    )
    .map_err(|e| MacOsScanError::ToolFailed {
        tool: "ps".to_string(),
        message: e.to_string(),
    })?;

    if !output.success() {
        return Err(MacOsScanError::ToolFailed {
            tool: "ps".to_string(),
            message: "Failed to get process info".to_string(),
        });
    }

    let stdout = output.stdout_str();
    let mut info = HashMap::new();

    for line in stdout.lines().skip(1) {
        // Skip header
        if let Some(parsed) = parse_ps_line_macos(line) {
            info.insert(parsed.0, parsed.1);
        }
    }

    Ok(info)
}

/// Parse a single ps output line for macOS.
fn parse_ps_line_macos(line: &str) -> Option<(u32, BaseProcessInfo)> {
    let fields: Vec<&str> = line.split_whitespace().collect();

    // Need at least: pid ppid uid user pgid sess state %cpu rss vsz + lstart(5 fields) + etime + comm
    // Total minimum: 17 fields
    if fields.len() < 17 {
        return None;
    }

    let pid: u32 = fields[0].parse().ok()?;
    let ppid: u32 = fields[1].parse().ok()?;
    let uid: u32 = fields[2].parse().ok()?;
    let user = fields[3].to_string();
    let pgid: u32 = fields[4].parse().ok()?;
    let sid: u32 = fields[5].parse().ok()?;
    let state = fields[6].chars().next().unwrap_or('?');
    let cpu_percent: f64 = fields[7].parse().unwrap_or(0.0);
    let rss_kb: u64 = fields[8].parse().unwrap_or(0);
    let vsz_kb: u64 = fields[9].parse().unwrap_or(0);

    // lstart is fields 10-14 (day mon date time year)
    // etime is field 15
    // comm is field 16
    // args is 17+

    let etime_idx = 15;
    let comm_idx = 16;

    let elapsed_secs = parse_etime_macos(fields.get(etime_idx)?).unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    let start_time_unix = now - elapsed_secs as i64;

    let comm = fields.get(comm_idx)?.to_string();
    let cmdline = if fields.len() > comm_idx + 1 {
        fields[comm_idx + 1..].join(" ")
    } else {
        comm.clone()
    };

    // Create start_id for macOS (less precise than Linux)
    let start_id = StartId::from_macos("unknown", start_time_unix as u64, pid);

    Some((
        pid,
        BaseProcessInfo {
            ppid: ProcessId(ppid),
            uid,
            user,
            pgid: Some(pgid),
            sid: Some(sid),
            start_id,
            comm,
            cmdline,
            exe: None, // Would need additional lookup
            state,
            cpu_percent,
            rss_bytes: rss_kb * 1024,
            vsz_bytes: vsz_kb * 1024,
            start_time_unix,
            elapsed: Duration::from_secs(elapsed_secs),
        },
    ))
}

/// Parse macOS etime format.
fn parse_etime_macos(s: &str) -> Option<u64> {
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
            let hours: u64 = time_parts[0].parse().ok()?;
            let mins: u64 = time_parts[1].parse().ok()?;
            let secs: u64 = time_parts[2].parse().ok()?;
            total_secs += hours * 3600 + mins * 60 + secs;
        }
        2 => {
            let mins: u64 = time_parts[0].parse().ok()?;
            let secs: u64 = time_parts[1].parse().ok()?;
            total_secs += mins * 60 + secs;
        }
        1 => {
            let secs: u64 = time_parts[0].parse().ok()?;
            total_secs += secs;
        }
        _ => return None,
    }

    Some(total_secs)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csrutil_output_enabled() {
        let output = "System Integrity Protection status: enabled.";
        assert_eq!(parse_csrutil_output(output), SipStatus::Enabled);
    }

    #[test]
    fn test_parse_csrutil_output_disabled() {
        let output = "System Integrity Protection status: disabled.";
        assert_eq!(parse_csrutil_output(output), SipStatus::Disabled);
    }

    #[test]
    fn test_parse_csrutil_output_custom() {
        let output = "System Integrity Protection status: enabled (Custom Configuration).";
        assert_eq!(parse_csrutil_output(output), SipStatus::CustomConfiguration);
    }

    #[test]
    fn test_parse_csrutil_output_unknown() {
        let output = "Something unexpected";
        assert_eq!(parse_csrutil_output(output), SipStatus::Unknown);
    }

    #[test]
    fn test_parse_etime_seconds() {
        assert_eq!(parse_etime_macos("30"), Some(30));
    }

    #[test]
    fn test_parse_etime_minutes_seconds() {
        assert_eq!(parse_etime_macos("10:30"), Some(630));
    }

    #[test]
    fn test_parse_etime_hours_minutes_seconds() {
        assert_eq!(parse_etime_macos("2:30:45"), Some(9045));
    }

    #[test]
    fn test_parse_etime_days() {
        assert_eq!(parse_etime_macos("1-00:00:00"), Some(86400));
        assert_eq!(
            parse_etime_macos("2-12:30:15"),
            Some(2 * 86400 + 12 * 3600 + 30 * 60 + 15)
        );
    }

    #[test]
    fn test_parse_process_snapshot_line() {
        let line = "501 1 Ss ttys001 01:02 bash";
        let snapshot = parse_process_snapshot_line(line, 1_700_000_000).expect("snapshot");

        assert_eq!(snapshot.uid, 501);
        assert_eq!(snapshot.ppid, 1);
        assert_eq!(snapshot.state, 'S');
        assert_eq!(snapshot.tty.as_deref(), Some("ttys001"));
        assert_eq!(snapshot.elapsed, Duration::from_secs(62));
        assert_eq!(snapshot.start_time_unix, 1_699_999_938);
        assert_eq!(snapshot.comm, "bash");
    }

    #[test]
    fn test_parse_process_snapshot_line_without_tty() {
        let line = "0 1 I ?? 30 launchd";
        let snapshot = parse_process_snapshot_line(line, 1_700_000_000).expect("snapshot");

        assert_eq!(snapshot.uid, 0);
        assert_eq!(snapshot.ppid, 1);
        assert_eq!(snapshot.state, 'I');
        assert_eq!(snapshot.tty, None);
        assert_eq!(snapshot.elapsed, Duration::from_secs(30));
        assert_eq!(snapshot.start_time_unix, 1_699_999_970);
        assert_eq!(snapshot.comm, "launchd");
    }

    #[test]
    fn test_parse_lsof_output_files() {
        let output = "f3\ntREG\nnpath/to/file.txt\nar\n";
        let (files, connections) = parse_lsof_output(output);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].fd, Some(3));
        assert_eq!(files[0].file_type, "REG");
        assert_eq!(files[0].name, "path/to/file.txt");
        assert_eq!(files[0].mode, Some("r".to_string()));
        assert!(connections.is_empty());
    }

    #[test]
    fn test_parse_lsof_output_network() {
        let output = "f5\ntIPv4\nnlocalhost:8080->remote:443 (ESTABLISHED)\n";
        let (files, connections) = parse_lsof_output(output);

        assert!(files.is_empty());
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].local_address, "localhost:8080");
        assert_eq!(
            connections[0].remote_address,
            Some("remote:443".to_string())
        );
        assert_eq!(connections[0].state, Some("ESTABLISHED".to_string()));
    }

    // Mock-based tests for full scan would go here
    // These tests can run on any platform since they use mocked data

    #[test]
    fn test_macos_capabilities_default() {
        let caps = MacOsCapabilities::default();
        assert_eq!(caps.sip_status, SipStatus::Unknown);
        assert!(!caps.lsof_available);
    }
}
