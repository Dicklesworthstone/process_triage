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
//! Native collection compiles on macOS. Pure parsers and the worker protocol
//! also compile in Linux unit tests so bounded/partial behavior is exercised.

use super::tool_runner::{run_tool, ToolConfig, ToolError, ToolOutput, ToolRunner, ToolSpec};
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::{IdentityQuality, ProcessId, StartId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
use std::path::Path;
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SipStatus {
    /// SIP is enabled (default macOS configuration).
    Enabled,
    /// SIP is disabled (requires boot to Recovery Mode).
    Disabled,
    /// SIP status is partially enabled (custom configuration).
    CustomConfiguration,
    /// Unable to determine SIP status.
    #[default]
    Unknown,
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
            lsof_path(),
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

    /// Skip processes whose native identity cannot be verified; otherwise fail.
    /// Optional probe failures remain explicit unavailable evidence in records.
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

    #[error("macOS deep scan worker failed: {0}")]
    Worker(String),
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_files: Vec<OpenFile>,

    /// Network connections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_connections: Vec<MacOsNetworkConnection>,

    /// True only after a complete, successful lsof response for this identity.
    /// Empty file/socket lists with false here mean unknown, not no open files.
    #[serde(default)]
    pub lsof_complete: bool,

    /// launchctl list observes only the collector's bootstrap domain. A missing
    /// service is never proof that another user or domain does not supervise it.
    #[serde(default)]
    pub launchd_domain_observed: bool,

    /// Failed optional probes. The base process remains visible, but callers
    /// must not interpret the missing evidence as inactivity or no supervision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,

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

    /// Coverage of the inventory and worker stream, separate from optional
    /// probe availability on each process (for example SIP-restricted lsof).
    #[serde(default)]
    pub collection: MacOsScanCollection,

    /// Warnings encountered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Completed process outcomes, even when a deadline cancels later probes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacOsScanCollection {
    pub complete: bool,
    pub timed_out: bool,
    pub output_truncated: bool,
    pub budget_ms: Option<u64>,
    /// Unknown until the native process inventory has been received.
    pub requested_count: Option<usize>,
    pub processed_count: usize,
    pub incomplete_count: Option<usize>,
    pub failed_count: usize,
}

const MACOS_REQUEST_LIMIT: usize = 1024 * 1024;
const MACOS_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const MACOS_MESSAGE_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacOsScanRequest {
    pids: Vec<u32>,
    skip_inaccessible: bool,
    include_environ: bool,
    tool_timeout_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum MacOsScanEvent {
    Inventory { pids: Vec<u32> },
    Capabilities { capabilities: MacOsCapabilities },
    Record { record: Box<MacOsScanRecord> },
    Skipped { pid: u32, warning: String },
    Complete { metadata: Box<MacOsScanMetadata> },
}

/// Private worker protocol: the parent owns its deadline and only accepts
/// complete JSONL records. No logging or session setup runs in this subprocess.
#[cfg(target_os = "macos")]
pub fn run_macos_scan_worker() -> Result<(), MacOsScanError> {
    let mut request = Vec::new();
    std::io::stdin()
        .lock()
        .take((MACOS_REQUEST_LIMIT + 1) as u64)
        .read_to_end(&mut request)?;
    if request.len() > MACOS_REQUEST_LIMIT {
        return Err(MacOsScanError::Worker("request exceeds 1 MiB".into()));
    }
    let request: MacOsScanRequest = serde_json::from_slice(&request)
        .map_err(|error| MacOsScanError::Worker(format!("invalid request: {error}")))?;
    let options = MacOsScanOptions {
        pids: request.pids,
        skip_inaccessible: request.skip_inaccessible,
        include_environ: request.include_environ,
        tool_timeout: request.tool_timeout_ms.map(Duration::from_millis),
        progress: None,
    };
    let mut writer = std::io::BufWriter::new(std::io::stdout().lock());
    let mut observer = |event| {
        serde_json::to_writer(&mut writer, &event)
            .map_err(|error| MacOsScanError::Worker(format!("cannot stream result: {error}")))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    };
    macos_scan_observed(&options, Some(&mut observer))?;
    Ok(())
}

/// Bound the whole native scan, including startup, capability probes, lsof,
/// launchctl and output parsing. Completed records survive cancellation only as
/// explicitly incomplete evidence. Callback delivery follows cancellation so
/// a slow caller-owned progress sink cannot prolong a running collector.
pub fn macos_scan_with_budget(
    options: &MacOsScanOptions,
    budget: Duration,
    worker_executable: &Path,
) -> Result<MacOsScanResult, MacOsScanError> {
    let started = Instant::now();
    let budget_ms = u64::try_from(budget.as_millis())
        .map_err(|_| MacOsScanError::Worker("collection budget exceeds u64 milliseconds".into()))?;
    let mut stream = MacOsScanStream::new(options, budget_ms);
    if budget_ms == 0 {
        stream.result.metadata.collection.timed_out = true;
        return Ok(stream.finish(started, false));
    }
    let request = serde_json::to_vec(&MacOsScanRequest {
        pids: options.pids.clone(),
        skip_inaccessible: options.skip_inaccessible,
        include_environ: options.include_environ,
        tool_timeout_ms: options
            .tool_timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
    })
    .map_err(|error| MacOsScanError::Worker(format!("cannot encode request: {error}")))?;
    if request.len() > MACOS_REQUEST_LIMIT {
        return Err(MacOsScanError::Worker("request exceeds 1 MiB".into()));
    }
    let remaining = budget.saturating_sub(started.elapsed());
    if remaining.as_millis() == 0 {
        stream.result.metadata.collection.timed_out = true;
        return Ok(stream.finish(started, false));
    }
    let executable = worker_executable
        .to_str()
        .ok_or_else(|| MacOsScanError::Worker("worker path is not UTF-8".into()))?;
    let runner = ToolRunner::new(ToolConfig {
        default_timeout: remaining,
        budget_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
        max_output_bytes: MACOS_OUTPUT_LIMIT,
        use_nice: false,
        #[cfg(target_os = "linux")]
        use_ionice: false,
        ..ToolConfig::default()
    });
    let spec = ToolSpec::new(executable, vec!["__deep-scan-worker".into()])
        .with_stdin(request)
        .with_timeout(remaining)
        .with_process_group();
    let output = runner.run_with_stdout_handler(&spec, Some(&mut |bytes| stream.consume(bytes)));
    let successful = match output {
        Ok(output) => {
            stream.result.metadata.collection.timed_out = output.timed_out;
            stream.result.metadata.collection.output_truncated |= output.truncated;
            if !output.success() {
                stream.result.metadata.warnings.push(format!(
                    "macOS deep scan worker incomplete: status {:?}, timed_out={}, truncated={}; {}",
                    output.exit_code, output.timed_out, output.truncated,
                    output.stderr_str().chars().take(4096).collect::<String>(),
                ));
            }
            output.success()
        }
        Err(error) => {
            stream.result.metadata.collection.timed_out = matches!(
                error,
                ToolError::Timeout(_) | ToolError::BudgetExhausted { .. }
            );
            stream
                .result
                .metadata
                .warnings
                .push(format!("macOS deep scan worker: {error}"));
            false
        }
    };
    // ToolRunner's deadline begins after request/configuration setup. Keep the
    // caller's original deadline authoritative even for a late successful exit.
    if started.elapsed() >= budget {
        stream.result.metadata.collection.timed_out = true;
    }
    Ok(stream.finish(started, successful))
}

struct MacOsScanStream<'a> {
    result: MacOsScanResult,
    pending: Vec<u8>,
    expected_pids: Option<HashSet<u32>>,
    outcomes: HashSet<u32>,
    inventory_received: bool,
    capabilities_received: bool,
    complete_received: bool,
    options: &'a MacOsScanOptions,
}

impl<'a> MacOsScanStream<'a> {
    fn new(options: &'a MacOsScanOptions, budget_ms: u64) -> Self {
        let expected_pids = (!options.pids.is_empty())
            .then(|| options.pids.iter().copied().collect::<HashSet<_>>());
        let requested_count = expected_pids.as_ref().map(HashSet::len);
        Self {
            result: MacOsScanResult {
                processes: Vec::new(),
                metadata: MacOsScanMetadata {
                    started_at: chrono::Utc::now().to_rfc3339(),
                    duration_ms: 0,
                    process_count: 0,
                    skipped_count: 0,
                    capabilities: MacOsCapabilities::default(),
                    warnings: Vec::new(),
                    collection: MacOsScanCollection {
                        budget_ms: Some(budget_ms),
                        requested_count,
                        incomplete_count: requested_count,
                        ..MacOsScanCollection::default()
                    },
                },
            },
            pending: Vec::new(),
            expected_pids,
            outcomes: HashSet::new(),
            inventory_received: false,
            capabilities_received: false,
            complete_received: false,
            options,
        }
    }

    fn consume(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            if self.pending.len().saturating_add(part.len()) > MACOS_MESSAGE_LIMIT {
                self.result.metadata.collection.output_truncated = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "macOS deep scan message exceeds 4 MiB",
                ));
            }
            self.pending.extend_from_slice(part);
            if part.last() == Some(&b'\n') {
                let event = serde_json::from_slice(&self.pending)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                self.pending.clear();
                self.accept(event)?;
            }
        }
        Ok(())
    }

    fn accept(&mut self, event: MacOsScanEvent) -> std::io::Result<()> {
        let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
        if self.complete_received {
            return Err(invalid("macOS deep scan event follows completion"));
        }
        match event {
            MacOsScanEvent::Inventory { pids } => {
                let count = pids.len();
                let pids: HashSet<_> = pids.into_iter().collect();
                if self.inventory_received
                    || pids.len() != count
                    || pids.iter().any(|pid| *pid == 0 || *pid > i32::MAX as u32)
                    || self
                        .expected_pids
                        .as_ref()
                        .is_some_and(|expected| expected != &pids)
                {
                    return Err(invalid("inconsistent macOS deep scan inventory"));
                }
                self.inventory_received = true;
                self.expected_pids = Some(pids);
                self.result.metadata.collection.requested_count = Some(count);
            }
            MacOsScanEvent::Capabilities { capabilities } => {
                if !self.inventory_received
                    || self.capabilities_received
                    || !self.outcomes.is_empty()
                {
                    return Err(invalid("unexpected macOS capability snapshot"));
                }
                self.capabilities_received = true;
                self.result.metadata.capabilities = capabilities;
            }
            MacOsScanEvent::Record { record } => {
                let pid = record.pid.0;
                if !self.capabilities_received
                    || !self
                        .expected_pids
                        .as_ref()
                        .is_some_and(|pids| pids.contains(&pid))
                    || !record.cpu_percent.is_finite()
                    || record.cpu_percent < 0.0
                    || record.identity_quality == IdentityQuality::PidOnly
                    || record.start_id.0.is_empty()
                    || !self.outcomes.insert(pid)
                {
                    return Err(invalid(
                        "duplicate, unannounced or invalid macOS process record",
                    ));
                }
                self.result.processes.push(*record);
            }
            MacOsScanEvent::Skipped { pid, warning } => {
                if !self.capabilities_received
                    || !self
                        .expected_pids
                        .as_ref()
                        .is_some_and(|pids| pids.contains(&pid))
                    || !self.outcomes.insert(pid)
                {
                    return Err(invalid("duplicate or unannounced macOS process skip"));
                }
                self.result.metadata.skipped_count += 1;
                self.result.metadata.collection.failed_count += 1;
                self.result.metadata.warnings.push(warning);
            }
            MacOsScanEvent::Complete { metadata } => {
                let collection = &metadata.collection;
                if !self.capabilities_received
                    || self.result.metadata.collection.requested_count != Some(self.outcomes.len())
                    || metadata.process_count != self.result.processes.len()
                    || metadata.skipped_count != self.result.metadata.skipped_count
                    || collection.failed_count != self.result.metadata.collection.failed_count
                    || !collection.complete
                    || collection.timed_out
                    || collection.output_truncated
                    || collection.requested_count != Some(self.outcomes.len())
                    || collection.processed_count != self.outcomes.len()
                    || collection.incomplete_count != Some(0)
                {
                    return Err(invalid(
                        "macOS completion disagrees with observed process coverage",
                    ));
                }
                self.result.metadata.warnings = metadata.warnings;
                self.complete_received = true;
            }
        }
        Ok(())
    }

    fn finish(mut self, started: Instant, successful: bool) -> MacOsScanResult {
        let collection = &mut self.result.metadata.collection;
        collection.complete = successful
            && self.complete_received
            && self.pending.is_empty()
            && !collection.timed_out
            && !collection.output_truncated;
        collection.processed_count = self.outcomes.len();
        collection.incomplete_count = collection
            .requested_count
            .map(|count| count.saturating_sub(self.outcomes.len()));
        self.result.metadata.process_count = self.result.processes.len();
        self.result.metadata.duration_ms =
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        if !collection.complete {
            self.result.metadata.warnings.push(format!(
                "Incomplete macOS deep scan: {} outcomes from inventory {:?}; missing evidence remains unknown",
                collection.processed_count, collection.requested_count
            ));
        }
        if let Some(emitter) = self.options.progress.as_ref() {
            emitter.emit(
                ProgressEvent::new(event_names::DEEP_SCAN_COMPLETE, Phase::DeepScan)
                    .with_progress(
                        collection.processed_count as u64,
                        collection.requested_count.map(|count| count as u64),
                    )
                    .with_elapsed_ms(self.result.metadata.duration_ms)
                    .with_detail("complete", collection.complete)
                    .with_detail("timed_out", collection.timed_out),
            );
        }
        self.result
    }
}

// ============================================================================
// lsof Parsing
// ============================================================================

/// Parse NUL-delimited lsof fields, retaining newlines inside filenames. Every
/// response must name the requested PID and every file must provide its type.
fn parse_lsof_output(
    output: &str,
    expected_pid: u32,
) -> Result<(Vec<OpenFile>, Vec<MacOsNetworkConnection>), String> {
    let mut files = Vec::new();
    let mut connections = Vec::new();
    let mut process_seen = false;
    let mut entry: Option<LsofEntry> = None;
    if !output.contains('\0') || !output.trim_end_matches('\n').ends_with('\0') {
        return Err("lsof response is not a complete NUL-delimited field stream".into());
    }
    for field in output.split('\0') {
        // lsof separates process/file sets with a newline after the NUL.
        let field = field.trim_start_matches('\n');
        if field.is_empty() {
            continue;
        }
        if !field.as_bytes()[0].is_ascii() {
            return Err("invalid lsof field identifier".into());
        }
        let (key, value) = field.split_at(1);
        match key {
            "p" => {
                if process_seen || value.parse::<u32>() != Ok(expected_pid) {
                    return Err("lsof response names an unexpected or repeated process".into());
                }
                process_seen = true;
            }
            "f" => {
                if !process_seen || value.is_empty() {
                    return Err("lsof file appears without its process or descriptor".into());
                }
                if let Some(previous) = entry.take() {
                    flush_lsof_entry(&mut files, &mut connections, previous)?;
                }
                entry = Some(LsofEntry {
                    fd: value.parse().ok(),
                    ..LsofEntry::default()
                });
            }
            "t" | "n" | "a" | "P" | "T" => {
                let current = entry.as_mut().ok_or("lsof field appears before a file")?;
                let destination = match key {
                    "t" => &mut current.file_type,
                    "n" => &mut current.name,
                    "a" => &mut current.mode,
                    "P" => &mut current.protocol,
                    "T" if value.starts_with("ST=") => &mut current.state,
                    _ => continue,
                };
                let value = if key == "T" { &value[3..] } else { value };
                if destination.replace(value.to_string()).is_some() {
                    return Err(format!("duplicate lsof {key} field"));
                }
            }
            _ => return Err(format!("unexpected lsof field {key}")),
        }
    }
    if !process_seen {
        return Err("lsof response has no process identity".into());
    }
    if let Some(previous) = entry {
        flush_lsof_entry(&mut files, &mut connections, previous)?;
    }
    Ok((files, connections))
}

#[derive(Default)]
struct LsofEntry {
    fd: Option<i32>,
    file_type: Option<String>,
    name: Option<String>,
    mode: Option<String>,
    protocol: Option<String>,
    state: Option<String>,
}

fn flush_lsof_entry(
    files: &mut Vec<OpenFile>,
    connections: &mut Vec<MacOsNetworkConnection>,
    entry: LsofEntry,
) -> Result<(), String> {
    let file_type = entry.file_type.ok_or("lsof file type is unavailable")?;
    let name = entry.name.ok_or("lsof file name is unavailable")?;
    if file_type.is_empty()
        || file_type.eq_ignore_ascii_case("unknown")
        || file_type.starts_with("UNKN")
        || file_type == "UNSP"
        || file_type.contains('?')
        || name.is_empty()
    {
        return Err("lsof file metadata is unavailable".into());
    }
    if file_type == "IPv4" || file_type == "IPv6" {
        let (local, remote) = name
            .split_once("->")
            .map_or((name.as_str(), None), |(local, remote)| {
                (local, Some(remote))
            });
        let protocol = entry
            .protocol
            .ok_or("lsof socket protocol is unavailable")?;
        connections.push(MacOsNetworkConnection {
            protocol: if file_type == "IPv6" {
                format!("{protocol}6")
            } else {
                protocol
            },
            local_address: local.to_string(),
            remote_address: remote.map(str::to_string),
            state: entry.state,
        });
    } else {
        files.push(OpenFile {
            fd: entry.fd,
            file_type,
            name,
            mode: entry.mode,
        });
    }
    Ok(())
}

/// `lsof` lives in /usr/sbin on macOS, which is often missing from PATH (launchd
/// agents, cron, minimal shells); without it the data-loss gate could not inspect
/// open files.
pub fn lsof_path() -> &'static str {
    if std::path::Path::new("/usr/sbin/lsof").exists() {
        "/usr/sbin/lsof"
    } else {
        "lsof"
    }
}

/// Collect open files and network connections for a PID using lsof.
pub fn collect_lsof_info(
    pid: u32,
    timeout: Duration,
) -> Result<(Vec<OpenFile>, Vec<MacOsNetworkConnection>), MacOsScanError> {
    let output = match run_tool(
        lsof_path(),
        &["-nP", "-p", &pid.to_string(), "-F0pftnaPT"],
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

    parse_lsof_tool_output(&output, pid)
}

fn parse_lsof_tool_output(
    output: &ToolOutput,
    pid: u32,
) -> Result<(Vec<OpenFile>, Vec<MacOsNetworkConnection>), MacOsScanError> {
    // lsof can exit zero after returning only some requested information. Its
    // warnings (for example an unreadable filesystem) make coverage unknown.
    if !output.success() || !output.stderr.is_empty() {
        // lsof returns non-zero for various reasons (process exited, permission denied)
        let stderr = output.stderr_str();
        if stderr.contains("Permission denied") {
            return Err(MacOsScanError::PermissionDenied(pid));
        }
        return Err(MacOsScanError::ToolFailed {
            tool: "lsof".into(),
            message: format!(
                "incomplete response: status {:?}, timed_out={}, truncated={}; {}",
                output.exit_code,
                output.timed_out,
                output.truncated,
                stderr.chars().take(4096).collect::<String>(),
            ),
        });
    }
    let stdout =
        std::str::from_utf8(&output.stdout).map_err(|error| MacOsScanError::ParseError {
            pid,
            message: format!("lsof output is not UTF-8: {error}"),
        })?;
    parse_lsof_output(stdout, pid).map_err(|message| MacOsScanError::ParseError { pid, message })
}

// ============================================================================
// launchd Detection
// ============================================================================

/// Check if a PID is managed by launchd and get service info.
pub fn detect_launchd_service(pid: u32) -> Option<LaunchdService> {
    collect_launchd_services(Duration::from_secs(5))
        .ok()?
        .remove(&pid)
}

fn collect_launchd_services(timeout: Duration) -> Result<HashMap<u32, LaunchdService>, String> {
    let output = crate::collect::tool_runner::run_tool("launchctl", &["list"], Some(timeout), None)
        .map_err(|error| error.to_string())?;
    if !output.success() || !output.stderr.is_empty() {
        return Err(format!(
            "incomplete domain listing: status {:?}, timed_out={}, truncated={}; {}",
            output.exit_code,
            output.timed_out,
            output.truncated,
            output.stderr_str().chars().take(4096).collect::<String>(),
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|error| error.to_string())?;
    parse_launchd_services(stdout)
}

fn parse_launchd_services(output: &str) -> Result<HashMap<u32, LaunchdService>, String> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["PID", "Status", "Label"])
    {
        return Err("invalid launchctl list header".into());
    }
    let mut services = HashMap::new();
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err("malformed launchctl service row".into());
        }
        let status = parts[1]
            .parse::<i32>()
            .map_err(|_| "invalid launchctl service status")?;
        if parts[0] == "-" {
            continue;
        }
        let pid = parts[0]
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or("invalid launchctl service PID")?;
        let service = LaunchdService {
            label: parts[2].to_string(),
            pid: Some(pid),
            last_exit_status: Some(status),
        };
        if services.insert(pid, service).is_some() {
            return Err("ambiguous launchctl service ownership".into());
        }
    }
    Ok(services)
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

/// Capture this boundary before spawning ps. XNU initializes ps_start with
/// microtime_with_abstime at fork and exports it as ri_proc_start_abstime
/// through proc_pid_rusage. Both observations use the Mach absolute clock,
/// independently of calendar-clock adjustments between ps and libproc reads.
#[derive(Clone, Copy)]
pub(crate) struct MacosScanBirthFence(u64);

impl MacosScanBirthFence {
    #[cfg(target_os = "macos")]
    pub(crate) fn capture(_pids: &[u32]) -> Self {
        // libSystem exports this clock in <mach/mach_time.h>. Its native
        // ticks can be compared directly with ri_proc_start_abstime.
        unsafe extern "C" {
            fn mach_absolute_time() -> u64;
        }
        // SAFETY: mach_absolute_time reads a clock and takes no arguments.
        Self(unsafe { mach_absolute_time() })
    }

    fn accepts_reading(&self, calendar_birth_us: u64, absolute_birth: Option<u64>) -> bool {
        calendar_birth_us != 0 && absolute_birth.is_some_and(|ticks| ticks > 0 && ticks < self.0)
    }

    /// Call after reading BSD identity and session data. A replacement that
    /// supplied any of these fields also has a new absolute birth, so it cannot
    /// be attached to an earlier ps row. Missing accounting leaves identity unknown.
    #[cfg(target_os = "macos")]
    pub(crate) fn accepts(&self, pid: u32, calendar_birth_us: u64) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v0>::zeroed();
        // SAFETY: libproc's V0 flavor writes one rusage_info_v0 into this buffer.
        // The C API types the output parameter as rusage_info_t *, an opaque pointer.
        let status = unsafe {
            libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V0, usage.as_mut_ptr().cast())
        };
        let absolute_birth = (status == 0).then(|| {
            // SAFETY: the buffer was zeroed and the syscall reported success.
            unsafe { usage.assume_init() }.ri_proc_start_abstime
        });
        self.accepts_reading(calendar_birth_us, absolute_birth)
    }
}

/// XNU exports kern.bootsessionuuid as a read-only, NUL-terminated uuid_string_t.
#[cfg(target_os = "macos")]
pub(crate) fn boot_session_id() -> Option<String> {
    let mut bytes = [0xffu8; 37];
    let mut len = bytes.len();
    // SAFETY: sysctlbyname writes at most len bytes into the array. No new value is supplied.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    parse_boot_session_id(bytes.get(..len)?)
}

fn parse_boot_session_id(bytes: &[u8]) -> Option<String> {
    let text = std::ffi::CStr::from_bytes_with_nul(bytes)
        .ok()?
        .to_str()
        .ok()?;
    let id = uuid::Uuid::parse_str(text).ok()?;
    (text.len() == 36 && !id.is_nil()).then(|| id.hyphenated().to_string())
}

/// A full identity must match the independently observed boot. Older scans
/// recorded the literal "unknown" together with the same native birth and PID.
pub(crate) fn target_birth(
    target: &pt_common::ProcessIdentity,
    current_boot: Option<&str>,
) -> Option<u64> {
    let (boot, birth) = parse_native_start(&target.start_id, target.pid.0)?;
    match target.quality {
        IdentityQuality::Full if current_boot == Some(boot) => Some(birth),
        IdentityQuality::NoBootId if boot == "unknown" => Some(birth),
        _ => None,
    }
}

fn parse_native_start(id: &StartId, pid: u32) -> Option<(&str, u64)> {
    let (boot, suffix) = id.0.split_once(':')?;
    let (birth, recorded_pid) = suffix.split_once(':')?;
    let birth = birth.parse::<u64>().ok()?;
    (pid > 0
        && birth > 0
        && recorded_pid.parse::<u32>() == Ok(pid)
        && *id == StartId::from_macos(boot, birth, pid))
        .then_some((boot, birth))
}

/// Compare a saved pre-UUID selector with one newly observed native Darwin birth.
pub(super) fn legacy_birth_matches(
    saved: &StartId,
    observed: &StartId,
    pid: u32,
    current_boot: Option<&str>,
) -> bool {
    let (Some(("unknown", birth)), Some((boot, live_birth))) =
        (parse_native_start(saved, pid), parse_native_start(observed, pid))
    else {
        return false;
    };
    current_boot == Some(boot) && birth == live_birth
}

/// Exact identity facts for a live process from `proc_pidinfo(PROC_PIDTBSDINFO)`
/// (public `<libproc.h>` API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacBsdInfo {
    /// Process start time, microseconds since the Unix epoch (exact, unlike `ps etime`).
    pub start_us: u64,
    pub uid: u32,
    pub ppid: u32,
}

/// Raw `proc_bsdinfo` for `pid`; `None` if it is gone or not readable.
#[cfg(target_os = "macos")]
fn raw_bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: proc_bsdinfo is plain old data; proc_pidinfo writes at most `size` bytes.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            // XNU uses a nonzero argument for this flavor to include unreaped zombies.
            1,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (n == size && info.pbi_pid == pid as u32).then_some(info)
}

/// Effective credential group, distinct from the real and saved GIDs.
#[cfg(target_os = "macos")]
pub(super) fn effective_gid(target: &pt_common::ProcessIdentity) -> Option<u32> {
    let pid = target.pid.0;
    let info = raw_bsd_info(pid)?;
    let expected_birth = target_birth(target, boot_session_id().as_deref())?;
    if info.pbi_uid != target.uid || info.pbi_start_tvusec >= 1_000_000 {
        return None;
    }
    let birth = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)?;
    (birth == expected_birth).then_some(info.pbi_gid)
}

/// Session facts for `pid` in the shape of a Linux `/proc/<pid>/stat` record.
/// `starttime` carries the native process birth in microseconds since the Unix
/// epoch, rather than Linux clock ticks, so session safety can compare process
/// identity across repeated macOS observations. Uncollected CPU and memory
/// fields remain zero. `tty_nr` is 0 when there is no controlling terminal, as
/// on Linux.
#[cfg(target_os = "macos")]
pub fn read_session_stat(pid: u32) -> Option<crate::collect::proc_parsers::ProcessStat> {
    let info = raw_bsd_info(pid)?;
    // SAFETY: getsid only reads kernel state for the pid.
    let session = unsafe { libc::getsid(pid as libc::pid_t) };
    // SAFETY: pbi_comm is a NUL-terminated C string within the struct (zeroed first).
    let comm = unsafe { std::ffi::CStr::from_ptr(info.pbi_comm.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    // NODEV (all bits set) means no controlling terminal.
    let tty_nr = if info.e_tdev == u32::MAX {
        0
    } else {
        info.e_tdev as i32
    };
    let state = match info.pbi_status {
        1 => 'I', // SIDL
        2 => 'R', // SRUN
        3 => 'S', // SSLEEP
        4 => 'T', // SSTOP
        5 => 'Z', // SZOMB
        _ => '?',
    };
    Some(crate::collect::proc_parsers::ProcessStat {
        pid,
        comm,
        state,
        ppid: info.pbi_ppid,
        pgrp: info.pbi_pgid as i32,
        session,
        tty_nr,
        tpgid: info.e_tpgid as i32,
        utime: 0,
        stime: 0,
        starttime: info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
        vsize: 0,
        rss: 0,
        nice: info.pbi_nice,
        num_threads: 0,
    })
}

/// Read [`MacBsdInfo`] for `pid`; `None` if it is gone or not readable.
#[cfg(target_os = "macos")]
pub fn read_bsd_info(pid: u32) -> Option<MacBsdInfo> {
    let info = raw_bsd_info(pid)?;
    if info.pbi_start_tvusec >= 1_000_000 {
        return None;
    }
    let start_us = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
        .filter(|value| *value > 0)?;
    Some(MacBsdInfo {
        start_us,
        uid: info.pbi_uid,
        ppid: info.pbi_ppid,
    })
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

fn validate_inventory_warnings(warnings: &[String]) -> Result<(), MacOsScanError> {
    if !warnings.is_empty() {
        // quick_scan deliberately permits malformed rows in a full-host scan.
        // Those missing rows prevent us from announcing a complete census.
        return Err(MacOsScanError::ToolFailed {
            tool: "ps".into(),
            message: format!(
                "process inventory is unknown: {} unreadable rows; {}",
                warnings.len(),
                warnings[0]
            ),
        });
    }
    Ok(())
}

/// Perform a macOS-specific deep scan.
///
/// Collects detailed process information using macOS tools (lsof, launchctl, etc.)
/// since /proc filesystem is not available.
#[cfg(target_os = "macos")]
pub fn macos_scan(options: &MacOsScanOptions) -> Result<MacOsScanResult, MacOsScanError> {
    macos_scan_observed(options, None)
}

#[cfg(target_os = "macos")]
fn macos_scan_observed(
    options: &MacOsScanOptions,
    mut observer: Option<&mut dyn FnMut(MacOsScanEvent) -> Result<(), MacOsScanError>>,
) -> Result<MacOsScanResult, MacOsScanError> {
    use crate::action::IdentityProvider;

    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let tool_timeout = options.tool_timeout.unwrap_or(Duration::from_secs(5));
    // Reuse the shipped scanner's target-only selection and exact native birth
    // identity. The old private ps parser mixed -e with -p and reconstructed
    // birth from elapsed seconds, which could join evidence across PID reuse.
    let scan = super::quick_scan(&super::QuickScanOptions {
        pids: options.pids.clone(),
        timeout: Some(tool_timeout),
        ..super::QuickScanOptions::default()
    })
    .map_err(|error| MacOsScanError::ToolFailed {
        tool: "ps".into(),
        message: error.to_string(),
    })?;
    validate_inventory_warnings(&scan.metadata.warnings)?;
    let mut pids = if options.pids.is_empty() {
        scan.processes
            .iter()
            .map(|process| process.pid.0)
            .collect::<Vec<_>>()
    } else {
        options.pids.clone()
    };
    pids.sort_unstable();
    pids.dedup();
    if let Some(observer) = observer.as_deref_mut() {
        observer(MacOsScanEvent::Inventory { pids: pids.clone() })?;
    }
    let base_info: HashMap<_, _> = scan
        .processes
        .into_iter()
        .map(|process| (process.pid.0, process))
        .collect();
    let identity_quality = if scan
        .metadata
        .boot_id
        .as_deref()
        .is_some_and(|boot| !boot.is_empty() && boot != "unknown")
    {
        IdentityQuality::Full
    } else {
        IdentityQuality::NoBootId
    };
    let capabilities = MacOsCapabilities::detect();
    if let Some(observer) = observer.as_deref_mut() {
        observer(MacOsScanEvent::Capabilities {
            capabilities: capabilities.clone(),
        })?;
    }
    // One launchctl snapshot per scan, not one full domain listing per PID.
    let launchd = if capabilities.launchctl_available {
        collect_launchd_services(tool_timeout)
    } else {
        Err("launchctl is unavailable".to_string())
    };
    let total_pids = pids.len() as u64;
    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_STARTED, Phase::DeepScan)
                .with_progress(0, Some(total_pids))
                .with_detail("capabilities", format!("{:?}", capabilities.sip_status)),
        );
    }

    let mut processes = Vec::new();
    let mut warnings = scan.metadata.warnings;
    warnings.push("launchd observations cover only the collector's bootstrap domain; no matching service does not establish absence of supervision".into());
    let mut skipped_count = 0usize;
    let identity_provider = crate::action::signal::LiveIdentityProvider::new();

    for pid in &pids {
        let Some(base) = base_info.get(pid) else {
            if !options.skip_inaccessible {
                return Err(MacOsScanError::ParseError {
                    pid: *pid,
                    message: "base process identity is unavailable".into(),
                });
            }
            skipped_count += 1;
            let warning = format!("PID {pid}: base process identity is unavailable");
            warnings.push(warning.clone());
            if let Some(observer) = observer.as_deref_mut() {
                observer(MacOsScanEvent::Skipped { pid: *pid, warning })?;
            }
            continue;
        };
        // BSD ps's sess value is not a native numeric session ID. Read both
        // group and session from the same birth used by the action subsystem.
        let identity = read_session_stat(*pid)
            .filter(|native| {
                native.starttime == read_bsd_info(*pid).map_or(0, |info| info.start_us)
            })
            .map(|native| {
                pt_common::ProcessIdentity::full(
                    *pid,
                    base.start_id.clone(),
                    base.uid,
                    u32::try_from(native.pgrp).ok(),
                    u32::try_from(native.session).ok(),
                    identity_quality,
                )
            });
        let Some(identity) =
            identity.filter(|identity| identity_provider.revalidate(identity).unwrap_or(false))
        else {
            if !options.skip_inaccessible {
                return Err(MacOsScanError::ParseError {
                    pid: *pid,
                    message: "native identity changed or could not be verified before collection"
                        .into(),
                });
            }
            skipped_count += 1;
            let warning = format!(
                "PID {pid}: native identity changed or could not be verified before collection"
            );
            warnings.push(warning.clone());
            if let Some(observer) = observer.as_deref_mut() {
                observer(MacOsScanEvent::Skipped { pid: *pid, warning })?;
            }
            continue;
        };
        let mut unavailable = Vec::new();
        let (open_files, network_connections, lsof_complete) = if capabilities.lsof_available {
            match collect_lsof_info(*pid, tool_timeout) {
                Ok((files, sockets)) => (files, sockets, true),
                Err(e) => {
                    unavailable.push(format!("lsof: {e}"));
                    (Vec::new(), Vec::new(), false)
                }
            }
        } else {
            unavailable.push("lsof is unavailable".into());
            (Vec::new(), Vec::new(), false)
        };
        let launchd_service = match &launchd {
            Ok(services) => services.get(pid).cloned(),
            Err(error) => {
                unavailable.push(format!("launchctl: {error}"));
                None
            }
        };
        let environ = if options.include_environ {
            let values = collect_environ(*pid);
            if values.is_none() {
                unavailable.push("process environment is unavailable".into());
            }
            values
        } else {
            None
        };
        if !identity_provider.revalidate(&identity).unwrap_or(false) {
            if !options.skip_inaccessible {
                return Err(MacOsScanError::ParseError {
                    pid: *pid,
                    message: "native identity changed or became unavailable during collection; evidence discarded".into(),
                });
            }
            skipped_count += 1;
            let warning = format!("PID {pid}: native identity changed or became unavailable during collection; evidence discarded");
            warnings.push(warning.clone());
            if let Some(observer) = observer.as_deref_mut() {
                observer(MacOsScanEvent::Skipped { pid: *pid, warning })?;
            }
            continue;
        }
        let record = MacOsScanRecord {
            pid: ProcessId(*pid),
            ppid: base.ppid,
            uid: base.uid,
            user: base.user.clone(),
            pgid: identity.pgid,
            sid: identity.sid,
            start_id: base.start_id.clone(),
            comm: base.comm.clone(),
            cmdline: base.cmd.clone(),
            exe: None,
            state: base.state.to_string().chars().next().unwrap_or('?'),
            cpu_percent: base.cpu_percent,
            rss_bytes: base.rss_bytes,
            vsz_bytes: base.vsz_bytes,
            open_files,
            network_connections,
            lsof_complete,
            launchd_domain_observed: launchd.is_ok(),
            unavailable,
            launchd_service,
            environ,
            start_time_unix: base.start_time_unix,
            elapsed: base.elapsed,
            source: "macos_scan".to_string(),
            identity_quality,
        };
        if let Some(observer) = observer.as_deref_mut() {
            observer(MacOsScanEvent::Record {
                record: Box::new(record.clone()),
            })?;
        }
        processes.push(record);
        let current = processes.len() + skipped_count;
        if current.is_multiple_of(50) {
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

    let metadata = MacOsScanMetadata {
        started_at,
        duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
        process_count,
        skipped_count,
        capabilities,
        warnings,
        collection: MacOsScanCollection {
            complete: true,
            requested_count: Some(pids.len()),
            processed_count: pids.len(),
            incomplete_count: Some(0),
            failed_count: skipped_count,
            ..MacOsScanCollection::default()
        },
    };
    if let Some(observer) = observer {
        observer(MacOsScanEvent::Complete {
            metadata: Box::new(metadata.clone()),
        })?;
    }
    Ok(MacOsScanResult {
        processes,
        metadata,
    })
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

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
    fn native_scan_fence_requires_both_births_and_strict_absolute_order() {
        let fence = MacosScanBirthFence(500);
        assert!(fence.accepts_reading(1_700_000_000_000_010, Some(499)));
        // A backwards calendar adjustment cannot make a replacement older.
        assert!(!fence.accepts_reading(1_699_999_999_000_000, Some(501)));
        assert!(!fence.accepts_reading(1, Some(500)));
        assert!(!fence.accepts_reading(1, Some(0)));
        assert!(!fence.accepts_reading(0, Some(499)));
        assert!(!fence.accepts_reading(1, None));
    }

    #[test]
    fn boot_session_uuid_requires_the_complete_kernel_string() {
        let boot = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f";
        assert_eq!(
            parse_boot_session_id(format!("{}\0", boot.to_uppercase()).as_bytes()).as_deref(),
            Some(boot)
        );
        for invalid in [
            boot,
            "",
            "unknown\0",
            "00000000-0000-0000-0000-000000000000\0",
            "9d2d4e208c2b4a3aa8a290bcb7a1d86f\0",
            "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f\0\0",
            "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86X\0",
        ] {
            assert_eq!(parse_boot_session_id(invalid.as_bytes()), None);
        }
    }

    #[test]
    fn full_and_legacy_births_have_distinct_boot_requirements() {
        let boot = "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f";
        let other = "22222222-2222-4222-8222-222222222222";
        let pid = 42;
        let birth = 1_800_000_000_123_456;
        let current = StartId::from_macos(boot, birth, pid);
        let mut target = pt_common::ProcessIdentity::new(pid, current.clone(), 1000);
        assert_eq!(target_birth(&target, Some(boot)), Some(birth));
        assert_eq!(target_birth(&target, Some(other)), None);
        assert_eq!(target_birth(&target, None), None);
        let legacy = StartId::from_macos("unknown", birth, pid);
        target.start_id = legacy.clone();
        assert_eq!(target_birth(&target, Some(boot)), None);
        target.quality = IdentityQuality::NoBootId;
        assert_eq!(target_birth(&target, None), Some(birth));
        assert_eq!(target_birth(&target, Some(boot)), Some(birth));
        assert!(legacy_birth_matches(&legacy, &current, pid, Some(boot)));
        assert!(!legacy_birth_matches(&current, &legacy, pid, Some(boot)));
        assert!(!legacy_birth_matches(&legacy, &current, pid, Some(other)));
        assert!(!legacy_birth_matches(&legacy, &current, pid, None));
        assert!(!legacy_birth_matches(&legacy, &current, pid + 1, Some(boot)));
        for (scope, value, id) in [
            ("synthetic", birth, pid),
            ("unknown", 0, pid),
            ("unknown", birth, pid + 1),
            ("unknown", birth / 1_000_000, pid),
        ] {
            let saved = StartId::from_macos(scope, value, id);
            assert!(!legacy_birth_matches(&saved, &current, pid, Some(boot)));
        }
        target.start_id = current;
        assert_eq!(target_birth(&target, Some(boot)), None);
        target.quality = IdentityQuality::PidOnly;
        assert_eq!(target_birth(&target, Some(boot)), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_scan_and_live_provider_agree_on_the_running_boot() {
        use crate::action::executor::IdentityProvider;
        use crate::action::signal::LiveIdentityProvider;
        let pid = std::process::id();
        let scan = super::super::quick_scan(&super::super::QuickScanOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .unwrap();
        let boot = boot_session_id().expect("read native boot UUID");
        assert_eq!(scan.metadata.boot_id.as_deref(), Some(boot.as_str()));
        let row = scan.processes.iter().find(|row| row.pid.0 == pid).unwrap();
        let native = read_bsd_info(pid).unwrap();
        let mut target = row.identity();
        let provider = LiveIdentityProvider::new();
        assert_eq!(target.quality, IdentityQuality::Full);
        assert_eq!(target.start_id, StartId::from_macos(&boot, native.start_us, pid));
        assert!(provider.revalidate(&target).unwrap());
        // SAFETY: getegid observes this test process's own effective group.
        let group = unsafe { libc::getegid() };
        assert_eq!(effective_gid(&target), Some(group));
        assert!(crate::decision::goal_contribution::macos_fd_count(&target).is_some());
        let mut foreign = uuid::Uuid::parse_str(&boot).unwrap().into_bytes();
        foreign[0] ^= 1;
        let foreign = uuid::Uuid::from_bytes(foreign).to_string();
        target.start_id = StartId::from_macos(&foreign, native.start_us, pid);
        assert!(!row.matches_saved_identity(&target));
        assert!(!provider.revalidate(&target).unwrap());
        assert_eq!(effective_gid(&target), None);
        assert_eq!(crate::decision::goal_contribution::macos_fd_count(&target), None);
        target.start_id = StartId::from_macos("unknown", native.start_us, pid);
        target.quality = IdentityQuality::NoBootId;
        assert!(row.matches_saved_identity(&target));
        assert!(provider.revalidate(&target).unwrap());
        assert_eq!(effective_gid(&target), Some(group));
        assert!(crate::decision::goal_contribution::macos_fd_count(&target).is_some());
        target.uid = target.uid.wrapping_add(1);
        assert!(!row.matches_saved_identity(&target));
        assert!(!provider.revalidate(&target).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unreaped_child_keeps_its_exact_birth_until_wait() {
        use crate::action::executor::IdentityProvider;
        use crate::action::signal::{observe_zombie_reaped, LiveIdentityProvider};

        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.wait();
            }
        }
        let mut child = Child(std::process::Command::new("/usr/bin/true").spawn().unwrap());
        let pid = child.0.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let stat = loop {
            if let Some(stat) = read_session_stat(pid).filter(|stat| stat.state == 'Z') {
                break stat;
            }
            assert!(std::time::Instant::now() < deadline, "unreaped child was not visible");
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let scan = super::super::quick_scan(&super::super::QuickScanOptions {
            pids: vec![pid],
            include_kernel_threads: true,
            ..Default::default()
        })
        .unwrap();
        let row = scan.processes.iter().find(|row| row.pid.0 == pid).unwrap();
        let target = row.identity();
        assert!(row.state.is_zombie());
        assert_eq!(row.ppid.0, std::process::id());
        assert_eq!(target.quality, IdentityQuality::Full);
        assert_eq!(target_birth(&target, scan.metadata.boot_id.as_deref()), Some(stat.starttime));
        assert_eq!(target.sid, u32::try_from(stat.session).ok());
        let provider = LiveIdentityProvider::new();
        assert!(provider.revalidate(&target).unwrap());
        assert!(!observe_zombie_reaped(&target).unwrap());
        let mut wrong_session = target.clone();
        wrong_session.sid = Some(target.sid.unwrap_or(0).wrapping_add(1));
        assert!(!provider.revalidate(&wrong_session).unwrap());
        assert!(child.0.wait().unwrap().success());
        assert!(observe_zombie_reaped(&target).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn effective_group_binds_the_native_birth_when_boot_id_is_unknown() {
        let pid = std::process::id();
        let live = read_bsd_info(pid).unwrap();
        let mut target = pt_common::ProcessIdentity::full(
            pid,
            pt_common::StartId::from_macos("unknown", live.start_us, pid),
            live.uid,
            None,
            None,
            pt_common::IdentityQuality::NoBootId,
        );
        // SAFETY: getegid only observes this test process's credentials.
        assert_eq!(effective_gid(&target), Some(unsafe { libc::getegid() }));
        target.uid = live.uid.wrapping_add(1);
        assert_eq!(effective_gid(&target), None);
        target.uid = live.uid;
        target.start_id = pt_common::StartId::from_macos("unknown", live.start_us + 1, pid);
        assert_eq!(effective_gid(&target), None);
        target.start_id = pt_common::StartId::from_macos("synthetic", live.start_us, pid);
        assert_eq!(effective_gid(&target), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_session_stat_preserves_native_process_birth() {
        let pid = std::process::id();
        let identity = read_bsd_info(pid).expect("read current process native identity");
        assert!(identity.start_us > 0, "native birth must be available");
        let fence = MacosScanBirthFence::capture(&[pid]);
        assert!(fence.accepts(pid, identity.start_us));

        let stat = read_session_stat(pid).expect("read current process session facts");
        assert_eq!(stat.pid, pid);
        assert_eq!(stat.starttime, identity.start_us);
        assert_eq!(
            read_session_stat(pid)
                .expect("reread current process session facts")
                .starttime,
            stat.starttime,
            "revalidation must preserve the same live process birth"
        );
    }

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
        let output = "p42\0\nf3\0tREG\0npath/to/file.txt\0ar\0\n";
        let (files, connections) = parse_lsof_output(output, 42).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].fd, Some(3));
        assert_eq!(files[0].file_type, "REG");
        assert_eq!(files[0].name, "path/to/file.txt");
        assert_eq!(files[0].mode, Some("r".to_string()));
        assert!(connections.is_empty());
    }

    #[test]
    fn test_parse_lsof_output_network() {
        let output = "p42\0\nf5\0tIPv4\0PTCP\0n127.0.0.1:8080->127.0.0.2:443\0TST=ESTABLISHED\0\n";
        let (files, connections) = parse_lsof_output(output, 42).unwrap();

        assert!(files.is_empty());
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].protocol, "TCP");
        assert_eq!(connections[0].local_address, "127.0.0.1:8080");
        assert_eq!(
            connections[0].remote_address,
            Some("127.0.0.2:443".to_string())
        );
        assert_eq!(connections[0].state, Some("ESTABLISHED".to_string()));
    }

    #[test]
    fn lsof_preserves_filename_boundaries_and_udp_protocol() {
        let output =
            "p42\0\nf3\0tREG\0n/tmp/日本語\np999\nf7\0aw\0\nf9\0tIPv6\0PUDP\0n[::1]:5353\0\n";
        let (files, sockets) = parse_lsof_output(output, 42).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "/tmp/日本語\np999\nf7");
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].protocol, "UDP6");
        assert_eq!(sockets[0].local_address, "[::1]:5353");
        assert_eq!(sockets[0].state, None);
        assert_eq!(sockets[0].remote_address, None);
    }

    #[test]
    fn lsof_missing_identity_truncated_and_malformed_evidence_is_unknown() {
        for invalid in [
            "",
            "p42\nf3\ntREG\nn/tmp/file\n",
            "p42\0\nf3\0tREG\0n/tmp/file",
            "p43\0\nf3\0tREG\0n/tmp/file\0",
            "p42\0p42\0",
            "f3\0tREG\0n/tmp/file\0",
            "p42\0f3\0n/tmp/file\0",
            "p42\0f3\0tREG\0",
            "p42\0f3\0tREG\0tREG\0n/file\0",
            "p42\0f3\0tIPv4\0n*:1234\0",
            "p42\0f3\0tUNKNfd\0nstat(/secret): Permission denied\0",
            "p42\0f3\0tUNSP\0n/unsupported\0",
            "p42\0f3\0t\0n/unknown\0",
            "p42\0ébad\0",
        ] {
            assert!(
                parse_lsof_output(invalid, 42).is_err(),
                "accepted {invalid:?}"
            );
        }
        let (files, sockets) = parse_lsof_output("p42\0\n", 42).unwrap();
        assert!(files.is_empty() && sockets.is_empty());
    }

    #[test]
    fn successful_lsof_with_diagnostics_is_unavailable_evidence() {
        let mut output = ToolOutput {
            command: "lsof".into(),
            args: vec![],
            stdout: b"p42\0\nf3\0tREG\0n/tmp/file\0ar\0\n".to_vec(),
            stderr: vec![],
            exit_code: Some(0),
            truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
        };
        assert_eq!(parse_lsof_tool_output(&output, 42).unwrap().0.len(), 1);
        output.stderr = b"lsof: WARNING: cannot stat filesystem; output may be incomplete".to_vec();
        assert!(parse_lsof_tool_output(&output, 42).is_err());
        output.stderr.clear();
        output.truncated = true;
        assert!(parse_lsof_tool_output(&output, 42).is_err());
        output.truncated = false;
        output.timed_out = true;
        assert!(parse_lsof_tool_output(&output, 42).is_err());
        output.timed_out = false;
        output.exit_code = Some(1);
        assert!(parse_lsof_tool_output(&output, 42).is_err());
    }

    #[test]
    fn launchd_snapshot_preserves_domain_matches_and_rejects_ambiguous_evidence() {
        let snapshot = parse_launchd_services(
            "PID\tStatus\tLabel\n-\t0\tdisabled.job\n42\t-9\tcom.example.worker\n",
        )
        .unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&42].label, "com.example.worker");
        assert_eq!(snapshot[&42].last_exit_status, Some(-9));
        for invalid in [
            "",
            "42 0 job",
            "PID Status Label\n42 x job",
            "PID Status Label\n0 0 job",
            "PID Status Label\n42 0 one\n42 0 two",
        ] {
            assert!(
                parse_launchd_services(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(parse_launchd_services("PID Status Label\n")
            .unwrap()
            .is_empty());
    }

    fn stream_record(pid: u32) -> MacOsScanRecord {
        MacOsScanRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(1),
            uid: 501,
            user: "fixture".into(),
            pgid: Some(pid),
            sid: None,
            start_id: StartId::from_macos("boot", 1_000_000, pid),
            comm: "sleep".into(),
            cmdline: "sleep 30".into(),
            exe: None,
            state: 'S',
            cpu_percent: 0.0,
            rss_bytes: 4096,
            vsz_bytes: 8192,
            open_files: vec![],
            network_connections: vec![],
            lsof_complete: false,
            launchd_domain_observed: false,
            unavailable: vec!["lsof: permission denied".into()],
            launchd_service: None,
            environ: None,
            start_time_unix: 1,
            elapsed: Duration::from_secs(3),
            source: "macos_scan".into(),
            identity_quality: IdentityQuality::Full,
        }
    }

    fn stream_prefix() -> Vec<MacOsScanEvent> {
        vec![
            MacOsScanEvent::Inventory { pids: vec![41, 42] },
            MacOsScanEvent::Capabilities {
                capabilities: MacOsCapabilities::default(),
            },
            MacOsScanEvent::Record {
                record: Box::new(stream_record(41)),
            },
        ]
    }

    fn stream_bytes(events: &[MacOsScanEvent]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend(serde_json::to_vec(event).unwrap());
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn streamed_records_preserve_unknown_evidence_and_exact_coverage() {
        let options = MacOsScanOptions {
            pids: vec![41, 42],
            ..MacOsScanOptions::default()
        };
        let mut stream = MacOsScanStream::new(&options, 500);
        for byte in stream_bytes(&stream_prefix()) {
            stream.consume(&[byte]).unwrap();
        }
        let partial = stream.finish(Instant::now(), false);
        assert_eq!(partial.metadata.process_count, 1);
        assert!(!partial.metadata.collection.complete);
        assert_eq!(partial.metadata.collection.processed_count, 1);
        assert_eq!(partial.metadata.collection.incomplete_count, Some(1));
        assert!(!partial.processes[0].lsof_complete);
        assert!(!partial.processes[0].unavailable.is_empty());

        let mut stream = MacOsScanStream::new(&options, 500);
        stream.consume(&stream_bytes(&stream_prefix())).unwrap();
        stream
            .accept(MacOsScanEvent::Skipped {
                pid: 42,
                warning: "process exited".into(),
            })
            .unwrap();
        let mut metadata = partial.metadata;
        metadata.skipped_count = 1;
        metadata.collection = MacOsScanCollection {
            complete: true,
            requested_count: Some(2),
            processed_count: 2,
            incomplete_count: Some(0),
            failed_count: 1,
            ..MacOsScanCollection::default()
        };
        stream
            .accept(MacOsScanEvent::Complete {
                metadata: Box::new(metadata),
            })
            .unwrap();
        let complete = stream.finish(Instant::now(), true);
        assert!(complete.metadata.collection.complete);
        assert_eq!(complete.metadata.collection.failed_count, 1);
        assert_eq!(complete.metadata.collection.incomplete_count, Some(0));
    }

    #[test]
    fn malformed_worker_cannot_claim_duplicate_or_missing_processes() {
        let options = MacOsScanOptions {
            pids: vec![41, 42],
            ..MacOsScanOptions::default()
        };
        for pid in [41, 43] {
            let mut stream = MacOsScanStream::new(&options, 500);
            stream.consume(&stream_bytes(&stream_prefix())).unwrap();
            assert!(stream
                .accept(MacOsScanEvent::Record {
                    record: Box::new(stream_record(pid))
                })
                .is_err());
        }
        let mut stream = MacOsScanStream::new(&options, 500);
        assert!(stream
            .accept(MacOsScanEvent::Inventory { pids: vec![41] })
            .is_err());
        let mut stream = MacOsScanStream::new(&options, 500);
        assert!(stream
            .accept(MacOsScanEvent::Record {
                record: Box::new(stream_record(41))
            })
            .is_err());
        let mut stream = MacOsScanStream::new(&options, 500);
        stream.consume(&stream_bytes(&stream_prefix())).unwrap();
        let mut metadata = stream.result.metadata.clone();
        metadata.process_count = 1;
        metadata.collection.complete = true;
        metadata.collection.processed_count = 2;
        metadata.collection.incomplete_count = Some(0);
        assert!(stream
            .accept(MacOsScanEvent::Complete {
                metadata: Box::new(metadata)
            })
            .is_err());
        assert!(
            !stream
                .finish(Instant::now(), true)
                .metadata
                .collection
                .complete
        );
    }

    #[test]
    fn zero_budget_does_not_start_worker_or_invent_a_census() {
        for pids in [vec![], vec![41, 41, 42]] {
            let options = MacOsScanOptions {
                pids,
                ..MacOsScanOptions::default()
            };
            let result =
                macos_scan_with_budget(&options, Duration::ZERO, Path::new("/does/not/exist"))
                    .unwrap();
            assert!(result.metadata.collection.timed_out);
            assert!(!result.metadata.collection.complete);
            assert!(result.processes.is_empty());
            assert_eq!(
                result.metadata.collection.requested_count,
                (!options.pids.is_empty()).then_some(2)
            );
        }
    }

    #[test]
    fn unreadable_snapshot_rows_prevent_a_complete_inventory() {
        assert!(validate_inventory_warnings(&[]).is_ok());
        let warning = "Line 2: malformed process row".to_string();
        let error = validate_inventory_warnings(&[warning]).unwrap_err();
        assert!(error.to_string().contains("process inventory is unknown"));
        let options = MacOsScanOptions::default();
        // The native collector validates before publishing its Inventory event.
        let result = MacOsScanStream::new(&options, 500).finish(Instant::now(), false);
        assert!(!result.metadata.collection.complete);
        assert_eq!(result.metadata.collection.requested_count, None);
        assert_eq!(result.metadata.collection.incomplete_count, None);
    }

    #[cfg(unix)]
    #[test]
    fn owned_worker_deadline_retains_only_completed_records() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("macos-scan-fixture");
        let events = String::from_utf8(stream_bytes(&stream_prefix())).unwrap();
        let script = format!(
            "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{}'\nexec sleep 30\n",
            events.replace('\'', "'\"'\"'")
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let options = MacOsScanOptions {
            pids: vec![41, 42],
            ..MacOsScanOptions::default()
        };
        let started = Instant::now();
        let result =
            macos_scan_with_budget(&options, Duration::from_millis(750), &executable).unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(result.metadata.collection.timed_out);
        assert!(!result.metadata.collection.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].pid, ProcessId(41));
        assert_eq!(result.metadata.collection.incomplete_count, Some(1));
    }

    #[test]
    fn test_macos_capabilities_default() {
        let caps = MacOsCapabilities::default();
        assert_eq!(caps.sip_status, SipStatus::Unknown);
        assert!(!caps.lsof_available);
    }
}
