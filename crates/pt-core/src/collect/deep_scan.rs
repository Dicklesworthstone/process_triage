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

use super::gpu::{
    collect_gpu_handles, collect_gpu_snapshot, gpu_resource_evidence, process_gpu_evidence,
    GpuSnapshot, ProcessGpuEvidence,
};
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
use super::tool_runner::{ToolConfig, ToolError, ToolRunner, ToolSpec};
use super::user_intent::{collect_user_intent, UserIntentConfig, UserIntentFeatures};
use super::workspace_resolver::resolve_workspace_for_pid;
use crate::events::{event_names, Phase, ProgressEmitter, ProgressEvent};
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use pt_common::{RawResourceEvidence, RawWorkspaceEvidence};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
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

    #[error("Deep scan worker failed: {0}")]
    Worker(String),
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

    /// Local GPU descriptor ownership, with explicit unknown allocation/activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<ProcessGpuEvidence>,

    /// Identity-bound recent repository activity from the bounded worker.
    /// Other intent probes are disabled here. Direct synchronous deep_scan
    /// leaves this absent; absence never establishes inactivity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_intent: Option<UserIntentFeatures>,

    /// Repository/worktree provenance for the same observed process and CWD,
    /// collected only in the bounded worker path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<RawWorkspaceEvidence>,

    /// Cgroup information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<CgroupInfo>,

    /// Wait channel (kernel function where sleeping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wchan: Option<String>,

    /// Network connection info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,

    /// Gaps in socket attribution. When nonempty, the counts and queues in
    /// `network` describe only the sockets we could resolve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_unavailable: Vec<String>,

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
    fn collect_network(&mut self, snapshot: &NetworkSnapshot) {
        match snapshot.observe_identity(&self.to_identity()) {
            Ok(observation) => {
                self.network = Some(observation.info);
                self.network_unavailable = observation.unavailable;
            }
            Err(error) => {
                self.network = None;
                self.network_unavailable = vec![error.to_string()];
            }
        }
    }

    /// Complete, partially attributed, or unavailable socket inventory.
    /// Legacy records only retained complete network-table observations.
    pub fn network_coverage(&self) -> &'static str {
        match &self.network {
            None => "unavailable",
            Some(_) if self.network_unavailable.is_empty() => "complete",
            Some(_) => "partial",
        }
    }

    /// Positive socket ownership evidence. An empty observation cannot prove
    /// inactivity, even when every descriptor was attributed.
    pub fn observed_socket_presence(&self) -> Option<bool> {
        let observed = self.network.as_ref().is_some_and(|network| {
            let counts = &network.socket_counts;
            [
                counts.tcp,
                counts.tcp6,
                counts.udp,
                counts.udp6,
                counts.unix,
                counts.raw,
            ]
            .iter()
            .any(|count| *count > 0)
                || !network.listen_ports.is_empty()
                || !network.tcp_connections.is_empty()
                || !network.udp_sockets.is_empty()
                || !network.unix_sockets.is_empty()
        }) || self.fd.as_ref().is_some_and(|fd| fd.sockets > 0);
        observed.then_some(true)
    }

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

    /// One vendor snapshot for the scan. Driver PIDs remain unverified and are
    /// not joined to process records merely because numeric PIDs are equal.
    #[serde(default)]
    pub gpu: GpuSnapshot,
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

    /// Collection coverage, distinct from inaccessible/vanished process counts.
    #[serde(default)]
    pub collection: DeepScanCollection,

    /// Any warnings encountered during scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Last collection phase reached, including unfinished optional enrichment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeepScanStage {
    #[default]
    Initializing,
    Processes,
    Gpu,
    GpuEnrichment,
    Complete,
}

/// Explicit coverage for completed and deadline-limited scans.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeepScanCollection {
    pub complete: bool,
    pub timed_out: bool,
    pub output_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
    /// None means the worker did not finish enumerating the process inventory.
    pub requested_count: Option<usize>,
    /// Number of PIDs with a reported success, skip, or failure.
    pub processed_count: usize,
    /// PIDs with no reported outcome; unknown until the inventory is known.
    pub incomplete_count: Option<usize>,
    /// Failed outcomes that were reported as warnings rather than skips.
    pub failed_count: usize,
    /// Collected records whose optional workflow/GPU enrichment finished.
    pub enriched_count: usize,
    pub stage: DeepScanStage,
}

const WORKER_REQUEST_LIMIT: usize = 1024 * 1024;
const WORKER_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const WORKER_MESSAGE_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeepScanWorkerRequest {
    pids: Vec<u32>,
    skip_inaccessible: bool,
    include_environ: bool,
    use_wait_free: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum DeepScanWorkerEvent {
    Inventory {
        pids: Vec<u32>,
    },
    Stage {
        stage: DeepScanStage,
    },
    Record {
        record: Box<DeepScanRecord>,
        enriched: bool,
    },
    Skipped {
        pid: u32,
        failed: bool,
        warning: Option<String>,
    },
    Gpu {
        snapshot: Box<GpuSnapshot>,
    },
    Complete {
        metadata: DeepScanMetadata,
    },
}

type ScanObserver<'a> = dyn Fn(DeepScanWorkerEvent) -> Result<(), DeepScanError> + Sync + 'a;

/// Run only in the dedicated `__deep-scan-worker` subprocess, before application
/// locks, configuration, logging, or sessions are initialized. The request is a
/// bounded JSON document on stdin and stdout is exclusively a JSONL event stream.
pub fn run_deep_scan_worker() -> Result<(), DeepScanError> {
    let mut request = Vec::new();
    std::io::stdin()
        .lock()
        .take((WORKER_REQUEST_LIMIT + 1) as u64)
        .read_to_end(&mut request)?;
    if request.len() > WORKER_REQUEST_LIMIT {
        return Err(DeepScanError::Worker("request exceeds 1 MiB".into()));
    }
    let request: DeepScanWorkerRequest = serde_json::from_slice(&request)
        .map_err(|error| DeepScanError::Worker(format!("invalid request: {error}")))?;
    let output = Mutex::new(std::io::BufWriter::new(std::io::stdout()));
    let observer = |event| {
        let mut writer = output
            .lock()
            .map_err(|_| DeepScanError::Worker("output lock poisoned".into()))?;
        serde_json::to_writer(&mut *writer, &event)
            .map_err(|error| DeepScanError::Worker(format!("cannot stream result: {error}")))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    };
    deep_scan_observed(
        &DeepScanOptions {
            pids: request.pids,
            skip_inaccessible: request.skip_inaccessible,
            include_environ: request.include_environ,
            use_wait_free: request.use_wait_free,
            progress: None,
        },
        Some(&observer),
    )?;
    Ok(())
}

/// Isolate `/proc`, filesystem, and GPU reads in an owned subprocess. The parent
/// stops collecting at its deadline and retains records streamed before
/// cancellation, including evidence collected before optional GPU enrichment.
///
/// The wall budget includes worker startup, stdin, output, and collection. Small
/// local serialization/cleanup overhead is unavoidable; SIGKILL cannot force a
/// task out of uninterruptible kernel I/O. A cleanup-only reaper may remain until
/// the kernel releases that task, but no detached scanning thread runs here.
///
/// Progress callbacks are coalesced and invoked only after the worker has exited
/// or cancellation has been requested. Callback/output delivery is outside the
/// collection budget; a blocked caller-owned sink cannot delay cancellation.
pub fn deep_scan_with_budget(
    options: &DeepScanOptions,
    budget: Duration,
    worker_executable: &Path,
) -> Result<DeepScanResult, DeepScanError> {
    let started = Instant::now();
    let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    let mut stream = DeepScanStream::new(options, budget_ms);
    if budget.as_millis() == 0 {
        stream.result.metadata.collection.timed_out = true;
        stream
            .result
            .metadata
            .warnings
            .push("Deep scan budget expired before collection started; no probes were run".into());
        return Ok(stream.finish(started, false));
    }
    let request = serde_json::to_vec(&DeepScanWorkerRequest {
        pids: options.pids.clone(),
        skip_inaccessible: options.skip_inaccessible,
        include_environ: options.include_environ,
        use_wait_free: options.use_wait_free,
    })
    .map_err(|error| DeepScanError::Worker(format!("cannot encode request: {error}")))?;
    if request.len() > WORKER_REQUEST_LIMIT {
        return Err(DeepScanError::Worker("request exceeds 1 MiB".into()));
    }
    // Keep the same minimal GPU runtime context as the complete-response CLI
    // worker. Never inherit output overrides, arbitrary variables, or credentials.
    let mut worker_env = std::collections::BTreeMap::new();
    for key in ["HOME", "XDG_RUNTIME_DIR", "TMPDIR"] {
        match std::env::var(key) {
            Ok(value) => {
                worker_env.insert(key.to_string(), value);
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(DeepScanError::Worker(format!(
                    "deep-scan environment {key} is not UTF-8"
                )));
            }
        }
    }
    let remaining = budget.saturating_sub(started.elapsed());
    // Millisecond budget accounting must never round a tiny budget up and probe.
    if remaining.as_millis() == 0 {
        stream.result.metadata.collection.timed_out = true;
        stream
            .result
            .metadata
            .warnings
            .push("Deep scan budget expired before collection started; no probes were run".into());
        return Ok(stream.finish(started, false));
    }
    let executable = worker_executable
        .to_str()
        .ok_or_else(|| DeepScanError::Worker("worker path is not UTF-8".into()))?;
    let runner = ToolRunner::new(ToolConfig {
        default_timeout: remaining,
        budget_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
        max_output_bytes: WORKER_OUTPUT_LIMIT,
        use_nice: false,
        use_ionice: false,
        ..ToolConfig::default()
    });
    let mut spec = ToolSpec::new(executable, vec!["__deep-scan-worker".into()])
        .with_stdin(request)
        .with_timeout(remaining)
        .with_process_group();
    spec.env = worker_env;
    let output = runner.run_with_stdout_handler(&spec, Some(&mut |bytes| stream.consume(bytes)));
    let successful = match output {
        Ok(output) => {
            stream.result.metadata.collection.timed_out = output.timed_out;
            stream.result.metadata.collection.output_truncated = output.truncated;
            if output.timed_out {
                stream.result.metadata.warnings.push(format!(
                    "Deep scan exceeded its {budget_ms} ms collection budget; completed evidence was retained"
                ));
            }
            if output.truncated {
                stream.result.metadata.warnings.push(
                    "Deep scan worker output exceeded its byte limit; collection is incomplete"
                        .into(),
                );
            }
            if !output.success() && !output.timed_out && !output.truncated {
                stream.result.metadata.warnings.push(format!(
                    "Deep scan worker exited without success (status {:?})",
                    output.exit_code
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
                .push(format!("Deep scan worker: {error}"));
            false
        }
    };
    Ok(stream.finish(started, successful))
}

/// Incremental, bounded protocol decoder; no large post-deadline JSON parse.
struct DeepScanStream<'a> {
    result: DeepScanResult,
    pending: Vec<u8>,
    outcomes: HashSet<u32>,
    expected_pids: Option<HashSet<u32>>,
    records: HashMap<u32, usize>,
    enriched: HashSet<u32>,
    inventory_received: bool,
    gpu_received: bool,
    terminal_received: bool,
    options: &'a DeepScanOptions,
    progress_started: Option<ProgressEvent>,
}

impl<'a> DeepScanStream<'a> {
    fn new(options: &'a DeepScanOptions, budget_ms: u64) -> Self {
        let expected_pids = (!options.pids.is_empty())
            .then(|| options.pids.iter().copied().collect::<HashSet<_>>());
        let requested_count = expected_pids.as_ref().map(HashSet::len);
        Self {
            result: DeepScanResult {
                processes: Vec::new(),
                gpu: GpuSnapshot::default(),
                metadata: DeepScanMetadata {
                    started_at: chrono::Utc::now().to_rfc3339(),
                    duration_ms: 0,
                    process_count: 0,
                    skipped_count: 0,
                    warnings: Vec::new(),
                    collection: DeepScanCollection {
                        budget_ms: Some(budget_ms),
                        requested_count,
                        incomplete_count: requested_count,
                        ..DeepScanCollection::default()
                    },
                },
            },
            pending: Vec::new(),
            outcomes: HashSet::new(),
            expected_pids,
            records: HashMap::new(),
            enriched: HashSet::new(),
            inventory_received: false,
            gpu_received: false,
            terminal_received: false,
            options,
            progress_started: None,
        }
    }

    fn consume(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            if self.pending.len().saturating_add(part.len()) > WORKER_MESSAGE_LIMIT {
                self.result.metadata.collection.output_truncated = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "deep scan worker message exceeds 4 MiB",
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

    fn accept(&mut self, event: DeepScanWorkerEvent) -> std::io::Result<()> {
        let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
        if self.terminal_received {
            return Err(invalid("deep scan event after completion"));
        }
        match event {
            DeepScanWorkerEvent::Inventory { pids } => {
                let count = pids.len();
                let pids: HashSet<_> = pids.into_iter().collect();
                if self.inventory_received
                    || pids.len() != count
                    || self
                        .expected_pids
                        .as_ref()
                        .is_some_and(|expected| expected != &pids)
                {
                    return Err(invalid("inconsistent deep scan inventory"));
                }
                self.inventory_received = true;
                self.expected_pids = Some(pids);
                self.result.metadata.collection.requested_count = Some(count);
                if self.options.progress.is_some() {
                    self.progress_started = Some(
                        ProgressEvent::new(event_names::DEEP_SCAN_STARTED, Phase::DeepScan)
                            .with_progress(0, Some(count as u64))
                            .with_detail("include_environ", self.options.include_environ)
                            .with_detail("skip_inaccessible", self.options.skip_inaccessible)
                            .with_detail("wait_free", self.options.use_wait_free)
                            .with_detail("budget_ms", self.result.metadata.collection.budget_ms),
                    );
                }
            }
            DeepScanWorkerEvent::Stage { stage } => {
                let previous = self.result.metadata.collection.stage;
                let valid = self.inventory_received
                    && matches!(
                        (previous, stage),
                        (DeepScanStage::Initializing, DeepScanStage::Processes)
                            | (DeepScanStage::Processes, DeepScanStage::Gpu)
                            | (DeepScanStage::Gpu, DeepScanStage::GpuEnrichment)
                    );
                if !valid || (stage == DeepScanStage::GpuEnrichment && !self.gpu_received) {
                    return Err(invalid("invalid deep scan phase transition"));
                }
                self.result.metadata.collection.stage = stage;
            }
            DeepScanWorkerEvent::Record { record, enriched } => {
                let pid = record.pid.0;
                if !self
                    .expected_pids
                    .as_ref()
                    .is_some_and(|pids| pids.contains(&pid))
                {
                    return Err(invalid(
                        "deep scan record is outside the requested inventory",
                    ));
                }
                if enriched {
                    if self.result.metadata.collection.stage != DeepScanStage::GpuEnrichment {
                        return Err(invalid("deep scan enrichment outside its collection phase"));
                    }
                    let index = *self
                        .records
                        .get(&pid)
                        .ok_or_else(|| invalid("enrichment without a process record"))?;
                    if self.result.processes[index].start_id != record.start_id
                        || record.gpu.is_none()
                        || !self.enriched.insert(pid)
                    {
                        return Err(invalid("inconsistent deep scan enrichment identity"));
                    }
                    self.result.processes[index] = *record;
                } else {
                    if self.result.metadata.collection.stage != DeepScanStage::Processes
                        || !self.outcomes.insert(pid)
                    {
                        return Err(invalid("duplicate or unannounced deep scan process"));
                    }
                    self.records.insert(pid, self.result.processes.len());
                    self.result.processes.push(*record);
                }
            }
            DeepScanWorkerEvent::Skipped {
                pid,
                failed,
                warning,
            } => {
                if self.result.metadata.collection.stage != DeepScanStage::Processes
                    || !self
                        .expected_pids
                        .as_ref()
                        .is_some_and(|pids| pids.contains(&pid))
                    || !self.outcomes.insert(pid)
                {
                    return Err(invalid("duplicate or unannounced deep scan skip"));
                }
                if failed {
                    self.result.metadata.collection.failed_count += 1;
                } else {
                    self.result.metadata.skipped_count += 1;
                }
                if let Some(warning) = warning {
                    self.result.metadata.warnings.push(warning);
                }
            }
            DeepScanWorkerEvent::Gpu { snapshot } => {
                if self.result.metadata.collection.stage != DeepScanStage::Gpu || self.gpu_received
                {
                    return Err(invalid("unexpected deep scan GPU snapshot"));
                }
                self.gpu_received = true;
                self.result.metadata.warnings.extend(
                    snapshot
                        .provenance
                        .warnings
                        .iter()
                        .map(|warning| format!("GPU: {warning}")),
                );
                self.result.gpu = *snapshot;
            }
            DeepScanWorkerEvent::Complete { metadata } => {
                if !self.inventory_received
                    || self.result.metadata.collection.requested_count != Some(self.outcomes.len())
                    || metadata.process_count != self.result.processes.len()
                    || metadata.skipped_count != self.result.metadata.skipped_count
                    || metadata.collection.failed_count
                        != self.result.metadata.collection.failed_count
                    || self.enriched.len() != self.result.processes.len()
                    || !metadata.collection.complete
                    || metadata.collection.stage != DeepScanStage::Complete
                    || self.result.metadata.collection.stage != DeepScanStage::GpuEnrichment
                    || metadata.collection.requested_count != Some(self.outcomes.len())
                    || metadata.collection.processed_count != self.outcomes.len()
                    || metadata.collection.enriched_count != self.enriched.len()
                    || metadata.collection.incomplete_count != Some(0)
                    || metadata.collection.timed_out
                    || metadata.collection.output_truncated
                {
                    return Err(invalid(
                        "deep scan completion does not match observed coverage",
                    ));
                }
                self.terminal_received = true;
                self.result.metadata.warnings = metadata.warnings;
            }
        }
        if self
            .result
            .metadata
            .collection
            .requested_count
            .is_some_and(|count| self.outcomes.len() > count)
        {
            return Err(invalid("deep scan outcomes exceed the inventory"));
        }
        Ok(())
    }

    fn finish(mut self, started: Instant, successful: bool) -> DeepScanResult {
        let collection = &mut self.result.metadata.collection;
        collection.complete = successful && self.terminal_received && self.pending.is_empty();
        collection.processed_count = self.outcomes.len();
        collection.incomplete_count = collection
            .requested_count
            .map(|count| count.saturating_sub(self.outcomes.len()));
        collection.enriched_count = self.enriched.len();
        if collection.complete {
            collection.stage = DeepScanStage::Complete;
        } else {
            self.result.metadata.warnings.push(format!(
                "Incomplete deep scan: {} process outcomes, inventory {:?}, last stage {:?}; missing evidence remains unknown",
                collection.processed_count, collection.requested_count, collection.stage
            ));
        }
        self.result.metadata.process_count = self.result.processes.len();
        self.result.metadata.duration_ms =
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        // ToolRunner has already exited or cancelled its worker before finish.
        // Never invoke arbitrary callback I/O while probes still own a deadline.
        if let Some(emitter) = self.options.progress.as_ref() {
            if let Some(event) = self.progress_started {
                emitter.emit(event);
            }
            if collection.processed_count > 0 {
                emitter.emit(
                    ProgressEvent::new(event_names::DEEP_SCAN_PROGRESS, Phase::DeepScan)
                        .with_progress(
                            collection.processed_count as u64,
                            collection.requested_count.map(|count| count as u64),
                        )
                        .with_detail("skipped", self.result.metadata.skipped_count)
                        .with_detail("failed", collection.failed_count),
                );
            }
            emitter.emit(
                ProgressEvent::new(event_names::DEEP_SCAN_COMPLETE, Phase::DeepScan)
                    .with_elapsed_ms(self.result.metadata.duration_ms)
                    .with_detail("complete", collection.complete)
                    .with_detail("timed_out", collection.timed_out)
                    .with_detail("process_count", self.result.metadata.process_count)
                    .with_detail("skipped", self.result.metadata.skipped_count)
                    .with_detail("warnings", self.result.metadata.warnings.len())
                    .with_detail("stage", collection.stage),
            );
        }
        self.result
    }
}

#[derive(Default)]
struct ProcessCollection {
    processes: Vec<DeepScanRecord>,
    warnings: Vec<String>,
    skipped: usize,
    failed: usize,
}

impl ProcessCollection {
    fn record(
        &mut self,
        pid: u32,
        result: Result<DeepScanRecord, DeepScanError>,
        skip_inaccessible: bool,
        observer: Option<&ScanObserver<'_>>,
    ) -> Result<(), DeepScanError> {
        match result {
            Ok(record) => {
                if let Some(observer) = observer {
                    observer(DeepScanWorkerEvent::Record {
                        record: Box::new(record.clone()),
                        enriched: false,
                    })?;
                }
                self.processes.push(record);
            }
            Err(error) => {
                let failed =
                    !skip_inaccessible && !matches!(error, DeepScanError::ProcessVanished(_));
                let warning = failed.then(|| format!("PID {pid}: {error}"));
                if failed {
                    self.failed += 1;
                } else {
                    self.skipped += 1;
                }
                if let Some(observer) = observer {
                    observer(DeepScanWorkerEvent::Skipped {
                        pid,
                        failed,
                        warning: warning.clone(),
                    })?;
                }
                if let Some(warning) = warning {
                    self.warnings.push(warning);
                }
            }
        }
        Ok(())
    }
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
    deep_scan_observed(options, None)
}

fn deep_scan_observed(
    options: &DeepScanOptions,
    observer: Option<&ScanObserver<'_>>,
) -> Result<DeepScanResult, DeepScanError> {
    let start = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Inventory precedes potentially blocked initialization so partial results
    // can distinguish an unknown census from a known set of unfinished PIDs.
    let pids = if options.pids.is_empty() {
        list_all_pids()?
    } else {
        // Explicit target order can encode VOI priority; retain first occurrence.
        let mut seen = HashSet::new();
        options
            .pids
            .iter()
            .copied()
            .filter(|pid| seen.insert(*pid))
            .collect::<Vec<_>>()
    };
    let total_pids = pids.len() as u64;
    if let Some(observer) = observer {
        observer(DeepScanWorkerEvent::Inventory { pids: pids.clone() })?;
    }

    // Initialize user cache to avoid reading /etc/passwd for every process
    let user_cache = UserCache::new();

    // Initialize network snapshot once for O(1) lookups per process
    let network_snapshot = NetworkSnapshot::collect();

    // Read boot_id once
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string());

    if let Some(emitter) = options.progress.as_ref() {
        emitter.emit(
            ProgressEvent::new(event_names::DEEP_SCAN_STARTED, Phase::DeepScan)
                .with_progress(0, Some(total_pids))
                .with_detail("include_environ", options.include_environ)
                .with_detail("skip_inaccessible", options.skip_inaccessible)
                .with_detail("wait_free", options.use_wait_free),
        );
    }

    if let Some(observer) = observer {
        observer(DeepScanWorkerEvent::Stage {
            stage: DeepScanStage::Processes,
        })?;
    }
    let mut collected = ProcessCollection::default();

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
                    collected.record(
                        pid,
                        parse_probed_process(
                            pid,
                            &results,
                            &user_cache,
                            &boot_id,
                            &network_snapshot,
                        ),
                        options.skip_inaccessible,
                        observer,
                    )?;
                }
            }

            return finish_scan(
                start,
                started_at,
                collected,
                pids.len(),
                options.progress.as_ref(),
                observer,
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
    let chunk_size = pids.len().div_ceil(num_threads.max(1)).max(1);
    let chunks: Vec<_> = pids.chunks(chunk_size).collect();

    let collected = thread::scope(|s| -> Result<ProcessCollection, DeepScanError> {
        let mut handles = Vec::new();

        for chunk in chunks {
            let user_cache_ref = &user_cache;
            let network_snapshot_ref = &network_snapshot;
            let boot_id_ref = &boot_id;
            let progress_ref = options.progress.as_ref();
            let counter_ref = &scanned_counter;

            handles.push(
                s.spawn(move || -> Result<ProcessCollection, DeepScanError> {
                    let mut local = ProcessCollection::default();

                    for &pid in chunk {
                        local.record(
                            pid,
                            scan_process(
                                pid,
                                options.include_environ,
                                user_cache_ref,
                                boot_id_ref,
                                network_snapshot_ref,
                            ),
                            options.skip_inaccessible,
                            observer,
                        )?;

                        let current = counter_ref.fetch_add(1, Ordering::Relaxed) + 1;
                        if current.is_multiple_of(PROGRESS_STEP) {
                            if let Some(emitter) = progress_ref {
                                emitter.emit(
                                    ProgressEvent::new(
                                        event_names::DEEP_SCAN_PROGRESS,
                                        Phase::DeepScan,
                                    )
                                    .with_progress(current as u64, Some(total_pids))
                                    .with_detail("skipped", local.skipped),
                                );
                            }
                        }
                    }
                    Ok(local)
                }),
            );
        }

        let mut all = ProcessCollection::default();

        for handle in handles {
            let local = handle
                .join()
                .map_err(|_| DeepScanError::Worker("process collector panicked".into()))??;
            all.processes.extend(local.processes);
            all.warnings.extend(local.warnings);
            all.skipped += local.skipped;
            all.failed += local.failed;
        }

        Ok(all)
    })?;

    finish_scan(
        start,
        started_at,
        collected,
        pids.len(),
        options.progress.as_ref(),
        observer,
    )
}

/// Collect optional filesystem context only after the base record is retained.
/// Only the observed worker path calls this: direct synchronous deep_scan
/// callers must not inherit arbitrary checkout-filesystem I/O.
fn collect_workflow_context(
    record: &DeepScanRecord,
) -> (Option<UserIntentFeatures>, Option<RawWorkspaceEvidence>) {
    use crate::action::{IdentityProvider, LiveIdentityProvider};

    let provider = LiveIdentityProvider::new();
    let identity = record.to_identity();
    if !record.can_automate() || !matches!(provider.revalidate(&identity), Ok(true)) {
        return (None, None);
    }
    let cwd_path = format!("/proc/{}/cwd", record.pid.0);
    let Ok(cwd) = fs::read_link(&cwd_path) else {
        return (None, None);
    };
    let config = UserIntentConfig {
        enable_tty: false,
        enable_session_mux: false,
        enable_ssh: false,
        enable_shell_activity: false,
        enable_repo_activity: true,
        enable_editor_focus: false,
        ..UserIntentConfig::default()
    };
    let user_intent = collect_user_intent(record.pid.0, &config);
    let workspace = resolve_workspace_for_pid(record.pid.0);
    if !matches!(fs::read_link(&cwd_path), Ok(current) if current == cwd)
        || !matches!(provider.revalidate(&identity), Ok(true))
    {
        return (None, None);
    }
    let workspace = workspace
        .cwd
        .as_ref()
        .is_some_and(|observed| Path::new(&observed.original) == cwd.as_path())
        .then_some(workspace);
    (user_intent, workspace)
}

fn finish_scan(
    start: Instant,
    started_at: String,
    collected: ProcessCollection,
    requested_count: usize,
    progress: Option<&Arc<dyn ProgressEmitter>>,
    observer: Option<&ScanObserver<'_>>,
) -> Result<DeepScanResult, DeepScanError> {
    use crate::action::{IdentityProvider, LiveIdentityProvider};

    let ProcessCollection {
        mut processes,
        mut warnings,
        skipped: skipped_count,
        failed,
    } = collected;
    if let Some(observer) = observer {
        observer(DeepScanWorkerEvent::Stage {
            stage: DeepScanStage::Gpu,
        })?;
    }
    let gpu = collect_gpu_snapshot();
    if let Some(observer) = observer {
        observer(DeepScanWorkerEvent::Gpu {
            snapshot: Box::new(gpu.clone()),
        })?;
        observer(DeepScanWorkerEvent::Stage {
            stage: DeepScanStage::GpuEnrichment,
        })?;
    }
    let identity_provider = LiveIdentityProvider::new();
    let observed_at = chrono::Utc::now().to_rfc3339();
    for record in &mut processes {
        // Only the dedicated worker's observed path may inspect arbitrary
        // checkout files. Its base records were streamed first, so a deadline
        // here preserves their counters with context explicitly unknown.
        if observer.is_some() {
            let (user_intent, workspace) = collect_workflow_context(record);
            record.user_intent = user_intent;
            record.workspace = workspace;
        }
        let handles = collect_gpu_handles(record.pid.0, record.fd.as_ref());
        let identity = record.to_identity();
        let identity_verified =
            record.can_automate() && matches!(identity_provider.revalidate(&identity), Ok(true));
        let evidence =
            process_gpu_evidence(record.fd.as_ref(), handles, identity_verified, &observed_at);
        record
            .local_resource_evidence
            .extend(gpu_resource_evidence(record.pid.0, &evidence));
        record.gpu = Some(evidence);
        if let Some(observer) = observer {
            observer(DeepScanWorkerEvent::Record {
                record: Box::new(record.clone()),
                enriched: true,
            })?;
        }
    }
    warnings.extend(
        gpu.provenance
            .warnings
            .iter()
            .map(|warning| format!("GPU: {warning}")),
    );
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

    let metadata = DeepScanMetadata {
        started_at,
        duration_ms: duration.as_millis() as u64,
        process_count,
        skipped_count,
        warnings,
        collection: DeepScanCollection {
            complete: true,
            requested_count: Some(requested_count),
            processed_count: process_count + skipped_count + failed,
            incomplete_count: Some(0),
            failed_count: failed,
            enriched_count: process_count,
            stage: DeepScanStage::Complete,
            ..DeepScanCollection::default()
        },
    };
    if let Some(observer) = observer {
        observer(DeepScanWorkerEvent::Complete {
            metadata: metadata.clone(),
        })?;
    }
    Ok(DeepScanResult {
        processes,
        gpu,
        metadata,
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
    let mut record = DeepScanRecord {
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
        gpu: None,
        user_intent: None,
        workspace: None,
        cgroup,
        wchan,
        network: None,
        network_unavailable: Vec::new(),
        environ,
        starttime: stat_info.starttime,
        source: "deep_scan".to_string(),
        identity_quality,
    };
    record.collect_network(network_snapshot);
    Ok(record)
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

    // Collect environment variables if requested (may contain sensitive data)
    let environ = if include_environ {
        parse_environ(pid)
    } else {
        None
    };

    let mut record = DeepScanRecord {
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
        gpu: None,
        user_intent: None,
        workspace: None,
        cgroup,
        wchan,
        network: None,
        network_unavailable: Vec::new(),
        environ,
        starttime: stat_info.starttime,
        source: "deep_scan".to_string(),
        identity_quality,
    };
    record.collect_network(network_snapshot);
    Ok(record)
}

/// Compute start_id from available information.
fn compute_start_id(boot_id: &Option<String>, starttime: u64, pid: u32) -> StartId {
    let boot = boot_id.as_deref().unwrap_or("unknown");
    StartId::from_linux(boot, starttime, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol_record(pid: u32) -> DeepScanRecord {
        DeepScanRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(1),
            uid: 1000,
            user: "fixture".into(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId::from_linux("fixture-boot", 12345, pid),
            comm: "fixture".into(),
            cmdline: "fixture --wait".into(),
            exe: None,
            state: 'S',
            io: None,
            schedstat: None,
            sched: None,
            mem: None,
            fd: None,
            local_resource_evidence: Vec::new(),
            gpu: None,
            user_intent: None,
            workspace: None,
            cgroup: None,
            wchan: None,
            network: None,
            network_unavailable: Vec::new(),
            environ: None,
            starttime: 12345,
            source: "protocol-fixture".into(),
            identity_quality: IdentityQuality::Full,
        }
    }

    fn protocol_bytes(events: &[DeepScanWorkerEvent]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in events {
            serde_json::to_writer(&mut bytes, event).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    fn process_events(pids: Vec<u32>, record_pid: u32) -> Vec<DeepScanWorkerEvent> {
        vec![
            DeepScanWorkerEvent::Inventory { pids },
            DeepScanWorkerEvent::Stage {
                stage: DeepScanStage::Processes,
            },
            DeepScanWorkerEvent::Record {
                record: Box::new(protocol_record(record_pid)),
                enriched: false,
            },
        ]
    }

    fn blocked_worker(events: &[DeepScanWorkerEvent]) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("worker");
        let fifo = directory.path().join("worker.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        // Consume the real bounded request, emit complete records, then block
        // inside a synchronous filesystem open until the owned process is killed.
        let script = format!(
            "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$$\" >\"$0.pid\"\ncat <<'PT_DEEP_SCAN_EVENTS'\n{}PT_DEEP_SCAN_EVENTS\nexec 3<\"$0.fifo\"\n",
            String::from_utf8(protocol_bytes(events)).unwrap(),
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        (directory, executable)
    }

    #[test]
    fn deadline_zero_never_starts_a_worker_and_keeps_unknown_inventory() {
        for pids in [vec![], vec![41, 42, 41]] {
            let options = DeepScanOptions {
                pids,
                ..DeepScanOptions::default()
            };
            let result =
                deep_scan_with_budget(&options, Duration::ZERO, Path::new("/does/not/exist"))
                    .expect("zero budget does not validate or launch an executable");
            assert!(result.metadata.collection.timed_out);
            assert!(!result.metadata.collection.complete);
            assert_eq!(result.metadata.collection.processed_count, 0);
            assert_eq!(result.metadata.skipped_count, 0);
            assert_eq!(
                result.metadata.collection.incomplete_count,
                if options.pids.is_empty() {
                    None
                } else {
                    Some(2)
                }
            );
            assert!(result.processes.is_empty());
            assert_eq!(result.gpu.has_gpu, None);
        }
    }

    #[test]
    fn deadline_retains_completed_records_when_a_worker_blocks_in_a_fifo_open() {
        let mut events = process_events(vec![41, 42, 43], 41);
        events.push(DeepScanWorkerEvent::Skipped {
            pid: 42,
            failed: false,
            warning: None,
        });
        let (_directory, executable) = blocked_worker(&events);
        let options = DeepScanOptions {
            pids: vec![41, 42, 43],
            ..DeepScanOptions::default()
        };
        let started = Instant::now();
        let result =
            deep_scan_with_budget(&options, Duration::from_millis(750), &executable).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            result.metadata.collection.timed_out,
            "{:?}",
            result.metadata
        );
        assert!(!result.metadata.collection.complete);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].pid.0, 41);
        assert_eq!(result.metadata.collection.processed_count, 2);
        assert_eq!(result.metadata.collection.incomplete_count, Some(1));
        assert_eq!(result.metadata.skipped_count, 1);
        assert_eq!(result.metadata.collection.enriched_count, 0);
        assert_eq!(result.metadata.collection.stage, DeepScanStage::Processes);
        assert!(result.processes[0].gpu.is_none());
    }

    #[test]
    fn deadline_during_gpu_keeps_process_evidence_without_claiming_completion() {
        let mut events = process_events(vec![41], 41);
        events.push(DeepScanWorkerEvent::Stage {
            stage: DeepScanStage::Gpu,
        });
        let (_directory, executable) = blocked_worker(&events);
        let options = DeepScanOptions {
            pids: vec![41],
            ..DeepScanOptions::default()
        };
        let result =
            deep_scan_with_budget(&options, Duration::from_millis(750), &executable).unwrap();
        assert!(
            result.metadata.collection.timed_out,
            "{:?}",
            result.metadata
        );
        assert!(!result.metadata.collection.complete);
        assert_eq!(result.metadata.collection.incomplete_count, Some(0));
        assert_eq!(result.metadata.collection.stage, DeepScanStage::Gpu);
        assert_eq!(result.metadata.process_count, 1);
        assert_eq!(result.gpu.has_gpu, None);
        assert!(result.processes[0].gpu.is_none());
    }

    #[test]
    fn deadline_protocol_rejects_unrequested_duplicate_and_reused_processes() {
        let options = DeepScanOptions {
            pids: vec![41],
            ..DeepScanOptions::default()
        };
        let prefix = protocol_bytes(&process_events(vec![41], 41));
        let mut stream = DeepScanStream::new(&options, 1000);
        stream.consume(&prefix).unwrap();
        let duplicate = protocol_bytes(&[DeepScanWorkerEvent::Record {
            record: Box::new(protocol_record(41)),
            enriched: false,
        }]);
        assert!(stream.consume(&duplicate).is_err());

        let mut stream = DeepScanStream::new(&options, 1000);
        assert!(stream
            .consume(&protocol_bytes(&process_events(vec![41], 42)))
            .is_err());
        assert!(stream.result.processes.is_empty());

        let mut stream = DeepScanStream::new(&options, 1000);
        stream.consume(&prefix).unwrap();
        stream
            .consume(&protocol_bytes(&[
                DeepScanWorkerEvent::Stage {
                    stage: DeepScanStage::Gpu,
                },
                DeepScanWorkerEvent::Gpu {
                    snapshot: Box::default(),
                },
                DeepScanWorkerEvent::Stage {
                    stage: DeepScanStage::GpuEnrichment,
                },
            ]))
            .unwrap();
        let mut reused = protocol_record(41);
        reused.start_id = StartId::from_linux("fixture-boot", 99999, 41);
        reused.gpu = Some(ProcessGpuEvidence::default());
        assert!(stream
            .consume(&protocol_bytes(&[DeepScanWorkerEvent::Record {
                record: Box::new(reused),
                enriched: true
            }]))
            .is_err());
        assert_eq!(stream.result.processes[0].starttime, 12345);
    }

    #[test]
    fn deadline_protocol_requires_a_complete_terminal_record_and_bounds_messages() {
        let options = DeepScanOptions {
            pids: vec![41],
            ..DeepScanOptions::default()
        };
        let bytes = protocol_bytes(&process_events(vec![41], 41));
        let mut stream = DeepScanStream::new(&options, 1000);
        for byte in &bytes {
            stream.consume(std::slice::from_ref(byte)).unwrap();
        }
        stream.consume(b"{\"event\":\"complete\"").unwrap();
        let partial = stream.finish(Instant::now(), true);
        assert_eq!(partial.processes.len(), 1);
        assert!(!partial.metadata.collection.complete);

        let mut stream = DeepScanStream::new(&options, 1000);
        assert!(stream
            .consume(&vec![b' '; WORKER_MESSAGE_LIMIT + 1])
            .is_err());
        assert!(stream.result.metadata.collection.output_truncated);
        assert!(stream.pending.len() <= WORKER_MESSAGE_LIMIT);
    }

    #[test]
    fn deadline_protocol_verifies_terminal_totals_before_declaring_completion() {
        let options = DeepScanOptions {
            pids: vec![41],
            ..DeepScanOptions::default()
        };
        for terminal_count in [2, 1] {
            let mut events = process_events(vec![41], 41);
            let mut enriched = protocol_record(41);
            enriched.gpu = Some(ProcessGpuEvidence::default());
            events.extend([
                DeepScanWorkerEvent::Stage {
                    stage: DeepScanStage::Gpu,
                },
                DeepScanWorkerEvent::Gpu {
                    snapshot: Box::default(),
                },
                DeepScanWorkerEvent::Stage {
                    stage: DeepScanStage::GpuEnrichment,
                },
                DeepScanWorkerEvent::Record {
                    record: Box::new(enriched),
                    enriched: true,
                },
                DeepScanWorkerEvent::Complete {
                    metadata: DeepScanMetadata {
                        started_at: "2026-01-01T00:00:00Z".into(),
                        duration_ms: 5,
                        process_count: terminal_count,
                        skipped_count: 0,
                        warnings: vec![],
                        collection: DeepScanCollection {
                            complete: true,
                            requested_count: Some(1),
                            processed_count: 1,
                            incomplete_count: Some(0),
                            enriched_count: 1,
                            stage: DeepScanStage::Complete,
                            ..DeepScanCollection::default()
                        },
                    },
                },
            ]);
            let mut stream = DeepScanStream::new(&options, 1000);
            let parsed = stream.consume(&protocol_bytes(&events));
            assert_eq!(parsed.is_ok(), terminal_count == 1);
            let result = stream.finish(Instant::now(), parsed.is_ok());
            assert_eq!(result.metadata.collection.complete, terminal_count == 1);
            assert_eq!(result.metadata.process_count, 1);
            assert_eq!(result.metadata.collection.enriched_count, 1);
            assert_eq!(result.metadata.collection.budget_ms, Some(1000));
        }
    }

    #[test]
    fn deadline_explicit_pid_order_preserves_probe_priority() {
        let options = DeepScanOptions {
            pids: vec![300, 100, 300, 200],
            ..DeepScanOptions::default()
        };
        let observed = Mutex::new(None);
        let observer = |event| {
            if let DeepScanWorkerEvent::Inventory { pids } = event {
                *observed.lock().unwrap() = Some(pids);
                Err(DeepScanError::Worker("stop after inventory".into()))
            } else {
                panic!("inventory must precede every probe");
            }
        };
        assert!(matches!(
            deep_scan_observed(&options, Some(&observer)),
            Err(DeepScanError::Worker(_))
        ));
        assert_eq!(observed.into_inner().unwrap().unwrap(), vec![300, 100, 200]);
    }

    #[test]
    fn deadline_cancels_worker_before_invoking_progress_callbacks() {
        struct ConfirmWorkerStopped {
            marker: PathBuf,
            events: Mutex<Vec<ProgressEvent>>,
        }
        impl ProgressEmitter for ConfirmWorkerStopped {
            fn emit(&self, event: ProgressEvent) {
                let pid: u32 = fs::read_to_string(&self.marker)
                    .expect("worker recorded its identity before streaming")
                    .trim()
                    .parse()
                    .unwrap();
                let checked = Instant::now();
                loop {
                    let state = fs::read_to_string(format!("/proc/{pid}/stat"))
                        .ok()
                        .and_then(|contents| parse_proc_stat_content(&contents))
                        .map(|stat| stat.state);
                    if matches!(state, None | Some('Z') | Some('X')) {
                        break;
                    }
                    assert!(
                        checked.elapsed() < Duration::from_secs(1),
                        "a progress callback ran while collection was still active"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                self.events.lock().unwrap().push(event);
            }
        }

        let events = process_events(vec![41], 41);
        let (_directory, executable) = blocked_worker(&events);
        let emitter = Arc::new(ConfirmWorkerStopped {
            marker: executable.with_extension("pid"),
            events: Mutex::new(Vec::new()),
        });
        let options = DeepScanOptions {
            pids: vec![41],
            use_wait_free: false,
            progress: Some(emitter.clone()),
            ..DeepScanOptions::default()
        };
        let result =
            deep_scan_with_budget(&options, Duration::from_millis(750), &executable).unwrap();
        assert!(result.metadata.collection.timed_out);
        assert_eq!(result.metadata.process_count, 1);
        let events = emitter.events.lock().unwrap();
        assert_eq!(
            events.len(),
            3,
            "progress is coalesced to a bounded event set"
        );
        assert_eq!(events[0].event, event_names::DEEP_SCAN_STARTED);
        assert_eq!(events[0].details["wait_free"], serde_json::json!(false));
        assert_eq!(events[1].event, event_names::DEEP_SCAN_PROGRESS);
        assert_eq!(
            serde_json::to_value(&events[1]).unwrap()["progress"]["current"],
            1
        );
        assert_eq!(events[2].event, event_names::DEEP_SCAN_COMPLETE);
        assert_eq!(events[2].details["complete"], serde_json::json!(false));
        assert_eq!(events[2].details["timed_out"], serde_json::json!(true));
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
    fn worker_collects_checkout_context_on_both_collection_paths() {
        use std::process::{Command, Stdio};

        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                // Only an unreaped owned child is signalled; an exited child
                // reaped by try_wait is never addressed again by numeric PID.
                if matches!(self.0.try_wait(), Ok(None)) {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }

        let root = std::env::temp_dir().join(format!(
            "pt-deep-workflow-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let main_gitdir = root.join("main/.git");
        let worktree = root.join("linked");
        let gitdir = main_gitdir.join("worktrees/linked");
        let cwd = worktree.join("src");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(main_gitdir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(gitdir.join("HEAD"), "ref: refs/heads/agent-work\n").unwrap();
        fs::write(gitdir.join("index"), b"owned workflow fixture").unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .unwrap();
        let mut child = OwnedChild(
            Command::new("sleep")
                .arg("60")
                .current_dir(&cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|boot| boot.trim().to_string());

        for use_wait_free in [false, true] {
            assert!(child.0.try_wait().unwrap().is_none());
            let options = DeepScanOptions {
                pids: vec![child.0.id()],
                skip_inaccessible: false,
                include_environ: false,
                use_wait_free,
                progress: None,
            };
            let direct = deep_scan(&options).unwrap();
            assert!(direct
                .processes
                .iter()
                .all(|record| { record.user_intent.is_none() && record.workspace.is_none() }));
            let observer = |_event: DeepScanWorkerEvent| Ok(());
            let scan = deep_scan_observed(&options, Some(&observer)).unwrap();
            let record = scan.processes.first().expect("owned process was scanned");
            let intent = record.user_intent.as_ref().expect("identity-bound context");
            assert_eq!(intent.pid, child.0.id());
            assert!(intent.privacy_mode.repo_activity_collected);
            assert!(!intent.privacy_mode.session_mux_enabled);
            assert!(!intent.privacy_mode.ssh_enabled);
            assert!(intent.evidence.iter().any(|evidence| {
                evidence.signal_type
                    == super::super::user_intent::IntentSignalType::ActiveRepoContext
            }));
            let workspace = record.workspace.as_ref().expect("checkout provenance");
            assert_eq!(workspace.pid, child.0.id());
            assert_eq!(
                workspace.worktree.as_ref().unwrap().effective_path(),
                fs::canonicalize(&worktree).unwrap().to_str().unwrap()
            );
            assert_eq!(
                workspace.head_state,
                Some(pt_common::HeadState::Branch {
                    name: "agent-work".to_string()
                })
            );

            // The optional fields survive the same serialization used by the
            // worker stream; stale numeric-PID joins never acquire context.
            let serialized = serde_json::to_value(record).unwrap();
            assert!(serialized["user_intent"].is_object());
            assert!(serialized["workspace"].is_object());
            let mut stale = record.clone();
            stale.start_id = compute_start_id(&boot_id, record.starttime + 1, record.pid.0);
            let (intent, workspace) = collect_workflow_context(&stale);
            assert!(intent.is_none());
            assert!(workspace.is_none());
        }
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
