//! GPU process detection and device information collection.
//!
//! Detects GPU presence and per-process GPU usage using:
//! - `nvidia-smi` for NVIDIA GPUs (CUDA)
//! - `rocm-smi` for AMD GPUs (ROCm)
//!
//! # Graceful Degradation
//! - All GPU tools are optional; missing tools remain explicitly unknown
//! - Parse failures produce warnings in provenance, never hard errors
//! - One bounded vendor snapshot is collected for an entire deep scan
//! - Vendor PIDs are not assumed to belong to the mounted procfs PID namespace

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::LazyLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

const GPU_COLLECTION_BUDGET: Duration = Duration::from_secs(10);
const GPU_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
static GPU_COLLECTION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from GPU detection operations.
#[derive(Debug, Error)]
pub enum GpuError {
    #[error("GPU tool not found: {0}")]
    ToolNotFound(String),

    #[error("GPU tool execution failed: {0}")]
    ExecutionFailed(String),

    #[error("failed to parse GPU tool output: {0}")]
    ParseError(String),

    #[error("GPU tool timed out")]
    Timeout,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// GPU hardware type / vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuType {
    /// NVIDIA GPU (CUDA capable).
    Nvidia,
    /// AMD GPU (ROCm capable).
    Amd,
    /// No GPU detected.
    #[default]
    None,
}

/// Source of GPU detection data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuDetectionSource {
    /// Data from nvidia-smi.
    NvidiaSmi,
    /// Data from rocm-smi.
    RocmSmi,
    /// No GPU data source available.
    #[default]
    None,
}

/// Provenance for GPU detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GpuProvenance {
    /// Which tool provided the data.
    pub source: GpuDetectionSource,
    /// Non-fatal issues encountered during detection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Whether a query yielded usable observations. Empty data is not a failed query.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuQueryStatus {
    #[default]
    NotCollected,
    Observed,
    Unavailable,
    Failed,
}

/// Information about a single GPU device.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GpuDevice {
    /// Device index (e.g. 0, 1, 2).
    pub index: u32,
    /// Device name (e.g. "NVIDIA A100-SXM4-40GB").
    pub name: String,
    /// GPU UUID if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Total VRAM in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_mib: Option<u64>,
    /// Used VRAM in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_used_mib: Option<u64>,
    /// GPU utilization percentage (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utilization_percent: Option<u32>,
    /// GPU temperature in Celsius.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature_c: Option<u32>,
    /// Driver version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
}

/// Per-process GPU usage information.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessGpuUsage {
    /// Driver-reported process ID, not verified against the mounted procfs namespace.
    pub pid: u32,
    /// GPU index, only when the reported device can be resolved in this snapshot.
    pub gpu_index: Option<u32>,
    /// Reported UUID, retained even when the device is absent from the inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_uuid: Option<String>,
    /// GPU memory used by this process in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_gpu_memory_mib: Option<u64>,
    /// Process type as reported by nvidia-smi (C=Compute, G=Graphics, C+G).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_process_type: Option<String>,
}

/// System-wide GPU information snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GpuSnapshot {
    /// GPU presence in the queried vendor inventory; None means unavailable or
    /// failed observation, and false is scoped to that inventory only.
    #[serde(default)]
    pub has_gpu: Option<bool>,
    /// GPU vendor type.
    pub gpu_type: GpuType,
    /// Detected GPU devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<GpuDevice>,
    /// Vendor-reported compute-process usage, keyed by unverified driver PID.
    /// An absent row does not establish that a process is idle or GPU-free.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub process_usage: HashMap<u32, Vec<ProcessGpuUsage>>,
    /// Total number of GPU-using processes detected.
    pub gpu_process_count: usize,
    /// Device-query coverage, independent of process-query coverage.
    #[serde(default)]
    pub device_status: GpuQueryStatus,
    #[serde(default)]
    pub process_status: GpuQueryStatus,
    /// Collection start time. Device and process queries are sequential snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    /// Time spent collecting the vendor snapshot.
    #[serde(default)]
    pub duration_ms: u64,
    /// Always false for these CLI backends, which can report host PIDs in containers.
    #[serde(default)]
    pub process_pid_namespace_verified: bool,
    /// Provenance tracking.
    pub provenance: GpuProvenance,
}

/// A GPU-related descriptor belonging to a revalidated local process.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GpuDeviceHandle {
    pub fd: u32,
    pub path: String,
    /// Kernel character-device identity, not a vendor index or UUID.
    /// Only per-device handles (not global control interfaces) have a resource key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_key: Option<String>,
}

/// Identity-bound local ownership observations. Vendor PID rows are deliberately
/// kept in `GpuSnapshot` rather than joined by a possibly unrelated numeric PID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ProcessGpuEvidence {
    pub identity_verified: bool,
    /// Positive descriptor observation only; None means unknown, never idle.
    pub has_gpu_handle: Option<bool>,
    pub device_handles: Vec<GpuDeviceHandle>,
    /// No CLI backend used here establishes namespace-safe per-process allocation.
    pub used_gpu_memory_mib: Option<u64>,
    /// Device utilization must never be substituted for per-process utilization.
    pub utilization_percent: Option<u32>,
    pub observed_at: String,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tool availability
// ---------------------------------------------------------------------------

/// Check whether a GPU tool binary is available on the system.
fn tool_available(name: &str) -> bool {
    crate::collect::tool_runner::run_tool(
        "which",
        &[name],
        Some(std::time::Duration::from_secs(1)),
        None,
    )
    .map(|o| o.success() && !o.timed_out && !o.truncated)
    .unwrap_or(false)
}

/// Check if nvidia-smi is available.
pub fn is_nvidia_available() -> bool {
    tool_available("nvidia-smi")
}

/// Check if rocm-smi is available.
pub fn is_rocm_available() -> bool {
    tool_available("rocm-smi")
}

// ---------------------------------------------------------------------------
// nvidia-smi parsing
// ---------------------------------------------------------------------------

/// Run nvidia-smi and collect GPU device information.
fn query_nvidia_devices(deadline: Instant) -> Result<Vec<GpuDevice>, GpuError> {
    let output = run_gpu_tool(
        "nvidia-smi",
        &[
            "--query-gpu=index,name,uuid,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version",
            "--format=csv,noheader,nounits",
        ],
        deadline,
    )?;

    let stdout = output.stdout_str();
    parse_nvidia_device_csv(&stdout)
}

/// Parse nvidia-smi CSV device output.
///
/// Expected format (one row per GPU):
/// `index, name, uuid, memory.total [MiB], memory.used [MiB], utilization.gpu [%], temperature.gpu, driver_version`
pub fn parse_nvidia_device_csv(csv: &str) -> Result<Vec<GpuDevice>, GpuError> {
    let mut devices = Vec::new();
    for line in csv.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() != 8 {
            return Err(GpuError::ParseError(format!(
                "expected 8 CSV fields, got {}",
                fields.len()
            )));
        }
        let device = parse_nvidia_device_fields(&fields)?;
        if devices.iter().any(|previous: &GpuDevice| {
            previous.index == device.index
                || (device.uuid.is_some() && previous.uuid == device.uuid)
        }) {
            return Err(GpuError::ParseError(
                "duplicate GPU identity in device inventory".into(),
            ));
        }
        devices.push(device);
    }
    Ok(devices)
}

fn parse_nvidia_device_fields(fields: &[&str]) -> Result<GpuDevice, GpuError> {
    let index = fields[0]
        .trim()
        .parse::<u32>()
        .map_err(|e| GpuError::ParseError(format!("bad GPU index '{}': {e}", fields[0])))?;

    Ok(GpuDevice {
        index,
        name: fields[1].trim().to_string(),
        uuid: non_empty(fields[2]),
        memory_total_mib: parse_u64_opt(fields[3]),
        memory_used_mib: parse_u64_opt(fields[4]),
        utilization_percent: parse_percent_opt(fields[5]),
        temperature_c: parse_u32_opt(fields[6]),
        driver_version: non_empty(fields[7]),
    })
}

/// Query per-process GPU usage from nvidia-smi.
fn query_nvidia_processes(
    devices: &[GpuDevice],
    deadline: Instant,
) -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let output = run_gpu_tool(
        "nvidia-smi",
        &[
            "--query-compute-apps=pid,gpu_uuid,used_memory",
            "--format=csv,noheader,nounits",
        ],
        deadline,
    )?;

    let stdout = output.stdout_str();
    parse_nvidia_process_csv(&stdout, devices)
}

/// Parse nvidia-smi per-process CSV output.
///
/// Format: `pid, gpu_uuid, used_gpu_memory [MiB]`
///
/// The `devices` slice maps UUIDs to indices. Unknown UUIDs stay unresolved;
/// inventing index zero would incorrectly attribute allocations to another GPU.
pub fn parse_nvidia_process_csv(
    csv: &str,
    devices: &[GpuDevice],
) -> Result<Vec<ProcessGpuUsage>, GpuError> {
    // Build UUID → index lookup
    let uuid_to_idx: HashMap<&str, u32> = devices
        .iter()
        .filter_map(|d| d.uuid.as_deref().map(|u| (u, d.index)))
        .collect();

    let mut usages = Vec::new();
    for line in csv.lines() {
        let line = line.trim();
        if line.is_empty() || line == "No running compute processes found" {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() != 3 {
            return Err(GpuError::ParseError(format!(
                "expected 3 process CSV fields, got {}",
                fields.len()
            )));
        }

        let pid = match fields[0].parse::<u32>() {
            Ok(p) if p > 0 => p,
            _ => return Err(GpuError::ParseError("invalid GPU process PID".into())),
        };

        let gpu_uuid = fields[1].trim();
        let gpu_index = uuid_to_idx.get(gpu_uuid).copied();
        let used_mem = parse_u64_opt(fields[2]);

        usages.push(ProcessGpuUsage {
            pid,
            gpu_index,
            gpu_uuid: non_empty(gpu_uuid),
            used_gpu_memory_mib: used_mem,
            gpu_process_type: Some("Compute".to_string()),
        });
    }
    Ok(usages)
}

// ---------------------------------------------------------------------------
// rocm-smi parsing
// ---------------------------------------------------------------------------

/// Run rocm-smi and collect GPU device information.
fn query_rocm_devices(deadline: Instant) -> Result<Vec<GpuDevice>, GpuError> {
    let output = run_gpu_tool(
        "rocm-smi",
        &[
            "--showid",
            "--showproductname",
            "--showuniqueid",
            "--showdriverversion",
            "--showtemp",
            "--showuse",
            "--showmeminfo",
            "vram",
            "--json",
        ],
        deadline,
    )?;

    let stdout = output.stdout_str();
    parse_rocm_json(&stdout)
}

/// Parse rocm-smi JSON output.
pub fn parse_rocm_json(json_str: &str) -> Result<Vec<GpuDevice>, GpuError> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| GpuError::ParseError(format!("rocm-smi JSON: {e}")))?;

    let mut devices = Vec::new();
    let driver_version = val
        .get("system")
        .and_then(|system| system.get("Driver version"))
        .and_then(|value| value.as_str())
        .and_then(non_empty);
    if let Some(obj) = val.as_object() {
        for (key, card) in obj {
            // Keys look like "card0", "card1", etc.
            static CARD_RE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^card(\d+)$").expect("regex"));
            if let Some(caps) = CARD_RE.captures(key) {
                if !card.is_object() {
                    return Err(GpuError::ParseError("invalid ROCm device record".into()));
                }
                let index = caps[1]
                    .parse::<u32>()
                    .map_err(|_| GpuError::ParseError("invalid ROCm device index".into()))?;
                let name = card
                    .get("Card Series")
                    .or_else(|| card.get("Card series"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("AMD GPU")
                    .to_string();

                let temperature_c = card
                    .get("Temperature (Sensor edge) (C)")
                    .or_else(|| card.get("Temperature"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.trim_end_matches('C').trim().parse::<u32>().ok());

                let utilization_percent = card
                    .get("GPU use (%)")
                    .or_else(|| card.get("GPU Usage"))
                    .and_then(json_u64_opt)
                    .and_then(|value| u32::try_from(value).ok())
                    .filter(|value| *value <= 100);

                let memory_total_mib = card
                    .get("VRAM Total Memory (B)")
                    .and_then(json_u64_opt)
                    .map(|b| b / (1024 * 1024));

                let memory_used_mib = card
                    .get("VRAM Total Used Memory (B)")
                    .and_then(json_u64_opt)
                    .map(|b| b / (1024 * 1024));

                let uuid = card
                    .get("Unique ID")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                devices.push(GpuDevice {
                    index,
                    name,
                    uuid,
                    memory_total_mib,
                    memory_used_mib,
                    utilization_percent,
                    temperature_c,
                    driver_version: driver_version.clone(),
                });
            }
        }
    }

    if !val.is_object()
        || (!val.as_object().is_some_and(|obj| obj.is_empty()) && devices.is_empty())
    {
        return Err(GpuError::ParseError(
            "unrecognized rocm-smi device schema".into(),
        ));
    }
    // Sort by index for deterministic output
    devices.sort_by_key(|d| d.index);
    Ok(devices)
}

/// Parse rocm-smi basic text output (fallback).
///
/// Handles the table format:
/// ```text
/// ========================= ROCm System Management Interface =========================
/// ================================ Concise Info ======================================
/// GPU  Temp  AvgPwr  SCLK  MCLK    Fan  Perf    PwrCap  VRAM%  GPU%
/// 0    42c   45.0W   300Mhz 1200Mhz 0%  auto    250.0W  10%    0%
/// ```
pub fn parse_rocm_text(output: &str) -> Result<Vec<GpuDevice>, GpuError> {
    static ROW_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^\s*(\d+)\s+(\d+)c?\s+").expect("rocm text row regex"));

    let mut devices = Vec::new();
    for caps in ROW_RE.captures_iter(output) {
        let index = caps[1]
            .parse::<u32>()
            .map_err(|_| GpuError::ParseError("invalid ROCm text device index".into()))?;
        let temp = caps[2].parse::<u32>().ok();

        devices.push(GpuDevice {
            index,
            name: format!("AMD GPU {index}"),
            uuid: None,
            memory_total_mib: None,
            memory_used_mib: None,
            utilization_percent: None,
            temperature_c: temp,
            driver_version: None,
        });
    }

    if devices.is_empty() {
        return Err(GpuError::ParseError(
            "no GPU rows found in rocm-smi output".to_string(),
        ));
    }
    Ok(devices)
}

/// Query per-process GPU usage from rocm-smi.
fn query_rocm_processes(deadline: Instant) -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let output = run_gpu_tool("rocm-smi", &["--showpids", "--json"], deadline)?;

    let stdout = output.stdout_str();
    parse_rocm_process_json(&stdout)
}

/// Parse rocm-smi per-process JSON output.
pub fn parse_rocm_process_json(json_str: &str) -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| GpuError::ParseError(format!("rocm-smi process JSON: {e}")))?;

    let mut usages = Vec::new();
    if let Some(obj) = val.as_object() {
        for (key, proc_info) in obj {
            // rocm_smi.py showPids/print2DArray serialize aggregate KFD data as
            // {"system":{"PID123":"name, GPU count, VRAM bytes, SDMA bytes, CU occupancy"}}.
            // GPU count is not a device index. Keep the aggregate as one unresolved
            // allocation instead of duplicating it onto every GPU.
            if key == "system" {
                let procs = proc_info.as_object().ok_or_else(|| {
                    GpuError::ParseError("invalid ROCm system process record".into())
                })?;
                for (pid_key, fields) in procs {
                    let pid = pid_key
                        .strip_prefix("PID")
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid > 0)
                        .ok_or_else(|| {
                            GpuError::ParseError("invalid ROCm system process PID".into())
                        })?;
                    let fields: Vec<_> = fields
                        .as_str()
                        .ok_or_else(|| {
                            GpuError::ParseError("invalid ROCm system process fields".into())
                        })?
                        .split(',')
                        .map(str::trim)
                        .collect();
                    if fields.len() < 5 {
                        return Err(GpuError::ParseError(
                            "incomplete ROCm system process fields".into(),
                        ));
                    }
                    usages.push(ProcessGpuUsage {
                        pid,
                        gpu_index: None,
                        gpu_uuid: None,
                        used_gpu_memory_mib: parse_u64_opt(fields[fields.len() - 3])
                            .map(|bytes| bytes / (1024 * 1024)),
                        gpu_process_type: Some("Compute".into()),
                    });
                }
                continue;
            }
            // Keys may be "card0" etc.
            static CARD_RE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^card(\d+)$").expect("regex"));
            let gpu_index = CARD_RE
                .captures(key)
                .and_then(|c| c[1].parse::<u32>().ok())
                .ok_or_else(|| GpuError::ParseError("unrecognized ROCm process device".into()))?;

            if let Some(procs) = proc_info.as_object() {
                for (pid_str, mem_val) in procs {
                    let pid = match pid_str.parse::<u32>() {
                        Ok(p) if p > 0 => p,
                        _ => return Err(GpuError::ParseError("invalid ROCm process PID".into())),
                    };
                    let mem_bytes = mem_val
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| mem_val.as_u64());
                    let mem_mib = mem_bytes.map(|b| b / (1024 * 1024));

                    usages.push(ProcessGpuUsage {
                        pid,
                        gpu_index: Some(gpu_index),
                        gpu_uuid: None,
                        used_gpu_memory_mib: mem_mib,
                        gpu_process_type: Some("Compute".to_string()),
                    });
                }
            } else {
                return Err(GpuError::ParseError(
                    "unrecognized ROCm process schema".into(),
                ));
            }
        }
    } else {
        return Err(GpuError::ParseError(
            "unrecognized ROCm process schema".into(),
        ));
    }
    Ok(usages)
}

// ---------------------------------------------------------------------------
// High-level API
// ---------------------------------------------------------------------------

/// Collect a system-wide GPU snapshot.
///
/// Tries NVIDIA first, then AMD, within one wall-clock budget. This observes one
/// vendor's visible devices, not a complete inventory of a mixed-vendor host.
/// Missing tools and failed queries remain unknown, with provenance warnings.
pub fn collect_gpu_snapshot() -> GpuSnapshot {
    let started = Instant::now();
    let observed_at = chrono::Utc::now().to_rfc3339();
    let worker_observed_at = observed_at.clone();
    let worker = start_gpu_worker(&GPU_COLLECTION_IN_FLIGHT, move || {
        collect_gpu_snapshot_inner(started, worker_observed_at)
    });
    let (receiver, worker_handle) = match worker {
        Ok(worker) => worker,
        Err(error) => {
            return unavailable_gpu_snapshot(started, observed_at, error);
        }
    };
    // A vendor tool can enter uninterruptible driver I/O. ToolRunner's child.wait()
    // may then remain blocked even after a kill request. Never join that worker on
    // the scan thread; the single in-flight lease prevents repeated scans from
    // accumulating stuck workers. A completed late result is discarded, not cached
    // or attached to a subsequent process incarnation.
    drop(worker_handle);
    let remaining = (started + GPU_COLLECTION_BUDGET).saturating_duration_since(Instant::now());
    receive_gpu_snapshot(&receiver, remaining, started, observed_at)
}

struct GpuCollectionLease(&'static AtomicBool);

impl GpuCollectionLease {
    fn acquire(in_flight: &'static AtomicBool) -> Option<Self> {
        in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(in_flight))
    }
}

impl Drop for GpuCollectionLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn start_gpu_worker(
    in_flight: &'static AtomicBool,
    collect: impl FnOnce() -> GpuSnapshot + Send + 'static,
) -> Result<(Receiver<GpuSnapshot>, JoinHandle<()>), String> {
    let lease = GpuCollectionLease::acquire(in_flight).ok_or_else(|| {
        "Previous GPU collection is still running; skipped another probe and retained unknown GPU evidence".to_string()
    })?;
    let (sender, receiver) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("pt-gpu-probe".into())
        .spawn(move || {
            let _lease = lease;
            let snapshot = collect();
            let _ = sender.send(snapshot);
        })
        .map_err(|error| format!("Cannot start GPU collection worker: {error}"))?;
    Ok((receiver, handle))
}

fn receive_gpu_snapshot(
    receiver: &Receiver<GpuSnapshot>,
    remaining: Duration,
    started: Instant,
    observed_at: String,
) -> GpuSnapshot {
    match receiver.recv_timeout(remaining) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let warning = match error {
                mpsc::RecvTimeoutError::Timeout => "GPU collection deadline exceeded; GPU evidence is unknown and the pending worker will not be duplicated",
                mpsc::RecvTimeoutError::Disconnected => "GPU collection worker stopped without a result; GPU evidence is unknown",
            };
            let mut snapshot = unavailable_gpu_snapshot(started, observed_at, warning.to_owned());
            snapshot.device_status = GpuQueryStatus::Failed;
            snapshot
        }
    }
}

fn unavailable_gpu_snapshot(started: Instant, observed_at: String, warning: String) -> GpuSnapshot {
    GpuSnapshot {
        device_status: GpuQueryStatus::Unavailable,
        observed_at: Some(observed_at),
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        provenance: GpuProvenance {
            source: GpuDetectionSource::None,
            warnings: vec![warning],
        },
        ..Default::default()
    }
}

fn collect_gpu_snapshot_inner(started: Instant, observed_at: String) -> GpuSnapshot {
    let deadline = started + GPU_COLLECTION_BUDGET;
    let mut warnings = Vec::new();
    let mut attempted = false;
    let mut snapshot = None;
    if gpu_tool_available("nvidia-smi", deadline) {
        attempted = true;
        debug!("nvidia-smi available, querying GPU info");
        match collect_nvidia_snapshot(deadline) {
            Ok(snap) => snapshot = Some(snap),
            Err(e) => {
                warn!(error = %e, "nvidia-smi query failed, trying rocm-smi");
                warnings.push(format!("nvidia-smi device query failed: {e}"));
            }
        }
    }

    if snapshot.is_none() && gpu_tool_available("rocm-smi", deadline) {
        attempted = true;
        debug!("rocm-smi available, querying GPU info");
        match collect_rocm_snapshot(deadline) {
            Ok(snap) => snapshot = Some(snap),
            Err(e) => {
                warn!(error = %e, "rocm-smi query failed");
                warnings.push(format!("rocm-smi device query failed: {e}"));
            }
        }
    }

    let mut snapshot = snapshot.unwrap_or_else(|| GpuSnapshot {
        device_status: if attempted {
            GpuQueryStatus::Failed
        } else {
            GpuQueryStatus::Unavailable
        },
        process_status: GpuQueryStatus::NotCollected,
        ..Default::default()
    });
    if !attempted {
        warnings.push("GPU tools unavailable or could not be inspected; GPU presence and activity are unknown".into());
    }
    warnings.append(&mut snapshot.provenance.warnings);
    warnings.push("Vendor PIDs are not verified against the mounted procfs namespace; an absent process row does not prove GPU inactivity".into());
    warnings.push(
        "Utilization is device-wide; per-process utilization and reclaimable VRAM are unknown"
            .into(),
    );
    snapshot.provenance.warnings = warnings;
    snapshot.observed_at = Some(observed_at);
    snapshot.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    snapshot
}

fn collect_nvidia_snapshot(deadline: Instant) -> Result<GpuSnapshot, GpuError> {
    let devices = query_nvidia_devices(deadline)?;
    let processes = query_nvidia_processes(&devices, deadline);
    Ok(snapshot_from_queries(
        GpuType::Nvidia,
        GpuDetectionSource::NvidiaSmi,
        devices,
        processes,
    ))
}

fn collect_rocm_snapshot(deadline: Instant) -> Result<GpuSnapshot, GpuError> {
    let devices = query_rocm_devices(deadline)?;
    let processes = query_rocm_processes(deadline);
    Ok(snapshot_from_queries(
        GpuType::Amd,
        GpuDetectionSource::RocmSmi,
        devices,
        processes,
    ))
}

fn snapshot_from_queries(
    gpu_type: GpuType,
    source: GpuDetectionSource,
    devices: Vec<GpuDevice>,
    processes: Result<Vec<ProcessGpuUsage>, GpuError>,
) -> GpuSnapshot {
    let mut warnings = Vec::new();
    let (processes, process_status) = match processes {
        Ok(processes) => (processes, GpuQueryStatus::Observed),
        Err(error) => {
            warnings.push(format!(
                "GPU process query failed; process allocations are unknown: {error}"
            ));
            (Vec::new(), GpuQueryStatus::Failed)
        }
    };
    let mut process_usage: HashMap<u32, Vec<ProcessGpuUsage>> = HashMap::new();
    for process in processes {
        process_usage.entry(process.pid).or_default().push(process);
    }
    let gpu_process_count = process_usage.len();

    GpuSnapshot {
        has_gpu: Some(!devices.is_empty()),
        gpu_type,
        devices,
        process_usage,
        gpu_process_count,
        provenance: GpuProvenance { source, warnings },
        device_status: GpuQueryStatus::Observed,
        process_status,
        ..Default::default()
    }
}

/// Look up usage by driver-reported PID. This does not establish local identity.
pub fn gpu_usage_for_pid(snapshot: &GpuSnapshot, pid: u32) -> Option<&Vec<ProcessGpuUsage>> {
    snapshot.process_usage.get(&pid)
}

/// Sum a driver-reported PID's allocations only when every value is known.
/// This is neither a local-process identity join nor a reclaimable-memory estimate.
pub fn total_vram_mib_for_pid(snapshot: &GpuSnapshot, pid: u32) -> Option<u64> {
    let usages = snapshot.process_usage.get(&pid)?;
    if usages.is_empty() {
        return None;
    }
    usages.iter().try_fold(0_u64, |total, usage| {
        total.checked_add(usage.used_gpu_memory_mib?)
    })
}

/// Read only GPU-related character descriptors from the mounted procfs. The
/// caller must revalidate process identity after this probe before publishing it.
pub(super) fn collect_gpu_handles(
    pid: u32,
    fd_info: Option<&super::proc_parsers::FdInfo>,
) -> Vec<GpuDeviceHandle> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    gpu_handles_from_fds(fd_info, |fd, expected_path| {
        // O_PATH pins the existing object without opening/initializing a GPU
        // device. Check the pinned path and type together so an FD reused during
        // collection cannot borrow an earlier descriptor's GPU pathname.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(format!("/proc/{pid}/fd/{fd}"))
            .ok()?;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
        if path != std::path::Path::new(expected_path) {
            return None;
        }
        let metadata = file.metadata().ok()?;
        metadata
            .file_type()
            .is_char_device()
            .then_some(metadata.rdev())
    })
}

fn gpu_handles_from_fds(
    fd_info: Option<&super::proc_parsers::FdInfo>,
    mut character_device: impl FnMut(u32, &str) -> Option<u64>,
) -> Vec<GpuDeviceHandle> {
    use super::proc_parsers::FdType;
    let Some(fd_info) = fd_info else {
        return Vec::new();
    };
    let mut handles = Vec::new();
    for file in &fd_info.open_files {
        if file.fd_type != FdType::Device {
            continue;
        }
        let Some(individual_device) = gpu_device_path(&file.path) else {
            continue;
        };
        let Some(device) = character_device(file.fd, &file.path) else {
            continue;
        };
        handles.push(GpuDeviceHandle {
            fd: file.fd,
            path: file.path.clone(),
            resource_key: individual_device.then(|| format!("gpu:char:{device}")),
        });
    }
    handles.sort_by_key(|handle| handle.fd);
    handles
}

/// Some(false) denotes a GPU control interface, not an individual shared GPU.
fn gpu_device_path(path: &str) -> Option<bool> {
    if matches!(
        path,
        "/dev/nvidiactl" | "/dev/nvidia-uvm" | "/dev/nvidia-uvm-tools" | "/dev/kfd"
    ) {
        return Some(false);
    }
    ["/dev/nvidia", "/dev/dri/card", "/dev/dri/renderD"]
        .iter()
        .find_map(|prefix| {
            path.strip_prefix(prefix)
                .filter(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
                .map(|_| true)
        })
}

/// Combine local descriptor facts with a post-probe identity result. Failed or
/// missing identity validation removes every positive ownership observation.
pub(super) fn process_gpu_evidence(
    fd_info: Option<&super::proc_parsers::FdInfo>,
    handles: Vec<GpuDeviceHandle>,
    identity_verified: bool,
    observed_at: &str,
) -> ProcessGpuEvidence {
    let mut evidence = ProcessGpuEvidence {
        identity_verified,
        observed_at: observed_at.to_owned(),
        warnings: vec!["GPU allocation and process utilization remain unknown: vendor PID namespace is unverified".into()],
        ..Default::default()
    };
    if !identity_verified {
        evidence.warnings.push("Process identity changed or could not be revalidated; GPU descriptor observations discarded".into());
        return evidence;
    }
    match fd_info {
        None => evidence
            .warnings
            .push("GPU descriptor inspection unavailable".into()),
        Some(info) if info.truncated => evidence.warnings.push(
            "Descriptor inspection truncated; additional GPU handles may be unobserved".into(),
        ),
        Some(_) => {}
    }
    if !handles.is_empty() {
        evidence.has_gpu_handle = Some(true);
        evidence.device_handles = handles;
    } else {
        evidence.warnings.push(
            "No verified GPU descriptor observed; this does not establish absence or inactivity"
                .into(),
        );
    }
    evidence
}

/// Shared-device evidence is observational only: holding the same device does
/// not prove an application dependency or that another holder would be harmed.
pub(super) fn gpu_resource_evidence(
    owner_pid: u32,
    evidence: &ProcessGpuEvidence,
) -> Vec<pt_common::RawResourceEvidence> {
    use pt_common::{
        RawResourceEvidence, ResourceCollectionMethod, ResourceDetails, ResourceKind, ResourceState,
    };
    if !evidence.identity_verified {
        return Vec::new();
    }
    let mut by_key = std::collections::BTreeMap::new();
    for handle in &evidence.device_handles {
        let Some(key) = &handle.resource_key else {
            continue;
        };
        by_key.entry(key.clone()).or_insert_with(|| RawResourceEvidence {
            kind: ResourceKind::GpuDevice,
            key: key.clone(),
            owner_pid,
            collection_method: ResourceCollectionMethod::ProcFd,
            state: ResourceState::Active,
            details: ResourceDetails::Generic {
                description: format!("Observed open GPU character device {}; compute activity and reclaimable VRAM unknown", handle.path),
            },
            observed_at: evidence.observed_at.clone(),
        });
    }
    by_key.into_values().collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gpu_query_timeout(deadline: Instant, now: Instant) -> Result<Duration, GpuError> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(GPU_QUERY_TIMEOUT))
        .ok_or(GpuError::Timeout)
}

fn validate_gpu_output(output: &super::tool_runner::ToolOutput) -> Result<(), GpuError> {
    if output.timed_out {
        return Err(GpuError::Timeout);
    }
    if output.truncated {
        return Err(GpuError::ParseError(
            "GPU output was truncated; completeness is unknown".into(),
        ));
    }
    if !output.success() {
        return Err(GpuError::ExecutionFailed(format!(
            "{} exited {:?}: {}",
            output.command,
            output.exit_code,
            output.stderr_str()
        )));
    }
    Ok(())
}

fn run_gpu_tool(
    tool: &str,
    args: &[&str],
    deadline: Instant,
) -> Result<super::tool_runner::ToolOutput, GpuError> {
    let timeout = gpu_query_timeout(deadline, Instant::now())?;
    let output = super::tool_runner::run_tool(tool, args, Some(timeout), Some(1024 * 1024))
        .map_err(|error| GpuError::ExecutionFailed(format!("{tool}: {error}")))?;
    validate_gpu_output(&output)?;
    Ok(output)
}

fn gpu_tool_available(tool: &str, deadline: Instant) -> bool {
    run_gpu_tool(
        "which",
        &[tool],
        deadline.min(Instant::now() + Duration::from_secs(1)),
    )
    .is_ok()
}

fn non_empty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "[N/A]" || trimmed == "N/A" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_u64_opt(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

fn parse_u32_opt(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok()
}

fn parse_percent_opt(s: &str) -> Option<u32> {
    parse_u32_opt(s).filter(|value| *value <= 100)
}

fn json_u64_opt(value: &serde_json::Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_str()?
            .trim()
            .trim_end_matches('%')
            .trim()
            .parse()
            .ok()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === nvidia-smi device CSV parsing ===

    #[test]
    fn test_parse_nvidia_device_csv_single_gpu() {
        let csv = "0, NVIDIA A100-SXM4-40GB, GPU-abc-123, 40960, 1024, 45, 55, 535.104.05\n";
        let devices = parse_nvidia_device_csv(csv).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[0].name, "NVIDIA A100-SXM4-40GB");
        assert_eq!(devices[0].uuid.as_deref(), Some("GPU-abc-123"));
        assert_eq!(devices[0].memory_total_mib, Some(40960));
        assert_eq!(devices[0].memory_used_mib, Some(1024));
        assert_eq!(devices[0].utilization_percent, Some(45));
        assert_eq!(devices[0].temperature_c, Some(55));
        assert_eq!(devices[0].driver_version.as_deref(), Some("535.104.05"));
    }

    #[test]
    fn test_parse_nvidia_device_csv_multi_gpu() {
        let csv = "\
0, NVIDIA A100-SXM4-40GB, GPU-aaa, 40960, 512, 10, 42, 535.104.05
1, NVIDIA A100-SXM4-40GB, GPU-bbb, 40960, 2048, 90, 68, 535.104.05
";
        let devices = parse_nvidia_device_csv(csv).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[1].index, 1);
        assert_eq!(devices[1].memory_used_mib, Some(2048));
        assert_eq!(devices[1].utilization_percent, Some(90));
    }

    #[test]
    fn test_parse_nvidia_device_csv_comma_only() {
        // Some nvidia-smi versions use comma without space
        let csv = "0,Tesla T4,GPU-xyz,15360,256,5,38,525.85.12\n";
        let devices = parse_nvidia_device_csv(csv).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Tesla T4");
    }

    #[test]
    fn test_parse_nvidia_device_csv_with_na() {
        let csv = "0, GeForce RTX 3090, [N/A], 24576, 300, 0, 35, 535.54.03\n";
        let devices = parse_nvidia_device_csv(csv).unwrap();
        assert_eq!(devices[0].uuid, None);
    }

    #[test]
    fn test_parse_nvidia_device_csv_empty() {
        let devices = parse_nvidia_device_csv("").unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_parse_nvidia_device_csv_malformed() {
        let csv = "not,enough,fields\n";
        let result = parse_nvidia_device_csv(csv);
        assert!(result.is_err());
    }

    // === nvidia-smi process CSV parsing ===

    #[test]
    fn test_parse_nvidia_process_csv_basic() {
        let devices = vec![
            GpuDevice {
                index: 0,
                name: "A100".into(),
                uuid: Some("GPU-aaa".into()),
                memory_total_mib: None,
                memory_used_mib: None,
                utilization_percent: None,
                temperature_c: None,
                driver_version: None,
            },
            GpuDevice {
                index: 1,
                name: "A100".into(),
                uuid: Some("GPU-bbb".into()),
                memory_total_mib: None,
                memory_used_mib: None,
                utilization_percent: None,
                temperature_c: None,
                driver_version: None,
            },
        ];

        let csv = "12345, GPU-aaa, 4096\n54321, GPU-bbb, 8192\n";
        let usages = parse_nvidia_process_csv(csv, &devices).unwrap();
        assert_eq!(usages.len(), 2);
        assert_eq!(usages[0].pid, 12345);
        assert_eq!(usages[0].gpu_index, Some(0));
        assert_eq!(usages[0].used_gpu_memory_mib, Some(4096));
        assert_eq!(usages[1].pid, 54321);
        assert_eq!(usages[1].gpu_index, Some(1));
        assert_eq!(usages[1].used_gpu_memory_mib, Some(8192));
    }

    #[test]
    fn test_parse_nvidia_process_csv_no_running() {
        let csv = "No running compute processes found\n";
        let usages = parse_nvidia_process_csv(csv, &[]).unwrap();
        assert!(usages.is_empty());
    }

    #[test]
    fn test_parse_nvidia_process_csv_empty() {
        let usages = parse_nvidia_process_csv("", &[]).unwrap();
        assert!(usages.is_empty());
    }

    #[test]
    fn test_parse_nvidia_process_csv_unknown_uuid() {
        let csv = "999, GPU-unknown, 512\n";
        let usages = parse_nvidia_process_csv(csv, &[]).unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].gpu_index, None);
        assert_eq!(usages[0].gpu_uuid.as_deref(), Some("GPU-unknown"));
    }

    // === rocm-smi parsing ===

    #[test]
    fn test_parse_rocm_json_single_card() {
        let json = r#"{
            "card0": {
                "Card Series": "AMD Instinct MI250X",
                "Temperature (Sensor edge) (C)": "42",
                "GPU use (%)": "85",
                "VRAM Total Memory (B)": "68719476736",
                "VRAM Total Used Memory (B)": "17179869184",
                "Unique ID": "0x12345"
            }
        }"#;
        let devices = parse_rocm_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[0].name, "AMD Instinct MI250X");
        assert_eq!(devices[0].temperature_c, Some(42));
        assert_eq!(devices[0].utilization_percent, Some(85));
        assert_eq!(devices[0].memory_total_mib, Some(65536));
        assert_eq!(devices[0].memory_used_mib, Some(16384));
        assert_eq!(devices[0].uuid.as_deref(), Some("0x12345"));
    }

    #[test]
    fn test_parse_rocm_json_multi_card() {
        let json = r#"{
            "card0": {
                "Card Series": "MI250X",
                "Temperature (Sensor edge) (C)": "40",
                "GPU use (%)": "50"
            },
            "card1": {
                "Card Series": "MI250X",
                "Temperature (Sensor edge) (C)": "45",
                "GPU use (%)": "90"
            }
        }"#;
        let devices = parse_rocm_json(json).unwrap();
        assert_eq!(devices.len(), 2);
        // Sorted by index
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[1].index, 1);
    }

    #[test]
    fn test_parse_rocm_json_invalid() {
        let result = parse_rocm_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rocm_text_basic() {
        let output = r#"
========================= ROCm System Management Interface =========================
================================ Concise Info ======================================
GPU  Temp  AvgPwr  SCLK     MCLK     Fan  Perf    PwrCap  VRAM%  GPU%
0    42c   45.0W   300Mhz   1200Mhz  0%   auto    250.0W  10%    0%
1    55c   120.0W  1500Mhz  1200Mhz  30%  auto    250.0W  75%    95%
========================= End of ROCm SMI Log ======================================
"#;
        let devices = parse_rocm_text(output).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[0].temperature_c, Some(42));
        assert_eq!(devices[1].index, 1);
        assert_eq!(devices[1].temperature_c, Some(55));
    }

    #[test]
    fn test_parse_rocm_text_empty() {
        let result = parse_rocm_text("No GPUs found\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rocm_process_json_basic() {
        let json = r#"{
            "card0": {
                "12345": "4294967296",
                "67890": "2147483648"
            }
        }"#;
        let usages = parse_rocm_process_json(json).unwrap();
        assert_eq!(usages.len(), 2);
        // PIDs may come in any order
        let pids: Vec<u32> = usages.iter().map(|u| u.pid).collect();
        assert!(pids.contains(&12345));
        assert!(pids.contains(&67890));
        // 4294967296 bytes = 4096 MiB
        let p1 = usages.iter().find(|u| u.pid == 12345).unwrap();
        assert_eq!(p1.used_gpu_memory_mib, Some(4096));
        assert_eq!(p1.gpu_index, Some(0));
    }

    #[test]
    fn test_parse_rocm_process_json_empty() {
        let json = "{}";
        let usages = parse_rocm_process_json(json).unwrap();
        assert!(usages.is_empty());
    }

    // === Snapshot helpers ===

    #[test]
    fn test_gpu_usage_for_pid() {
        let mut process_usage = HashMap::new();
        process_usage.insert(
            100,
            vec![ProcessGpuUsage {
                pid: 100,
                gpu_index: Some(0),
                gpu_uuid: None,
                used_gpu_memory_mib: Some(2048),
                gpu_process_type: None,
            }],
        );
        let snap = GpuSnapshot {
            has_gpu: Some(true),
            gpu_type: GpuType::Nvidia,
            process_usage,
            gpu_process_count: 1,
            ..Default::default()
        };
        assert!(gpu_usage_for_pid(&snap, 100).is_some());
        assert!(gpu_usage_for_pid(&snap, 999).is_none());
    }

    #[test]
    fn test_total_vram_mib_for_pid() {
        let mut process_usage = HashMap::new();
        process_usage.insert(
            42,
            vec![
                ProcessGpuUsage {
                    pid: 42,
                    gpu_index: Some(0),
                    gpu_uuid: None,
                    used_gpu_memory_mib: Some(1024),
                    gpu_process_type: None,
                },
                ProcessGpuUsage {
                    pid: 42,
                    gpu_index: Some(1),
                    gpu_uuid: None,
                    used_gpu_memory_mib: Some(2048),
                    gpu_process_type: None,
                },
            ],
        );
        let snap = GpuSnapshot {
            has_gpu: Some(true),
            gpu_type: GpuType::Nvidia,
            process_usage,
            gpu_process_count: 1,
            ..Default::default()
        };
        assert_eq!(total_vram_mib_for_pid(&snap, 42), Some(3072));
        assert_eq!(total_vram_mib_for_pid(&snap, 999), None);
    }

    // === Default / serialization ===

    #[test]
    fn test_gpu_snapshot_default() {
        let snap = GpuSnapshot::default();
        assert_eq!(snap.has_gpu, None);
        assert_eq!(snap.gpu_type, GpuType::None);
        assert!(snap.devices.is_empty());
        assert!(snap.process_usage.is_empty());
        assert_eq!(snap.gpu_process_count, 0);
    }

    #[test]
    fn test_gpu_snapshot_serde_roundtrip() {
        let mut process_usage = HashMap::new();
        process_usage.insert(
            1,
            vec![ProcessGpuUsage {
                pid: 1,
                gpu_index: Some(0),
                gpu_uuid: None,
                used_gpu_memory_mib: Some(512),
                gpu_process_type: Some("C".into()),
            }],
        );
        let snap = GpuSnapshot {
            has_gpu: Some(true),
            gpu_type: GpuType::Nvidia,
            devices: vec![GpuDevice {
                index: 0,
                name: "RTX 4090".into(),
                uuid: Some("GPU-xyz".into()),
                memory_total_mib: Some(24576),
                memory_used_mib: Some(512),
                utilization_percent: Some(30),
                temperature_c: Some(50),
                driver_version: Some("535.0".into()),
            }],
            process_usage,
            gpu_process_count: 1,
            provenance: GpuProvenance {
                source: GpuDetectionSource::NvidiaSmi,
                warnings: Vec::new(),
            },
            ..Default::default()
        };

        let json = serde_json::to_string(&snap).unwrap();
        let restored: GpuSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.has_gpu, Some(true));
        assert_eq!(restored.gpu_type, GpuType::Nvidia);
        assert_eq!(restored.devices.len(), 1);
        assert_eq!(restored.devices[0].name, "RTX 4090");
        assert_eq!(restored.gpu_process_count, 1);
    }

    #[test]
    fn test_gpu_type_serde() {
        assert_eq!(
            serde_json::to_string(&GpuType::Nvidia).unwrap(),
            "\"nvidia\""
        );
        assert_eq!(serde_json::to_string(&GpuType::Amd).unwrap(), "\"amd\"");
        assert_eq!(serde_json::to_string(&GpuType::None).unwrap(), "\"none\"");
    }

    #[test]
    fn test_gpu_detection_source_serde() {
        assert_eq!(
            serde_json::to_string(&GpuDetectionSource::NvidiaSmi).unwrap(),
            "\"nvidia_smi\""
        );
        assert_eq!(
            serde_json::to_string(&GpuDetectionSource::RocmSmi).unwrap(),
            "\"rocm_smi\""
        );
    }

    #[test]
    fn test_non_empty_helper() {
        assert_eq!(non_empty("hello"), Some("hello".into()));
        assert_eq!(non_empty("  hello  "), Some("hello".into()));
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("   "), None);
        assert_eq!(non_empty("[N/A]"), None);
        assert_eq!(non_empty("N/A"), None);
    }

    #[test]
    fn test_parse_u64_opt_helper() {
        assert_eq!(parse_u64_opt("1024"), Some(1024));
        assert_eq!(parse_u64_opt(" 2048 "), Some(2048));
        assert_eq!(parse_u64_opt("abc"), None);
        assert_eq!(parse_u64_opt(""), None);
    }

    #[test]
    fn test_parse_u32_opt_helper() {
        assert_eq!(parse_u32_opt("42"), Some(42));
        assert_eq!(parse_u32_opt("not_a_number"), None);
    }

    // === Error types ===

    #[test]
    fn test_gpu_error_display() {
        let e = GpuError::ToolNotFound("nvidia-smi".into());
        assert!(e.to_string().contains("nvidia-smi"));

        let e = GpuError::ParseError("bad format".into());
        assert!(e.to_string().contains("bad format"));
    }

    #[test]
    fn gpu_regression_vendor_queries_keep_multi_device_identity() {
        let devices = parse_nvidia_device_csv(
            "3, A100, GPU-first, 40960, 256, 90, 55, 535.0\n7, A100, GPU-second, 40960, 512, 0, 40, 535.0\n"
        ).unwrap();
        let rows =
            parse_nvidia_process_csv("42, GPU-second, 512\n42, MIG-unlisted, N/A\n", &devices)
                .unwrap();
        assert_eq!(rows[0].gpu_index, Some(7));
        assert_eq!(rows[1].gpu_index, None);
        assert_eq!(rows[1].gpu_uuid.as_deref(), Some("MIG-unlisted"));
        let snapshot = snapshot_from_queries(
            GpuType::Nvidia,
            GpuDetectionSource::NvidiaSmi,
            devices,
            Ok(rows),
        );
        assert_eq!(snapshot.process_status, GpuQueryStatus::Observed);
        assert!(!snapshot.process_pid_namespace_verified);
        assert_eq!(total_vram_mib_for_pid(&snapshot, 42), None);
    }

    #[test]
    fn gpu_regression_failed_process_query_is_not_empty_success() {
        let devices =
            parse_nvidia_device_csv("0, A100, GPU-first, 40960, 256, 90, 55, 535.0\n").unwrap();
        let failed = snapshot_from_queries(
            GpuType::Nvidia,
            GpuDetectionSource::NvidiaSmi,
            devices.clone(),
            Err(GpuError::Timeout),
        );
        assert_eq!(failed.has_gpu, Some(true));
        assert_eq!(failed.device_status, GpuQueryStatus::Observed);
        assert_eq!(failed.process_status, GpuQueryStatus::Failed);
        assert!(!failed.provenance.warnings.is_empty());
        assert_eq!(total_vram_mib_for_pid(&failed, 42), None);
        let empty = snapshot_from_queries(
            GpuType::Nvidia,
            GpuDetectionSource::NvidiaSmi,
            devices,
            Ok(Vec::new()),
        );
        assert_eq!(empty.process_status, GpuQueryStatus::Observed);
        assert!(empty.process_usage.is_empty());
        // Even an observed empty compute list cannot prove a specific process idle.
        assert_eq!(total_vram_mib_for_pid(&empty, 42), None);
    }

    #[test]
    fn gpu_regression_vram_sum_requires_complete_nonoverflowing_values() {
        for (values, expected) in [
            (vec![None], None),
            (vec![Some(100), None], None),
            (vec![Some(u64::MAX), Some(1)], None),
            (vec![Some(0), Some(0)], Some(0)),
            (vec![Some(100), Some(200)], Some(300)),
            (vec![], None),
        ] {
            let usages = values
                .into_iter()
                .enumerate()
                .map(|(index, memory)| ProcessGpuUsage {
                    pid: 42,
                    gpu_index: Some(index as u32),
                    gpu_uuid: None,
                    used_gpu_memory_mib: memory,
                    gpu_process_type: Some("Compute".into()),
                })
                .collect();
            let mut snapshot = GpuSnapshot::default();
            snapshot.process_usage.insert(42, usages);
            assert_eq!(total_vram_mib_for_pid(&snapshot, 42), expected);
        }
    }

    #[test]
    fn gpu_regression_malformed_queries_and_duplicate_devices_fail_closed() {
        for text in [
            "42, GPU-x",
            "not-a-pid, GPU-x, 512",
            "0, GPU-x, 512",
            "ERROR: driver unavailable",
        ] {
            assert!(parse_nvidia_process_csv(text, &[]).is_err(), "{text}");
        }
        assert!(parse_nvidia_device_csv(
            "0, A100, GPU-x, 1024, 0, 0, 30, 1\n1, A100, GPU-x, 1024, 0, 0, 30, 1\n"
        )
        .is_err());
        assert!(parse_rocm_process_json(r#"{"unexpected":{"42":1024}}"#).is_err());
        assert!(parse_rocm_process_json("[]").is_err());
        assert!(parse_rocm_json(r#"{"error":"permission denied"}"#).is_err());
        let devices = parse_nvidia_device_csv("0, A100, GPU-x, 1024, 0, 101, 30, 1\n").unwrap();
        assert_eq!(devices[0].utilization_percent, None);
    }

    #[test]
    fn gpu_regression_rocm_supported_process_schema_keeps_aggregate_unassigned() {
        // Shape emitted by upstream rocm_smi.py showPids + print2DArray;
        // process-name spaces become commas, so numeric fields are read from the end.
        let usages = parse_rocm_process_json(
            r#"{"system": {
            "PID42": "python, training, job, 2, 4294967296, 0, 87",
            "PID43": "worker, 1, unknown, unknown, unknown"
        }}"#,
        )
        .unwrap();
        let known = usages.iter().find(|usage| usage.pid == 42).unwrap();
        assert_eq!(known.used_gpu_memory_mib, Some(4096));
        assert_eq!(known.gpu_index, None); // 2 is a GPU count, never GPU index 2.
        assert_eq!(known.gpu_uuid, None);
        assert_eq!(
            usages
                .iter()
                .find(|usage| usage.pid == 43)
                .unwrap()
                .used_gpu_memory_mib,
            None
        );
    }

    #[test]
    fn gpu_regression_rocm_numeric_fields_and_driver_metadata() {
        let devices = parse_rocm_json(r#"{
            "card2":{"GPU use (%)": 91,"VRAM Total Memory (B)":1073741824,"VRAM Total Used Memory (B)":"1048576"},
            "system":{"Driver version":"6.8.0"}
        }"#).unwrap();
        assert_eq!(devices[0].index, 2);
        assert_eq!(devices[0].utilization_percent, Some(91));
        assert_eq!(devices[0].memory_total_mib, Some(1024));
        assert_eq!(devices[0].memory_used_mib, Some(1));
        assert_eq!(devices[0].driver_version.as_deref(), Some("6.8.0"));
    }

    #[test]
    fn gpu_regression_timeout_and_truncated_success_are_rejected() {
        let mut output = super::super::tool_runner::ToolOutput {
            command: "nvidia-smi".into(),
            args: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: Some(0),
            truncated: false,
            duration: Duration::ZERO,
            timed_out: false,
        };
        assert!(validate_gpu_output(&output).is_ok());
        output.truncated = true;
        assert!(validate_gpu_output(&output).is_err());
        output.truncated = false;
        output.timed_out = true;
        assert!(matches!(
            validate_gpu_output(&output),
            Err(GpuError::Timeout)
        ));
        output.timed_out = false;
        output.exit_code = Some(1);
        assert!(validate_gpu_output(&output).is_err());
    }

    #[test]
    fn gpu_regression_query_budget_is_deterministic_and_capped() {
        let now = Instant::now();
        assert_eq!(
            gpu_query_timeout(now + GPU_COLLECTION_BUDGET, now).unwrap(),
            GPU_QUERY_TIMEOUT
        );
        assert_eq!(
            gpu_query_timeout(now + Duration::from_millis(10), now).unwrap(),
            Duration::from_millis(10)
        );
        assert!(matches!(
            gpu_query_timeout(now, now),
            Err(GpuError::Timeout)
        ));
        assert!(matches!(
            gpu_query_timeout(now, now + Duration::from_millis(1)),
            Err(GpuError::Timeout)
        ));
    }

    #[test]
    fn gpu_regression_outer_deadline_returns_unknown_without_duplicate_workers() {
        static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
        let (release, wait_for_release) = mpsc::channel();
        let (receiver, worker) = start_gpu_worker(&IN_FLIGHT, move || {
            wait_for_release.recv().unwrap();
            GpuSnapshot::default()
        })
        .unwrap();
        let snapshot = receive_gpu_snapshot(
            &receiver,
            Duration::ZERO,
            Instant::now(),
            "2026-01-01T00:00:00Z".into(),
        );
        let pending = IN_FLIGHT.load(Ordering::Acquire);
        let second = start_gpu_worker(&IN_FLIGHT, GpuSnapshot::default);
        // Release and join the injected worker before any assertions: no test
        // leaves a blocked worker behind, even if the behavior regresses.
        release.send(()).unwrap();
        worker.join().unwrap();
        let second_rejected = match second {
            Err(_) => true,
            Ok((_, worker)) => {
                worker.join().unwrap();
                false
            }
        };
        assert!(pending);
        assert!(second_rejected);
        assert!(!IN_FLIGHT.load(Ordering::Acquire));
        assert_eq!(snapshot.has_gpu, None);
        assert_eq!(snapshot.device_status, GpuQueryStatus::Failed);
        assert_eq!(snapshot.process_status, GpuQueryStatus::NotCollected);
        assert!(snapshot.provenance.warnings[0].contains("deadline exceeded"));
    }

    #[test]
    fn gpu_regression_worker_lease_releases_on_success_and_unwind() {
        static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
        let (receiver, worker) =
            start_gpu_worker(&IN_FLIGHT, || panic!("injected GPU parser panic")).unwrap();
        let failed = worker.join().is_err();
        let snapshot = receive_gpu_snapshot(
            &receiver,
            Duration::ZERO,
            Instant::now(),
            "2026-01-01T00:00:00Z".into(),
        );
        assert!(failed);
        assert!(!IN_FLIGHT.load(Ordering::Acquire));
        assert_eq!(snapshot.has_gpu, None);
        assert!(snapshot.provenance.warnings[0].contains("without a result"));

        let (receiver, worker) = start_gpu_worker(&IN_FLIGHT, || GpuSnapshot {
            has_gpu: Some(false),
            device_status: GpuQueryStatus::Observed,
            ..Default::default()
        })
        .unwrap();
        worker.join().unwrap();
        let snapshot = receive_gpu_snapshot(
            &receiver,
            Duration::ZERO,
            Instant::now(),
            "2026-01-01T00:00:00Z".into(),
        );
        assert_eq!(snapshot.has_gpu, Some(false));
        assert_eq!(snapshot.device_status, GpuQueryStatus::Observed);
        assert!(!IN_FLIGHT.load(Ordering::Acquire));
    }

    fn gpu_fixture_fds() -> super::super::proc_parsers::FdInfo {
        use super::super::proc_parsers::{FdInfo, FdType, OpenFile, OpenMode};
        FdInfo {
            open_files: [
                "/dev/nvidia2",
                "/dev/nvidia2",
                "/dev/nvidiactl",
                "/dev/kfd",
                "/dev/null",
                "/dev/nvidia2-fake",
            ]
            .into_iter()
            .enumerate()
            .map(|(index, path)| OpenFile {
                fd: index as u32 + 3,
                path: path.into(),
                fd_type: FdType::Device,
                mode: OpenMode::default(),
            })
            .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn gpu_regression_local_handles_require_verified_characters_and_identity() {
        let info = gpu_fixture_fds();
        let mut inspected = Vec::new();
        let handles = gpu_handles_from_fds(Some(&info), |fd, _| {
            inspected.push(fd);
            Some(if fd <= 4 { 195 * 256 + 2 } else { 123 })
        });
        assert_eq!(inspected, vec![3, 4, 5, 6]); // Unrelated descriptors never probed.
        assert_eq!(handles.len(), 4);
        assert!(handles[2].resource_key.is_none()); // Global control nodes aren't one GPU.
        assert!(handles[3].resource_key.is_none());
        let evidence =
            process_gpu_evidence(Some(&info), handles.clone(), true, "2026-01-01T00:00:00Z");
        assert_eq!(evidence.has_gpu_handle, Some(true));
        assert_eq!(evidence.used_gpu_memory_mib, None);
        assert_eq!(evidence.utilization_percent, None);
        let resources = gpu_resource_evidence(42, &evidence);
        assert_eq!(resources.len(), 1); // Duplicate descriptors don't duplicate a device.
        assert_eq!(resources[0].owner_pid, 42);
        assert_eq!(resources[0].kind, pt_common::ResourceKind::GpuDevice);
        let stale = process_gpu_evidence(Some(&info), handles, false, "2026-01-01T00:00:00Z");
        assert_eq!(stale.has_gpu_handle, None);
        assert!(stale.device_handles.is_empty());
        assert!(gpu_resource_evidence(42, &stale).is_empty());
        assert!(gpu_handles_from_fds(Some(&info), |_, _| None).is_empty());
    }

    #[test]
    fn gpu_regression_missing_or_truncated_local_evidence_never_means_idle() {
        for info in [
            None,
            Some(super::super::proc_parsers::FdInfo::default()),
            Some(super::super::proc_parsers::FdInfo {
                truncated: true,
                ..Default::default()
            }),
        ] {
            let evidence =
                process_gpu_evidence(info.as_ref(), Vec::new(), true, "2026-01-01T00:00:00Z");
            let json = serde_json::to_value(&evidence).unwrap();
            assert!(json["has_gpu_handle"].is_null());
            assert!(json["used_gpu_memory_mib"].is_null());
            assert!(json["utilization_percent"].is_null());
            assert!(!evidence.warnings.is_empty());
        }
    }

    // === No-mock integration tests ===

    #[test]
    fn test_nomock_collect_gpu_snapshot_no_panic() {
        crate::test_log!(INFO, "GPU snapshot collection test starting");

        let snap = collect_gpu_snapshot();

        crate::test_log!(
            INFO,
            "GPU snapshot result",
            has_gpu = snap.has_gpu,
            gpu_type = format!("{:?}", snap.gpu_type).as_str(),
            device_count = snap.devices.len(),
            process_count = snap.gpu_process_count
        );

        // Structural invariants
        if snap.has_gpu == Some(true) {
            assert!(
                !snap.devices.is_empty(),
                "has_gpu=true but no devices listed"
            );
            assert!(
                snap.provenance.source != GpuDetectionSource::None,
                "has_gpu=true but source is None"
            );
        }
    }

    #[test]
    fn test_nomock_tool_availability_consistent() {
        crate::test_log!(INFO, "GPU tool availability test");

        let nvidia = is_nvidia_available();
        let rocm = is_rocm_available();

        crate::test_log!(INFO, "GPU tools", nvidia_smi = nvidia, rocm_smi = rocm);

        // A binary can be installed without a usable driver or accessible GPU.
        // Only a successful inventory can establish observed device presence.
        let snap = collect_gpu_snapshot();
        if snap.device_status == GpuQueryStatus::Observed {
            assert_eq!(snap.has_gpu, Some(!snap.devices.is_empty()));
        } else {
            assert_eq!(snap.has_gpu, None);
        }
        // Note: if both are available, NVIDIA takes precedence
    }
}
