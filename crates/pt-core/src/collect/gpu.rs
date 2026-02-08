//! GPU process detection and device information collection.
//!
//! Detects GPU presence and per-process GPU usage using:
//! - `nvidia-smi` for NVIDIA GPUs (CUDA)
//! - `rocm-smi` for AMD GPUs (ROCm)
//!
//! # Graceful Degradation
//! - All GPU tools are optional; missing tools are silently skipped
//! - Parse failures produce warnings in provenance, never hard errors
//! - Query results are cached to avoid hammering expensive GPU tools

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::LazyLock;
use thiserror::Error;
use tracing::{debug, trace, warn};

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
    /// Process ID.
    pub pid: u32,
    /// GPU device index this process is using.
    pub gpu_index: u32,
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
    /// Whether any GPU was detected.
    pub has_gpu: bool,
    /// GPU vendor type.
    pub gpu_type: GpuType,
    /// Detected GPU devices.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<GpuDevice>,
    /// Per-process GPU usage (keyed by PID).
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub process_usage: HashMap<u32, Vec<ProcessGpuUsage>>,
    /// Total number of GPU-using processes detected.
    pub gpu_process_count: usize,
    /// Provenance tracking.
    pub provenance: GpuProvenance,
}

// ---------------------------------------------------------------------------
// Tool availability
// ---------------------------------------------------------------------------

/// Check whether a GPU tool binary is available on the system.
fn tool_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
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
fn query_nvidia_devices() -> Result<Vec<GpuDevice>, GpuError> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,uuid,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(|e| GpuError::ExecutionFailed(format!("nvidia-smi device query: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpuError::ExecutionFailed(format!(
            "nvidia-smi exited {}: {}",
            output.status, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
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
        let fields: Vec<&str> = line.split(", ").collect();
        if fields.len() < 8 {
            // Try comma-only split (some nvidia-smi versions)
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.len() < 8 {
                return Err(GpuError::ParseError(format!(
                    "expected 8 CSV fields, got {}: {line}",
                    fields.len()
                )));
            }
            devices.push(parse_nvidia_device_fields(&fields)?);
            continue;
        }
        devices.push(parse_nvidia_device_fields(&fields)?);
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
        utilization_percent: parse_u32_opt(fields[5]),
        temperature_c: parse_u32_opt(fields[6]),
        driver_version: non_empty(fields[7]),
    })
}

/// Query per-process GPU usage from nvidia-smi.
fn query_nvidia_processes() -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,gpu_uuid,used_memory",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(|e| GpuError::ExecutionFailed(format!("nvidia-smi process query: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpuError::ExecutionFailed(format!(
            "nvidia-smi process query exited {}: {}",
            output.status, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nvidia_process_csv(&stdout, &[])
}

/// Parse nvidia-smi per-process CSV output.
///
/// Format: `pid, gpu_uuid, used_gpu_memory [MiB]`
///
/// The `devices` slice is used to map GPU UUIDs to device indices. If empty,
/// GPU index defaults to 0.
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
        if line.is_empty() || line.starts_with("No running") {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 3 {
            continue; // skip malformed lines
        }

        let pid = match fields[0].parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let gpu_uuid = fields[1].trim();
        let gpu_index = uuid_to_idx.get(gpu_uuid).copied().unwrap_or(0);
        let used_mem = parse_u64_opt(fields[2]);

        usages.push(ProcessGpuUsage {
            pid,
            gpu_index,
            used_gpu_memory_mib: used_mem,
            gpu_process_type: None,
        });
    }
    Ok(usages)
}

// ---------------------------------------------------------------------------
// rocm-smi parsing
// ---------------------------------------------------------------------------

/// Run rocm-smi and collect GPU device information.
fn query_rocm_devices() -> Result<Vec<GpuDevice>, GpuError> {
    let output = Command::new("rocm-smi")
        .args(["--showid", "--showtemp", "--showuse", "--showmeminfo", "vram", "--json"])
        .output()
        .map_err(|e| GpuError::ExecutionFailed(format!("rocm-smi: {e}")))?;

    if !output.status.success() {
        // rocm-smi without --json for older versions
        return query_rocm_devices_text();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rocm_json(&stdout)
}

/// Fallback: parse rocm-smi text output for older versions.
fn query_rocm_devices_text() -> Result<Vec<GpuDevice>, GpuError> {
    let output = Command::new("rocm-smi")
        .output()
        .map_err(|e| GpuError::ExecutionFailed(format!("rocm-smi text fallback: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rocm_text(&stdout)
}

/// Parse rocm-smi JSON output.
pub fn parse_rocm_json(json_str: &str) -> Result<Vec<GpuDevice>, GpuError> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| GpuError::ParseError(format!("rocm-smi JSON: {e}")))?;

    let mut devices = Vec::new();
    if let Some(obj) = val.as_object() {
        for (key, card) in obj {
            // Keys look like "card0", "card1", etc.
            static CARD_RE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^card(\d+)$").expect("regex"));
            if let Some(caps) = CARD_RE.captures(key) {
                let index = caps[1].parse::<u32>().unwrap_or(0);
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
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.trim_end_matches('%').trim().parse::<u32>().ok());

                let memory_total_mib = card
                    .get("VRAM Total Memory (B)")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|b| b / (1024 * 1024));

                let memory_used_mib = card
                    .get("VRAM Total Used Memory (B)")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
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
                    driver_version: None,
                });
            }
        }
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
    static ROW_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?m)^\s*(\d+)\s+(\d+)c?\s+").expect("rocm text row regex")
    });

    let mut devices = Vec::new();
    for caps in ROW_RE.captures_iter(output) {
        let index = caps[1].parse::<u32>().unwrap_or(0);
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
fn query_rocm_processes() -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let output = Command::new("rocm-smi")
        .args(["--showpidgpumem", "--json"])
        .output()
        .map_err(|e| GpuError::ExecutionFailed(format!("rocm-smi process query: {e}")))?;

    if !output.status.success() {
        // Older rocm-smi may not support this
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rocm_process_json(&stdout)
}

/// Parse rocm-smi per-process JSON output.
pub fn parse_rocm_process_json(json_str: &str) -> Result<Vec<ProcessGpuUsage>, GpuError> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| GpuError::ParseError(format!("rocm-smi process JSON: {e}")))?;

    let mut usages = Vec::new();
    if let Some(obj) = val.as_object() {
        for (key, proc_info) in obj {
            // Keys may be "card0" etc.
            static CARD_RE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"card(\d+)").expect("regex"));
            let gpu_index = CARD_RE
                .captures(key)
                .and_then(|c| c[1].parse::<u32>().ok())
                .unwrap_or(0);

            if let Some(procs) = proc_info.as_object() {
                for (pid_str, mem_val) in procs {
                    let pid = match pid_str.parse::<u32>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let mem_bytes = mem_val
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| mem_val.as_u64());
                    let mem_mib = mem_bytes.map(|b| b / (1024 * 1024));

                    usages.push(ProcessGpuUsage {
                        pid,
                        gpu_index,
                        used_gpu_memory_mib: mem_mib,
                        gpu_process_type: Some("Compute".to_string()),
                    });
                }
            }
        }
    }
    Ok(usages)
}

// ---------------------------------------------------------------------------
// High-level API
// ---------------------------------------------------------------------------

/// Collect a system-wide GPU snapshot.
///
/// Tries NVIDIA first, then AMD. Returns a default (no-GPU) snapshot if
/// neither tool is available.
pub fn collect_gpu_snapshot() -> GpuSnapshot {
    // Try NVIDIA
    if is_nvidia_available() {
        debug!("nvidia-smi available, querying GPU info");
        match collect_nvidia_snapshot() {
            Ok(snap) => return snap,
            Err(e) => {
                warn!(error = %e, "nvidia-smi query failed, trying rocm-smi");
            }
        }
    }

    // Try AMD
    if is_rocm_available() {
        debug!("rocm-smi available, querying GPU info");
        match collect_rocm_snapshot() {
            Ok(snap) => return snap,
            Err(e) => {
                warn!(error = %e, "rocm-smi query failed");
                return GpuSnapshot {
                    provenance: GpuProvenance {
                        source: GpuDetectionSource::RocmSmi,
                        warnings: vec![format!("rocm-smi failed: {e}")],
                    },
                    ..Default::default()
                };
            }
        }
    }

    trace!("no GPU tools available");
    GpuSnapshot::default()
}

fn collect_nvidia_snapshot() -> Result<GpuSnapshot, GpuError> {
    let devices = query_nvidia_devices()?;
    let processes = query_nvidia_processes().unwrap_or_default();

    let mut process_usage: HashMap<u32, Vec<ProcessGpuUsage>> = HashMap::new();
    for p in &processes {
        process_usage.entry(p.pid).or_default().push(p.clone());
    }
    let gpu_process_count = process_usage.len();

    Ok(GpuSnapshot {
        has_gpu: true,
        gpu_type: GpuType::Nvidia,
        devices,
        process_usage,
        gpu_process_count,
        provenance: GpuProvenance {
            source: GpuDetectionSource::NvidiaSmi,
            warnings: Vec::new(),
        },
    })
}

fn collect_rocm_snapshot() -> Result<GpuSnapshot, GpuError> {
    let devices = query_rocm_devices()?;
    let processes = query_rocm_processes().unwrap_or_default();

    let mut process_usage: HashMap<u32, Vec<ProcessGpuUsage>> = HashMap::new();
    for p in &processes {
        process_usage.entry(p.pid).or_default().push(p.clone());
    }
    let gpu_process_count = process_usage.len();

    Ok(GpuSnapshot {
        has_gpu: true,
        gpu_type: GpuType::Amd,
        devices,
        process_usage,
        gpu_process_count,
        provenance: GpuProvenance {
            source: GpuDetectionSource::RocmSmi,
            warnings: Vec::new(),
        },
    })
}

/// Look up GPU usage for a specific PID from a snapshot.
pub fn gpu_usage_for_pid(snapshot: &GpuSnapshot, pid: u32) -> Option<&Vec<ProcessGpuUsage>> {
    snapshot.process_usage.get(&pid)
}

/// Compute total VRAM used by a PID across all GPUs.
pub fn total_vram_mib_for_pid(snapshot: &GpuSnapshot, pid: u32) -> Option<u64> {
    snapshot.process_usage.get(&pid).map(|usages| {
        usages
            .iter()
            .filter_map(|u| u.used_gpu_memory_mib)
            .sum()
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        assert_eq!(usages[0].gpu_index, 0);
        assert_eq!(usages[0].used_gpu_memory_mib, Some(4096));
        assert_eq!(usages[1].pid, 54321);
        assert_eq!(usages[1].gpu_index, 1);
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
        assert_eq!(usages[0].gpu_index, 0); // defaults to 0
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
        assert_eq!(p1.gpu_index, 0);
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
                gpu_index: 0,
                used_gpu_memory_mib: Some(2048),
                gpu_process_type: None,
            }],
        );
        let snap = GpuSnapshot {
            has_gpu: true,
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
                    gpu_index: 0,
                    used_gpu_memory_mib: Some(1024),
                    gpu_process_type: None,
                },
                ProcessGpuUsage {
                    pid: 42,
                    gpu_index: 1,
                    used_gpu_memory_mib: Some(2048),
                    gpu_process_type: None,
                },
            ],
        );
        let snap = GpuSnapshot {
            has_gpu: true,
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
        assert!(!snap.has_gpu);
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
                gpu_index: 0,
                used_gpu_memory_mib: Some(512),
                gpu_process_type: Some("C".into()),
            }],
        );
        let snap = GpuSnapshot {
            has_gpu: true,
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
        };

        let json = serde_json::to_string(&snap).unwrap();
        let restored: GpuSnapshot = serde_json::from_str(&json).unwrap();
        assert!(restored.has_gpu);
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
        if snap.has_gpu {
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

        crate::test_log!(
            INFO,
            "GPU tools",
            nvidia_smi = nvidia,
            rocm_smi = rocm
        );

        // If tool check says available, snapshot should detect GPU
        let snap = collect_gpu_snapshot();
        if nvidia {
            assert!(snap.has_gpu, "nvidia-smi available but no GPU detected");
            assert_eq!(snap.gpu_type, GpuType::Nvidia);
        }
        // Note: if both are available, NVIDIA takes precedence
    }
}
