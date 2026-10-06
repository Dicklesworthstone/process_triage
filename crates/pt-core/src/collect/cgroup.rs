//! Cgroup collection and resource limit parsing.
//!
//! This module provides comprehensive cgroup information for process triage:
//! - Cgroup v1 and v2 path parsing
//! - Resource limit extraction (CPU quota, memory limits)
//! - Hierarchical cgroup detection
//!
//! # Data Sources
//! - `/proc/[pid]/cgroup` - cgroup membership
//! - `/sys/fs/cgroup/...` - cgroup limits and stats (v2)
//! - `/sys/fs/cgroup/<controller>/...` - cgroup limits (v1)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Comprehensive cgroup information for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupDetails {
    /// Cgroup version detected (1, 2, or hybrid).
    pub version: CgroupVersion,

    /// Cgroup v2 unified path (if using v2 or hybrid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified_path: Option<String>,

    /// Cgroup v1 paths by controller (if using v1 or hybrid).
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub v1_paths: HashMap<String, String>,

    /// CPU resource limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limits: Option<CpuLimits>,

    /// Memory resource limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limits: Option<MemoryLimits>,

    /// Systemd slice membership (derived from cgroup path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_slice: Option<String>,

    /// Scope or service name (derived from cgroup path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,

    /// Provenance tracking for derivation.
    pub provenance: CgroupProvenance,
}

/// Cgroup version indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    /// Pure cgroup v1 (legacy hierarchy).
    V1,
    /// Pure cgroup v2 (unified hierarchy).
    V2,
    /// Hybrid mode (both v1 and v2 controllers active).
    Hybrid,
    /// Version not determined.
    #[default]
    Unknown,
}

/// CPU resource limits from cgroup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuLimits {
    /// CPU quota in microseconds per period (None = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_us: Option<i64>,

    /// CPU period in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_us: Option<u64>,

    /// Effective CPU limit as fraction of one core (quota/period).
    /// E.g., 0.5 = half a core, 2.0 = two cores worth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_cores: Option<f64>,

    /// CPU shares (relative weight, v1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,

    /// CPU weight (v2 equivalent of shares, 1-10000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,

    /// Source of the CPU limit data.
    pub source: CpuLimitSource,
}

/// Source of CPU limit information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuLimitSource {
    /// Cgroup v2 cpu.max file.
    CgroupV2CpuMax,
    /// Cgroup v1 cpu.cfs_quota_us / cpu.cfs_period_us.
    CgroupV1Cfs,
    /// No limit found or unlimited.
    #[default]
    None,
}

/// Memory resource limits from cgroup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Hard memory limit in bytes (None = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,

    /// Soft memory limit / high watermark in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_bytes: Option<u64>,

    /// Swap limit in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_max_bytes: Option<u64>,

    /// Source of the memory limit data.
    pub source: MemoryLimitSource,
}

/// Source of memory limit information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLimitSource {
    /// Cgroup v2 memory.max / memory.high.
    CgroupV2,
    /// Cgroup v1 memory.limit_in_bytes.
    CgroupV1,
    /// No limit found or unlimited.
    #[default]
    None,
}

/// Provenance tracking for cgroup data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupProvenance {
    /// Path to /proc/\[pid\]/cgroup.
    pub cgroup_file: String,

    /// Paths attempted for resource limits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limit_paths_tried: Vec<String>,

    /// Any warnings during collection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Collect comprehensive cgroup information for a process.
///
/// # Arguments
/// * `pid` - Process ID to collect cgroup info for
///
/// # Returns
/// * `Option<CgroupDetails>` - Cgroup details or None if unavailable
pub fn collect_cgroup_details(pid: u32) -> Option<CgroupDetails> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let bytes = fs::read(&cgroup_path).ok()?;
    let content = String::from_utf8_lossy(&bytes);

    collect_cgroup_from_content(&content, &cgroup_path, Some(pid))
}

/// Parse cgroup content and collect resource limits.
///
/// Separated for testing with fixture data.
pub fn collect_cgroup_from_content(
    content: &str,
    source_path: &str,
    pid: Option<u32>,
) -> Option<CgroupDetails> {
    let mut details = CgroupDetails {
        provenance: CgroupProvenance {
            cgroup_file: source_path.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut has_v1 = false;
    let mut has_v2 = false;

    for line in content.lines() {
        // Format: "hierarchy-ID:controller-list:cgroup-path"
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }

        let hierarchy = parts[0];
        let controllers = parts[1];
        let path = parts[2];

        // Cgroup v2 (unified) has hierarchy "0" and empty controller field
        if hierarchy == "0" && controllers.is_empty() {
            has_v2 = true;
            details.unified_path = Some(path.to_string());

            // Extract systemd slice/unit from v2 path
            extract_systemd_info(&mut details, path);
        } else if !controllers.is_empty() {
            // Cgroup v1
            has_v1 = true;
            for controller in controllers.split(',') {
                if controller == "name=systemd" {
                    extract_systemd_info(&mut details, path);
                }
                details
                    .v1_paths
                    .insert(controller.to_string(), path.to_string());
            }
        }
    }

    // Determine version
    details.version = match (has_v1, has_v2) {
        (false, true) => CgroupVersion::V2,
        (true, false) => CgroupVersion::V1,
        (true, true) => CgroupVersion::Hybrid,
        (false, false) => CgroupVersion::Unknown,
    };

    // Collect resource limits if we have a PID (live system)
    if let Some(pid) = pid {
        collect_cpu_limits(&mut details, pid);
        collect_memory_limits(&mut details, pid);
    }

    Some(details)
}

/// Extract systemd slice/unit info from cgroup path.
fn extract_systemd_info(details: &mut CgroupDetails, path: &str) {
    // Common patterns:
    // /user.slice/user-1000.slice/session-1.scope
    // /system.slice/docker.service
    // /system.slice/nginx.service

    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for (i, part) in parts.iter().enumerate() {
        if part.ends_with(".slice") {
            // Take the most specific slice (last one that's a slice)
            details.systemd_slice = Some(part.to_string());
        }
        if part.ends_with(".service") || part.ends_with(".scope") {
            // This is the unit
            details.systemd_unit = Some(part.to_string());
        }
        // Handle session scopes like session-1.scope
        if part.starts_with("session-") && part.ends_with(".scope") {
            details.systemd_unit = Some(part.to_string());
        }
        // Handle user@ services
        if part.starts_with("user@") && part.ends_with(".service") {
            details.systemd_unit = Some(part.to_string());
        }
        // Also record user slice with UID
        if part.starts_with("user-") && part.ends_with(".slice") && i > 0 {
            details.systemd_slice = Some(part.to_string());
        }
    }
}

/// Collect CPU limits from cgroup filesystem.
fn collect_cpu_limits(details: &mut CgroupDetails, _pid: u32) {
    let mut limits = CpuLimits::default();
    let provenance = &mut details.provenance;

    // Try cgroup v2 first
    if let Some(ref unified_path) = details.unified_path {
        let cgroup_root = "/sys/fs/cgroup";
        let cpu_max_path = format!("{}{}/cpu.max", cgroup_root, unified_path);
        provenance.limit_paths_tried.push(cpu_max_path.clone());

        if let Some((quota, period)) = read_cpu_max(&cpu_max_path) {
            limits.quota_us = quota;
            limits.period_us = Some(period);
            limits.source = CpuLimitSource::CgroupV2CpuMax;

            if let Some(q) = quota {
                if q > 0 {
                    limits.effective_cores = Some(q as f64 / period as f64);
                }
            }
        }

        // Also try cpu.weight
        let weight_path = format!("{}{}/cpu.weight", cgroup_root, unified_path);
        provenance.limit_paths_tried.push(weight_path.clone());
        if let Ok(bytes) = fs::read(&weight_path) {
            let content = String::from_utf8_lossy(&bytes);
            if let Ok(weight) = content.trim().parse::<u64>() {
                limits.weight = Some(weight);
            }
        }
    }

    // Try cgroup v1 if v2 didn't yield results
    if limits.source == CpuLimitSource::None {
        if let Some(cpu_path) = details.v1_paths.get("cpu") {
            let cgroup_root = "/sys/fs/cgroup/cpu";
            let quota_path = format!("{}{}/cpu.cfs_quota_us", cgroup_root, cpu_path);
            let period_path = format!("{}{}/cpu.cfs_period_us", cgroup_root, cpu_path);
            let shares_path = format!("{}{}/cpu.shares", cgroup_root, cpu_path);

            provenance.limit_paths_tried.push(quota_path.clone());
            provenance.limit_paths_tried.push(period_path.clone());

            if let (Some(quota), Some(period)) =
                (read_i64_file(&quota_path), read_u64_file(&period_path))
            {
                limits.quota_us = if quota < 0 { None } else { Some(quota) };
                limits.period_us = Some(period);
                limits.source = CpuLimitSource::CgroupV1Cfs;

                if quota > 0 && period > 0 {
                    limits.effective_cores = Some(quota as f64 / period as f64);
                }
            }

            provenance.limit_paths_tried.push(shares_path.clone());
            if let Some(shares) = read_u64_file(&shares_path) {
                limits.shares = Some(shares);
            }
        }
    }

    if limits.source != CpuLimitSource::None || limits.shares.is_some() || limits.weight.is_some() {
        details.cpu_limits = Some(limits);
    }
}

/// Collect memory limits from cgroup filesystem.
fn collect_memory_limits(details: &mut CgroupDetails, _pid: u32) {
    let mut limits = MemoryLimits::default();
    let provenance = &mut details.provenance;

    // Try cgroup v2 first
    if let Some(ref unified_path) = details.unified_path {
        let cgroup_root = "/sys/fs/cgroup";
        let max_path = format!("{}{}/memory.max", cgroup_root, unified_path);
        let high_path = format!("{}{}/memory.high", cgroup_root, unified_path);
        let swap_path = format!("{}{}/memory.swap.max", cgroup_root, unified_path);

        provenance.limit_paths_tried.push(max_path.clone());
        provenance.limit_paths_tried.push(high_path.clone());

        if let Some(max) = read_memory_limit(&max_path) {
            limits.max_bytes = max;
            limits.source = MemoryLimitSource::CgroupV2;
        }

        if let Some(high) = read_memory_limit(&high_path) {
            limits.high_bytes = high;
            if limits.source == MemoryLimitSource::None {
                limits.source = MemoryLimitSource::CgroupV2;
            }
        }

        provenance.limit_paths_tried.push(swap_path.clone());
        if let Some(swap) = read_memory_limit(&swap_path) {
            limits.swap_max_bytes = swap;
            if limits.source == MemoryLimitSource::None {
                limits.source = MemoryLimitSource::CgroupV2;
            }
        }
    }

    // Try cgroup v1 if v2 didn't yield results
    if limits.source == MemoryLimitSource::None {
        if let Some(memory_path) = details.v1_paths.get("memory") {
            let cgroup_root = "/sys/fs/cgroup/memory";
            let limit_path = format!("{}{}/memory.limit_in_bytes", cgroup_root, memory_path);
            let soft_path = format!("{}{}/memory.soft_limit_in_bytes", cgroup_root, memory_path);
            let swap_path = format!("{}{}/memory.memsw.limit_in_bytes", cgroup_root, memory_path);

            provenance.limit_paths_tried.push(limit_path.clone());

            if let Some(max) = read_v1_memory_limit(&limit_path) {
                limits.max_bytes = max;
                limits.source = MemoryLimitSource::CgroupV1;
            }

            provenance.limit_paths_tried.push(soft_path.clone());
            if let Some(high) = read_v1_memory_limit(&soft_path) {
                limits.high_bytes = high;
                if limits.source == MemoryLimitSource::None {
                    limits.source = MemoryLimitSource::CgroupV1;
                }
            }

            provenance.limit_paths_tried.push(swap_path.clone());
            if let Some(swap) = read_v1_memory_limit(&swap_path) {
                limits.swap_max_bytes = swap;
                if limits.source == MemoryLimitSource::None {
                    limits.source = MemoryLimitSource::CgroupV1;
                }
            }
        }
    }

    if limits.source != MemoryLimitSource::None {
        details.memory_limits = Some(limits);
    }
}

/// Read cpu.max file (v2 format: "quota period" or "max period").
fn read_cpu_max(path: &str) -> Option<(Option<i64>, u64)> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let quota = if parts[0] == "max" {
        None // Unlimited
    } else {
        parts[0].parse::<i64>().ok()
    };

    let period = parts[1].parse::<u64>().ok()?;

    Some((quota, period))
}

/// Read memory limit file (v2 format: number or "max").
fn read_memory_limit(path: &str) -> Option<Option<u64>> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let trimmed = content.trim();

    if trimmed == "max" {
        Some(None) // Unlimited
    } else {
        Some(Some(trimmed.parse::<u64>().ok()?))
    }
}

/// Read v1 memory limit (large values like PAGE_COUNTER_MAX mean unlimited).
fn read_v1_memory_limit(path: &str) -> Option<Option<u64>> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let value = content.trim().parse::<u64>().ok()?;

    // v1 uses very large values to indicate unlimited
    // PAGE_COUNTER_MAX is typically 0x7FFFFFFFFFFFF000 on 64-bit
    const V1_UNLIMITED_THRESHOLD: u64 = 0x7FFFFFFFFFFFF000;

    if value >= V1_UNLIMITED_THRESHOLD {
        Some(None) // Unlimited
    } else {
        Some(Some(value))
    }
}

/// Helper to read a u64 from a file.
fn read_u64_file(path: &str) -> Option<u64> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    content.trim().parse::<u64>().ok()
}

/// Helper to read an i64 from a file.
fn read_i64_file(path: &str) -> Option<i64> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    content.trim().parse::<i64>().ok()
}

/// Compute effective core count from CPU quota.
///
/// Returns None if no quota is set (unlimited).
pub fn effective_cores_from_quota(quota_us: Option<i64>, period_us: Option<u64>) -> Option<f64> {
    match (quota_us, period_us) {
        (Some(q), Some(p)) if q > 0 && p > 0 => Some(q as f64 / p as f64),
        _ => None,
    }
}

/// Coarse role of a process derived from its systemd cgroup placement.
///
/// This is what lets pt tell a *system service* (supervised, never a kill candidate)
/// from a *workload someone started in a login session* (a legitimate candidate even
/// when it runs as root or has been reparented to PID 1). On the reality-check fleet,
/// protecting "any root process" and "any child of PID 1" hid every build on the
/// root-run worker hosts while still missing postgres/nginx worker children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupRole {
    /// A system unit: `/system.slice/<name>.service`, `/init.scope`, or other
    /// system-slice service placement.
    SystemService,
    /// A unit of a user's service manager: `user@UID.service/.../<name>.service`
    /// (or the user manager itself).
    UserService,
    /// Inside a container runtime's cgroup (docker, podman, containerd, k8s, lxc).
    Container,
    /// A login session: `/user.slice/user-UID.slice/session-N.scope`.
    LoginSession,
    /// A transient scope started on behalf of a user (tmux-spawn-*, app-*, run-*),
    /// or a live terminal pane proven beneath its mux's user-service cgroup.
    TransientScope,
    /// No systemd placement could be determined (cgroup v1 without systemd, macOS, ...).
    Unknown,
}

impl CgroupRole {
    /// Workloads started by a person/agent (as opposed to supervised services).
    pub fn is_user_workload(self) -> bool {
        matches!(self, CgroupRole::LoginSession | CgroupRole::TransientScope)
    }

    /// Supervised by systemd or a container runtime: killing is futile or harmful.
    pub fn is_supervised_service(self) -> bool {
        matches!(
            self,
            CgroupRole::SystemService | CgroupRole::UserService | CgroupRole::Container
        )
    }
}

/// Classify a cgroup v2 unified path (the `0::<path>` line of `/proc/<pid>/cgroup`).
pub fn classify_cgroup_path(path: &str) -> CgroupRole {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        return CgroupRole::Unknown;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("/docker-")
        || lower.contains("/docker/")
        || lower.contains("kubepods")
        || lower.contains("libpod-")
        || lower.contains("/lxc")
        || lower.contains("containerd")
        || lower.contains("/crio-")
    {
        return CgroupRole::Container;
    }
    let last = path.rsplit('/').next().unwrap_or("");
    if let Some(idx) = path.find(".service/") {
        // Nested below a service unit. Distinguish the user manager's children
        // (`user@UID.service/...`) from anything nested inside a system service.
        let unit_start = path[..idx].rfind('/').map(|i| i + 1).unwrap_or(0);
        let unit = &path[unit_start..idx];
        if unit.starts_with("user@") {
            return if last.ends_with(".service") || last == "init.scope" {
                CgroupRole::UserService
            } else if last.ends_with(".scope") || last.ends_with(".slice") {
                CgroupRole::TransientScope
            } else {
                CgroupRole::UserService
            };
        }
        return CgroupRole::SystemService;
    }
    if last.starts_with("session-") && last.ends_with(".scope") {
        return CgroupRole::LoginSession;
    }
    if last == "init.scope" || last.ends_with(".service") {
        return if path.contains("user@") {
            CgroupRole::UserService
        } else {
            CgroupRole::SystemService
        };
    }
    if last.ends_with(".scope") {
        return CgroupRole::TransientScope;
    }
    CgroupRole::Unknown
}

/// The systemd service a cgroup path places a process in, as `(unit, user_manager)`:
/// `user_manager` is true for units of a user's service manager (`systemctl --user`).
/// `None` unless the placement is a supervised service (a system or user `.service`);
/// login sessions, transient scopes and containers are not services.
pub fn systemd_service_unit(path: &str) -> Option<(&str, bool)> {
    if !matches!(
        classify_cgroup_path(path),
        CgroupRole::SystemService | CgroupRole::UserService
    ) {
        return None;
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let idx = segments.iter().rposition(|s| s.ends_with(".service"))?;
    let user_manager = segments[..idx]
        .iter()
        .any(|s| s.starts_with("user@") && s.ends_with(".service"));
    Some((segments[idx], user_manager))
}

/// The XDG desktop application unit a cgroup path places a process in, if any:
/// `app-<launcher>-<AppID>-<RANDOM>.scope` or `app-<launcher>-<AppID>@<RANDOM>.service`
/// below a user's service manager, which is how graphical sessions (GNOME, KDE,
/// uwsm, ...) launch applications (systemd's desktop-environment conventions).
pub fn desktop_app_unit(path: &str) -> Option<&str> {
    if !path.contains("/user@") {
        return None;
    }
    path.rsplit('/').find(|segment| {
        segment.starts_with("app-")
            && (segment.ends_with(".scope") || segment.ends_with(".service"))
    })
}

/// The systemd cgroup path of a live process (`0::<path>` on cgroup v2, else the v1
/// `name=systemd` hierarchy). Linux only; `None` elsewhere or when unreadable.
pub fn read_systemd_cgroup_path(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let bytes = fs::read(format!("/proc/{pid}/cgroup")).ok()?;
        let content = String::from_utf8_lossy(&bytes);
        let mut v1_systemd: Option<&str> = None;
        for line in content.lines() {
            let mut parts = line.splitn(3, ':');
            let (Some(h), Some(ctrl), Some(path)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if h == "0" && ctrl.is_empty() {
                return Some(path.trim().to_string());
            }
            if ctrl == "name=systemd" {
                v1_systemd = Some(path);
            }
        }
        v1_systemd.map(|p| p.trim().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Classify a live process by reading `/proc/<pid>/cgroup` (Linux only).
pub fn read_cgroup_role(pid: u32) -> CgroupRole {
    read_systemd_cgroup_path(pid)
        .map(|path| classify_live_cgroup_path(pid, &path))
        .unwrap_or(CgroupRole::Unknown)
}

/// Refine an observed service placement using current process ancestry.
///
/// A terminal pane inherits its mux server's service cgroup without being
/// supervised by that unit. Only a stable, same-owner chain containing a TTY
/// below a live mux server earns the existing transient-workload treatment.
/// Unreadable, moved, reparented or changed chains retain service protection.
pub fn classify_live_cgroup_path(pid: u32, path: &str) -> CgroupRole {
    #[cfg(target_os = "linux")]
    {
        classify_process_cgroup_with(pid, path, read_terminal_process)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        classify_cgroup_path(path)
    }
}

#[cfg(any(target_os = "linux", test))]
fn classify_process_cgroup_with(
    pid: u32,
    path: &str,
    read: impl FnMut(u32) -> Option<TerminalProcess>,
) -> CgroupRole {
    let role = classify_cgroup_path(path);
    if role == CgroupRole::UserService && terminal_pane_chain(pid, path, read) {
        CgroupRole::TransientScope
    } else {
        role
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalProcess {
    pid: u32,
    ppid: u32,
    birth_ticks: u64,
    uids: [u32; 4],
    sid: i32,
    tty: i32,
    comm: String,
    cmdline: Vec<u8>,
    executable: std::path::PathBuf,
    cgroup: String,
}

#[cfg(target_os = "linux")]
fn read_terminal_process(pid: u32) -> Option<TerminalProcess> {
    parse_terminal_process(
        pid,
        &fs::read_to_string(format!("/proc/{pid}/stat")).ok()?,
        &fs::read_to_string(format!("/proc/{pid}/status")).ok()?,
        fs::read(format!("/proc/{pid}/cmdline")).ok()?,
        fs::read_link(format!("/proc/{pid}/exe")).ok()?,
        &fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?,
    )
}

#[cfg(any(target_os = "linux", test))]
fn parse_terminal_process(
    pid: u32,
    stat: &str,
    status: &str,
    cmdline: Vec<u8>,
    executable: std::path::PathBuf,
    cgroup_content: &str,
) -> Option<TerminalProcess> {
    // These fields must be parsed strictly: the general-purpose stat parser's
    // default-zero fields cannot establish a safety exemption.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open || stat[..open].trim().parse::<u32>().ok()? != pid {
        return None;
    }
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    if !matches!(
        fields.first(),
        Some(&"R" | &"S" | &"D" | &"T" | &"t" | &"I")
    ) {
        return None;
    }
    let uid_fields: Vec<_> = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .collect();
    if uid_fields.len() != 4 {
        return None;
    }
    if cmdline.is_empty() || cmdline.last() != Some(&0) {
        return None;
    }
    let mut systemd_path = None;
    for line in cgroup_content.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        hierarchy.parse::<u32>().ok()?;
        if !path.starts_with('/') {
            return None;
        }
        if hierarchy == "0" && controllers.is_empty() {
            systemd_path = Some(path.to_string());
            break;
        }
        if controllers
            .split(',')
            .any(|controller| controller == "name=systemd")
        {
            systemd_path = Some(path.to_string());
        }
    }
    Some(TerminalProcess {
        pid,
        ppid: fields.get(1)?.parse().ok()?,
        birth_ticks: fields.get(19)?.parse().ok()?,
        uids: [
            uid_fields[0].parse().ok()?,
            uid_fields[1].parse().ok()?,
            uid_fields[2].parse().ok()?,
            uid_fields[3].parse().ok()?,
        ],
        sid: fields.get(3)?.parse().ok()?,
        tty: fields.get(4)?.parse().ok()?,
        comm: stat[open + 1..close].to_string(),
        cmdline,
        executable,
        cgroup: systemd_path?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn terminal_pane_chain(
    pid: u32,
    path: &str,
    mut read: impl FnMut(u32) -> Option<TerminalProcess>,
) -> bool {
    let Some((unit, true)) = systemd_service_unit(path) else {
        return false;
    };
    let Some(stem) = unit.strip_suffix(".service") else {
        return false;
    };
    let mux = stem.split('@').next().unwrap_or(stem);
    if !matches!(
        mux,
        "frankenterm-mux-server"
            | "wezterm-mux-server"
            | "tmux"
            | "zellij"
            | "screen"
            | "abduco"
            | "dtach"
    ) {
        return false;
    }
    let Some(owner) = path.split('/').find_map(|component| {
        component
            .strip_prefix("user@")?
            .strip_suffix(".service")?
            .parse::<u32>()
            .ok()
    }) else {
        return false;
    };
    let mut chain = Vec::new();
    let mut current = pid;
    let mut saw_tty = false;
    for _ in 0..64 {
        if current <= 1
            || chain
                .iter()
                .any(|node: &TerminalProcess| node.pid == current)
        {
            return false;
        }
        let Some(node) = read(current) else {
            return false;
        };
        if node.pid != current
            || node.birth_ticks == 0
            || node.sid <= 0
            || node.cmdline.is_empty()
            || node.cgroup != path
            || node.uids.iter().any(|uid| *uid != owner)
        {
            return false;
        }
        let executable = node.executable.file_name().and_then(|name| name.to_str());
        let executable = executable.map(|name| name.strip_suffix(" (deleted)").unwrap_or(name));
        let is_mux = match mux {
            "tmux" => executable == Some("tmux") && node.comm == "tmux: server",
            "screen" => matches!(executable, Some("screen" | "SCREEN")),
            _ => executable == Some(mux),
        };
        if is_mux {
            if !saw_tty {
                return false;
            }
            chain.push(node);
            // Re-read every witness, including the target and the mux. A stale
            // birth, owner, command, PPID, TTY, session or placement fails closed.
            return chain
                .iter()
                .all(|before| read(before.pid).as_ref() == Some(before));
        }
        saw_tty |= node.tty != 0;
        current = node.ppid;
        chain.push(node);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANE_PATH: &str =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/frankenterm-mux-server.service";

    fn pane_layout() -> HashMap<u32, TerminalProcess> {
        [
            (4000, 3000, 4000, 0, "sleep", "/usr/bin/sleep"),
            (3000, 2000, 3000, 34816, "bash", "/usr/bin/bash"),
            (
                2000,
                1000,
                1000,
                0,
                "frankenterm-mux",
                "/usr/bin/frankenterm-mux-server",
            ),
        ]
        .into_iter()
        .map(|(pid, ppid, sid, tty, comm, executable)| {
            (
                pid,
                TerminalProcess {
                    pid,
                    ppid,
                    birth_ticks: u64::from(pid) + 100,
                    uids: [1000; 4],
                    sid,
                    tty,
                    comm: comm.to_string(),
                    cmdline: format!("{executable}\0").into_bytes(),
                    executable: executable.into(),
                    cgroup: PANE_PATH.to_string(),
                },
            )
        })
        .collect()
    }

    #[test]
    fn terminal_pane_accepts_tty_shell_and_ttyless_new_session_child() {
        let layout = pane_layout();
        for pid in [3000, 4000] {
            assert!(
                terminal_pane_chain(pid, PANE_PATH, |p| layout.get(&p).cloned()),
                "PID {pid}"
            );
        }
        assert!(!terminal_pane_chain(2000, PANE_PATH, |p| layout
            .get(&p)
            .cloned()));
    }

    #[test]
    fn terminal_pane_keeps_other_services_and_containers_protected() {
        for path in [
            "/user.slice/user-1000.slice/user@1000.service/app.slice/rchd.service",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/ordinary.service",
            "/system.slice/frankenterm-mux-server.service",
            "/docker/frankenterm-mux-server.service",
        ] {
            let mut layout = pane_layout();
            for node in layout.values_mut() {
                node.cgroup = path.to_string();
            }
            assert!(
                !terminal_pane_chain(4000, path, |p| layout.get(&p).cloned()),
                "{path}"
            );
        }
    }

    #[test]
    fn terminal_pane_requires_live_executable_tty_owner_and_complete_chain() {
        for missing in [2000, 3000, 4000] {
            let layout = pane_layout();
            assert!(!terminal_pane_chain(4000, PANE_PATH, |p| {
                (p != missing).then(|| layout.get(&p).cloned()).flatten()
            }));
        }
        for mutation in 0..7 {
            let mut layout = pane_layout();
            match mutation {
                0 => layout.get_mut(&2000).unwrap().executable = "/usr/bin/sleep".into(),
                1 => layout.get_mut(&3000).unwrap().tty = 0,
                2 => layout.get_mut(&3000).unwrap().uids = [0; 4],
                3 => layout.get_mut(&4000).unwrap().ppid = 1,
                4 => layout.get_mut(&3000).unwrap().cgroup = "/other.scope".to_string(),
                5 => layout.get_mut(&3000).unwrap().ppid = 4000,
                _ => layout.get_mut(&4000).unwrap().cmdline.clear(),
            }
            assert!(
                !terminal_pane_chain(4000, PANE_PATH, |p| layout.get(&p).cloned()),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn terminal_pane_rechecks_every_identity_and_placement_witness() {
        for changed_pid in [2000, 3000, 4000] {
            for mutation in 0..10 {
                let layout = pane_layout();
                let mut seen = std::collections::HashSet::new();
                assert!(
                    !terminal_pane_chain(4000, PANE_PATH, |p| {
                        let mut node = layout.get(&p)?.clone();
                        if !seen.insert(p) && p == changed_pid {
                            match mutation {
                                0 => node.birth_ticks += 1,
                                1 => node.uids[0] += 1,
                                2 => node.uids[3] += 1,
                                3 => node.ppid += 1,
                                4 => node.sid += 1,
                                5 => node.tty += 1,
                                6 => node.comm.push('x'),
                                7 => node.cmdline.push(b'x'),
                                8 => node.executable = "/changed-executable".into(),
                                _ => node.cgroup.push_str("/moved.scope"),
                            }
                        }
                        Some(node)
                    }),
                    "changed PID {changed_pid}, mutation {mutation}"
                );
            }
        }
    }

    #[test]
    fn recorded_pane_layout_replays_raw_proc_classification() {
        // Captured read-only from this host's /proc on 2026-10-06. Keep raw
        // cgroup placement rather than freezing the answer in the fixture.
        let cgroup = format!("0::{PANE_PATH}\n");
        let uids = "Uid:\t1000\t1000\t1000\t1000\n";
        let records = [
            (
                201816,
                "201816 (zsh) S 3922144 201816 201816 34817 205613 4194304 47689 674954 16 3469 58 45 534 317 10 -10 1 0 309148456 13611008 1080 18446744073709551615 107304865968128 107304866725421 140725043534432 0 0 0 2 3686400 134295555 1 0 0 17 6 0 0 0 0 0 107304866818320 107304866847844 107305608462336 140725043538716 140725043538721 140725043538721 140725043539947 0\n",
                "-zsh\0",
                "/usr/bin/zsh",
            ),
            (
                205613,
                "205613 (bun) S 201816 205613 201816 34817 205613 4194304 17864 0 742 0 245 467 0 0 20 0 2 0 309151911 6614761472 2097 18446744073709551615 24619008 81466400 140732652608384 0 0 0 0 16781312 536888571 0 0 0 17 0 0 0 0 0 0 81470496 81584000 283578368 140732652613499 140732652613699 140732652613699 140732652617694 0\n",
                "/home/ubuntu/.bun/bin/bun\0/home/ubuntu/.bun/bin/codex\0--dangerously-bypass-approvals-and-sandbox\0--search\0-m\0gpt-6.1-sol\0-c\0model_reasoning_effort=xhigh\0-c\0model_reasoning_summary_format=experimental\0",
                "/home/ubuntu/.bun/bin/bun",
            ),
            (
                205617,
                "205617 (codex) S 205613 205613 201816 34817 205613 4194304 5020017 489148705 42063 74007 100913 49261 492084 269024 20 0 31 0 309151913 1452662784 48052 18446744073709551615 137489896624128 137490122597542 140728226570448 0 0 0 0 4096 134284352 0 0 0 17 0 0 0 0 0 0 137490172539032 137490178202992 93825122615296 140728226573864 140728226574123 140728226574123 140728226578311 0\n",
                "/home/ubuntu/.bun/install/global/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex\0--dangerously-bypass-approvals-and-sandbox\0--search\0-m\0gpt-6.1-sol\0-c\0model_reasoning_effort=xhigh\0-c\0model_reasoning_summary_format=experimental\0",
                "/home/ubuntu/.bun/install/global/node_modules/.old-2BE0AF0907BE6867/vendor/x86_64-unknown-linux-musl/bin/codex (deleted)",
            ),
            (
                3922144,
                "3922144 (frankenterm-mux) R 3922121 3922144 3922144 0 -1 4194304 15451008 0 67876 0 1624336 1206174 0 0 10 -10 48 0 240148391 4418912256 20497 18446744073709551615 96965981952320 96966004899280 140720516953392 0 0 0 0 4096 17474 0 0 0 17 7 0 0 0 0 0 96966005614752 96966005651800 96966984384512 140720516959107 140720516959235 140720516959235 140720516960201 0\n",
                "/home/ubuntu/.local/bin/frankenterm-mux-server\0--daemonize=false\0--config-file=/home/ubuntu/.config/frankenterm/frankenterm.lua\0",
                "/home/ubuntu/.local/bin/frankenterm-mux-server",
            ),
        ];
        let layout: HashMap<_, _> = records
            .into_iter()
            .map(|(pid, stat, cmd, exe)| {
                let node = parse_terminal_process(
                    pid,
                    stat,
                    uids,
                    cmd.as_bytes().to_vec(),
                    exe.into(),
                    &cgroup,
                )
                .expect("captured proc record parses");
                (pid, node)
            })
            .collect();
        assert_eq!(classify_cgroup_path(PANE_PATH), CgroupRole::UserService);
        for pid in [201816, 205613, 205617] {
            assert_eq!(
                classify_process_cgroup_with(pid, PANE_PATH, |p| layout.get(&p).cloned()),
                CgroupRole::TransientScope,
                "captured pane PID {pid}"
            );
        }
        assert_eq!(
            classify_process_cgroup_with(3922144, PANE_PATH, |p| layout.get(&p).cloned()),
            CgroupRole::UserService
        );
        let mut no_terminal = layout.clone();
        for node in no_terminal.values_mut() {
            node.tty = 0;
        }
        assert_eq!(
            classify_process_cgroup_with(205617, PANE_PATH, |p| no_terminal.get(&p).cloned()),
            CgroupRole::UserService
        );
        // A subreaper-adopted pane no longer has a mux witness and fails closed.
        let mut adopted = layout;
        adopted.get_mut(&201816).unwrap().ppid = 3922121;
        assert_eq!(
            classify_process_cgroup_with(205617, PANE_PATH, |p| adopted.get(&p).cloned()),
            CgroupRole::UserService
        );
        for (pid, stat, cmd, exe) in records {
            for invalid in ["", "0", "0::relative", "x::/", "1:memory"] {
                assert!(parse_terminal_process(
                    pid,
                    stat,
                    uids,
                    cmd.as_bytes().to_vec(),
                    exe.into(),
                    invalid,
                )
                .is_none());
            }
            assert!(parse_terminal_process(
                pid,
                "truncated (stat) S 1",
                uids,
                cmd.as_bytes().to_vec(),
                exe.into(),
                &cgroup,
            )
            .is_none());
        }
    }

    #[test]
    fn classify_cgroup_paths_from_fleet() {
        use CgroupRole::*;
        let cases = [
            ("/system.slice/nginx.service", SystemService),
            ("/system.slice/postgresql@18-main.service", SystemService),
            ("/system.slice/cron.service", SystemService),
            ("/init.scope", SystemService),
            ("/system.slice/docker-0123abcd.scope", Container),
            (
                "/kubepods.slice/kubepods-burstable.slice/cri-containerd-ab.scope",
                Container,
            ),
            ("/user.slice/user-0.slice/session-12.scope", LoginSession),
            ("/user.slice/user-1000.slice/session-3.scope", LoginSession),
            (
                "/user.slice/user-1000.slice/user@1000.service/init.scope",
                UserService,
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/pm2.service",
                UserService,
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-1c2d.scope",
                TransientScope,
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot-123.scope",
                TransientScope,
            ),
            ("/system.slice/run-u42.scope", TransientScope),
            ("/", Unknown),
            ("", Unknown),
        ];
        for (path, expected) in cases {
            assert_eq!(classify_cgroup_path(path), expected, "path {path}");
        }
        assert!(LoginSession.is_user_workload());
        assert!(TransientScope.is_user_workload());
        assert!(!SystemService.is_user_workload());
        assert!(SystemService.is_supervised_service());
        assert!(Container.is_supervised_service());
        assert!(!Unknown.is_supervised_service() && !Unknown.is_user_workload());
    }

    #[test]
    fn systemd_service_unit_names_the_unit_and_manager() {
        let cases = [
            ("/system.slice/nginx.service", Some(("nginx.service", false))),
            (
                "/system.slice/postgresql@18-main.service",
                Some(("postgresql@18-main.service", false)),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/pm2.service",
                Some(("pm2.service", true)),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-slack@4f2.service",
                Some(("app-slack@4f2.service", true)),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/session.slice/wayland-wm@hyprland.desktop.service",
                Some(("wayland-wm@hyprland.desktop.service", true)),
            ),
            // Not services: login session, transient scopes, containers, init.
            ("/user.slice/user-1000.slice/session-1.scope", None),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-slack-123.scope",
                None,
            ),
            ("/system.slice/docker-0123abcd.scope", None),
            ("/init.scope", None),
            ("/", None),
        ];
        for (path, expected) in cases {
            assert_eq!(systemd_service_unit(path), expected, "path {path}");
        }
    }

    #[test]
    fn desktop_app_unit_recognizes_xdg_application_units() {
        let cases = [
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-slack-4821.scope",
                Some("app-Hyprland-slack-4821.scope"),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Nautilus-2211.scope",
                Some("app-gnome-org.gnome.Nautilus-2211.scope"),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole@a1b2.service",
                Some("app-org.kde.konsole@a1b2.service"),
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-1c2d.scope",
                None,
            ),
            ("/user.slice/user-1000.slice/session-3.scope", None),
            ("/system.slice/app-fake.service", None),
            ("/user.slice/user-1000.slice/user@1000.service/app.slice", None),
        ];
        for (path, expected) in cases {
            assert_eq!(desktop_app_unit(path), expected, "path {path}");
        }
    }

    #[test]
    fn test_parse_cgroup_v2() {
        let content = "0::/user.slice/user-1000.slice/session-1.scope\n";
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();

        assert_eq!(details.version, CgroupVersion::V2);
        assert_eq!(
            details.unified_path,
            Some("/user.slice/user-1000.slice/session-1.scope".to_string())
        );
        assert_eq!(details.systemd_slice, Some("user-1000.slice".to_string()));
        assert_eq!(details.systemd_unit, Some("session-1.scope".to_string()));
    }

    #[test]
    fn test_parse_cgroup_v1() {
        let content = r#"12:pids:/user.slice/user-1000.slice
11:memory:/user.slice/user-1000.slice
10:cpu,cpuacct:/user.slice/user-1000.slice
"#;
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();

        assert_eq!(details.version, CgroupVersion::V1);
        assert!(details.unified_path.is_none());
        assert_eq!(
            details.v1_paths.get("pids"),
            Some(&"/user.slice/user-1000.slice".to_string())
        );
        assert_eq!(
            details.v1_paths.get("cpu"),
            Some(&"/user.slice/user-1000.slice".to_string())
        );
        assert_eq!(
            details.v1_paths.get("cpuacct"),
            Some(&"/user.slice/user-1000.slice".to_string())
        );
    }

    #[test]
    fn test_parse_cgroup_hybrid() {
        let content = r#"12:pids:/docker/abc123
0::/docker/abc123
"#;
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();

        assert_eq!(details.version, CgroupVersion::Hybrid);
        assert_eq!(details.unified_path, Some("/docker/abc123".to_string()));
        assert_eq!(
            details.v1_paths.get("pids"),
            Some(&"/docker/abc123".to_string())
        );
    }

    #[test]
    fn test_parse_cgroup_systemd_service() {
        let content = "0::/system.slice/nginx.service\n";
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();

        assert_eq!(details.systemd_slice, Some("system.slice".to_string()));
        assert_eq!(details.systemd_unit, Some("nginx.service".to_string()));
    }

    #[test]
    fn test_read_cpu_max_limited() {
        // This would require a mock filesystem or temp files for true testing
        // Here we just test the parsing logic with a helper
        let content = "50000 100000";
        let parts: Vec<&str> = content.split_whitespace().collect();
        let quota = parts[0].parse::<i64>().ok();
        let period = parts[1].parse::<u64>().ok();

        assert_eq!(quota, Some(50000));
        assert_eq!(period, Some(100000));
    }

    #[test]
    fn test_read_cpu_max_unlimited() {
        let content = "max 100000";
        let parts: Vec<&str> = content.split_whitespace().collect();
        let quota = if parts[0] == "max" {
            None
        } else {
            parts[0].parse::<i64>().ok()
        };
        let period = parts[1].parse::<u64>().ok();

        assert_eq!(quota, None);
        assert_eq!(period, Some(100000));
    }

    #[test]
    fn test_effective_cores_from_quota() {
        // 50% of one core
        assert_eq!(
            effective_cores_from_quota(Some(50000), Some(100000)),
            Some(0.5)
        );

        // 2 cores
        assert_eq!(
            effective_cores_from_quota(Some(200000), Some(100000)),
            Some(2.0)
        );

        // Unlimited
        assert_eq!(effective_cores_from_quota(None, Some(100000)), None);
        assert_eq!(effective_cores_from_quota(Some(-1), Some(100000)), None);
    }

    #[test]
    fn test_systemd_user_service() {
        let content = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-test.scope\n";
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();

        // Should capture the most specific slice and unit
        assert!(details.systemd_slice.is_some());
        assert!(details.systemd_unit.is_some());
    }

    #[test]
    fn test_cgroup_version_default() {
        let content = "";
        let details = collect_cgroup_from_content(content, "/proc/1234/cgroup", None).unwrap();
        assert_eq!(details.version, CgroupVersion::Unknown);
    }

    // =====================================================
    // No-mock tests using real processes and system cgroups
    // =====================================================

    #[test]
    fn test_nomock_collect_cgroup_details_self() {
        // Test collecting cgroup details for our own process
        if !std::path::Path::new("/proc/self/cgroup").exists() {
            crate::test_log!(
                INFO,
                "Skipping no-mock test: /proc/self/cgroup not available"
            );
            return;
        }

        let my_pid = std::process::id();
        crate::test_log!(INFO, "cgroup details no-mock test", pid = my_pid);

        let details = collect_cgroup_details(my_pid);
        crate::test_log!(
            INFO,
            "cgroup details result",
            pid = my_pid,
            has_result = details.is_some()
        );

        assert!(details.is_some(), "Should be able to read cgroup for self");
        let details = details.unwrap();

        // Version should be detected (not Unknown on a properly configured system)
        crate::test_log!(
            INFO,
            "cgroup version detected",
            version = format!("{:?}", details.version).as_str()
        );

        // Provenance should track the cgroup file
        assert!(details.provenance.cgroup_file.contains(&my_pid.to_string()));

        crate::test_log!(
            INFO,
            "cgroup details completed",
            version = format!("{:?}", details.version).as_str(),
            has_unified_path = details.unified_path.is_some(),
            v1_paths_count = details.v1_paths.len()
        );
    }

    #[test]
    fn test_nomock_collect_cgroup_details_spawned() {
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness;
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(
            INFO,
            "cgroup details spawned process test",
            pid = proc.pid()
        );

        let details = collect_cgroup_details(proc.pid());
        crate::test_log!(
            INFO,
            "cgroup details result",
            pid = proc.pid(),
            has_result = details.is_some()
        );

        assert!(
            details.is_some(),
            "Should be able to read cgroup for spawned process"
        );
        let details = details.unwrap();

        // Either unified path (v2) or v1 paths should be present
        let has_paths = details.unified_path.is_some() || !details.v1_paths.is_empty();
        assert!(
            has_paths || details.version == CgroupVersion::Unknown,
            "Should have cgroup paths or be Unknown"
        );

        crate::test_log!(
            INFO,
            "cgroup details spawned completed",
            pid = proc.pid(),
            version = format!("{:?}", details.version).as_str(),
            unified_path = details.unified_path.as_deref().unwrap_or("none")
        );
    }

    #[test]
    fn test_nomock_cgroup_systemd_slice_detection() {
        // Test that systemd slice/unit detection works on real cgroup paths
        if !std::path::Path::new("/proc/self/cgroup").exists() {
            crate::test_log!(
                INFO,
                "Skipping no-mock test: /proc/self/cgroup not available"
            );
            return;
        }

        let my_pid = std::process::id();
        let details = collect_cgroup_details(my_pid).expect("Should collect cgroup details");

        crate::test_log!(
            INFO,
            "systemd slice detection test",
            pid = my_pid,
            has_slice = details.systemd_slice.is_some(),
            has_unit = details.systemd_unit.is_some(),
            slice = details.systemd_slice.as_deref().unwrap_or("none"),
            unit = details.systemd_unit.as_deref().unwrap_or("none")
        );

        // On a systemd system, we should detect at least slice or unit
        // (but don't fail on non-systemd systems)
        if details.version == CgroupVersion::V2 || details.version == CgroupVersion::Hybrid {
            // V2 or hybrid should have unified path
            crate::test_log!(
                INFO,
                "v2/hybrid cgroup detected",
                unified_path = details.unified_path.as_deref().unwrap_or("none")
            );
        }
    }

    #[test]
    fn test_nomock_effective_cores_calculation() {
        // Test effective_cores_from_quota with real values
        // This is a pure calculation test but uses realistic values

        // Test common container CPU limits
        let test_cases = [
            (Some(100000i64), Some(100000u64), Some(1.0)), // 1 core
            (Some(50000), Some(100000), Some(0.5)),        // 0.5 cores
            (Some(200000), Some(100000), Some(2.0)),       // 2 cores
            (None, Some(100000), None),                    // Unlimited
            (Some(-1), Some(100000), None),                // Unlimited (v1 style)
        ];

        for (quota, period, expected) in test_cases {
            let result = effective_cores_from_quota(quota, period);
            crate::test_log!(
                INFO,
                "effective_cores test case",
                quota = format!("{:?}", quota).as_str(),
                period = format!("{:?}", period).as_str(),
                expected = format!("{:?}", expected).as_str(),
                result = format!("{:?}", result).as_str()
            );
            assert_eq!(result, expected, "quota={:?}, period={:?}", quota, period);
        }
    }
}
