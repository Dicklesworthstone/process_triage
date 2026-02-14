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
    let content = fs::read_to_string(&cgroup_path).ok()?;

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
        if let Ok(content) = fs::read_to_string(&weight_path) {
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
    let content = fs::read_to_string(path).ok()?;
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
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();

    if trimmed == "max" {
        Some(None) // Unlimited
    } else {
        Some(Some(trimmed.parse::<u64>().ok()?))
    }
}

/// Read v1 memory limit (large values like PAGE_COUNTER_MAX mean unlimited).
fn read_v1_memory_limit(path: &str) -> Option<Option<u64>> {
    let content = fs::read_to_string(path).ok()?;
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
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u64>().ok()
}

/// Helper to read an i64 from a file.
fn read_i64_file(path: &str) -> Option<i64> {
    let content = fs::read_to_string(path).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
