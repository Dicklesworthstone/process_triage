//! CPU capacity derivation for process triage.
//!
//! This module computes `N_eff_cores`: the effective CPU core capacity available
//! to a process, honoring OS constraints such as:
//! - CPU affinity mask (sched_getaffinity)
//! - cpuset constraints (cgroup cpuset controller)
//! - cgroup CPU quota (cpu.max or cpu.cfs_quota_us)
//!
//! The final value is computed conservatively:
//! `N_eff_cores = min(affinity_cores, cpuset_cores, quota_cores)`
//!
//! # Data Sources
//! - `/proc/[pid]/status` - Cpus_allowed_list field
//! - `/sys/fs/cgroup/.../cpuset.cpus` (v2) or `/sys/fs/cgroup/cpuset/.../cpuset.cpus` (v1)
//! - CPU quota from cgroup module

use super::cgroup::CgroupDetails;
use serde::{Deserialize, Serialize};
use std::fs;

/// Effective CPU capacity for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuCapacity {
    /// Effective number of CPU cores available to the process.
    /// This is the minimum of all constraints.
    pub n_eff_cores: f64,

    /// Number of cores from CPU affinity mask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity_cores: Option<u32>,

    /// Number of cores from cpuset constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_cores: Option<u32>,

    /// Effective cores from CPU quota (quota/period).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_cores: Option<f64>,

    /// Provenance tracking for derivation.
    pub provenance: CpuCapacityProvenance,
}

/// Provenance tracking for CPU capacity derivation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuCapacityProvenance {
    /// Source of affinity information.
    pub affinity_source: AffinitySource,

    /// Source of cpuset information.
    pub cpuset_source: CpusetSource,

    /// Source of quota information.
    pub quota_source: QuotaSource,

    /// Which constraint was the binding minimum.
    pub binding_constraint: BindingConstraint,

    /// Paths attempted for data collection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths_tried: Vec<String>,

    /// Any warnings during derivation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Source of CPU affinity information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffinitySource {
    /// From /proc/[pid]/status Cpus_allowed_list.
    ProcStatus,
    /// Not available (assume unconstrained).
    #[default]
    None,
}

/// Source of cpuset information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpusetSource {
    /// From cgroup v2 cpuset.cpus.effective.
    CgroupV2Effective,
    /// From cgroup v2 cpuset.cpus.
    CgroupV2,
    /// From cgroup v1 cpuset.cpus.
    CgroupV1,
    /// Not available (assume unconstrained).
    #[default]
    None,
}

/// Source of quota information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaSource {
    /// From cgroup v2 cpu.max.
    CgroupV2CpuMax,
    /// From cgroup v1 cpu.cfs_quota_us.
    CgroupV1Cfs,
    /// No quota (unlimited).
    #[default]
    None,
}

/// Which constraint was the binding (minimum) value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingConstraint {
    /// CPU affinity was the limiting factor.
    Affinity,
    /// cpuset was the limiting factor.
    Cpuset,
    /// CPU quota was the limiting factor.
    Quota,
    /// System default (logical CPU count).
    #[default]
    SystemDefault,
}

/// Compute effective CPU capacity for a process.
///
/// # Arguments
/// * `pid` - Process ID
/// * `cgroup_details` - Optional pre-collected cgroup details
///
/// # Returns
/// * `CpuCapacity` - Computed capacity with provenance
pub fn compute_cpu_capacity(pid: u32, cgroup_details: Option<&CgroupDetails>) -> CpuCapacity {
    let mut capacity = CpuCapacity::default();
    let logical_cpus = num_logical_cpus();

    // 1) Collect affinity from /proc/[pid]/status
    let affinity = collect_affinity(pid, &mut capacity.provenance);
    capacity.affinity_cores = affinity;

    // 2) Collect cpuset constraints
    let cpuset = collect_cpuset(pid, cgroup_details, &mut capacity.provenance);
    capacity.cpuset_cores = cpuset;

    // 3) Extract quota cores from cgroup details
    if let Some(cgroup) = cgroup_details {
        if let Some(ref cpu_limits) = cgroup.cpu_limits {
            if let Some(eff_cores) = cpu_limits.effective_cores {
                capacity.quota_cores = Some(eff_cores);
                capacity.provenance.quota_source = match cpu_limits.source {
                    super::cgroup::CpuLimitSource::CgroupV2CpuMax => QuotaSource::CgroupV2CpuMax,
                    super::cgroup::CpuLimitSource::CgroupV1Cfs => QuotaSource::CgroupV1Cfs,
                    super::cgroup::CpuLimitSource::None => QuotaSource::None,
                };
            }
        }
    }

    // 4) Compute N_eff_cores as minimum of all constraints
    let mut n_eff = logical_cpus as f64;
    let mut binding = BindingConstraint::SystemDefault;

    if let Some(aff) = capacity.affinity_cores {
        if (aff as f64) < n_eff {
            n_eff = aff as f64;
            binding = BindingConstraint::Affinity;
        }
    }

    if let Some(cpus) = capacity.cpuset_cores {
        if (cpus as f64) < n_eff {
            n_eff = cpus as f64;
            binding = BindingConstraint::Cpuset;
        }
    }

    if let Some(quota) = capacity.quota_cores {
        if quota < n_eff {
            n_eff = quota;
            binding = BindingConstraint::Quota;
        }
    }

    capacity.n_eff_cores = n_eff;
    capacity.provenance.binding_constraint = binding;

    capacity
}

/// Collect CPU affinity from /proc/[pid]/status.
fn collect_affinity(pid: u32, provenance: &mut CpuCapacityProvenance) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    provenance.paths_tried.push(path.clone());

    let content = fs::read_to_string(&path).ok()?;
    let affinity = parse_cpus_allowed_list(&content)?;

    provenance.affinity_source = AffinitySource::ProcStatus;
    Some(affinity)
}

/// Parse Cpus_allowed_list from /proc/[pid]/status content.
///
/// Format: "Cpus_allowed_list:\t0-3" or "Cpus_allowed_list:\t0,2,4-7"
pub fn parse_cpus_allowed_list(content: &str) -> Option<u32> {
    for line in content.lines() {
        if line.starts_with("Cpus_allowed_list:") {
            let value = line.split(':').nth(1)?.trim();
            return Some(count_cpus_in_list(value));
        }
    }
    None
}

/// Count CPUs in a list format like "0-3,5,7-9".
pub fn count_cpus_in_list(list: &str) -> u32 {
    let mut count = 0u32;

    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            // Range like "0-3"
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u32>(), end.trim().parse::<u32>()) {
                if e >= s {
                    count += e - s + 1;
                }
            }
        } else {
            // Single CPU like "5"
            if part.parse::<u32>().is_ok() {
                count += 1;
            }
        }
    }

    count
}

/// Collect cpuset constraints from cgroup.
fn collect_cpuset(
    pid: u32,
    cgroup_details: Option<&CgroupDetails>,
    provenance: &mut CpuCapacityProvenance,
) -> Option<u32> {
    // Try cgroup v2 first
    if let Some(cgroup) = cgroup_details {
        if let Some(ref unified_path) = cgroup.unified_path {
            // Try cpuset.cpus.effective first (actual available CPUs)
            let effective_path = format!("/sys/fs/cgroup{}/cpuset.cpus.effective", unified_path);
            provenance.paths_tried.push(effective_path.clone());

            if let Some(count) = read_cpuset_file(&effective_path) {
                provenance.cpuset_source = CpusetSource::CgroupV2Effective;
                return Some(count);
            }

            // Fall back to cpuset.cpus
            let cpus_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            provenance.paths_tried.push(cpus_path.clone());

            if let Some(count) = read_cpuset_file(&cpus_path) {
                provenance.cpuset_source = CpusetSource::CgroupV2;
                return Some(count);
            }
        }

        // Try cgroup v1 cpuset
        if let Some(cpuset_path) = cgroup.v1_paths.get("cpuset") {
            let cpus_path = format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", cpuset_path);
            provenance.paths_tried.push(cpus_path.clone());

            if let Some(count) = read_cpuset_file(&cpus_path) {
                provenance.cpuset_source = CpusetSource::CgroupV1;
                return Some(count);
            }
        }
    }

    // Try reading from /proc/[pid]/cpuset directly
    let cpuset_path = format!("/proc/{}/cpuset", pid);
    provenance.paths_tried.push(cpuset_path.clone());

    if let Ok(content) = fs::read_to_string(&cpuset_path) {
        let cgroup_path = content.trim();
        if !cgroup_path.is_empty() && cgroup_path != "/" {
            // Try both v2 and v1 locations
            let v2_path = format!("/sys/fs/cgroup{}/cpuset.cpus", cgroup_path);
            let v1_path = format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", cgroup_path);

            provenance.paths_tried.push(v2_path.clone());
            if let Some(count) = read_cpuset_file(&v2_path) {
                provenance.cpuset_source = CpusetSource::CgroupV2;
                return Some(count);
            }

            provenance.paths_tried.push(v1_path.clone());
            if let Some(count) = read_cpuset_file(&v1_path) {
                provenance.cpuset_source = CpusetSource::CgroupV1;
                return Some(count);
            }
        }
    }

    None
}

/// Read and parse a cpuset.cpus file.
fn read_cpuset_file(path: &str) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();

    if trimmed.is_empty() {
        return None;
    }

    Some(count_cpus_in_list(trimmed))
}

/// Get the number of logical CPUs on the system.
pub fn num_logical_cpus() -> u32 {
    // Try /proc/cpuinfo first
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        let count = content.lines().filter(|l| l.starts_with("processor")).count();
        if count > 0 {
            return count as u32;
        }
    }

    // Fall back to libc sysconf
    #[cfg(unix)]
    {
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if cpus > 0 {
            return cpus as u32;
        }
    }

    // Ultimate fallback
    1
}

/// Compute N_eff_cores directly from individual constraints.
///
/// This is a convenience function when you have the constraints already.
pub fn compute_n_eff(
    affinity_cores: Option<u32>,
    cpuset_cores: Option<u32>,
    quota_cores: Option<f64>,
    logical_cpus: u32,
) -> f64 {
    let mut n_eff = logical_cpus as f64;

    if let Some(aff) = affinity_cores {
        n_eff = n_eff.min(aff as f64);
    }

    if let Some(cpus) = cpuset_cores {
        n_eff = n_eff.min(cpus as f64);
    }

    if let Some(quota) = quota_cores {
        n_eff = n_eff.min(quota);
    }

    n_eff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_cpus_single() {
        assert_eq!(count_cpus_in_list("0"), 1);
        assert_eq!(count_cpus_in_list("5"), 1);
    }

    #[test]
    fn test_count_cpus_range() {
        assert_eq!(count_cpus_in_list("0-3"), 4);
        assert_eq!(count_cpus_in_list("0-7"), 8);
        assert_eq!(count_cpus_in_list("4-7"), 4);
    }

    #[test]
    fn test_count_cpus_mixed() {
        assert_eq!(count_cpus_in_list("0,2,4"), 3);
        assert_eq!(count_cpus_in_list("0-3,5"), 5);
        assert_eq!(count_cpus_in_list("0-3,5,7-9"), 8);
        assert_eq!(count_cpus_in_list("0,2,4-6,8"), 6);
    }

    #[test]
    fn test_count_cpus_whitespace() {
        assert_eq!(count_cpus_in_list(" 0 - 3 "), 4);
        assert_eq!(count_cpus_in_list("0, 2, 4"), 3);
    }

    #[test]
    fn test_count_cpus_empty() {
        assert_eq!(count_cpus_in_list(""), 0);
        assert_eq!(count_cpus_in_list("   "), 0);
    }

    #[test]
    fn test_parse_cpus_allowed_list() {
        let content = r#"Name:	bash
State:	S (sleeping)
Tgid:	1234
Pid:	1234
PPid:	1
Cpus_allowed:	ffffffff
Cpus_allowed_list:	0-31
Mems_allowed:	00000001
"#;

        let count = parse_cpus_allowed_list(content);
        assert_eq!(count, Some(32));
    }

    #[test]
    fn test_parse_cpus_allowed_list_restricted() {
        let content = r#"Name:	worker
Cpus_allowed_list:	0-3,8-11
"#;

        let count = parse_cpus_allowed_list(content);
        assert_eq!(count, Some(8)); // 4 + 4
    }

    #[test]
    fn test_parse_cpus_allowed_list_single() {
        let content = "Cpus_allowed_list:\t2\n";
        let count = parse_cpus_allowed_list(content);
        assert_eq!(count, Some(1));
    }

    #[test]
    fn test_parse_cpus_allowed_list_missing() {
        let content = "Name:\tbash\nPid:\t1234\n";
        let count = parse_cpus_allowed_list(content);
        assert_eq!(count, None);
    }

    #[test]
    fn test_compute_n_eff_all_none() {
        let n_eff = compute_n_eff(None, None, None, 8);
        assert_eq!(n_eff, 8.0);
    }

    #[test]
    fn test_compute_n_eff_affinity_only() {
        let n_eff = compute_n_eff(Some(4), None, None, 8);
        assert_eq!(n_eff, 4.0);
    }

    #[test]
    fn test_compute_n_eff_cpuset_only() {
        let n_eff = compute_n_eff(None, Some(2), None, 8);
        assert_eq!(n_eff, 2.0);
    }

    #[test]
    fn test_compute_n_eff_quota_only() {
        let n_eff = compute_n_eff(None, None, Some(0.5), 8);
        assert_eq!(n_eff, 0.5);
    }

    #[test]
    fn test_compute_n_eff_min_of_all() {
        // Affinity: 4, cpuset: 6, quota: 2.0 -> min is 2.0
        let n_eff = compute_n_eff(Some(4), Some(6), Some(2.0), 8);
        assert_eq!(n_eff, 2.0);
    }

    #[test]
    fn test_compute_n_eff_affinity_is_min() {
        // Affinity: 2, cpuset: 4, quota: 3.0 -> min is 2
        let n_eff = compute_n_eff(Some(2), Some(4), Some(3.0), 8);
        assert_eq!(n_eff, 2.0);
    }

    #[test]
    fn test_compute_n_eff_cpuset_is_min() {
        // Affinity: 4, cpuset: 1, quota: 3.0 -> min is 1
        let n_eff = compute_n_eff(Some(4), Some(1), Some(3.0), 8);
        assert_eq!(n_eff, 1.0);
    }

    #[test]
    fn test_binding_constraint_tracking() {
        let capacity = CpuCapacity {
            n_eff_cores: 2.0,
            affinity_cores: Some(4),
            cpuset_cores: Some(8),
            quota_cores: Some(2.0),
            provenance: CpuCapacityProvenance {
                binding_constraint: BindingConstraint::Quota,
                ..Default::default()
            },
        };

        assert_eq!(capacity.provenance.binding_constraint, BindingConstraint::Quota);
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_num_logical_cpus() {
        let cpus = num_logical_cpus();
        assert!(cpus >= 1);
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_compute_cpu_capacity_self() {
        let pid = std::process::id();
        let capacity = compute_cpu_capacity(pid, None);

        assert!(capacity.n_eff_cores >= 1.0);
        // Affinity should be available for our own process
        assert!(capacity.affinity_cores.is_some());
    }
}
