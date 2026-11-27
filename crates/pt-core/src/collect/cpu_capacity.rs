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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

const CAPACITY_MAX_THREADS: usize = 256;
const CAPACITY_MAX_MASK_RANGES: usize = 32_768;
const CAPACITY_MAX_FILE_BYTES: usize = 64 * 1024;
const CAPACITY_MAX_MOUNT_BYTES: usize = 2 * 1024 * 1024;
const CAPACITY_PROCESS_BUDGET: Duration = Duration::from_millis(50);
const CAPACITY_SCAN_BUDGET: Duration = Duration::from_millis(500);

/// Complete endpoint observations for inference, unlike the best-effort
/// capacity hints returned by `compute_cpu_capacity` to diagnostic callers.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct CpuCapacitySample {
    pub online_cores: u32,
    pub online: Vec<(u32, u32)>,
    pub affinity_cores: u32,
    pub quota_cores: Option<f64>,
    pub threads: u32,
    pub affinity_parallelism: Option<u32>,
    pub membership: String,
    pub tasks: Vec<TaskAffinity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TaskAffinity {
    pub tid: u32,
    pub start_ticks: u64,
    pub mask: Vec<(u32, u32)>,
}

impl CpuCapacitySample {
    pub fn effective_cores(&self) -> f64 {
        // Cpus_allowed_list is already the effective affinity/cpuset mask.
        // Do not read a guessed /sys/fs/cgroup cpuset path in another namespace.
        compute_n_eff(
            Some(self.affinity_cores),
            None,
            self.quota_cores,
            self.online_cores,
        )
    }
}

/// One shared capacity view per activity-window endpoint. CPU quota hierarchies
/// are read once per observed membership, not once per process or thread.
pub(super) struct CpuCapacitySampler {
    started: Instant,
    online: Result<Vec<(u32, u32)>, String>,
    mountinfo: Result<String, String>,
    quotas: HashMap<String, Result<Option<f64>, String>>,
}

impl CpuCapacitySampler {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            online: read_capacity_text(
                Path::new("/sys/devices/system/cpu/online"),
                CAPACITY_MAX_FILE_BYTES,
            )
            .and_then(|list| parse_observed_affinity(&format!("Cpus_allowed_list:{list}"))),
            mountinfo: read_capacity_text(
                Path::new("/proc/self/mountinfo"),
                CAPACITY_MAX_MOUNT_BYTES,
            ),
            quotas: HashMap::new(),
        }
    }

    pub fn observe(&mut self, pid: u32, threads: u32) -> Result<CpuCapacitySample, String> {
        let started = Instant::now();
        capacity_budget(started, self.started)?;
        let online = self.online.as_ref().map_err(Clone::clone)?;
        let online_cores = affinity_count(online)?;
        let root = std::path::PathBuf::from(format!("/proc/{pid}"));
        let membership = read_capacity_membership(&root.join("cgroup"))?;
        let quota_cores = if let Some(cached) = self.quotas.get(&membership) {
            cached.clone()
        } else {
            let observed = self
                .mountinfo
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|mountinfo| observed_quota(&membership, mountinfo));
            self.quotas.insert(membership.clone(), observed.clone());
            observed
        }?;
        capacity_budget(started, self.started)?;
        let tasks = read_capacity_tasks(&root.join("task"), threads)?;
        let mut observed_tasks = Vec::with_capacity(tasks.len());
        let mut range_count = 0;
        for tid in &tasks {
            capacity_budget(started, self.started)?;
            let task = root.join("task").join(tid.to_string());
            let starttime = read_capacity_starttime(&task.join("stat"), *tid)?;
            let status = read_capacity_text(&task.join("status"), CAPACITY_MAX_FILE_BYTES)?;
            let mask = parse_observed_affinity(&status)?;
            range_count += mask.len();
            if range_count > CAPACITY_MAX_MASK_RANGES {
                return Err("thread affinity masks exceed CPU capacity inspection limit".into());
            }
            if read_capacity_membership(&task.join("cgroup"))? != membership {
                return Err("threads have different CPU cgroup memberships".into());
            }
            observed_tasks.push(TaskAffinity {
                tid: *tid,
                start_ticks: starttime,
                mask,
            });
        }
        // A thread that exits or changes affinity/membership during inspection
        // must not lend a capacity denominator to the original process.
        for observed in &observed_tasks {
            capacity_budget(started, self.started)?;
            let task = root.join("task").join(observed.tid.to_string());
            let status = read_capacity_text(&task.join("status"), CAPACITY_MAX_FILE_BYTES)?;
            if read_capacity_starttime(&task.join("stat"), observed.tid)? != observed.start_ticks
                || parse_observed_affinity(&status)? != observed.mask
                || read_capacity_membership(&task.join("cgroup"))? != membership
            {
                return Err(
                    "thread identity, affinity or cgroup changed during capacity sampling".into(),
                );
            }
        }
        capacity_budget(started, self.started)?;
        if read_capacity_tasks(&root.join("task"), threads)? != tasks
            || read_capacity_membership(&root.join("cgroup"))? != membership
        {
            return Err("thread inventory or cgroup changed during capacity sampling".into());
        }
        capacity_budget(started, self.started)?;
        let (affinity_cores, affinity_parallelism) = thread_affinity_capacity(
            &observed_tasks,
            online,
            || capacity_budget(started, self.started),
        )?;
        Ok(CpuCapacitySample {
            online_cores,
            online: online.clone(),
            affinity_cores,
            quota_cores,
            threads,
            affinity_parallelism,
            membership,
            tasks: observed_tasks,
        })
    }
}

fn capacity_budget(started: Instant, scan_started: Instant) -> Result<(), String> {
    if scan_started.elapsed() > CAPACITY_SCAN_BUDGET {
        Err("shared CPU capacity scan budget exhausted".into())
    } else if started.elapsed() > CAPACITY_PROCESS_BUDGET {
        Err("CPU capacity inspection budget exhausted".into())
    } else {
        Ok(())
    }
}

fn read_capacity_text(path: &Path, limit: usize) -> Result<String, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit as u64 + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!(
            "CPU capacity evidence exceeds byte limit: {}",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("non-UTF-8 CPU capacity evidence: {}", path.display()))
}

fn read_capacity_membership(path: &Path) -> Result<String, String> {
    let content = read_capacity_text(path, CAPACITY_MAX_FILE_BYTES)?;
    if content.is_empty()
        || content.lines().any(|line| {
            let fields: Vec<_> = line.splitn(3, ':').collect();
            fields.len() != 3 || fields[0].parse::<u32>().is_err() || !fields[2].starts_with('/')
        })
    {
        return Err("CPU cgroup membership is invalid or incomplete".into());
    }
    Ok(content)
}

fn observed_quota(membership: &str, mountinfo: &str) -> Result<Option<f64>, String> {
    let mut details =
        super::cgroup::collect_cgroup_from_content(membership, "activity_window", None)
            .ok_or("cannot parse CPU cgroup membership")?;
    super::cgroup::collect_cpu_limits_from_mounts(&mut details, mountinfo);
    let limits = details
        .cpu_limits
        .filter(|limits| limits.quota_hierarchy_complete)
        .ok_or("complete CPU quota hierarchy is unavailable (including hidden ancestors)")?;
    if limits
        .effective_cores
        .is_some_and(|cores| !cores.is_finite() || cores <= 0.0)
    {
        return Err("observed CPU quota is not positive and finite".into());
    }
    Ok(limits.effective_cores)
}

fn read_capacity_tasks(root: &Path, threads: u32) -> Result<Vec<u32>, String> {
    if threads == 0 || threads as usize > CAPACITY_MAX_THREADS {
        return Err("thread count is zero or exceeds CPU capacity inspection limit".into());
    }
    let entries =
        fs::read_dir(root).map_err(|error| format!("cannot inspect thread inventory: {error}"))?;
    let mut tasks = Vec::new();
    for entry in entries {
        if tasks.len() >= CAPACITY_MAX_THREADS {
            return Err("thread inventory exceeds CPU capacity inspection limit".into());
        }
        let entry = entry.map_err(|error| format!("incomplete thread inventory: {error}"))?;
        let tid = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .filter(|tid| *tid > 0)
            .ok_or("invalid thread inventory entry")?;
        tasks.push(tid);
    }
    tasks.sort_unstable();
    if tasks.len() != threads as usize {
        return Err("thread inventory differs from sampled thread count".into());
    }
    Ok(tasks)
}

fn read_capacity_starttime(path: &Path, tid: u32) -> Result<u64, String> {
    let content = read_capacity_text(path, CAPACITY_MAX_FILE_BYTES)?;
    let parse = || -> Option<u64> {
        let start = content.find('(')?;
        if content[..start].trim().parse::<u32>().ok()? != tid {
            return None;
        }
        let fields = content.get(content.rfind(')')? + 1..)?;
        fields.split_whitespace().nth(19)?.parse().ok()
    };
    parse().ok_or_else(|| "invalid thread identity during CPU capacity inspection".into())
}

/// Strict complete affinity parsing for inference; malformed fragments must not
/// silently reduce the capacity as the legacy best-effort count helper can.
fn parse_observed_affinity(status: &str) -> Result<Vec<(u32, u32)>, String> {
    let mut fields = status
        .lines()
        .filter_map(|line| line.strip_prefix("Cpus_allowed_list:"));
    let list = fields.next().ok_or("CPU affinity is unavailable")?.trim();
    if fields.next().is_some() || list.is_empty() {
        return Err("CPU affinity is empty or duplicated".into());
    }
    let mut intervals = Vec::new();
    for entry in list.split(',') {
        let (first, last) = entry
            .trim()
            .split_once('-')
            .unwrap_or((entry.trim(), entry.trim()));
        let first = first
            .parse::<u32>()
            .map_err(|_| "invalid CPU affinity range")?;
        let last = last
            .parse::<u32>()
            .map_err(|_| "invalid CPU affinity range")?;
        if last < first {
            return Err("reversed CPU affinity range".into());
        }
        intervals.push((first, last));
    }
    intervals.sort_unstable();
    let mut canonical: Vec<(u32, u32)> = Vec::new();
    for (first, last) in intervals {
        if let Some(previous) = canonical.last_mut() {
            if first <= previous.1 {
                return Err("overlapping CPU affinity ranges".into());
            }
            if previous.1.checked_add(1) == Some(first) {
                previous.1 = last;
                continue;
            }
        }
        canonical.push((first, last));
    }
    affinity_count(&canonical)?;
    Ok(canonical)
}

fn affinity_count(intervals: &[(u32, u32)]) -> Result<u32, String> {
    intervals.iter().try_fold(0u32, |total, (first, last)| {
        last.checked_sub(*first)
            .and_then(|size| size.checked_add(1))
            .and_then(|size| total.checked_add(size))
            .filter(|total| *total > 0)
            .ok_or_else(|| "CPU affinity size is invalid or overflows".into())
    })
}

fn online_affinity(
    affinity: &[(u32, u32)],
    online: &[(u32, u32)],
) -> Result<Vec<(u32, u32)>, String> {
    let mut intersection = Vec::new();
    let (mut left, mut right) = (0, 0);
    while left < affinity.len() && right < online.len() {
        let first = affinity[left].0.max(online[right].0);
        let last = affinity[left].1.min(online[right].1);
        if first <= last {
            intersection.push((first, last));
        }
        if affinity[left].1 <= online[right].1 {
            left += 1;
        } else {
            right += 1;
        }
    }
    if intersection.is_empty() {
        return Err("CPU affinity has no observed online CPUs".into());
    }
    Ok(intersection)
}

/// Count online CPUs in the union, then find how many threads can actually
/// run on distinct CPUs. Two workers pinned to CPU 0 cannot fill two cores
/// just because a third worker is allowed to run anywhere.
fn thread_affinity_capacity(
    tasks: &[TaskAffinity],
    online: &[(u32, u32)],
    budget: impl Fn() -> Result<(), String>,
) -> Result<(u32, Option<u32>), String> {
    let first = tasks
        .first()
        .ok_or("no complete thread affinity observation")?;
    if tasks.iter().all(|task| task.mask == first.mask) {
        let count = affinity_count(&online_affinity(&first.mask, online)?)?;
        return Ok((count, None));
    }

    let mut union = Vec::new();
    let mut choices = Vec::with_capacity(tasks.len());
    for task in tasks {
        budget()?;
        let mask = online_affinity(&task.mask, online)?;
        // There are at most N-1 other threads. Keeping any N distinct CPUs
        // per thread therefore preserves the maximum matching, even for a
        // range spanning billions of CPU IDs.
        choices.push(
            mask.iter()
                .flat_map(|&(lo, hi)| lo..=hi)
                .take(tasks.len())
                .collect(),
        );
        if union.len() + mask.len() > CAPACITY_MAX_MASK_RANGES {
            return Err("online thread affinity ranges exceed CPU capacity inspection limit".into());
        }
        union.extend(mask);
    }
    union.sort_unstable();
    let mut disjoint: Vec<(u32, u32)> = Vec::new();
    for (lo, hi) in union {
        if let Some(last) = disjoint.last_mut() {
            if lo <= last.1.saturating_add(1) {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        disjoint.push((lo, hi));
    }
    let affinity_cores = affinity_count(&disjoint)?;
    let mut owners = HashMap::new();
    for task in 0..tasks.len() {
        budget()?;
        assign_cpu(task, &choices, &mut owners, &mut HashSet::new(), &budget)?;
    }
    Ok((affinity_cores, Some(owners.len() as u32)))
}

/// Find an augmenting path from the new task to an unoccupied CPU.
fn assign_cpu(
    task: usize,
    choices: &[Vec<u32>],
    owners: &mut HashMap<u32, usize>,
    visited: &mut HashSet<u32>,
    budget: &impl Fn() -> Result<(), String>,
) -> Result<bool, String> {
    budget()?;
    for &cpu in &choices[task] {
        if let std::collections::hash_map::Entry::Vacant(slot) = owners.entry(cpu) {
            slot.insert(task);
            return Ok(true);
        }
    }
    for &cpu in &choices[task] {
        if visited.insert(cpu) && assign_cpu(owners[&cpu], choices, owners, visited, budget)? {
            owners.insert(cpu, task);
            return Ok(true);
        }
    }
    Ok(false)
}

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
    /// From /proc/\[pid\]/status Cpus_allowed_list.
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
        capacity
            .provenance
            .warnings
            .extend(cgroup.provenance.warnings.iter().cloned());
        if let Some(ref cpu_limits) = cgroup.cpu_limits {
            if let Some(path) = &cpu_limits.effective_limit_path {
                capacity.provenance.paths_tried.push(path.clone());
            }
            if let Some(eff_cores) = cpu_limits.effective_cores {
                if eff_cores.is_finite() && eff_cores > 0.0 {
                    capacity.quota_cores = Some(eff_cores);
                    capacity.provenance.quota_source = match cpu_limits.source {
                        super::cgroup::CpuLimitSource::CgroupV2CpuMax => {
                            QuotaSource::CgroupV2CpuMax
                        }
                        super::cgroup::CpuLimitSource::CgroupV1Cfs => QuotaSource::CgroupV1Cfs,
                        super::cgroup::CpuLimitSource::None => QuotaSource::None,
                    };
                } else {
                    capacity
                        .provenance
                        .warnings
                        .push("invalid observed CPU quota".into());
                }
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

    let bytes = fs::read(&path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let affinity = parse_cpus_allowed_list(&content)?;

    provenance.affinity_source = AffinitySource::ProcStatus;
    Some(affinity)
}

/// Parse Cpus_allowed_list from /proc/\[pid\]/status content.
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

    if let Ok(bytes) = fs::read(&cpuset_path) {
        let content = String::from_utf8_lossy(&bytes);
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
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let trimmed = content.trim();

    if trimmed.is_empty() {
        return None;
    }

    Some(count_cpus_in_list(trimmed))
}

/// Get the number of logical CPUs on the system.
/// Uses one CPU as a conservative fallback for capacity heuristics. Consumers
/// that need an observation must use `observed_logical_cpus` instead.
pub fn num_logical_cpus() -> u32 {
    observed_logical_cpus().unwrap_or(1)
}

/// Observe the number of online logical CPUs without inventing a fallback.
pub fn observed_logical_cpus() -> Option<u32> {
    // Try /proc/cpuinfo first
    if let Ok(bytes) = fs::read("/proc/cpuinfo") {
        let content = String::from_utf8_lossy(&bytes);
        let count = content
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count();
        if count > 0 {
            return u32::try_from(count).ok();
        }
    }

    // Fall back to libc sysconf
    #[cfg(unix)]
    {
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if cpus > 0 {
            return u32::try_from(cpus).ok();
        }
    }

    None
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
    fn observed_affinity_requires_complete_nonoverlapping_nonempty_ranges() {
        let compact =
            parse_observed_affinity("Name:\tworker\nCpus_allowed_list:\t0-3,5\n").unwrap();
        let expanded = parse_observed_affinity("Cpus_allowed_list:\t0,1,2,3,5\n").unwrap();
        assert_eq!(compact, expanded);
        assert_eq!(affinity_count(&compact).unwrap(), 5);
        for list in [
            "",
            "0,",
            "bad",
            "0-3,bad",
            "5-2",
            "0-3,2-4",
            "0,0",
            "0-4294967295",
        ] {
            assert!(
                parse_observed_affinity(&format!("Cpus_allowed_list:\t{list}\n")).is_err(),
                "{list:?} must not become a smaller fabricated capacity"
            );
        }
        assert!(parse_observed_affinity("Name:\tworker\n").is_err());
        assert!(parse_observed_affinity("Cpus_allowed_list:\t0\nCpus_allowed_list:\t1\n").is_err());
    }

    #[test]
    fn online_affinity_uses_cpu_ids_instead_of_minimum_mask_sizes() {
        assert_eq!(online_affinity(&[(0, 3)], &[(2, 5)]).unwrap(), vec![(2, 3)]);
        assert_eq!(
            online_affinity(&[(0, 3), (8, 11)], &[(1, 2), (4, 9)]).unwrap(),
            vec![(1, 2), (8, 9)]
        );
        assert!(online_affinity(&[(0, 3)], &[(4, 7)]).is_err());
        assert!(online_affinity(&[], &[(0, 3)]).is_err());
    }

    #[test]
    fn heterogeneous_masks_measure_simultaneously_placeable_threads() {
        let capacity = |ranges: &[(u32, u32)], online| {
            let tasks: Vec<_> = ranges
                .iter()
                .enumerate()
                .map(|(index, &range)| TaskAffinity {
                    tid: index as u32 + 1,
                    start_ticks: 100,
                    mask: vec![range],
                })
                .collect();
            thread_affinity_capacity(&tasks, &[online], || Ok(()))
        };
        // The broad first worker must move off CPU 0 for the pinned worker.
        assert_eq!(capacity(&[(0, 1), (0, 0)], (0, 7)).unwrap(), (2, Some(2)));
        // A union-size or thread-count denominator would incorrectly use 3.
        assert_eq!(
            capacity(&[(0, 0), (0, 0), (0, 7)], (0, 7)).unwrap(),
            (8, Some(2))
        );
        // Disjoint pinned workers can both run, and offline IDs do not count.
        assert_eq!(capacity(&[(0, 1), (2, 3)], (1, 2)).unwrap(), (2, Some(2)));
        assert!(capacity(&[(0, 0), (2, 3)], (1, 2)).is_err());
        // A huge legal mask is represented by ranges and bounded choices.
        assert_eq!(
            capacity(&[(0, u32::MAX - 1), (0, 0)], (0, u32::MAX - 1)).unwrap(),
            (u32::MAX, Some(2))
        );
        // The homogeneous fast path preserves the legacy observation.
        assert_eq!(capacity(&[(0, 3), (0, 3)], (0, 7)).unwrap(), (4, None));
    }

    #[test]
    fn capacity_quota_rejects_hidden_or_unreadable_hierarchies() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("cgroup.controllers"), "cpu\n").unwrap();
        fs::create_dir(directory.path().join("job")).unwrap();
        fs::write(directory.path().join("job/cpu.max"), "10000 100000\n").unwrap();
        fs::write(directory.path().join("job/cpu.weight"), "100\n").unwrap();
        let mountinfo = format!(
            "42 31 0:35 / {} rw - cgroup2 cgroup rw\n",
            directory.path().display()
        );
        assert_eq!(observed_quota("0::/job\n", &mountinfo).unwrap(), Some(0.1));

        // A quota at the purported root proves ancestors are hidden even when
        // mountinfo reports a slash root. Do not infer that this is the limit.
        fs::write(directory.path().join("cpu.max"), "max 100000\n").unwrap();
        assert!(observed_quota("0::/job\n", &mountinfo).is_err());
        let hidden = mountinfo.replacen(" / ", " /hidden ", 1);
        assert!(observed_quota("0::/hidden/job\n", &hidden).is_err());
        assert!(observed_quota("0::/job\n", "").is_err());
    }

    #[test]
    fn capacity_thread_inventory_is_bounded_and_complete() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("12")).unwrap();
        fs::create_dir(directory.path().join("13")).unwrap();
        assert_eq!(
            read_capacity_tasks(directory.path(), 2).unwrap(),
            vec![12, 13]
        );
        assert!(read_capacity_tasks(directory.path(), 1).is_err());
        assert!(read_capacity_tasks(directory.path(), 0).is_err());
        assert!(read_capacity_tasks(directory.path(), CAPACITY_MAX_THREADS as u32 + 1).is_err());
        fs::create_dir(directory.path().join("bad")).unwrap();
        assert!(read_capacity_tasks(directory.path(), 3).is_err());
    }

    #[test]
    fn exhausted_capacity_scan_does_not_probe_later_processes() {
        let mut sampler = CpuCapacitySampler {
            started: Instant::now() - CAPACITY_SCAN_BUDGET - Duration::from_millis(1),
            online: Ok(vec![(0, 7)]),
            mountinfo: Err("must not be consulted".into()),
            quotas: HashMap::new(),
        };
        for pid in [std::process::id(), u32::MAX] {
            let error = sampler.observe(pid, 1).unwrap_err();
            assert_eq!(error, "shared CPU capacity scan budget exhausted");
            assert!(sampler.quotas.is_empty());
        }
    }

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

        assert_eq!(
            capacity.provenance.binding_constraint,
            BindingConstraint::Quota
        );
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
