//! Responsible-unit diagnostics over one observed process census.
//!
//! Units partition the census: a process contributes once, even when an agent,
//! terminal and cgroup overlap. The result is attribution, never authorization
//! to act on a group or credit a single-process action with a group's resources.
//! Rates must come from the caller's shared sampling window; this module does
//! not sleep, collect lifetime CPU, or turn partial observations into totals.

use super::protected::{agent_kind, builtin_protection_match};
use super::{ProcessActivity, ProcessRecord};
use pt_common::StartId;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_UNIT_DIAGNOSTICS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionResource {
    Cpu,
    Memory,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsibleUnitKind {
    TransientScope,
    UserService,
    AgentTree,
    TerminalTree,
    SystemService,
    LoginSession,
    Process,
}

/// An observed identity, not an execution manifest or a proof of current liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttributionIdentity {
    pub pid: u32,
    pub start_id: StartId,
    pub uid: u32,
}

impl AttributionIdentity {
    fn from_process(process: &ProcessRecord) -> Self {
        Self {
            pid: process.pid.0,
            start_id: process.start_id.clone(),
            uid: process.uid,
        }
    }

    fn matches(&self, process: &ProcessRecord) -> bool {
        self.pid == process.pid.0 && self.start_id == process.start_id && self.uid == process.uid
    }
}

/// Cgroup placement bracketed by checks against the scanned incarnation.
#[derive(Debug, Clone, Serialize)]
pub struct CgroupMembership {
    pub pid: u32,
    pub start_id: StartId,
    pub uid: u32,
    pub path: Option<String>,
    pub source: String,
    pub unavailable: Option<String>,
}

impl CgroupMembership {
    fn matches(&self, process: &ProcessRecord) -> bool {
        self.pid == process.pid.0 && self.start_id == process.start_id && self.uid == process.uid
    }
}

/// A complete total is present only when every observed member supplied a value.
/// `observed` is the known subtotal, with its coverage, not a whole-unit estimate.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ObservedTotal {
    pub value: Option<f64>,
    pub observed: Option<f64>,
    pub observed_members: usize,
    pub total_members: usize,
}

impl ObservedTotal {
    fn from_values(values: impl Iterator<Item = Option<f64>>) -> Self {
        let mut result = Self::default();
        let mut sum = 0.0;
        for value in values {
            result.total_members += 1;
            if let Some(value) = valid_nonnegative(value) {
                sum += value;
                result.observed_members += 1;
            }
        }
        if result.observed_members > 0 && sum.is_finite() {
            result.observed = Some(sum);
            if result.observed_members == result.total_members {
                result.value = Some(sum);
            }
        }
        result
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UnitResourceUsage {
    pub cpu_cores: ObservedTotal,
    /// Measured cores / observed online capacity. Values above one remain visible
    /// when sampling skew or changing capacity makes the observations disagree.
    pub cpu_capacity_fraction: Option<f64>,
    pub observed_cpu_capacity_fraction: Option<f64>,
    /// Sum of process RSS; shared pages can be counted more than once.
    pub rss_bytes: ObservedTotal,
    pub swap_bytes: ObservedTotal,
    pub read_bytes_per_second: ObservedTotal,
    pub write_bytes_per_second: ObservedTotal,
    pub major_faults_per_second: ObservedTotal,
    /// These diagnostics cover the leaders, not all threads of each process.
    pub leader_run_queue_wait_seconds_per_second: ObservedTotal,
    pub leader_blkio_delay_seconds_per_second: ObservedTotal,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributedProcess {
    pub identity: AttributionIdentity,
    pub comm: String,
    pub cpu_cores: Option<f64>,
    pub rss_bytes: u64,
    pub swap_bytes: Option<u64>,
    pub read_bytes_per_second: Option<f64>,
    pub write_bytes_per_second: Option<f64>,
    pub major_faults_per_second: Option<f64>,
    pub leader_run_queue_wait_seconds_per_second: Option<f64>,
    pub leader_blkio_delay_seconds_per_second: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponsibleUnit {
    pub id: String,
    pub kind: ResponsibleUnitKind,
    pub label: String,
    pub cgroup_path: Option<String>,
    pub root: Option<AttributionIdentity>,
    pub member_count: usize,
    pub members: Vec<AttributionIdentity>,
    pub usage: UnitResourceUsage,
    pub top_processes: Vec<AttributedProcess>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponsibleUnitTable {
    pub units: Vec<ResponsibleUnit>,
    pub rank_by: AttributionResource,
    pub input_processes: usize,
    pub attributed_processes: usize,
    pub excluded_duplicate_pids: Vec<u32>,
    pub cgroup_memberships_observed: usize,
    pub online_cpus: Option<u32>,
    pub sampling_window_ms: Option<u64>,
    pub unavailable: Vec<String>,
    pub limitations: Vec<&'static str>,
    #[serde(skip)]
    lookup: BTreeMap<u32, (AttributionIdentity, usize)>,
}

impl ResponsibleUnitTable {
    /// A replacement process must never inherit an earlier incarnation's unit.
    pub fn unit_for(&self, process: &ProcessRecord) -> Option<&ResponsibleUnit> {
        let (identity, index) = self.lookup.get(&process.pid.0)?;
        identity
            .matches(process)
            .then(|| self.units.get(*index))
            .flatten()
    }
}

/// Read only cgroup membership and the identity fields needed to bind it.
/// The boot ID is read once per batch; there are no per-process sysfs queries.
pub fn collect_cgroup_memberships(processes: &[ProcessRecord]) -> Vec<CgroupMembership> {
    if cfg!(target_os = "linux") {
        collect_cgroup_memberships_from(processes, Path::new("/proc"))
    } else {
        processes
            .iter()
            .map(|process| {
                membership_result(
                    process,
                    Err("cgroup membership is unavailable on this platform".to_string()),
                )
            })
            .collect()
    }
}

/// Injectable proc root for fixtures. No live host reads escape this root.
pub fn collect_cgroup_memberships_from(
    processes: &[ProcessRecord],
    proc_root: &Path,
) -> Vec<CgroupMembership> {
    let boot = std::fs::read_to_string(proc_root.join("sys/kernel/random/boot_id"))
        .map(|boot| boot.trim().to_string())
        .map_err(|error| format!("boot identity unavailable: {error}"));
    processes
        .iter()
        .map(|process| {
            let result = (|| {
                let boot = boot.as_ref().map_err(Clone::clone)?;
                let (expected_boot, expected_birth) = birth(process)
                    .ok_or_else(|| "scanned process birth identity is unavailable".to_string())?;
                if expected_boot != boot || boot.is_empty() {
                    return Err(
                        "scanned process belongs to a different or unknown boot".to_string()
                    );
                }
                let before = read_binding(proc_root, process.pid.0)?;
                if before.birth != expected_birth
                    || before.uid != process.uid
                    || before.ppid != process.ppid.0
                {
                    return Err("process identity or parent changed since the census".to_string());
                }
                let content = std::fs::read_to_string(
                    proc_root.join(process.pid.0.to_string()).join("cgroup"),
                )
                .map_err(|error| format!("cgroup membership unreadable: {error}"))?;
                let membership = parse_cgroup_membership(&content)?;
                let after = read_binding(proc_root, process.pid.0)?;
                if before != after {
                    return Err(
                        "process identity or parent changed while reading membership".to_string(),
                    );
                }
                Ok(membership)
            })();
            membership_result(process, result)
        })
        .collect()
}

fn membership_result(
    process: &ProcessRecord,
    result: Result<(String, &'static str), String>,
) -> CgroupMembership {
    let (path, source, unavailable) = match result {
        Ok((path, source)) => (Some(path), source.to_string(), None),
        Err(reason) => (None, "unavailable".to_string(), Some(reason)),
    };
    CgroupMembership {
        pid: process.pid.0,
        start_id: process.start_id.clone(),
        uid: process.uid,
        path,
        source,
        unavailable,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Binding {
    birth: u64,
    ppid: u32,
    uid: u32,
    uids: [u32; 4],
}

fn read_binding(root: &Path, pid: u32) -> Result<Binding, String> {
    if pid == 0 {
        return Err("invalid process ID".to_string());
    }
    let directory = root.join(pid.to_string());
    let stat = std::fs::read_to_string(directory.join("stat"))
        .map_err(|error| format!("process stat unreadable: {error}"))?;
    let status = std::fs::read_to_string(directory.join("status"))
        .map_err(|error| format!("process owner unreadable: {error}"))?;
    let invalid = || "process birth/owner evidence is missing or invalid".to_string();
    let open = stat.find('(').ok_or_else(invalid)?;
    let close = stat
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(invalid)?;
    if stat[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err("process identity mismatch".to_string());
    }
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    if fields.first().is_none_or(|state| {
        !matches!(
            *state,
            "R" | "S" | "D" | "Z" | "T" | "t" | "X" | "x" | "K" | "W" | "P" | "I"
        )
    }) {
        return Err(invalid());
    }
    let birth = fields
        .get(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    let ppid = fields
        .get(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let uids = uid_lines
        .next()
        .ok_or_else(invalid)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let uids: [u32; 4] = uids.try_into().map_err(|_| invalid())?;
    if uid_lines.next().is_some() {
        return Err(invalid());
    }
    Ok(Binding {
        birth,
        ppid,
        uid: uids[0],
        uids,
    })
}

fn parse_cgroup_membership(content: &str) -> Result<(String, &'static str), String> {
    let mut unified = BTreeSet::new();
    let mut systemd = BTreeSet::new();
    for line in content.lines() {
        let mut fields = line.splitn(3, ':');
        if let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        {
            if hierarchy == "0" && controllers.is_empty() {
                unified.insert(path);
            } else if controllers
                .split(',')
                .any(|controller| controller == "name=systemd")
            {
                systemd.insert(path);
            }
        }
    }
    let (paths, source) = if unified.is_empty() {
        (systemd, "cgroup_v1_systemd")
    } else {
        (unified, "cgroup_v2")
    };
    if paths.len() != 1 {
        return Err("no unambiguous unified/systemd cgroup membership".to_string());
    }
    normalize_cgroup_path(paths.first().copied().unwrap_or_default())
        .map(|path| (path, source))
        .ok_or_else(|| "invalid cgroup path".to_string())
}

fn normalize_cgroup_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.len() > 4096 || path.chars().any(char::is_control) {
        return None;
    }
    let components: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    if components.iter().any(|part| matches!(*part, "." | "..")) {
        return None;
    }
    Some(format!("/{}", components.join("/")))
}

fn birth(process: &ProcessRecord) -> Option<(&str, u64)> {
    let mut parts = process.start_id.0.split(':');
    let boot = parts.next()?;
    let birth: u64 = parts.next()?.parse().ok()?;
    let pid: u32 = parts.next()?.parse().ok()?;
    (parts.next().is_none() && !boot.is_empty() && birth > 0 && pid == process.pid.0 && pid > 0)
        .then_some((boot, birth))
}

fn valid_nonnegative(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value >= 0.0)
}

#[derive(Clone)]
struct UnitDescriptor {
    id: String,
    kind: ResponsibleUnitKind,
    label: String,
    cgroup_path: Option<String>,
    root: Option<AttributionIdentity>,
}

fn cgroup_unit(path: &str, uid: u32) -> Option<UnitDescriptor> {
    let components: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    let manager = components
        .iter()
        .position(|part| part.starts_with("user@") && part.ends_with(".service"));
    let unit = components
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, part)| {
            let transient = part.ends_with(".scope")
                && ["run-", "tmux-spawn-", "app-"]
                    .iter()
                    .any(|prefix| part.starts_with(prefix));
            let kind = if transient {
                ResponsibleUnitKind::TransientScope
            } else if part.ends_with(".service") && !part.starts_with("user@") {
                if manager.is_some_and(|manager| manager < index) {
                    ResponsibleUnitKind::UserService
                } else {
                    ResponsibleUnitKind::SystemService
                }
            } else if part.starts_with("session-") && part.ends_with(".scope") {
                ResponsibleUnitKind::LoginSession
            } else if *part == "init.scope" && manager.is_none() {
                ResponsibleUnitKind::SystemService
            } else {
                return None;
            };
            Some((index, *part, kind))
        })?;
    let path = format!("/{}", components[..=unit.0].join("/"));
    Some(UnitDescriptor {
        id: format!("cgroup:{uid}:{path}"),
        kind: unit.2,
        label: unit.1.to_string(),
        cgroup_path: Some(path),
        root: None,
    })
}

fn process_unit(
    process: &ProcessRecord,
    kind: ResponsibleUnitKind,
    label: String,
) -> UnitDescriptor {
    let prefix = match kind {
        ResponsibleUnitKind::AgentTree => "agent",
        ResponsibleUnitKind::TerminalTree => "terminal",
        _ => "process",
    };
    UnitDescriptor {
        id: format!(
            "{prefix}:{}:{}:{}",
            process.uid, process.pid.0, process.start_id
        ),
        kind,
        label,
        cgroup_path: None,
        root: Some(AttributionIdentity::from_process(process)),
    }
}

fn unique_index<T>(values: &[T], pid: impl Fn(&T) -> u32) -> (BTreeMap<u32, &T>, BTreeSet<u32>) {
    let mut index = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for value in values {
        let pid = pid(value);
        if !duplicates.contains(&pid) && index.insert(pid, value).is_some() {
            index.remove(&pid);
            duplicates.insert(pid);
        }
    }
    (index, duplicates)
}

#[derive(Clone, Copy, Default)]
struct Lineage {
    agent: Option<usize>,
    mux: Option<usize>,
    terminal: Option<usize>,
}

/// Partition once, aggregate once, and sort deterministically by observed usage.
/// Duplicate PID evidence is excluded rather than selecting whichever row came
/// first. Parents must have comparable birth identities and the same owner.
pub fn attribute_responsible_units(
    processes: &[ProcessRecord],
    activities: &[ProcessActivity],
    memberships: &[CgroupMembership],
    online_cpus: Option<u32>,
    rank_by: AttributionResource,
) -> ResponsibleUnitTable {
    let (mut process_index, duplicate_pids) = unique_index(processes, |process| process.pid.0);
    process_index.remove(&0);
    let records: Vec<_> = process_index.values().copied().collect();
    let indices: BTreeMap<_, _> = records
        .iter()
        .enumerate()
        .map(|(index, process)| (process.pid.0, index))
        .collect();
    let (activity_index, duplicate_activity) = unique_index(activities, |activity| activity.pid);
    let (membership_index, duplicate_membership) =
        unique_index(memberships, |membership| membership.pid);
    let mut reasons = vec![Vec::new(); records.len()];
    for (index, process) in records.iter().enumerate() {
        if birth(process).is_none() {
            reasons[index].push("process birth identity is unavailable; ancestry cannot establish a responsible root".to_string());
        }
    }
    let mut observed_cgroups = 0;
    let paths: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(index, process)| {
            let membership = membership_index
                .get(&process.pid.0)
                .copied()
                .filter(|membership| membership.matches(process));
            let path = membership
                .and_then(|membership| membership.path.as_deref())
                .and_then(normalize_cgroup_path);
            if path.is_some() {
                observed_cgroups += 1;
            } else {
                let reason = if duplicate_membership.contains(&process.pid.0) {
                    "ambiguous duplicate cgroup membership".to_string()
                } else {
                    membership
                        .and_then(|membership| membership.unavailable.clone())
                        .unwrap_or_else(|| {
                            "cgroup membership missing, invalid, or belongs to another incarnation"
                                .to_string()
                        })
                };
                reasons[index].push(reason);
            }
            path
        })
        .collect();
    let cgroups: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(index, process)| {
            paths[index]
                .as_deref()
                .and_then(|path| cgroup_unit(path, process.uid))
        })
        .collect();
    let agents: Vec<_> = records
        .iter()
        .map(|process| agent_kind(&process.cmd))
        .collect();
    let multiplexers: Vec<_> = records
        .iter()
        .map(|process| {
            builtin_protection_match(&process.comm, &process.cmd)
                .is_some_and(|(rule, _)| rule == "builtin.multiplexer")
        })
        .collect();

    let mut parents: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(index, process)| {
            let Some(parent) = indices.get(&process.ppid.0).copied() else {
                if process.ppid.0 > 1 {
                    reasons[index].push(format!(
                        "parent PID {} is absent or ambiguous in this census",
                        process.ppid.0
                    ));
                }
                return None;
            };
            let ancestor = records[parent];
            let valid_birth = match (birth(process), birth(ancestor)) {
                (Some((boot, started)), Some((parent_boot, parent_started)))
                    if boot == parent_boot =>
                {
                    if matches!(boot, "synthetic" | "unknown") {
                        parent_started < started
                    } else {
                        parent_started <= started
                    }
                }
                _ => false,
            };
            if process.uid != ancestor.uid || !valid_birth {
                reasons[index].push(
                    "ancestry stopped at a different owner or unproven parent birth".to_string(),
                );
                return None;
            }
            if let (Some(child_path), Some(parent_path)) = (&paths[index], &paths[parent]) {
                let child_root = cgroups[index]
                    .as_ref()
                    .and_then(|group| group.cgroup_path.as_ref())
                    .unwrap_or(child_path);
                let parent_root = cgroups[parent]
                    .as_ref()
                    .and_then(|group| group.cgroup_path.as_ref())
                    .unwrap_or(parent_path);
                if child_root != parent_root {
                    reasons[index]
                        .push("ancestry stopped at a different observed cgroup root".to_string());
                    return None;
                }
            }
            Some(parent)
        })
        .collect();
    // Iterative cycle detection avoids recursion limits on long process chains.
    let mut state = vec![0u8; records.len()];
    let mut cyclic = vec![false; records.len()];
    for start in 0..records.len() {
        let mut chain = Vec::new();
        let mut current = Some(start);
        while let Some(index) = current {
            if state[index] == 2 {
                break;
            }
            if state[index] == 1 {
                if let Some(cycle_start) = chain.iter().position(|node| *node == index) {
                    for node in chain[cycle_start..].iter().copied() {
                        cyclic[node] = true;
                        parents[node] = None;
                        reasons[node].push(
                            "cyclic ancestry cannot establish a responsible root".to_string(),
                        );
                    }
                }
                break;
            }
            state[index] = 1;
            chain.push(index);
            current = parents[index];
        }
        for node in chain {
            state[node] = 2;
        }
    }
    let mut lineage = vec![None; records.len()];
    for start in 0..records.len() {
        if lineage[start].is_some() {
            continue;
        }
        let mut chain = Vec::new();
        let mut current = Some(start);
        let mut inherited = Lineage::default();
        while let Some(index) = current {
            if let Some(resolved) = lineage[index] {
                inherited = resolved;
                break;
            }
            chain.push(index);
            current = parents[index];
        }
        for index in chain.into_iter().rev() {
            if cyclic[index] || birth(records[index]).is_none() {
                inherited = Lineage::default();
            } else if multiplexers[index] {
                inherited = Lineage {
                    mux: Some(index),
                    ..Lineage::default()
                };
            } else {
                if inherited.mux.is_some()
                    && inherited.terminal.is_none()
                    && records[index].has_tty()
                {
                    inherited.terminal = Some(index);
                }
                if agents[index].is_some() {
                    inherited.agent = Some(index);
                }
            }
            lineage[index] = Some(inherited);
        }
    }

    let matching_activity: Vec<_> = records
        .iter()
        .map(|process| {
            activity_index
                .get(&process.pid.0)
                .copied()
                .filter(|activity| activity.matches_record(process))
        })
        .collect();
    let windows: BTreeSet<_> = matching_activity
        .iter()
        .flatten()
        .filter(|activity| activity.source == "procfs_window" && activity.requested_window_ms > 0)
        .map(|activity| activity.requested_window_ms)
        .collect();
    let comparable_window = windows.len() <= 1;
    let measurements: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(index, process)| {
            if matching_activity[index].is_none() {
                reasons[index].push(
                    if duplicate_activity.contains(&process.pid.0) {
                        "ambiguous duplicate activity"
                    } else {
                        "activity missing or belongs to another incarnation"
                    }
                    .to_string(),
                );
            }
            process_usage(process, matching_activity[index], comparable_window)
        })
        .collect();

    let mut groups: BTreeMap<String, (UnitDescriptor, Vec<usize>)> = BTreeMap::new();
    for (index, process) in records.iter().enumerate() {
        let inherited = lineage[index].unwrap_or_default();
        let cgroup = cgroups[index].as_ref();
        // A shared mux service/scope is a container for independent terminals
        // and agents, not proof that every pane belongs to one remediation unit.
        let shared_mux = inherited
            .mux
            .filter(|mux| *mux != index)
            .is_some_and(|mux| {
                cgroup
                    .zip(cgroups[mux].as_ref())
                    .is_some_and(|(own, mux_group)| own.id == mux_group.id)
            });
        let primary_cgroup = cgroup.filter(|group| {
            !shared_mux
                && matches!(
                    group.kind,
                    ResponsibleUnitKind::TransientScope | ResponsibleUnitKind::UserService
                )
        });
        let descriptor = if let Some(group) = primary_cgroup {
            group.clone()
        } else if let Some(root) = inherited.agent {
            process_unit(
                records[root],
                ResponsibleUnitKind::AgentTree,
                format!(
                    "{} (PID {})",
                    agents[root].unwrap_or("agent"),
                    records[root].pid.0
                ),
            )
        } else if let Some(root) = inherited.terminal {
            process_unit(
                records[root],
                ResponsibleUnitKind::TerminalTree,
                format!(
                    "terminal subtree {} (PID {})",
                    records[root].tty.as_deref().unwrap_or("unknown"),
                    records[root].pid.0
                ),
            )
        } else if let Some(group) = cgroup {
            group.clone()
        } else {
            process_unit(
                process,
                ResponsibleUnitKind::Process,
                format!("{} (PID {})", process.comm, process.pid.0),
            )
        };
        groups
            .entry(descriptor.id.clone())
            .or_insert_with(|| (descriptor, Vec::new()))
            .1
            .push(index);
    }
    let online_cpus = online_cpus.filter(|cpus| *cpus > 0);
    let mut units: Vec<_> = groups
        .into_values()
        .map(|(descriptor, indices)| {
            let member_usage: Vec<_> = indices.iter().map(|index| &measurements[*index]).collect();
            let usage = aggregate_usage(&member_usage, online_cpus);
            let mut unavailable = Vec::new();
            for index in &indices {
                for reason in &reasons[*index] {
                    if unavailable.len() < MAX_UNIT_DIAGNOSTICS {
                        unavailable.push(format!("PID {}: {reason}", records[*index].pid.0));
                    }
                }
            }
            for (name, total) in [
                ("cpu", &usage.cpu_cores),
                ("swap", &usage.swap_bytes),
                ("read I/O", &usage.read_bytes_per_second),
                ("write I/O", &usage.write_bytes_per_second),
                ("major faults", &usage.major_faults_per_second),
                (
                    "leader run-queue wait",
                    &usage.leader_run_queue_wait_seconds_per_second,
                ),
                (
                    "leader block-I/O delay",
                    &usage.leader_blkio_delay_seconds_per_second,
                ),
            ] {
                if total.value.is_none() {
                    unavailable.push(format!(
                        "{name}: complete total unavailable; {}/{} members observed",
                        total.observed_members, total.total_members
                    ));
                }
            }
            let mut top_processes: Vec<_> = member_usage.into_iter().cloned().collect();
            top_processes.sort_by(|left, right| {
                compare_usage(process_rank(left, rank_by), process_rank(right, rank_by))
                    .then_with(|| right.rss_bytes.cmp(&left.rss_bytes))
                    .then_with(|| left.identity.pid.cmp(&right.identity.pid))
            });
            top_processes.truncate(3);
            ResponsibleUnit {
                id: descriptor.id,
                kind: descriptor.kind,
                label: descriptor.label,
                cgroup_path: descriptor.cgroup_path,
                root: descriptor.root,
                member_count: indices.len(),
                members: indices
                    .iter()
                    .map(|index| measurements[*index].identity.clone())
                    .collect(),
                usage,
                top_processes,
                unavailable,
            }
        })
        .collect();
    units.sort_by(|left, right| {
        compare_usage(unit_rank(left, rank_by), unit_rank(right, rank_by))
            .then_with(|| {
                compare_usage(
                    left.usage.rss_bytes.observed,
                    right.usage.rss_bytes.observed,
                )
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    let lookup = units
        .iter()
        .enumerate()
        .flat_map(|(index, unit)| {
            unit.members
                .iter()
                .map(move |identity| (identity.pid, (identity.clone(), index)))
        })
        .collect();
    let mut unavailable = Vec::new();
    if !duplicate_pids.is_empty() {
        unavailable.push(
            "duplicate PID rows excluded; ancestry cannot use ambiguous incarnations".to_string(),
        );
    }
    if process_index.len() < processes.len() {
        unavailable.push(format!(
            "{} input rows could not be attributed uniquely",
            processes.len() - process_index.len()
        ));
    }
    if online_cpus.is_none() {
        unavailable
            .push("observed online CPU count unavailable; capacity shares are null".to_string());
    }
    if !comparable_window {
        unavailable
            .push("mixed requested sampling windows; aggregate rates are unavailable".to_string());
    }
    if observed_cgroups < records.len() {
        unavailable.push(format!(
            "cgroup placement unavailable for {}/{} observed processes",
            records.len() - observed_cgroups,
            records.len()
        ));
    }
    ResponsibleUnitTable {
        units, rank_by, input_processes: processes.len(), attributed_processes: records.len(),
        excluded_duplicate_pids: duplicate_pids.into_iter().collect(), cgroup_memberships_observed: observed_cgroups,
        online_cpus, sampling_window_ms: (windows.len() == 1).then(|| *windows.first().unwrap()), unavailable,
        limitations: vec![
            "Observed census members only; this is not proof of complete cgroup membership or current liveness.",
            "Diagnostic groups do not authorize group actions or increase relief credit for a single-process action.",
            "RSS is summed process residency, not unique reclaimable memory; swap is reported separately.",
            "Ranking uses observed subtotals with coverage, not invented complete totals for unmeasured members.",
            "CPU and I/O totals require the caller's shared measurement window; lifetime CPU is never aggregated.",
            "Per-cgroup CPU usage deltas, memory.current and PSI are not measured by this member-sum report.",
            "Terminal subtrees are inferred from observed mux/TTY ancestry, not a multiplexer pane-ID query.",
        ],
        lookup,
    }
}

fn process_usage(
    process: &ProcessRecord,
    activity: Option<&ProcessActivity>,
    comparable_window: bool,
) -> AttributedProcess {
    let sampled = activity.filter(|activity| {
        comparable_window && activity.source == "procfs_window" && activity.requested_window_ms > 0
    });
    let cpu = sampled.filter(|activity| {
        valid_window(activity.cpu_window_seconds) && activity.cpu_error.is_none()
    });
    let io = sampled
        .filter(|activity| valid_window(activity.io_window_seconds) && activity.io_error.is_none());
    let pressure = activity.and_then(|activity| activity.pressure.as_ref());
    let memory = pressure
        .filter(|pressure| pressure.memory_error.is_none())
        .and_then(|pressure| pressure.memory.as_ref());
    let sampled_pressure = sampled.and_then(|activity| activity.pressure.as_ref());
    AttributedProcess {
        identity: AttributionIdentity::from_process(process),
        comm: process.comm.clone(),
        cpu_cores: cpu
            .and_then(|activity| valid_nonnegative(activity.cpu_percent))
            .map(|percent| percent / 100.0),
        rss_bytes: memory.map_or(process.rss_bytes, |memory| memory.rss_bytes),
        swap_bytes: memory.map(|memory| memory.swap_bytes),
        read_bytes_per_second: io
            .and_then(|activity| valid_nonnegative(activity.read_bytes_per_second)),
        write_bytes_per_second: io
            .and_then(|activity| valid_nonnegative(activity.write_bytes_per_second)),
        major_faults_per_second: sampled_pressure
            .filter(|pressure| {
                valid_window(pressure.stat_window_seconds) && pressure.faults_error.is_none()
            })
            .and_then(|pressure| valid_nonnegative(pressure.major_faults_per_second)),
        leader_run_queue_wait_seconds_per_second: sampled_pressure
            .filter(|pressure| {
                valid_window(pressure.scheduler_window_seconds)
                    && pressure.scheduler_error.is_none()
            })
            .and_then(|pressure| valid_nonnegative(pressure.leader_run_queue_wait_percent))
            .map(|percent| percent / 100.0),
        leader_blkio_delay_seconds_per_second: sampled_pressure
            .filter(|pressure| {
                valid_window(pressure.stat_window_seconds) && pressure.blkio_error.is_none()
            })
            .and_then(|pressure| valid_nonnegative(pressure.leader_blkio_delay_percent))
            .map(|percent| percent / 100.0),
    }
}

fn valid_window(seconds: Option<f64>) -> bool {
    seconds.is_some_and(|seconds| seconds.is_finite() && seconds > 0.0)
}

fn aggregate_usage(members: &[&AttributedProcess], cpus: Option<u32>) -> UnitResourceUsage {
    let cpu_cores = ObservedTotal::from_values(members.iter().map(|process| process.cpu_cores));
    let share = |cores: Option<f64>| cores.zip(cpus).map(|(cores, cpus)| cores / f64::from(cpus));
    UnitResourceUsage {
        cpu_capacity_fraction: share(cpu_cores.value),
        observed_cpu_capacity_fraction: share(cpu_cores.observed),
        cpu_cores,
        rss_bytes: ObservedTotal::from_values(
            members.iter().map(|process| Some(process.rss_bytes as f64)),
        ),
        swap_bytes: ObservedTotal::from_values(
            members
                .iter()
                .map(|process| process.swap_bytes.map(|bytes| bytes as f64)),
        ),
        read_bytes_per_second: ObservedTotal::from_values(
            members.iter().map(|process| process.read_bytes_per_second),
        ),
        write_bytes_per_second: ObservedTotal::from_values(
            members.iter().map(|process| process.write_bytes_per_second),
        ),
        major_faults_per_second: ObservedTotal::from_values(
            members
                .iter()
                .map(|process| process.major_faults_per_second),
        ),
        leader_run_queue_wait_seconds_per_second: ObservedTotal::from_values(
            members
                .iter()
                .map(|process| process.leader_run_queue_wait_seconds_per_second),
        ),
        leader_blkio_delay_seconds_per_second: ObservedTotal::from_values(
            members
                .iter()
                .map(|process| process.leader_blkio_delay_seconds_per_second),
        ),
    }
}

fn combined_io(read: Option<f64>, write: Option<f64>) -> Option<f64> {
    match (read, write) {
        (None, None) => None,
        (read, write) => valid_nonnegative(Some(read.unwrap_or(0.0) + write.unwrap_or(0.0))),
    }
}

fn process_rank(process: &AttributedProcess, resource: AttributionResource) -> Option<f64> {
    match resource {
        AttributionResource::Cpu => process.cpu_cores,
        AttributionResource::Memory => {
            Some(process.rss_bytes as f64 + process.swap_bytes.unwrap_or(0) as f64)
        }
        AttributionResource::Io => combined_io(
            process.read_bytes_per_second,
            process.write_bytes_per_second,
        ),
    }
}

fn unit_rank(unit: &ResponsibleUnit, resource: AttributionResource) -> Option<f64> {
    match resource {
        AttributionResource::Cpu => unit.usage.cpu_cores.observed,
        AttributionResource::Memory => combined_io(
            unit.usage.rss_bytes.observed,
            unit.usage.swap_bytes.observed,
        ),
        AttributionResource::Io => combined_io(
            unit.usage.read_bytes_per_second.observed,
            unit.usage.write_bytes_per_second.observed,
        ),
    }
}

fn compare_usage(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => right.total_cmp(&left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{ProcessMemoryUsage, ProcessPressureActivity, ProcessState};
    use proptest::prelude::*;
    use pt_common::ProcessId;
    use std::time::Duration;

    const AGENT_SCOPE: &str =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/run-p100-test.scope";

    fn process(pid: u32, ppid: u32, command: &str, ticks: u64) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(ppid),
            uid: 1000,
            user: "user".to_string(),
            pgid: Some(pid),
            sid: Some(10),
            start_id: StartId::from_linux("boot", ticks, pid),
            comm: command
                .split_whitespace()
                .next()
                .unwrap_or(command)
                .to_string(),
            cmd: command.to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 999.0,
            rss_bytes: u64::from(pid) * 1024,
            vsz_bytes: 1 << 30,
            tty: None,
            start_time_unix: 12345,
            elapsed: Duration::from_secs(3600),
            source: "fixture".to_string(),
            container_info: None,
        }
    }

    fn activity(process: &ProcessRecord, cpu: f64) -> ProcessActivity {
        let mut activity =
            ProcessActivity::unavailable(process, Duration::from_millis(500), "fixture");
        activity.source = "procfs_window".to_string();
        activity.cpu_percent = Some(cpu);
        activity.cpu_ticks = Some(1);
        activity.cpu_window_seconds = Some(0.5);
        activity.io_window_seconds = Some(0.5);
        activity.read_bytes_per_second = Some(0.0);
        activity.write_bytes_per_second = Some(4096.0);
        activity.cpu_error = None;
        activity.io_error = None;
        activity.pressure = Some(ProcessPressureActivity {
            memory: Some(ProcessMemoryUsage {
                rss_bytes: process.rss_bytes,
                rss_anon_bytes: process.rss_bytes,
                rss_file_bytes: 0,
                rss_shmem_bytes: 0,
                swap_bytes: 1024,
                threads: 1,
            }),
            stat_window_seconds: Some(0.5),
            major_faults_per_second: Some(2.0),
            scheduler_window_seconds: Some(0.5),
            leader_run_queue_wait_percent: Some(20.0),
            leader_blkio_delay_percent: Some(10.0),
            ..ProcessPressureActivity::default()
        });
        activity
    }

    fn membership(process: &ProcessRecord, path: &str) -> CgroupMembership {
        CgroupMembership {
            pid: process.pid.0,
            start_id: process.start_id.clone(),
            uid: process.uid,
            path: Some(path.to_string()),
            source: "fixture".to_string(),
            unavailable: None,
        }
    }

    fn table(
        processes: &[ProcessRecord],
        activities: &[ProcessActivity],
        groups: &[CgroupMembership],
    ) -> ResponsibleUnitTable {
        attribute_responsible_units(
            processes,
            activities,
            groups,
            Some(8),
            AttributionResource::Cpu,
        )
    }

    fn member_pids(unit: &ResponsibleUnit) -> Vec<u32> {
        unit.members.iter().map(|identity| identity.pid).collect()
    }

    #[test]
    fn agent_scope_aggregates_three_busy_children_once() {
        let processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "rustc", 101),
            process(102, 100, "rustc", 102),
            process(103, 100, "rustc", 103),
        ];
        let samples: Vec<_> = processes
            .iter()
            .enumerate()
            .map(|(index, process)| activity(process, if index == 0 { 0.0 } else { 100.0 }))
            .collect();
        let memberships: Vec<_> = processes
            .iter()
            .map(|process| membership(process, AGENT_SCOPE))
            .collect();
        let result = table(&processes, &samples, &memberships);
        assert_eq!(result.units.len(), 1);
        let unit = &result.units[0];
        assert_eq!(unit.kind, ResponsibleUnitKind::TransientScope);
        assert_eq!(member_pids(unit), vec![100, 101, 102, 103]);
        assert_eq!(unit.usage.cpu_cores.value, Some(3.0));
        assert_eq!(unit.usage.cpu_capacity_fraction, Some(3.0 / 8.0));
        assert_eq!(unit.usage.swap_bytes.value, Some(4096.0));
        assert_eq!(unit.usage.write_bytes_per_second.value, Some(16_384.0));
        assert_eq!(unit.top_processes.len(), 3);
        assert!(unit
            .top_processes
            .iter()
            .all(|process| process.identity.pid != 100));
        for process in &processes {
            assert_eq!(result.unit_for(process).unwrap().id, unit.id);
        }
    }

    #[test]
    fn nearest_nested_agent_roots_form_disjoint_units() {
        let processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "bash", 101),
            process(102, 101, "codex", 102),
            process(103, 102, "rustc", 103),
            process(104, 101, "cargo", 104),
        ];
        let result = table(&processes, &[], &[]);
        assert_eq!(result.units.len(), 2);
        assert_eq!(
            member_pids(result.unit_for(&processes[0]).unwrap()),
            vec![100, 101, 104]
        );
        assert_eq!(
            member_pids(result.unit_for(&processes[2]).unwrap()),
            vec![102, 103]
        );
        assert!(result
            .units
            .iter()
            .all(|unit| unit.kind == ResponsibleUnitKind::AgentTree));
    }

    #[test]
    fn shared_mux_service_does_not_collapse_distinct_agents_and_terminals() {
        let mut processes = vec![
            process(10, 1, "tmux: server", 10),
            process(11, 10, "bash", 11),
            process(12, 11, "codex", 12),
            process(13, 12, "rustc", 13),
            process(20, 10, "bash", 20),
            process(21, 20, "sleep", 21),
        ];
        processes[1].tty = Some("pts/1".to_string());
        processes[2].tty = Some("pts/1".to_string());
        processes[4].tty = Some("pts/2".to_string());
        let memberships: Vec<_> = processes
            .iter()
            .map(|process| {
                membership(
                    process,
                    "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux.service",
                )
            })
            .collect();
        let result = table(&processes, &[], &memberships);
        assert_eq!(result.units.len(), 4);
        assert_eq!(
            member_pids(result.unit_for(&processes[2]).unwrap()),
            vec![12, 13]
        );
        assert_eq!(
            result.unit_for(&processes[2]).unwrap().kind,
            ResponsibleUnitKind::AgentTree
        );
        assert_eq!(
            member_pids(result.unit_for(&processes[4]).unwrap()),
            vec![20, 21]
        );
        assert_eq!(
            result.unit_for(&processes[4]).unwrap().kind,
            ResponsibleUnitKind::TerminalTree
        );
        assert_eq!(
            member_pids(result.unit_for(&processes[0]).unwrap()),
            vec![10]
        );
    }

    #[test]
    fn birth_ticks_owner_and_cgroup_roots_bound_ancestry() {
        let mut processes = vec![
            process(100, 1, "claude", 200),
            process(101, 100, "rustc", 199),
            process(102, 100, "cargo", 200),
            process(103, 100, "rustc", 201),
        ];
        processes[3].uid = 2000;
        // Coarse Unix times deliberately match; tick ordering must reject PID reuse.
        assert_eq!(processes[0].start_time_unix, processes[1].start_time_unix);
        let result = table(&processes, &[], &[]);
        assert_eq!(
            result.unit_for(&processes[1]).unwrap().kind,
            ResponsibleUnitKind::Process
        );
        assert_eq!(
            result.unit_for(&processes[3]).unwrap().kind,
            ResponsibleUnitKind::Process
        );
        assert_eq!(
            member_pids(result.unit_for(&processes[0]).unwrap()),
            vec![100, 102]
        );
        let memberships = vec![
            membership(&processes[0], "/container/one"),
            membership(&processes[2], "/container/two"),
        ];
        let result = table(&processes, &[], &memberships);
        assert_eq!(
            result.unit_for(&processes[2]).unwrap().kind,
            ResponsibleUnitKind::Process
        );
        assert!(result
            .unit_for(&processes[2])
            .unwrap()
            .unavailable
            .iter()
            .any(|reason| reason.contains("different observed cgroup root")));
    }

    #[test]
    fn cycles_and_duplicate_pid_rows_never_establish_agent_ownership() {
        let processes = vec![
            process(100, 101, "claude", 100),
            process(101, 100, "sleep", 100),
            process(102, 100, "rustc", 102),
        ];
        let result = table(&processes, &[], &[]);
        assert_eq!(result.units.len(), 3);
        assert!(result
            .units
            .iter()
            .all(|unit| unit.kind == ResponsibleUnitKind::Process));
        let duplicate = vec![
            process(100, 1, "claude", 100),
            process(100, 1, "codex", 200),
            process(101, 100, "rustc", 300),
        ];
        let result = table(&duplicate, &[], &[]);
        assert_eq!(result.excluded_duplicate_pids, vec![100]);
        assert_eq!(result.attributed_processes, 1);
        assert!(result.unit_for(&duplicate[0]).is_none());
        assert_eq!(
            result.unit_for(&duplicate[2]).unwrap().kind,
            ResponsibleUnitKind::Process
        );
        assert!(result.units[0]
            .unavailable
            .iter()
            .any(|reason| reason.contains("absent or ambiguous")));
    }

    #[test]
    fn shared_slices_and_root_cgroups_are_not_responsible_units() {
        for path in [
            "/",
            "/user.slice",
            "/system.slice",
            "/user.slice/user-1000.slice/user@1000.service/app.slice",
        ] {
            let processes = vec![process(100, 1, "sleep", 100), process(101, 1, "sleep", 101)];
            let memberships: Vec<_> = processes
                .iter()
                .map(|process| membership(process, path))
                .collect();
            let result = table(&processes, &[], &memberships);
            assert_eq!(result.units.len(), 2, "{path}");
            assert!(result
                .units
                .iter()
                .all(|unit| unit.kind == ResponsibleUnitKind::Process));
        }
    }

    #[test]
    fn partial_activity_exposes_known_subtotals_without_fabricating_totals() {
        let processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "rustc", 101),
            process(102, 100, "rustc", 102),
        ];
        let mut samples = vec![
            activity(&processes[0], 0.0),
            activity(&processes[1], 100.0),
            activity(&processes[2], 900.0),
        ];
        samples[1].io_error = Some("I/O permission denied".to_string());
        samples[2].start_id = StartId::from_linux("boot", 999, 102);
        let result = table(&processes, &samples, &[]);
        let usage = &result.units[0].usage;
        assert_eq!(usage.cpu_cores.value, None);
        assert_eq!(usage.cpu_cores.observed, Some(1.0));
        assert_eq!(
            (
                usage.cpu_cores.observed_members,
                usage.cpu_cores.total_members
            ),
            (2, 3)
        );
        assert_eq!(usage.cpu_capacity_fraction, None);
        assert_eq!(usage.observed_cpu_capacity_fraction, Some(0.125));
        assert_eq!(usage.swap_bytes.value, None);
        assert_eq!(usage.swap_bytes.observed, Some(2048.0));
        assert_eq!(usage.write_bytes_per_second.value, None);
        assert_eq!(usage.write_bytes_per_second.observed, Some(4096.0));
        assert_eq!(
            usage.rss_bytes.value,
            Some((100 + 101 + 102) as f64 * 1024.0)
        );
    }

    #[test]
    fn lifetime_and_mixed_window_rates_are_not_aggregated_as_current_cpu() {
        let processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "rustc", 101),
        ];
        let mut samples: Vec<_> = processes
            .iter()
            .map(|process| activity(process, 100.0))
            .collect();
        samples[1].requested_window_ms = 1000;
        let result = table(&processes, &samples, &[]);
        assert_eq!(result.units[0].usage.cpu_cores.observed, None);
        assert_eq!(result.sampling_window_ms, None);
        assert!(result
            .unavailable
            .iter()
            .any(|reason| reason.contains("mixed requested")));
        samples[1].requested_window_ms = 500;
        for sample in &mut samples {
            sample.source = "ps_lifetime_fallback".to_string();
        }
        let result = table(&processes, &samples, &[]);
        assert_eq!(result.units[0].usage.cpu_cores.observed, None);
        assert_eq!(result.units[0].usage.cpu_cores.observed_members, 0);
    }

    #[test]
    fn zero_rates_and_missing_capacity_are_distinct_from_unavailable_activity() {
        let processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "rustc", 101),
        ];
        let samples: Vec<_> = processes
            .iter()
            .map(|process| activity(process, 0.0))
            .collect();
        let result =
            attribute_responsible_units(&processes, &samples, &[], None, AttributionResource::Cpu);
        assert_eq!(result.units[0].usage.cpu_cores.value, Some(0.0));
        assert_eq!(result.units[0].usage.cpu_capacity_fraction, None);
        let absent = table(&processes, &[], &[]);
        assert_eq!(absent.units[0].usage.cpu_cores.value, None);
        assert_eq!(absent.units[0].usage.cpu_cores.observed, None);
    }

    #[test]
    fn duplicate_activity_invalid_rates_and_replaced_memberships_are_unavailable() {
        let processes = vec![process(100, 1, "sleep", 100), process(101, 1, "sleep", 101)];
        let mut samples = vec![
            activity(&processes[0], 100.0),
            activity(&processes[0], 100.0),
            activity(&processes[1], f64::NAN),
        ];
        let mut stale = membership(&processes[0], AGENT_SCOPE);
        stale.start_id = StartId::from_linux("boot", 999, 100);
        let result = table(&processes, &samples, &[stale]);
        assert!(result
            .units
            .iter()
            .all(|unit| unit.usage.cpu_cores.observed.is_none()));
        assert_eq!(result.cgroup_memberships_observed, 0);
        assert_eq!(
            result.unit_for(&processes[0]).unwrap().kind,
            ResponsibleUnitKind::Process
        );
        for invalid in [-1.0, f64::INFINITY] {
            samples[2].cpu_percent = Some(invalid);
            assert_eq!(
                table(&processes, &samples, &[])
                    .unit_for(&processes[1])
                    .unwrap()
                    .usage
                    .cpu_cores
                    .value,
                None
            );
        }
        let mut replacement = processes[0].clone();
        replacement.start_id = StartId::from_linux("boot", 200, 100);
        assert!(result.unit_for(&replacement).is_none());
        replacement = processes[0].clone();
        replacement.uid += 1;
        assert!(result.unit_for(&replacement).is_none());
    }

    #[test]
    fn cgroup_versions_and_unit_kinds_resolve_without_live_reads() {
        for (path, kind) in [
            (AGENT_SCOPE, ResponsibleUnitKind::TransientScope),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-a.scope",
                ResponsibleUnitKind::TransientScope,
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-editor.scope",
                ResponsibleUnitKind::TransientScope,
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service",
                ResponsibleUnitKind::UserService,
            ),
            (
                "/system.slice/sshd.service/worker",
                ResponsibleUnitKind::SystemService,
            ),
            (
                "/user.slice/user-1000.slice/session-2.scope",
                ResponsibleUnitKind::LoginSession,
            ),
            ("/init.scope", ResponsibleUnitKind::SystemService),
        ] {
            assert_eq!(cgroup_unit(path, 1000).unwrap().kind, kind, "{path}");
        }
        assert_eq!(
            parse_cgroup_membership(&format!("4:cpu:/other\n7:name=systemd:{AGENT_SCOPE}\n"))
                .unwrap(),
            (AGENT_SCOPE.to_string(), "cgroup_v1_systemd")
        );
        assert_eq!(
            parse_cgroup_membership(&format!("7:name=systemd:/old\n0::{AGENT_SCOPE}\n")).unwrap(),
            (AGENT_SCOPE.to_string(), "cgroup_v2")
        );
        assert!(parse_cgroup_membership("4:cpu:/container\n").is_err());
        assert!(parse_cgroup_membership("0::/one\n0::/two\n").is_err());
        for path in [
            "relative.scope",
            "/../run-a.scope",
            "/run-a.scope/../b",
            "/bad\0.scope",
        ] {
            assert!(normalize_cgroup_path(path).is_none());
        }
    }

    #[test]
    fn coarse_equal_births_fall_back_but_observed_macos_tree_can_resolve() {
        let mut processes = vec![
            process(100, 1, "claude", 100),
            process(101, 100, "rustc", 101),
        ];
        processes[0].start_id = StartId::from_macos("unknown", 100, 100);
        processes[1].start_id = StartId::from_macos("unknown", 100, 101);
        assert_eq!(
            table(&processes, &[], &[])
                .unit_for(&processes[1])
                .unwrap()
                .kind,
            ResponsibleUnitKind::Process
        );
        processes[1].start_id = StartId::from_macos("unknown", 101, 101);
        assert_eq!(
            member_pids(table(&processes, &[], &[]).unit_for(&processes[0]).unwrap()),
            vec![100, 101]
        );
    }

    fn write_proc_fixture(root: &Path, process: &ProcessRecord, ticks: u64, owner: u32) {
        let path = root.join(process.pid.0.to_string());
        std::fs::create_dir_all(&path).unwrap();
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = "S".to_string();
        fields[1] = process.ppid.0.to_string();
        fields[19] = ticks.to_string();
        std::fs::write(
            path.join("stat"),
            format!(
                "{} (worker (with parentheses)) {}",
                process.pid.0,
                fields.join(" ")
            ),
        )
        .unwrap();
        std::fs::write(
            path.join("status"),
            format!(
                "Pid:\t{}\nTgid:\t{}\nUid:\t{owner} {owner} {owner} {owner}\n",
                process.pid.0, process.pid.0
            ),
        )
        .unwrap();
        std::fs::write(path.join("cgroup"), format!("0::{AGENT_SCOPE}\n")).unwrap();
    }

    #[test]
    fn injected_proc_collector_binds_placement_to_boot_birth_owner_and_parent() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        std::fs::create_dir_all(root.join("sys/kernel/random")).unwrap();
        std::fs::write(root.join("sys/kernel/random/boot_id"), "boot\n").unwrap();
        let process = process(100, 1, "sleep", 100);
        write_proc_fixture(root, &process, 100, 1000);
        let observed = collect_cgroup_memberships_from(std::slice::from_ref(&process), root);
        assert_eq!(observed[0].path.as_deref(), Some(AGENT_SCOPE));
        assert_eq!(observed[0].source, "cgroup_v2");
        for (ticks, owner) in [(101, 1000), (100, 2000)] {
            write_proc_fixture(root, &process, ticks, owner);
            let observed = collect_cgroup_memberships_from(std::slice::from_ref(&process), root);
            assert!(observed[0].path.is_none());
            assert!(observed[0]
                .unavailable
                .as_deref()
                .unwrap()
                .contains("identity or parent changed"));
        }
        write_proc_fixture(root, &process, 100, 1000);
        let mut changed_parent = process.clone();
        changed_parent.ppid = ProcessId(999);
        assert!(collect_cgroup_memberships_from(&[changed_parent], root)[0]
            .path
            .is_none());
        std::fs::write(root.join("sys/kernel/random/boot_id"), "other-boot\n").unwrap();
        assert!(
            collect_cgroup_memberships_from(std::slice::from_ref(&process), root)[0]
                .path
                .is_none()
        );
        std::fs::write(root.join("sys/kernel/random/boot_id"), "boot\n").unwrap();
        std::fs::write(root.join("100/status"), "Gid:\t0 0 0 0\n").unwrap();
        assert!(
            collect_cgroup_memberships_from(std::slice::from_ref(&process), root)[0]
                .path
                .is_none()
        );
    }

    #[test]
    fn empty_census_has_no_fabricated_unit_or_usage() {
        let result = table(&[], &[], &[]);
        assert!(result.units.is_empty());
        assert_eq!(result.attributed_processes, 0);
        assert_eq!(result.sampling_window_ms, None);
    }

    proptest! {
        #[test]
        fn partition_and_usage_are_conserved_and_input_order_independent(cpu in prop::collection::vec(0.0f64..300.0, 1..40)) {
            let mut processes: Vec<_> = cpu.iter().enumerate().map(|(index, _)| {
                let pid = 100 + index as u32;
                process(pid, if index == 0 { 1 } else { pid - 1 }, if index % 7 == 0 { "claude" } else { "rustc" }, u64::from(pid))
            }).collect();
            let mut samples: Vec<_> = processes.iter().zip(&cpu).map(|(process, cpu)| activity(process, *cpu)).collect();
            let first = table(&processes, &samples, &[]);
            let members: BTreeSet<_> = first.units.iter().flat_map(|unit| unit.members.iter().map(|identity| identity.pid)).collect();
            prop_assert_eq!(members.len(), processes.len());
            prop_assert_eq!(first.units.iter().map(|unit| unit.member_count).sum::<usize>(), processes.len());
            let cores: f64 = first.units.iter().map(|unit| unit.usage.cpu_cores.value.unwrap()).sum();
            let observed_cpu: f64 = cpu.iter().sum::<f64>() / 100.0;
            prop_assert!((cores - observed_cpu).abs() < 1e-9);
            processes.reverse(); samples.reverse();
            let reversed = table(&processes, &samples, &[]);
            prop_assert_eq!(serde_json::to_value(&first).unwrap(), serde_json::to_value(&reversed).unwrap());
        }

        #[test]
        fn unrelated_owner_cannot_inflate_existing_unit(cpu in 0.0f64..400.0, foreign_cpu in 0.0f64..400.0) {
            let original = process(100, 1, "claude", 100);
            let sample = activity(&original, cpu);
            let group = membership(&original, AGENT_SCOPE);
            let baseline = table(std::slice::from_ref(&original), std::slice::from_ref(&sample), std::slice::from_ref(&group));
            let mut foreign = process(101, 100, "rustc", 101);
            foreign.uid = 2000;
            let expanded = table(&[original.clone(), foreign.clone()], &[sample, activity(&foreign, foreign_cpu)], &[group, membership(&foreign, AGENT_SCOPE)]);
            prop_assert_eq!(serde_json::to_value(baseline.unit_for(&original).unwrap()).unwrap(), serde_json::to_value(expanded.unit_for(&original).unwrap()).unwrap());
        }
    }
}
