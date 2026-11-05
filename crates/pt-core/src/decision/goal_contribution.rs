//! Expected goal contribution per action, with uncertainty.
//!
//! Estimates how much each candidate kill/stop contributes toward a
//! resource goal, accounting for shared memory, respawn probability,
//! and blast radius.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::goal_parser::{Goal, Metric};
use crate::collect::ProcessRecord;
use pt_common::ProcessIdentity;

/// Observed resources for one process incarnation. These are current counts,
/// not estimates inferred from its command, children or resident memory.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessGoalResources {
    pub identity: ProcessIdentity,
    pub fd_count: u64,
}

/// Observed holders of sockets bound to a requested port in this network
/// namespace, within the mounted procfs view. `None` means that census could not
/// be completed; `Some([])` means no bound sockets were observed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PortGoalResources {
    pub holders: Option<Vec<ProcessIdentity>>,
    pub bound_socket_count: Option<usize>,
}

/// A single resource observation reused by preliminary and final goal planning.
/// In particular, filtering candidates must never remove a shared socket holder
/// from the port's requirements.
#[derive(Debug, Clone, Default)]
pub struct GoalResourceSnapshot {
    pub processes: BTreeMap<u32, ProcessGoalResources>,
    pub ports: BTreeMap<u16, PortGoalResources>,
    pub warnings: Vec<String>,
}

impl GoalResourceSnapshot {
    /// Collect only the extra evidence required by the goal. Memory and CPU
    /// goals incur no descriptor or socket-table work here.
    pub fn collect(goal: &Goal, population: &[ProcessRecord]) -> Self {
        let mut need_fds = false;
        let mut ports = BTreeMap::new();
        requested_resources(goal, &mut need_fds, &mut ports);
        if !need_fds && ports.is_empty() {
            return Self::default();
        }
        #[cfg(target_os = "linux")]
        {
            collect_linux_goal_resources(population, need_fds, ports)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = population;
            Self {
                ports,
                warnings: vec!["fd_and_port_goal_measurements_unavailable_on_this_platform".into()],
                ..Self::default()
            }
        }
    }

    /// A PID alone is not sufficient to use a measured descriptor count.
    pub fn fd_count(&self, identity: &ProcessIdentity) -> Option<u64> {
        self.processes
            .get(&identity.pid.0)
            .filter(|observed| observed.identity.matches(identity))
            .map(|observed| observed.fd_count)
    }
}

fn requested_resources(
    goal: &Goal,
    need_fds: &mut bool,
    ports: &mut BTreeMap<u16, PortGoalResources>,
) {
    match goal {
        Goal::Target(target) => match target.metric {
            Metric::FileDescriptors => *need_fds = true,
            Metric::Port => {
                if let Some(port) = target.port {
                    ports.entry(port).or_default();
                }
            }
            _ => {}
        },
        Goal::And(parts) | Goal::Or(parts) => {
            for part in parts {
                requested_resources(part, need_fds, ports);
            }
        }
    }
}

#[cfg(target_os = "linux")]
type PortBindings = BTreeMap<u16, std::collections::BTreeSet<u64>>;

/// Parse the binding facts needed for a goal without silently dropping malformed
/// rows. TCP connections and connected UDP sockets also keep their local port
/// bound; considering only listeners would overstate what a kill can release.
#[cfg(target_os = "linux")]
fn add_port_bindings(contents: &str, bindings: &mut PortBindings) -> Result<(), String> {
    let mut lines = contents.lines();
    if !lines
        .next()
        .is_some_and(|header| header.contains("local_address"))
    {
        return Err("socket table header is missing".into());
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        let local = fields.get(1).ok_or("incomplete socket table row")?;
        let (_, port) = local.rsplit_once(':').ok_or("invalid socket address")?;
        let port = u16::from_str_radix(port, 16).map_err(|_| "invalid socket port")?;
        if let Some(inodes) = bindings.get_mut(&port) {
            let inode = fields
                .get(9)
                .ok_or("socket inode is missing")?
                .parse::<u64>()
                .map_err(|_| "invalid socket inode")?;
            // Inode zero (for example, TIME_WAIT) remains an unmet requirement:
            // there is no process we can terminate to release that binding.
            inodes.insert(inode);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_port_bindings(ports: &BTreeMap<u16, PortGoalResources>) -> Result<PortBindings, String> {
    let mut bindings = ports
        .keys()
        .map(|&port| (port, Default::default()))
        .collect();
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        match std::fs::read_to_string(format!("/proc/net/{table}")) {
            Ok(contents) => add_port_bindings(&contents, &mut bindings)?,
            // IPv6 tables do not exist when the protocol is unavailable.
            Err(error) if table.ends_with('6') && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot read {table} socket table: {error}")),
        }
    }
    Ok(bindings)
}

#[cfg(target_os = "linux")]
fn read_goal_identity(pid: u32, boot_id: &str) -> Option<ProcessIdentity> {
    let stat = crate::collect::proc_parsers::read_required_proc_stat(pid).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = goal_uid_from_status(&status)?;
    (stat.pid == pid).then(|| {
        ProcessIdentity::new(
            pid,
            pt_common::StartId::from_linux(boot_id, stat.starttime, pid),
            uid,
        )
    })
}

#[cfg(target_os = "linux")]
fn goal_uid_from_status(status: &str) -> Option<u32> {
    let uid_line = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let uids = uid_line
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if uids.len() != 4 {
        return None;
    }
    Some(uids[0])
}

#[cfg(target_os = "linux")]
fn goal_process_census() -> Result<std::collections::BTreeSet<u32>, String> {
    let mut pids = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

/// A hidepid mount can omit an entire holder without returning a read error.
/// Do not claim a complete shared-socket census from such a view, even if all
/// of the visible descriptors can be inspected.
#[cfg(target_os = "linux")]
fn goal_procfs_has_unrestricted_view(mounts: &str) -> bool {
    let mut found_proc = false;
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(1) != Some(&"/proc") {
            continue;
        }
        if fields.get(2) != Some(&"proc") {
            return false;
        }
        let Some(options) = fields.get(3) else {
            return false;
        };
        if options.split(',').any(|option| {
            option
                .strip_prefix("hidepid=")
                .is_some_and(|value| !matches!(value, "0" | "off"))
        }) {
            return false;
        }
        found_proc = true;
    }
    found_proc
}

/// Inspect links only: do not stat descriptor targets, which may be on a
/// stalled FUSE/network filesystem. One walk supplies both counts and sockets.
#[cfg(target_os = "linux")]
fn read_goal_descriptors(
    pid: u32,
    sockets: bool,
) -> Result<(u64, std::collections::BTreeSet<u64>), String> {
    let mut count = 0;
    let mut inodes = std::collections::BTreeSet::new();
    let entries =
        std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            return Err("invalid descriptor entry".into());
        }
        count += 1;
        if count > 50_000 {
            return Err("descriptor observation budget exceeded".into());
        }
        if sockets {
            let target = std::fs::read_link(entry.path()).map_err(|error| error.to_string())?;
            let target = target.to_string_lossy();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                inodes.insert(inode.parse().map_err(|_| "invalid socket descriptor")?);
            }
        }
    }
    Ok((count, inodes))
}

#[cfg(target_os = "linux")]
fn collect_linux_goal_resources(
    population: &[ProcessRecord],
    need_fds: bool,
    ports: BTreeMap<u16, PortGoalResources>,
) -> GoalResourceSnapshot {
    let mut snapshot = GoalResourceSnapshot {
        ports,
        ..Default::default()
    };
    let boot_id = match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(id) if !id.trim().is_empty() => id.trim().to_string(),
        _ => {
            snapshot
                .warnings
                .push("goal_resource_identity_unavailable".into());
            return snapshot;
        }
    };
    let inspect_sockets = !snapshot.ports.is_empty();
    let bindings = if inspect_sockets {
        match collect_port_bindings(&snapshot.ports) {
            Ok(bindings) => Some(bindings),
            Err(error) => {
                snapshot
                    .warnings
                    .push(format!("port_bindings_unavailable: {error}"));
                None
            }
        }
    } else {
        None
    };
    let mut incomplete = inspect_sockets
        && !std::fs::read_to_string("/proc/mounts")
            .ok()
            .is_some_and(|mounts| goal_procfs_has_unrestricted_view(&mounts));
    if incomplete {
        snapshot
            .warnings
            .push("port_holder_census_visibility_unavailable".into());
    }
    let pids: std::collections::BTreeSet<u32> = if inspect_sockets {
        // Include protected processes, non-candidates and other users: any of
        // them can retain a duplicated socket or a SO_REUSEPORT binding.
        match goal_process_census() {
            Ok(pids) => pids,
            Err(_) => {
                incomplete = true;
                population.iter().map(|process| process.pid.0).collect()
            }
        }
    } else {
        population.iter().map(|process| process.pid.0).collect()
    };
    let mut observed_sockets = Vec::new();
    let mut unavailable = 0usize;
    for &pid in &pids {
        let sample = read_goal_identity(pid, &boot_id).and_then(|identity| {
            let (fd_count, inodes) = read_goal_descriptors(pid, inspect_sockets).ok()?;
            let after = read_goal_identity(pid, &boot_id)?;
            identity
                .matches(&after)
                .then_some((identity, fd_count, inodes))
        });
        let Some((identity, fd_count, inodes)) = sample else {
            // A process that has exited cannot retain a socket. All other
            // missing or changed evidence prevents a complete owner census.
            let gone = matches!(std::fs::symlink_metadata(format!("/proc/{pid}")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound);
            if !gone {
                incomplete = true;
                unavailable += 1;
            }
            continue;
        };
        if need_fds {
            snapshot.processes.insert(
                pid,
                ProcessGoalResources {
                    identity: identity.clone(),
                    fd_count,
                },
            );
        }
        if inspect_sockets {
            observed_sockets.push((identity, inodes));
        }
    }
    if inspect_sockets && goal_process_census().ok().as_ref() != Some(&pids) {
        incomplete = true;
        snapshot
            .warnings
            .push("port_holder_census_changed_during_observation".into());
    }
    if unavailable > 0 {
        snapshot.warnings.push(format!(
            "goal_resource_evidence_unavailable_for_{unavailable}_processes"
        ));
    }
    if let Some(bindings) = bindings {
        let bindings_stable =
            collect_port_bindings(&snapshot.ports).ok().as_ref() == Some(&bindings);
        if !bindings_stable {
            incomplete = true;
            snapshot
                .warnings
                .push("port_bindings_changed_during_observation".into());
        }
        for (port, inodes) in bindings {
            let resources = snapshot.ports.get_mut(&port).expect("requested port");
            resources.bound_socket_count = Some(inodes.len());
            if inodes.is_empty() && bindings_stable {
                resources.holders = Some(Vec::new());
            } else if !incomplete {
                let mut holders = BTreeMap::new();
                let all_owned = inodes.iter().all(|inode| {
                    let mut found = false;
                    for (identity, held) in &observed_sockets {
                        if held.contains(inode) {
                            holders.insert(identity.pid.0, identity.clone());
                            found = true;
                        }
                    }
                    found
                });
                if all_owned {
                    resources.holders = Some(holders.into_values().collect());
                }
            }
            if resources.holders.is_none() {
                snapshot
                    .warnings
                    .push(format!("port_{port}_ownership_incomplete"));
            }
        }
    }
    snapshot
}

/// A candidate process for goal contribution estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionCandidate {
    /// Process identifier.
    pub pid: u32,
    /// RSS bytes.
    pub rss_bytes: u64,
    /// USS bytes (if known).
    pub uss_bytes: Option<u64>,
    /// CPU fraction (0.0 to 1.0+).
    pub cpu_frac: f64,
    /// File descriptor count.
    pub fd_count: u32,
    /// Bound ports.
    pub bound_ports: Vec<u16>,
    /// Probability of respawn after kill (0.0 to 1.0).
    pub respawn_probability: f64,
    /// Whether this process has shared memory segments.
    pub has_shared_memory: bool,
    /// Number of child processes.
    pub child_count: usize,
}

/// Estimated contribution toward a goal metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalContribution {
    /// Expected value of the contribution.
    pub expected: f64,
    /// Lower bound (pessimistic).
    pub low: f64,
    /// Upper bound (optimistic).
    pub high: f64,
    /// Confidence in the estimate (0.0 to 1.0).
    pub confidence: f64,
    /// Factors affecting the estimate.
    pub factors: Vec<ContributionFactor>,
}

/// A factor that modifies the contribution estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionFactor {
    pub name: String,
    pub multiplier: f64,
    pub explanation: String,
}

/// Estimate memory contribution from killing a process.
pub fn estimate_memory_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    // Base: use USS if available (true private memory), else RSS.
    let base_bytes = candidate.uss_bytes.unwrap_or(candidate.rss_bytes) as f64;

    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    // Shared memory discount: RSS includes shared pages.
    if candidate.uss_bytes.is_none() && candidate.has_shared_memory {
        let shared_discount = 0.6; // Assume 40% shared.
        multiplier *= shared_discount;
        factors.push(ContributionFactor {
            name: "shared_memory".to_string(),
            multiplier: shared_discount,
            explanation: "RSS includes shared pages; estimated 40% shared".to_string(),
        });
    }

    // Respawn discount: if process respawns, memory isn't permanently freed.
    if candidate.respawn_probability > 0.0 {
        let respawn_discount = 1.0 - candidate.respawn_probability;
        multiplier *= respawn_discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: respawn_discount,
            explanation: format!(
                "Respawn probability {:.0}% reduces expected contribution",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    let expected = base_bytes * multiplier;

    // Uncertainty: wider when USS unknown or respawn likely.
    let uncertainty_factor = if candidate.uss_bytes.is_some() {
        0.1
    } else {
        0.3
    };
    let low = expected * (1.0 - uncertainty_factor);
    let high = base_bytes * (1.0 + uncertainty_factor * 0.5); // High can exceed expected

    let confidence = if candidate.uss_bytes.is_some() {
        0.9
    } else {
        0.6
    };
    let confidence = confidence * (1.0 - candidate.respawn_probability * 0.5);

    GoalContribution {
        expected,
        low: low.max(0.0),
        high,
        confidence: confidence.clamp(0.0, 1.0),
        factors,
    }
}

/// Estimate CPU contribution from killing a process.
pub fn estimate_cpu_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    let base_cpu = candidate.cpu_frac;
    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    if candidate.respawn_probability > 0.0 {
        let discount = 1.0 - candidate.respawn_probability;
        multiplier *= discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: discount,
            explanation: format!(
                "Respawn probability {:.0}%",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    let expected = base_cpu * multiplier;
    let low = expected * 0.8;
    let high = base_cpu * 1.1; // CPU slightly fluctuates

    GoalContribution {
        expected,
        low: low.max(0.0),
        high: high.min(1.0),
        confidence: (0.8 * (1.0 - candidate.respawn_probability * 0.5)).clamp(0.0, 1.0),
        factors,
    }
}

/// Estimate port release contribution.
pub fn estimate_port_contribution(
    candidate: &ContributionCandidate,
    target_port: u16,
) -> GoalContribution {
    let holds_port = candidate.bound_ports.contains(&target_port);

    if !holds_port {
        return GoalContribution {
            expected: 0.0,
            low: 0.0,
            high: 0.0,
            confidence: 1.0,
            factors: vec![],
        };
    }

    let mut factors = Vec::new();
    let mut prob = 1.0;

    if candidate.respawn_probability > 0.0 {
        prob *= 1.0 - candidate.respawn_probability;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: 1.0 - candidate.respawn_probability,
            explanation: "Process may respawn and rebind port".to_string(),
        });
    }

    GoalContribution {
        expected: prob,
        low: prob * 0.9,
        high: 1.0,
        confidence: (0.9 * (1.0 - candidate.respawn_probability * 0.5)).clamp(0.0, 1.0),
        factors,
    }
}

/// Estimate FD contribution from killing a process.
pub fn estimate_fd_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    let base = candidate.fd_count as f64;
    let mut factors = Vec::new();
    let mut multiplier = 1.0;

    if candidate.respawn_probability > 0.0 {
        let discount = 1.0 - candidate.respawn_probability;
        multiplier *= discount;
        factors.push(ContributionFactor {
            name: "respawn".to_string(),
            multiplier: discount,
            explanation: format!(
                "Respawn probability {:.0}%",
                candidate.respawn_probability * 100.0
            ),
        });
    }

    // Child processes also hold FDs.
    if candidate.child_count > 0 {
        let child_factor = 1.0 + (candidate.child_count as f64 * 0.5).min(3.0);
        multiplier *= child_factor;
        factors.push(ContributionFactor {
            name: "children".to_string(),
            multiplier: child_factor,
            explanation: format!(
                "Process has {} children that may also release FDs",
                candidate.child_count
            ),
        });
    }

    let expected = base * multiplier;

    GoalContribution {
        expected,
        low: (base * 0.8).max(0.0),
        high: expected * 1.2,
        confidence: 0.7,
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_and_cpu_goals_do_not_collect_descriptor_evidence() {
        let goal = super::super::goal_parser::parse_goal("free 4GB RAM AND free 20% CPU").unwrap();
        let snapshot = GoalResourceSnapshot::collect(&goal, &[]);
        assert!(snapshot.processes.is_empty());
        assert!(snapshot.ports.is_empty());
        assert!(snapshot.warnings.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn goal_uid_requires_observed_complete_numeric_uid_field() {
        assert_eq!(
            goal_uid_from_status("Uid:\t1000\t1000\t1000\t1000\nGid:\t0\t0\t0\t0\n"),
            Some(1000)
        );
        assert_eq!(goal_uid_from_status("Uid:\t0\t0\t0\t0\n"), Some(0));
        for status in [
            "Gid:\t0\t0\t0\t0\n",
            "Uid:\t1000\t1000\n",
            "Uid:\tunknown\t0\t0\t0\n",
            "",
        ] {
            assert_eq!(goal_uid_from_status(status), None, "{status:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_holder_census_requires_unrestricted_procfs_view() {
        for options in ["rw,nosuid,nodev,noexec", "rw,hidepid=0", "rw,hidepid=off"] {
            assert!(goal_procfs_has_unrestricted_view(&format!(
                "proc /proc proc {options} 0 0\n"
            )));
        }
        for mounts in [
            "",
            "proc /another-proc proc rw 0 0\n",
            "overlay /proc overlay rw 0 0\n",
            "proc /proc proc\n",
            "proc /proc proc rw,hidepid=1 0 0\n",
            "proc /proc proc rw,hidepid=2 0 0\n",
            "proc /proc proc rw,hidepid=invisible 0 0\n",
            "proc /proc proc rw,hidepid=ptraceable 0 0\n",
            "proc /proc proc rw,hidepid=invalid 0 0\n",
        ] {
            assert!(!goal_procfs_has_unrestricted_view(mounts), "{mounts:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_goal_parser_retains_every_binding_and_unowned_socket() {
        let mut bindings: PortBindings = [(3000, Default::default())].into();
        add_port_bindings(
            "sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n\
             0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 100\n\
             1: 0100007F:0BB8 0100007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 101\n\
             2: 0100007F:0BB8 0100007F:C351 06 00000000:00000000 00:00000000 00000000 1000 0 0\n\
             3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 200\n",
            &mut bindings,
        ).unwrap();
        add_port_bindings(
            "sl local_address remote_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n\
             0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 102\n",
            &mut bindings,
        ).unwrap();
        assert_eq!(bindings[&3000], [0, 100, 101, 102].into());
        assert_eq!(bindings.len(), 1);
        for bad in [
            "",
            "invalid header\n",
            "local_address\n0: broken\n",
            "local_address\n0: 0100007F:0BB8 missing_inode\n",
        ] {
            assert!(add_port_bindings(bad, &mut bindings).is_err(), "{bad:?}");
        }
    }

    fn make_candidate() -> ContributionCandidate {
        ContributionCandidate {
            pid: 1234,
            rss_bytes: 1_000_000_000, // 1GB
            uss_bytes: None,
            cpu_frac: 0.25,
            fd_count: 50,
            bound_ports: vec![3000],
            respawn_probability: 0.0,
            has_shared_memory: false,
            child_count: 0,
        }
    }

    #[test]
    fn test_memory_basic() {
        let c = make_candidate();
        let contrib = estimate_memory_contribution(&c);
        assert!(contrib.expected > 0.0);
        assert!(contrib.low < contrib.expected);
        assert!(contrib.high > contrib.expected);
        assert!(contrib.confidence > 0.5);
    }

    #[test]
    fn test_memory_with_uss() {
        let c = ContributionCandidate {
            uss_bytes: Some(500_000_000),
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        // Should use USS, not RSS.
        assert!((contrib.expected - 500_000_000.0).abs() < 100_000_000.0);
        assert!(contrib.confidence > 0.8); // Higher confidence with USS.
    }

    #[test]
    fn test_memory_shared_discount() {
        let c = ContributionCandidate {
            has_shared_memory: true,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        // Should be discounted below RSS.
        assert!(contrib.expected < 1_000_000_000.0);
        assert!(
            contrib.factors.iter().any(|f| f.name == "shared_memory"),
            "Should have shared_memory factor"
        );
    }

    #[test]
    fn test_memory_respawn_discount() {
        let c = ContributionCandidate {
            respawn_probability: 0.8,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        assert!(contrib.expected < 300_000_000.0); // 1GB * (1-0.8) = 200MB
        assert!(contrib.confidence < 0.7);
    }

    #[test]
    fn test_cpu_basic() {
        let c = make_candidate();
        let contrib = estimate_cpu_contribution(&c);
        assert!((contrib.expected - 0.25).abs() < 0.05);
    }

    #[test]
    fn test_cpu_respawn() {
        let c = ContributionCandidate {
            respawn_probability: 0.5,
            ..make_candidate()
        };
        let contrib = estimate_cpu_contribution(&c);
        assert!((contrib.expected - 0.125).abs() < 0.05); // 0.25 * 0.5
    }

    #[test]
    fn test_port_holds_target() {
        let c = make_candidate();
        let contrib = estimate_port_contribution(&c, 3000);
        assert!(contrib.expected > 0.9);
    }

    #[test]
    fn test_port_does_not_hold() {
        let c = make_candidate();
        let contrib = estimate_port_contribution(&c, 8080);
        assert_eq!(contrib.expected, 0.0);
    }

    #[test]
    fn test_port_with_respawn() {
        let c = ContributionCandidate {
            respawn_probability: 0.7,
            ..make_candidate()
        };
        let contrib = estimate_port_contribution(&c, 3000);
        assert!(contrib.expected < 0.5); // High respawn probability.
    }

    #[test]
    fn test_fd_basic() {
        let c = make_candidate();
        let contrib = estimate_fd_contribution(&c);
        assert!((contrib.expected - 50.0).abs() < 10.0);
    }

    #[test]
    fn test_fd_with_children() {
        let c = ContributionCandidate {
            child_count: 4,
            ..make_candidate()
        };
        let contrib = estimate_fd_contribution(&c);
        // Should account for children's FDs.
        assert!(contrib.expected > 50.0);
        assert!(
            contrib.factors.iter().any(|f| f.name == "children"),
            "Should have children factor"
        );
    }

    #[test]
    fn test_all_contributions_have_intervals() {
        let c = make_candidate();
        for contrib in [
            estimate_memory_contribution(&c),
            estimate_cpu_contribution(&c),
            estimate_port_contribution(&c, 3000),
            estimate_fd_contribution(&c),
        ] {
            assert!(contrib.low <= contrib.expected, "low should be <= expected");
            assert!(
                contrib.high >= contrib.expected || contrib.expected == 0.0,
                "high should be >= expected"
            );
        }
    }
}
