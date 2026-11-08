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

/// Private resident pages observed for one process incarnation. Ordinary
/// private bytes are `Private_Clean + Private_Dirty` from Linux smaps_rollup.
/// This is a footprint forecast, not a guarantee that MemAvailable will rise
/// by that amount after exit: clean file pages may remain cached, allocations
/// can change, and other work or a respawn can consume the released capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPrivateMemory {
    pub identity: ProcessIdentity,
    pub private_clean_bytes: u64,
    pub private_dirty_bytes: u64,
    /// Huge-TLB pages return to a separate pool. Retain this observation but
    /// never credit it toward an ordinary RAM goal. None means not reported.
    #[serde(default)]
    pub private_hugetlb_bytes: Option<u64>,
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
    /// Separate from descriptor observations so a memory-only collection never
    /// manufactures a zero descriptor count. Other goals leave this map empty.
    pub private_memory: BTreeMap<u32, ProcessPrivateMemory>,
    pub warnings: Vec<String>,
}

impl GoalResourceSnapshot {
    /// Collect only the extra evidence required by the goal. Memory and CPU
    /// goals incur no descriptor or socket-table work here.
    pub fn collect(goal: &Goal, population: &[ProcessRecord]) -> Self {
        let mut need_fds = false;
        let mut need_memory = false;
        let mut ports = BTreeMap::new();
        requested_resources(goal, &mut need_fds, &mut need_memory, &mut ports);
        if !need_fds && !need_memory && ports.is_empty() {
            return Self::default();
        }
        #[cfg(target_os = "linux")]
        {
            collect_linux_goal_resources(population, need_fds, need_memory, ports)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = population;
            let mut warnings = Vec::new();
            if need_fds || !ports.is_empty() {
                warnings.push("fd_and_port_goal_measurements_unavailable_on_this_platform".into());
            }
            if need_memory {
                warnings
                    .push("private_memory_goal_measurements_unavailable_on_this_platform".into());
            }
            Self {
                ports,
                warnings,
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

    /// Identity-bound ordinary private bytes, with no RSS, shared-page, swap or
    /// huge-TLB fallback. Absence is an error, never an observed zero.
    pub fn private_memory_bytes(&self, identity: &ProcessIdentity) -> Result<u64, String> {
        let observed = self
            .private_memory
            .get(&identity.pid.0)
            .ok_or_else(|| format!("private memory was not observed for pid {}", identity.pid.0))?;
        if !identity.can_safely_revalidate()
            || !observed.identity.can_safely_revalidate()
            || !observed.identity.matches(identity)
        {
            return Err(format!(
                "private-memory identity differs for pid {}",
                identity.pid.0
            ));
        }
        observed
            .private_clean_bytes
            .checked_add(observed.private_dirty_bytes)
            .ok_or_else(|| "private-memory byte total overflows u64".into())
    }
}

fn requested_resources(
    goal: &Goal,
    need_fds: &mut bool,
    need_memory: &mut bool,
    ports: &mut BTreeMap<u16, PortGoalResources>,
) {
    match goal {
        Goal::Target(target) => match target.metric {
            Metric::FileDescriptors => *need_fds = true,
            Metric::Memory => *need_memory = true,
            Metric::Port => {
                if let Some(port) = target.port {
                    ports.entry(port).or_default();
                }
            }
            _ => {}
        },
        Goal::And(parts) | Goal::Or(parts) => {
            for part in parts {
                requested_resources(part, need_fds, need_memory, ports);
            }
        }
    }
}

/// Parse only the private resident fields used by the forecast. Unknown fields
/// (including RSS, PSS and Swap) do not substitute for missing private fields.
#[cfg(any(target_os = "linux", test))]
fn parse_private_memory_fields(contents: &str) -> Result<(u64, u64, Option<u64>), String> {
    let mut clean = None;
    let mut dirty = None;
    let mut hugetlb = None;
    for line in contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            if ["Private_Clean", "Private_Dirty", "Private_Hugetlb"]
                .iter()
                .any(|key| line.trim_start().starts_with(key))
            {
                return Err("private-memory field is missing its colon".into());
            }
            continue;
        };
        let slot = match key.trim() {
            "Private_Clean" => &mut clean,
            "Private_Dirty" => &mut dirty,
            "Private_Hugetlb" => &mut hugetlb,
            _ => continue,
        };
        if slot.is_some() {
            return Err(format!("duplicate {} field", key.trim()));
        }
        let mut fields = value.split_whitespace();
        let count = fields
            .next()
            .ok_or_else(|| format!("{} is missing a count", key.trim()))?;
        if count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("{} has an invalid unsigned count", key.trim()));
        }
        if fields.next() != Some("kB") || fields.next().is_some() {
            return Err(format!(
                "{} must contain exactly a count and kB unit",
                key.trim()
            ));
        }
        let bytes = count
            .parse::<u64>()
            .ok()
            .and_then(|count| count.checked_mul(1024))
            .ok_or_else(|| format!("{} byte count overflows u64", key.trim()))?;
        *slot = Some(bytes);
    }
    let clean = clean.ok_or("Private_Clean was not observed")?;
    let dirty = dirty.ok_or("Private_Dirty was not observed")?;
    clean
        .checked_add(dirty)
        .ok_or("private-memory byte total overflows u64")?;
    Ok((clean, dirty, hugetlb))
}

/// A pinned proc directory prevents a reused numeric PID from redirecting the
/// smaps read to a new process between the identity checks.
#[cfg(target_os = "linux")]
struct GoalProcDirectory {
    handle: std::fs::File,
}

#[cfg(target_os = "linux")]
impl GoalProcDirectory {
    fn open(pid: u32) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .map_err(|error| format!("cannot pin /proc/{pid}: {error}"))?;
        Ok(Self { handle })
    }

    fn read(&self, name: &str) -> Result<String, String> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        const MAX_PROC_FIELD_BYTES: u64 = 64 * 1024;
        let path = format!("/proc/self/fd/{}/{}", self.handle.as_raw_fd(), name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| format!("cannot read pinned {name}: {error}"))?;
        let mut content = String::new();
        file.take(MAX_PROC_FIELD_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("cannot read pinned {name}: {error}"))?;
        if content.len() as u64 > MAX_PROC_FIELD_BYTES {
            return Err(format!("pinned {name} exceeds the observation size limit"));
        }
        Ok(content)
    }

    fn identity(&self, pid: u32, boot_id: &str) -> Result<ProcessIdentity, String> {
        let stat = self.read("stat")?;
        let open = stat.find('(').ok_or("stat command is missing")?;
        let close = stat
            .rfind(')')
            .filter(|close| *close > open)
            .ok_or("stat command is malformed")?;
        let raw_pid = stat[..open].trim();
        if raw_pid.is_empty() || !raw_pid.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("stat PID is invalid".into());
        }
        let observed_pid = raw_pid.parse::<u32>().map_err(|_| "stat PID is invalid")?;
        if observed_pid != pid {
            return Err("stat PID differs from the requested process".into());
        }
        let raw_start_ticks = stat[close + 1..]
            .split_whitespace()
            .nth(19)
            .ok_or("stat birth ticks are missing")?;
        if !raw_start_ticks.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("stat birth ticks are invalid".into());
        }
        let start_ticks = raw_start_ticks
            .parse::<u64>()
            .map_err(|_| "stat birth ticks are invalid")?;
        let status = self.read("status")?;
        if status
            .lines()
            .filter(|line| line.starts_with("Uid:"))
            .count()
            != 1
        {
            return Err("process UID field is missing or duplicated".into());
        }
        if status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .is_some_and(|uids| {
                uids.split_whitespace()
                    .any(|uid| !uid.bytes().all(|byte| byte.is_ascii_digit()))
            })
        {
            return Err("process UID field is invalid".into());
        }
        let uid = goal_uid_from_status(&status).ok_or("process UID is unavailable")?;
        Ok(ProcessIdentity::new(
            pid,
            pt_common::StartId::from_linux(boot_id, start_ticks, pid),
            uid,
        ))
    }
}

#[cfg(target_os = "linux")]
fn read_private_memory(
    expected: &ProcessIdentity,
    boot_id: &str,
) -> Result<ProcessPrivateMemory, String> {
    let directory = GoalProcDirectory::open(expected.pid.0)?;
    let before = directory.identity(expected.pid.0, boot_id)?;
    if !expected.can_safely_revalidate() || !expected.matches(&before) {
        return Err("process identity changed before private-memory observation".into());
    }
    let contents = directory.read("smaps_rollup")?;
    let (private_clean_bytes, private_dirty_bytes, private_hugetlb_bytes) =
        parse_private_memory_fields(&contents)?;
    let after = directory.identity(expected.pid.0, boot_id)?;
    if !expected.matches(&after) {
        return Err("process identity changed during private-memory observation".into());
    }
    Ok(ProcessPrivateMemory {
        identity: before,
        private_clean_bytes,
        private_dirty_bytes,
        private_hugetlb_bytes,
    })
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
    need_memory: bool,
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
    if need_memory {
        for process in population {
            let identity =
                ProcessIdentity::new(process.pid.0, process.start_id.clone(), process.uid);
            match read_private_memory(&identity, &boot_id) {
                Ok(memory) => {
                    snapshot.private_memory.insert(process.pid.0, memory);
                }
                Err(error) => snapshot.warnings.push(format!(
                    "private_memory_unavailable_for_pid_{}: {error}",
                    process.pid.0
                )),
            }
        }
    }
    // The memory path has no dependency on descriptor permissions, socket
    // tables or a complete process census. Do not enter that path unnecessarily.
    if !need_fds && snapshot.ports.is_empty() {
        return snapshot;
    }
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
    /// Observed ordinary private resident bytes (if known), excluding swap and
    /// huge-TLB pages. RSS is not a substitute for this measurement.
    #[serde(default)]
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

/// Forecast memory contribution from an observed private resident footprint.
///
/// No positive credit is available without an observation. Even with one, the
/// footprint is not a guaranteed host-memory delta or a calibrated confidence
/// interval: clean pages can stay cached and concurrent allocations can change.
pub fn estimate_memory_contribution(candidate: &ContributionCandidate) -> GoalContribution {
    let unavailable = |explanation: &str| GoalContribution {
        expected: 0.0,
        low: 0.0,
        high: 0.0,
        confidence: 0.0,
        factors: vec![ContributionFactor {
            name: "memory_forecast_unavailable".into(),
            multiplier: 0.0,
            explanation: explanation.into(),
        }],
    };
    let Some(private_bytes) = candidate.uss_bytes else {
        return unavailable("Private resident memory was not observed; RSS and guessed shared-page fractions provide no memory-goal credit");
    };
    if !candidate.respawn_probability.is_finite()
        || !(0.0..=1.0).contains(&candidate.respawn_probability)
    {
        return unavailable("Respawn probability is not a finite value between zero and one");
    }
    let base_bytes = private_bytes as f64;
    let mut factors = vec![ContributionFactor {
        name: "private_resident_footprint".into(),
        multiplier: 1.0,
        explanation: "Observed private resident footprint; excludes shared pages, swap and huge-TLB memory. This is a forecast, not guaranteed host RAM recovery or a calibrated confidence interval".into(),
    }];
    let mut multiplier = 1.0;

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

    GoalContribution {
        expected,
        low: 0.0,
        high: base_bytes,
        confidence: 0.0,
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
        assert!(snapshot.private_memory.is_empty());
        #[cfg(target_os = "linux")]
        assert!(snapshot.warnings.is_empty());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            snapshot.warnings,
            ["private_memory_goal_measurements_unavailable_on_this_platform"]
        );
    }

    fn private_memory_identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity::new(
            pid,
            pt_common::StartId::from_linux("test-boot", 1234, pid),
            1000,
        )
    }

    #[test]
    fn private_memory_requires_observed_fields_and_excludes_other_memory() {
        let (clean, dirty, hugetlb) = parse_private_memory_fields(
            "00000000-ffffffff ---p 00000000 00:00 0 [rollup]\n\
             Rss: 1048576 kB\nPss: 999999 kB\n\
             Private_Clean: 64 kB\nPrivate_Dirty: 512 kB\n\
             Shared_Clean: 123456 kB\nSwap: 999999 kB\nPrivate_Hugetlb: 2048 kB\n",
        )
        .unwrap();
        assert_eq!(
            (clean, dirty, hugetlb),
            (64 * 1024, 512 * 1024, Some(2048 * 1024))
        );
        let identity = private_memory_identity(42);
        let mut snapshot = GoalResourceSnapshot::default();
        snapshot.private_memory.insert(
            42,
            ProcessPrivateMemory {
                identity: identity.clone(),
                private_clean_bytes: clean,
                private_dirty_bytes: dirty,
                private_hugetlb_bytes: hugetlb,
            },
        );
        assert_eq!(
            snapshot.private_memory_bytes(&identity).unwrap(),
            576 * 1024
        );
        assert_eq!(
            snapshot.fd_count(&identity),
            None,
            "memory is not a descriptor count"
        );
        assert!(snapshot
            .private_memory_bytes(&private_memory_identity(43))
            .is_err());
        let mut wrong = identity.clone();
        wrong.uid += 1;
        assert!(snapshot.private_memory_bytes(&wrong).is_err());
        wrong = identity.clone();
        wrong.start_id = pt_common::StartId::from_linux("test-boot", 1235, 42);
        assert!(snapshot.private_memory_bytes(&wrong).is_err());
        snapshot
            .private_memory
            .get_mut(&42)
            .unwrap()
            .identity
            .quality = pt_common::IdentityQuality::PidOnly;
        assert!(
            snapshot.private_memory_bytes(&identity).is_err(),
            "PID-only observed evidence cannot grant credit"
        );

        let fields = parse_private_memory_fields(
            "Private_Clean: 0 kB\nPrivate_Dirty: 0 kB\nPrivate_Hugetlb: 2048 kB\nSwap: 4096 kB\n",
        )
        .unwrap();
        assert_eq!(fields, (0, 0, Some(2048 * 1024)));
        assert_eq!(
            parse_private_memory_fields("Private_Clean: 0 kB\nPrivate_Dirty: 1 kB\n").unwrap(),
            (0, 1024, None)
        );
    }

    #[test]
    fn private_memory_parser_rejects_missing_malformed_duplicate_and_overflow_fields() {
        for bad in [
            "", "Rss: 1024 kB\nPss: 512 kB\n", "Private_Clean: 1 kB\n",
            "Private_Dirty: 1 kB\n", "Private_Clean: 1 kB\nPrivate_Clean: 1 kB\nPrivate_Dirty: 2 kB\n",
            "Private_Clean: 1 kB\nPrivate_Dirty: 2 kB\nPrivate_Dirty: 2 kB\n",
            "Private_Clean: 1 kB\nPrivate_Dirty: 2 kB\nPrivate_Hugetlb: 0 kB\nPrivate_Hugetlb: 0 kB\n",
            "Private_Clean: 18446744073709551616 kB\nPrivate_Dirty: 0 kB\n",
            "Private_Clean: 18014398509481984 kB\nPrivate_Dirty: 0 kB\n",
            "Private_Clean: 18014398509481983 kB\nPrivate_Dirty: 1 kB\n",
            "Private_Clean: 0 kB\nPrivate_Dirty: 0 kB\nPrivate_Hugetlb: 18014398509481984 kB\n",
            "Private_Clean 1 kB\nPrivate_Dirty: 0 kB\n",
        ] {
            assert!(parse_private_memory_fields(bad).is_err(), "{bad:?}");
        }
        for field in ["Private_Clean", "Private_Dirty", "Private_Hugetlb"] {
            for bad_value in [
                "",
                "1",
                "-1 kB",
                "+1 kB",
                "1.0 kB",
                "0x10 kB",
                "NaN kB",
                "1 KB",
                "1 KiB",
                "1 bytes",
                "1 kB trailing",
            ] {
                let mut input = String::new();
                for key in ["Private_Clean", "Private_Dirty", "Private_Hugetlb"] {
                    input.push_str(&format!(
                        "{key}: {}\n",
                        if key == field { bad_value } else { "0 kB" }
                    ));
                }
                assert!(parse_private_memory_fields(&input).is_err(), "{input:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_memory_uses_live_proc_identity_and_never_scan_rss() {
        // Use the mounted procfs view, just as quick_scan does. A container can
        // mount a procfs instance whose PID namespace differs from getpid().
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let pid = stat
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let mut scan = crate::collect::quick_scan(&crate::collect::QuickScanOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .expect("scan the owned test process");
        let process = scan
            .processes
            .iter_mut()
            .find(|process| process.pid.0 == pid)
            .unwrap();
        // A bogus scan footprint must not be substituted for the kernel's
        // separate, identity-bound private-page observation.
        process.rss_bytes = u64::MAX;
        let identity = ProcessIdentity::new(pid, process.start_id.clone(), process.uid);
        let population = vec![process.clone()];
        let goal = super::super::goal_parser::parse_goal("free 1MB RAM").unwrap();
        let snapshot = GoalResourceSnapshot::collect(&goal, &population);
        let bytes = snapshot
            .private_memory_bytes(&identity)
            .unwrap_or_else(|error| panic!("{error}: {:?}", snapshot.warnings));
        assert!(bytes > 0 && bytes < u64::MAX);
        assert!(snapshot.processes.is_empty());
        assert!(snapshot.ports.is_empty());
        assert!(snapshot.warnings.is_empty(), "{:?}", snapshot.warnings);

        for change in ["uid", "start"] {
            let mut changed = population[0].clone();
            if change == "uid" {
                changed.uid = changed.uid.wrapping_add(1);
            } else {
                changed.start_id = pt_common::StartId("wrong-incarnation".into());
            }
            let rejected = GoalResourceSnapshot::collect(&goal, &[changed]);
            assert!(rejected.private_memory.is_empty());
            assert!(rejected
                .warnings
                .iter()
                .any(|warning| warning.contains("identity changed before")));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_proc_reader_retains_its_directory_and_rejects_truncated_identity() {
        let temporary = tempfile::TempDir::new().unwrap();
        let original = temporary.path().join("process");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(
            original.join("smaps_rollup"),
            "Private_Clean: 1 kB\nPrivate_Dirty: 2 kB\n",
        )
        .unwrap();
        let pinned = GoalProcDirectory {
            handle: std::fs::File::open(&original).unwrap(),
        };
        std::fs::rename(&original, temporary.path().join("old-process")).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(
            original.join("smaps_rollup"),
            "Private_Clean: 999 kB\nPrivate_Dirty: 999 kB\n",
        )
        .unwrap();
        assert_eq!(
            parse_private_memory_fields(&pinned.read("smaps_rollup").unwrap()).unwrap(),
            (1024, 2048, None)
        );
        let old = temporary.path().join("old-process");
        std::fs::write(old.join("stat"), "42 (worker) S 1 0\n").unwrap();
        std::fs::write(old.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
        assert!(pinned
            .identity(42, "test-boot")
            .unwrap_err()
            .contains("birth ticks"));
        assert!(pinned.read("absent").is_err());
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
        assert_eq!(contrib.expected, 0.0);
        assert_eq!(contrib.low, 0.0);
        assert_eq!(contrib.high, 0.0);
        assert_eq!(contrib.confidence, 0.0);
        assert_eq!(contrib.factors[0].name, "memory_forecast_unavailable");
    }

    #[test]
    fn test_memory_with_uss() {
        let c = ContributionCandidate {
            uss_bytes: Some(500_000_000),
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        // Should use USS, not RSS.
        assert_eq!(contrib.expected, 500_000_000.0);
        assert_eq!(contrib.high, 500_000_000.0);
        assert_eq!(contrib.low, 0.0); // Private footprint is not guaranteed host relief.
        assert_eq!(contrib.confidence, 0.0); // No calibrated recovery model.
    }

    #[test]
    fn test_memory_does_not_guess_shared_memory_from_rss() {
        let c = ContributionCandidate {
            has_shared_memory: true,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        assert_eq!(contrib.expected, 0.0);
        let observed = estimate_memory_contribution(&ContributionCandidate {
            uss_bytes: Some(1234),
            ..c
        });
        assert_eq!(
            observed.expected, 1234.0,
            "observed private memory needs no shared-page guess"
        );
    }

    #[test]
    fn test_memory_respawn_discount() {
        let c = ContributionCandidate {
            uss_bytes: Some(1_000_000_000),
            respawn_probability: 0.8,
            ..make_candidate()
        };
        let contrib = estimate_memory_contribution(&c);
        assert!((contrib.expected - 200_000_000.0).abs() < 1e-6);
        assert_eq!(contrib.high, 1_000_000_000.0);
        assert_eq!(contrib.low, 0.0);
        for invalid in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            let invalid_forecast = estimate_memory_contribution(&ContributionCandidate {
                respawn_probability: invalid,
                ..c.clone()
            });
            assert_eq!(invalid_forecast.expected, 0.0);
            assert_eq!(
                invalid_forecast.factors[0].name,
                "memory_forecast_unavailable"
            );
        }
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
