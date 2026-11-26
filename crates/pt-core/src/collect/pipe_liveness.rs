//! Bounded, identity-bound anonymous-pipe endpoint observations.
//!
//! This is positive evidence about the supplied process inventory, not a proof
//! that every pipe holder was observed. Only leader descriptor tables are read;
//! threads with unshared tables, other PID namespaces, new processes and races
//! can hide additional endpoints. Reads across processes are sequential: they
//! establish observed holders, not simultaneous ownership or actual pipe traffic.
//! Even a complete observation cannot establish abandonment from a missing
//! reader or writer. Descriptor targets are never
//! opened or stat'ed: a FUSE path or named FIFO must not stall this collector.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

pub const PIPE_CENSUS_SCOPE: &str = "supplied_inventory_leader_descriptor_tables";

/// The boot identity is shared by the snapshot and must also match the caller's
/// recorded StartId. uid is the effective UID, matching the quick-scan inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PipeProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PipeAccess {
    Read,
    Write,
    ReadWrite,
}

impl PipeAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
        }
    }

    #[cfg(target_os = "linux")]
    fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    #[cfg(target_os = "linux")]
    fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PipeEndpoint {
    pub fd: u32,
    pub inode: u64,
    pub access: PipeAccess,
}

/// One directionally matched endpoint belonging to another exact process.
/// For readers, local_fd writes to peer_fd; for writers, local_fd reads peer_fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PipePeer {
    pub identity: PipeProcessIdentity,
    pub local_fd: u32,
    pub peer_fd: u32,
    pub inode: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessPipeLiveness {
    pub identity: PipeProcessIdentity,
    /// Both final identity observations succeeded; not a promise of future life.
    pub identity_verified: bool,
    pub endpoints: Vec<PipeEndpoint>,
    /// Observed readers of this process's writable anonymous pipe descriptors.
    pub readers: Vec<PipePeer>,
    /// Observed writers of this process's readable anonymous pipe descriptors.
    pub writers: Vec<PipePeer>,
    /// No detected gap in this process's bounded observation, within the scope
    /// above. Missing peers are not negative evidence even when this is true.
    pub complete: bool,
    pub unavailable: Vec<String>,
}

impl ProcessPipeLiveness {
    fn new(identity: PipeProcessIdentity) -> Self {
        Self {
            identity,
            identity_verified: false,
            endpoints: Vec::new(),
            readers: Vec::new(),
            writers: Vec::new(),
            complete: true,
            unavailable: Vec::new(),
        }
    }

    fn incomplete(&mut self, reason: &str) {
        self.complete = false;
        add_reason(&mut self.unavailable, reason);
    }

    pub fn stdin_writers(&self) -> impl Iterator<Item = &PipePeer> {
        self.writers.iter().filter(|peer| peer.local_fd == 0)
    }

    pub fn output_readers(&self) -> impl Iterator<Item = &PipePeer> {
        self.readers
            .iter()
            .filter(|peer| matches!(peer.local_fd, 1 | 2))
    }
}

#[derive(Debug, Clone)]
pub struct PipeCollectionLimits {
    /// Limit on process tables probed. Result storage remains linear in the
    /// caller's inventory so every unprobed PID has an explicit unknown result.
    pub max_processes: usize,
    pub max_descriptors_per_process: usize,
    /// First-pass descriptor visits plus reserved final endpoint validations.
    pub max_descriptors_total: usize,
    /// Combined reader and writer links stored for one process.
    pub max_links_per_process: usize,
    /// Also bounds pair-expansion work, including pairs refused by a local cap.
    pub max_links_total: usize,
    pub max_duration: Duration,
}

impl Default for PipeCollectionLimits {
    fn default() -> Self {
        Self {
            max_processes: 4096,
            max_descriptors_per_process: 1024,
            max_descriptors_total: 65_536,
            max_links_per_process: 128,
            max_links_total: 32_768,
            max_duration: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipeLivenessSnapshot {
    pub boot_id: Option<String>,
    pub processes: BTreeMap<u32, ProcessPipeLiveness>,
    pub complete: bool,
    pub unavailable: Vec<String>,
    pub descriptors_inspected: usize,
    pub elapsed: Duration,
}

impl PipeLivenessSnapshot {
    fn new(inputs: &[PipeProcessIdentity]) -> Self {
        let mut snapshot = Self {
            boot_id: None,
            processes: BTreeMap::new(),
            complete: true,
            unavailable: Vec::new(),
            descriptors_inspected: 0,
            elapsed: Duration::ZERO,
        };
        for &identity in inputs {
            match snapshot.processes.entry(identity.pid) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let mut process = ProcessPipeLiveness::new(identity);
                    if identity.pid == 0 || identity.pid > i32::MAX as u32 {
                        process.incomplete("pipe_invalid_pid");
                    }
                    entry.insert(process);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    // Even identical duplicate rows make inventory coverage
                    // ambiguous. Do not choose one incarnation silently.
                    entry.get_mut().incomplete("pipe_duplicate_inventory_pid");
                }
            }
        }
        snapshot
    }

    fn incomplete(&mut self, reason: &str) {
        self.complete = false;
        add_reason(&mut self.unavailable, reason);
    }

    fn invalidate(&mut self, reason: &str) {
        self.incomplete(reason);
        self.boot_id = None;
        for process in self.processes.values_mut() {
            process.identity_verified = false;
            process.endpoints.clear();
            process.readers.clear();
            process.writers.clear();
            process.incomplete(reason);
        }
    }

    /// Find deterministic shortest stdout/stderr paths to externally active
    /// consumers. Activity seeds must be justified by the caller's independent,
    /// identity-bound observations. This method never labels an idle process.
    ///
    /// Reverse multi-source BFS visits each recorded edge at most twice. Seed processes
    /// receive no self proof; unseeded cycles receive no proof. Returned paths
    /// have at most 32 hops and each hop identifies the actual paired FDs.
    pub fn active_downstream_paths(
        &self,
        active: &BTreeSet<PipeProcessIdentity>,
        max_hops: usize,
    ) -> BTreeMap<PipeProcessIdentity, Vec<PipePeer>> {
        let max_hops = max_hops.min(32);
        if self.boot_id.is_none() || max_hops == 0 {
            return BTreeMap::new();
        }
        let verified = |identity: &PipeProcessIdentity| {
            self.processes
                .get(&identity.pid)
                .is_some_and(|process| {
                    process.identity_verified && process.identity == *identity
                })
        };
        let mut incoming: BTreeMap<
            PipeProcessIdentity,
            Vec<(PipeProcessIdentity, PipePeer)>,
        > = BTreeMap::new();
        for process in self.processes.values() {
            if !verified(&process.identity) {
                continue;
            }
            for &peer in process.output_readers() {
                if peer.identity.pid != process.identity.pid && verified(&peer.identity) {
                    incoming
                        .entry(peer.identity)
                        .or_default()
                        .push((process.identity, peer));
                }
            }
        }
        for edges in incoming.values_mut() {
            edges.sort_unstable();
            edges.dedup();
        }
        #[derive(Clone, Copy)]
        struct Route {
            seed: PipeProcessIdentity,
            distance: usize,
            next: Option<PipePeer>,
        }
        // Retain two distinct nearest seeds, so a writer that is itself active
        // can still receive evidence for a DIFFERENT active consumer. There
        // are at most two queued states per node, independent of seed count.
        let mut routes: BTreeMap<PipeProcessIdentity, Vec<Route>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        for &seed in active.iter().filter(|identity| verified(identity)) {
            let route = Route {
                seed,
                distance: 0,
                next: None,
            };
            routes.entry(seed).or_default().push(route);
            queue.push_back((seed, route));
        }
        while let Some((consumer, route)) = queue.pop_front() {
            if route.distance >= max_hops {
                continue;
            }
            for &(producer, peer) in incoming.get(&consumer).into_iter().flatten() {
                let known = routes.entry(producer).or_default();
                if known.len() >= 2 || known.iter().any(|known| known.seed == route.seed) {
                    continue;
                }
                let predecessor = Route {
                    seed: route.seed,
                    distance: route.distance + 1,
                    next: Some(peer),
                };
                known.push(predecessor);
                queue.push_back((producer, predecessor));
            }
        }
        let mut paths = BTreeMap::new();
        for (&producer, choices) in &routes {
            let Some(chosen) = choices
                .iter()
                .filter(|route| route.seed != producer && route.distance > 0)
                .min_by_key(|route| (route.distance, route.seed))
            else {
                continue;
            };
            let mut current = producer;
            let mut path = Vec::new();
            while current != chosen.seed && path.len() < max_hops {
                let Some(peer) = routes
                    .get(&current)
                    .and_then(|choices| choices.iter().find(|route| route.seed == chosen.seed))
                    .and_then(|route| route.next)
                else {
                    break;
                };
                path.push(peer);
                current = peer.identity;
            }
            if current == chosen.seed && !path.is_empty() {
                paths.insert(producer, path);
            }
        }
        paths
    }
}

fn add_reason(reasons: &mut Vec<String>, reason: &str) {
    // Bound diagnostics even for a process with thousands of unreadable FDs.
    if reasons.len() < 16 && !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

/// Collect once for the full unfiltered inventory. An excluded or young reader
/// is still an important consumer, even when it can never become an action.
pub fn collect_pipe_liveness(
    inputs: &[PipeProcessIdentity],
    limits: &PipeCollectionLimits,
) -> PipeLivenessSnapshot {
    #[cfg(target_os = "linux")]
    {
        linux::collect_from(std::path::Path::new("/proc"), inputs, limits, || {})
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = limits;
        let mut snapshot = PipeLivenessSnapshot::new(inputs);
        snapshot.invalidate("pipe_observation_unsupported_on_this_platform");
        snapshot
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const MAX_PROCESS_FIELD: usize = 65_536;
    const MAX_FDINFO_FIELD: usize = 16_384;
    const O_PATH: u64 = 0o10_000_000;

    struct Budget {
        began: Instant,
        max_duration: Duration,
        max_descriptors: usize,
        descriptors: usize,
        reserved_final: usize,
    }

    impl Budget {
        fn check(&self) -> Result<(), &'static str> {
            if self.began.elapsed() >= self.max_duration {
                Err("pipe_collection_deadline")
            } else {
                Ok(())
            }
        }

        fn initial_visit(&mut self) -> Result<(), &'static str> {
            self.check()?;
            if self.descriptors.saturating_add(self.reserved_final) >= self.max_descriptors {
                return Err("pipe_total_descriptor_limit");
            }
            self.descriptors += 1;
            Ok(())
        }

        fn reserve_final(&mut self) -> Result<(), &'static str> {
            if self.descriptors.saturating_add(self.reserved_final) >= self.max_descriptors {
                return Err("pipe_total_descriptor_limit");
            }
            self.reserved_final += 1;
            Ok(())
        }

        fn final_visit(&mut self) -> Result<(), &'static str> {
            self.reserved_final = self.reserved_final.saturating_sub(1);
            self.check()?;
            if self.descriptors >= self.max_descriptors {
                return Err("pipe_total_descriptor_limit");
            }
            self.descriptors += 1;
            Ok(())
        }

        fn release(&mut self, count: usize) {
            self.reserved_final = self.reserved_final.saturating_sub(count);
        }
    }

    fn bounded_read(
        path: &Path,
        limit: usize,
        budget: &Budget,
    ) -> Result<Vec<u8>, &'static str> {
        budget.check()?;
        let file = File::open(path).map_err(|_| "pipe_proc_field_unavailable")?;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "pipe_proc_field_unavailable")?;
        budget.check()?;
        if bytes.len() > limit {
            return Err("pipe_proc_field_size_limit");
        }
        Ok(bytes)
    }

    fn read_boot_id(root: &Path, budget: &Budget) -> Result<String, &'static str> {
        let raw = bounded_read(&root.join("sys/kernel/random/boot_id"), 128, budget)?;
        let text = std::str::from_utf8(&raw).map_err(|_| "pipe_boot_id_invalid")?;
        let value = text.strip_suffix('\n').unwrap_or(text);
        // Kernel boot_id is a UUID. Do not accept whitespace or delimiters that
        // could be mistaken for a different StartId component.
        if value.len() != 36
            || value.bytes().enumerate().any(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte != b'-'
                } else {
                    !byte.is_ascii_hexdigit()
                }
            })
        {
            return Err("pipe_boot_id_invalid");
        }
        Ok(value.to_string())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
    }

    struct PinnedProcess {
        directory: File,
        original_path: PathBuf,
        identity: DirectoryIdentity,
    }

    impl PinnedProcess {
        fn open(root: &Path, pid: u32, budget: &Budget) -> Result<Self, &'static str> {
            budget.check()?;
            let original_path = root.join(pid.to_string());
            // This only opens a kernel-owned numeric /proc directory. The
            // private alternate root is used by filesystem fixtures, not CLI
            // input. No descriptor target is ever followed.
            let directory =
                File::open(&original_path).map_err(|_| "pipe_process_directory_unavailable")?;
            let metadata = directory
                .metadata()
                .map_err(|_| "pipe_process_directory_unavailable")?;
            if !metadata.is_dir() {
                return Err("pipe_process_directory_invalid");
            }
            let pinned = Self {
                directory,
                original_path,
                identity: DirectoryIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            };
            pinned.check_path(budget)?;
            Ok(pinned)
        }

        fn path(&self, field: &str) -> PathBuf {
            // Pinning also works for a private fixture root: the fd link refers
            // to the held directory even if the numeric pathname is replaced.
            PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                self.directory.as_raw_fd(),
                field
            ))
        }

        fn check_path(&self, budget: &Budget) -> Result<(), &'static str> {
            budget.check()?;
            let current = fs::symlink_metadata(&self.original_path)
                .map_err(|_| "pipe_process_directory_changed")?;
            if !current.is_dir()
                || current.dev() != self.identity.device
                || current.ino() != self.identity.inode
            {
                return Err("pipe_process_directory_changed");
            }
            Ok(())
        }

        fn validate(
            &self,
            expected: PipeProcessIdentity,
            budget: &Budget,
        ) -> Result<(), &'static str> {
            self.check_path(budget)?;
            let stat = bounded_read(&self.path("stat"), MAX_PROCESS_FIELD, budget)?;
            let status = bounded_read(&self.path("status"), MAX_PROCESS_FIELD, budget)?;
            if parse_identity(&stat, &status)? != expected {
                return Err("pipe_process_identity_changed");
            }
            self.check_path(budget)
        }
    }

    fn unsigned<T: std::str::FromStr>(text: &str) -> Result<T, &'static str> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("pipe_invalid_unsigned_field");
        }
        text.parse().map_err(|_| "pipe_invalid_unsigned_field")
    }

    fn parse_identity(stat: &[u8], status: &[u8]) -> Result<PipeProcessIdentity, &'static str> {
        if stat.last() != Some(&b'\n') || status.last() != Some(&b'\n') {
            return Err("pipe_process_identity_incomplete");
        }
        let stat = std::str::from_utf8(stat).map_err(|_| "pipe_process_stat_invalid")?;
        let open = stat.find('(').ok_or("pipe_process_stat_invalid")?;
        let close = stat
            .rfind(')')
            .filter(|&close| close > open)
            .ok_or("pipe_process_stat_invalid")?;
        let pid: u32 = unsigned(stat[..open].trim())?;
        let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
        if fields.len() < 22 {
            return Err("pipe_process_stat_incomplete");
        }
        if matches!(fields[0], "Z" | "X" | "x") {
            return Err("pipe_process_no_longer_live");
        }
        if !matches!(fields[0], "R" | "S" | "D" | "T" | "t" | "I" | "P" | "W" | "K") {
            return Err("pipe_process_state_unavailable");
        }
        let start_ticks = unsigned(fields[19])?;
        let status = std::str::from_utf8(status).map_err(|_| "pipe_process_uid_invalid")?;
        let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
        let uids = uid_lines
            .next()
            .ok_or("pipe_process_uid_unavailable")?
            .split_whitespace()
            .map(unsigned::<u32>)
            .collect::<Result<Vec<_>, _>>()?;
        if uids.len() != 4 || uid_lines.next().is_some() {
            return Err("pipe_process_uid_invalid");
        }
        Ok(PipeProcessIdentity {
            pid,
            start_ticks,
            uid: uids[1],
        })
    }

    fn pipe_inode(target: &Path) -> Result<Option<u64>, &'static str> {
        let Some(text) = target.to_str() else {
            // Unrelated filesystem paths need not be UTF-8.
            return Ok(None);
        };
        if !text.starts_with("pipe:") {
            return Ok(None);
        }
        let raw = text
            .strip_prefix("pipe:[")
            .and_then(|value| value.strip_suffix(']'))
            .ok_or("pipe_descriptor_link_invalid")?;
        let inode = unsigned(raw)?;
        if inode == 0 {
            return Err("pipe_descriptor_link_invalid");
        }
        Ok(Some(inode))
    }

    fn descriptor_info(raw: &[u8]) -> Result<(u64, u64, Option<PipeAccess>), &'static str> {
        if raw.last() != Some(&b'\n') {
            return Err("pipe_descriptor_info_incomplete");
        }
        let text = std::str::from_utf8(raw).map_err(|_| "pipe_descriptor_info_invalid")?;
        let (mut flags, mut inode) = (None, None);
        for line in text.lines() {
            let Some((name, value)) = line.split_once(':') else {
                return Err("pipe_descriptor_info_invalid");
            };
            let value = value.trim();
            match name {
                "flags" => {
                    if flags.is_some()
                        || value.is_empty()
                        || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
                    {
                        return Err("pipe_descriptor_flags_invalid");
                    }
                    flags = Some(
                        u64::from_str_radix(value, 8)
                            .map_err(|_| "pipe_descriptor_flags_invalid")?,
                    );
                }
                "ino" => {
                    if inode.is_some() {
                        return Err("pipe_descriptor_inode_invalid");
                    }
                    inode = Some(unsigned(value)?);
                }
                _ => {}
            }
        }
        let flags = flags.ok_or("pipe_descriptor_flags_unavailable")?;
        let inode = inode.ok_or("pipe_descriptor_inode_unavailable")?;
        let access = if flags & O_PATH != 0 {
            // O_PATH holds a reference but cannot read or write the pipe.
            None
        } else {
            Some(match flags & 0b11 {
                0 => PipeAccess::Read,
                1 => PipeAccess::Write,
                2 => PipeAccess::ReadWrite,
                _ => return Err("pipe_descriptor_access_invalid"),
            })
        };
        Ok((inode, flags, access))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ObservedEndpoint {
        endpoint: PipeEndpoint,
        flags: u64,
    }

    fn read_endpoint(
        process: &PinnedProcess,
        fd: u32,
        budget: &Budget,
    ) -> Result<Option<ObservedEndpoint>, &'static str> {
        budget.check()?;
        let path = process.path(&format!("fd/{fd}"));
        let before = fs::read_link(&path).map_err(|_| "pipe_descriptor_link_unavailable")?;
        let Some(inode) = pipe_inode(&before)? else {
            return Ok(None);
        };
        let raw = bounded_read(
            &process.path(&format!("fdinfo/{fd}")),
            MAX_FDINFO_FIELD,
            budget,
        )?;
        let (reported_inode, flags, access) = descriptor_info(&raw)?;
        let after = fs::read_link(&path).map_err(|_| "pipe_descriptor_link_unavailable")?;
        budget.check()?;
        if before != after || inode != reported_inode {
            return Err("pipe_descriptor_changed");
        }
        Ok(access.map(|access| ObservedEndpoint {
            endpoint: PipeEndpoint { fd, inode, access },
            flags,
        }))
    }

    struct PendingProcess {
        directory: DirectoryIdentity,
        endpoints: Vec<ObservedEndpoint>,
    }

    fn observe_process(
        root: &Path,
        output: &mut ProcessPipeLiveness,
        limits: &PipeCollectionLimits,
        budget: &mut Budget,
    ) -> Result<PendingProcess, &'static str> {
        let process = PinnedProcess::open(root, output.identity.pid, budget)?;
        process.validate(output.identity, budget)?;
        let entries =
            fs::read_dir(process.path("fd")).map_err(|_| "pipe_descriptor_table_unavailable")?;
        let mut endpoints = Vec::new();
        for (visited, entry) in entries.enumerate() {
            if visited >= limits.max_descriptors_per_process {
                output.incomplete("pipe_process_descriptor_limit");
                break;
            }
            if let Err(reason) = budget.initial_visit() {
                output.incomplete(reason);
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    output.incomplete("pipe_descriptor_entry_unavailable");
                    continue;
                }
            };
            let name = entry.file_name();
            let fd: u32 = match name.to_str().and_then(|name| unsigned::<u32>(name).ok()) {
                Some(fd) if name == fd.to_string().as_str() => fd,
                _ => {
                    output.incomplete("pipe_descriptor_number_invalid");
                    continue;
                }
            };
            match read_endpoint(&process, fd, budget) {
                Ok(Some(endpoint)) => match budget.reserve_final() {
                    Ok(()) => endpoints.push(endpoint),
                    Err(reason) => {
                        output.incomplete(reason);
                        break;
                    }
                },
                Ok(None) => {}
                Err(reason) => output.incomplete(reason),
            }
        }
        if let Err(reason) = process.validate(output.identity, budget) {
            budget.release(endpoints.len());
            return Err(reason);
        }
        endpoints.sort_unstable_by_key(|observed| observed.endpoint.fd);
        Ok(PendingProcess {
            directory: process.identity,
            endpoints,
        })
    }

    fn verify_process(
        root: &Path,
        output: &mut ProcessPipeLiveness,
        pending: PendingProcess,
        budget: &mut Budget,
    ) {
        let process = match PinnedProcess::open(root, output.identity.pid, budget).and_then(|process| {
            if process.identity != pending.directory {
                return Err("pipe_process_directory_changed");
            }
            process.validate(output.identity, budget)?;
            Ok(process)
        }) {
            Ok(process) => process,
            Err(reason) => {
                budget.release(pending.endpoints.len());
                output.incomplete(reason);
                return;
            }
        };
        let mut endpoints = Vec::new();
        for expected in pending.endpoints {
            if let Err(reason) = budget.final_visit() {
                output.incomplete(reason);
                continue;
            }
            match read_endpoint(&process, expected.endpoint.fd, budget) {
                Ok(Some(observed)) if observed == expected => endpoints.push(observed.endpoint),
                Ok(_) => output.incomplete("pipe_descriptor_changed"),
                Err(reason) => output.incomplete(reason),
            }
        }
        match process.validate(output.identity, budget) {
            Ok(()) => {
                output.identity_verified = true;
                output.endpoints = endpoints;
            }
            Err(reason) => output.incomplete(reason),
        }
    }

    fn link_endpoints(
        snapshot: &mut PipeLivenessSnapshot,
        limits: &PipeCollectionLimits,
        budget: &Budget,
    ) {
        let mut pipes: BTreeMap<u64, Vec<(PipeProcessIdentity, PipeEndpoint)>> = BTreeMap::new();
        for process in snapshot.processes.values() {
            if !process.identity_verified {
                continue;
            }
            for &endpoint in &process.endpoints {
                if let Err(reason) = budget.check() {
                    snapshot.incomplete(reason);
                    return;
                }
                pipes.entry(endpoint.inode).or_default().push((process.identity, endpoint));
            }
        }
        let mut pair_work = 0usize;
        'pipes: for (&inode, holders) in &pipes {
            // Partition once. Re-filtering a reader-less pipe for every writer
            // would otherwise be quadratic without consuming the pair budget.
            let readers: Vec<_> = holders
                .iter()
                .copied()
                .filter(|(_, endpoint)| endpoint.access.reads())
                .collect();
            for &(writer, output) in holders.iter().filter(|(_, endpoint)| endpoint.access.writes()) {
                for &(reader, input) in &readers {
                    if let Err(reason) = budget.check() {
                        snapshot.incomplete(reason);
                        break 'pipes;
                    }
                    // Charge even self/capped pairs, so a high-fanout pipe
                    // cannot consume unbounded CPU without producing edges.
                    if limits.max_links_total.saturating_sub(pair_work) < 2 {
                        snapshot.incomplete("pipe_total_link_limit");
                        break 'pipes;
                    }
                    pair_work += 2;
                    if writer.pid == reader.pid {
                        continue;
                    }
                    let writer_count = snapshot.processes[&writer.pid].readers.len()
                        + snapshot.processes[&writer.pid].writers.len();
                    if writer_count >= limits.max_links_per_process {
                        if let Some(process) = snapshot.processes.get_mut(&writer.pid) {
                            process.incomplete("pipe_process_link_limit");
                        }
                        break;
                    }
                    let reader_count = snapshot.processes[&reader.pid].readers.len()
                        + snapshot.processes[&reader.pid].writers.len();
                    if reader_count >= limits.max_links_per_process {
                        if let Some(process) = snapshot.processes.get_mut(&reader.pid) {
                            process.incomplete("pipe_process_link_limit");
                        }
                        continue;
                    }
                    if let Some(process) = snapshot.processes.get_mut(&writer.pid) {
                        process.readers.push(PipePeer {
                            identity: reader,
                            local_fd: output.fd,
                            peer_fd: input.fd,
                            inode,
                        });
                    }
                    if let Some(process) = snapshot.processes.get_mut(&reader.pid) {
                        process.writers.push(PipePeer {
                            identity: writer,
                            local_fd: input.fd,
                            peer_fd: output.fd,
                            inode,
                        });
                    }
                }
            }
        }
        for process in snapshot.processes.values_mut() {
            process.readers.sort_unstable();
            process.writers.sort_unstable();
        }
    }

    pub(super) fn collect_from(
        root: &Path,
        inputs: &[PipeProcessIdentity],
        limits: &PipeCollectionLimits,
        before_final: impl FnOnce(),
    ) -> PipeLivenessSnapshot {
        let mut budget = Budget {
            began: Instant::now(),
            max_duration: limits.max_duration,
            max_descriptors: limits.max_descriptors_total,
            descriptors: 0,
            reserved_final: 0,
        };
        let mut snapshot = PipeLivenessSnapshot::new(inputs);
        let boot = match read_boot_id(root, &budget) {
            Ok(boot) => boot,
            Err(reason) => {
                snapshot.invalidate(reason);
                snapshot.elapsed = budget.began.elapsed();
                return snapshot;
            }
        };
        let mut pending = BTreeMap::new();
        let mut admitted = 0usize;
        for process in snapshot.processes.values_mut() {
            if !process.complete {
                continue;
            }
            if admitted >= limits.max_processes {
                process.incomplete("pipe_process_limit");
                continue;
            }
            admitted += 1;
            match observe_process(root, process, limits, &mut budget) {
                Ok(observed) => {
                    pending.insert(process.identity.pid, observed);
                }
                Err(reason) => process.incomplete(reason),
            }
        }
        before_final();
        for (pid, observed) in pending {
            if let Some(process) = snapshot.processes.get_mut(&pid) {
                verify_process(root, process, observed, &mut budget);
            }
        }
        match read_boot_id(root, &budget) {
            Ok(after) if after == boot => {
                snapshot.boot_id = Some(boot);
                link_endpoints(&mut snapshot, limits, &budget);
            }
            Ok(_) => snapshot.invalidate("pipe_boot_id_changed"),
            Err(reason) => snapshot.invalidate(reason),
        }
        if snapshot.processes.values().any(|process| !process.complete) {
            snapshot.incomplete("pipe_process_observation_incomplete");
        }
        snapshot.descriptors_inspected = budget.descriptors;
        snapshot.elapsed = budget.began.elapsed();
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";

    fn identity(pid: u32) -> PipeProcessIdentity {
        PipeProcessIdentity {
            pid,
            start_ticks: 100 + u64::from(pid),
            uid: 1000,
        }
    }

    fn graph(pids: &[u32], edges: &[(u32, u32, u32, u32, u64)]) -> PipeLivenessSnapshot {
        let identities: Vec<_> = pids.iter().copied().map(identity).collect();
        let mut snapshot = PipeLivenessSnapshot::new(&identities);
        snapshot.boot_id = Some(BOOT.into());
        for process in snapshot.processes.values_mut() {
            process.identity_verified = true;
        }
        for &(producer, local_fd, consumer, peer_fd, inode) in edges {
            let writer = snapshot.processes.get_mut(&producer).unwrap();
            writer.endpoints.push(PipeEndpoint {
                fd: local_fd,
                inode,
                access: PipeAccess::Write,
            });
            writer.readers.push(PipePeer {
                identity: identity(consumer),
                local_fd,
                peer_fd,
                inode,
            });
            let reader = snapshot.processes.get_mut(&consumer).unwrap();
            reader.endpoints.push(PipeEndpoint {
                fd: peer_fd,
                inode,
                access: PipeAccess::Read,
            });
            reader.writers.push(PipePeer {
                identity: identity(producer),
                local_fd: peer_fd,
                peer_fd: local_fd,
                inode,
            });
        }
        snapshot
    }

    #[test]
    fn active_consumer_protects_a_pipeline_without_inventing_activity() {
        let snapshot = graph(&[1, 2, 3, 4], &[(1, 1, 2, 0, 50), (2, 1, 3, 0, 60)]);
        assert!(snapshot.active_downstream_paths(&BTreeSet::new(), 32).is_empty());
        let paths = snapshot.active_downstream_paths(&BTreeSet::from([identity(3)]), 32);
        assert_eq!(
            paths[&identity(1)].iter().map(|peer| peer.identity.pid).collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(paths[&identity(2)][0].identity, identity(3));
        assert!(!paths.contains_key(&identity(3)));
        assert!(!paths.contains_key(&identity(4)));
        assert_eq!(snapshot.processes[&2].stdin_writers().count(), 1);
    }

    #[test]
    fn cycles_self_endpoints_and_unverified_seeds_do_not_create_proof() {
        let mut snapshot = graph(
            &[1, 2, 3],
            &[(1, 1, 1, 0, 50), (1, 2, 2, 0, 60), (2, 1, 1, 0, 70)],
        );
        assert!(snapshot.active_downstream_paths(&BTreeSet::new(), 32).is_empty());
        let paths = snapshot.active_downstream_paths(&BTreeSet::from([identity(1)]), 32);
        assert!(!paths.contains_key(&identity(1)), "a seed cannot prove itself by a cycle");
        assert_eq!(paths[&identity(2)][0].identity, identity(1));
        snapshot.processes.get_mut(&1).unwrap().identity_verified = false;
        assert!(snapshot.active_downstream_paths(&BTreeSet::from([identity(1)]), 32).is_empty());
        assert!(snapshot.active_downstream_paths(&BTreeSet::from([identity(99)]), 32).is_empty());
        let mut stale = identity(2);
        stale.start_ticks += 1;
        assert!(snapshot.active_downstream_paths(&BTreeSet::from([stale]), 32).is_empty());
    }

    #[test]
    fn active_writer_can_have_a_different_active_downstream_consumer() {
        let snapshot = graph(
            &[1, 2, 3, 4],
            &[(1, 1, 2, 0, 50), (2, 2, 1, 0, 60), (2, 1, 3, 0, 70), (3, 1, 4, 0, 80)],
        );
        let seeds = BTreeSet::from([identity(1), identity(4)]);
        let paths = snapshot.active_downstream_paths(&seeds, 32);
        assert_eq!(
            paths[&identity(1)].iter().map(|peer| peer.identity.pid).collect::<Vec<_>>(),
            [2, 3, 4]
        );
        assert_eq!(paths[&identity(2)][0].identity, identity(1));
        assert!(!paths.contains_key(&identity(4)));
    }

    #[test]
    fn shortest_paths_are_deterministic_bounded_and_only_follow_output() {
        let edges = [(1, 1, 2, 0, 50), (2, 1, 3, 0, 60), (1, 2, 4, 0, 70), (5, 7, 3, 0, 80)];
        let snapshot = graph(&[1, 2, 3, 4, 5], &edges);
        let mut reversed = edges;
        reversed.reverse();
        let reordered = graph(&[5, 4, 3, 2, 1], &reversed);
        let seeds = BTreeSet::from([identity(3), identity(4)]);
        let paths = snapshot.active_downstream_paths(&seeds, 32);
        assert_eq!(paths, reordered.active_downstream_paths(&seeds, 32));
        assert_eq!(paths[&identity(1)].len(), 1);
        assert_eq!(paths[&identity(1)][0].identity, identity(4));
        assert!(!paths.contains_key(&identity(5)), "arbitrary non-output pipes are diagnostic only");
        assert!(snapshot.active_downstream_paths(&seeds, 0).is_empty());

        let pids: Vec<_> = (1..=40).collect();
        let chain: Vec<_> = (1..40).map(|pid| (pid, 1, pid + 1, 0, u64::from(pid))).collect();
        let long = graph(&pids, &chain);
        let paths = long.active_downstream_paths(&BTreeSet::from([identity(40)]), usize::MAX);
        assert!(!paths.contains_key(&identity(7)));
        assert_eq!(paths[&identity(8)].len(), 32);
    }

    #[test]
    fn partial_coverage_retains_verified_positive_paths_but_missing_boot_does_not() {
        let mut snapshot = graph(&[1, 2], &[(1, 1, 2, 0, 50)]);
        snapshot.complete = false;
        snapshot.processes.get_mut(&2).unwrap().incomplete("another_descriptor_unavailable");
        let seeds = BTreeSet::from([identity(2)]);
        assert!(snapshot.active_downstream_paths(&seeds, 32).contains_key(&identity(1)));
        snapshot.boot_id = None;
        assert!(snapshot.active_downstream_paths(&seeds, 32).is_empty());
    }

    #[cfg(target_os = "linux")]
    mod live {
        use super::*;
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::symlink;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            root: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let token = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "pt-pipe-liveness-{}-{nanos}-{token}",
                    std::process::id()
                ));
                fs::create_dir_all(root.join("sys/kernel/random")).unwrap();
                fs::write(root.join("sys/kernel/random/boot_id"), format!("{BOOT}\n")).unwrap();
                Self { root }
            }

            fn process(&self, process: PipeProcessIdentity) {
                let directory = self.root.join(process.pid.to_string());
                fs::create_dir_all(directory.join("fd")).unwrap();
                fs::create_dir_all(directory.join("fdinfo")).unwrap();
                self.state(process, "S");
            }

            fn state(&self, process: PipeProcessIdentity, state: &str) {
                let directory = self.root.join(process.pid.to_string());
                fs::write(directory.join("stat"), stat_text(process, state)).unwrap();
                fs::write(
                    directory.join("status"),
                    format!("Name:\tpipe-worker\nUid:\t999\t{}\t{}\t{}\n", process.uid, process.uid, process.uid),
                ).unwrap();
            }

            fn endpoint(&self, pid: u32, fd: u32, inode: u64, flags: u64) {
                let directory = self.root.join(pid.to_string());
                symlink(format!("pipe:[{inode}]"), directory.join(format!("fd/{fd}"))).unwrap();
                fs::write(
                    directory.join(format!("fdinfo/{fd}")),
                    format!("pos:\t0\nflags:\t{flags:08o}\nmnt_id:\t17\nino:\t{inode}\n"),
                ).unwrap();
            }

            fn link_only(&self, pid: u32, fd: u32, target: &str) {
                symlink(target, self.root.join(format!("{pid}/fd/{fd}"))).unwrap();
            }

            fn pair() -> Self {
                let fixture = Self::new();
                fixture.process(identity(1));
                fixture.process(identity(2));
                fixture.endpoint(1, 1, 50, 1);
                fixture.endpoint(2, 0, 50, 0);
                fixture
            }

            fn collect(&self, inputs: &[PipeProcessIdentity]) -> PipeLivenessSnapshot {
                linux::collect_from(&self.root, inputs, &test_limits(), || {})
            }
        }

        fn test_limits() -> PipeCollectionLimits {
            PipeCollectionLimits {
                max_duration: Duration::from_secs(10),
                ..PipeCollectionLimits::default()
            }
        }

        fn stat_text(process: PipeProcessIdentity, state: &str) -> String {
            let mut fields = vec!["0".to_string(); 50];
            fields[0] = state.into();
            fields[17] = "1".into();
            fields[19] = process.start_ticks.to_string();
            format!("{} (pipe (worker)) {}\n", process.pid, fields.join(" "))
        }

        #[test]
        fn direction_modes_and_standard_streams_are_observed_without_following_targets() {
            let fixture = Fixture::pair();
            fixture.process(identity(3));
            fixture.endpoint(2, 2, 60, 1);
            fixture.endpoint(3, 0, 60, 0);
            fixture.endpoint(1, 3, 70, 2);
            fixture.endpoint(3, 4, 70, 0);
            fixture.endpoint(1, 9, 50, 0o10_000_000); // O_PATH is not a reader.
            fixture.link_only(2, 8, "/a/named/fifo/or/unresponsive/fuse/path");
            fixture.link_only(2, 9, "socket:[50]");
            let snapshot = fixture.collect(&[identity(1), identity(2), identity(3)]);
            assert!(snapshot.complete, "{snapshot:?}");
            assert_eq!(snapshot.boot_id.as_deref(), Some(BOOT));
            assert_eq!(snapshot.processes[&1].endpoints.len(), 2);
            assert_eq!(snapshot.processes[&1].output_readers().count(), 1);
            assert_eq!(snapshot.processes[&1].readers.len(), 2);
            assert_eq!(snapshot.processes[&2].stdin_writers().next().unwrap().identity, identity(1));
            let paths = snapshot.active_downstream_paths(&BTreeSet::from([identity(3)]), 32);
            assert_eq!(paths[&identity(1)].len(), 2, "fd 3 is not stdout/stderr");
            assert_eq!(paths[&identity(2)][0].local_fd, 2);
        }

        #[test]
        fn unreadable_descriptor_preserves_other_finally_verified_positive_evidence() {
            let fixture = Fixture::pair();
            fixture.link_only(1, 2, "pipe:[60]"); // fdinfo is deliberately unavailable.
            let snapshot = fixture.collect(&[identity(1), identity(2)]);
            assert!(!snapshot.complete);
            assert!(!snapshot.processes[&1].complete);
            assert!(snapshot.processes[&1].identity_verified);
            assert_eq!(snapshot.processes[&1].readers.len(), 1);
            assert!(snapshot.processes[&1].unavailable.iter().any(|reason| reason.contains("unavailable")));
            assert!(snapshot.active_downstream_paths(&BTreeSet::from([identity(2)]), 32).contains_key(&identity(1)));
        }

        #[test]
        fn final_revalidation_rejects_pid_uid_state_directory_and_descriptor_reuse() {
            for change in ["start", "uid", "zombie", "fd_mode", "fd_inode", "directory"] {
                let fixture = Fixture::pair();
                let snapshot = linux::collect_from(
                    &fixture.root,
                    &[identity(1), identity(2)],
                    &test_limits(),
                    || match change {
                        "start" => fixture.state(PipeProcessIdentity { start_ticks: 9999, ..identity(2) }, "S"),
                        "uid" => fixture.state(PipeProcessIdentity { uid: 1001, ..identity(2) }, "S"),
                        "zombie" => fixture.state(identity(2), "Z"),
                        "fd_mode" => {
                            fs::write(fixture.root.join("2/fdinfo/0"), "flags:\t1\nino:\t50\n").unwrap();
                        }
                        "fd_inode" => {
                            fs::rename(fixture.root.join("2/fd/0"), fixture.root.join("old-fd")).unwrap();
                            fixture.endpoint(2, 0, 51, 0);
                        }
                        "directory" => {
                            fs::rename(fixture.root.join("2"), fixture.root.join("old-process")).unwrap();
                            fixture.process(identity(2));
                            fixture.endpoint(2, 0, 50, 0);
                        }
                        _ => unreachable!(),
                    },
                );
                assert!(!snapshot.complete, "{change}: {snapshot:?}");
                assert!(snapshot.processes[&1].readers.is_empty(), "{change}");
                assert!(snapshot.processes[&2].endpoints.is_empty(), "{change}");
                assert!(snapshot.active_downstream_paths(&BTreeSet::from([identity(2)]), 32).is_empty(), "{change}");
            }
        }

        #[test]
        fn duplicate_or_unknown_processes_never_supply_reader_proof() {
            let fixture = Fixture::pair();
            let duplicate = fixture.collect(&[identity(1), identity(2), identity(2)]);
            assert!(!duplicate.complete);
            assert!(!duplicate.processes[&2].identity_verified);
            assert!(duplicate.processes[&1].readers.is_empty());
            let mismatch = fixture.collect(&[
                identity(1),
                PipeProcessIdentity { uid: 1001, ..identity(2) },
            ]);
            assert!(!mismatch.complete);
            assert!(mismatch.processes[&1].readers.is_empty());
            let partial = fixture.collect(&[identity(1), identity(2), identity(99)]);
            assert!(!partial.complete);
            assert_eq!(partial.processes[&1].readers.len(), 1);
            assert!(!partial.processes[&99].identity_verified);
        }

        #[test]
        fn changing_or_missing_boot_identity_invalidates_all_endpoint_facts() {
            for missing in [false, true] {
                let fixture = Fixture::pair();
                let snapshot = linux::collect_from(
                    &fixture.root,
                    &[identity(1), identity(2)],
                    &test_limits(),
                    || {
                        let path = fixture.root.join("sys/kernel/random/boot_id");
                        if missing {
                            fs::rename(path, fixture.root.join("old-boot-id")).unwrap();
                        } else {
                            fs::write(path, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n").unwrap();
                        }
                    },
                );
                assert!(snapshot.boot_id.is_none());
                assert!(!snapshot.complete);
                assert!(snapshot.processes.values().all(|process| {
                    !process.identity_verified && process.endpoints.is_empty() && process.readers.is_empty()
                }));
            }
        }

        #[test]
        fn collection_limits_bound_probe_and_link_work_without_fabricating_absence() {
            let fixture = Fixture::pair();
            fixture.process(identity(3));
            fixture.endpoint(3, 0, 50, 0);
            let inputs = [identity(1), identity(2), identity(3)];
            let mut limits = test_limits();
            limits.max_descriptors_total = 4;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(limited.descriptors_inspected <= 4);
            assert!(!limited.complete);
            assert_eq!(limited.processes[&1].readers.len(), 1, "reserved final checks retain the first verified pair");

            limits = test_limits();
            limits.max_processes = 1;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(!limited.complete);
            assert!(limited.processes[&1].readers.is_empty());
            assert!(limited.processes[&2].unavailable.iter().any(|reason| reason == "pipe_process_limit"));

            limits = test_limits();
            limits.max_links_total = 2;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(!limited.complete);
            assert_eq!(limited.processes.values().map(|process| process.readers.len() + process.writers.len()).sum::<usize>(), 2);
            assert!(limited.unavailable.iter().any(|reason| reason == "pipe_total_link_limit"));

            limits = test_limits();
            limits.max_links_per_process = 1;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(!limited.complete);
            assert!(limited.processes.values().all(|process| process.readers.len() + process.writers.len() <= 1));

            limits = test_limits();
            limits.max_duration = Duration::ZERO;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(!limited.complete);
            assert_eq!(limited.descriptors_inspected, 0);
            assert!(limited.boot_id.is_none());

            fixture.endpoint(1, 2, 60, 1);
            limits = test_limits();
            limits.max_descriptors_per_process = 1;
            let limited = linux::collect_from(&fixture.root, &inputs, &limits, || {});
            assert!(!limited.processes[&1].complete);
            assert!(limited.processes[&1].endpoints.len() <= 1);
        }

        #[test]
        fn malformed_fdinfo_and_identity_fields_are_unknown_not_empty() {
            for invalid in [
                "flags:\t0\n",
                "ino:\t50\n",
                "flags:\t0\nflags:\t1\nino:\t50\n",
                "flags:\t0\nino:\t50\nino:\t51\n",
                "flags:\t08\nino:\t50\n",
                "flags:\t3\nino:\t50\n",
                "flags:\t-1\nino:\t50\n",
                "flags:\t0 1\nino:\t50\n",
                "flags:\t0\nino:\t+50\n",
                "flags:\t0\nino:\t51\n",
                "flags:\t0\nino:\t50",
            ] {
                let fixture = Fixture::pair();
                fs::write(fixture.root.join("2/fdinfo/0"), invalid).unwrap();
                let snapshot = fixture.collect(&[identity(1), identity(2)]);
                assert!(!snapshot.complete, "{invalid:?}");
                assert!(snapshot.processes[&1].readers.is_empty(), "{invalid:?}");
            }
            for status in [
                "",
                "Uid:\t1000 1000\n",
                "Uid:\t1000 +1000 1000 1000\n",
                "Uid:\t1000 1000 1000 1000\nUid:\t1000 1000 1000 1000\n",
                "Uid:\t1000 1000 1000 1000",
            ] {
                let fixture = Fixture::pair();
                fs::write(fixture.root.join("2/status"), status).unwrap();
                let snapshot = fixture.collect(&[identity(1), identity(2)]);
                assert!(!snapshot.processes[&2].identity_verified, "{status:?}");
                assert!(snapshot.processes[&1].readers.is_empty(), "{status:?}");
            }
        }

        struct OwnedChild(Child);

        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn observed_identity(path: &Path) -> PipeProcessIdentity {
            let stat = fs::read_to_string(path.join("stat")).unwrap();
            let close = stat.rfind(')').unwrap();
            let open = stat.find('(').unwrap();
            let pid = stat[..open].trim().parse().unwrap();
            let start_ticks = stat[close + 1..].split_whitespace().nth(19).unwrap().parse().unwrap();
            let status = fs::read_to_string(path.join("status")).unwrap();
            let uid = status.lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
            PipeProcessIdentity { pid, start_ticks, uid }
        }

        #[test]
        fn real_anonymous_pipeline_reports_exact_stream_endpoints_and_ignores_other_pipes() {
            let mut producer = OwnedChild(Command::new("sh")
                .args(["-c", "printf ready; exec sleep 30"])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn().unwrap());
            let producer_output = producer.0.stdout.take().unwrap();
            let consumer = OwnedChild(Command::new("cat")
                .stdin(Stdio::from(producer_output)).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().unwrap());
            let unrelated = OwnedChild(Command::new("sleep").arg("30")
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn().unwrap());
            let producer_id = observed_identity(&PathBuf::from(format!("/proc/{}", producer.0.id())));
            let consumer_id = observed_identity(&PathBuf::from(format!("/proc/{}", consumer.0.id())));
            let other_id = observed_identity(&PathBuf::from(format!("/proc/{}", unrelated.0.id())));
            let parent_id = observed_identity(Path::new("/proc/self"));
            let parent_fd = producer.0.stdin.as_ref().unwrap().as_raw_fd() as u32;
            let snapshot = collect_pipe_liveness(
                &[producer_id, consumer_id, other_id, parent_id],
                &test_limits(),
            );
            let writer = &snapshot.processes[&producer_id.pid];
            assert!(writer.identity_verified, "{snapshot:?}");
            assert!(writer.output_readers().any(|peer| {
                peer.identity == consumer_id && peer.local_fd == 1 && peer.peer_fd == 0
            }), "{snapshot:?}");
            assert!(!writer.readers.iter().any(|peer| peer.identity == other_id));
            assert!(writer.stdin_writers().any(|peer| {
                peer.identity == parent_id && peer.peer_fd == parent_fd
            }), "{snapshot:?}");
            // This seed is supplied explicitly to test graph traversal. The
            // collector does not claim that cat consumed bytes or made progress.
            let paths = snapshot.active_downstream_paths(&BTreeSet::from([consumer_id]), 32);
            assert_eq!(paths[&producer_id][0].identity, consumer_id);
        }
    }
}
