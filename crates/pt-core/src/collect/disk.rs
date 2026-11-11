//! Deleted-file allocation and filesystem capacity for disk recovery goals.
//!
//! Allocation is a forecast, never measured recovery or evidence of abandonment.
//! Positive credit requires a complete holder census, including memory mappings;
//! neither unreadable processes nor unmeasured files become observed zeroes.

use super::ProcessRecord;
use pt_common::ProcessIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn digest(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hex::encode(hash.finalize())
}

/// A mount binding in the collector's mount namespace, including the boot and
/// mount configuration. A pathname alone cannot identify comparable capacity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskMountIdentity {
    pub boot_id: String,
    pub mount_namespace_device: u64,
    pub mount_namespace_inode: u64,
    pub mount_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub filesystem_type: String,
    pub mount_root_sha256: String,
    pub mount_source_sha256: String,
    pub mount_options_sha256: String,
}

impl DiskMountIdentity {
    pub fn key(&self) -> String {
        digest([
            self.boot_id.clone(),
            self.mount_namespace_device.to_string(),
            self.mount_namespace_inode.to_string(),
            self.mount_id.to_string(),
            self.device_major.to_string(),
            self.device_minor.to_string(),
            self.filesystem_type.clone(),
            self.mount_root_sha256.clone(),
            self.mount_source_sha256.clone(),
            self.mount_options_sha256.clone(),
        ])
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.boot_id.trim().is_empty()
            || self.boot_id.contains(':')
            || self.mount_namespace_inode == 0
            || self.mount_id == 0
            || self.filesystem_type.trim().is_empty()
            || [
                &self.mount_root_sha256,
                &self.mount_source_sha256,
                &self.mount_options_sha256,
            ]
            .iter()
            .any(|value| value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err("disk_mount_identity_invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskMountObservation {
    pub identity: DiskMountIdentity,
    /// The observed mount point, not a deleted file name or command argument.
    pub mount_point: String,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub error: Option<String>,
    /// Observed allocation, counted once per inode. Not promised recovery.
    #[serde(default)]
    pub deleted_allocated_bytes: Option<u64>,
    #[serde(default)]
    pub known_holder_count: Option<usize>,
    #[serde(default)]
    pub ownership_complete: bool,
}

impl DiskMountObservation {
    pub fn validate_capacity(&self) -> Result<(), String> {
        self.identity.validate()?;
        let (Some(total), Some(free), Some(available)) =
            (self.total_bytes, self.free_bytes, self.available_bytes)
        else {
            return Err("disk_capacity_unavailable".into());
        };
        if self.error.is_some() || total == 0 || available > free || free > total {
            return Err("disk_capacity_invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeletedFileObservation {
    pub id: String,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub allocated_bytes: Option<u64>,
    pub logical_bytes: Option<u64>,
    /// None means a deleted-looking mapping could not be inspected through a
    /// live handle; a filename suffix alone never establishes link count zero.
    pub unlinked: Option<bool>,
    pub unnamed_temporary: bool,
    pub holders: Vec<ProcessIdentity>,
    pub mount_keys: Vec<String>,
    pub allocation_stable: bool,
    pub holders_complete: bool,
    pub path_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskProcessObservation {
    pub identity: ProcessIdentity,
    pub fd_count: u64,
    pub complete: bool,
    pub file_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskDiagnostic {
    pub pid: Option<u32>,
    /// Fixed codes only; OS errors can disclose file paths.
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskResourceSnapshot {
    pub observed_at: String,
    pub mounts: Vec<DiskMountObservation>,
    pub files: Vec<DeletedFileObservation>,
    pub processes: Vec<DiskProcessObservation>,
    /// Complete process descriptor/mapping coverage for supported local filesystems.
    /// Capacity observations have independent validity.
    pub complete: bool,
    pub diagnostics: Vec<DiskDiagnostic>,
    pub omitted_diagnostics: usize,
    pub limitations: Vec<String>,
}

impl DiskResourceSnapshot {
    fn note(&mut self, pid: Option<u32>, reason: &'static str) {
        if self.diagnostics.len() < 32 {
            self.diagnostics.push(DiskDiagnostic {
                pid,
                reason: reason.to_string(),
            });
        } else {
            self.omitted_diagnostics = self.omitted_diagnostics.saturating_add(1);
        }
    }

    fn diagnostic(&mut self, pid: Option<u32>, reason: &'static str) {
        self.complete = false;
        self.note(pid, reason);
    }

    pub fn mark_census_incomplete(&mut self) {
        self.diagnostic(None, "disk_process_census_incomplete");
        for file in &mut self.files {
            file.holders_complete = false;
        }
        for mount in &mut self.mounts {
            mount.ownership_complete = false;
        }
    }

    /// The optional selector is DiskMountIdentity::key(), never a pathname.
    /// A known second holder makes an inode's exclusive credit zero. Missing
    /// ownership or allocation prevents positive credit, rather than making it
    /// a zero-sized file. No lifecycle or data-loss gate is bypassed.
    pub fn exclusive_allocated_bytes(
        &self,
        identity: &ProcessIdentity,
        mount: Option<&str>,
    ) -> Result<u64, String> {
        if !identity.can_safely_revalidate() {
            return Err("disk_process_identity_unusable".into());
        }
        if let Some(key) = mount {
            let selected = self
                .mounts
                .iter()
                .find(|item| item.identity.key() == key)
                .ok_or("disk_mount_not_observed")?;
            selected.identity.validate()?;
        }
        let matches: Vec<_> = self
            .processes
            .iter()
            .filter(|process| process.identity.matches(identity)
                && process.identity.can_safely_revalidate()
                && identity.pgid.is_none_or(|pgid| process.identity.pgid == Some(pgid))
                && identity.sid.is_none_or(|sid| process.identity.sid == Some(sid)))
            .collect();
        if matches.len() != 1 || !matches[0].complete {
            return Err("disk_process_ownership_unavailable".into());
        }
        let mut total = 0u64;
        let mut seen = std::collections::BTreeSet::new();
        for id in &matches[0].file_ids {
            if !seen.insert(id) {
                return Err("disk_file_membership_ambiguous".into());
            }
            let file = self
                .files
                .iter()
                .find(|file| &file.id == id)
                .ok_or("disk_file_observation_missing")?;
            if mount.is_some_and(|key| !file.mount_keys.iter().any(|observed| observed == key)) {
                continue;
            }
            if file.unlinked == Some(false) {
                continue;
            }
            if !file.holders.iter().any(|holder| holder.matches(identity)) {
                return Err("disk_file_holder_identity_changed".into());
            }
            if file.holders.iter().any(|holder| !holder.matches(identity)) {
                continue;
            }
            if !self.complete || !file.holders_complete || !file.allocation_stable {
                return Err("disk_file_exclusive_ownership_unavailable".into());
            }
            if file.unlinked != Some(true) {
                return Err("disk_file_link_count_unavailable".into());
            }
            let bytes = file
                .allocated_bytes
                .ok_or("disk_file_allocation_unavailable")?;
            total = total
                .checked_add(bytes)
                .ok_or("disk_allocation_total_overflow")?;
        }
        Ok(total)
    }
}

#[cfg(target_os = "linux")]
pub use linux::{collect_disk_resources, observe_mount, resolve_mount};

#[cfg(not(target_os = "linux"))]
pub fn collect_disk_resources(_population: &[ProcessRecord]) -> DiskResourceSnapshot {
    let mut snapshot = DiskResourceSnapshot {
        observed_at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };
    snapshot.diagnostic(None, "disk_collection_unsupported_on_this_platform");
    snapshot
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_mount(_path: Option<&str>) -> Result<DiskMountObservation, String> {
    Err("disk_collection_unsupported_on_this_platform".into())
}

#[cfg(not(target_os = "linux"))]
pub fn observe_mount(_identity: &DiskMountIdentity) -> Result<DiskMountObservation, String> {
    Err("disk_collection_unsupported_on_this_platform".into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::collect::procfs::{self, FilesystemGuard, MountInfo};
    use pt_common::{IdentityQuality, StartId};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const MAX_FIELD: usize = 65_536;
    const MAX_MAPS: usize = 2_097_152;
    const MAX_PROCESSES: usize = 1024;
    const MAX_FDS: usize = 4096;
    const MAX_TASKS: usize = 256;
    const MAX_TOTAL_FDS: usize = 65_536;
    const MAX_FILES: usize = 2048;
    const MAX_MOUNTS: usize = 128;
    const BUDGET: Duration = Duration::from_secs(2);

    fn supported_disk(filesystem: &str) -> bool {
        matches!(
            filesystem,
            "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "overlay" | "zfs"
        )
    }

    struct Context {
        boot: String,
        namespace_device: u64,
        namespace_inode: u64,
        mounts: BTreeMap<u64, MountInfo>,
        mount_table_sha256: String,
        guard: FilesystemGuard,
    }

    impl Context {
        fn load() -> Result<Self, &'static str> {
            let boot = procfs::read_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
            let boot = std::str::from_utf8(&boot)
                .map_err(|_| "disk_boot_identity_invalid")?
                .trim();
            if boot.is_empty() || boot.contains(':') {
                return Err("disk_boot_identity_invalid");
            }
            let namespace = fs::metadata("/proc/self/ns/mnt")
                .map_err(|_| "disk_mount_namespace_unavailable")?;
            let raw = procfs::read_bounded(Path::new("/proc/self/mountinfo"), MAX_MAPS)?;
            Ok(Self {
                boot: boot.to_string(),
                namespace_device: namespace.dev(),
                namespace_inode: namespace.ino(),
                mounts: procfs::parse_mountinfo(&raw)?,
                mount_table_sha256: digest([&raw]),
                guard: FilesystemGuard::parse(&raw)?,
            })
        }

        fn identity(&self, mount: &MountInfo) -> DiskMountIdentity {
            DiskMountIdentity {
                boot_id: self.boot.clone(),
                mount_namespace_device: self.namespace_device,
                mount_namespace_inode: self.namespace_inode,
                mount_id: mount.id,
                device_major: mount.device_major,
                device_minor: mount.device_minor,
                filesystem_type: mount.filesystem_type.clone(),
                mount_root_sha256: digest([mount.root.as_bytes()]),
                mount_source_sha256: digest([mount.source.as_bytes()]),
                mount_options_sha256: digest([mount.mount_options.as_bytes(), mount.super_options.as_bytes()]),
            }
        }

        fn binding_matches(&self, identity: &DiskMountIdentity) -> bool {
            self.mounts
                .get(&identity.mount_id)
                .is_some_and(|mount| self.identity(mount) == *identity)
        }

        fn resolve(&self, path: Option<&str>, deadline: Instant) -> Result<File, &'static str> {
            let cwd = procfs::open_directory(Path::new("/proc/self/cwd"))?;
            self.guard
                .resolve_directory(&cwd, Path::new(path.unwrap_or(".")), 64, deadline)
        }
    }

    fn capacity(context: &Context, handle: &File) -> Result<DiskMountObservation, &'static str> {
        if !context.guard.permits(handle) {
            return Err("disk_filesystem_unsupported");
        }
        let mount_id = procfs::mount_id(handle).ok_or("disk_mount_identity_unavailable")?;
        let mount = context
            .mounts
            .get(&mount_id)
            .ok_or("disk_mount_identity_unavailable")?;
        if !supported_disk(&mount.filesystem_type) {
            return Err("disk_filesystem_not_persistent");
        }
        let metadata = handle
            .metadata()
            .map_err(|_| "disk_mount_metadata_unavailable")?;
        if libc::major(metadata.dev()) != mount.device_major
            || libc::minor(metadata.dev()) != mount.device_minor
        {
            return Err("disk_mount_device_changed");
        }
        let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the descriptor is held and the writable statvfs storage is
        // valid. Its mount was classified through procfs before this syscall.
        if unsafe { libc::fstatvfs(handle.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err("disk_capacity_unavailable");
        }
        // SAFETY: successful fstatvfs initialized the entire structure.
        let status = unsafe { status.assume_init() };
        if status.f_frsize == 0 {
            return Err("disk_capacity_unit_invalid");
        }
        let bytes = |blocks: libc::fsblkcnt_t| {
            u64::try_from(u128::from(blocks) * u128::from(status.f_frsize))
                .map_err(|_| "disk_capacity_overflow")
        };
        let observed = DiskMountObservation {
            identity: context.identity(mount),
            mount_point: mount.mount_point.clone(),
            total_bytes: Some(bytes(status.f_blocks)?),
            free_bytes: Some(bytes(status.f_bfree)?),
            available_bytes: Some(bytes(status.f_bavail)?),
            ..Default::default()
        };
        observed
            .validate_capacity()
            .map_err(|_| "disk_capacity_invalid")?;
        Ok(observed)
    }

    /// Resolve an existing directory, defaulting to the caller's cwd, without
    /// following symlinks or traversing unsupported filesystems. The result is
    /// a stable mount binding that can be saved in a plan.
    pub fn resolve_mount(path: Option<&str>) -> Result<DiskMountObservation, String> {
        let context = Context::load().map_err(str::to_string)?;
        let handle = context
            .resolve(path, Instant::now() + BUDGET)
            .map_err(str::to_string)?;
        let observed = capacity(&context, &handle).map_err(str::to_string)?;
        let after = Context::load().map_err(str::to_string)?;
        if !after.binding_matches(&observed.identity) {
            return Err("disk_mount_changed_during_observation".into());
        }
        Ok(observed)
    }

    /// Re-observe exactly the planned mount identity. Remounts, namespace or
    /// boot changes remain unavailable rather than comparing unrelated space.
    pub fn observe_mount(identity: &DiskMountIdentity) -> Result<DiskMountObservation, String> {
        identity.validate()?;
        let context = Context::load().map_err(str::to_string)?;
        if !context.binding_matches(identity) {
            return Err("disk_mount_identity_changed".into());
        }
        let mount = context
            .mounts
            .get(&identity.mount_id)
            .ok_or("disk_mount_identity_unavailable")?;
        let handle = context
            .resolve(Some(&mount.mount_point), Instant::now() + BUDGET)
            .map_err(str::to_string)?;
        let observed = capacity(&context, &handle).map_err(str::to_string)?;
        if observed.identity != *identity
            || !Context::load()
                .map_err(str::to_string)?
                .binding_matches(identity)
        {
            return Err("disk_mount_changed_during_observation".into());
        }
        Ok(observed)
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct FileKey {
        major: u32,
        minor: u32,
        inode: u64,
    }

    impl FileKey {
        fn from_metadata(metadata: &fs::Metadata) -> Self {
            Self {
                major: libc::major(metadata.dev()),
                minor: libc::minor(metadata.dev()),
                inode: metadata.ino(),
            }
        }

        fn id(&self, boot: &str) -> String {
            digest([
                boot.to_string(),
                self.major.to_string(),
                self.minor.to_string(),
                self.inode.to_string(),
            ])
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Mapping {
        range: String,
        key: FileKey,
        path_sha256: String,
        deleted_name: bool,
        unnamed_temporary: bool,
    }

    fn mappings(bytes: &[u8]) -> Result<BTreeSet<Mapping>, &'static str> {
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return Err("disk_mapping_table_incomplete");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "disk_mapping_table_invalid")?;
        let mut result = BTreeSet::new();
        for line in text.lines() {
            let mut remainder = line;
            let mut fields = Vec::new();
            for _ in 0..5 {
                remainder = remainder.trim_start_matches(char::is_whitespace);
                let end = remainder
                    .find(char::is_whitespace)
                    .unwrap_or(remainder.len());
                if end == 0 {
                    return Err("disk_mapping_table_invalid");
                }
                fields.push(&remainder[..end]);
                remainder = &remainder[end..];
            }
            let (start, end) = fields[0]
                .split_once('-')
                .ok_or("disk_mapping_range_invalid")?;
            let start = u64::from_str_radix(start, 16).map_err(|_| "disk_mapping_range_invalid")?;
            let end = u64::from_str_radix(end, 16).map_err(|_| "disk_mapping_range_invalid")?;
            let (major, minor) = fields[3]
                .split_once(':')
                .ok_or("disk_mapping_device_invalid")?;
            let major =
                u32::from_str_radix(major, 16).map_err(|_| "disk_mapping_device_invalid")?;
            let minor =
                u32::from_str_radix(minor, 16).map_err(|_| "disk_mapping_device_invalid")?;
            let inode = fields[4]
                .parse::<u64>()
                .map_err(|_| "disk_mapping_inode_invalid")?;
            if start >= end || fields[1].len() != 4 || u64::from_str_radix(fields[2], 16).is_err() {
                return Err("disk_mapping_table_invalid");
            }
            let permissions = fields[1].as_bytes();
            if !matches!(permissions[0], b'r' | b'-')
                || !matches!(permissions[1], b'w' | b'-')
                || !matches!(permissions[2], b'x' | b'-')
                || !matches!(permissions[3], b'p' | b's')
            {
                return Err("disk_mapping_permissions_invalid");
            }
            if inode == 0 {
                continue;
            }
            let path = remainder.trim_start_matches(char::is_whitespace);
            result.insert(Mapping {
                range: fields[0].to_string(),
                key: FileKey {
                    major,
                    minor,
                    inode,
                },
                path_sha256: digest([path.as_bytes()]),
                deleted_name: path.ends_with(" (deleted)"),
                unnamed_temporary: unnamed_temporary(path.as_bytes()),
            });
        }
        Ok(result)
    }

    struct PinnedProcess {
        directory: File,
    }

    impl PinnedProcess {
        fn open(root: &Path, pid: u32) -> Result<Self, &'static str> {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root.join(pid.to_string()))
                .map(|directory| Self { directory })
                .map_err(|_| "disk_process_directory_unavailable")
        }

        fn path(&self, field: &str) -> PathBuf {
            procfs::directory_path(&self.directory, field)
        }

        fn read(&self, field: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
            procfs::read_bounded(&self.path(field), limit)
        }

        fn identity(&self, pid: u32, boot: &str) -> Result<ProcessState, &'static str> {
            let raw = self.read("stat", MAX_FIELD)?;
            let text = std::str::from_utf8(&raw).map_err(|_| "disk_process_stat_invalid")?;
            let open = text.find('(').ok_or("disk_process_stat_invalid")?;
            let close = text
                .rfind(')')
                .filter(|&close| close > open)
                .ok_or("disk_process_stat_invalid")?;
            if !text.ends_with('\n') || text[..open].trim().parse::<u32>().ok() != Some(pid) {
                return Err("disk_process_stat_invalid");
            }
            let fields: Vec<_> = text[close + 1..].split_whitespace().collect();
            if fields.len() < 22 || fields[0].len() != 1 {
                return Err("disk_process_stat_incomplete");
            }
            let state = fields[0].as_bytes()[0];
            if !matches!(
                state,
                b'R' | b'S' | b'D' | b'T' | b't' | b'Z' | b'I' | b'P' | b'W' | b'K'
            ) {
                return Err("disk_process_state_unavailable");
            }
            let parent = fields[1]
                .parse::<u32>()
                .map_err(|_| "disk_process_stat_invalid")?;
            let pgid = fields[2]
                .parse::<u32>()
                .map_err(|_| "disk_process_stat_invalid")?;
            let sid = fields[3]
                .parse::<u32>()
                .map_err(|_| "disk_process_stat_invalid")?;
            let threads = fields[17].parse::<usize>()
                .ok().filter(|threads| *threads > 0).ok_or("disk_task_count_invalid")?;
            let flags = fields[6]
                .parse::<u64>()
                .map_err(|_| "disk_process_stat_invalid")?;
            let ticks = fields[19]
                .parse::<u64>()
                .map_err(|_| "disk_process_stat_invalid")?;
            let raw_status = self.read("status", MAX_FIELD)?;
            let status =
                std::str::from_utf8(&raw_status).map_err(|_| "disk_process_uid_invalid")?;
            let mut lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
            let uids = lines
                .next()
                .ok_or("disk_process_uid_unavailable")?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "disk_process_uid_invalid")?;
            if uids.len() != 4 || lines.next().is_some() {
                return Err("disk_process_uid_invalid");
            }
            Ok(ProcessState {
                identity: ProcessIdentity::full(
                    pid,
                    StartId::from_linux(boot, ticks, pid),
                    uids[1],
                    Some(pgid),
                    Some(sid),
                    IdentityQuality::Full,
                ),
                parent,
                comm: text[open + 1..close].to_string(),
                kernel_thread: flags & 0x0020_0000 != 0,
                threads,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ProcessState {
        identity: ProcessIdentity,
        parent: u32,
        comm: String,
        kernel_thread: bool,
        threads: usize,
    }

    impl ProcessState {
        fn matches_record(&self, process: &ProcessRecord) -> bool {
            self.identity.pid == process.pid
                && self.identity.start_id == process.start_id
                && self.identity.uid == process.uid
                && self.parent == process.ppid.0
                && self.comm == process.comm
                && process
                    .pgid
                    .is_none_or(|pgid| self.identity.pgid == Some(pgid))
                && process.sid.is_none_or(|sid| self.identity.sid == Some(sid))
                && process.state != super::super::ProcessState::Unknown
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Descriptor {
        task_id: u32,
        fd: u32,
        mount_id: u64,
        inode: u64,
        flags: u32,
        link_sha256: String,
    }

    fn descriptor_info(bytes: &[u8]) -> Result<(u64, u64, u32), &'static str> {
        if bytes.last() != Some(&b'\n') {
            return Err("disk_descriptor_information_incomplete");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "disk_descriptor_information_invalid")?;
        let (mut mount, mut inode, mut flags) = (None, None, None);
        for line in text.lines() {
            let (name, value) = line
                .split_once(':')
                .ok_or("disk_descriptor_information_invalid")?;
            match name {
                "mnt_id" => {
                    if mount
                        .replace(
                            value
                                .trim()
                                .parse::<u64>()
                                .map_err(|_| "disk_descriptor_mount_invalid")?,
                        )
                        .is_some()
                    {
                        return Err("disk_descriptor_mount_ambiguous");
                    }
                }
                "ino" => {
                    if inode
                        .replace(
                            value
                                .trim()
                                .parse::<u64>()
                                .map_err(|_| "disk_descriptor_inode_invalid")?,
                        )
                        .is_some()
                    {
                        return Err("disk_descriptor_inode_ambiguous");
                    }
                }
                "flags" => {
                    if flags
                        .replace(
                            u32::from_str_radix(value.trim(), 8)
                                .map_err(|_| "disk_descriptor_flags_invalid")?,
                        )
                        .is_some()
                    {
                        return Err("disk_descriptor_flags_ambiguous");
                    }
                }
                _ => {}
            }
        }
        Ok((
            mount.ok_or("disk_descriptor_mount_missing")?,
            inode.ok_or("disk_descriptor_inode_missing")?,
            flags.ok_or("disk_descriptor_flags_missing")?,
        ))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Allocation {
        key: FileKey,
        bytes: u64,
        logical: u64,
        unnamed_temporary: bool,
        path_sha256: String,
    }

    fn unnamed_temporary(path: &[u8]) -> bool {
        path.strip_suffix(b" (deleted)")
            .unwrap_or(path)
            .rsplit(|&byte| byte == b'/')
            .next()
            .and_then(|name| name.strip_prefix(b"#"))
            .is_some_and(|name| !name.is_empty() && name.iter().all(u8::is_ascii_digit))
    }

    fn allocation_from_handle(
        context: &Context,
        handle: &File,
        expected: &FileKey,
        path: &[u8],
    ) -> Result<Option<Allocation>, &'static str> {
        if !context.guard.permits(handle) {
            return Err("disk_file_filesystem_unsupported");
        }
        let mount = procfs::mount_id(handle)
            .and_then(|id| context.mounts.get(&id))
            .ok_or("disk_file_mount_unavailable")?;
        if !supported_disk(&mount.filesystem_type) {
            return Ok(None);
        }
        let first = handle
            .metadata()
            .map_err(|_| "disk_file_metadata_unavailable")?;
        if !first.is_file() || first.nlink() > 0 {
            return Ok(None);
        }
        if FileKey::from_metadata(&first) != *expected {
            return Err("disk_descriptor_file_changed");
        }
        let bytes = first
            .blocks()
            .checked_mul(512)
            .ok_or("disk_file_allocation_overflow")?;
        let after = handle
            .metadata()
            .map_err(|_| "disk_file_metadata_unavailable")?;
        if FileKey::from_metadata(&after) != *expected
            || after.nlink() != 0
            || after.blocks() != first.blocks()
            || after.len() != first.len()
        {
            return Err("disk_file_allocation_changed");
        }
        Ok(Some(Allocation {
            key: expected.clone(),
            bytes,
            logical: first.len(),
            unnamed_temporary: unnamed_temporary(path),
            path_sha256: digest([path]),
        }))
    }

    struct ProcessSample {
        state: ProcessState,
        tasks: BTreeMap<u32, ProcessState>,
        fd_count: u64,
        descriptors: BTreeSet<Descriptor>,
        mappings: BTreeSet<Mapping>,
        allocations: BTreeMap<FileKey, Allocation>,
    }

    fn task_census(process: &PinnedProcess, deadline: Instant) -> Result<BTreeSet<u32>, &'static str> {
        let entries = fs::read_dir(process.path("task")).map_err(|_| "disk_task_census_unavailable")?;
        let mut tasks = BTreeSet::new();
        for entry in entries {
            if tasks.len() >= MAX_TASKS { return Err("disk_task_count_limit"); }
            if Instant::now() >= deadline { return Err("disk_collection_time_budget"); }
            let entry = entry.map_err(|_| "disk_task_census_incomplete")?;
            let tid = entry.file_name().to_str().and_then(|value| value.parse::<u32>().ok())
                .filter(|tid| *tid > 0).ok_or("disk_task_id_invalid")?;
            tasks.insert(tid);
        }
        Ok(tasks)
    }

    fn inspect_descriptors(
        process: &PinnedProcess,
        task_id: u32,
        context: &Context,
        deadline: Instant,
        total_fds: &mut usize,
        sample: &mut ProcessSample,
    ) -> Result<(), &'static str> {
        use std::os::unix::ffi::OsStrExt;
        let entries = fs::read_dir(process.path("fd")).map_err(|_| "disk_descriptor_table_unavailable")?;
        let mut task_fds = 0;
        // Keep the iterator alive while inspecting entries. The collector's
        // transient procfs handles are excluded by filesystem type.
        for entry in entries {
            if task_fds >= MAX_FDS || *total_fds >= MAX_TOTAL_FDS {
                return Err("disk_descriptor_count_limit");
            }
            if Instant::now() >= deadline { return Err("disk_collection_time_budget"); }
            let entry = entry.map_err(|_| "disk_descriptor_table_incomplete")?;
            let fd = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok())
                .ok_or("disk_descriptor_name_invalid")?;
            task_fds += 1;
            *total_fds += 1;
            // Retain the leader count for conventional per-process FD displays;
            // every task's table still participates in ownership and budgets.
            if task_id == sample.state.identity.pid.0 { sample.fd_count += 1; }
            let target = fs::read_link(entry.path()).map_err(|_| "disk_descriptor_link_unavailable")?;
            let target = target.as_os_str().as_bytes();
            if !target.starts_with(b"/") || target.starts_with(b"/memfd:") { continue; }
            let (mount_id, inode, flags) = descriptor_info(&process.read(&format!("fdinfo/{fd}"), MAX_FIELD)?)?;
            let mount = context.mounts.get(&mount_id).ok_or("disk_descriptor_mount_outside_scope")?;
            if !supported_disk(&mount.filesystem_type) { continue; }
            sample.descriptors.insert(Descriptor { task_id, fd, mount_id, inode, flags, link_sha256: digest([target]) });
            if !target.ends_with(b" (deleted)") { continue; }
            let handle = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(entry.path()).map_err(|_| "disk_file_handle_unavailable")?;
            let expected = FileKey { major: mount.device_major, minor: mount.device_minor, inode };
            if let Some(observed) = allocation_from_handle(context, &handle, &expected, target)? {
                if sample.allocations.len() >= MAX_FILES && !sample.allocations.contains_key(&expected) {
                    return Err("disk_file_count_limit");
                }
                if let Some(previous) = sample.allocations.get_mut(&expected) {
                    if previous.key != observed.key || previous.bytes != observed.bytes || previous.logical != observed.logical {
                        return Err("disk_file_allocation_changed");
                    }
                    previous.unnamed_temporary |= observed.unnamed_temporary;
                    if observed.path_sha256 < previous.path_sha256 { previous.path_sha256 = observed.path_sha256; }
                } else {
                    sample.allocations.insert(expected, observed);
                }
            }
            if descriptor_info(&process.read(&format!("fdinfo/{fd}"), MAX_FIELD)?)? != (mount_id, inode, flags) {
                return Err("disk_descriptor_file_changed");
            }
        }
        Ok(())
    }

    fn sample_process(
        root: &Path,
        pid: u32,
        context: &Context,
        deadline: Instant,
        total_fds: &mut usize,
    ) -> Result<ProcessSample, &'static str> {
        if Instant::now() >= deadline { return Err("disk_collection_time_budget"); }
        let process = PinnedProcess::open(root, pid)?;
        let state = process.identity(pid, &context.boot)?;
        let mut sample = ProcessSample {
            state, tasks: BTreeMap::new(), fd_count: 0, descriptors: BTreeSet::new(),
            mappings: BTreeSet::new(), allocations: BTreeMap::new(),
        };
        if sample.state.threads == 1 {
            inspect_descriptors(&process, pid, context, deadline, total_fds, &mut sample)?;
            sample.tasks.insert(pid, sample.state.clone());
        } else {
            let tasks = task_census(&process, deadline)?;
            if tasks.len() != sample.state.threads || !tasks.contains(&pid) {
                return Err("disk_task_census_changed");
            }
            for &tid in &tasks {
                let task = PinnedProcess::open(&process.path("task"), tid)?;
                let before = task.identity(tid, &context.boot)?;
                if before.kernel_thread || before.threads != sample.state.threads {
                    return Err("disk_task_identity_inconsistent");
                }
                inspect_descriptors(&task, tid, context, deadline, total_fds, &mut sample)?;
                if task.identity(tid, &context.boot)? != before { return Err("disk_task_identity_changed"); }
                sample.tasks.insert(tid, before);
            }
            if task_census(&process, deadline)? != tasks { return Err("disk_task_census_changed"); }
        }
        // Threads in a stable thread group share the mm. Per-task FD tables
        // may differ after unshare(CLONE_FILES), so all of those were inspected.
        sample.mappings = mappings(&process.read("maps", MAX_MAPS)?)?;
        if process.identity(pid, &context.boot)? != sample.state {
            return Err("disk_process_identity_changed");
        }
        Ok(sample)
    }

    fn census(root: &Path) -> Result<BTreeSet<u32>, &'static str> {
        let entries = fs::read_dir(root).map_err(|_| "disk_process_census_unavailable")?;
        let mut pids = BTreeSet::new();
        for entry in entries {
            let entry = entry.map_err(|_| "disk_process_census_incomplete")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
                let pid = name.parse::<u32>().map_err(|_| "disk_process_id_invalid")?;
                if pid == 0 {
                    return Err("disk_process_id_invalid");
                }
                pids.insert(pid);
            }
        }
        Ok(pids)
    }

    fn unrestricted_procfs(context: &Context) -> bool {
        let proc_mounts: Vec<_> = context.mounts.values()
            .filter(|mount| mount.mount_point == "/proc").collect();
        if proc_mounts.len() != 1 || proc_mounts[0].filesystem_type != "proc" {
            return false;
        }
        let mount = proc_mounts[0];
        let split = |character: char| character == ',' || character.is_whitespace() || character == ';';
        !mount.mount_options.split(split).chain(mount.super_options.split(split)).any(|option| {
            option.strip_prefix("hidepid=").is_some_and(|value| !matches!(value, "0" | "off"))
                || option.strip_prefix("subset=").is_some_and(|value| value != "all")
        })
    }

    fn mount_observations(
        context: &Context,
        deadline: Instant,
        snapshot: &mut DiskResourceSnapshot,
    ) {
        let mut count = 0;
        for mount in context
            .mounts
            .values()
            .filter(|mount| supported_disk(&mount.filesystem_type))
        {
            if count >= MAX_MOUNTS || Instant::now() >= deadline {
                snapshot.note(None, "disk_mount_observation_budget");
                break;
            }
            count += 1;
            let observation = context
                .resolve(Some(&mount.mount_point), deadline)
                .and_then(|handle| capacity(context, &handle))
                .and_then(|observed| {
                    if observed.identity == context.identity(mount) {
                        Ok(observed)
                    } else {
                        Err("disk_mount_identity_changed")
                    }
                });
            match observation {
                Ok(observed) => snapshot.mounts.push(observed),
                Err(reason) => {
                    snapshot.note(None, reason);
                    snapshot.mounts.push(DiskMountObservation {
                        identity: context.identity(mount),
                        mount_point: mount.mount_point.clone(),
                        error: Some(reason.to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn new_file(context: &Context, key: &FileKey) -> DeletedFileObservation {
        DeletedFileObservation {
            id: key.id(&context.boot),
            device_major: key.major,
            device_minor: key.minor,
            inode: key.inode,
            mount_keys: context
                .mounts
                .values()
                .filter(|mount| {
                    supported_disk(&mount.filesystem_type)
                        && mount.device_major == key.major
                        && mount.device_minor == key.minor
                })
                .map(|mount| context.identity(mount).key())
                .collect(),
            allocation_stable: true,
            ..Default::default()
        }
    }

    fn add_allocation(file: &mut DeletedFileObservation, allocation: &Allocation) {
        if file
            .allocated_bytes
            .is_some_and(|bytes| bytes != allocation.bytes)
            || file
                .logical_bytes
                .is_some_and(|bytes| bytes != allocation.logical)
        {
            file.allocation_stable = false;
        }
        file.allocated_bytes = Some(
            file.allocated_bytes
                .map_or(allocation.bytes, |bytes| bytes.min(allocation.bytes)),
        );
        file.logical_bytes = Some(
            file.logical_bytes
                .map_or(allocation.logical, |bytes| bytes.min(allocation.logical)),
        );
        file.unlinked = Some(true);
        file.unnamed_temporary |= allocation.unnamed_temporary;
        if file
            .path_sha256
            .as_ref()
            .is_none_or(|path| path > &allocation.path_sha256)
        {
            file.path_sha256 = Some(allocation.path_sha256.clone());
        }
    }

    fn mapping_allocation(
        root: &Path,
        sample: &ProcessSample,
        mapping: &Mapping,
        context: &Context,
    ) -> Result<Option<Allocation>, &'static str> {
        let process = PinnedProcess::open(root, sample.state.identity.pid.0)?;
        if process.identity(sample.state.identity.pid.0, &context.boot)? != sample.state {
            return Err("disk_process_identity_changed");
        }
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(process.path(&format!("map_files/{}", mapping.range)))
            .map_err(|_| "disk_mapping_allocation_unavailable")?;
        let mut result = allocation_from_handle(context, &handle, &mapping.key, b"")?;
        if let Some(allocation) = &mut result {
            allocation.path_sha256 = mapping.path_sha256.clone();
            allocation.unnamed_temporary = mapping.unnamed_temporary;
        }
        if process.identity(sample.state.identity.pid.0, &context.boot)? != sample.state {
            return Err("disk_process_identity_changed");
        }
        Ok(result)
    }

    fn revalidate_mapping_allocations(
        root: &Path,
        context: &Context,
        deadline: Instant,
        process_samples: (&BTreeMap<u32, ProcessSample>, &BTreeSet<u32>),
        measurements: &BTreeMap<u32, Vec<Mapping>>,
        files: &mut BTreeMap<FileKey, DeletedFileObservation>,
        snapshot: &mut DiskResourceSnapshot,
    ) {
        let (samples, valid_processes) = process_samples;
        for (&pid, mappings) in measurements {
            for mapping in mappings {
                let Some(file) = files.get_mut(&mapping.key) else { continue; };
                let result = if valid_processes.contains(&pid) && Instant::now() < deadline {
                    samples.get(&pid).ok_or("disk_mapping_process_unavailable")
                        .and_then(|sample| mapping_allocation(root, sample, mapping, context))
                } else { Err("disk_mapping_revalidation_unavailable") };
                match result {
                    Ok(Some(allocation)) => add_allocation(file, &allocation),
                    Ok(None) => {
                        file.allocation_stable = false;
                        file.allocated_bytes = None;
                        file.unlinked = None;
                        snapshot.note(Some(pid), "disk_mapping_link_state_changed");
                    }
                    Err(reason) => {
                        file.allocation_stable = false;
                        file.allocated_bytes = None;
                        snapshot.note(Some(pid), reason);
                    }
                }
            }
        }
    }

    fn summarize_mount_ownership(snapshot: &mut DiskResourceSnapshot) {
        for mount in &mut snapshot.mounts {
            let key = mount.identity.key();
            let mut bytes = 0u64;
            let mut holders = BTreeSet::new();
            let mut allocation_complete = true;
            for file in snapshot
                .files
                .iter()
                .filter(|file| file.mount_keys.contains(&key))
            {
                for holder in &file.holders {
                    holders.insert(holder.pid.0);
                }
                match (file.unlinked, file.allocated_bytes) {
                    (Some(true), Some(allocated)) => {
                        if let Some(total) = bytes.checked_add(allocated) {
                            bytes = total;
                        } else {
                            allocation_complete = false;
                        }
                    }
                    (Some(false), _) => {}
                    _ => allocation_complete = false,
                }
                allocation_complete &= file.allocation_stable;
            }
            mount.deleted_allocated_bytes = allocation_complete.then_some(bytes);
            mount.known_holder_count = Some(holders.len());
            mount.ownership_complete = snapshot.complete;
        }
    }

    /// Inspect all visible user processes, including protected/noncandidate
    /// processes, and compare both descriptors and file-backed mappings twice.
    /// No file is read, truncated, unlinked, or signalled by this collector.
    pub fn collect_disk_resources(population: &[ProcessRecord]) -> DiskResourceSnapshot {
        match Context::load() {
            Ok(context) => collect_from(population, Path::new("/proc"), context, BUDGET),
            Err(reason) => {
                let mut snapshot = DiskResourceSnapshot {
                    observed_at: chrono::Utc::now().to_rfc3339(),
                    ..Default::default()
                };
                snapshot.diagnostic(None, reason);
                snapshot
            }
        }
    }

    fn attach_holders(
        snapshot: &mut DiskResourceSnapshot,
        samples: &BTreeMap<u32, ProcessSample>,
        files: &mut BTreeMap<FileKey, DeletedFileObservation>,
        valid_processes: &BTreeSet<u32>,
        incomplete_catalogs: &BTreeSet<u32>,
    ) {
        for sample in samples.values() {
            let held: BTreeSet<_> = sample
                .allocations
                .keys()
                .chain(sample.mappings.iter().map(|mapping| &mapping.key))
                .cloned()
                .collect();
            let mut file_ids = Vec::new();
            for key in held {
                if let Some(file) = files.get_mut(&key) {
                    file.holders.push(sample.state.identity.clone());
                    file_ids.push(file.id.clone());
                }
            }
            snapshot.processes.push(DiskProcessObservation {
                identity: sample.state.identity.clone(),
                fd_count: sample.fd_count,
                complete: valid_processes.contains(&sample.state.identity.pid.0)
                    && !incomplete_catalogs.contains(&sample.state.identity.pid.0),
                file_ids,
            });
        }
    }

    fn collect_from(
        population: &[ProcessRecord],
        root: &Path,
        context: Context,
        budget: Duration,
    ) -> DiskResourceSnapshot {
        let deadline = Instant::now() + budget;
        let mut snapshot = DiskResourceSnapshot {
            observed_at: chrono::Utc::now().to_rfc3339(), complete: true,
            limitations: vec![
                "Allocated 512-byte blocks are potential recovery, not guaranteed released filesystem space; shared extents, delayed accounting, new writes and concurrent work can change the result".into(),
                "Complete coverage concerns process descriptors and mappings; kernel-held references such as queued SCM_RIGHTS or io_uring registered files can retain storage after those close".into(),
                "Only supported local persistent filesystems in the collector mount namespace are included. tmpfs, memfd, network and FUSE storage are not disk-goal contributions".into(),
                "Exclusive credit requires complete process, descriptor and mapping coverage. A mounted procfs view inside a PID namespace cannot establish absence of outside holders".into(),
                "Unnamed temporary files remain subject to the existing data-loss gates; disk attribution never authorizes a kill or truncation".into(),
                "Collection is bounded by process, descriptor, file, byte and elapsed-work limits. Individual kernel filesystem calls are not cancellable".into(),
            ], ..Default::default()
        };
        mount_observations(&context, deadline, &mut snapshot);
        let pids = match census(root) {
            Ok(pids) => pids,
            Err(reason) => {
                snapshot.diagnostic(None, reason);
                return snapshot;
            }
        };
        if !unrestricted_procfs(&context) {
            snapshot.diagnostic(None, "disk_procfs_visibility_restricted_or_unknown");
        }
        let mut expected = BTreeMap::new();
        for process in population {
            expected
                .entry(process.pid.0)
                .and_modify(|slot| *slot = None)
                .or_insert(Some(process));
        }
        let mut samples = BTreeMap::new();
        let mut total_fds = 0;
        let mut host_anchor_observed = false;
        let mut ordered: Vec<_> = pids.iter().copied().collect();
        ordered.sort_by_key(|pid| (*pid != std::process::id(), *pid));
        for (attempt, pid) in ordered.into_iter().enumerate() {
            if attempt >= MAX_PROCESSES {
                snapshot.diagnostic(None, "disk_process_count_limit");
                break;
            }
            if Instant::now() >= deadline {
                snapshot.diagnostic(None, "disk_collection_time_budget");
                break;
            }
            match sample_process(root, pid, &context, deadline, &mut total_fds) {
                Ok(sample) => {
                    host_anchor_observed |= sample.state.kernel_thread
                        && sample.state.identity.pid.0 == 2
                        && sample.state.parent == 0
                        && sample.state.identity.uid == 0
                        && sample.state.comm == "kthreadd";
                    if !sample.state.kernel_thread {
                        if !expected
                            .get(&pid)
                            .copied()
                            .flatten()
                            .is_some_and(|process| sample.state.matches_record(process))
                        {
                            snapshot.diagnostic(
                                Some(pid),
                                "disk_supplied_census_identity_missing_or_changed",
                            );
                        }
                    }
                    samples.insert(pid, sample);
                }
                Err(reason) => snapshot.diagnostic(Some(pid), reason),
            }
        }
        // Linux creates PID 2 kthreadd in init_pid_ns during boot; its PID
        // namespace cannot change. The kernel flag prevents a user process
        // named kthreadd from satisfying this deliberately narrow host-view
        // proof. Absence stays unknown; NS_GET_PARENT's EPERM is ambiguous.
        if !host_anchor_observed {
            snapshot.diagnostic(None, "disk_host_process_visibility_unproven");
        }
        if expected.keys().any(|pid| !pids.contains(pid)) {
            snapshot.diagnostic(None, "disk_supplied_census_process_missing");
        }
        let mut files = BTreeMap::<FileKey, DeletedFileObservation>::new();
        let mut incomplete_catalogs = BTreeSet::new();
        for sample in samples.values() {
            for allocation in sample.allocations.values() {
                if files.len() >= MAX_FILES && !files.contains_key(&allocation.key) {
                    snapshot.diagnostic(None, "disk_file_count_limit");
                    incomplete_catalogs.insert(sample.state.identity.pid.0);
                    continue;
                }
                let file = files
                    .entry(allocation.key.clone())
                    .or_insert_with(|| new_file(&context, &allocation.key));
                add_allocation(file, allocation);
            }
        }
        let mut mapping_attempts = 0;
        let mut mapping_measurements = BTreeMap::<u32, Vec<Mapping>>::new();
        for sample in samples.values() {
            for mapping in sample
                .mappings
                .iter()
                .filter(|mapping| mapping.deleted_name)
            {
                if files.contains_key(&mapping.key) {
                    continue;
                }
                if !context.mounts.values().any(|mount| {
                    supported_disk(&mount.filesystem_type)
                        && mount.device_major == mapping.key.major
                        && mount.device_minor == mapping.key.minor
                }) {
                    continue;
                }
                if files.len() >= MAX_FILES {
                    snapshot.diagnostic(None, "disk_file_count_limit");
                    incomplete_catalogs.insert(sample.state.identity.pid.0);
                    break;
                }
                let mut file = new_file(&context, &mapping.key);
                file.path_sha256 = Some(mapping.path_sha256.clone());
                file.unnamed_temporary = mapping.unnamed_temporary;
                if mapping_attempts < MAX_FILES && Instant::now() < deadline {
                    mapping_attempts += 1;
                    match mapping_allocation(root, sample, mapping, &context) {
                        Ok(Some(allocation)) => {
                            add_allocation(&mut file, &allocation);
                            mapping_measurements.entry(sample.state.identity.pid.0).or_default().push(mapping.clone());
                        }
                        Ok(None) => file.unlinked = Some(false),
                        Err(reason) => snapshot.note(Some(sample.state.identity.pid.0), reason),
                    }
                } else {
                    snapshot.note(
                        Some(sample.state.identity.pid.0),
                        "disk_mapping_allocation_budget",
                    );
                }
                files.insert(mapping.key.clone(), file);
            }
        }
        let mut valid_processes = BTreeSet::new();
        for (&pid, sample) in &samples {
            match sample_process(root, pid, &context, deadline, &mut total_fds) {
                Ok(after)
                    if after.state == sample.state
                        && after.tasks == sample.tasks
                        && after.descriptors == sample.descriptors
                        && after.mappings == sample.mappings =>
                {
                    if after.allocations.keys().ne(sample.allocations.keys()) {
                        snapshot.diagnostic(Some(pid), "disk_deleted_file_set_changed");
                    } else {
                        valid_processes.insert(pid);
                    }
                    for allocation in after.allocations.values() {
                        if let Some(file) = files.get_mut(&allocation.key) {
                            add_allocation(file, allocation);
                        }
                    }
                }
                Ok(_) => {
                    snapshot.diagnostic(Some(pid), "disk_process_files_changed_during_observation")
                }
                Err(reason) => snapshot.diagnostic(Some(pid), reason),
            }
        }
        revalidate_mapping_allocations(root, &context, deadline, (&samples, &valid_processes),
            &mapping_measurements, &mut files, &mut snapshot);
        if census(root).ok().as_ref() != Some(&pids) {
            snapshot.diagnostic(None, "disk_process_census_changed");
        }
        if !Context::load().ok().is_some_and(|after| {
            after.boot == context.boot
                && after.namespace_device == context.namespace_device
                && after.namespace_inode == context.namespace_inode
                && after.mount_table_sha256 == context.mount_table_sha256
        }) {
            snapshot.diagnostic(None, "disk_mount_namespace_changed");
        }
        attach_holders(&mut snapshot, &samples, &mut files, &valid_processes, &incomplete_catalogs);
        for file in files.values_mut() {
            file.holders.sort_by_key(|holder| holder.pid.0);
            file.holders_complete = snapshot.complete;
        }
        snapshot.files = files.into_values().collect();
        summarize_mount_ownership(&mut snapshot);
        snapshot
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn identity(pid: u32) -> ProcessIdentity {
            ProcessIdentity::full(pid, StartId::from_linux("disk-test-boot", 10, pid), 1000, Some(500), Some(400), IdentityQuality::Full)
        }

        fn mount() -> DiskMountObservation {
            DiskMountObservation {
                identity: DiskMountIdentity {
                    boot_id: "disk-test-boot".into(), mount_namespace_device: 4,
                    mount_namespace_inode: 5, mount_id: 6, device_major: 8, device_minor: 1,
                    filesystem_type: "ext4".into(), mount_root_sha256: digest([b"/"]),
                    mount_source_sha256: digest([b"device"]), mount_options_sha256: digest([b"rw"]),
                },
                mount_point: "/private/test-volume".into(), total_bytes: Some(100_000),
                free_bytes: Some(5000), available_bytes: Some(4000), ..Default::default()
            }
        }

        fn owned_snapshot() -> DiskResourceSnapshot {
            let mount = mount();
            DiskResourceSnapshot {
                complete: true,
                files: vec![DeletedFileObservation {
                    id: "file-one".into(), device_major: 8, device_minor: 1, inode: 17,
                    allocated_bytes: Some(4096), logical_bytes: Some(1 << 30),
                    unlinked: Some(true), holders: vec![identity(101)], mount_keys: vec![mount.identity.key()],
                    allocation_stable: true, holders_complete: true, ..Default::default()
                }],
                processes: vec![DiskProcessObservation { identity: identity(101), fd_count: 2, complete: true, file_ids: vec!["file-one".into()] }],
                mounts: vec![mount], ..Default::default()
            }
        }

        #[test]
        fn exclusive_credit_uses_allocated_blocks_and_counts_bind_alias_once() {
            let mut snapshot = owned_snapshot();
            let mut alias = snapshot.mounts[0].clone();
            alias.identity.mount_id += 1;
            alias.mount_point = "/alias".into();
            let alias_key = alias.identity.key();
            snapshot.files[0].mount_keys.push(alias_key.clone());
            snapshot.mounts.push(alias);
            assert_eq!(snapshot.exclusive_allocated_bytes(&identity(101), None), Ok(4096));
            assert_eq!(snapshot.exclusive_allocated_bytes(&identity(101), Some(&alias_key)), Ok(4096));
            assert!(snapshot.exclusive_allocated_bytes(&identity(101), Some("not-observed")).is_err());
            snapshot.processes[0].file_ids.push("file-one".into());
            assert!(snapshot.exclusive_allocated_bytes(&identity(101), None).is_err());
        }

        #[test]
        fn any_second_holder_makes_exclusive_credit_zero_even_without_global_coverage() {
            let mut snapshot = owned_snapshot();
            snapshot.files[0].holders.push(identity(102));
            snapshot.mark_census_incomplete();
            assert_eq!(snapshot.exclusive_allocated_bytes(&identity(101), None), Ok(0));
            snapshot.processes[0].complete = false;
            assert!(snapshot.exclusive_allocated_bytes(&identity(101), None).is_err());
        }

        #[test]
        fn partial_allocation_ownership_and_stale_processes_never_get_positive_credit() {
            for mode in 0..6 {
                let mut snapshot = owned_snapshot();
                match mode {
                    0 => snapshot.mark_census_incomplete(),
                    1 => snapshot.files[0].allocated_bytes = None,
                    2 => snapshot.files[0].unlinked = None,
                    3 => snapshot.files[0].allocation_stable = false,
                    4 => snapshot.files[0].holders_complete = false,
                    _ => snapshot.processes[0].complete = false,
                }
                assert!(snapshot.exclusive_allocated_bytes(&identity(101), None).is_err(), "mode {mode}");
            }
            let snapshot = owned_snapshot();
            for mode in 0..5 {
                let mut changed = identity(101);
                match mode {
                    0 => changed.pid.0 += 1,
                    1 => changed.uid += 1,
                    2 => changed.start_id = StartId::from_linux("disk-test-boot", 11, 101),
                    3 => changed.pgid = Some(999),
                    _ => changed.sid = Some(999),
                }
                assert!(snapshot.exclusive_allocated_bytes(&changed, None).is_err());
            }
        }

        #[test]
        fn capacities_are_independent_of_ownership_and_validate_binding() {
            let mut snapshot = owned_snapshot();
            snapshot.mark_census_incomplete();
            assert!(snapshot.mounts[0].validate_capacity().is_ok());
            assert_eq!(snapshot.mounts[0].available_bytes, Some(4000));
            let mut invalid = mount();
            invalid.available_bytes = Some(6000);
            assert!(invalid.validate_capacity().is_err());
            invalid = mount(); invalid.total_bytes = None;
            assert!(invalid.validate_capacity().is_err());
            invalid = mount(); invalid.identity.mount_namespace_inode = 0;
            assert!(invalid.validate_capacity().is_err());
            invalid = mount(); invalid.identity.mount_options_sha256 = "invalid".into();
            assert!(invalid.validate_capacity().is_err());
            let mut changed = mount().identity;
            let key = changed.key();
            changed.mount_options_sha256 = digest([b"ro"]);
            assert_ne!(changed.key(), key);
        }

        #[test]
        fn mapping_parser_keeps_file_holders_without_requiring_descriptor_or_path_match() {
            let parsed = mappings(b"1000-2000 rw-s 00000000 08:01 17 /private/path with spaces (deleted)\n2000-3000 r--p 00001000 08:01 17 /different-open-name\n3000-4000 rw-p 00000000 00:00 0 [heap]\n").unwrap();
            assert_eq!(parsed.len(), 2);
            assert!(parsed.iter().all(|mapping| mapping.key == FileKey { major: 8, minor: 1, inode: 17 }));
            assert_eq!(parsed.iter().filter(|mapping| mapping.deleted_name).count(), 1);
            assert!(mappings(b"1000-2000 rw-s 0 08:01 17 /x (deleted)").is_err());
            assert!(mappings(b"2000-1000 rw-s 0 08:01 17 /x\n").is_err());
            assert!(mappings(b"1000-2000 xxxx 0 08:01 17 /x\n").is_err());
            assert!(mappings(b"1000-2000 rw-s 0 invalid 17 /x\n").is_err());
            assert!(mappings(b"").unwrap().is_empty());
        }

        #[test]
        fn descriptor_parser_requires_unambiguous_mount_inode_and_flags() {
            assert_eq!(descriptor_info(b"pos: 0\nflags: 0100002\nmnt_id: 6\nino: 17\n"), Ok((6, 17, 0o100002)));
            for bad in [b"flags: 2\nino: 17\n".as_slice(), b"flags: 2\nmnt_id: 6\nino: 17\nino: 18\n", b"flags: 9\nmnt_id: 6\nino: 17\n", b"flags: 2\nmnt_id: 6\nino: 17"] {
                assert!(descriptor_info(bad).is_err());
            }
        }

        fn persistent_directory() -> PathBuf {
            let mut candidates = vec![std::env::current_dir().unwrap(), PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
            if Path::new(file!()).is_absolute() {
                if let Some(parent) = Path::new(file!()).parent() { candidates.push(parent.to_path_buf()); }
            }
            candidates.into_iter().find(|directory| resolve_mount(directory.to_str()).is_ok())
                .expect("a local persistent filesystem is required for disk collection tests")
        }

        #[test]
        fn observed_mount_rejects_changed_binding_and_symlink_scope() {
            let directory = persistent_directory();
            let observed = resolve_mount(directory.to_str()).unwrap();
            observed.validate_capacity().unwrap();
            let repeated = observe_mount(&observed.identity).unwrap();
            assert_eq!(repeated.identity, observed.identity);
            assert_eq!(repeated.total_bytes, observed.total_bytes);
            let mut stale = observed.identity;
            stale.boot_id.push_str("-stale");
            assert!(observe_mount(&stale).is_err());
            let temporary = tempfile::tempdir().unwrap().keep();
            let link = temporary.join("scope-alias");
            std::os::unix::fs::symlink(&directory, &link).unwrap();
            assert!(resolve_mount(Some(link.to_str().unwrap())).is_err());
        }

        #[test]
        fn disk_serialization_exposes_hashes_and_explicit_unknowns() {
            let mut snapshot = owned_snapshot();
            snapshot.files[0].path_sha256 = Some(digest([b"secret-file-name"]));
            snapshot.files[0].allocated_bytes = None;
            let encoded = serde_json::to_string(&snapshot).unwrap();
            assert!(!encoded.contains("secret-file-name"));
            let restored: DiskResourceSnapshot = serde_json::from_str(&encoded).unwrap();
            assert_eq!(restored.files[0].allocated_bytes, None);
            assert!(restored.exclusive_allocated_bytes(&identity(101), None).is_err());
        }

        fn allocated_unnamed_file() -> File {
            use std::io::Write;
            let context = Context::load().unwrap();
            let directory = persistent_directory();
            let handle = context.resolve(directory.to_str(), Instant::now() + BUDGET).unwrap();
            // O_TMPFILE has link count zero from creation; no directory entry is
            // deleted. One MiB is allocated and the rest is deliberately sparse.
            let mut file = OpenOptions::new().read(true).write(true)
                .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
                .open(procfs::directory_path(&handle, "")).unwrap();
            let block = vec![0x5a; 65_536];
            for _ in 0..16 { file.write_all(&block).unwrap(); }
            file.set_len(64 * 1024 * 1024).unwrap();
            file.sync_data().unwrap();
            assert_eq!(file.metadata().unwrap().nlink(), 0);
            file
        }

        struct LiveChild {
            child: std::process::Child,
            reader: Option<std::thread::JoinHandle<()>>,
        }

        impl LiveChild {
            fn spawn(file: &File, mapping_only: bool) -> Self {
                use std::io::BufRead;
                use std::os::unix::process::CommandExt;
                use std::process::{Command, Stdio};
                const SCRIPT: &str = r#"import ctypes, os, sys
fd = int(sys.argv[1])
if fd != 7:
    os.dup2(fd, 7)
    os.close(fd)
fd = 7
if sys.argv[2] == 'mapping':
    library = ctypes.CDLL(None, use_errno=True)
    library.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    library.mmap.restype = ctypes.c_void_p
    address = library.mmap(None, os.fstat(fd).st_size, 1, 1, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), 'owned fixture mmap failed')
    os.close(fd)
print('PT_DISK_READY', flush=True)
sys.stdin.readline()
"#;
                let fd = file.as_raw_fd();
                let mut command = Command::new("python3");
                command.args(["-c", SCRIPT, &fd.to_string(), if mapping_only { "mapping" } else { "descriptor" }])
                    .env_clear().env("PATH", "/usr/bin:/bin")
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
                // SAFETY: only fcntl on the explicitly owned fixture descriptor
                // runs after fork; it neither allocates nor touches other tasks.
                unsafe {
                    command.pre_exec(move || {
                        let flags = libc::fcntl(fd, libc::F_GETFD);
                        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let mut fixture = Self { child: command.spawn().expect("spawn owned disk fixture"), reader: None };
                let output = fixture.child.stdout.take().unwrap();
                let (sender, receiver) = std::sync::mpsc::channel();
                fixture.reader = Some(std::thread::spawn(move || {
                    let mut line = String::new();
                    let result = std::io::BufReader::new(output).read_line(&mut line).map(|_| line);
                    let _ = sender.send(result);
                }));
                let ready = receiver.recv_timeout(Duration::from_secs(5)).expect("bounded disk fixture readiness").unwrap();
                assert_eq!(ready.trim(), "PT_DISK_READY");
                fixture
            }
        }

        impl Drop for LiveChild {
            fn drop(&mut self) {
                // Only our still-owned child is stopped and reaped.
                match self.child.try_wait() {
                    Ok(Some(_)) => {}
                    _ => { let _ = self.child.kill(); let _ = self.child.wait(); }
                }
                if let Some(reader) = self.reader.take() { let _ = reader.join(); }
            }
        }

        #[test]
        fn live_allocated_blocks_and_map_only_coholder_are_attributed_without_double_counting() {
            let context = Context::load().unwrap();
            let file = allocated_unnamed_file();
            let metadata = file.metadata().unwrap();
            let expected = metadata.blocks() * 512;
            assert!(expected >= 1024 * 1024 && expected < metadata.len());
            let key = FileKey::from_metadata(&metadata);
            let descriptor = LiveChild::spawn(&file, false);
            let mapping = LiveChild::spawn(&file, true);
            drop(file);
            let mut total_fds = 0;
            let first = sample_process(Path::new("/proc"), descriptor.child.id(), &context, Instant::now() + BUDGET, &mut total_fds).unwrap();
            let second = sample_process(Path::new("/proc"), mapping.child.id(), &context, Instant::now() + BUDGET, &mut total_fds).unwrap();
            assert_eq!(first.allocations.get(&key).unwrap().bytes, expected);
            assert!(!second.allocations.contains_key(&key), "mapping fixture must close every descriptor for the inode");
            assert!(second.mappings.iter().any(|entry| entry.key == key));
            let first_identity = first.state.identity.clone();
            let samples = BTreeMap::from([(first_identity.pid.0, first), (second.state.identity.pid.0, second)]);
            let mut files = BTreeMap::new();
            let mut observed = new_file(&context, &key);
            add_allocation(&mut observed, samples[&first_identity.pid.0].allocations.get(&key).unwrap());
            files.insert(key, observed);
            let mut snapshot = DiskResourceSnapshot { complete: false, ..Default::default() };
            let valid = samples.keys().copied().collect();
            attach_holders(&mut snapshot, &samples, &mut files, &valid, &BTreeSet::new());
            snapshot.files = files.into_values().collect();
            assert_eq!(snapshot.files.len(), 1);
            assert_eq!(snapshot.files[0].holders.len(), 2);
            assert_eq!(snapshot.files[0].allocated_bytes, Some(expected));
            assert_eq!(snapshot.exclusive_allocated_bytes(&first_identity, None), Ok(0));
        }

        #[test]
        fn live_mapping_only_file_has_known_inode_and_unknown_allocation_if_access_is_denied() {
            let context = Context::load().unwrap();
            let file = allocated_unnamed_file();
            let metadata = file.metadata().unwrap();
            let expected = metadata.blocks() * 512;
            let key = FileKey::from_metadata(&metadata);
            let child = LiveChild::spawn(&file, true);
            drop(file);
            let sample = sample_process(Path::new("/proc"), child.child.id(), &context, Instant::now() + BUDGET, &mut 0).unwrap();
            assert!(!sample.allocations.contains_key(&key));
            let mapping = sample.mappings.iter().find(|mapping| mapping.key == key).unwrap();
            match mapping_allocation(Path::new("/proc"), &sample, mapping, &context) {
                Ok(Some(allocation)) => assert_eq!(allocation.bytes, expected),
                Err(reason) => assert_eq!(reason, "disk_mapping_allocation_unavailable"),
                Ok(None) => panic!("owned unlinked regular file must not become an observed zero"),
            }
        }

        fn fixture_process(directory: &Path, pid: u32, threads: usize, descriptor_source: Option<u32>) {
            fs::create_dir_all(directory).unwrap();
            let mut fields = vec!["0".to_string(); 22];
            fields[0] = "S".into(); fields[1] = "1".into(); fields[2] = "500".into(); fields[3] = "400".into();
            fields[17] = threads.to_string(); fields[19] = "10".into();
            fs::write(directory.join("stat"), format!("{pid} (fixture) {}\n", fields.join(" "))).unwrap();
            fs::write(directory.join("status"), "Uid: 1000 1000 1000 1000\n").unwrap();
            fs::write(directory.join("maps"), "").unwrap();
            if let Some(source) = descriptor_source {
                std::os::unix::fs::symlink(format!("/proc/{source}/fd"), directory.join("fd")).unwrap();
                std::os::unix::fs::symlink(format!("/proc/{source}/fdinfo"), directory.join("fdinfo")).unwrap();
            } else {
                fs::create_dir(directory.join("fd")).unwrap();
                fs::create_dir(directory.join("fdinfo")).unwrap();
            }
        }

        #[test]
        fn procfs_super_options_control_visibility_and_mount_binding() {
            let mut context = Context::load().unwrap();
            context.mounts = procfs::parse_mountinfo(b"10 1 0:1 / /proc rw - proc proc rw,hidepid=2\n").unwrap();
            assert!(!unrestricted_procfs(&context));
            let hidden = context.identity(&context.mounts[&10]).key();
            context.mounts.get_mut(&10).unwrap().super_options = "rw,hidepid=0".into();
            assert!(unrestricted_procfs(&context));
            assert_ne!(context.identity(&context.mounts[&10]).key(), hidden);
            context.mounts.get_mut(&10).unwrap().super_options = "rw,subset=pid".into();
            assert!(!unrestricted_procfs(&context));
        }

        #[test]
        fn private_task_descriptor_tables_keep_same_fd_numbers_distinct_and_attribute_to_tgid() {
            let context = Context::load().unwrap();
            let first = allocated_unnamed_file();
            let second = allocated_unnamed_file();
            let first_key = FileKey::from_metadata(&first.metadata().unwrap());
            let second_key = FileKey::from_metadata(&second.metadata().unwrap());
            let first_child = LiveChild::spawn(&first, false);
            let second_child = LiveChild::spawn(&second, false);
            drop(first); drop(second);
            let root = tempfile::tempdir().unwrap().keep();
            fixture_process(&root.join("4001"), 4001, 3, None);
            fixture_process(&root.join("4001/task/4001"), 4001, 3, None);
            fixture_process(&root.join("4001/task/4002"), 4002, 3, Some(first_child.child.id()));
            fixture_process(&root.join("4001/task/4003"), 4003, 3, Some(second_child.child.id()));
            let sample = sample_process(&root, 4001, &context, Instant::now() + BUDGET, &mut 0).unwrap();
            assert_eq!(sample.tasks.len(), 3);
            assert_eq!(sample.fd_count, 0, "leader's empty FD table must not hide private task tables");
            assert_eq!(sample.allocations.len(), 2);
            assert!(sample.allocations.contains_key(&first_key));
            assert!(sample.allocations.contains_key(&second_key));
            assert!(sample.descriptors.iter().any(|entry| entry.task_id == 4002 && entry.fd == 7 && entry.inode == first_key.inode));
            assert!(sample.descriptors.iter().any(|entry| entry.task_id == 4003 && entry.fd == 7 && entry.inode == second_key.inode));
            let mut files = BTreeMap::new();
            for allocation in sample.allocations.values() {
                let mut file = new_file(&context, &allocation.key);
                add_allocation(&mut file, allocation);
                files.insert(allocation.key.clone(), file);
            }
            let samples = BTreeMap::from([(4001, sample)]);
            let mut snapshot = DiskResourceSnapshot::default();
            attach_holders(&mut snapshot, &samples, &mut files, &BTreeSet::from([4001]), &BTreeSet::new());
            assert!(files.values().all(|file| file.holders.len() == 1 && file.holders[0].pid.0 == 4001));
            fixture_process(&root.join("4001/task/4004"), 4004, 4, None);
            assert_eq!(sample_process(&root, 4001, &context, Instant::now() + BUDGET, &mut 0).err(), Some("disk_task_census_changed"));
        }

        #[test]
        fn mapping_only_allocation_is_remeasured_even_when_mapping_table_is_unchanged() {
            use std::io::{Seek, SeekFrom, Write};
            let context = Context::load().unwrap();
            let mut file = allocated_unnamed_file();
            let key = FileKey::from_metadata(&file.metadata().unwrap());
            let initial_bytes = file.metadata().unwrap().blocks() * 512;
            let root = tempfile::tempdir().unwrap().keep();
            let process = root.join("5001");
            fixture_process(&process, 5001, 1, None);
            let table = format!("1000-2000 r--s 00000000 {:02x}:{:02x} {} /private/#{} (deleted)\n",
                key.major, key.minor, key.inode, key.inode);
            fs::write(process.join("maps"), &table).unwrap();
            fs::create_dir(process.join("map_files")).unwrap();
            std::os::unix::fs::symlink(format!("/proc/self/fd/{}", file.as_raw_fd()),
                process.join("map_files/1000-2000")).unwrap();
            let sample = sample_process(&root, 5001, &context, Instant::now() + BUDGET, &mut 0).unwrap();
            let mapping = sample.mappings.iter().next().unwrap().clone();
            let allocation = mapping_allocation(&root, &sample, &mapping, &context).unwrap().unwrap();
            assert_eq!(allocation.bytes, initial_bytes);
            let mut observed = new_file(&context, &key);
            add_allocation(&mut observed, &allocation);
            let mut files = BTreeMap::from([(key.clone(), observed)]);
            let samples = BTreeMap::from([(5001, sample)]);
            let measurements = BTreeMap::from([(5001, vec![mapping])]);
            file.seek(SeekFrom::Start(4 * 1024 * 1024)).unwrap();
            let block = vec![0x3c; 65_536];
            for _ in 0..16 { file.write_all(&block).unwrap(); }
            file.sync_data().unwrap();
            assert!(file.metadata().unwrap().blocks() * 512 > initial_bytes);
            assert_eq!(fs::read_to_string(process.join("maps")).unwrap(), table);
            let mut snapshot = DiskResourceSnapshot { complete: true, ..Default::default() };
            let valid = BTreeSet::from([5001]);
            revalidate_mapping_allocations(&root, &context, Instant::now() + BUDGET,
                (&samples, &valid), &measurements, &mut files, &mut snapshot);
            assert!(!files[&key].allocation_stable);
            assert_eq!(files[&key].allocated_bytes, Some(initial_bytes));
        }
    }
}
