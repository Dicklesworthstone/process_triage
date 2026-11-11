//! Identity-bound diagnostics for duplicate and competing build/test work.
//!
//! Equal command strings are insufficient: argument boundaries, executable,
//! working directory, workspace, namespaces and selected build environment must
//! agree. These observations are review advice, never abandonment likelihoods
//! or permission to stop a process. Unknown lock ownership preserves all peers.

use super::ProcessRecord;
use pt_common::{IdentityQuality, ProcessIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_DIAGNOSTICS: usize = 32;

/// A preference among observed independent peers, not an execution instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateRole {
    PreferredNewest,
    ProtectedLockHolder,
    RedundantOlder,
    RedundantWaiter,
    Undetermined,
}

impl DuplicateRole {
    fn reason(self) -> &'static str {
        match self {
            Self::PreferredNewest => "Preserve the newest observed independent copy; review the older copies without assuming they are safe to stop",
            Self::ProtectedLockHolder => "Preserve this copy: an observed file lock may protect work that the other copies are waiting for",
            Self::RedundantOlder => "Possible redundant older copy of an independent build/test invocation; inspect its inputs and progress before acting",
            Self::RedundantWaiter => "This copy waits on a file lock held by another observed copy; preserve the holder and review the waiter",
            Self::Undetermined => "Preserve all observed copies: incomplete or ambiguous workload/lock evidence cannot identify the copy to retain",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateWorkMember {
    pub identity: ProcessIdentity,
    pub parent_pid: u32,
    pub comm: String,
    pub record_command_sha256: String,
    pub role: DuplicateRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateWorkGroup {
    pub id: String,
    pub command_sha256: String,
    pub workspace_sha256: String,
    pub cwd_sha256: String,
    pub configuration_sha256: String,
    pub members: Vec<DuplicateWorkMember>,
    pub lock_evidence_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingBuildMember {
    pub identity: ProcessIdentity,
    pub parent_pid: u32,
    pub comm: String,
    pub record_command_sha256: String,
    /// Identity of an explicitly selected, observed target directory. Neither
    /// its path nor the environment value is exposed.
    pub target_directory_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingBuildGroup {
    pub id: String,
    pub workspace_sha256: String,
    pub members: Vec<CompetingBuildMember>,
    pub target_directory_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadDiagnostic {
    pub pid: Option<u32>,
    /// Fixed diagnostic code; never an OS error containing paths or values.
    pub reason: String,
}

/// A replayable diagnosis attached to one exact census row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessWorkDiagnosis {
    pub identity: ProcessIdentity,
    pub parent_pid: u32,
    pub record_command_sha256: String,
    pub duplicate_group_id: Option<String>,
    pub duplicate_role: Option<DuplicateRole>,
    pub competing_group_ids: Vec<String>,
    pub review_reason: Option<String>,
}

impl ProcessWorkDiagnosis {
    pub fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.identity.can_safely_revalidate()
            && self.identity.pid == process.pid
            && self.identity.start_id == process.start_id
            && self.identity.uid == process.uid
            && self.identity.pgid == process.pgid
            && self.identity.sid == process.sid
            && self.parent_pid == process.ppid.0
            && self.record_command_sha256 == record_command_digest(process)
    }

    /// A preservation veto only. False never means a copy is safe to stop.
    pub fn preserves_work(&self) -> bool {
        matches!(
            self.duplicate_role,
            Some(
                DuplicateRole::PreferredNewest
                    | DuplicateRole::ProtectedLockHolder
                    | DuplicateRole::Undetermined
            )
        )
    }
}

/// Observed groups, with explicit collection coverage. No missing process is
/// interpreted as unique, idle or redundant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DuplicateWorkSnapshot {
    pub observed_at: String,
    pub input_processes: usize,
    pub eligible_processes: usize,
    #[serde(default)]
    pub attempted_processes: usize,
    pub observed_processes: usize,
    pub complete: bool,
    pub duplicates: Vec<DuplicateWorkGroup>,
    pub competing_builds: Vec<CompetingBuildGroup>,
    pub diagnostics: Vec<WorkloadDiagnostic>,
    pub omitted_diagnostics: usize,
    pub limitations: Vec<String>,
}

impl DuplicateWorkSnapshot {
    /// Retain positive observations from a partial census without inferring
    /// which copy is newest or whether any unobserved peer holds a lock.
    pub fn mark_census_incomplete(&mut self) {
        self.diagnostic(None, "process_census_incomplete");
        for group in &mut self.duplicates {
            group.lock_evidence_complete = false;
            for member in &mut group.members {
                if member.role != DuplicateRole::ProtectedLockHolder {
                    member.role = DuplicateRole::Undetermined;
                }
            }
        }
    }

    pub fn diagnosis_for(&self, process: &ProcessRecord) -> Option<ProcessWorkDiagnosis> {
        let mut diagnosis = ProcessWorkDiagnosis {
            identity: identity_from_record(process),
            parent_pid: process.ppid.0,
            record_command_sha256: record_command_digest(process),
            duplicate_group_id: None,
            duplicate_role: None,
            competing_group_ids: Vec::new(),
            review_reason: None,
        };
        for group in &self.duplicates {
            for member in &group.members {
                if member.identity == diagnosis.identity
                    && member.parent_pid == diagnosis.parent_pid
                    && member.record_command_sha256 == diagnosis.record_command_sha256
                {
                    // Duplicate membership is exclusive in collector output.
                    // A malformed persisted snapshot must not choose one role.
                    if diagnosis.duplicate_group_id.is_some() {
                        return None;
                    }
                    diagnosis.duplicate_group_id = Some(group.id.clone());
                    diagnosis.duplicate_role = Some(member.role);
                    diagnosis.review_reason = Some(member.role.reason().to_string());
                }
            }
        }
        for group in &self.competing_builds {
            if group.members.iter().any(|member| {
                member.identity == diagnosis.identity
                    && member.parent_pid == diagnosis.parent_pid
                    && member.record_command_sha256 == diagnosis.record_command_sha256
            }) {
                diagnosis.competing_group_ids.push(group.id.clone());
            }
        }
        if diagnosis.duplicate_role.is_none() && diagnosis.competing_group_ids.is_empty() {
            return None;
        }
        if diagnosis.review_reason.is_none() {
            diagnosis.review_reason = Some("Concurrent builds in this workspace use different observed target directories; under CPU or I/O pressure consider serializing them. This is not abandonment evidence".to_string());
        }
        diagnosis.matches_record(process).then_some(diagnosis)
    }

    fn diagnostic(&mut self, pid: Option<u32>, reason: &'static str) {
        self.complete = false;
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(WorkloadDiagnostic {
                pid,
                reason: reason.to_string(),
            });
        } else {
            self.omitted_diagnostics = self.omitted_diagnostics.saturating_add(1);
        }
    }
}

fn digest(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hex::encode(hash.finalize())
}

/// Match a recorded observation to the same command presented by the census.
/// Grouping separately uses exact NUL-delimited argv, never this display string.
pub fn record_command_digest(process: &ProcessRecord) -> String {
    digest([process.comm.as_bytes(), process.cmd.as_bytes()])
}

fn identity_from_record(process: &ProcessRecord) -> ProcessIdentity {
    ProcessIdentity::full(
        process.pid.0,
        process.start_id.clone(),
        process.uid,
        process.pgid,
        process.sid,
        if process.start_id.0.starts_with("unknown:")
            || process.start_id.0.starts_with("synthetic:")
        {
            IdentityQuality::NoBootId
        } else {
            IdentityQuality::Full
        },
    )
}

#[cfg(target_os = "linux")]
pub use linux::collect_duplicate_work;

/// Other platforms retain the same output schema without invented observations.
#[cfg(not(target_os = "linux"))]
pub fn collect_duplicate_work(processes: &[ProcessRecord]) -> DuplicateWorkSnapshot {
    DuplicateWorkSnapshot {
        observed_at: chrono::Utc::now().to_rfc3339(),
        input_processes: processes.len(),
        complete: false,
        diagnostics: vec![WorkloadDiagnostic {
            pid: None,
            reason: "duplicate_work_collection_unsupported_on_this_platform".to_string(),
        }],
        limitations: vec![
            "Identity-bound workload and file-lock collection currently requires Linux procfs"
                .to_string(),
        ],
        ..Default::default()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::collect::proc_parsers::parse_proc_stat_content;
    use crate::collect::ProcessState;
    use pt_common::StartId;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const MAX_PROCESSES: usize = 256;
    const MAX_FDS: usize = 1024;
    const MAX_FIELD_BYTES: usize = 65_536;
    const MAX_ENV_BYTES: usize = 262_144;
    const MAX_LOCK_BYTES: usize = 2_097_152;
    const MAX_WORKSPACE_DEPTH: usize = 24;
    const COLLECTION_BUDGET: Duration = Duration::from_millis(750);
    const ENV_KEYS: [&[u8]; 4] = [
        b"CARGO_TARGET_DIR",
        b"CARGO_BUILD_TARGET_DIR",
        b"RUSTFLAGS",
        b"CARGO_ENCODED_RUSTFLAGS",
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WorkKind {
        Build,
        Test,
    }

    fn basename(value: &[u8]) -> &[u8] {
        value.rsplit(|byte| *byte == b'/').next().unwrap_or(value)
    }

    /// Recognize only executable/argument positions, never shell program text.
    fn workload_kind(argv: &[&[u8]]) -> Option<WorkKind> {
        let mut name = basename(argv.first()?);
        let mut args = &argv[1..];
        // Script launchers are common for pytest, npm and package-manager wrappers.
        // A `sh -c 'cargo ...'` remains a shell, not a second build invocation.
        if matches!(
            name,
            b"sh" | b"bash" | b"dash" | b"python" | b"python3" | b"node"
        ) {
            if matches!(name, b"python" | b"python3") && args.first() == Some(&b"-m".as_slice()) {
                return (args.get(1) == Some(&b"pytest".as_slice())).then_some(WorkKind::Test);
            }
            let script = args.first()?;
            if script.starts_with(b"-") {
                return None;
            }
            name = basename(script);
            args = &args[1..];
        }
        match name {
            b"rustc" | b"rustdoc" | b"cc" | b"c++" | b"gcc" | b"g++" | b"clang" | b"clang++"
            | b"cc1" | b"cc1plus" | b"make" | b"gmake" | b"ninja" => Some(WorkKind::Build),
            b"pytest" | b"py.test" | b"jest" | b"jest.js" | b"vitest" | b"vitest.mjs"
            | b"vitest.js" | b"mocha" | b"ctest" => Some(WorkKind::Test),
            b"cmake" => args
                .contains(&b"--build".as_slice())
                .then_some(WorkKind::Build),
            b"cargo" => {
                if args.first().is_some_and(|arg| arg.starts_with(b"+")) {
                    args = &args[1..];
                }
                match args.first().copied()? {
                    b"build" | b"check" | b"clippy" | b"rustc" => Some(WorkKind::Build),
                    b"test" | b"bench" | b"nextest" => Some(WorkKind::Test),
                    _ => None,
                }
            }
            b"go" => match args.first().copied()? {
                b"build" => Some(WorkKind::Build),
                b"test" => Some(WorkKind::Test),
                _ => None,
            },
            b"bun" | b"npm" | b"pnpm" | b"yarn" => {
                if args.first() == Some(&b"run".as_slice()) {
                    args = &args[1..];
                }
                match args.first().copied()? {
                    b"build" | b"check" => Some(WorkKind::Build),
                    b"test" | b"test:unit" | b"test:integration" => Some(WorkKind::Test),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn candidate_hint(process: &ProcessRecord) -> bool {
        if matches!(
            process.state,
            ProcessState::Zombie | ProcessState::Dead | ProcessState::Unknown
        ) {
            return false;
        }
        command_hint(process)
    }

    fn command_hint(process: &ProcessRecord) -> bool {
        let args: Vec<_> = process.cmd.split_whitespace().map(str::as_bytes).collect();
        workload_kind(&args).is_some()
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct ObjectId {
        device: u64,
        inode: u64,
    }

    impl ObjectId {
        fn of(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }

        fn digest(&self) -> String {
            digest([self.device.to_le_bytes(), self.inode.to_le_bytes()])
        }
    }

    struct PinnedProc {
        directory: File,
    }

    impl PinnedProc {
        fn open(proc_root: &Path, pid: u32) -> Result<Self, &'static str> {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(proc_root.join(pid.to_string()))
                .map(|directory| Self { directory })
                .map_err(|_| "process_directory_unavailable")
        }

        fn path(&self, field: &str) -> PathBuf {
            PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                self.directory.as_raw_fd(),
                field
            ))
        }

        fn read(&self, field: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
            read_bounded(&self.path(field), limit)
        }

        fn identity(&self, process: &ProcessRecord, boot: &str) -> Result<u64, &'static str> {
            let stat = self.read("stat", MAX_FIELD_BYTES)?;
            let stat = std::str::from_utf8(&stat).map_err(|_| "process_stat_invalid")?;
            // The general parser intentionally tolerates missing counters. An
            // identity check must reject truncated/invalid required fields.
            let fields: Vec<_> = stat
                .rsplit_once(')')
                .ok_or("process_stat_invalid")?
                .1
                .split_whitespace()
                .collect();
            if fields.len() < 22
                || fields[0].len() != 1
                || fields[1].parse::<u32>().is_err()
                || fields[2].parse::<i32>().is_err()
                || fields[3].parse::<i32>().is_err()
                || fields[19].parse::<u64>().is_err()
            {
                return Err("process_stat_invalid");
            }
            let stat = parse_proc_stat_content(stat).ok_or("process_stat_invalid")?;
            let status = self.read("status", MAX_FIELD_BYTES)?;
            let status = std::str::from_utf8(&status).map_err(|_| "process_status_invalid")?;
            let mut uid_lines = status.lines().filter(|line| line.starts_with("Uid:"));
            let uid_fields: Vec<_> = uid_lines
                .next()
                .ok_or("process_uid_missing")?
                .split_whitespace()
                .collect();
            if uid_lines.next().is_some() {
                return Err("process_uid_ambiguous");
            }
            if uid_fields.len() != 5
                || uid_fields[1..]
                    .iter()
                    .any(|field| field.parse::<u32>().is_err())
            {
                return Err("process_uid_invalid");
            }
            let uid = uid_fields[2]
                .parse::<u32>()
                .map_err(|_| "process_uid_invalid")?;
            if stat.pid != process.pid.0
                || stat.ppid != process.ppid.0
                || stat.comm != process.comm
                || uid != process.uid
                || process
                    .pgid
                    .is_some_and(|pgid| i64::from(stat.pgrp) != i64::from(pgid))
                || process
                    .sid
                    .is_some_and(|sid| i64::from(stat.session) != i64::from(sid))
                || StartId::from_linux(boot, stat.starttime, stat.pid) != process.start_id
                || !matches!(
                    stat.state,
                    'R' | 'S' | 'D' | 'T' | 't' | 'I' | 'P' | 'W' | 'K'
                )
            {
                return Err("process_identity_changed_or_unusable");
            }
            Ok(stat.starttime)
        }

        fn namespace(&self, name: &str) -> Result<ObjectId, &'static str> {
            fs::metadata(self.path(name))
                .map(|meta| ObjectId::of(&meta))
                .map_err(|_| "namespace_identity_unavailable")
        }
    }

    fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "process_field_unavailable")?;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "process_field_unavailable")?;
        if bytes.len() > limit {
            return Err("process_field_size_limit");
        }
        Ok(bytes)
    }

    fn open_directory(path: &Path) -> Result<File, &'static str> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "directory_identity_unavailable")
    }

    fn directory_path(file: &File, suffix: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{}", file.as_raw_fd(), suffix))
    }

    fn directory_id(directory: &File) -> Result<ObjectId, &'static str> {
        directory
            .metadata()
            .map(|meta| ObjectId::of(&meta))
            .map_err(|_| "directory_identity_unavailable")
    }

    /// Classify held paths through kernel procfs tables. Even fstatfs can invoke
    /// a stalled FUSE/network server, so it must not be used as the safety probe.
    struct FilesystemGuard {
        mounts: BTreeMap<u64, bool>,
    }

    impl FilesystemGuard {
        fn load() -> Result<Self, &'static str> {
            let bytes = read_bounded(Path::new("/proc/self/mountinfo"), MAX_LOCK_BYTES)?;
            Self::parse(&bytes)
        }

        fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
            if bytes.last() != Some(&b'\n') {
                return Err("filesystem_mount_table_incomplete");
            }
            let text = std::str::from_utf8(bytes).map_err(|_| "filesystem_mount_table_invalid")?;
            let mut mounts = BTreeMap::new();
            for line in text.lines() {
                let (before, after) = line
                    .split_once(" - ")
                    .ok_or("filesystem_mount_table_invalid")?;
                let before: Vec<_> = before.split_whitespace().collect();
                let after: Vec<_> = after.split_whitespace().collect();
                if before.len() < 6 || after.len() < 3 {
                    return Err("filesystem_mount_table_invalid");
                }
                let mount_id = before[0]
                    .parse::<u64>()
                    .map_err(|_| "filesystem_mount_table_invalid")?;
                let safe = matches!(
                    after[0],
                    "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "tmpfs" | "overlay" | "zfs"
                );
                if mounts.insert(mount_id, safe).is_some() {
                    return Err("filesystem_mount_table_ambiguous");
                }
            }
            Ok(Self { mounts })
        }

        fn permits(&self, file: &File) -> bool {
            let path = PathBuf::from(format!("/proc/self/fdinfo/{}", file.as_raw_fd()));
            let Ok(bytes) = read_bounded(&path, MAX_FIELD_BYTES) else {
                return false;
            };
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return false;
            };
            let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
            let Some(id) = ids.next().and_then(|id| id.trim().parse::<u64>().ok()) else {
                return false;
            };
            ids.next().is_none() && self.mounts.get(&id) == Some(&true)
        }
    }

    fn workspace_id(
        cwd: &File,
        deadline: Instant,
        filesystems: &FilesystemGuard,
    ) -> Result<ObjectId, &'static str> {
        let mut current = cwd
            .try_clone()
            .map_err(|_| "workspace_directory_unavailable")?;
        for _ in 0..MAX_WORKSPACE_DEPTH {
            if Instant::now() >= deadline {
                return Err("collection_time_budget");
            }
            if !filesystems.permits(&current) {
                return Err("workspace_filesystem_unsupported");
            }
            let this = directory_id(&current)?;
            let parent = open_directory(&directory_path(&current, ".."))?;
            if !filesystems.permits(&parent) {
                return Err("workspace_filesystem_unsupported");
            }
            if this == directory_id(&parent)? {
                return Err("workspace_marker_not_found");
            }
            for marker in [
                "Cargo.toml",
                "package.json",
                "go.mod",
                "pyproject.toml",
                ".git",
            ] {
                // O_PATH avoids opening special files or triggering an
                // automount; do not follow a marker into another filesystem.
                match OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(directory_path(&current, marker))
                {
                    Ok(file) => {
                        if !filesystems.permits(&file) {
                            return Err("workspace_filesystem_unsupported");
                        }
                        let meta = file
                            .metadata()
                            .map_err(|_| "workspace_marker_unavailable")?;
                        if (marker == ".git" && meta.is_dir()) || meta.is_file() {
                            return Ok(this);
                        }
                        return Err("workspace_marker_ambiguous");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("workspace_marker_unavailable"),
                }
            }
            current = parent;
        }
        Err("workspace_depth_limit")
    }

    fn argv(bytes: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
        if bytes.last() != Some(&0) {
            return Err("command_line_incomplete");
        }
        let args: Vec<_> = bytes[..bytes.len() - 1].split(|byte| *byte == 0).collect();
        if args.first().is_none_or(|arg| arg.is_empty()) {
            return Err("command_line_empty");
        }
        Ok(args)
    }

    /// Values are kept only long enough to hash them and resolve explicit targets.
    fn selected_environment(
        bytes: &[u8],
    ) -> Result<BTreeMap<&'static [u8], Vec<u8>>, &'static str> {
        if !bytes.is_empty() && bytes.last() != Some(&0) {
            return Err("environment_incomplete");
        }
        let mut selected = BTreeMap::new();
        for entry in bytes
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let Some(eq) = entry.iter().position(|byte| *byte == b'=') else {
                return Err("environment_malformed");
            };
            if let Some(&key) = ENV_KEYS.iter().find(|&&key| key == &entry[..eq]) {
                if selected.insert(key, entry[eq + 1..].to_vec()).is_some() {
                    return Err("environment_key_ambiguous");
                }
            }
        }
        Ok(selected)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct WorkContext {
        command: String,
        configuration: String,
        cwd: String,
        workspace: String,
        mount_namespace: ObjectId,
        pid_namespace: ObjectId,
        target_directory: Option<String>,
        kind: WorkKind,
        is_cargo: bool,
    }

    fn context(
        proc: &PinnedProc,
        process: &ProcessRecord,
        deadline: Instant,
        filesystems: &FilesystemGuard,
    ) -> Result<WorkContext, &'static str> {
        let raw_args = proc.read("cmdline", MAX_FIELD_BYTES)?;
        if String::from_utf8_lossy(&raw_args).replace('\0', " ").trim() != process.cmd.trim() {
            return Err("command_changed_since_census");
        }
        let args = argv(&raw_args)?;
        let kind = workload_kind(&args).ok_or("command_is_no_longer_build_or_test")?;
        let is_cargo = args.first().is_some_and(|arg| basename(arg) == b"cargo")
            || (matches!(
                basename(args[0]),
                b"python" | b"python3" | b"sh" | b"bash" | b"dash"
            ) && args.get(1).is_some_and(|arg| basename(arg) == b"cargo"));
        let executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(proc.path("exe"))
            .map_err(|_| "executable_identity_unavailable")?;
        if !filesystems.permits(&executable) {
            return Err("executable_filesystem_unsupported");
        }
        let executable = executable
            .metadata()
            .map_err(|_| "executable_identity_unavailable")?;
        if !executable.is_file() {
            return Err("executable_identity_unavailable");
        }
        let cwd = open_directory(&proc.path("cwd"))?;
        if !filesystems.permits(&cwd) {
            return Err("workspace_filesystem_unsupported");
        }
        if cwd
            .metadata()
            .map_err(|_| "cwd_identity_unavailable")?
            .nlink()
            == 0
        {
            return Err("cwd_deleted");
        }
        let cwd_id = directory_id(&cwd)?;
        let workspace = workspace_id(&cwd, deadline, filesystems)?;
        let mount_namespace = proc.namespace("ns/mnt")?;
        let pid_namespace = proc.namespace("ns/pid")?;
        let environment = proc.read("environ", MAX_ENV_BYTES)?;
        let selected = selected_environment(&environment)?;
        let configuration = digest(ENV_KEYS.into_iter().flat_map(|key| {
            let mut fields = vec![key.to_vec()];
            if let Some(value) = selected.get(key) {
                fields.push(vec![1]);
                fields.push(value.clone());
            } else {
                fields.push(vec![0]);
            }
            fields
        }));
        let target_directory = if is_cargo {
            explicit_target_directory(
                &args,
                &selected,
                &cwd,
                &mount_namespace,
                deadline,
                filesystems,
            )
        } else {
            None
        };
        let exe_id = ObjectId::of(&executable).digest();
        let command = digest([
            raw_args.as_slice(),
            exe_id.as_bytes(),
            &executable.len().to_le_bytes(),
            &executable.mtime().to_le_bytes(),
            &executable.mtime_nsec().to_le_bytes(),
        ]);
        let namespace = mount_namespace.digest();
        Ok(WorkContext {
            command,
            configuration,
            cwd: digest([namespace.as_bytes(), cwd_id.digest().as_bytes()]),
            workspace: digest([namespace.as_bytes(), workspace.digest().as_bytes()]),
            mount_namespace,
            pid_namespace,
            target_directory,
            kind,
            is_cargo,
        })
    }

    fn explicit_target_directory(
        args: &[&[u8]],
        selected: &BTreeMap<&[u8], Vec<u8>>,
        cwd: &File,
        namespace: &ObjectId,
        deadline: Instant,
        filesystems: &FilesystemGuard,
    ) -> Option<String> {
        use std::os::unix::ffi::OsStrExt;
        let mut target: Option<&[u8]> = None;
        let mut arguments = args.iter().copied();
        while let Some(arg) = arguments.next() {
            // Cargo passes the remainder to the test/program. Its options do
            // not select Cargo's target directory.
            if arg == b"--" {
                break;
            }
            let value = if arg == b"--target-dir" {
                Some(arguments.next()?)
            } else {
                arg.strip_prefix(b"--target-dir=")
            };
            if let Some(value) = value {
                if target.replace(value).is_some() {
                    return None;
                }
            }
        }
        let target = target
            .or_else(|| {
                selected
                    .get(b"CARGO_TARGET_DIR".as_slice())
                    .map(Vec::as_slice)
            })
            .or_else(|| {
                selected
                    .get(b"CARGO_BUILD_TARGET_DIR".as_slice())
                    .map(Vec::as_slice)
            })?;
        if target.is_empty() {
            return None;
        }
        let target = Path::new(std::ffi::OsStr::from_bytes(target));
        let mut directory = if target.is_absolute() {
            // Absolute names are only interpretable in the collector's mount namespace.
            let own = ObjectId::of(&fs::metadata("/proc/self/ns/mnt").ok()?);
            if &own != namespace {
                return None;
            }
            open_directory(Path::new("/")).ok()?
        } else {
            cwd.try_clone().ok()?
        };
        if !filesystems.permits(&directory) {
            return None;
        }
        // Resolve one final component at a time, rejecting symlinks and unsafe
        // mounts before any following lookup. A direct open of an arbitrary
        // target path could traverse a stalled FUSE mount or automount.
        for (count, component) in target.components().enumerate() {
            if count >= MAX_WORKSPACE_DEPTH || Instant::now() >= deadline {
                return None;
            }
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Prefix(_) => return None,
                _ => {}
            }
            directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory_path(&directory, "").join(component.as_os_str()))
                .ok()?;
            if !filesystems.permits(&directory) {
                return None;
            }
        }
        Some(digest([
            namespace.digest(),
            directory_id(&directory).ok()?.digest(),
        ]))
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct LockKey {
        major: u32,
        minor: u32,
        inode: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct LockRecord {
        owner: i64,
        waiter: bool,
        key: Option<LockKey>,
    }

    /// Reuse the safety gate's complete-record validator before interpreting fields.
    fn lock_record(line: &str) -> Result<LockRecord, &'static str> {
        let owner = crate::action::prechecks::parse_proc_lock_owner(line)
            .map_err(|_| "lock_record_invalid")?;
        let fields: Vec<_> = line.split_whitespace().collect();
        let waiter = fields.get(1) == Some(&"->");
        let offset = usize::from(waiter);
        let key = if fields[5 + offset] == "<none>:0" {
            None
        } else {
            let values: Vec<_> = fields[5 + offset].split(':').collect();
            Some(LockKey {
                major: u32::from_str_radix(values[0], 16).map_err(|_| "lock_device_invalid")?,
                minor: u32::from_str_radix(values[1], 16).map_err(|_| "lock_device_invalid")?,
                inode: values[2].parse().map_err(|_| "lock_inode_invalid")?,
            })
        };
        Ok(LockRecord { owner, waiter, key })
    }

    fn lock_table(bytes: &[u8]) -> Result<Vec<LockRecord>, &'static str> {
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return Err("lock_table_incomplete");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "lock_table_invalid")?;
        text.lines().map(lock_record).collect()
    }

    #[derive(Debug, Clone, Default)]
    struct LockObservation {
        held: BTreeSet<LockKey>,
        waiting: BTreeSet<LockKey>,
        holds_any: bool,
        waiting_unattributed: bool,
        complete: bool,
    }

    impl LockObservation {
        fn add(&mut self, record: &LockRecord) {
            if record.waiter {
                if let Some(key) = &record.key {
                    self.waiting.insert(key.clone());
                } else {
                    self.waiting_unattributed = true;
                }
            } else {
                self.holds_any = true;
                if let Some(key) = &record.key {
                    self.held.insert(key.clone());
                }
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DescriptorLocks {
        inode: u64,
        flags: u32,
        locks: Vec<LockRecord>,
    }

    fn descriptor_locks(bytes: &[u8]) -> Result<DescriptorLocks, &'static str> {
        if bytes.last() != Some(&b'\n') {
            return Err("descriptor_information_incomplete");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "descriptor_information_invalid")?;
        let mut position = None;
        let mut flags = None;
        let mut inode = None;
        let mut locks = Vec::new();
        for line in text.lines() {
            let (field, value) = line
                .split_once(':')
                .ok_or("descriptor_information_invalid")?;
            match field {
                "pos" => {
                    let value = value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| "descriptor_position_invalid")?;
                    if position.replace(value).is_some() {
                        return Err("descriptor_position_ambiguous");
                    }
                }
                "flags" => {
                    let value = u32::from_str_radix(value.trim(), 8)
                        .map_err(|_| "descriptor_flags_invalid")?;
                    if flags.replace(value).is_some() {
                        return Err("descriptor_flags_ambiguous");
                    }
                }
                "ino" => {
                    let value = value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| "descriptor_inode_invalid")?;
                    if inode.replace(value).is_some() {
                        return Err("descriptor_inode_ambiguous");
                    }
                }
                "lock" => locks.push(lock_record(value)?),
                _ => {}
            }
        }
        position.ok_or("descriptor_position_missing")?;
        Ok(DescriptorLocks {
            inode: inode.ok_or("descriptor_inode_missing")?,
            flags: flags.ok_or("descriptor_flags_missing")?,
            locks,
        })
    }

    fn descriptor_names(
        proc: &PinnedProc,
        deadline: Instant,
    ) -> Result<BTreeSet<u32>, &'static str> {
        let entries =
            fs::read_dir(proc.path("fdinfo")).map_err(|_| "descriptor_directory_unavailable")?;
        let mut names = BTreeSet::new();
        for entry in entries {
            if Instant::now() >= deadline {
                return Err("collection_time_budget");
            }
            if names.len() >= MAX_FDS {
                return Err("descriptor_count_limit");
            }
            let entry = entry.map_err(|_| "descriptor_directory_incomplete")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("descriptor_name_invalid")?;
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("descriptor_name_invalid");
            }
            names.insert(name.parse::<u32>().map_err(|_| "descriptor_name_invalid")?);
        }
        Ok(names)
    }

    fn collect_locks(
        proc: &PinnedProc,
        pid: u32,
        table: &Result<Vec<LockRecord>, &'static str>,
        deadline: Instant,
    ) -> (LockObservation, Option<&'static str>) {
        let mut observation = LockObservation::default();
        if let Ok(records) = table {
            for record in records
                .iter()
                .filter(|record| record.owner == i64::from(pid))
            {
                observation.add(record);
            }
        }
        let result = (|| {
            let names = descriptor_names(proc, deadline)?;
            for &fd in &names {
                if Instant::now() >= deadline {
                    return Err("collection_time_budget");
                }
                let field = format!("fdinfo/{fd}");
                let first = descriptor_locks(&proc.read(&field, MAX_FIELD_BYTES)?)?;
                for record in &first.locks {
                    // Inherited flock/OFD owners may be -1 or an exited PID. The
                    // process's own fdinfo establishes its retained open description.
                    observation.add(record);
                }
                let second = descriptor_locks(&proc.read(&field, MAX_FIELD_BYTES)?)?;
                if first != second {
                    return Err("descriptor_lock_state_changed");
                }
            }
            if names != descriptor_names(proc, deadline)? {
                return Err("descriptor_set_changed");
            }
            table.as_ref().map_err(|error| *error)?;
            Ok(())
        })();
        observation.complete = result.is_ok();
        (observation, result.err())
    }

    #[derive(Debug, Clone)]
    struct WorkObservation {
        identity: ProcessIdentity,
        parent_pid: u32,
        ancestry: Vec<u32>,
        comm: String,
        record_command_sha256: String,
        family: String,
        start_ticks: u64,
        context: WorkContext,
        locks: LockObservation,
    }

    fn family(process: &ProcessRecord) -> String {
        digest([
            process.uid.to_le_bytes().as_slice(),
            record_command_digest(process).as_bytes(),
        ])
    }

    fn ancestry(
        process: &ProcessRecord,
        population: &BTreeMap<u32, Option<&ProcessRecord>>,
    ) -> Result<Option<Vec<u32>>, &'static str> {
        let mut parents = Vec::new();
        let mut current = process.ppid.0;
        let mut seen = BTreeSet::from([process.pid.0]);
        for _ in 0..64 {
            if current <= 1 {
                return Ok(Some(parents));
            }
            if !seen.insert(current) {
                return Err("process_ancestry_cycle");
            }
            let parent = population
                .get(&current)
                .copied()
                .flatten()
                .ok_or("process_ancestry_incomplete")?;
            if parent.state == ProcessState::Unknown && command_hint(parent) {
                return Err("process_ancestor_state_unavailable");
            }
            if candidate_hint(parent) {
                // A compiler/test worker or nested invocation belongs to its build.
                return Ok(None);
            }
            parents.push(current);
            current = parent.ppid.0;
        }
        Err("process_ancestry_depth_limit")
    }

    fn independent(peers: &[&WorkObservation]) -> bool {
        let mut parents = BTreeSet::new();
        let pids: BTreeSet<_> = peers.iter().map(|peer| peer.identity.pid.0).collect();
        peers.iter().all(|peer| {
            peer.parent_pid > 1
                && parents.insert(peer.parent_pid)
                && !peer.ancestry.iter().any(|ancestor| pids.contains(ancestor))
        })
    }

    fn duplicate_key(observation: &WorkObservation) -> String {
        digest([
            observation.identity.uid.to_string(),
            observation.context.command.clone(),
            observation.context.cwd.clone(),
            observation.context.workspace.clone(),
            observation.context.configuration.clone(),
            observation.context.pid_namespace.digest(),
        ])
    }

    fn summarize(
        snapshot: &mut DuplicateWorkSnapshot,
        observations: &[WorkObservation],
        incomplete_families: &BTreeSet<String>,
    ) {
        let mut by_duplicate = BTreeMap::<String, Vec<&WorkObservation>>::new();
        let mut by_workspace = BTreeMap::<String, Vec<&WorkObservation>>::new();
        for observed in observations {
            by_duplicate
                .entry(duplicate_key(observed))
                .or_default()
                .push(observed);
            if observed.context.is_cargo && observed.context.target_directory.is_some() {
                let key = digest([
                    observed.identity.uid.to_string(),
                    observed.context.workspace.clone(),
                    observed.context.pid_namespace.digest(),
                ]);
                by_workspace.entry(key).or_default().push(observed);
            }
        }
        for (id, peers) in by_duplicate {
            if peers.len() < 2 || !independent(&peers) {
                continue;
            }
            let newest = peers.iter().map(|peer| peer.start_ticks).max().unwrap_or(0);
            let complete = peers
                .iter()
                .all(|peer| peer.locks.complete && !incomplete_families.contains(&peer.family));
            let held: BTreeSet<_> = peers
                .iter()
                .flat_map(|peer| peer.locks.held.iter().cloned())
                .collect();
            let any_holders = peers.iter().any(|peer| peer.locks.holds_any);
            let any_waiters = peers
                .iter()
                .any(|peer| !peer.locks.waiting.is_empty() || peer.locks.waiting_unattributed);
            let members = peers
                .iter()
                .map(|peer| {
                    let role = if peer.locks.holds_any {
                        DuplicateRole::ProtectedLockHolder
                    } else if !complete || peer.locks.waiting_unattributed {
                        DuplicateRole::Undetermined
                    } else if any_holders {
                        if !peer.locks.waiting.is_empty() && peer.locks.waiting.is_subset(&held) {
                            DuplicateRole::RedundantWaiter
                        } else {
                            DuplicateRole::Undetermined
                        }
                    } else if any_waiters {
                        DuplicateRole::Undetermined
                    } else if peer.start_ticks == newest {
                        DuplicateRole::PreferredNewest
                    } else {
                        DuplicateRole::RedundantOlder
                    };
                    DuplicateWorkMember {
                        identity: peer.identity.clone(),
                        parent_pid: peer.parent_pid,
                        comm: peer.comm.clone(),
                        record_command_sha256: peer.record_command_sha256.clone(),
                        role,
                    }
                })
                .collect();
            snapshot.duplicates.push(DuplicateWorkGroup {
                id,
                command_sha256: peers[0].context.command.clone(),
                workspace_sha256: peers[0].context.workspace.clone(),
                cwd_sha256: peers[0].context.cwd.clone(),
                configuration_sha256: peers[0].context.configuration.clone(),
                members,
                lock_evidence_complete: complete,
            });
        }
        for (id, peers) in by_workspace {
            if peers.len() < 2 || !independent(&peers) {
                continue;
            }
            let targets: BTreeSet<_> = peers
                .iter()
                .filter_map(|peer| peer.context.target_directory.as_ref())
                .collect();
            if targets.len() < 2 {
                continue;
            }
            snapshot.competing_builds.push(CompetingBuildGroup {
                id,
                workspace_sha256: peers[0].context.workspace.clone(),
                target_directory_count: targets.len(),
                members: peers
                    .iter()
                    .filter_map(|peer| {
                        Some(CompetingBuildMember {
                            identity: peer.identity.clone(),
                            parent_pid: peer.parent_pid,
                            comm: peer.comm.clone(),
                            record_command_sha256: peer.record_command_sha256.clone(),
                            target_directory_sha256: peer.context.target_directory.clone()?,
                        })
                    })
                    .collect(),
            });
        }
    }

    /// Inspect one complete census, including young peers and protected ancestors.
    /// No process is signalled, no environment value is serialized, and no posterior
    /// is changed. Collection is bounded by item/byte/depth limits and an elapsed
    /// work budget; unavailable syscall results remain explicit unknown evidence.
    pub fn collect_duplicate_work(processes: &[ProcessRecord]) -> DuplicateWorkSnapshot {
        collect_from(processes, Path::new("/proc"), COLLECTION_BUDGET)
    }

    fn collect_from(
        processes: &[ProcessRecord],
        proc_root: &Path,
        budget: Duration,
    ) -> DuplicateWorkSnapshot {
        let deadline = Instant::now() + budget;
        let mut snapshot = DuplicateWorkSnapshot {
        observed_at: chrono::Utc::now().to_rfc3339(),
        input_processes: processes.len(), complete: true,
        limitations: vec![
            "Groups contain observed independent build/test launches only; absent groups do not prove uniqueness. Siblings, nested workers and incomplete identities are excluded".to_string(),
            "Matching argv, executable, cwd and selected environment is review advice, not proof of interchangeable work. Other environment, inputs, outputs and intentional parallelism can differ".to_string(),
            "Newest means newest among observed peers at kernel start-tick resolution. Known lock holders and ambiguous lock evidence are preserved".to_string(),
            "Competing-build findings require different explicit, existing target-directory identities in one observed workspace. Missing/default/config-file targets are not guessed; pressure and contention are assessed separately".to_string(),
            "The process census and filesystem reads are not atomic. Limits bound work and bytes, not the duration of an individual kernel filesystem call".to_string(),
        ],
        ..Default::default()
    };
        let mut population = BTreeMap::new();
        for process in processes {
            population
                .entry(process.pid.0)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(process));
        }
        let candidates: Vec<_> = processes
            .iter()
            .filter(|process| {
                candidate_hint(process)
                    || (process.state == ProcessState::Unknown && command_hint(process))
            })
            .collect();
        if candidates.is_empty() {
            return snapshot;
        }
        let boot = match read_bounded(&proc_root.join("sys/kernel/random/boot_id"), 128)
            .ok()
            .and_then(|value| String::from_utf8(value).ok())
            .filter(|value| !value.trim().is_empty() && !value.contains(':'))
        {
            Some(boot) => boot.trim().to_string(),
            None => {
                snapshot.eligible_processes = candidates.len();
                snapshot.diagnostic(None, "boot_identity_unavailable");
                return snapshot;
            }
        };
        let filesystems = match FilesystemGuard::load() {
            Ok(filesystems) => filesystems,
            Err(_) => {
                snapshot.eligible_processes = candidates.len();
                snapshot.diagnostic(None, "filesystem_mount_table_unavailable");
                return snapshot;
            }
        };
        struct Pending<'a> {
            record: &'a ProcessRecord,
            proc: PinnedProc,
            observation: WorkObservation,
        }
        let mut pending = Vec::new();
        let mut incomplete_families = BTreeSet::new();
        let mut attempts = 0;
        for process in candidates {
            if process.state == ProcessState::Unknown {
                snapshot.eligible_processes += 1;
                snapshot.diagnostic(Some(process.pid.0), "process_state_unavailable");
                incomplete_families.insert(family(process));
                continue;
            }
            let parents = match ancestry(process, &population) {
                Ok(Some(parents)) => parents,
                Ok(None) => continue,
                Err(reason) => {
                    snapshot.eligible_processes += 1;
                    snapshot.diagnostic(Some(process.pid.0), reason);
                    incomplete_families.insert(family(process));
                    continue;
                }
            };
            snapshot.eligible_processes += 1;
            let observed = (|| {
                if population.get(&process.pid.0).copied().flatten().is_none() {
                    return Err("duplicate_census_pid");
                }
                // Bound attempted probes, including denied or vanished PIDs.
                // A success-count limit alone allows unbounded failed reads.
                if attempts >= MAX_PROCESSES {
                    return Err("process_count_limit");
                }
                if Instant::now() >= deadline {
                    return Err("collection_time_budget");
                }
                attempts += 1;
                let proc = PinnedProc::open(proc_root, process.pid.0)?;
                let start_ticks = proc.identity(process, &boot)?;
                let context = context(&proc, process, deadline, &filesystems)?;
                proc.identity(process, &boot)?;
                Ok(Pending {
                    record: process,
                    proc,
                    observation: WorkObservation {
                        identity: identity_from_record(process),
                        parent_pid: process.ppid.0,
                        ancestry: parents,
                        comm: process.comm.clone(),
                        record_command_sha256: record_command_digest(process),
                        family: family(process),
                        start_ticks,
                        context,
                        locks: LockObservation::default(),
                    },
                })
            })();
            match observed {
                Ok(observed) => pending.push(observed),
                Err(reason) => {
                    snapshot.diagnostic(Some(process.pid.0), reason);
                    incomplete_families.insert(family(process));
                }
            }
        }
        // Descriptor walks are required only for repeated invocations. A single
        // shared lock table is reused, rather than reread once per process.
        let mut groups = BTreeMap::<String, Vec<&WorkObservation>>::new();
        for observed in &pending {
            groups
                .entry(duplicate_key(&observed.observation))
                .or_default()
                .push(&observed.observation);
        }
        let needs_locks: BTreeSet<_> = groups
            .values()
            .filter(|peers| peers.len() > 1 && independent(peers))
            .flat_map(|peers| peers.iter().map(|peer| peer.identity.pid.0))
            .collect();
        let locks = if needs_locks.is_empty() {
            Ok(Vec::new())
        } else {
            read_bounded(&proc_root.join("locks"), MAX_LOCK_BYTES)
                .map_err(|_| "lock_table_unavailable")
                .and_then(|bytes| lock_table(&bytes))
        };
        let mut observations = Vec::new();
        for mut pending in pending {
            if needs_locks.contains(&pending.record.pid.0) {
                let (observation, error) =
                    collect_locks(&pending.proc, pending.record.pid.0, &locks, deadline);
                pending.observation.locks = observation;
                if let Some(reason) = error {
                    snapshot.diagnostic(Some(pending.record.pid.0), reason);
                }
            }
            let valid = (|| {
                if Instant::now() >= deadline {
                    return Err("collection_time_budget");
                }
                pending.proc.identity(pending.record, &boot)?;
                if context(&pending.proc, pending.record, deadline, &filesystems)?
                    != pending.observation.context
                {
                    return Err("workload_context_changed");
                }
                pending.proc.identity(pending.record, &boot)?;
                Ok(())
            })();
            match valid {
                Ok(()) => observations.push(pending.observation),
                Err(reason) => {
                    snapshot.diagnostic(Some(pending.record.pid.0), reason);
                    incomplete_families.insert(pending.observation.family);
                }
            }
        }
        observations.sort_by_key(|observation| observation.identity.pid.0);
        snapshot.attempted_processes = attempts;
        snapshot.observed_processes = observations.len();
        summarize(&mut snapshot, &observations, &incomplete_families);
        snapshot
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pt_common::ProcessId;
        use std::os::unix::fs::symlink;

        const BOOT: &str = "11111111-2222-3333-4444-555555555555";

        fn record(pid: u32, parent: u32, ticks: u64, cmd: &str) -> ProcessRecord {
            ProcessRecord {
                pid: ProcessId(pid),
                ppid: ProcessId(parent),
                uid: 1000,
                user: "fixture".to_string(),
                pgid: Some(parent),
                sid: Some(900),
                start_id: StartId::from_linux(BOOT, ticks, pid),
                comm: cmd.split_whitespace().next().unwrap_or("cargo").to_string(),
                cmd: cmd.to_string(),
                state: ProcessState::Sleeping,
                cpu_percent: 0.0,
                rss_bytes: 4096,
                vsz_bytes: 8192,
                tty: None,
                start_time_unix: 0,
                elapsed: Duration::from_secs(60),
                source: "duplicate_work_fixture".to_string(),
                container_info: None,
            }
        }

        struct ProcFixture {
            root: PathBuf,
            workspace: PathBuf,
            executable: PathBuf,
            processes: Vec<ProcessRecord>,
        }

        impl ProcFixture {
            fn new() -> Self {
                // Retain fixture artifacts for post-failure inspection.
                let directory = tempfile::tempdir().unwrap().keep();
                let root = directory.join("proc");
                let workspace = directory.join("private-workspace-name");
                let executable = directory.join("cargo-executable");
                fs::create_dir_all(root.join("sys/kernel/random")).unwrap();
                fs::create_dir(&workspace).unwrap();
                fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
                fs::write(&executable, "fixture executable identity").unwrap();
                fs::write(root.join("sys/kernel/random/boot_id"), BOOT).unwrap();
                fs::write(root.join("locks"), "").unwrap();
                Self {
                    root,
                    workspace,
                    executable,
                    processes: Vec::new(),
                }
            }

            fn add(&mut self, pid: u32, parent: u32, ticks: u64, args: &[u8], env: &[u8]) {
                let cmd = String::from_utf8_lossy(args)
                    .replace('\0', " ")
                    .trim()
                    .to_string();
                let process = record(pid, parent, ticks, &cmd);
                let directory = self.root.join(pid.to_string());
                fs::create_dir_all(directory.join("ns")).unwrap();
                fs::create_dir(directory.join("fdinfo")).unwrap();
                let mut fields = vec!["0".to_string(); 22];
                fields[0] = "S".to_string();
                fields[1] = parent.to_string();
                fields[2] = parent.to_string();
                fields[3] = "900".to_string();
                fields[17] = "1".to_string();
                fields[19] = ticks.to_string();
                fs::write(
                    directory.join("stat"),
                    format!("{pid} ({}) {}\n", process.comm, fields.join(" ")),
                )
                .unwrap();
                fs::write(
                    directory.join("status"),
                    "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
                )
                .unwrap();
                fs::write(directory.join("cmdline"), args).unwrap();
                fs::write(directory.join("environ"), env).unwrap();
                symlink(&self.workspace, directory.join("cwd")).unwrap();
                symlink(&self.executable, directory.join("exe")).unwrap();
                symlink("/proc/self/ns/mnt", directory.join("ns/mnt")).unwrap();
                symlink("/proc/self/ns/pid", directory.join("ns/pid")).unwrap();
                self.processes.push(process);
                if !self.processes.iter().any(|process| process.pid.0 == parent) {
                    self.processes.push(record(parent, 1, 1, "bash"));
                }
            }

            fn two() -> Self {
                let mut fixture = Self::new();
                fixture.add(101, 201, 10, b"cargo\0build\0", b"");
                fixture.add(102, 202, 20, b"cargo\0build\0", b"");
                fixture
            }

            fn collect(&self) -> DuplicateWorkSnapshot {
                collect_from(&self.processes, &self.root, Duration::from_secs(5))
            }
        }

        fn roles(snapshot: &DuplicateWorkSnapshot) -> Vec<DuplicateRole> {
            assert_eq!(snapshot.duplicates.len(), 1, "{snapshot:?}");
            snapshot.duplicates[0]
                .members
                .iter()
                .map(|member| member.role)
                .collect()
        }

        #[test]
        fn exact_arguments_and_bounded_launcher_classification() {
            let left = argv(b"cargo\0test\0two words\0").unwrap();
            let right = argv(b"cargo\0test\0two\0words\0").unwrap();
            assert_ne!(digest(left), digest(right));
            assert_eq!(
                argv(b"cargo\0\0").unwrap(),
                vec![b"cargo".as_slice(), b"".as_slice()]
            );
            assert!(argv(b"cargo\0test").is_err());
            assert!(argv(b"\0build\0").is_err());
            assert_eq!(
                workload_kind(&[b"python3", b"/private/cargo", b"build"]),
                Some(WorkKind::Build)
            );
            assert_eq!(
                workload_kind(&[b"python3", b"-m", b"pytest"]),
                Some(WorkKind::Test)
            );
            assert_eq!(workload_kind(&[b"bash", b"-c", b"cargo build"]), None);
            let mut deep = vec![b"python".as_slice(); 10_000];
            deep.extend([b"cargo".as_slice(), b"build".as_slice()]);
            assert_eq!(workload_kind(&deep), None);
        }

        #[test]
        fn environment_rejects_partial_and_ambiguous_values() {
            assert!(selected_environment(b"RUSTFLAGS=-C opt-level=3").is_err());
            assert!(selected_environment(b"RUSTFLAGS=first\0RUSTFLAGS=second\0").is_err());
            assert!(selected_environment(b"MALFORMED\0").is_err());
            let selected =
                selected_environment(b"SECRET_TOKEN=do-not-retain\0RUSTFLAGS=\0").unwrap();
            assert_eq!(selected.len(), 1);
            assert_eq!(selected.get(b"RUSTFLAGS".as_slice()), Some(&Vec::new()));
            assert!(selected_environment(b"").unwrap().is_empty());
        }

        #[test]
        fn independent_duplicate_peers_keep_newest_and_roundtrip_identity() {
            let fixture = ProcFixture::two();
            let snapshot = fixture.collect();
            assert!(snapshot.complete, "{snapshot:?}");
            assert_eq!(snapshot.attempted_processes, 2);
            assert_eq!(snapshot.observed_processes, 2);
            assert_eq!(
                roles(&snapshot),
                vec![
                    DuplicateRole::RedundantOlder,
                    DuplicateRole::PreferredNewest
                ]
            );
            let process = fixture
                .processes
                .iter()
                .find(|process| process.pid.0 == 102)
                .unwrap();
            let diagnosis = snapshot.diagnosis_for(process).unwrap();
            assert!(diagnosis.preserves_work());
            let restored: ProcessWorkDiagnosis =
                serde_json::from_str(&serde_json::to_string(&diagnosis).unwrap()).unwrap();
            assert!(restored.matches_record(process));
            for field in [
                "uid", "pid", "ppid", "pgid", "sid", "start_id", "comm", "cmd",
            ] {
                let mut changed = process.clone();
                match field {
                    "uid" => changed.uid += 1,
                    "pid" => changed.pid.0 += 1,
                    "ppid" => changed.ppid.0 += 1,
                    "pgid" => changed.pgid = None,
                    "sid" => changed.sid = None,
                    "start_id" => changed.start_id = StartId::from_linux(BOOT, 99, changed.pid.0),
                    "comm" => changed.comm.push('x'),
                    "cmd" => changed.cmd.push_str(" --release"),
                    _ => unreachable!(),
                }
                assert!(!restored.matches_record(&changed), "changed {field}");
                assert!(
                    snapshot.diagnosis_for(&changed).is_none(),
                    "changed {field}"
                );
            }
        }

        #[test]
        fn argument_boundaries_and_rustflags_prevent_false_duplicates() {
            let mut arguments = ProcFixture::new();
            arguments.add(101, 201, 10, b"cargo\0test\0two words\0", b"");
            arguments.add(102, 202, 20, b"cargo\0test\0two\0words\0", b"");
            let snapshot = arguments.collect();
            assert_eq!(snapshot.observed_processes, 2);
            assert!(snapshot.duplicates.is_empty());
            for environment in [
                b"RUSTFLAGS=-C debuginfo=1\0".as_slice(),
                b"RUSTFLAGS=\0",
                b"CARGO_ENCODED_RUSTFLAGS=-C\x1fdebuginfo=1\0",
            ] {
                let fixture = ProcFixture::two();
                fs::write(fixture.root.join("102/environ"), environment).unwrap();
                let snapshot = fixture.collect();
                assert_eq!(snapshot.observed_processes, 2);
                assert!(snapshot.duplicates.is_empty());
            }
        }

        #[test]
        fn competing_explicit_targets_are_hashed_and_aliases_are_not_competing() {
            let fixture = ProcFixture::two();
            fs::create_dir(fixture.workspace.join("private-target-one")).unwrap();
            fs::create_dir(fixture.workspace.join("private-target-two")).unwrap();
            symlink("private-target-one", fixture.workspace.join("alias-target")).unwrap();
            fs::write(
                fixture.root.join("101/environ"),
                b"CARGO_TARGET_DIR=private-target-one\0RUSTFLAGS=private-compiler-flags\0",
            )
            .unwrap();
            fs::write(
                fixture.root.join("102/environ"),
                b"CARGO_TARGET_DIR=private-target-two\0RUSTFLAGS=private-compiler-flags\0",
            )
            .unwrap();
            let snapshot = fixture.collect();
            assert!(snapshot.duplicates.is_empty());
            assert_eq!(snapshot.competing_builds.len(), 1);
            assert_eq!(snapshot.competing_builds[0].target_directory_count, 2);
            let serialized = serde_json::to_string(&snapshot).unwrap();
            for secret in [
                "private-target-one",
                "private-target-two",
                "private-workspace-name",
                "private-compiler-flags",
                "CARGO_TARGET_DIR",
                "RUSTFLAGS",
            ] {
                assert!(!serialized.contains(secret), "leaked {secret}");
            }
            fs::write(
                fixture.root.join("102/environ"),
                b"CARGO_TARGET_DIR=alias-target\0RUSTFLAGS=private-compiler-flags\0",
            )
            .unwrap();
            assert!(fixture.collect().competing_builds.is_empty());
        }

        #[test]
        fn target_option_after_program_separator_is_not_a_cargo_target() {
            let mut fixture = ProcFixture::new();
            fs::create_dir(fixture.workspace.join("one")).unwrap();
            fs::create_dir(fixture.workspace.join("two")).unwrap();
            fixture.add(101, 201, 10, b"cargo\0test\0--\0--target-dir\0one\0", b"");
            fixture.add(102, 202, 20, b"cargo\0test\0--\0--target-dir\0two\0", b"");
            let snapshot = fixture.collect();
            assert_eq!(snapshot.observed_processes, 2);
            assert!(snapshot.competing_builds.is_empty());
        }

        #[test]
        fn siblings_and_nested_build_workers_are_not_independent_duplicates() {
            let mut siblings = ProcFixture::new();
            siblings.add(101, 201, 10, b"cargo\0build\0", b"");
            siblings.add(102, 201, 20, b"cargo\0build\0", b"");
            assert!(siblings.collect().duplicates.is_empty());
            let mut nested = ProcFixture::new();
            nested.add(101, 201, 10, b"cargo\0build\0", b"");
            nested.add(102, 101, 20, b"cargo\0build\0", b"");
            let snapshot = nested.collect();
            assert_eq!(snapshot.eligible_processes, 1);
            assert!(snapshot.duplicates.is_empty());
            let population = BTreeMap::from([(101, Some(&nested.processes[0]))]);
            assert_eq!(
                ancestry(&nested.processes[0], &population),
                Err("process_ancestry_incomplete")
            );
        }

        #[test]
        fn holders_are_preserved_and_only_their_known_waiters_are_redundant() {
            let fixture = ProcFixture::two();
            fs::write(fixture.root.join("locks"), "1: FLOCK ADVISORY WRITE 101 00:01:77 0 EOF\n1: -> FLOCK ADVISORY WRITE 102 00:01:77 0 EOF\n").unwrap();
            let snapshot = fixture.collect();
            assert_eq!(
                roles(&snapshot),
                vec![
                    DuplicateRole::ProtectedLockHolder,
                    DuplicateRole::RedundantWaiter
                ]
            );
            fs::write(fixture.root.join("locks"), "1: FLOCK ADVISORY WRITE 101 00:01:77 0 EOF\n2: -> FLOCK ADVISORY WRITE 102 00:01:88 0 EOF\n").unwrap();
            assert_eq!(
                roles(&fixture.collect()),
                vec![
                    DuplicateRole::ProtectedLockHolder,
                    DuplicateRole::Undetermined
                ]
            );
        }

        #[test]
        fn malformed_lock_table_preserves_every_duplicate_including_newest() {
            let fixture = ProcFixture::two();
            fs::write(
                fixture.root.join("locks"),
                "1: FLOCK ADVISORY WRITE 101 00:01:77 0",
            )
            .unwrap();
            let snapshot = fixture.collect();
            assert!(!snapshot.complete);
            assert!(!snapshot.duplicates[0].lock_evidence_complete);
            assert_eq!(
                roles(&snapshot),
                vec![DuplicateRole::Undetermined, DuplicateRole::Undetermined]
            );
        }

        #[test]
        fn descriptor_owned_ofd_lock_protects_holder_when_global_table_is_incomplete() {
            let fixture = ProcFixture::two();
            fs::write(fixture.root.join("locks"), "truncated").unwrap();
            fs::write(fixture.root.join("101/fdinfo/3"), "pos:\t0\nflags:\t0100002\nino:\t77\nlock:\t1: OFDLCK ADVISORY WRITE -1 00:01:77 0 EOF\n").unwrap();
            assert_eq!(
                roles(&fixture.collect()),
                vec![
                    DuplicateRole::ProtectedLockHolder,
                    DuplicateRole::Undetermined
                ]
            );
            assert!(descriptor_locks(b"pos: 0\nflags: 2\nino: 77\nino: 88\n").is_err());
            assert!(descriptor_locks(b"pos: 0\nflags: 2\n").is_err());
        }

        #[test]
        fn partial_census_downgrades_preferences_but_preserves_positive_holders() {
            let fixture = ProcFixture::two();
            let mut snapshot = fixture.collect();
            snapshot.mark_census_incomplete();
            assert!(!snapshot.complete);
            assert_eq!(
                roles(&snapshot),
                vec![DuplicateRole::Undetermined, DuplicateRole::Undetermined]
            );
            fs::write(
                fixture.root.join("locks"),
                "1: FLOCK ADVISORY WRITE 101 00:01:77 0 EOF\n",
            )
            .unwrap();
            let mut snapshot = fixture.collect();
            snapshot.mark_census_incomplete();
            assert_eq!(
                roles(&snapshot),
                vec![
                    DuplicateRole::ProtectedLockHolder,
                    DuplicateRole::Undetermined
                ]
            );
        }

        #[test]
        fn unreadable_peer_and_stale_identity_cannot_imply_uniqueness_or_newest() {
            let mut fixture = ProcFixture::two();
            fixture.add(103, 203, 30, b"cargo\0build\0", b"RUSTFLAGS=truncated");
            let snapshot = fixture.collect();
            assert_eq!(snapshot.observed_processes, 2);
            assert!(!snapshot.complete);
            assert_eq!(
                roles(&snapshot),
                vec![DuplicateRole::Undetermined, DuplicateRole::Undetermined]
            );
            let process = fixture
                .processes
                .iter_mut()
                .find(|process| process.pid.0 == 102)
                .unwrap();
            process.start_id = StartId::from_linux(BOOT, 999, 102);
            let snapshot = fixture.collect();
            assert!(snapshot.duplicates.is_empty());
            assert_eq!(snapshot.observed_processes, 1);
        }

        #[test]
        fn identity_requires_complete_stat_and_uid_fields() {
            let fixture = ProcFixture::two();
            let proc = PinnedProc::open(&fixture.root, 101).unwrap();
            let process = &fixture.processes[0];
            assert_eq!(proc.identity(process, BOOT), Ok(10));
            fs::write(
                fixture.root.join("101/status"),
                "Uid: 1000\nGid: 1000 1000 1000 1000\n",
            )
            .unwrap();
            assert_eq!(proc.identity(process, BOOT), Err("process_uid_invalid"));
            fs::write(
                fixture.root.join("101/status"),
                "Uid: 1000 1000 1000 1000\n",
            )
            .unwrap();
            fs::write(fixture.root.join("101/stat"), "101 (cargo) S 201\n").unwrap();
            assert_eq!(proc.identity(process, BOOT), Err("process_stat_invalid"));
        }

        #[test]
        fn failed_probes_consume_attempt_budget_and_zero_budget_probes_nothing() {
            let mut fixture = ProcFixture::new();
            fixture.processes.push(record(200, 1, 1, "bash"));
            for index in 0..MAX_PROCESSES + 17 {
                fixture
                    .processes
                    .push(record(1000 + index as u32, 200, 10, "cargo build"));
            }
            let snapshot = fixture.collect();
            assert!(!snapshot.complete);
            assert_eq!(snapshot.eligible_processes, MAX_PROCESSES + 17);
            assert_eq!(snapshot.attempted_processes, MAX_PROCESSES);
            assert_eq!(snapshot.observed_processes, 0);
            assert!(snapshot.omitted_diagnostics > 0);
            let expired = collect_from(&fixture.processes, &fixture.root, Duration::ZERO);
            assert_eq!(expired.attempted_processes, 0);
            assert_eq!(expired.observed_processes, 0);
            assert!(expired
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.reason == "collection_time_budget"));
            assert!(collect_from(&[], &fixture.root, Duration::ZERO).complete);
        }

        #[test]
        fn unknown_state_peer_preserves_observed_duplicates() {
            let mut fixture = ProcFixture::two();
            let mut unknown = record(103, 203, 30, "cargo build");
            unknown.state = ProcessState::Unknown;
            fixture.processes.push(unknown);
            let snapshot = fixture.collect();
            assert!(!snapshot.complete);
            assert_eq!(snapshot.eligible_processes, 3);
            assert_eq!(snapshot.attempted_processes, 2);
            assert_eq!(
                roles(&snapshot),
                vec![DuplicateRole::Undetermined, DuplicateRole::Undetermined]
            );
        }

        #[test]
        fn filesystem_guard_excludes_fuse_network_and_ambiguous_mounts() {
            let table = FilesystemGuard::parse(b"10 1 0:1 / /rw rw - ext4 /dev/loop0 rw\n11 1 0:2 / /remote rw - fuse.sshfs remote rw\n12 1 0:3 / /nfs rw - nfs4 remote rw\n13 1 0:4 / /auto rw - autofs auto rw\n").unwrap();
            assert_eq!(table.mounts.get(&10), Some(&true));
            for id in [11, 12, 13] {
                assert_eq!(table.mounts.get(&id), Some(&false));
            }
            assert!(FilesystemGuard::parse(
                b"10 1 0:1 / /rw rw - ext4 /dev/loop0 rw\n10 1 0:2 / /other rw - tmpfs none rw\n"
            )
            .is_err());
            assert!(FilesystemGuard::parse(b"10 1 0:1 / /rw rw - ext4 /dev/loop0 rw").is_err());
            let fixture = ProcFixture::two();
            let cwd = open_directory(&fixture.workspace).unwrap();
            assert!(FilesystemGuard::load().unwrap().permits(&cwd));
            assert!(!FilesystemGuard {
                mounts: BTreeMap::new()
            }
            .permits(&cwd));
        }

        struct LiveChild {
            child: std::process::Child,
            reader: Option<std::thread::JoinHandle<()>>,
        }

        impl LiveChild {
            fn spawn(script: &Path, cwd: &Path, mode: &str, target: &str, flags: &str) -> Self {
                use std::io::BufRead;
                use std::process::{Command, Stdio};
                let mut fixture = Self {
                    child: Command::new("python3")
                        .arg(script)
                        .arg("build")
                        .current_dir(cwd)
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin")
                        .env("PT_DUPLICATE_FIXTURE_MODE", mode)
                        .env("CARGO_TARGET_DIR", target)
                        .env("RUSTFLAGS", flags)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .expect("spawn owned duplicate-work fixture"),
                    reader: None,
                };
                let output = fixture.child.stdout.take().unwrap();
                let (sender, receiver) = std::sync::mpsc::channel();
                fixture.reader = Some(std::thread::spawn(move || {
                    let mut line = String::new();
                    let result = std::io::BufReader::new(output)
                        .read_line(&mut line)
                        .map(|_| line);
                    let _ = sender.send(result);
                }));
                let ready = receiver
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded owned child readiness")
                    .expect("read owned child readiness");
                assert_eq!(ready.trim(), "PT_DUPLICATE_READY");
                fixture
            }

            fn record(&self) -> ProcessRecord {
                let pid = self.child.id();
                let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                let stat = parse_proc_stat_content(&stat).unwrap();
                let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
                let status =
                    crate::collect::proc_parsers::parse_proc_status_content(&status).unwrap();
                let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
                let command = String::from_utf8(args).unwrap().replace('\0', " ");
                let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
                let mut process = record(pid, stat.ppid, stat.starttime, command.trim());
                process.uid = status.euid;
                process.comm = stat.comm;
                process.pgid = Some(stat.pgrp as u32);
                process.sid = Some(stat.session as u32);
                process.start_id = StartId::from_linux(boot.trim(), stat.starttime, pid);
                process.state = ProcessState::from_char(stat.state);
                process
            }

            fn probe(&self) -> (ProcessRecord, PinnedProc, WorkContext) {
                let process = self.record();
                let pinned = PinnedProc::open(Path::new("/proc"), process.pid.0).unwrap();
                let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
                pinned.identity(&process, boot.trim()).unwrap();
                let filesystems = FilesystemGuard::load().unwrap();
                let observed = context(
                    &pinned,
                    &process,
                    Instant::now() + Duration::from_secs(2),
                    &filesystems,
                )
                .unwrap();
                pinned.identity(&process, boot.trim()).unwrap();
                (process, pinned, observed)
            }
        }

        impl Drop for LiveChild {
            fn drop(&mut self) {
                // Child remains owned/unreaped until this guard completes. No
                // name search, process-group signal or unrelated workload is used.
                match self.child.try_wait() {
                    Ok(Some(_)) => {}
                    _ => {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                    }
                }
                if let Some(reader) = self.reader.take() {
                    let _ = reader.join();
                }
            }
        }

        fn live_workspace() -> (PathBuf, PathBuf) {
            let directory = tempfile::tempdir().unwrap().keep();
            fs::write(directory.join("Cargo.toml"), "[workspace]\n").unwrap();
            fs::create_dir(directory.join("target-one")).unwrap();
            fs::create_dir(directory.join("target-two")).unwrap();
            let script = directory.join("cargo");
            fs::write(
                &script,
                r#"import fcntl, os, sys
mode = os.environ['PT_DUPLICATE_FIXTURE_MODE']
if mode in ('holder', 'waiter'):
    lock = open('.cargo-lock', 'a')
    if mode == 'holder':
        fcntl.flock(lock, fcntl.LOCK_EX)
    print('PT_DUPLICATE_READY', flush=True)
    if mode == 'waiter':
        fcntl.flock(lock, fcntl.LOCK_EX)
else:
    print('PT_DUPLICATE_READY', flush=True)
sys.stdin.readline()
"#,
            )
            .unwrap();
            (directory, script)
        }

        #[test]
        fn live_children_bind_exact_context_and_distinguish_target_configuration() {
            let (workspace, script) = live_workspace();
            let first =
                LiveChild::spawn(&script, &workspace, "idle", "target-one", "-C debuginfo=1");
            let same =
                LiveChild::spawn(&script, &workspace, "idle", "target-one", "-C debuginfo=1");
            let different =
                LiveChild::spawn(&script, &workspace, "idle", "target-two", "-C debuginfo=2");
            let (record, pinned, left) = first.probe();
            let (_, _, equal) = same.probe();
            let (_, _, right) = different.probe();
            assert_eq!(left, equal);
            assert_eq!(left.command, right.command);
            assert_eq!(left.cwd, right.cwd);
            assert_eq!(left.workspace, right.workspace);
            assert_ne!(left.configuration, right.configuration);
            assert_ne!(left.target_directory, right.target_directory);
            assert!(left.target_directory.is_some());
            let filesystems = FilesystemGuard::load().unwrap();
            let mut stale_command = record.clone();
            stale_command.cmd.push_str(" --release");
            assert_eq!(
                context(
                    &pinned,
                    &stale_command,
                    Instant::now() + Duration::from_secs(2),
                    &filesystems
                ),
                Err("command_changed_since_census")
            );
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
            let mut stale_parent = record;
            stale_parent.ppid.0 += 1;
            assert_eq!(
                pinned.identity(&stale_parent, boot.trim()),
                Err("process_identity_changed_or_unusable")
            );
        }

        #[test]
        fn live_file_lock_holder_and_blocked_waiter_remain_distinct() {
            let (workspace, script) = live_workspace();
            let holder = LiveChild::spawn(&script, &workspace, "holder", "target-one", "");
            let waiter = LiveChild::spawn(&script, &workspace, "waiter", "target-one", "");
            let (holder_record, holder_proc, holder_context) = holder.probe();
            let (waiter_record, waiter_proc, waiter_context) = waiter.probe();
            assert_eq!(holder_context, waiter_context);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let table = read_bounded(Path::new("/proc/locks"), MAX_LOCK_BYTES)
                    .and_then(|bytes| lock_table(&bytes));
                let (held, holder_error) =
                    collect_locks(&holder_proc, holder_record.pid.0, &table, deadline);
                let (waiting, waiter_error) =
                    collect_locks(&waiter_proc, waiter_record.pid.0, &table, deadline);
                if held.complete && waiting.complete && !waiting.waiting.is_empty() {
                    assert_eq!(holder_error, None);
                    assert_eq!(waiter_error, None);
                    assert!(held.holds_any);
                    assert!(!waiting.holds_any);
                    assert!(waiting.waiting.is_subset(&held.held));
                    assert!(held.waiting.is_empty());
                    break;
                }
                assert!(Instant::now() < deadline, "owned flock fixture never settled: holder={held:?}/{holder_error:?} waiter={waiting:?}/{waiter_error:?}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
