//! Bounded procfs reads and conservative traversal of held local directories.
//!
//! Filesystem classification comes from procfs mount IDs, before following a
//! directory component. A metadata query against an unknown FUSE or network
//! filesystem would itself be an unsafe way to decide whether it can be read.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

const MAX_MOUNTINFO_BYTES: usize = 2_097_152;
const MAX_FDINFO_BYTES: usize = 65_536;

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or("process_field_size_limit")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "process_field_unavailable")?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| "process_field_unavailable")?;
    if bytes.len() > limit {
        return Err("process_field_size_limit");
    }
    Ok(bytes)
}

/// Pin a known directory, including a procfs descriptor/cwd link. Arbitrary
/// user paths must instead be walked with `FilesystemGuard::resolve_directory`.
pub(crate) fn open_directory(path: &Path) -> Result<File, &'static str> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "directory_identity_unavailable")
}

pub(crate) fn directory_path(file: &File, suffix: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", file.as_raw_fd(), suffix))
}

/// A complete, stable view of each task's descriptor table. Threads can unshare
/// their file table, so `/proc/PID/fd` alone cannot establish socket ownership.
///
/// `process_dir` must name the caller's pinned procfs process directory. Every
/// task and descriptor entry shares one deadline/work budget across both passes.
/// Only descriptor links are read: no descriptor target is opened or stat'ed.
/// Unknown or changing evidence is an error, never an empty descriptor table.
pub(crate) fn task_descriptor_snapshot(
    process_dir: &Path,
    pid: u32,
    deadline: Instant,
    max_tasks: usize,
    max_entries: usize,
) -> Result<BTreeMap<u32, BTreeMap<u32, PathBuf>>, &'static str> {
    task_descriptor_snapshot_with(process_dir, pid, deadline, max_tasks, max_entries, || {})
}

struct TaskDescriptorBudget {
    deadline: Instant,
    remaining_entries: usize,
    max_tasks: usize,
}

impl TaskDescriptorBudget {
    fn check(&self) -> Result<(), &'static str> {
        if Instant::now() >= self.deadline {
            Err("task_descriptor_budget_exhausted")
        } else {
            Ok(())
        }
    }

    fn visit(&mut self) -> Result<(), &'static str> {
        self.check()?;
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .ok_or("task_descriptor_budget_exhausted")?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TaskDescriptorIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    birth_ticks: u64,
}

type TaskDescriptorObservation = BTreeMap<u32, (TaskDescriptorIdentity, BTreeMap<u32, PathBuf>)>;

fn task_descriptor_id(name: &std::ffi::OsStr, allow_zero: bool) -> Result<u32, &'static str> {
    let text = name.to_str().ok_or("task_descriptor_invalid_entry")?;
    let id = text
        .parse::<u32>()
        .map_err(|_| "task_descriptor_invalid_entry")?;
    if text != id.to_string() || id > i32::MAX as u32 || (!allow_zero && id == 0) {
        return Err("task_descriptor_invalid_entry");
    }
    Ok(id)
}

fn task_descriptor_ids(
    process_dir: &Path,
    pid: u32,
    budget: &mut TaskDescriptorBudget,
) -> Result<BTreeSet<u32>, &'static str> {
    budget.check()?;
    let entries = std::fs::read_dir(process_dir.join("task"))
        .map_err(|_| "task_descriptor_tasks_unavailable")?;
    let mut tids = BTreeSet::new();
    for entry in entries {
        budget.visit()?;
        let entry = entry.map_err(|_| "task_descriptor_tasks_unavailable")?;
        if tids.len() >= budget.max_tasks {
            return Err("task_descriptor_task_limit");
        }
        let tid = task_descriptor_id(&entry.file_name(), false)?;
        if !entry
            .file_type()
            .map_err(|_| "task_descriptor_tasks_unavailable")?
            .is_dir()
            || !tids.insert(tid)
        {
            return Err("task_descriptor_invalid_entry");
        }
    }
    budget.check()?;
    if !tids.contains(&pid) {
        return Err("task_descriptor_leader_unavailable");
    }
    Ok(tids)
}

fn task_descriptor_identity(
    directory: &File,
    path: &Path,
    tid: u32,
    budget: &TaskDescriptorBudget,
) -> Result<TaskDescriptorIdentity, &'static str> {
    budget.check()?;
    let pinned = directory
        .metadata()
        .map_err(|_| "task_descriptor_identity_unavailable")?;
    let current =
        std::fs::symlink_metadata(path).map_err(|_| "task_descriptor_identity_unavailable")?;
    if !current.is_dir()
        || pinned.dev() != current.dev()
        || pinned.ino() != current.ino()
        || pinned.uid() != current.uid()
    {
        return Err("task_descriptor_identity_changed");
    }
    let bytes = read_bounded(&directory_path(directory, "stat"), 16 * 1024)?;
    let content =
        std::str::from_utf8(&bytes).map_err(|_| "task_descriptor_identity_unavailable")?;
    let stat = super::proc_parsers::parse_required_proc_stat_content(tid, content)
        .map_err(|_| "task_descriptor_identity_unavailable")?;
    budget.check()?;
    Ok(TaskDescriptorIdentity {
        device: pinned.dev(),
        inode: pinned.ino(),
        uid: pinned.uid(),
        birth_ticks: stat.starttime,
    })
}

fn task_descriptor_observation(
    process_dir: &Path,
    pid: u32,
    budget: &mut TaskDescriptorBudget,
) -> Result<TaskDescriptorObservation, &'static str> {
    let tids = task_descriptor_ids(process_dir, pid, budget)?;
    let mut tasks = BTreeMap::new();
    for &tid in &tids {
        budget.check()?;
        let path = process_dir.join("task").join(tid.to_string());
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "task_descriptor_identity_unavailable")?;
        let before = task_descriptor_identity(&directory, &path, tid, budget)?;
        let entries = std::fs::read_dir(directory_path(&directory, "fd"))
            .map_err(|_| "task_descriptor_table_unavailable")?;
        let mut descriptors = BTreeMap::new();
        for entry in entries {
            budget.visit()?;
            let entry = entry.map_err(|_| "task_descriptor_table_unavailable")?;
            let fd = task_descriptor_id(&entry.file_name(), true)?;
            let target =
                std::fs::read_link(entry.path()).map_err(|_| "task_descriptor_link_unavailable")?;
            if descriptors.insert(fd, target).is_some() {
                return Err("task_descriptor_invalid_entry");
            }
        }
        let after = task_descriptor_identity(&directory, &path, tid, budget)?;
        if before != after {
            return Err("task_descriptor_identity_changed");
        }
        tasks.insert(tid, (before, descriptors));
    }
    if task_descriptor_ids(process_dir, pid, budget)? != tids {
        return Err("task_descriptor_task_set_changed");
    }
    Ok(tasks)
}

fn task_descriptor_snapshot_with(
    process_dir: &Path,
    pid: u32,
    deadline: Instant,
    max_tasks: usize,
    max_entries: usize,
    before_recheck: impl FnOnce(),
) -> Result<BTreeMap<u32, BTreeMap<u32, PathBuf>>, &'static str> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("task_descriptor_invalid_pid");
    }
    let mut budget = TaskDescriptorBudget {
        deadline,
        remaining_entries: max_entries,
        max_tasks,
    };
    let before = task_descriptor_observation(process_dir, pid, &mut budget)?;
    before_recheck();
    let after = task_descriptor_observation(process_dir, pid, &mut budget)?;
    budget.check()?;
    if before != after {
        return Err("task_descriptor_observation_changed");
    }
    Ok(before
        .into_iter()
        .map(|(tid, (_, descriptors))| (tid, descriptors))
        .collect())
}

/// One complete mountinfo record. Paths have the kernel's octal escapes
/// decoded exactly once; non-UTF-8 names remain unavailable rather than lossy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountInfo {
    pub id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub root: String,
    pub mount_point: String,
    pub filesystem_type: String,
    pub source: String,
    pub mount_options: String,
    pub super_options: String,
}

fn unsigned<T: std::str::FromStr>(value: &str) -> Result<T, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("filesystem_mount_table_invalid");
    }
    value.parse().map_err(|_| "filesystem_mount_table_invalid")
}

fn decode_mount_field(field: &str) -> Result<String, &'static str> {
    let input = field.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(&byte) = input.get(offset) {
        match byte {
            b'\\' => {
                let escaped = input
                    .get(offset + 1..offset + 4)
                    .ok_or("filesystem_mount_table_invalid")?;
                output.push(match escaped {
                    b"040" => b' ',
                    b"011" => b'\t',
                    b"012" => b'\n',
                    b"134" => b'\\',
                    _ => return Err("filesystem_mount_table_invalid"),
                });
                offset += 4;
            }
            b'\0' | b' ' | b'\t' | b'\n' => {
                return Err("filesystem_mount_table_invalid");
            }
            _ => {
                output.push(byte);
                offset += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|_| "filesystem_mount_table_invalid")
}

fn is_kernel_nsfs_root(filesystem_type: &str, root: &str) -> bool {
    if filesystem_type != "nsfs" {
        return false;
    }
    let Some((namespace, rest)) = root.split_once(":[") else {
        return false;
    };
    let Some(inode) = rest.strip_suffix(']') else {
        return false;
    };
    !namespace.is_empty()
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && !inode.is_empty()
        && inode.bytes().all(|byte| byte.is_ascii_digit())
}

/// Parse the complete kernel mount table. Unknown optional fields are ignored
/// as required by procfs; malformed required fields invalidate the whole view.
pub(crate) fn parse_mountinfo(bytes: &[u8]) -> Result<BTreeMap<u64, MountInfo>, &'static str> {
    if bytes.len() > MAX_MOUNTINFO_BYTES || bytes.last() != Some(&b'\n') {
        return Err("filesystem_mount_table_incomplete");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "filesystem_mount_table_invalid")?;
    let mut mounts = BTreeMap::new();
    for line in text[..text.len() - 1].split('\n') {
        let (before, after) = line
            .split_once(" - ")
            .ok_or("filesystem_mount_table_invalid")?;
        let before: Vec<_> = before.split(' ').collect();
        let after: Vec<_> = after.split(' ').collect();
        if before.len() < 6
            || after.len() != 3
            || before.iter().chain(&after).any(|field| {
                field.is_empty()
                    || field
                        .bytes()
                        .any(|byte| matches!(byte, b'\0' | b'\t' | b'\n'))
            })
        {
            return Err("filesystem_mount_table_invalid");
        }
        let id: u64 = unsigned(before[0])?;
        let parent: u64 = unsigned(before[1])?;
        if id == 0 || parent == 0 {
            return Err("filesystem_mount_table_invalid");
        }
        let (major, minor) = before[2]
            .split_once(':')
            .ok_or("filesystem_mount_table_invalid")?;
        let root = decode_mount_field(before[3])?;
        let mount_point = decode_mount_field(before[4])?;
        let filesystem_type = decode_mount_field(after[0])?;
        if !mount_point.starts_with('/')
            || (!root.starts_with('/') && !is_kernel_nsfs_root(&filesystem_type, &root))
        {
            return Err("filesystem_mount_table_invalid");
        }
        for options in [before[5], after[2]] {
            let mut fields = options.split(',');
            if !matches!(fields.next(), Some("rw" | "ro"))
                || fields.any(|field| field.is_empty() || matches!(field, "rw" | "ro"))
            {
                return Err("filesystem_mount_table_invalid");
            }
        }
        let record = MountInfo {
            id,
            device_major: unsigned(major)?,
            device_minor: unsigned(minor)?,
            root,
            mount_point,
            filesystem_type,
            source: decode_mount_field(after[1])?,
            mount_options: before[5].to_string(),
            super_options: after[2].to_string(),
        };
        if mounts.insert(id, record).is_some() {
            return Err("filesystem_mount_table_ambiguous");
        }
    }
    Ok(mounts)
}

fn parse_mount_id(bytes: &[u8]) -> Option<u64> {
    if bytes.last() != Some(&b'\n') {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let id: u64 = unsigned(ids.next()?.trim()).ok()?;
    (id != 0 && ids.next().is_none()).then_some(id)
}

/// Identify the filesystem of a held object without querying that filesystem.
pub(crate) fn mount_id(file: &File) -> Option<u64> {
    let path = PathBuf::from(format!("/proc/self/fdinfo/{}", file.as_raw_fd()));
    parse_mount_id(&read_bounded(&path, MAX_FDINFO_BYTES).ok()?)
}

/// Classify held paths through kernel procfs tables. Even fstatfs can invoke a
/// stalled FUSE/network server, so it must not be used as the safety probe.
pub(crate) struct FilesystemGuard {
    pub(crate) mounts: BTreeMap<u64, bool>,
}

impl FilesystemGuard {
    pub(crate) fn load() -> Result<Self, &'static str> {
        let bytes = read_bounded(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        Self::parse(&bytes)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        Ok(Self::from_mounts(&parse_mountinfo(bytes)?))
    }

    pub(crate) fn from_mounts(mounts: &BTreeMap<u64, MountInfo>) -> Self {
        Self {
            mounts: mounts
                .iter()
                .map(|(&id, mount)| {
                    let safe = matches!(
                        mount.filesystem_type.as_str(),
                        "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "tmpfs" | "overlay" | "zfs"
                    );
                    (id, safe)
                })
                .collect(),
        }
    }

    pub(crate) fn permits(&self, file: &File) -> bool {
        mount_id(file).is_some_and(|id| self.mounts.get(&id) == Some(&true))
    }

    /// Resolve existing directories one component at a time, rejecting
    /// symlinks and unknown/remote mounts before any subsequent lookup.
    /// Absolute paths belong to the collector's mount namespace: callers
    /// interpreting another process's path must establish that namespace first.
    pub(crate) fn resolve_directory(
        &self,
        base: &File,
        path: &Path,
        max_components: usize,
        deadline: Instant,
    ) -> Result<File, &'static str> {
        if path.as_os_str().is_empty() {
            return Err("directory_path_empty");
        }
        if Instant::now() >= deadline {
            return Err("directory_resolution_budget_exhausted");
        }
        let mut directory = if path.is_absolute() {
            open_directory(Path::new("/"))?
        } else {
            base.try_clone()
                .map_err(|_| "directory_identity_unavailable")?
        };
        if !self.permits(&directory) {
            return Err("directory_filesystem_unavailable");
        }
        for (count, component) in path.components().enumerate() {
            if count >= max_components || Instant::now() >= deadline {
                return Err("directory_resolution_budget_exhausted");
            }
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Prefix(_) => return Err("directory_path_invalid"),
                _ => {}
            }
            directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory_path(&directory, "").join(component.as_os_str()))
                .map_err(|_| "directory_identity_unavailable")?;
            if !self.permits(&directory) {
                return Err("directory_filesystem_unavailable");
            }
        }
        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::time::Duration;

    fn descriptor_fixture_task(process: &Path, tid: u32, birth: u64) -> PathBuf {
        let task = process.join("task").join(tid.to_string());
        std::fs::create_dir_all(task.join("fd")).unwrap();
        let mut fields = vec!["0".to_string(); 22];
        fields[0] = "S".to_string();
        fields[1] = "1".to_string();
        fields[17] = "2".to_string();
        fields[19] = birth.to_string();
        std::fs::write(
            task.join("stat"),
            format!("{tid} (worker) {}\n", fields.join(" ")),
        )
        .unwrap();
        task
    }

    fn descriptor_fixture_snapshot(
        process: &Path,
    ) -> Result<BTreeMap<u32, BTreeMap<u32, PathBuf>>, &'static str> {
        let held = open_directory(process).unwrap();
        task_descriptor_snapshot(
            &directory_path(&held, ""),
            42,
            Instant::now() + Duration::from_secs(5),
            16,
            1000,
        )
    }

    #[test]
    fn descriptor_snapshot_includes_private_thread_sockets_without_following_targets() {
        let process = tempfile::tempdir().unwrap().keep();
        let leader = descriptor_fixture_task(&process, 42, 100);
        let worker = descriptor_fixture_task(&process, 43, 101);
        symlink("/dev/null", leader.join("fd/0")).unwrap();
        symlink("socket:[501]", leader.join("fd/3")).unwrap();
        symlink("socket:[501]", worker.join("fd/3")).unwrap();
        symlink("socket:[900]", worker.join("fd/8")).unwrap();
        // A link to a missing or unhealthy mount must not be followed just to
        // establish that this is not the socket being attributed.
        symlink("/unavailable-fuse-mount/file", worker.join("fd/9")).unwrap();

        let tables = descriptor_fixture_snapshot(&process).unwrap();
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[&42].len(), 2);
        assert!(!tables[&42].contains_key(&8));
        assert_eq!(tables[&43][&8], Path::new("socket:[900]"));
        assert_eq!(tables[&43][&9], Path::new("/unavailable-fuse-mount/file"));
    }

    #[test]
    fn descriptor_snapshot_rejects_task_identity_and_descriptor_churn() {
        for mutation in [
            "new_task",
            "departed_task",
            "changed_birth",
            "replaced_task_directory",
            "new_fd",
            "closed_fd",
            "replaced_fd",
        ] {
            let process = tempfile::tempdir().unwrap().keep();
            descriptor_fixture_task(&process, 42, 100);
            let worker = descriptor_fixture_task(&process, 43, 101);
            symlink("socket:[900]", worker.join("fd/8")).unwrap();
            let held = open_directory(&process).unwrap();
            let observed = task_descriptor_snapshot_with(
                &directory_path(&held, ""),
                42,
                Instant::now() + Duration::from_secs(5),
                16,
                1000,
                || match mutation {
                    "new_task" => {
                        descriptor_fixture_task(&process, 44, 102);
                    }
                    "departed_task" => {
                        std::fs::rename(&worker, process.join("retained-worker")).unwrap();
                    }
                    "changed_birth" => {
                        descriptor_fixture_task(&process, 43, 999);
                    }
                    "replaced_task_directory" => {
                        std::fs::rename(&worker, process.join("retained-worker")).unwrap();
                        let replacement = descriptor_fixture_task(&process, 43, 101);
                        symlink("socket:[900]", replacement.join("fd/8")).unwrap();
                    }
                    "new_fd" => {
                        symlink("socket:[901]", worker.join("fd/9")).unwrap();
                    }
                    "closed_fd" => {
                        std::fs::rename(worker.join("fd/8"), process.join("retained-fd")).unwrap();
                    }
                    "replaced_fd" => {
                        std::fs::rename(worker.join("fd/8"), process.join("retained-fd")).unwrap();
                        symlink("socket:[901]", worker.join("fd/8")).unwrap();
                    }
                    _ => unreachable!(),
                },
            );
            assert!(observed.is_err(), "{mutation}: {observed:?}");
        }
    }

    #[test]
    fn descriptor_snapshot_rejects_missing_and_malformed_task_evidence() {
        for malformed in [
            "missing_task_table",
            "missing_leader",
            "missing_fd_table",
            "missing_stat",
            "invalid_stat",
            "wrong_stat_pid",
            "non_link_fd",
            "symlink_task",
        ] {
            let process = tempfile::tempdir().unwrap().keep();
            let leader = descriptor_fixture_task(&process, 42, 100);
            match malformed {
                "missing_task_table" => {
                    std::fs::rename(process.join("task"), process.join("retained-task-table"))
                        .unwrap();
                }
                "missing_leader" => {
                    std::fs::rename(&leader, process.join("retained-leader")).unwrap();
                    descriptor_fixture_task(&process, 43, 101);
                }
                "missing_fd_table" => {
                    let worker = descriptor_fixture_task(&process, 43, 101);
                    std::fs::rename(worker.join("fd"), process.join("retained-fds")).unwrap();
                }
                "missing_stat" => {
                    std::fs::rename(leader.join("stat"), process.join("retained-stat")).unwrap();
                }
                "invalid_stat" => {
                    std::fs::write(leader.join("stat"), "42 (worker) S 1\n").unwrap();
                }
                "wrong_stat_pid" => {
                    let other = descriptor_fixture_task(&process, 43, 101);
                    std::fs::copy(other.join("stat"), leader.join("stat")).unwrap();
                }
                "non_link_fd" => {
                    std::fs::write(leader.join("fd/0"), "socket:[900]").unwrap();
                }
                "symlink_task" => {
                    std::fs::rename(&leader, process.join("retained-leader")).unwrap();
                    symlink(process.join("retained-leader"), leader).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                descriptor_fixture_snapshot(&process).is_err(),
                "{malformed}"
            );
        }
        for name in ["+43", "043", "0", "-1", "2147483648", "worker"] {
            let process = tempfile::tempdir().unwrap().keep();
            descriptor_fixture_task(&process, 42, 100);
            std::fs::create_dir(process.join("task").join(name)).unwrap();
            assert!(
                descriptor_fixture_snapshot(&process).is_err(),
                "task {name}"
            );
        }
        for name in ["+8", "08", "-1", "2147483648", "socket"] {
            let process = tempfile::tempdir().unwrap().keep();
            let leader = descriptor_fixture_task(&process, 42, 100);
            symlink("socket:[900]", leader.join("fd").join(name)).unwrap();
            assert!(descriptor_fixture_snapshot(&process).is_err(), "fd {name}");
        }
    }

    #[test]
    fn descriptor_snapshot_shares_task_entry_and_time_budgets_across_passes() {
        let process = tempfile::tempdir().unwrap().keep();
        let leader = descriptor_fixture_task(&process, 42, 100);
        symlink("socket:[900]", leader.join("fd/0")).unwrap();
        let held = open_directory(&process).unwrap();
        let path = directory_path(&held, "");
        let deadline = Instant::now() + Duration::from_secs(5);
        // Both task enumerations and the FD walk consume the same budget in
        // each pass. A complete first pass does not reset that allowance.
        assert!(task_descriptor_snapshot(&path, 42, deadline, 1, 6).is_ok());
        assert_eq!(
            task_descriptor_snapshot(&path, 42, deadline, 1, 5),
            Err("task_descriptor_budget_exhausted")
        );
        assert_eq!(
            task_descriptor_snapshot(&path, 42, deadline, 0, 100),
            Err("task_descriptor_task_limit")
        );
        assert_eq!(
            task_descriptor_snapshot(&path, 42, Instant::now(), 1, 100),
            Err("task_descriptor_budget_exhausted")
        );
        for pid in [0, i32::MAX as u32 + 1] {
            assert_eq!(
                task_descriptor_snapshot(&path, pid, deadline, 1, 100),
                Err("task_descriptor_invalid_pid")
            );
        }
        descriptor_fixture_task(&process, 43, 101);
        assert_eq!(
            task_descriptor_snapshot(&path, 42, deadline, 1, 100),
            Err("task_descriptor_task_limit")
        );
    }

    #[test]
    fn mountinfo_decodes_paths_once_and_retains_bind_mount_identity() {
        let table = parse_mountinfo(b"36 35 8:2 /inner\\040path /mnt\\011tab\\134040 rw,nosuid shared:7 future:42 - ext4 /dev/mapper/a\\040b rw,errors=continue\n37 36 8:2 /inner\\040path /bind ro - ext4 /dev/mapper/a\\040b rw\n").unwrap();
        assert_eq!(table.len(), 2);
        let first = &table[&36];
        assert_eq!(first.id, 36);
        assert_eq!((first.device_major, first.device_minor), (8, 2));
        assert_eq!(first.root, "/inner path");
        assert_eq!(first.mount_point, "/mnt\ttab\\040");
        assert_eq!(first.filesystem_type, "ext4");
        assert_eq!(first.source, "/dev/mapper/a b");
        assert_eq!(first.mount_options, "rw,nosuid");
        assert_eq!(first.super_options, "rw,errors=continue");
        assert_eq!(table[&37].root, first.root);
        assert_ne!(table[&37].id, first.id);
    }

    #[test]
    fn mountinfo_retains_procfs_visibility_restrictions_in_super_options() {
        let table = parse_mountinfo(
            b"22 1 0:3 / /proc rw,nosuid,nodev,noexec - proc proc rw,hidepid=2,subset=pid\n",
        )
        .unwrap();
        let procfs = &table[&22];
        assert_eq!(procfs.filesystem_type, "proc");
        assert_eq!(procfs.mount_options, "rw,nosuid,nodev,noexec");
        assert_eq!(procfs.super_options, "rw,hidepid=2,subset=pid");
    }

    #[test]
    fn mountinfo_accepts_kernel_nsfs_namespace_roots() {
        let table = parse_mountinfo(
            b"470 31 0:5 net:[4026531833] /run/docker/netns/default rw shared:392 - nsfs nsfs rw\n",
        )
        .unwrap();
        let nsfs = &table[&470];
        assert_eq!(nsfs.filesystem_type, "nsfs");
        assert_eq!(nsfs.root, "net:[4026531833]");
        assert_eq!(nsfs.mount_point, "/run/docker/netns/default");
        assert!(parse_mountinfo(
            b"470 31 0:5 net:[4026531833] /run/docker/netns/default rw - tmpfs tmpfs rw\n",
        )
        .is_err());
    }

    #[test]
    fn mountinfo_rejects_incomplete_ambiguous_and_malformed_records() {
        for bad in [
            "",
            "\n",
            "10 1 0:1 / / rw - tmpfs none rw",
            "10 1 0:1 / / rw - tmpfs none rw\n\n",
            "+10 1 0:1 / / rw - tmpfs none rw\n",
            "0 1 0:1 / / rw - tmpfs none rw\n",
            "10 0 0:1 / / rw - tmpfs none rw\n",
            "10 parent 0:1 / / rw - tmpfs none rw\n",
            "18446744073709551616 1 0:1 / / rw - tmpfs none rw\n",
            "10 1 0:4294967296 / / rw - tmpfs none rw\n",
            "10 1 +1:2 / / rw - tmpfs none rw\n",
            "10 1 1:2:3 / / rw - tmpfs none rw\n",
            "10 1 0:1 relative / rw - tmpfs none rw\n",
            "10 1 0:1 / relative rw - tmpfs none rw\n",
            "10 1 0:1 / /bad\\041 rw - tmpfs none rw\n",
            "10 1 0:1 / /bad\\000 rw - tmpfs none rw\n",
            "10 1 0:1 / /bad\\ rw - tmpfs none rw\n",
            "10 1 0:1 / / rw,ro - tmpfs none rw\n",
            "10 1 0:1 / / rw, - tmpfs none rw\n",
            "10 1 0:1 / / rw - tmpfs none\n",
            "10 1 0:1 / / rw - tmpfs none rw trailing\n",
            "10 1 0:1 / / rw - tmpfs none rw\n10 1 0:2 / /other rw - ext4 /dev/a rw\n",
        ] {
            assert!(parse_mountinfo(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse_mountinfo(b"10 1 0:1 / /\xff rw - tmpfs none rw\n").is_err());
    }

    #[test]
    fn mount_id_requires_one_complete_unsigned_field() {
        assert_eq!(
            parse_mount_id(b"pos:\t0\nflags:\t0100000\nmnt_id:\t123\nino:\t4\n"),
            Some(123)
        );
        for bad in [
            "",
            "mnt_id: 123",
            "mnt_id: +123\n",
            "mnt_id: -1\n",
            "mnt_id: 0\n",
            "mnt_id: 1 trailing\n",
            "mnt_id: 1\nmnt_id: 1\n",
            "mnt_id: 18446744073709551616\n",
            "ino: 123\n",
        ] {
            assert_eq!(parse_mount_id(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn held_directory_resolution_rejects_symlinks_unknown_mounts_and_exhausted_budgets() {
        let temporary = tempfile::tempdir().unwrap().keep();
        std::fs::create_dir(temporary.join("child")).unwrap();
        std::fs::create_dir(temporary.join("child/nested")).unwrap();
        symlink("child", temporary.join("alias")).unwrap();
        let base = open_directory(&temporary).unwrap();
        let guard = FilesystemGuard::load().unwrap();
        assert!(guard.permits(&base));
        let deadline = Instant::now() + Duration::from_secs(5);
        let resolved = guard
            .resolve_directory(&base, Path::new("child/.."), 4, deadline)
            .unwrap();
        assert_eq!(
            resolved.metadata().unwrap().ino(),
            base.metadata().unwrap().ino()
        );
        assert!(guard
            .resolve_directory(&base, Path::new("alias"), 4, deadline)
            .is_err());
        assert!(guard
            .resolve_directory(&base, Path::new("alias/nested"), 4, deadline)
            .is_err());
        assert!(guard
            .resolve_directory(&base, Path::new("child/nested"), 1, deadline)
            .is_err());
        assert!(guard
            .resolve_directory(&base, Path::new("."), 0, deadline)
            .is_err());
        assert!(guard
            .resolve_directory(&base, Path::new("child"), 4, Instant::now())
            .is_err());
        assert!(guard
            .resolve_directory(&base, Path::new(""), 4, deadline)
            .is_err());
        assert!(FilesystemGuard {
            mounts: BTreeMap::new()
        }
        .resolve_directory(&base, Path::new("child"), 4, deadline)
        .is_err());
    }

    #[test]
    fn bounded_reads_reject_symlinks_and_oversize_fields() {
        let temporary = tempfile::tempdir().unwrap().keep();
        let file = temporary.join("field");
        std::fs::write(&file, b"abc").unwrap();
        symlink("field", temporary.join("alias")).unwrap();
        assert_eq!(read_bounded(&file, 3).unwrap(), b"abc");
        assert_eq!(read_bounded(&file, 2), Err("process_field_size_limit"));
        assert!(read_bounded(&temporary.join("alias"), 3).is_err());
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            read_bounded(&file, usize::MAX),
            Err("process_field_size_limit")
        );
    }
}
