//! Bounded procfs reads and conservative traversal of held local directories.
//!
//! Filesystem classification comes from procfs mount IDs, before following a
//! directory component. A metadata query against an unknown FUSE or network
//! filesystem would itself be an unsafe way to decide whether it can be read.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
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
        if !root.starts_with('/') || !mount_point.starts_with('/') {
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
            filesystem_type: decode_mount_field(after[0])?,
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
