//! File-backed resource provenance collection for lockfiles, pidfiles, and
//! other local coordination markers.
//!
//! This collector converts `/proc/[pid]/fd` observations into canonical
//! `RawResourceEvidence` records so later provenance, blast-radius, and
//! explainability layers can reason about shared file-backed coordination
//! surfaces without re-scanning the filesystem.

use super::proc_parsers::{CriticalFile, CriticalFileCategory, FdInfo, OpenFile};
use pt_common::{
    LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails, ResourceKind,
    ResourceState,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Collect file-backed shared-resource evidence from parsed file descriptors.
pub fn collect_local_resource_evidence(
    owner_pid: u32,
    fd_info: Option<&FdInfo>,
) -> Vec<RawResourceEvidence> {
    let Some(fd_info) = fd_info else {
        return Vec::new();
    };

    let observed_at = chrono::Utc::now().to_rfc3339();
    let critical_by_path: HashMap<&str, &CriticalFile> = fd_info
        .critical_writes
        .iter()
        .map(|critical| (critical.path.as_str(), critical))
        .collect();
    let mut evidence_by_key = HashMap::new();

    for open_file in &fd_info.open_files {
        let Some(raw) = open_file_to_resource(
            owner_pid,
            open_file,
            critical_by_path.get(open_file.path.as_str()).copied(),
            &observed_at,
        ) else {
            continue;
        };

        let dedupe_key = format!("{:?}:{}", raw.kind, raw.key);
        evidence_by_key.entry(dedupe_key).or_insert(raw);
    }

    let mut evidence: Vec<_> = evidence_by_key.into_values().collect();
    evidence.sort_by(|left, right| left.key.cmp(&right.key));
    evidence
}

fn open_file_to_resource(
    owner_pid: u32,
    open_file: &OpenFile,
    critical: Option<&CriticalFile>,
    observed_at: &str,
) -> Option<RawResourceEvidence> {
    if !looks_like_regular_path(&open_file.path) {
        return None;
    }

    if is_pidfile_path(&open_file.path) {
        return Some(build_pidfile_evidence(
            owner_pid,
            open_file,
            observed_at,
            critical,
        ));
    }

    if is_coordination_marker(&open_file.path, critical) {
        return Some(build_lockfile_evidence(
            owner_pid,
            open_file,
            observed_at,
            critical,
        ));
    }

    None
}

fn build_pidfile_evidence(
    owner_pid: u32,
    open_file: &OpenFile,
    observed_at: &str,
    critical: Option<&CriticalFile>,
) -> RawResourceEvidence {
    let recorded_pid = read_pidfile_pid(&open_file.path);
    let path_exists = Path::new(&open_file.path).exists();
    let state = match recorded_pid {
        Some(recorded) if recorded == owner_pid => ResourceState::Active,
        Some(_) => ResourceState::Conflicted,
        None if !path_exists => ResourceState::Stale,
        None if open_file.mode.write || critical.is_some() => ResourceState::Partial,
        None => ResourceState::Partial,
    };

    RawResourceEvidence {
        kind: ResourceKind::Pidfile,
        key: open_file.path.clone(),
        owner_pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state,
        details: ResourceDetails::Pidfile {
            path: open_file.path.clone(),
            recorded_pid,
        },
        observed_at: observed_at.to_string(),
    }
}

fn build_lockfile_evidence(
    owner_pid: u32,
    open_file: &OpenFile,
    observed_at: &str,
    critical: Option<&CriticalFile>,
) -> RawResourceEvidence {
    let path_exists = Path::new(&open_file.path).exists();
    let state = if open_file.mode.write || critical.is_some() {
        ResourceState::Active
    } else if !path_exists {
        ResourceState::Stale
    } else {
        ResourceState::Partial
    };

    RawResourceEvidence {
        kind: ResourceKind::Lockfile,
        key: open_file.path.clone(),
        owner_pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state,
        details: ResourceDetails::Lockfile {
            path: open_file.path.clone(),
            mechanism: infer_lock_mechanism(&open_file.path, critical),
        },
        observed_at: observed_at.to_string(),
    }
}

fn infer_lock_mechanism(path: &str, critical: Option<&CriticalFile>) -> LockMechanism {
    if path.ends_with(".lock")
        || path.ends_with(".lck")
        || path.contains("/lock/")
        || matches!(
            critical.map(|entry| entry.category),
            Some(
                CriticalFileCategory::GitLock
                    | CriticalFileCategory::GitRebase
                    | CriticalFileCategory::SystemPackageLock
                    | CriticalFileCategory::NodePackageLock
                    | CriticalFileCategory::CargoLock
                    | CriticalFileCategory::SqliteWal
                    | CriticalFileCategory::AppLock
            )
        )
    {
        LockMechanism::Existence
    } else {
        LockMechanism::Unknown
    }
}

fn looks_like_regular_path(path: &str) -> bool {
    path.starts_with('/')
}

fn is_pidfile_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let basename = lower
        .rsplit('/')
        .next()
        .unwrap_or(lower.as_str())
        .trim_matches('.');
    lower.ends_with(".pid")
        || lower.ends_with(".pidfile")
        || basename == "pid"
        || basename == "pidfile"
        || lower.contains("/run/")
            && (basename.ends_with(".pid") || basename == "pidfile" || basename == "pid")
        || lower.contains("/var/run/")
            && (basename.ends_with(".pid") || basename == "pidfile" || basename == "pid")
}

fn is_coordination_marker(path: &str, critical: Option<&CriticalFile>) -> bool {
    if matches!(
        critical.map(|entry| entry.category),
        Some(
            CriticalFileCategory::SqliteWal
                | CriticalFileCategory::GitLock
                | CriticalFileCategory::GitRebase
                | CriticalFileCategory::SystemPackageLock
                | CriticalFileCategory::NodePackageLock
                | CriticalFileCategory::CargoLock
                | CriticalFileCategory::AppLock
        )
    ) {
        return true;
    }

    path.ends_with(".lock")
        || path.ends_with(".lck")
        || path.contains("/lock/")
        || path.contains("/rebase-merge/")
        || path.contains("/rebase-apply/")
        || path.ends_with("/MERGE_HEAD")
        || path.ends_with("/CHERRY_PICK_HEAD")
        || path.ends_with("/REVERT_HEAD")
        || path.ends_with("/BISECT_LOG")
        || path.contains("node_modules/.staging/")
        || path.contains(".package-cache-lock")
}

fn read_pidfile_pid(path: &str) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().next()?.trim();
    first_line.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::proc_parsers::{FdType, OpenMode};
    use tempfile::tempdir;

    fn open_file(path: String, write: bool) -> OpenFile {
        OpenFile {
            fd: 3,
            path,
            fd_type: FdType::File,
            mode: OpenMode { read: true, write },
        }
    }

    #[test]
    fn collects_active_lockfile_from_critical_write() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("coordination.lock");
        fs::write(&path, "held").expect("write lock");
        let path = path.to_string_lossy().to_string();

        let fd_info = FdInfo {
            open_files: vec![open_file(path.clone(), true)],
            critical_writes: vec![CriticalFile {
                fd: 3,
                path: path.clone(),
                category: CriticalFileCategory::AppLock,
                strength: crate::collect::proc_parsers::DetectionStrength::Soft,
                rule_id: "generic_lock_file".to_string(),
            }],
            ..FdInfo::default()
        };

        let evidence = collect_local_resource_evidence(4242, Some(&fd_info));
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, ResourceKind::Lockfile);
        assert_eq!(evidence[0].owner_pid, 4242);
        assert_eq!(evidence[0].state, ResourceState::Active);
    }

    #[test]
    fn collects_pidfile_with_matching_pid_as_active() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("service.pid");
        fs::write(&path, "4242\n").expect("write pid");

        let fd_info = FdInfo {
            open_files: vec![open_file(path.to_string_lossy().to_string(), true)],
            ..FdInfo::default()
        };

        let evidence = collect_local_resource_evidence(4242, Some(&fd_info));
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, ResourceKind::Pidfile);
        assert_eq!(evidence[0].state, ResourceState::Active);
        match &evidence[0].details {
            ResourceDetails::Pidfile { recorded_pid, .. } => {
                assert_eq!(*recorded_pid, Some(4242));
            }
            other => panic!("unexpected details: {other:?}"),
        }
    }

    #[test]
    fn collects_pidfile_with_mismatched_pid_as_conflicted() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("service.pid");
        fs::write(&path, "9999\n").expect("write pid");

        let fd_info = FdInfo {
            open_files: vec![open_file(path.to_string_lossy().to_string(), true)],
            ..FdInfo::default()
        };

        let evidence = collect_local_resource_evidence(4242, Some(&fd_info));
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].state, ResourceState::Conflicted);
    }

    #[test]
    fn marks_missing_lockfile_as_stale() {
        let path = "/tmp/process-triage-missing.lock".to_string();
        let fd_info = FdInfo {
            open_files: vec![open_file(path, false)],
            ..FdInfo::default()
        };

        let evidence = collect_local_resource_evidence(4242, Some(&fd_info));
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, ResourceKind::Lockfile);
        assert_eq!(evidence[0].state, ResourceState::Stale);
    }

    #[test]
    fn ignores_non_coordination_files() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("notes.txt");
        fs::write(&path, "hello").expect("write file");

        let fd_info = FdInfo {
            open_files: vec![open_file(path.to_string_lossy().to_string(), true)],
            ..FdInfo::default()
        };

        let evidence = collect_local_resource_evidence(4242, Some(&fd_info));
        assert!(evidence.is_empty());
    }
}
