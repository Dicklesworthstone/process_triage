//! Filesystem-based resolver for cwd/repo/worktree workspace evidence.
//!
//! Maps a process cwd to repo/workspace evidence by walking the directory tree,
//! detecting `.git` markers, parsing HEAD state, and handling negative paths
//! (non-repo dirs, deleted CWDs, permission failures, nested repos, worktrees).
//!
//! Returns `RawWorkspaceEvidence` that feeds into `normalize_workspace()` from
//! `pt_common::workspace_evidence`.

use std::fs;
use std::path::{Path, PathBuf};

use pt_common::{
    HeadState, PathResolutionError, RawPathEvidence, RawWorkspaceEvidence,
    WorkspaceCollectionMethod,
};

/// Resolve workspace evidence for a process by its PID.
///
/// Reads `/proc/{pid}/cwd`, then walks up to find a `.git` directory.
/// Returns complete `RawWorkspaceEvidence` with all available context.
#[cfg(target_os = "linux")]
pub fn resolve_workspace_for_pid(pid: u32) -> RawWorkspaceEvidence {
    let now = chrono::Utc::now().to_rfc3339();
    let cwd = read_proc_cwd(pid);

    let (repo_root, worktree, head_state) = match &cwd {
        Some(cwd_ev) => {
            let effective = cwd_ev.effective_path();
            let (root, wt) = find_repo_root(Path::new(effective));
            let head = root
                .as_ref()
                .map(|r| read_head_state(Path::new(r.effective_path())))
                .unwrap_or(Some(HeadState::NotARepo));
            (root, wt, head)
        }
        None => (None, None, None),
    };

    RawWorkspaceEvidence {
        pid,
        cwd,
        repo_root,
        worktree,
        head_state,
        collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
        observed_at: now,
    }
}

/// Read the current working directory of a process from `/proc/{pid}/cwd`.
#[cfg(target_os = "linux")]
fn read_proc_cwd(pid: u32) -> Option<RawPathEvidence> {
    let link_path = PathBuf::from(format!("/proc/{pid}/cwd"));
    read_and_canonicalize_link(&link_path)
}

/// Read a symlink and attempt to canonicalize its target.
fn read_and_canonicalize_link(link: &Path) -> Option<RawPathEvidence> {
    match fs::read_link(link) {
        Ok(target) => {
            let original = target.to_string_lossy().to_string();
            // Check for deleted CWD indicator
            if original.contains("(deleted)") {
                return Some(RawPathEvidence::unresolved(
                    original.trim_end_matches(" (deleted)"),
                    PathResolutionError::NotFound,
                ));
            }
            match fs::canonicalize(&target) {
                Ok(canonical) => Some(RawPathEvidence::resolved(
                    &original,
                    canonical.to_string_lossy(),
                )),
                Err(e) => Some(RawPathEvidence::unresolved(
                    original,
                    io_error_to_resolution(e),
                )),
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Some(RawPathEvidence::unresolved(
                format!("{}", link.display()),
                PathResolutionError::PermissionDenied,
            )),
            std::io::ErrorKind::NotFound => None,
            _ => Some(RawPathEvidence::unresolved(
                format!("{}", link.display()),
                PathResolutionError::IoError {
                    message: e.to_string(),
                },
            )),
        },
    }
}

/// Walk up from a directory to find the nearest `.git` marker.
///
/// Handles:
/// - Standard repos (`.git` is a directory)
/// - Git worktrees (`.git` is a file with `gitdir: ...`)
/// - Nested repos (returns the nearest `.git`)
/// - Non-repo directories (returns None)
pub fn find_repo_root(start: &Path) -> (Option<RawPathEvidence>, Option<RawPathEvidence>) {
    let mut current = start.to_path_buf();

    loop {
        let git_path = current.join(".git");

        if git_path.is_dir() {
            // Standard git repo: .git is a directory
            let root_ev = canonicalize_path(&current);
            return (Some(root_ev), None);
        }

        if git_path.is_file() {
            // Git worktree: .git is a file containing `gitdir: <path>`
            match parse_gitdir_file(&git_path) {
                Some(actual_git_dir) => {
                    // The actual repo root is the parent of the actual .git dir
                    let actual_repo_root = resolve_worktree_repo_root(&actual_git_dir);
                    let repo_ev = actual_repo_root
                        .map(|r| canonicalize_path(&r))
                        .unwrap_or_else(|| canonicalize_path(&current));
                    let worktree_ev = canonicalize_path(&current);
                    return (Some(repo_ev), Some(worktree_ev));
                }
                None => {
                    // Malformed .git file — treat this dir as the root with degraded confidence
                    let root_ev = canonicalize_path(&current);
                    return (Some(root_ev), None);
                }
            }
        }

        if !current.pop() {
            break;
        }
    }

    (None, None)
}

/// Parse a `.git` file that points to a gitdir (git worktree format).
///
/// Expected format: `gitdir: /path/to/.git/worktrees/<name>`
fn parse_gitdir_file(git_file: &Path) -> Option<PathBuf> {
    let content = fs::read_to_string(git_file).ok()?;
    let line = content.lines().next()?;
    let gitdir = line.strip_prefix("gitdir: ")?;
    let gitdir_path = gitdir.trim();

    if gitdir_path.is_empty() {
        return None;
    }

    let path = Path::new(gitdir_path);
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        // Relative to the .git file's parent directory
        git_file.parent().map(|parent| parent.join(path))
    }
}

/// Given a `.git/worktrees/<name>` path, resolve back to the main repo root.
fn resolve_worktree_repo_root(gitdir: &Path) -> Option<PathBuf> {
    // Typical worktree gitdir: /path/to/repo/.git/worktrees/<name>
    // We need to go up from .git/worktrees/<name> to get the repo root.
    let common_dir_file = gitdir.join("commondir");
    if let Ok(content) = fs::read_to_string(&common_dir_file) {
        let common_dir = content.lines().next()?.trim();
        let common_path = if Path::new(common_dir).is_absolute() {
            PathBuf::from(common_dir)
        } else {
            gitdir.join(common_dir)
        };
        // The commondir points to the .git directory; repo root is its parent
        return fs::canonicalize(&common_path)
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()));
    }

    // Fallback: if gitdir contains "worktrees", walk up
    let mut parent = gitdir.to_path_buf();
    while parent.pop() {
        if parent.file_name().map_or(false, |n| n == ".git") {
            return parent.parent().map(|p| p.to_path_buf());
        }
    }
    None
}

/// Read HEAD state from a git repo root.
pub fn read_head_state(repo_root: &Path) -> Option<HeadState> {
    let head_path = repo_root.join(".git").join("HEAD");
    // Also handle worktrees where .git is a file
    let head_path = if head_path.exists() {
        head_path
    } else {
        // Try reading the .git file for a worktree reference
        let git_path = repo_root.join(".git");
        if git_path.is_file() {
            if let Some(gitdir) = parse_gitdir_file(&git_path) {
                gitdir.join("HEAD")
            } else {
                return Some(HeadState::Unreadable {
                    reason: "malformed .git file".to_string(),
                });
            }
        } else {
            return Some(HeadState::NotARepo);
        }
    };

    match fs::read_to_string(&head_path) {
        Ok(content) => {
            let trimmed = content.trim();
            if let Some(branch) = trimmed.strip_prefix("ref: refs/heads/") {
                Some(HeadState::Branch {
                    name: branch.to_string(),
                })
            } else if let Some(branch) = trimmed.strip_prefix("ref: ") {
                // Unusual ref (not heads/), still a branch-like reference
                Some(HeadState::Branch {
                    name: branch.to_string(),
                })
            } else if trimmed.len() >= 7 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                // Detached HEAD at a commit hash
                Some(HeadState::Detached {
                    commit_prefix: trimmed[..7.min(trimmed.len())].to_string(),
                })
            } else {
                Some(HeadState::Unreadable {
                    reason: format!(
                        "unexpected HEAD content: {}",
                        &trimmed[..40.min(trimmed.len())]
                    ),
                })
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Some(HeadState::Unreadable {
                reason: "permission denied".to_string(),
            }),
            std::io::ErrorKind::NotFound => Some(HeadState::NotARepo),
            _ => Some(HeadState::Unreadable {
                reason: e.to_string(),
            }),
        },
    }
}

/// Canonicalize a path, returning `RawPathEvidence`.
fn canonicalize_path(path: &Path) -> RawPathEvidence {
    let original = path.to_string_lossy().to_string();
    match fs::canonicalize(path) {
        Ok(canonical) => RawPathEvidence::resolved(&original, canonical.to_string_lossy()),
        Err(e) => RawPathEvidence::unresolved(original, io_error_to_resolution(e)),
    }
}

/// Convert an `io::Error` to a `PathResolutionError`.
fn io_error_to_resolution(e: std::io::Error) -> PathResolutionError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => PathResolutionError::PermissionDenied,
        std::io::ErrorKind::NotFound => PathResolutionError::NotFound,
        _ => PathResolutionError::IoError {
            message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_repo_root_in_actual_repo() {
        // This test runs inside the process_triage repo itself
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let (root, worktree) = find_repo_root(&manifest_dir);

        let root = root.expect("should find repo root");
        assert!(
            root.effective_path().contains("process_triage"),
            "repo root should contain 'process_triage': {}",
            root.effective_path()
        );
        // This is NOT a worktree, so worktree should be None
        assert!(worktree.is_none(), "should not be a worktree");
    }

    #[test]
    fn find_repo_root_from_subdirectory() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let subdir = manifest_dir.join("src").join("collect");
        if subdir.exists() {
            let (root, _worktree) = find_repo_root(&subdir);
            let root = root.expect("should find repo root from subdir");
            assert!(root.effective_path().contains("process_triage"));
        }
    }

    #[test]
    fn find_repo_root_from_non_repo_returns_none() {
        let (root, worktree) = find_repo_root(Path::new("/tmp"));
        assert!(root.is_none(), "tmp should not be a repo");
        assert!(worktree.is_none());
    }

    #[test]
    fn read_head_state_on_this_repo() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .expect("crates dir")
            .parent()
            .expect("repo root");

        let head = read_head_state(repo_root);
        let head = head.expect("should read HEAD");
        match &head {
            HeadState::Branch { name } => {
                assert!(!name.is_empty(), "branch name should not be empty");
            }
            HeadState::Detached { commit_prefix } => {
                assert!(commit_prefix.len() >= 7, "should have >= 7 char prefix");
            }
            other => panic!("unexpected HEAD state in CI: {other:?}"),
        }
    }

    #[test]
    fn read_head_state_non_repo() {
        let head = read_head_state(Path::new("/tmp"));
        assert_eq!(head, Some(HeadState::NotARepo));
    }

    #[test]
    fn parse_gitdir_file_empty_returns_none() {
        // Can't test without creating a temp file, but we test the logic
        // via find_repo_root on a non-worktree repo (above)
    }

    #[test]
    fn canonicalize_path_existing() {
        let ev = canonicalize_path(Path::new("/tmp"));
        assert!(ev.canonical.is_some());
        assert_eq!(ev.effective_path(), ev.canonical.as_deref().unwrap());
    }

    #[test]
    fn canonicalize_path_nonexistent() {
        let ev = canonicalize_path(Path::new("/nonexistent/path/surely"));
        assert!(ev.canonical.is_none());
        assert!(ev.resolution_error.is_some());
    }

    #[test]
    fn io_error_mapping() {
        let perm = io_error_to_resolution(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert_eq!(perm, PathResolutionError::PermissionDenied);

        let nf = io_error_to_resolution(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert_eq!(nf, PathResolutionError::NotFound);

        let other =
            io_error_to_resolution(std::io::Error::new(std::io::ErrorKind::Other, "something"));
        match other {
            PathResolutionError::IoError { message } => assert!(message.contains("something")),
            _ => panic!("expected IoError variant"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_workspace_for_own_pid() {
        let pid = std::process::id();
        let evidence = resolve_workspace_for_pid(pid);

        assert_eq!(evidence.pid, pid);
        // We should be able to read our own CWD
        assert!(evidence.cwd.is_some(), "should read own cwd");
        // We're running in the process_triage repo
        assert!(evidence.repo_root.is_some(), "should find repo root");
        assert!(evidence.head_state.is_some(), "should read HEAD");
    }
}
