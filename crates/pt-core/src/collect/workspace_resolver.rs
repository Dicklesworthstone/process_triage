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

use pt_common::{HeadState, PathResolutionError, RawPathEvidence};
#[cfg(target_os = "linux")]
use pt_common::{RawWorkspaceEvidence, WorkspaceCollectionMethod};

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
#[cfg(target_os = "linux")]
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
        if parent.file_name().is_some_and(|n| n == ".git") {
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
                        trimmed.chars().take(40).collect::<String>()
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

    fn retained_test_dir(label: &str) -> PathBuf {
        let checkout_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate belongs to the source workspace")
            .canonicalize()
            .expect("source workspace exists");
        // Build runners may set TMPDIR inside the checkout. Prefer the OS
        // temporary directory only when it cannot inherit repository evidence.
        let scratch_root = [std::env::temp_dir(), PathBuf::from("/tmp")]
            .into_iter()
            .filter_map(|path| path.canonicalize().ok())
            .find(|path| {
                let (root, worktree) = find_repo_root(path);
                !path.starts_with(&checkout_root) && root.is_none() && worktree.is_none()
            })
            .expect("existing OS scratch directory outside the checkout and any repository");
        let dir = scratch_root.join(format!(
            "pt-workspace-resolver-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&dir).expect("create unique retained workspace fixture");
        // Keep non-repo controls outside the source checkout. No fixture may
        // accidentally inherit an unrelated ancestor's .git marker.
        let (root, worktree) = find_repo_root(&dir);
        assert!(
            root.is_none(),
            "scratch directory has a repository ancestor: {root:?}"
        );
        assert!(worktree.is_none());
        dir
    }

    struct GitFixture {
        root: PathBuf,
        subdir: PathBuf,
        non_repo: PathBuf,
        commit: String,
    }

    impl GitFixture {
        fn new(label: &str) -> Self {
            let dir = retained_test_dir(label);
            let root = dir.join("process_triage");
            let subdir = root.join("crates/pt-core/src/collect");
            let non_repo = dir.join("not-a-repo");
            fs::create_dir_all(&subdir).unwrap();
            fs::create_dir(&non_repo).unwrap();
            fs::write(
                root.join("fixture.txt"),
                "owned workspace resolver Git fixture\n",
            )
            .unwrap();
            let mut fixture = Self {
                root,
                subdir,
                non_repo,
                commit: String::new(),
            };
            fixture.git(&["init", "--initial-branch=main"]);
            fixture.git(&["add", "--", "fixture.txt"]);
            fixture.git(&["commit", "-m", "Create owned workspace resolver fixture"]);
            fixture.commit = fixture.git(&["rev-parse", "--verify", "HEAD"]);
            assert!(fixture.commit.len() >= 40);
            assert!(fixture
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()));
            assert_eq!(fixture.git(&["symbolic-ref", "--short", "HEAD"]), "main");
            fixture
        }

        fn git(&self, args: &[&str]) -> String {
            use std::io::Write;
            use std::process::{Command, Stdio};

            let output = Command::new("git")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .env_remove("GIT_COMMON_DIR")
                .env_remove("GIT_CONFIG_COUNT")
                .env_remove("GIT_CONFIG_PARAMETERS")
                .env_remove("GIT_TEMPLATE_DIR")
                .args([
                    "-c",
                    "user.name=Workspace Resolver Fixture",
                    "-c",
                    "user.email=workspace-resolver@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .stdin(Stdio::null())
                .stderr(Stdio::inherit())
                .output()
                .expect("execute real Git on the owned fixture");
            let mut log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.root.parent().unwrap().join("git-commands.log"))
                .unwrap();
            writeln!(log, "git {args:?}: {}", output.status).unwrap();
            log.write_all(&output.stdout).unwrap();
            log.flush().unwrap();
            assert!(
                output.status.success(),
                "Git fixture command {args:?} failed: {}",
                output.status
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        }
    }

    #[cfg(target_os = "linux")]
    struct OwnedCwdChild {
        child: std::process::Child,
        pidfd: std::os::fd::OwnedFd,
    }

    #[cfg(target_os = "linux")]
    impl OwnedCwdChild {
        fn spawn(cwd: &Path) -> Self {
            use std::os::fd::FromRawFd;
            use std::process::{Command, Stdio};

            let mut child = Command::new("sleep")
                .arg("60")
                .current_dir(cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn owned child with actual fixture cwd");
            // SAFETY: an unreaped owned Child's PID cannot be reused while we
            // bind its descriptor; cleanup never signals an unrelated process.
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("bind owned cwd child: {error}");
            }
            Self {
                child,
                // SAFETY: pidfd_open returned a descriptor transferred once.
                pidfd: unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor as i32) },
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for OwnedCwdChild {
        fn drop(&mut self) {
            use std::os::fd::AsRawFd;

            // SAFETY: the descriptor pins only the original owned child.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            let _ = self.child.wait();
        }
    }

    #[test]
    fn find_repo_root_in_actual_repo() {
        // A source archive may omit .git. Exercise a real initialized and
        // committed repository rather than assuming checkout metadata shipped.
        let fixture = GitFixture::new("repo-root");
        let (root, worktree) = find_repo_root(&fixture.root);
        let root = root.expect("should find the actual fixture repository root");
        let expected = fs::canonicalize(&fixture.root).unwrap();
        assert_eq!(root.effective_path(), expected.to_str().unwrap());
        assert_eq!(root.original, fixture.root.to_str().unwrap());
        assert!(root.resolution_error.is_none());
        assert!(worktree.is_none(), "should not be a worktree");
    }

    #[test]
    fn find_repo_root_from_subdirectory() {
        let fixture = GitFixture::new("subdirectory");
        assert!(fixture.subdir.is_dir());
        assert_ne!(fixture.subdir, fixture.root);
        let (root, worktree) = find_repo_root(&fixture.subdir);
        let root = root.expect("should find repo root from the actual nested subdirectory");
        assert_eq!(
            root.effective_path(),
            fs::canonicalize(&fixture.root).unwrap().to_str().unwrap()
        );
        assert!(root.resolution_error.is_none());
        assert!(worktree.is_none());
    }

    #[test]
    fn find_repo_root_from_non_repo_returns_none() {
        let dir = retained_test_dir("non-repo-root");
        let subdir = dir.join("nested/directory");
        fs::create_dir_all(&subdir).unwrap();
        let (root, worktree) = find_repo_root(&subdir);
        assert!(
            root.is_none(),
            "owned directory without .git must not be a repo"
        );
        assert!(worktree.is_none());
    }

    #[test]
    fn read_head_state_on_this_repo() {
        let fixture = GitFixture::new("head-state");
        let branch = Some(HeadState::Branch {
            name: "main".to_string(),
        });
        assert_eq!(read_head_state(&fixture.root), branch);
        fixture.git(&["checkout", "--detach", &fixture.commit]);
        assert_eq!(
            fixture.git(&["rev-parse", "--verify", "HEAD"]),
            fixture.commit
        );
        assert_eq!(
            read_head_state(&fixture.root),
            Some(HeadState::Detached {
                commit_prefix: fixture.commit[..7].to_string()
            })
        );
        fixture.git(&["checkout", "main"]);
        assert_eq!(read_head_state(&fixture.root), branch);
    }

    #[test]
    fn read_head_state_non_repo() {
        let dir = retained_test_dir("non-repo-head");
        let head = read_head_state(&dir);
        assert_eq!(head, Some(HeadState::NotARepo));
    }

    #[test]
    fn read_head_state_malformed_utf8_boundaries_are_unreadable() {
        let cases = [
            (
                "unicode-byte-39",
                "€".repeat(13).into_bytes(),
                Some("€".repeat(13)),
            ),
            (
                "unicode-byte-42",
                "€".repeat(14).into_bytes(),
                Some("€".repeat(14)),
            ),
            (
                "unicode-byte-40",
                format!("{}€", "x".repeat(39)).into_bytes(),
                Some(format!("{}€", "x".repeat(39))),
            ),
            (
                "unicode-character-limit",
                "€".repeat(41).into_bytes(),
                Some("€".repeat(40)),
            ),
            ("invalid-utf8", vec![0xe2, 0x82], None),
        ];
        for (label, contents, expected_prefix) in cases {
            let fixture = GitFixture::new(label);
            assert_eq!(
                read_head_state(&fixture.root),
                Some(HeadState::Branch {
                    name: "main".to_string()
                })
            );
            // Corrupt only the retained owned repository's actual HEAD. The
            // Two 42-byte payloads put byte 40 inside a UTF-8 character;
            // the 39-byte payload also exercises the untruncated case.
            fs::write(fixture.root.join(".git/HEAD"), contents).unwrap();
            let head = read_head_state(&fixture.root);
            let Some(HeadState::Unreadable { reason }) = head else {
                panic!("malformed HEAD must return typed Unreadable: {head:?}");
            };
            match expected_prefix {
                Some(prefix) => assert_eq!(reason, format!("unexpected HEAD content: {prefix}")),
                None => {
                    assert!(!reason.is_empty());
                    assert!(
                        reason.contains("UTF-8"),
                        "invalid bytes must report an encoding error: {reason}"
                    );
                }
            }
            let (root, worktree) = find_repo_root(&fixture.subdir);
            assert_eq!(
                root.unwrap().effective_path(),
                fs::canonicalize(&fixture.root).unwrap().to_str().unwrap()
            );
            assert!(worktree.is_none());
        }
    }

    #[test]
    fn parse_gitdir_file_empty_returns_none() {
        let dir = retained_test_dir("empty-gitdir");
        let git_file = dir.join(".git");
        fs::write(&git_file, b"").unwrap();
        assert_eq!(parse_gitdir_file(&git_file), None);
        assert_eq!(
            read_head_state(&dir),
            Some(HeadState::Unreadable {
                reason: "malformed .git file".to_string()
            })
        );
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

        let other = io_error_to_resolution(std::io::Error::other("something"));
        match other {
            PathResolutionError::IoError { message } => assert!(message.contains("something")),
            _ => panic!("expected IoError variant"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_workspace_for_owned_child_pid() {
        let fixture = GitFixture::new("process-cwd");
        let original_cwd = std::env::current_dir().unwrap();
        let mut child = OwnedCwdChild::spawn(&fixture.subdir);
        let pid = child.child.id();
        assert!(child.child.try_wait().unwrap().is_none());
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let actual_cwd = fs::read_link(format!("/proc/{pid}/cwd")).unwrap();
        let expected_cwd = fs::canonicalize(&fixture.subdir).unwrap();
        assert_eq!(actual_cwd, expected_cwd);
        let evidence = resolve_workspace_for_pid(pid);

        assert_eq!(evidence.pid, pid);
        assert_eq!(
            evidence.collection_method,
            WorkspaceCollectionMethod::ProcfsCwdWalk
        );
        let cwd = evidence.cwd.as_ref().expect("read actual owned child cwd");
        assert_eq!(cwd.effective_path(), expected_cwd.to_str().unwrap());
        assert!(cwd.resolution_error.is_none());
        let root = evidence
            .repo_root
            .as_ref()
            .expect("find actual committed Git root");
        assert_eq!(
            root.effective_path(),
            fs::canonicalize(&fixture.root).unwrap().to_str().unwrap()
        );
        assert!(root.resolution_error.is_none());
        assert!(evidence.worktree.is_none());
        assert_eq!(
            evidence.head_state,
            Some(HeadState::Branch {
                name: "main".to_string()
            })
        );
        chrono::DateTime::parse_from_rfc3339(&evidence.observed_at).unwrap();

        let mut non_repo_child = OwnedCwdChild::spawn(&fixture.non_repo);
        let non_repo_pid = non_repo_child.child.id();
        assert_ne!(pid, non_repo_pid);
        assert!(non_repo_child.child.try_wait().unwrap().is_none());
        let non_repo_stat = fs::read_to_string(format!("/proc/{non_repo_pid}/stat")).unwrap();
        let non_repo_evidence = resolve_workspace_for_pid(non_repo_pid);
        assert_eq!(non_repo_evidence.pid, non_repo_pid);
        assert_eq!(
            non_repo_evidence.collection_method,
            WorkspaceCollectionMethod::ProcfsCwdWalk
        );
        let non_repo_cwd = non_repo_evidence.cwd.as_ref().unwrap();
        assert_eq!(
            non_repo_cwd.effective_path(),
            fs::canonicalize(&fixture.non_repo)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert!(non_repo_cwd.resolution_error.is_none());
        assert!(non_repo_evidence.repo_root.is_none());
        assert!(non_repo_evidence.worktree.is_none());
        assert_eq!(non_repo_evidence.head_state, Some(HeadState::NotARepo));
        assert!(child.child.try_wait().unwrap().is_none());
        assert!(non_repo_child.child.try_wait().unwrap().is_none());
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);

        // Retain original /proc identity and resolver output beside the real
        // Git command log; no synthetic evidence is supplied to the resolver.
        fs::write(
            fixture.root.parent().unwrap().join("process-evidence.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "repo_child": { "stat": stat, "evidence": evidence },
                "non_repo_child": { "stat": non_repo_stat, "evidence": non_repo_evidence },
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
