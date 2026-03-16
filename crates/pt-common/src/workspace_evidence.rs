//! Canonical raw evidence inputs and stable identifiers for workspace/repo provenance.
//!
//! This module defines how cwd, repo root, worktree, branch/HEAD state, and
//! workspace attribution are normalized into stable identifiers suitable for
//! provenance graph nodes and edges. It ensures that later classification and
//! origin logic is built on deterministic normalization rather than ad hoc
//! path parsing.
//!
//! Key design decisions:
//! - Stable identifiers are SHA-256 based hashes of canonical paths, not raw paths
//! - Symlinks are resolved before hashing to avoid aliases
//! - Missing/unreadable evidence produces explicit error variants, not silent defaults
//! - All normalization is pure and testable without filesystem access

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ProvenanceConfidence, ProvenanceEvidenceId, ProvenanceEvidenceKind, ProvenanceNodeId,
    ProvenanceNodeKind, ProvenanceObservationStatus,
};

/// Schema version for workspace evidence normalization.
pub const WORKSPACE_EVIDENCE_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Raw evidence inputs (what collectors provide)
// ---------------------------------------------------------------------------

/// Raw evidence gathered from the filesystem about a process's workspace context.
///
/// Collectors populate this struct; normalization then produces stable identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawWorkspaceEvidence {
    /// Process ID this evidence was collected for.
    pub pid: u32,
    /// The process's current working directory, as read from `/proc/[pid]/cwd`.
    pub cwd: Option<RawPathEvidence>,
    /// The resolved repo root (nearest ancestor containing `.git`).
    pub repo_root: Option<RawPathEvidence>,
    /// The worktree path, if different from the repo root (git worktree).
    pub worktree: Option<RawPathEvidence>,
    /// Branch or HEAD state at the time of observation.
    pub head_state: Option<HeadState>,
    /// How the evidence was obtained.
    pub collection_method: WorkspaceCollectionMethod,
    /// ISO-8601 timestamp of when evidence was gathered.
    pub observed_at: String,
}

/// A raw path with metadata about how it was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawPathEvidence {
    /// The original path as discovered (may contain symlinks).
    pub original: String,
    /// The canonicalized path after symlink resolution, if successful.
    pub canonical: Option<String>,
    /// Why canonical resolution may have failed.
    pub resolution_error: Option<PathResolutionError>,
}

impl RawPathEvidence {
    /// Create evidence for a successfully resolved path.
    pub fn resolved(original: impl Into<String>, canonical: impl Into<String>) -> Self {
        Self {
            original: original.into(),
            canonical: Some(canonical.into()),
            resolution_error: None,
        }
    }

    /// Create evidence for a path that could not be canonicalized.
    pub fn unresolved(original: impl Into<String>, error: PathResolutionError) -> Self {
        Self {
            original: original.into(),
            canonical: None,
            resolution_error: Some(error),
        }
    }

    /// The best available path: canonical if resolved, otherwise original.
    pub fn effective_path(&self) -> &str {
        self.canonical.as_deref().unwrap_or(&self.original)
    }
}

/// Why a path could not be canonicalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathResolutionError {
    /// The symlink target does not exist.
    BrokenSymlink,
    /// Permission denied reading the path.
    PermissionDenied,
    /// The path does not exist.
    NotFound,
    /// An I/O error occurred during resolution.
    IoError { message: String },
    /// The path was too long or contained invalid bytes.
    InvalidPath,
}

impl fmt::Display for PathResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrokenSymlink => write!(f, "broken symlink"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::NotFound => write!(f, "not found"),
            Self::IoError { message } => write!(f, "I/O error: {message}"),
            Self::InvalidPath => write!(f, "invalid path"),
        }
    }
}

/// Branch or detached HEAD state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HeadState {
    /// On a named branch.
    Branch { name: String },
    /// Detached at a specific commit.
    Detached { commit_prefix: String },
    /// HEAD reference exists but is unreadable.
    Unreadable { reason: String },
    /// No .git directory found; not a git repo.
    NotARepo,
}

impl HeadState {
    /// A short label for display/logging purposes.
    pub fn label(&self) -> &str {
        match self {
            Self::Branch { name } => name,
            Self::Detached { commit_prefix } => commit_prefix,
            Self::Unreadable { .. } => "<unreadable>",
            Self::NotARepo => "<not-a-repo>",
        }
    }
}

/// How workspace evidence was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceCollectionMethod {
    /// Read from /proc/[pid]/cwd + filesystem walk.
    ProcfsCwdWalk,
    /// Read from lsof output.
    Lsof,
    /// Inferred from command-line arguments.
    CommandLineInference,
    /// Synthetic/test evidence.
    Synthetic,
}

// ---------------------------------------------------------------------------
// Normalization: raw evidence → stable identifiers
// ---------------------------------------------------------------------------

/// A normalized workspace identity with stable, hash-based identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NormalizedWorkspace {
    /// Stable identifier for this workspace, derived from the canonical repo root.
    pub workspace_id: String,
    /// The canonical repo root path (after symlink resolution).
    pub canonical_root: String,
    /// Stable identifier for the worktree, if distinct from repo root.
    pub worktree_id: Option<String>,
    /// The canonical worktree path, if distinct from repo root.
    pub canonical_worktree: Option<String>,
    /// Branch/HEAD state at observation time.
    pub head_state: Option<HeadState>,
    /// Confidence in this normalization.
    pub confidence: ProvenanceConfidence,
    /// Reasons for any confidence downgrade.
    pub downgrade_reasons: Vec<String>,
}

impl NormalizedWorkspace {
    /// Generate provenance node IDs for this workspace.
    pub fn workspace_node_id(&self) -> ProvenanceNodeId {
        ProvenanceNodeId::new(
            ProvenanceNodeKind::Workspace,
            &format!("workspace:{}", self.workspace_id),
        )
    }

    /// Generate provenance node ID for the repo, if meaningful.
    pub fn repo_node_id(&self) -> ProvenanceNodeId {
        ProvenanceNodeId::new(
            ProvenanceNodeKind::Repo,
            &format!("repo:{}", self.workspace_id),
        )
    }

    /// Generate provenance evidence ID for the git evidence.
    pub fn git_evidence_id(&self) -> ProvenanceEvidenceId {
        ProvenanceEvidenceId::new(
            ProvenanceEvidenceKind::Git,
            &format!("git:root={}", self.canonical_root),
        )
    }
}

/// Result of attempting to normalize workspace evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum WorkspaceNormalizationResult {
    /// Successfully normalized to a stable workspace identity.
    Resolved { workspace: NormalizedWorkspace },
    /// No workspace could be determined (not in a repo, etc.).
    NoWorkspace { reason: String },
    /// Evidence was present but contradictory or unreliable.
    Degraded {
        partial: NormalizedWorkspace,
        warnings: Vec<String>,
    },
}

impl WorkspaceNormalizationResult {
    /// The observation status for provenance evidence.
    pub fn observation_status(&self) -> ProvenanceObservationStatus {
        match self {
            Self::Resolved { .. } => ProvenanceObservationStatus::Observed,
            Self::NoWorkspace { .. } => ProvenanceObservationStatus::Missing,
            Self::Degraded { .. } => ProvenanceObservationStatus::Partial,
        }
    }

    /// The confidence level of this result.
    pub fn confidence(&self) -> ProvenanceConfidence {
        match self {
            Self::Resolved { workspace } => workspace.confidence,
            Self::NoWorkspace { .. } => ProvenanceConfidence::Unknown,
            Self::Degraded { partial, .. } => partial.confidence,
        }
    }
}

// ---------------------------------------------------------------------------
// Normalization functions (pure, no I/O)
// ---------------------------------------------------------------------------

/// Compute a stable hash identifier for a canonical path.
///
/// The hash is computed over the UTF-8 bytes of the path after normalization.
/// Two paths that resolve to the same canonical form will always produce the
/// same identifier, regardless of how they were originally discovered.
pub fn stable_path_id(canonical_path: &str) -> String {
    let normalized = normalize_path_for_hashing(canonical_path);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Normalize a path string for consistent hashing.
///
/// - Strips trailing slashes (except for root `/`)
/// - Normalizes path separators to `/`
/// - Does NOT resolve symlinks (caller must provide canonical path)
pub fn normalize_path_for_hashing(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized
    }
}

/// Normalize raw workspace evidence into a stable identity.
///
/// This is a pure function operating on pre-collected evidence. It does not
/// perform any filesystem I/O.
pub fn normalize_workspace(evidence: &RawWorkspaceEvidence) -> WorkspaceNormalizationResult {
    let repo_root = match &evidence.repo_root {
        Some(path_ev) => path_ev,
        None => {
            // No repo root found — check if CWD gives us anything
            return match &evidence.cwd {
                Some(cwd) => WorkspaceNormalizationResult::NoWorkspace {
                    reason: format!(
                        "no .git directory found above cwd '{}'",
                        cwd.effective_path()
                    ),
                },
                None => WorkspaceNormalizationResult::NoWorkspace {
                    reason: "cwd unreadable and no repo root provided".to_string(),
                },
            };
        }
    };

    let canonical_root = repo_root.effective_path().to_string();
    let workspace_id = stable_path_id(&canonical_root);
    let mut downgrade_reasons = Vec::new();
    let mut confidence = ProvenanceConfidence::High;

    // Downgrade if repo root wasn't canonicalized
    if repo_root.canonical.is_none() {
        confidence = ProvenanceConfidence::Medium;
        downgrade_reasons.push(format!(
            "repo root '{}' could not be canonicalized: {}",
            repo_root.original,
            repo_root
                .resolution_error
                .as_ref()
                .map(|e| match e {
                    PathResolutionError::BrokenSymlink => "broken symlink",
                    PathResolutionError::PermissionDenied => "permission denied",
                    PathResolutionError::NotFound => "not found",
                    PathResolutionError::IoError { .. } => "I/O error",
                    PathResolutionError::InvalidPath => "invalid path",
                })
                .unwrap_or("unknown")
        ));
    }

    // Handle worktree
    let (worktree_id, canonical_worktree) = match &evidence.worktree {
        Some(wt) => {
            let wt_path = wt.effective_path().to_string();
            if wt_path != canonical_root {
                let wt_id = stable_path_id(&wt_path);
                if wt.canonical.is_none() {
                    confidence = downgrade_confidence(confidence);
                    downgrade_reasons.push(format!(
                        "worktree path '{}' could not be canonicalized",
                        wt.original
                    ));
                }
                (Some(wt_id), Some(wt_path))
            } else {
                (None, None) // worktree == repo root, no separate identity
            }
        }
        None => (None, None),
    };

    // Downgrade if CWD was unreadable (weaker context for attribution)
    if evidence.cwd.is_none() {
        confidence = downgrade_confidence(confidence);
        downgrade_reasons.push("cwd was unreadable; workspace attribution is inferred".to_string());
    } else if let Some(cwd) = &evidence.cwd {
        // Verify CWD is under the repo root OR the worktree (for git worktrees)
        let cwd_effective = cwd.effective_path();
        let under_root = is_path_under(&canonical_root, cwd_effective);
        let under_worktree = canonical_worktree
            .as_deref()
            .is_some_and(|wt| is_path_under(wt, cwd_effective));
        if !under_root && !under_worktree {
            confidence = downgrade_confidence(confidence);
            downgrade_reasons.push(format!(
                "cwd '{}' is not under repo root '{}'; attribution uncertain",
                cwd_effective, canonical_root
            ));
        }
    }

    if downgrade_reasons.is_empty() {
        let workspace = NormalizedWorkspace {
            workspace_id,
            canonical_root,
            worktree_id,
            canonical_worktree,
            head_state: evidence.head_state.clone(),
            confidence,
            downgrade_reasons: Vec::new(),
        };
        WorkspaceNormalizationResult::Resolved { workspace }
    } else {
        let workspace = NormalizedWorkspace {
            workspace_id,
            canonical_root,
            worktree_id,
            canonical_worktree,
            head_state: evidence.head_state.clone(),
            confidence,
            downgrade_reasons: downgrade_reasons.clone(),
        };
        WorkspaceNormalizationResult::Degraded {
            partial: workspace,
            warnings: downgrade_reasons,
        }
    }
}

/// Check if `child` is a path under `parent` (prefix match on normalized paths).
pub fn is_path_under(parent: &str, child: &str) -> bool {
    let parent_norm = normalize_path_for_hashing(parent);
    let child_norm = normalize_path_for_hashing(child);
    if child_norm == parent_norm {
        return true;
    }
    // Ensure the parent is a proper directory prefix
    let parent_prefix = if parent_norm.ends_with('/') {
        parent_norm
    } else {
        format!("{parent_norm}/")
    };
    child_norm.starts_with(&parent_prefix)
}

/// Downgrade confidence by one level.
fn downgrade_confidence(current: ProvenanceConfidence) -> ProvenanceConfidence {
    match current {
        ProvenanceConfidence::High => ProvenanceConfidence::Medium,
        ProvenanceConfidence::Medium => ProvenanceConfidence::Low,
        ProvenanceConfidence::Low | ProvenanceConfidence::Unknown => ProvenanceConfidence::Unknown,
    }
}

/// Determine whether two raw path evidence items refer to the same location.
///
/// Uses canonical paths when available, falls back to original paths.
pub fn paths_are_same_location(a: &RawPathEvidence, b: &RawPathEvidence) -> bool {
    let a_path = normalize_path_for_hashing(a.effective_path());
    let b_path = normalize_path_for_hashing(b.effective_path());
    a_path == b_path
}

// ---------------------------------------------------------------------------
// Debug/trace event helpers
// ---------------------------------------------------------------------------

/// Canonical debug event name for workspace normalization.
pub const WORKSPACE_EVIDENCE_NORMALIZED: &str = "provenance_workspace_evidence_normalized";
/// Canonical debug event name for workspace normalization failure.
pub const WORKSPACE_EVIDENCE_MISSING: &str = "provenance_workspace_evidence_missing";
/// Canonical debug event name for workspace path alias resolution.
pub const WORKSPACE_PATH_ALIAS_RESOLVED: &str = "provenance_workspace_path_alias_resolved";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_path_id_is_deterministic() {
        let id1 = stable_path_id("/home/user/project");
        let id2 = stable_path_id("/home/user/project");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16); // 8 bytes hex-encoded
    }

    #[test]
    fn stable_path_id_differs_for_different_paths() {
        let id1 = stable_path_id("/home/user/project-a");
        let id2 = stable_path_id("/home/user/project-b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(
            normalize_path_for_hashing("/home/user/project/"),
            "/home/user/project"
        );
        assert_eq!(normalize_path_for_hashing("/"), "/");
    }

    #[test]
    fn normalize_converts_backslashes() {
        assert_eq!(
            normalize_path_for_hashing("C:\\Users\\project"),
            "C:/Users/project"
        );
    }

    #[test]
    fn trailing_slash_does_not_change_stable_id() {
        let id1 = stable_path_id("/home/user/project");
        let id2 = stable_path_id("/home/user/project/");
        assert_eq!(id1, id2);
    }

    #[test]
    fn is_path_under_basic_cases() {
        assert!(is_path_under(
            "/home/user/project",
            "/home/user/project/src/main.rs"
        ));
        assert!(is_path_under("/home/user/project", "/home/user/project"));
        assert!(!is_path_under(
            "/home/user/project",
            "/home/user/project2/file"
        ));
        assert!(!is_path_under("/home/user/project", "/other/path"));
    }

    #[test]
    fn is_path_under_with_trailing_slashes() {
        assert!(is_path_under("/repo/", "/repo/src/lib.rs"));
        assert!(is_path_under("/repo", "/repo/src/lib.rs"));
    }

    #[test]
    fn raw_path_evidence_resolved() {
        let ev = RawPathEvidence::resolved("/tmp/link", "/home/user/project");
        assert_eq!(ev.effective_path(), "/home/user/project");
    }

    #[test]
    fn raw_path_evidence_unresolved_falls_back_to_original() {
        let ev = RawPathEvidence::unresolved("/tmp/link", PathResolutionError::BrokenSymlink);
        assert_eq!(ev.effective_path(), "/tmp/link");
    }

    #[test]
    fn normalize_workspace_success() {
        let evidence = RawWorkspaceEvidence {
            pid: 123,
            cwd: Some(RawPathEvidence::resolved(
                "/home/user/project/src",
                "/home/user/project/src",
            )),
            repo_root: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            worktree: None,
            head_state: Some(HeadState::Branch {
                name: "main".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Resolved { workspace } => {
                assert_eq!(workspace.canonical_root, "/home/user/project");
                assert_eq!(workspace.confidence, ProvenanceConfidence::High);
                assert!(workspace.downgrade_reasons.is_empty());
                assert!(workspace.worktree_id.is_none());
                assert_eq!(
                    workspace.head_state,
                    Some(HeadState::Branch {
                        name: "main".to_string()
                    })
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
        assert_eq!(
            result.observation_status(),
            ProvenanceObservationStatus::Observed
        );
        assert_eq!(result.confidence(), ProvenanceConfidence::High);
    }

    #[test]
    fn normalize_workspace_no_repo_root() {
        let evidence = RawWorkspaceEvidence {
            pid: 456,
            cwd: Some(RawPathEvidence::resolved("/tmp", "/tmp")),
            repo_root: None,
            worktree: None,
            head_state: Some(HeadState::NotARepo),
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::NoWorkspace { reason } => {
                assert!(reason.contains("/tmp"));
                assert!(reason.contains(".git"));
            }
            other => panic!("expected NoWorkspace, got {other:?}"),
        }
        assert_eq!(
            result.observation_status(),
            ProvenanceObservationStatus::Missing
        );
    }

    #[test]
    fn normalize_workspace_no_cwd_and_no_repo() {
        let evidence = RawWorkspaceEvidence {
            pid: 789,
            cwd: None,
            repo_root: None,
            worktree: None,
            head_state: None,
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::NoWorkspace { reason } => {
                assert!(reason.contains("cwd unreadable"));
            }
            other => panic!("expected NoWorkspace, got {other:?}"),
        }
    }

    #[test]
    fn normalize_workspace_uncanonicalized_repo_root_degrades() {
        let evidence = RawWorkspaceEvidence {
            pid: 111,
            cwd: Some(RawPathEvidence::resolved(
                "/mnt/link/project/src",
                "/mnt/link/project/src",
            )),
            repo_root: Some(RawPathEvidence::unresolved(
                "/mnt/link/project",
                PathResolutionError::BrokenSymlink,
            )),
            worktree: None,
            head_state: Some(HeadState::Branch {
                name: "feature".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Degraded { partial, warnings } => {
                assert_eq!(partial.confidence, ProvenanceConfidence::Medium);
                assert!(!warnings.is_empty());
                assert!(warnings[0].contains("canonicalized"));
                // Uses original path since canonical is absent
                assert_eq!(partial.canonical_root, "/mnt/link/project");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn normalize_workspace_cwd_outside_repo_degrades() {
        let evidence = RawWorkspaceEvidence {
            pid: 222,
            cwd: Some(RawPathEvidence::resolved("/other/dir", "/other/dir")),
            repo_root: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            worktree: None,
            head_state: None,
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Degraded { partial, warnings } => {
                assert!(warnings.iter().any(|w| w.contains("not under repo root")));
                assert_eq!(partial.confidence, ProvenanceConfidence::Medium);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn normalize_workspace_with_separate_worktree() {
        let evidence = RawWorkspaceEvidence {
            pid: 333,
            cwd: Some(RawPathEvidence::resolved(
                "/home/user/worktree-a",
                "/home/user/worktree-a",
            )),
            repo_root: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            worktree: Some(RawPathEvidence::resolved(
                "/home/user/worktree-a",
                "/home/user/worktree-a",
            )),
            head_state: Some(HeadState::Branch {
                name: "feature-a".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Resolved { workspace } => {
                assert!(workspace.worktree_id.is_some());
                assert_eq!(
                    workspace.canonical_worktree.as_deref(),
                    Some("/home/user/worktree-a")
                );
                assert_ne!(
                    workspace.worktree_id.as_ref().unwrap(),
                    &workspace.workspace_id
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn normalize_workspace_worktree_same_as_root_is_ignored() {
        let evidence = RawWorkspaceEvidence {
            pid: 444,
            cwd: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            repo_root: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            worktree: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            head_state: None,
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Resolved { workspace } => {
                assert!(workspace.worktree_id.is_none());
                assert!(workspace.canonical_worktree.is_none());
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn normalize_workspace_missing_cwd_degrades() {
        let evidence = RawWorkspaceEvidence {
            pid: 555,
            cwd: None,
            repo_root: Some(RawPathEvidence::resolved(
                "/home/user/project",
                "/home/user/project",
            )),
            worktree: None,
            head_state: None,
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        match &result {
            WorkspaceNormalizationResult::Degraded { partial, warnings } => {
                assert!(warnings.iter().any(|w| w.contains("cwd was unreadable")));
                assert_eq!(partial.confidence, ProvenanceConfidence::Medium);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn head_state_labels() {
        assert_eq!(
            HeadState::Branch {
                name: "main".to_string()
            }
            .label(),
            "main"
        );
        assert_eq!(
            HeadState::Detached {
                commit_prefix: "abc1234".to_string()
            }
            .label(),
            "abc1234"
        );
        assert_eq!(
            HeadState::Unreadable {
                reason: "perm".to_string()
            }
            .label(),
            "<unreadable>"
        );
        assert_eq!(HeadState::NotARepo.label(), "<not-a-repo>");
    }

    #[test]
    fn paths_are_same_location_works() {
        let a = RawPathEvidence::resolved("/tmp/link", "/home/user/project");
        let b = RawPathEvidence::resolved("/other/link", "/home/user/project");
        assert!(paths_are_same_location(&a, &b));

        let c = RawPathEvidence::resolved("/tmp/link", "/home/user/other");
        assert!(!paths_are_same_location(&a, &c));
    }

    #[test]
    fn paths_same_location_unresolved_uses_original() {
        let a = RawPathEvidence::unresolved("/shared/path", PathResolutionError::BrokenSymlink);
        let b = RawPathEvidence::unresolved("/shared/path", PathResolutionError::PermissionDenied);
        assert!(paths_are_same_location(&a, &b));
    }

    #[test]
    fn workspace_node_ids_are_deterministic() {
        let ws = NormalizedWorkspace {
            workspace_id: stable_path_id("/home/user/project"),
            canonical_root: "/home/user/project".to_string(),
            worktree_id: None,
            canonical_worktree: None,
            head_state: None,
            confidence: ProvenanceConfidence::High,
            downgrade_reasons: Vec::new(),
        };

        let node_id_1 = ws.workspace_node_id();
        let node_id_2 = ws.workspace_node_id();
        assert_eq!(node_id_1, node_id_2);
        assert!(node_id_1.0.starts_with("pn_workspace_"));
    }

    #[test]
    fn json_round_trip_raw_evidence() {
        let evidence = RawWorkspaceEvidence {
            pid: 99,
            cwd: Some(RawPathEvidence::resolved(
                "/home/user/src",
                "/home/user/src",
            )),
            repo_root: Some(RawPathEvidence::resolved("/home/user", "/home/user")),
            worktree: None,
            head_state: Some(HeadState::Branch {
                name: "main".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::ProcfsCwdWalk,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&evidence).expect("serialize");
        let parsed: RawWorkspaceEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, evidence);
    }

    #[test]
    fn json_round_trip_normalization_result() {
        let evidence = RawWorkspaceEvidence {
            pid: 100,
            cwd: Some(RawPathEvidence::resolved("/project/src", "/project/src")),
            repo_root: Some(RawPathEvidence::resolved("/project", "/project")),
            worktree: None,
            head_state: Some(HeadState::Detached {
                commit_prefix: "abc1234".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::Synthetic,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_workspace(&evidence);
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: WorkspaceNormalizationResult =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.observation_status(), result.observation_status());
        assert_eq!(parsed.confidence(), result.confidence());
    }

    #[test]
    fn path_resolution_error_display() {
        assert_eq!(
            PathResolutionError::BrokenSymlink.to_string(),
            "broken symlink"
        );
        assert_eq!(
            PathResolutionError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(PathResolutionError::NotFound.to_string(), "not found");
        assert_eq!(
            PathResolutionError::IoError {
                message: "disk full".to_string()
            }
            .to_string(),
            "I/O error: disk full"
        );
        assert_eq!(PathResolutionError::InvalidPath.to_string(), "invalid path");
    }
}
