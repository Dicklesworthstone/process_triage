//! End-to-end integration tests for repo/workspace/workflow-origin provenance.
//!
//! These tests exercise the full provenance pipeline:
//!   workspace_resolver → normalize_workspace → classify_workflow_origin
//!
//! They cover real user stories: stale test runners, active dev servers,
//! agent-owned shells, non-repo processes, and detached-HEAD CI builds.

mod support;

use pt_common::{
    classify_workflow_origin, normalize_workspace, CommandCategory, HeadState, PathResolutionError,
    ProvenanceConfidence, RawPathEvidence, RawWorkspaceEvidence, WorkflowFamily,
    WorkspaceCollectionMethod, WorkspaceNormalizationResult,
};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn workspace_in_repo(root: &str, cwd: &str, branch: &str) -> RawWorkspaceEvidence {
    RawWorkspaceEvidence {
        pid: 1000,
        cwd: Some(RawPathEvidence::resolved(cwd, cwd)),
        repo_root: Some(RawPathEvidence::resolved(root, root)),
        worktree: None,
        head_state: Some(HeadState::Branch {
            name: branch.to_string(),
        }),
        collection_method: WorkspaceCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn workspace_non_repo(cwd: &str) -> RawWorkspaceEvidence {
    RawWorkspaceEvidence {
        pid: 2000,
        cwd: Some(RawPathEvidence::resolved(cwd, cwd)),
        repo_root: None,
        worktree: None,
        head_state: Some(HeadState::NotARepo),
        collection_method: WorkspaceCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn workspace_detached_head(root: &str, commit: &str) -> RawWorkspaceEvidence {
    RawWorkspaceEvidence {
        pid: 3000,
        cwd: Some(RawPathEvidence::resolved(root, root)),
        repo_root: Some(RawPathEvidence::resolved(root, root)),
        worktree: None,
        head_state: Some(HeadState::Detached {
            commit_prefix: commit.to_string(),
        }),
        collection_method: WorkspaceCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn workspace_deleted_cwd(root: &str) -> RawWorkspaceEvidence {
    RawWorkspaceEvidence {
        pid: 4000,
        cwd: Some(RawPathEvidence::unresolved(
            format!("{root}/old-feature"),
            PathResolutionError::NotFound,
        )),
        repo_root: Some(RawPathEvidence::resolved(root, root)),
        worktree: None,
        head_state: Some(HeadState::Branch {
            name: "main".to_string(),
        }),
        collection_method: WorkspaceCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Scenario: stale test runner in a project workspace
// ---------------------------------------------------------------------------

#[test]
fn stale_test_runner_in_workspace_produces_high_confidence_classification() {
    let raw = workspace_in_repo("/home/dev/myapp", "/home/dev/myapp/tests", "main");
    let ws = normalize_workspace(&raw);

    let classification = classify_workflow_origin(
        CommandCategory::Test,
        "pytest",
        Some("pytest -x tests/"),
        Some(&ws),
    );

    assert_eq!(classification.family, WorkflowFamily::TestRunner);
    assert_eq!(classification.confidence, ProvenanceConfidence::High);
    assert!(classification.project_local);

    // Should have both command and workspace signals
    assert!(classification.signals.len() >= 2);
}

// ---------------------------------------------------------------------------
// Scenario: active dev server on feature branch
// ---------------------------------------------------------------------------

#[test]
fn dev_server_on_feature_branch_records_branch_context() {
    let raw = workspace_in_repo(
        "/home/dev/webapp",
        "/home/dev/webapp",
        "feature/auth-redesign",
    );
    let ws = normalize_workspace(&raw);

    let classification = classify_workflow_origin(
        CommandCategory::DevServer,
        "next",
        Some("next dev --port 3000"),
        Some(&ws),
    );

    assert_eq!(classification.family, WorkflowFamily::DevServer);
    assert_eq!(classification.confidence, ProvenanceConfidence::High);
    assert!(classification.project_local);

    // Should record the branch name
    let has_branch = classification.signals.iter().any(|s| {
        matches!(s, pt_common::ClassificationSignal::BranchContext { branch }
            if branch == "feature/auth-redesign")
    });
    assert!(has_branch, "should record branch context");
}

// ---------------------------------------------------------------------------
// Scenario: agent-owned shell in workspace
// ---------------------------------------------------------------------------

#[test]
fn agent_process_in_workspace_is_project_local() {
    let raw = workspace_in_repo("/home/dev/project", "/home/dev/project", "main");
    let ws = normalize_workspace(&raw);

    let classification = classify_workflow_origin(
        CommandCategory::Agent,
        "claude",
        Some("claude code --model opus"),
        Some(&ws),
    );

    assert_eq!(classification.family, WorkflowFamily::AgentSession);
    assert!(classification.project_local);
    assert!(classification.family.is_long_running());
}

// ---------------------------------------------------------------------------
// Scenario: process running outside any repo
// ---------------------------------------------------------------------------

#[test]
fn system_process_outside_repo_has_no_workspace() {
    let raw = workspace_non_repo("/usr/sbin");
    let ws = normalize_workspace(&raw);

    assert!(matches!(
        ws,
        WorkspaceNormalizationResult::NoWorkspace { .. }
    ));

    let classification = classify_workflow_origin(
        CommandCategory::Daemon,
        "nginx",
        Some("nginx: master process"),
        Some(&ws),
    );

    assert_eq!(classification.family, WorkflowFamily::SystemDaemon);
    assert!(!classification.project_local);
}

// ---------------------------------------------------------------------------
// Scenario: CI build with detached HEAD
// ---------------------------------------------------------------------------

#[test]
fn detached_head_with_unknown_command_suggests_build_tool() {
    let raw = workspace_detached_head("/ci/workspace", "abc1234");
    let ws = normalize_workspace(&raw);

    let classification = classify_workflow_origin(
        CommandCategory::Unknown,
        "run-tests",
        Some("./run-tests.sh --ci"),
        Some(&ws),
    );

    // Detached HEAD + unknown command → guess BuildTool (CI)
    assert_eq!(classification.family, WorkflowFamily::BuildTool);
    assert!(classification.project_local);

    let has_detached = classification.signals.iter().any(|s| {
        matches!(s, pt_common::ClassificationSignal::DetachedHead { commit_prefix }
            if commit_prefix == "abc1234")
    });
    assert!(has_detached, "should record detached HEAD");
}

// ---------------------------------------------------------------------------
// Scenario: process with deleted CWD (stale branch checkout)
// ---------------------------------------------------------------------------

#[test]
fn deleted_cwd_degrades_workspace_confidence() {
    let raw = workspace_deleted_cwd("/home/dev/project");
    let ws = normalize_workspace(&raw);

    // Should still find the workspace but with degraded confidence
    match &ws {
        WorkspaceNormalizationResult::Degraded { partial, warnings } => {
            assert!(!warnings.is_empty());
            assert!(partial.confidence <= ProvenanceConfidence::Medium);
        }
        WorkspaceNormalizationResult::Resolved { workspace } => {
            // If the deleted cwd happens to be under root, could still resolve
            // but confidence should reflect the unresolved path
            assert!(workspace.confidence <= ProvenanceConfidence::High);
        }
        other => panic!("unexpected result: {other:?}"),
    }

    let classification = classify_workflow_origin(
        CommandCategory::Test,
        "jest",
        Some("jest --watch"),
        Some(&ws),
    );

    // Still classified correctly, but with reduced confidence
    assert_eq!(classification.family, WorkflowFamily::TestRunner);
}

// ---------------------------------------------------------------------------
// Scenario: unknown process with no evidence at all
// ---------------------------------------------------------------------------

#[test]
fn unknown_process_with_no_workspace_is_unknown_confidence() {
    let classification = classify_workflow_origin(
        CommandCategory::Unknown,
        "mystery",
        Some("mystery --daemon"),
        None,
    );

    assert_eq!(classification.family, WorkflowFamily::Unknown);
    assert_eq!(classification.confidence, ProvenanceConfidence::Unknown);
}

// ---------------------------------------------------------------------------
// Scenario: test runner outside workspace is a contradiction
// ---------------------------------------------------------------------------

#[test]
fn test_runner_outside_workspace_flags_contradiction() {
    let raw = workspace_non_repo("/tmp");
    let ws = normalize_workspace(&raw);

    let classification = classify_workflow_origin(
        CommandCategory::Test,
        "cargo",
        Some("cargo test"),
        Some(&ws),
    );

    assert_eq!(classification.family, WorkflowFamily::TestRunner);
    assert!(!classification.project_local);

    let has_contradiction = classification
        .signals
        .iter()
        .any(|s| matches!(s, pt_common::ClassificationSignal::Contradiction { .. }));
    assert!(has_contradiction, "should flag contradiction");
    assert!(classification.confidence > ProvenanceConfidence::High);
}

// ---------------------------------------------------------------------------
// Scenario: live workspace resolution on an owned Git repository
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn live_workspace_resolution_on_owned_git_repo() {
    use pt_core::collect::resolve_workspace_for_pid;
    use std::process::{Child, Command, Stdio};
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = tempfile::tempdir()
        .expect("owned repository fixture")
        .keep();
    let repository = fixture.join("process_triage");
    let manifest_dir = repository.join("crates/pt-core");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let initialized = std::process::Command::new("git")
        .args(["init", "--initial-branch=main"])
        .arg(&repository)
        .output()
        .expect("initialize owned Git repository");
    assert!(
        initialized.status.success(),
        "git init: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let child = OwnedChild(
        Command::new("sleep")
            .arg("900")
            .current_dir(&manifest_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owned process in real repository"),
    );
    let raw = resolve_workspace_for_pid(child.0.id());
    assert_eq!(raw.pid, child.0.id());
    assert_eq!(
        raw.collection_method,
        WorkspaceCollectionMethod::ProcfsCwdWalk
    );
    assert_eq!(
        raw.head_state,
        Some(HeadState::Branch {
            name: "main".to_string()
        })
    );
    std::fs::write(
        fixture.join("workspace.json"),
        serde_json::to_vec_pretty(&raw).unwrap(),
    )
    .unwrap();

    let ws = normalize_workspace(&raw);

    // This real repository is available even when offload omits the caller's .git.
    match &ws {
        WorkspaceNormalizationResult::Resolved { workspace } => {
            assert!(
                workspace.canonical_root.contains("process_triage"),
                "root should be process_triage: {}",
                workspace.canonical_root
            );
            assert_eq!(
                workspace.canonical_root,
                repository.canonicalize().unwrap().to_string_lossy()
            );
            assert_eq!(workspace.confidence, ProvenanceConfidence::High);
        }
        other => panic!("owned repository must resolve with complete evidence: {other:?}"),
    }
}
