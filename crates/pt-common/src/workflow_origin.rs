//! Workflow-origin classifier for process provenance.
//!
//! Classifies the likely workflow origin of a process by combining command
//! category, workspace evidence, and process metadata. This raises explanatory
//! quality and reduces false positives by attaching a process to a likely
//! workflow family rather than relying on one-off command heuristics.
//!
//! # Design Decisions
//!
//! - Confidence is explicit: each classification carries a confidence level
//!   and the signals that contributed to it.
//! - Contradiction handling: when command and workspace signals disagree,
//!   confidence is downgraded and the conflict is recorded.
//! - Regression-safe: wrapped launchers (nohup, screen, tmux) are stripped
//!   before classification.

use serde::{Deserialize, Serialize};

use crate::categories::CommandCategory;
use crate::workspace_evidence::{HeadState, NormalizedWorkspace, WorkspaceNormalizationResult};
use crate::ProvenanceConfidence;

/// Schema version for workflow-origin classification.
pub const WORKFLOW_ORIGIN_VERSION: &str = "1.0.0";

/// The classified workflow family for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowFamily {
    /// Test runner (pytest, jest, cargo test, go test, bun test, etc.)
    TestRunner,
    /// Development server (next dev, vite, webpack-dev-server, etc.)
    DevServer,
    /// Interactive shell session (bash, zsh, fish)
    Shell,
    /// Editor or IDE (code, vim, nvim, emacs, cursor)
    Editor,
    /// AI/coding agent session (claude, codex, copilot, gemini)
    AgentSession,
    /// Build tool (cargo build, webpack, tsc, make)
    BuildTool,
    /// Production/long-running server (gunicorn, nginx, node server)
    ProductionServer,
    /// Background daemon or system service
    SystemDaemon,
    /// Database client or server
    Database,
    /// Version control operation
    VersionControl,
    /// Package manager operation
    PackageManager,
    /// Container or orchestrator tool
    ContainerTool,
    /// Could not determine workflow family
    Unknown,
}

impl WorkflowFamily {
    /// Whether this family is typically project-local (runs inside a repo).
    pub fn is_project_local(self) -> bool {
        matches!(
            self,
            Self::TestRunner
                | Self::DevServer
                | Self::BuildTool
                | Self::Editor
                | Self::AgentSession
                | Self::VersionControl
                | Self::PackageManager
        )
    }

    /// Whether this family is expected to be long-running.
    pub fn is_long_running(self) -> bool {
        matches!(
            self,
            Self::DevServer
                | Self::ProductionServer
                | Self::SystemDaemon
                | Self::Database
                | Self::AgentSession
        )
    }
}

impl From<CommandCategory> for WorkflowFamily {
    fn from(cat: CommandCategory) -> Self {
        match cat {
            CommandCategory::Test => Self::TestRunner,
            CommandCategory::DevServer => Self::DevServer,
            CommandCategory::Agent => Self::AgentSession,
            CommandCategory::Server => Self::ProductionServer,
            CommandCategory::Daemon => Self::SystemDaemon,
            CommandCategory::Build => Self::BuildTool,
            CommandCategory::Editor => Self::Editor,
            CommandCategory::Shell => Self::Shell,
            CommandCategory::Database => Self::Database,
            CommandCategory::Vcs => Self::VersionControl,
            CommandCategory::PackageManager => Self::PackageManager,
            CommandCategory::Container => Self::ContainerTool,
            CommandCategory::Unknown => Self::Unknown,
        }
    }
}

/// A signal that contributed to the workflow-origin classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ClassificationSignal {
    /// The command matched a known pattern.
    CommandPattern {
        category: CommandCategory,
        matched_pattern: String,
    },
    /// The process is running inside a git repo.
    InWorkspace { workspace_id: String },
    /// The process is running outside any known workspace.
    NoWorkspace,
    /// The process is on a specific branch (e.g., feature branch → likely dev work).
    BranchContext { branch: String },
    /// The process has a detached HEAD (e.g., CI checkout).
    DetachedHead { commit_prefix: String },
    /// A wrapper launcher was stripped before classification.
    WrappedLauncher { wrapper: String },
    /// Command and workspace evidence conflicted.
    Contradiction { description: String },
}

/// The result of classifying a process's workflow origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowOriginClassification {
    /// The classified workflow family.
    pub family: WorkflowFamily,
    /// Confidence in this classification.
    pub confidence: ProvenanceConfidence,
    /// Signals that contributed to this classification.
    pub signals: Vec<ClassificationSignal>,
    /// Whether the process appears to be project-local.
    pub project_local: bool,
}

/// Known launcher wrappers that should be stripped before classification.
const WRAPPER_LAUNCHERS: &[&str] = &[
    "nohup",
    "screen",
    "tmux",
    "nice",
    "ionice",
    "timeout",
    "env",
    "sudo",
    "su",
    "strace",
    "ltrace",
    "perf",
    "valgrind",
    "time",
    "taskset",
    "numactl",
    "chrt",
    "setsid",
    "daemonize",
    "start-stop-daemon",
];

/// Classify a process's workflow origin from its command and workspace evidence.
///
/// This is a pure function that combines command category with workspace context
/// to produce a richer classification than either signal alone.
pub fn classify_workflow_origin(
    cmd_category: CommandCategory,
    comm: &str,
    cmdline: Option<&str>,
    workspace: Option<&WorkspaceNormalizationResult>,
) -> WorkflowOriginClassification {
    let mut signals = Vec::new();
    let mut family = WorkflowFamily::from(cmd_category);
    let mut confidence = ProvenanceConfidence::High;

    // Record the command pattern signal
    if cmd_category != CommandCategory::Unknown {
        signals.push(ClassificationSignal::CommandPattern {
            category: cmd_category,
            matched_pattern: comm.to_string(),
        });
    }

    // Check for wrapper launchers in the command line
    if let Some(cmdline) = cmdline {
        let stripped = strip_wrapper_launchers(cmdline);
        if stripped != cmdline {
            let wrapper = cmdline
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            signals.push(ClassificationSignal::WrappedLauncher { wrapper });
            // If the command category was Unknown but we stripped a wrapper,
            // try to re-classify from the inner command
            if cmd_category == CommandCategory::Unknown {
                let inner_comm = stripped.split_whitespace().next().unwrap_or("");
                if let Some(better_family) = guess_family_from_comm(inner_comm) {
                    family = better_family;
                    confidence = ProvenanceConfidence::Medium; // less certain after stripping
                }
            }
        }
    }

    // Incorporate workspace evidence
    let project_local = match workspace {
        Some(WorkspaceNormalizationResult::Resolved { workspace: ws }) => {
            apply_workspace_signals(&mut signals, &mut confidence, &mut family, ws);
            true
        }
        Some(WorkspaceNormalizationResult::Degraded { partial, warnings }) => {
            apply_workspace_signals(&mut signals, &mut confidence, &mut family, partial);
            // Extra downgrade for degraded workspace evidence
            if !warnings.is_empty() {
                confidence = downgrade(confidence);
            }
            true
        }
        Some(WorkspaceNormalizationResult::NoWorkspace { .. }) => {
            signals.push(ClassificationSignal::NoWorkspace);
            // Project-local families without workspace context → contradiction
            if family.is_project_local() && cmd_category != CommandCategory::Unknown {
                signals.push(ClassificationSignal::Contradiction {
                    description: format!("{:?} process running outside any workspace", family),
                });
                confidence = downgrade(confidence);
            }
            false
        }
        None => {
            // No workspace evidence at all — can't determine locality
            if family == WorkflowFamily::Unknown {
                confidence = ProvenanceConfidence::Unknown;
            } else {
                confidence = downgrade(confidence);
            }
            family.is_project_local()
        }
    };

    // If we still have Unknown family and no signals, confidence is Unknown
    if family == WorkflowFamily::Unknown && signals.is_empty() {
        confidence = ProvenanceConfidence::Unknown;
    }

    WorkflowOriginClassification {
        family,
        confidence,
        signals,
        project_local,
    }
}

fn apply_workspace_signals(
    signals: &mut Vec<ClassificationSignal>,
    confidence: &mut ProvenanceConfidence,
    family: &mut WorkflowFamily,
    ws: &NormalizedWorkspace,
) {
    signals.push(ClassificationSignal::InWorkspace {
        workspace_id: ws.workspace_id.clone(),
    });

    if let Some(head) = &ws.head_state {
        match head {
            HeadState::Branch { name } => {
                signals.push(ClassificationSignal::BranchContext {
                    branch: name.clone(),
                });
            }
            HeadState::Detached { commit_prefix } => {
                signals.push(ClassificationSignal::DetachedHead {
                    commit_prefix: commit_prefix.clone(),
                });
                // Detached HEAD often indicates CI/automation
                if *family == WorkflowFamily::Unknown {
                    *family = WorkflowFamily::BuildTool;
                    *confidence = ProvenanceConfidence::Low;
                }
            }
            HeadState::Unreadable { .. } | HeadState::NotARepo => {
                *confidence = downgrade(*confidence);
            }
        }
    }

    // System daemons inside a workspace → contradiction
    if *family == WorkflowFamily::SystemDaemon {
        signals.push(ClassificationSignal::Contradiction {
            description: "system daemon running inside a workspace".to_string(),
        });
        *confidence = downgrade(*confidence);
    }
}

/// Strip known wrapper launchers from the beginning of a command line.
///
/// Handles chained wrappers like "sudo nohup pytest" → "pytest".
/// Does NOT attempt to strip wrapper flags (e.g., "nice -n 10 pytest"
/// strips "nice" but "-n 10 pytest" remains as-is, since flag parsing
/// across arbitrary wrappers is inherently fragile).
pub fn strip_wrapper_launchers(cmdline: &str) -> &str {
    let mut remaining = cmdline.trim();

    loop {
        let mut stripped = false;
        for wrapper in WRAPPER_LAUNCHERS {
            if let Some(rest) = remaining
                .strip_prefix(wrapper)
                .and_then(|r| r.strip_prefix(|c: char| c.is_whitespace()))
            {
                remaining = rest.trim();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }

    remaining
}

/// Guess a workflow family from a simple command name.
fn guess_family_from_comm(comm: &str) -> Option<WorkflowFamily> {
    let lower = comm.to_lowercase();
    match lower.as_str() {
        "pytest" | "jest" | "mocha" | "vitest" | "cargo-test" => Some(WorkflowFamily::TestRunner),
        "next" | "vite" | "webpack" | "nodemon" => Some(WorkflowFamily::DevServer),
        "code" | "vim" | "nvim" | "emacs" | "nano" => Some(WorkflowFamily::Editor),
        "bash" | "zsh" | "fish" | "sh" => Some(WorkflowFamily::Shell),
        "claude" | "codex" | "copilot" => Some(WorkflowFamily::AgentSession),
        "cargo" | "make" | "gcc" | "rustc" | "tsc" => Some(WorkflowFamily::BuildTool),
        "node" | "python" | "ruby" | "go" | "java" => None, // too ambiguous
        _ => None,
    }
}

fn downgrade(c: ProvenanceConfidence) -> ProvenanceConfidence {
    match c {
        ProvenanceConfidence::High => ProvenanceConfidence::Medium,
        ProvenanceConfidence::Medium => ProvenanceConfidence::Low,
        ProvenanceConfidence::Low | ProvenanceConfidence::Unknown => ProvenanceConfidence::Unknown,
    }
}

/// Canonical debug event name for workflow classification.
pub const WORKFLOW_ORIGIN_CLASSIFIED: &str = "provenance_workflow_origin_classified";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_evidence::normalize_workspace;
    use crate::workspace_evidence::{
        RawPathEvidence, RawWorkspaceEvidence, WorkspaceCollectionMethod,
    };

    fn make_workspace(root: &str, branch: &str) -> WorkspaceNormalizationResult {
        let evidence = RawWorkspaceEvidence {
            pid: 1,
            cwd: Some(RawPathEvidence::resolved(root, root)),
            repo_root: Some(RawPathEvidence::resolved(root, root)),
            worktree: None,
            head_state: Some(HeadState::Branch {
                name: branch.to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::Synthetic,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };
        normalize_workspace(&evidence)
    }

    fn make_no_workspace() -> WorkspaceNormalizationResult {
        WorkspaceNormalizationResult::NoWorkspace {
            reason: "not in a repo".to_string(),
        }
    }

    #[test]
    fn test_runner_in_workspace_is_high_confidence() {
        let ws = make_workspace("/home/user/project", "main");
        let result = classify_workflow_origin(
            CommandCategory::Test,
            "pytest",
            Some("pytest -k test_foo"),
            Some(&ws),
        );

        assert_eq!(result.family, WorkflowFamily::TestRunner);
        assert_eq!(result.confidence, ProvenanceConfidence::High);
        assert!(result.project_local);
        assert!(result.signals.iter().any(|s| matches!(
            s,
            ClassificationSignal::CommandPattern {
                category: CommandCategory::Test,
                ..
            }
        )));
        assert!(result
            .signals
            .iter()
            .any(|s| matches!(s, ClassificationSignal::InWorkspace { .. })));
    }

    #[test]
    fn dev_server_in_workspace_is_high_confidence() {
        let ws = make_workspace("/home/user/app", "feature-branch");
        let result = classify_workflow_origin(
            CommandCategory::DevServer,
            "next",
            Some("next dev"),
            Some(&ws),
        );

        assert_eq!(result.family, WorkflowFamily::DevServer);
        assert_eq!(result.confidence, ProvenanceConfidence::High);
        assert!(result.project_local);
    }

    #[test]
    fn test_runner_outside_workspace_is_contradiction() {
        let ws = make_no_workspace();
        let result = classify_workflow_origin(
            CommandCategory::Test,
            "jest",
            Some("jest --watch"),
            Some(&ws),
        );

        assert_eq!(result.family, WorkflowFamily::TestRunner);
        assert_eq!(result.confidence, ProvenanceConfidence::Medium); // downgraded
        assert!(!result.project_local);
        assert!(result
            .signals
            .iter()
            .any(|s| matches!(s, ClassificationSignal::Contradiction { .. })));
    }

    #[test]
    fn system_daemon_in_workspace_is_contradiction() {
        let ws = make_workspace("/home/user/project", "main");
        let result = classify_workflow_origin(CommandCategory::Daemon, "systemd", None, Some(&ws));

        assert_eq!(result.family, WorkflowFamily::SystemDaemon);
        assert!(result.confidence <= ProvenanceConfidence::Medium);
        assert!(result
            .signals
            .iter()
            .any(|s| matches!(s, ClassificationSignal::Contradiction { .. })));
    }

    #[test]
    fn unknown_command_no_workspace_is_unknown_confidence() {
        let result = classify_workflow_origin(
            CommandCategory::Unknown,
            "myapp",
            Some("myapp --start"),
            None,
        );

        assert_eq!(result.family, WorkflowFamily::Unknown);
        assert_eq!(result.confidence, ProvenanceConfidence::Unknown);
    }

    #[test]
    fn agent_session_classification() {
        let ws = make_workspace("/home/user/project", "main");
        let result = classify_workflow_origin(
            CommandCategory::Agent,
            "claude",
            Some("claude code"),
            Some(&ws),
        );

        assert_eq!(result.family, WorkflowFamily::AgentSession);
        assert_eq!(result.confidence, ProvenanceConfidence::High);
        assert!(result.project_local);
        assert!(result.family.is_long_running());
    }

    #[test]
    fn detached_head_suggests_ci() {
        let evidence = RawWorkspaceEvidence {
            pid: 1,
            cwd: Some(RawPathEvidence::resolved("/ci/build", "/ci/build")),
            repo_root: Some(RawPathEvidence::resolved("/ci/build", "/ci/build")),
            worktree: None,
            head_state: Some(HeadState::Detached {
                commit_prefix: "abc1234".to_string(),
            }),
            collection_method: WorkspaceCollectionMethod::Synthetic,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };
        let ws = normalize_workspace(&evidence);

        let result =
            classify_workflow_origin(CommandCategory::Unknown, "myprocess", None, Some(&ws));

        // Detached HEAD with unknown command → guesses BuildTool (CI)
        assert_eq!(result.family, WorkflowFamily::BuildTool);
        assert!(result
            .signals
            .iter()
            .any(|s| matches!(s, ClassificationSignal::DetachedHead { .. })));
    }

    #[test]
    fn workflow_family_traits() {
        assert!(WorkflowFamily::TestRunner.is_project_local());
        assert!(WorkflowFamily::DevServer.is_project_local());
        assert!(WorkflowFamily::Editor.is_project_local());
        assert!(!WorkflowFamily::SystemDaemon.is_project_local());
        assert!(!WorkflowFamily::ProductionServer.is_project_local());

        assert!(WorkflowFamily::DevServer.is_long_running());
        assert!(WorkflowFamily::AgentSession.is_long_running());
        assert!(!WorkflowFamily::TestRunner.is_long_running());
        assert!(!WorkflowFamily::BuildTool.is_long_running());
    }

    #[test]
    fn command_category_to_workflow_family() {
        assert_eq!(
            WorkflowFamily::from(CommandCategory::Test),
            WorkflowFamily::TestRunner
        );
        assert_eq!(
            WorkflowFamily::from(CommandCategory::Agent),
            WorkflowFamily::AgentSession
        );
        assert_eq!(
            WorkflowFamily::from(CommandCategory::Unknown),
            WorkflowFamily::Unknown
        );
    }

    #[test]
    fn strip_wrapper_nohup() {
        let stripped = strip_wrapper_launchers("nohup pytest -k test_foo");
        assert!(
            stripped.contains("pytest"),
            "should contain pytest: {stripped}"
        );
    }

    #[test]
    fn strip_wrapper_sudo() {
        let stripped = strip_wrapper_launchers("sudo npm start");
        assert!(stripped.contains("npm"), "should contain npm: {stripped}");
    }

    #[test]
    fn strip_no_wrapper() {
        let input = "pytest -k test_foo";
        let stripped = strip_wrapper_launchers(input);
        assert_eq!(stripped, input);
    }

    #[test]
    fn branch_context_recorded() {
        let ws = make_workspace("/home/user/project", "feature-auth");
        let result = classify_workflow_origin(CommandCategory::DevServer, "next", None, Some(&ws));

        assert!(result.signals.iter().any(|s| matches!(
            s,
            ClassificationSignal::BranchContext { branch } if branch == "feature-auth"
        )));
    }

    #[test]
    fn json_round_trip() {
        let ws = make_workspace("/project", "main");
        let result = classify_workflow_origin(CommandCategory::Test, "pytest", None, Some(&ws));

        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: WorkflowOriginClassification =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.family, result.family);
        assert_eq!(parsed.confidence, result.confidence);
    }
}
