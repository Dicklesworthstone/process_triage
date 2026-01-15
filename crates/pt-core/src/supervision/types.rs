//! Types for process supervision detection.
//!
//! This module defines the data structures for representing supervisor
//! detection results and patterns.

use pt_common::ProcessId;
use serde::{Deserialize, Serialize};

/// Category of supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorCategory {
    /// AI coding agents (Claude, Codex, Aider, Cursor).
    Agent,
    /// IDEs and development tools (VS Code, JetBrains).
    Ide,
    /// CI/CD systems (GitHub Actions, GitLab Runner, Jenkins).
    Ci,
    /// Process orchestrators (systemd, launchd).
    Orchestrator,
    /// Terminal multiplexers (tmux, screen).
    Terminal,
    /// Other known supervisors.
    Other,
}

impl std::fmt::Display for SupervisorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SupervisorCategory::Agent => "agent",
            SupervisorCategory::Ide => "ide",
            SupervisorCategory::Ci => "ci",
            SupervisorCategory::Orchestrator => "orchestrator",
            SupervisorCategory::Terminal => "terminal",
            SupervisorCategory::Other => "other",
        };
        write!(f, "{}", s)
    }
}

/// Entry in the process ancestry chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AncestryEntry {
    /// Process ID.
    pub pid: ProcessId,
    /// Command name.
    pub comm: String,
    /// Full command line (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

/// Result of supervisor detection for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisionResult {
    /// Whether the process is supervised.
    pub is_supervised: bool,
    /// The supervisor type if detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_type: Option<SupervisorCategory>,
    /// Name of the supervisor (e.g., "claude-code", "vscode").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_name: Option<String>,
    /// PID of the supervisor ancestor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_pid: Option<ProcessId>,
    /// How many levels up in the tree the supervisor was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Evidence that led to this detection.
    pub evidence: Vec<SupervisionEvidence>,
    /// Full ancestry chain from process to root.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ancestry_chain: Vec<AncestryEntry>,
}

impl SupervisionResult {
    /// Create a result indicating no supervision detected.
    pub fn not_supervised(ancestry_chain: Vec<AncestryEntry>) -> Self {
        Self {
            is_supervised: false,
            supervisor_type: None,
            supervisor_name: None,
            supervisor_pid: None,
            depth: None,
            confidence: 1.0,
            evidence: vec![],
            ancestry_chain,
        }
    }

    /// Create a result indicating supervision detected via ancestry.
    pub fn supervised_by_ancestry(
        supervisor_type: SupervisorCategory,
        supervisor_name: String,
        supervisor_pid: ProcessId,
        depth: u32,
        confidence: f64,
        evidence: Vec<SupervisionEvidence>,
        ancestry_chain: Vec<AncestryEntry>,
    ) -> Self {
        Self {
            is_supervised: true,
            supervisor_type: Some(supervisor_type),
            supervisor_name: Some(supervisor_name),
            supervisor_pid: Some(supervisor_pid),
            depth: Some(depth),
            confidence,
            evidence,
            ancestry_chain,
        }
    }
}

/// Evidence for supervision detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisionEvidence {
    /// Type of evidence.
    pub evidence_type: EvidenceType,
    /// Description of what was found.
    pub description: String,
    /// Weight of this evidence (higher = more significant).
    pub weight: f64,
}

/// Types of evidence for supervision detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Process name matches supervisor pattern.
    ProcessName,
    /// Ancestor in process tree matches supervisor.
    Ancestry,
    /// Environment variable indicates supervision.
    Environment,
    /// Socket connection to supervisor IPC.
    Socket,
    /// PID file indicates orchestrator management.
    PidFile,
    /// TTY indicates terminal supervision.
    Tty,
    /// Signal mask analysis (e.g., SIGHUP ignored for nohup).
    SignalMask,
    /// Command line pattern (e.g., nohup prefix).
    CommandLine,
    /// File descriptor analysis (stdout/stderr redirection).
    FileDescriptor,
    /// File activity analysis (e.g., nohup.out being written).
    FileActivity,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EvidenceType::ProcessName => "process_name",
            EvidenceType::Ancestry => "ancestry",
            EvidenceType::Environment => "environment",
            EvidenceType::Socket => "socket",
            EvidenceType::PidFile => "pid_file",
            EvidenceType::Tty => "tty",
            EvidenceType::SignalMask => "signal_mask",
            EvidenceType::CommandLine => "command_line",
            EvidenceType::FileDescriptor => "file_descriptor",
            EvidenceType::FileActivity => "file_activity",
        };
        write!(f, "{}", s)
    }
}

/// A supervisor signature pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorPattern {
    /// Human-readable name.
    pub name: String,
    /// Category of supervisor.
    pub category: SupervisorCategory,
    /// Process name patterns (regex).
    pub process_patterns: Vec<String>,
    /// Weight for confidence calculation.
    pub confidence_weight: f64,
    /// Notes about this supervisor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl SupervisorPattern {
    /// Create a new supervisor pattern.
    pub fn new(
        name: impl Into<String>,
        category: SupervisorCategory,
        patterns: Vec<&str>,
        weight: f64,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            process_patterns: patterns.into_iter().map(String::from).collect(),
            confidence_weight: weight,
            notes: None,
        }
    }

    /// Add notes to this pattern.
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Collection of supervisor patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupervisorDatabase {
    /// Loaded patterns.
    pub patterns: Vec<SupervisorPattern>,
}

impl SupervisorDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self { patterns: vec![] }
    }

    /// Create with default bundled patterns.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.add_default_patterns();
        db
    }

    /// Add a pattern to the database.
    pub fn add(&mut self, pattern: SupervisorPattern) {
        self.patterns.push(pattern);
    }

    /// Add all default bundled patterns.
    pub fn add_default_patterns(&mut self) {
        // AI Agents
        self.add(
            SupervisorPattern::new(
                "claude",
                SupervisorCategory::Agent,
                vec![r"^claude$", r"^claude-code$", r"^claude-cli$"],
                0.95,
            )
            .with_notes("Anthropic Claude AI agent"),
        );

        self.add(
            SupervisorPattern::new(
                "codex",
                SupervisorCategory::Agent,
                vec![r"^codex$", r"^codex-cli$"],
                0.95,
            )
            .with_notes("OpenAI Codex CLI agent"),
        );

        self.add(
            SupervisorPattern::new(
                "aider",
                SupervisorCategory::Agent,
                vec![r"^aider$", r"^aider-chat$"],
                0.90,
            )
            .with_notes("Aider AI pair programming"),
        );

        self.add(
            SupervisorPattern::new(
                "cursor",
                SupervisorCategory::Agent,
                vec![r"^cursor$", r"^Cursor$", r"^cursor-agent$"],
                0.90,
            )
            .with_notes("Cursor IDE with AI"),
        );

        // IDEs
        self.add(
            SupervisorPattern::new(
                "vscode",
                SupervisorCategory::Ide,
                vec![r"^code$", r"^code-server$", r"^Code$", r"^code-oss$"],
                0.85,
            )
            .with_notes("Visual Studio Code"),
        );

        self.add(
            SupervisorPattern::new(
                "jetbrains",
                SupervisorCategory::Ide,
                vec![
                    r"^idea$",
                    r"^pycharm$",
                    r"^webstorm$",
                    r"^goland$",
                    r"^clion$",
                    r"^rider$",
                    r"^rubymine$",
                    r"^phpstorm$",
                ],
                0.85,
            )
            .with_notes("JetBrains IDEs"),
        );

        self.add(
            SupervisorPattern::new(
                "nvim-lsp",
                SupervisorCategory::Ide,
                vec![r"^nvim$", r"^vim$"],
                0.60,
            )
            .with_notes("Neovim/Vim (with LSP)"),
        );

        // CI/CD
        self.add(
            SupervisorPattern::new(
                "github-actions",
                SupervisorCategory::Ci,
                vec![r"^Runner\.Worker$", r"^actions-runner$", r"^runner$"],
                0.95,
            )
            .with_notes("GitHub Actions runner"),
        );

        self.add(
            SupervisorPattern::new(
                "gitlab-runner",
                SupervisorCategory::Ci,
                vec![r"^gitlab-runner$", r"^gitlab-ci$"],
                0.95,
            )
            .with_notes("GitLab Runner"),
        );

        self.add(
            SupervisorPattern::new(
                "jenkins",
                SupervisorCategory::Ci,
                vec![r"^java.*jenkins", r"^jenkins$"],
                0.90,
            )
            .with_notes("Jenkins CI"),
        );

        // Terminal Multiplexers
        self.add(
            SupervisorPattern::new(
                "tmux",
                SupervisorCategory::Terminal,
                vec![r"^tmux: server$", r"^tmux$"],
                0.70,
            )
            .with_notes("tmux terminal multiplexer"),
        );

        self.add(
            SupervisorPattern::new(
                "screen",
                SupervisorCategory::Terminal,
                vec![r"^SCREEN$", r"^screen$"],
                0.70,
            )
            .with_notes("GNU Screen"),
        );

        // Orchestrators
        self.add(
            SupervisorPattern::new(
                "systemd",
                SupervisorCategory::Orchestrator,
                vec![r"^systemd$", r"^systemd-.*$"],
                0.95,
            )
            .with_notes("systemd init system"),
        );

        self.add(
            SupervisorPattern::new(
                "launchd",
                SupervisorCategory::Orchestrator,
                vec![r"^launchd$"],
                0.95,
            )
            .with_notes("macOS launchd"),
        );

        // Process managers
        self.add(
            SupervisorPattern::new(
                "pm2",
                SupervisorCategory::Orchestrator,
                vec![r"^PM2$", r"^pm2$", r"^PM2 v\d"],
                0.90,
            )
            .with_notes("PM2 process manager"),
        );

        self.add(
            SupervisorPattern::new(
                "supervisord",
                SupervisorCategory::Orchestrator,
                vec![r"^supervisord$", r"^python.*supervisord"],
                0.90,
            )
            .with_notes("Supervisor daemon"),
        );
    }

    /// Find matching patterns for a process name.
    pub fn find_matches(&self, comm: &str) -> Vec<&SupervisorPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                p.process_patterns.iter().any(|pattern| {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(comm))
                        .unwrap_or(false)
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_category_display() {
        assert_eq!(SupervisorCategory::Agent.to_string(), "agent");
        assert_eq!(SupervisorCategory::Ide.to_string(), "ide");
        assert_eq!(SupervisorCategory::Ci.to_string(), "ci");
    }

    #[test]
    fn test_supervision_result_not_supervised() {
        let result = SupervisionResult::not_supervised(vec![]);
        assert!(!result.is_supervised);
        assert!(result.supervisor_type.is_none());
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_supervision_result_supervised() {
        let result = SupervisionResult::supervised_by_ancestry(
            SupervisorCategory::Agent,
            "claude".to_string(),
            ProcessId(1234),
            2,
            0.95,
            vec![],
            vec![],
        );
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_type, Some(SupervisorCategory::Agent));
        assert_eq!(result.depth, Some(2));
    }

    #[test]
    fn test_supervisor_database_defaults() {
        let db = SupervisorDatabase::with_defaults();
        assert!(!db.patterns.is_empty());

        // Check some patterns exist
        let claude_matches = db.find_matches("claude");
        assert!(!claude_matches.is_empty());
        assert_eq!(claude_matches[0].category, SupervisorCategory::Agent);

        let vscode_matches = db.find_matches("code");
        assert!(!vscode_matches.is_empty());
        assert_eq!(vscode_matches[0].category, SupervisorCategory::Ide);
    }

    #[test]
    fn test_supervisor_database_no_match() {
        let db = SupervisorDatabase::with_defaults();
        let matches = db.find_matches("my-custom-app");
        assert!(matches.is_empty());
    }
}
