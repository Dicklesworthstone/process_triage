//! Genealogy narrative rendering for process ancestry chains.
//!
//! Provides deterministic, human-readable summaries of a process'
//! ancestry chain for agent/human explainability, with role annotations
//! and structured JSON genealogy output.

use serde::{Deserialize, Serialize};

use super::AncestryEntry;

// ---------------------------------------------------------------------------
// Role annotation
// ---------------------------------------------------------------------------

/// Annotated role for a process in an ancestry chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    /// Target process being analysed.
    Target,
    /// Interactive user shell (bash, zsh, fish, sh).
    UserShell,
    /// Terminal multiplexer (tmux, screen).
    Multiplexer,
    /// Test runner (pytest, jest, cargo-test, go test).
    TestRunner,
    /// Process supervisor / init (systemd, supervisord, launchd, s6, runit).
    Supervisor,
    /// Container runtime (containerd-shim, docker, podman).
    ContainerRuntime,
    /// CI runner (github-runner, gitlab-runner, jenkins-agent).
    CiRunner,
    /// Web server / application server.
    Server,
    /// Worker / child process (generic).
    Worker,
    /// SSH daemon or session.
    SshSession,
    /// Init / PID 1.
    Init,
    /// Unknown role.
    Unknown,
}

impl ProcessRole {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::UserShell => "user shell",
            Self::Multiplexer => "multiplexer",
            Self::TestRunner => "test runner",
            Self::Supervisor => "supervisor",
            Self::ContainerRuntime => "container runtime",
            Self::CiRunner => "CI runner",
            Self::Server => "server",
            Self::Worker => "worker",
            Self::SshSession => "SSH session",
            Self::Init => "init",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ProcessRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Classify a process command name into a role.
///
/// Rules are deterministic and applied in priority order.
pub fn classify_role(comm: &str, is_target: bool, is_pid1: bool) -> ProcessRole {
    if is_target {
        return ProcessRole::Target;
    }
    if is_pid1 {
        return ProcessRole::Init;
    }

    let c = comm.to_lowercase();

    // Supervisors / init systems.
    if matches!(
        c.as_str(),
        "systemd" | "supervisord" | "launchd" | "s6-svscan" | "runit" | "openrc" | "upstart"
    ) {
        return ProcessRole::Supervisor;
    }

    // Shells.
    if matches!(
        c.as_str(),
        "bash" | "zsh" | "fish" | "sh" | "dash" | "ksh" | "csh" | "tcsh"
    ) {
        return ProcessRole::UserShell;
    }

    // Terminal multiplexers.
    if c.starts_with("tmux") || c == "screen" {
        return ProcessRole::Multiplexer;
    }

    // SSH.
    if c == "sshd" || c == "ssh" {
        return ProcessRole::SshSession;
    }

    // Test runners.
    if c.contains("pytest")
        || c.contains("jest")
        || c.contains("cargo-test")
        || c.contains("go-test")
        || c == "test"
        || c.contains("mocha")
        || c.contains("rspec")
    {
        return ProcessRole::TestRunner;
    }

    // CI runners.
    if c.contains("runner") && (c.contains("github") || c.contains("gitlab"))
        || c.contains("jenkins")
        || c == "buildkite-agent"
    {
        return ProcessRole::CiRunner;
    }

    // Container runtimes.
    if c.contains("containerd") || c == "dockerd" || c == "podman" || c == "crio" {
        return ProcessRole::ContainerRuntime;
    }

    // Servers.
    if c.contains("nginx")
        || c.contains("apache")
        || c.contains("httpd")
        || c.contains("gunicorn")
        || c.contains("uvicorn")
        || c.contains("node")
        || c.contains("java")
    {
        return ProcessRole::Server;
    }

    ProcessRole::Unknown
}

// ---------------------------------------------------------------------------
// Structured genealogy
// ---------------------------------------------------------------------------

/// A single annotated node in a genealogy chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenealogyNode {
    pub pid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    pub role: ProcessRole,
    /// Depth in chain (0 = target, 1 = parent, 2 = grandparent, …).
    pub depth: usize,
}

/// Structured genealogy for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genealogy {
    pub nodes: Vec<GenealogyNode>,
    pub narrative: String,
    pub narrative_brief: String,
}

/// Build a full genealogy from an ancestry chain.
pub fn build_genealogy(chain: &[AncestryEntry]) -> Genealogy {
    let nodes: Vec<GenealogyNode> = chain
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_target = i == 0;
            let is_pid1 = entry.pid.0 == 1;
            GenealogyNode {
                pid: entry.pid.0,
                comm: entry.comm.clone(),
                cmdline: entry.cmdline.clone(),
                role: classify_role(&entry.comm, is_target, is_pid1),
                depth: i,
            }
        })
        .collect();

    let narrative = render_annotated_narrative(&nodes, NarrativeStyle::Standard);
    let narrative_brief = render_annotated_narrative(&nodes, NarrativeStyle::Brief);

    Genealogy {
        nodes,
        narrative,
        narrative_brief,
    }
}

// ---------------------------------------------------------------------------
// Narrative rendering
// ---------------------------------------------------------------------------

/// Narrative verbosity presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrativeStyle {
    /// Minimal summary: only target + immediate parent.
    Brief,
    /// Default summary: include full chain with roles.
    Standard,
    /// Detailed summary: include cmdline where available.
    Detailed,
}

/// Render a genealogy narrative with standard verbosity.
pub fn render_narrative(chain: &[AncestryEntry]) -> String {
    render_narrative_with_style(chain, NarrativeStyle::Standard)
}

/// Render a genealogy narrative with a selected style.
pub fn render_narrative_with_style(chain: &[AncestryEntry], style: NarrativeStyle) -> String {
    if chain.is_empty() {
        return "No ancestry information available.".to_string();
    }

    let target = &chain[0];
    if chain.len() == 1 {
        return format!(
            "Process '{}' (PID {}) has no recorded parent.",
            target.comm, target.pid.0
        );
    }

    let limit = match style {
        NarrativeStyle::Brief => 2,
        NarrativeStyle::Standard | NarrativeStyle::Detailed => chain.len(),
    };

    let mut narrative = format!(
        "Process '{}' (PID {}) was spawned by '{}' (PID {})",
        target.comm, target.pid.0, chain[1].comm, chain[1].pid.0
    );

    if chain.len() == 2 && chain[1].pid.0 == 1 {
        narrative.push_str(" and appears orphaned (parent is init)");
    }

    if limit > 2 {
        for entry in chain.iter().skip(2).take(limit - 2) {
            narrative.push_str(&format!(
                ", which was spawned by '{}' (PID {})",
                entry.comm, entry.pid.0
            ));
        }
    }

    if limit < chain.len() {
        narrative.push_str(&format!(
            ", and {} more ancestor(s)",
            chain.len().saturating_sub(limit)
        ));
    }

    narrative.push('.');
    narrative
}

/// Render a narrative from pre-annotated genealogy nodes (includes role labels).
fn render_annotated_narrative(nodes: &[GenealogyNode], style: NarrativeStyle) -> String {
    if nodes.is_empty() {
        return "No ancestry information available.".to_string();
    }

    let target = &nodes[0];
    if nodes.len() == 1 {
        return format!(
            "Process '{}' (PID {}) has no recorded parent.",
            target.comm, target.pid
        );
    }

    let limit = match style {
        NarrativeStyle::Brief => 2,
        NarrativeStyle::Standard | NarrativeStyle::Detailed => nodes.len(),
    };

    let parent = &nodes[1];
    let parent_role = if parent.role != ProcessRole::Unknown {
        format!(" [{}]", parent.role.label())
    } else {
        String::new()
    };

    let mut narrative = format!(
        "Process '{}' (PID {}) was spawned by '{}' (PID {}){}",
        target.comm, target.pid, parent.comm, parent.pid, parent_role,
    );

    if nodes.len() == 2 && parent.pid == 1 {
        narrative.push_str(" and appears orphaned (parent is init)");
    }

    if limit > 2 {
        for node in nodes.iter().skip(2).take(limit - 2) {
            let role_tag = if node.role != ProcessRole::Unknown {
                format!(" [{}]", node.role.label())
            } else {
                String::new()
            };
            narrative.push_str(&format!(
                ", which was spawned by '{}' (PID {}){}",
                node.comm, node.pid, role_tag,
            ));
        }
    }

    if limit < nodes.len() {
        narrative.push_str(&format!(
            ", and {} more ancestor(s)",
            nodes.len().saturating_sub(limit)
        ));
    }

    narrative.push('.');
    narrative
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::ProcessId;

    fn entry(pid: u32, comm: &str) -> AncestryEntry {
        AncestryEntry {
            pid: ProcessId(pid),
            comm: comm.to_string(),
            cmdline: None,
        }
    }

    #[test]
    fn narrative_empty_chain() {
        let narrative = render_narrative(&[]);
        assert!(narrative.contains("No ancestry information"));
    }

    #[test]
    fn narrative_orphan_detection() {
        let chain = vec![entry(1234, "node"), entry(1, "init")];
        let narrative = render_narrative(&chain);
        assert!(narrative.contains("orphaned"));
    }

    #[test]
    fn narrative_brief_truncates() {
        let chain = vec![entry(100, "node"), entry(90, "bash"), entry(1, "init")];
        let narrative = render_narrative_with_style(&chain, NarrativeStyle::Brief);
        assert!(narrative.contains("and 1 more ancestor"));
    }

    // --- Role classification tests ---

    #[test]
    fn classify_role_shells() {
        assert_eq!(classify_role("bash", false, false), ProcessRole::UserShell);
        assert_eq!(classify_role("zsh", false, false), ProcessRole::UserShell);
        assert_eq!(classify_role("fish", false, false), ProcessRole::UserShell);
    }

    #[test]
    fn classify_role_supervisors() {
        assert_eq!(
            classify_role("systemd", false, false),
            ProcessRole::Supervisor
        );
        assert_eq!(
            classify_role("supervisord", false, false),
            ProcessRole::Supervisor
        );
    }

    #[test]
    fn classify_role_target_overrides() {
        assert_eq!(classify_role("bash", true, false), ProcessRole::Target);
    }

    #[test]
    fn classify_role_pid1() {
        assert_eq!(classify_role("anything", false, true), ProcessRole::Init);
    }

    #[test]
    fn classify_role_multiplexer() {
        assert_eq!(
            classify_role("tmux: server", false, false),
            ProcessRole::Multiplexer
        );
        assert_eq!(
            classify_role("screen", false, false),
            ProcessRole::Multiplexer
        );
    }

    #[test]
    fn classify_role_test_runner() {
        assert_eq!(
            classify_role("pytest", false, false),
            ProcessRole::TestRunner
        );
    }

    #[test]
    fn classify_role_ssh() {
        assert_eq!(classify_role("sshd", false, false), ProcessRole::SshSession);
    }

    #[test]
    fn classify_role_container() {
        assert_eq!(
            classify_role("containerd-shim", false, false),
            ProcessRole::ContainerRuntime
        );
    }

    #[test]
    fn classify_role_unknown() {
        assert_eq!(
            classify_role("my_custom_app", false, false),
            ProcessRole::Unknown
        );
    }

    // --- Genealogy tests ---

    #[test]
    fn build_genealogy_basic() {
        let chain = vec![
            entry(500, "worker"),
            entry(400, "bash"),
            entry(1, "systemd"),
        ];
        let gen = build_genealogy(&chain);

        assert_eq!(gen.nodes.len(), 3);
        assert_eq!(gen.nodes[0].role, ProcessRole::Target);
        assert_eq!(gen.nodes[1].role, ProcessRole::UserShell);
        assert_eq!(gen.nodes[2].role, ProcessRole::Init);
    }

    #[test]
    fn build_genealogy_narrative_includes_roles() {
        let chain = vec![
            entry(500, "worker"),
            entry(400, "bash"),
            entry(300, "tmux: server"),
            entry(1, "systemd"),
        ];
        let gen = build_genealogy(&chain);

        assert!(gen.narrative.contains("[user shell]"));
        assert!(gen.narrative.contains("[multiplexer]"));
        assert!(gen.narrative.contains("[init]"));
    }

    #[test]
    fn build_genealogy_brief_is_shorter() {
        let chain = vec![
            entry(500, "worker"),
            entry(400, "bash"),
            entry(300, "sshd"),
            entry(1, "systemd"),
        ];
        let gen = build_genealogy(&chain);

        assert!(gen.narrative_brief.len() < gen.narrative.len());
        assert!(gen.narrative_brief.contains("more ancestor"));
    }

    #[test]
    fn genealogy_serialization() {
        let chain = vec![entry(100, "node"), entry(90, "bash")];
        let gen = build_genealogy(&chain);
        let json = serde_json::to_string(&gen).unwrap();
        let restored: Genealogy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.nodes.len(), 2);
        assert_eq!(restored.nodes[0].role, ProcessRole::Target);
    }

    #[test]
    fn genealogy_empty_chain() {
        let gen = build_genealogy(&[]);
        assert!(gen.nodes.is_empty());
        assert!(gen.narrative.contains("No ancestry"));
    }

    #[test]
    fn genealogy_orphan_narrative() {
        let chain = vec![entry(1234, "worker"), entry(1, "init")];
        let gen = build_genealogy(&chain);
        assert!(gen.narrative.contains("orphaned"));
    }
}
