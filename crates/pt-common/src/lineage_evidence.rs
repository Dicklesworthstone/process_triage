//! Canonical raw evidence inputs and normalization for process lineage,
//! session, TTY, and supervisor provenance.
//!
//! Defines how PPID ancestry, session IDs, controlling TTY, user boundaries,
//! and platform-specific supervisor markers are represented as normalized
//! evidence for provenance graph construction. Keeps parser quirks separate
//! from ownership inference.

use serde::{Deserialize, Serialize};

use crate::{ProvenanceConfidence, ProvenanceNodeId, ProvenanceNodeKind};

/// Schema version for lineage evidence normalization.
pub const LINEAGE_EVIDENCE_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Raw evidence inputs (what collectors provide)
// ---------------------------------------------------------------------------

/// Raw lineage and ownership evidence for a single process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawLineageEvidence {
    /// The process this evidence describes.
    pub pid: u32,
    /// Parent PID. `1` typically means orphaned (adopted by init/systemd).
    pub ppid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// Session ID (SID).
    pub sid: u32,
    /// UID of the process owner.
    pub uid: u32,
    /// Username of the process owner (if resolved).
    pub user: Option<String>,
    /// Controlling terminal, if any.
    pub tty: Option<TtyEvidence>,
    /// Detected supervisor information, if any.
    pub supervisor: Option<SupervisorEvidence>,
    /// Ancestor chain from this process up toward PID 1.
    /// Each entry is (pid, comm). May be truncated.
    pub ancestors: Vec<AncestorEntry>,
    /// How this evidence was collected.
    pub collection_method: LineageCollectionMethod,
    /// ISO-8601 timestamp of observation.
    pub observed_at: String,
}

/// A single ancestor in the process lineage chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestorEntry {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
}

/// TTY/terminal evidence for a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtyEvidence {
    /// The TTY device path or name (e.g., "/dev/pts/3", "?").
    pub device: String,
    /// Whether the process has a controlling terminal.
    pub has_controlling_tty: bool,
    /// Whether the process is a session leader.
    pub is_session_leader: bool,
    /// Whether the process is a process group leader.
    pub is_pgid_leader: bool,
}

/// Supervisor detection evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorEvidence {
    /// The type of supervisor detected.
    pub kind: SupervisorKind,
    /// The supervisor's unit/service name, if known.
    pub unit_name: Option<String>,
    /// Whether the supervisor is known to auto-restart on failure.
    pub auto_restart: Option<bool>,
    /// Confidence in the supervisor detection.
    pub confidence: ProvenanceConfidence,
}

/// Known supervisor types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorKind {
    /// systemd user or system service.
    Systemd,
    /// macOS launchd plist.
    Launchd,
    /// Docker/containerd process manager.
    Container,
    /// supervisord or similar process manager.
    Supervisord,
    /// tmux/screen session.
    TerminalMultiplexer,
    /// Shell job control (background process).
    ShellJob,
    /// Init system (PID 1 direct child with no other supervisor).
    Init,
    /// Unknown or no supervisor detected.
    Unknown,
}

/// How lineage evidence was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageCollectionMethod {
    /// Read from /proc filesystem.
    Procfs,
    /// Read from ps output.
    Ps,
    /// Read from lsof output.
    Lsof,
    /// Inferred from other evidence.
    Inferred,
    /// Synthetic/test evidence.
    Synthetic,
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Normalized ownership classification for a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedLineage {
    /// Stable identifier for this ownership context.
    pub lineage_id: String,
    /// The classified ownership state.
    pub ownership: OwnershipState,
    /// Whether this process is orphaned (PPID == 1 without a supervisor).
    pub is_orphaned: bool,
    /// Whether the process crossed a user boundary from its parent.
    pub crossed_user_boundary: bool,
    /// The session context.
    pub session: SessionContext,
    /// Confidence in this normalization.
    pub confidence: ProvenanceConfidence,
    /// Reasons for any confidence downgrade.
    pub downgrade_reasons: Vec<String>,
}

impl NormalizedLineage {
    /// Generate a provenance node ID for the supervisor, if applicable.
    pub fn supervisor_node_id(&self) -> Option<ProvenanceNodeId> {
        match &self.ownership {
            OwnershipState::Supervised { supervisor, .. } => {
                let key = format!(
                    "supervisor:{}:{}",
                    supervisor.kind.slug(),
                    supervisor.unit_name.as_deref().unwrap_or("unknown")
                );
                Some(ProvenanceNodeId::new(ProvenanceNodeKind::Supervisor, &key))
            }
            _ => None,
        }
    }

    /// Generate a provenance node ID for the session.
    pub fn session_node_id(&self) -> ProvenanceNodeId {
        let key = format!("session:sid={}", self.session.sid);
        ProvenanceNodeId::new(ProvenanceNodeKind::Session, &key)
    }
}

/// Classified ownership state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnershipState {
    /// Owned by an interactive shell (user started it).
    ShellOwned { shell_pid: u32, shell_comm: String },
    /// Managed by a service supervisor.
    Supervised { supervisor: SupervisorEvidence },
    /// Running inside an agent session.
    AgentOwned { agent_pid: u32, agent_comm: String },
    /// Orphaned — PPID is 1 with no supervisor.
    Orphaned,
    /// Owned by init/systemd directly (expected for system services).
    InitChild,
    /// Could not determine ownership.
    Unknown,
}

/// Session context information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    /// Session ID.
    pub sid: u32,
    /// Whether the process has a controlling TTY.
    pub has_tty: bool,
    /// The TTY device, if any.
    pub tty_device: Option<String>,
    /// Whether the process is the session leader.
    pub is_session_leader: bool,
}

impl SupervisorKind {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::Container => "container",
            Self::Supervisord => "supervisord",
            Self::TerminalMultiplexer => "tmux",
            Self::ShellJob => "shell_job",
            Self::Init => "init",
            Self::Unknown => "unknown",
        }
    }
}

/// Known shell command names for ownership classification.
const KNOWN_SHELLS: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "csh", "tcsh"];

/// Known agent command names.
const KNOWN_AGENTS: &[&str] = &[
    "claude", "codex", "copilot", "gemini", "cursor", "aider", "continue",
];

/// Known terminal multiplexers.
const KNOWN_MULTIPLEXERS: &[&str] = &["tmux", "screen", "zellij"];

/// Normalize raw lineage evidence into classified ownership.
pub fn normalize_lineage(evidence: &RawLineageEvidence) -> NormalizedLineage {
    let mut confidence = ProvenanceConfidence::High;
    let mut downgrade_reasons = Vec::new();

    // Check orphan status: PPID==1, no supervisor, AND no ancestors to explain why
    let is_orphaned =
        evidence.ppid == 1 && evidence.supervisor.is_none() && evidence.ancestors.is_empty();

    // Check user boundary crossing
    let crossed_user_boundary = evidence
        .ancestors
        .first()
        .is_some_and(|parent| parent.uid != evidence.uid);

    // Build session context
    let session = SessionContext {
        sid: evidence.sid,
        has_tty: evidence.tty.as_ref().is_some_and(|t| t.has_controlling_tty),
        tty_device: evidence.tty.as_ref().map(|t| t.device.clone()),
        is_session_leader: evidence.tty.as_ref().is_some_and(|t| t.is_session_leader),
    };

    // Classify ownership
    let ownership = classify_ownership(evidence, &mut confidence, &mut downgrade_reasons);

    // Generate stable lineage ID
    let lineage_id = format!(
        "lineage:pid={}:ppid={}:sid={}",
        evidence.pid, evidence.ppid, evidence.sid
    );

    NormalizedLineage {
        lineage_id,
        ownership,
        is_orphaned,
        crossed_user_boundary,
        session,
        confidence,
        downgrade_reasons,
    }
}

fn classify_ownership(
    evidence: &RawLineageEvidence,
    confidence: &mut ProvenanceConfidence,
    downgrade_reasons: &mut Vec<String>,
) -> OwnershipState {
    // If a supervisor was detected, that takes precedence
    if let Some(supervisor) = &evidence.supervisor {
        return OwnershipState::Supervised {
            supervisor: supervisor.clone(),
        };
    }

    // If PPID is 1 (init/systemd child)
    if evidence.ppid == 1 {
        // Check ancestors for context
        if evidence.ancestors.is_empty() {
            *confidence = downgrade(*confidence);
            downgrade_reasons.push(
                "PPID=1 with no ancestor chain; cannot distinguish init child from orphan"
                    .to_string(),
            );
            return OwnershipState::Orphaned;
        }
        return OwnershipState::InitChild;
    }

    // Walk ancestors to find the nearest shell or agent
    for ancestor in &evidence.ancestors {
        let comm_lower = ancestor.comm.to_lowercase();

        // Check for agent ownership
        if KNOWN_AGENTS.iter().any(|a| comm_lower.contains(a)) {
            return OwnershipState::AgentOwned {
                agent_pid: ancestor.pid,
                agent_comm: ancestor.comm.clone(),
            };
        }

        // Check for terminal multiplexer
        if KNOWN_MULTIPLEXERS.iter().any(|m| comm_lower.contains(m)) {
            return OwnershipState::Supervised {
                supervisor: SupervisorEvidence {
                    kind: SupervisorKind::TerminalMultiplexer,
                    unit_name: Some(ancestor.comm.clone()),
                    auto_restart: None,
                    confidence: ProvenanceConfidence::Medium,
                },
            };
        }

        // Check for shell ownership (stop at the first shell)
        if KNOWN_SHELLS.iter().any(|s| comm_lower == *s) {
            return OwnershipState::ShellOwned {
                shell_pid: ancestor.pid,
                shell_comm: ancestor.comm.clone(),
            };
        }
    }

    // No recognizable owner found
    if evidence.ancestors.is_empty() {
        *confidence = downgrade(*confidence);
        downgrade_reasons.push("no ancestors available; ownership is unknown".to_string());
    }

    OwnershipState::Unknown
}

fn downgrade(c: ProvenanceConfidence) -> ProvenanceConfidence {
    match c {
        ProvenanceConfidence::High => ProvenanceConfidence::Medium,
        ProvenanceConfidence::Medium => ProvenanceConfidence::Low,
        ProvenanceConfidence::Low | ProvenanceConfidence::Unknown => ProvenanceConfidence::Unknown,
    }
}

/// Canonical debug event name for lineage normalization.
pub const LINEAGE_EVIDENCE_NORMALIZED: &str = "provenance_lineage_evidence_normalized";
/// Canonical debug event name for lineage normalization failure.
pub const LINEAGE_EVIDENCE_MISSING: &str = "provenance_lineage_evidence_missing";

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_owned_evidence() -> RawLineageEvidence {
        RawLineageEvidence {
            pid: 1234,
            ppid: 500,
            pgid: 1234,
            sid: 500,
            uid: 1000,
            user: Some("alice".to_string()),
            tty: Some(TtyEvidence {
                device: "/dev/pts/3".to_string(),
                has_controlling_tty: true,
                is_session_leader: false,
                is_pgid_leader: true,
            }),
            supervisor: None,
            ancestors: vec![
                AncestorEntry {
                    pid: 500,
                    comm: "bash".to_string(),
                    uid: 1000,
                },
                AncestorEntry {
                    pid: 400,
                    comm: "sshd".to_string(),
                    uid: 0,
                },
            ],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        }
    }

    #[test]
    fn shell_owned_process() {
        let evidence = shell_owned_evidence();
        let result = normalize_lineage(&evidence);

        match &result.ownership {
            OwnershipState::ShellOwned {
                shell_pid,
                shell_comm,
            } => {
                assert_eq!(*shell_pid, 500);
                assert_eq!(shell_comm, "bash");
            }
            other => panic!("expected ShellOwned, got {other:?}"),
        }
        assert_eq!(result.confidence, ProvenanceConfidence::High);
        assert!(!result.is_orphaned);
        assert!(result.session.has_tty);
    }

    #[test]
    fn orphaned_process() {
        let evidence = RawLineageEvidence {
            pid: 9999,
            ppid: 1,
            pgid: 9999,
            sid: 9999,
            uid: 1000,
            user: Some("bob".to_string()),
            tty: None,
            supervisor: None,
            ancestors: vec![],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        assert_eq!(result.ownership, OwnershipState::Orphaned);
        assert!(result.is_orphaned);
        assert!(!result.session.has_tty);
        // Downgraded due to no ancestors
        assert!(result.confidence <= ProvenanceConfidence::Medium);
    }

    #[test]
    fn supervised_by_systemd() {
        let evidence = RawLineageEvidence {
            pid: 2000,
            ppid: 1,
            pgid: 2000,
            sid: 2000,
            uid: 0,
            user: Some("root".to_string()),
            tty: None,
            supervisor: Some(SupervisorEvidence {
                kind: SupervisorKind::Systemd,
                unit_name: Some("nginx.service".to_string()),
                auto_restart: Some(true),
                confidence: ProvenanceConfidence::High,
            }),
            ancestors: vec![],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        match &result.ownership {
            OwnershipState::Supervised { supervisor } => {
                assert_eq!(supervisor.kind, SupervisorKind::Systemd);
                assert_eq!(supervisor.unit_name.as_deref(), Some("nginx.service"));
            }
            other => panic!("expected Supervised, got {other:?}"),
        }
        assert!(!result.is_orphaned); // has supervisor
        assert_eq!(result.confidence, ProvenanceConfidence::High);
    }

    #[test]
    fn agent_owned_process() {
        let evidence = RawLineageEvidence {
            pid: 3000,
            ppid: 2500,
            pgid: 2500,
            sid: 2500,
            uid: 1000,
            user: Some("dev".to_string()),
            tty: Some(TtyEvidence {
                device: "/dev/pts/1".to_string(),
                has_controlling_tty: true,
                is_session_leader: false,
                is_pgid_leader: false,
            }),
            supervisor: None,
            ancestors: vec![
                AncestorEntry {
                    pid: 2500,
                    comm: "claude".to_string(),
                    uid: 1000,
                },
                AncestorEntry {
                    pid: 2000,
                    comm: "bash".to_string(),
                    uid: 1000,
                },
            ],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        match &result.ownership {
            OwnershipState::AgentOwned {
                agent_pid,
                agent_comm,
            } => {
                assert_eq!(*agent_pid, 2500);
                assert_eq!(agent_comm, "claude");
            }
            other => panic!("expected AgentOwned, got {other:?}"),
        }
    }

    #[test]
    fn tmux_detected_as_multiplexer() {
        let evidence = RawLineageEvidence {
            pid: 4000,
            ppid: 3500,
            pgid: 3500,
            sid: 3500,
            uid: 1000,
            user: None,
            tty: None,
            supervisor: None,
            ancestors: vec![AncestorEntry {
                pid: 3500,
                comm: "tmux: server".to_string(),
                uid: 1000,
            }],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        match &result.ownership {
            OwnershipState::Supervised { supervisor } => {
                assert_eq!(supervisor.kind, SupervisorKind::TerminalMultiplexer);
            }
            other => panic!("expected Supervised(TerminalMultiplexer), got {other:?}"),
        }
    }

    #[test]
    fn user_boundary_crossing() {
        let mut evidence = shell_owned_evidence();
        // Parent has different UID (sshd runs as root)
        evidence.ancestors[0].uid = 0;

        let result = normalize_lineage(&evidence);
        assert!(result.crossed_user_boundary);
    }

    #[test]
    fn no_user_boundary_crossing() {
        let evidence = shell_owned_evidence();
        let result = normalize_lineage(&evidence);
        assert!(!result.crossed_user_boundary);
    }

    #[test]
    fn init_child_with_ancestors() {
        let evidence = RawLineageEvidence {
            pid: 5000,
            ppid: 1,
            pgid: 5000,
            sid: 5000,
            uid: 0,
            user: Some("root".to_string()),
            tty: None,
            supervisor: None,
            ancestors: vec![AncestorEntry {
                pid: 1,
                comm: "systemd".to_string(),
                uid: 0,
            }],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        assert_eq!(result.ownership, OwnershipState::InitChild);
        assert!(!result.is_orphaned); // has ancestors showing init
    }

    #[test]
    fn unknown_ownership_no_ancestors() {
        let evidence = RawLineageEvidence {
            pid: 6000,
            ppid: 999,
            pgid: 6000,
            sid: 6000,
            uid: 1000,
            user: None,
            tty: None,
            supervisor: None,
            ancestors: vec![],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        assert_eq!(result.ownership, OwnershipState::Unknown);
        assert!(result.confidence <= ProvenanceConfidence::Medium);
    }

    #[test]
    fn supervisor_node_id_is_deterministic() {
        let evidence = RawLineageEvidence {
            pid: 7000,
            ppid: 1,
            pgid: 7000,
            sid: 7000,
            uid: 0,
            user: None,
            tty: None,
            supervisor: Some(SupervisorEvidence {
                kind: SupervisorKind::Systemd,
                unit_name: Some("my.service".to_string()),
                auto_restart: None,
                confidence: ProvenanceConfidence::High,
            }),
            ancestors: vec![],
            collection_method: LineageCollectionMethod::Procfs,
            observed_at: "2026-03-15T20:00:00Z".to_string(),
        };

        let result = normalize_lineage(&evidence);
        let id1 = result.supervisor_node_id().expect("should have supervisor");
        let id2 = result.supervisor_node_id().expect("should have supervisor");
        assert_eq!(id1, id2);
        assert!(id1.0.starts_with("pn_supervisor_"));
    }

    #[test]
    fn session_node_id_is_deterministic() {
        let evidence = shell_owned_evidence();
        let result = normalize_lineage(&evidence);
        let id1 = result.session_node_id();
        let id2 = result.session_node_id();
        assert_eq!(id1, id2);
        assert!(id1.0.starts_with("pn_session_"));
    }

    #[test]
    fn json_round_trip() {
        let evidence = shell_owned_evidence();
        let result = normalize_lineage(&evidence);
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: NormalizedLineage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.ownership, result.ownership);
        assert_eq!(parsed.confidence, result.confidence);
    }

    #[test]
    fn supervisor_kind_slugs() {
        assert_eq!(SupervisorKind::Systemd.slug(), "systemd");
        assert_eq!(SupervisorKind::Launchd.slug(), "launchd");
        assert_eq!(SupervisorKind::Container.slug(), "container");
        assert_eq!(SupervisorKind::TerminalMultiplexer.slug(), "tmux");
        assert_eq!(SupervisorKind::Init.slug(), "init");
    }
}
