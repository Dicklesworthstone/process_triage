//! Shared provenance graph schema and deterministic identifiers.
//!
//! This module defines the canonical graph entities used to explain why a
//! process exists, what it is connected to, and how strongly those claims are
//! supported. Collector and inference layers should populate these types rather
//! than inventing one-off JSON payloads.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProcessId, StartId};

/// Schema version for persisted provenance graphs.
pub const PROVENANCE_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical identifier for a graph node.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ProvenanceNodeId(pub String);

impl ProvenanceNodeId {
    pub fn new(kind: ProvenanceNodeKind, stable_key: &str) -> Self {
        Self(format!(
            "pn_{}_{}",
            kind.as_slug(),
            short_hash(stable_key.as_bytes())
        ))
    }
}

impl fmt::Display for ProvenanceNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canonical identifier for an edge between two nodes.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ProvenanceEdgeId(pub String);

impl ProvenanceEdgeId {
    pub fn new(kind: ProvenanceEdgeKind, from: &ProvenanceNodeId, to: &ProvenanceNodeId) -> Self {
        Self(format!(
            "pe_{}_{}",
            kind.as_slug(),
            short_hash(format!("{}>{}", from.0, to.0).as_bytes())
        ))
    }
}

impl fmt::Display for ProvenanceEdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canonical identifier for an observed or derived evidence item.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ProvenanceEvidenceId(pub String);

impl ProvenanceEvidenceId {
    pub fn new(kind: ProvenanceEvidenceKind, stable_key: &str) -> Self {
        Self(format!(
            "pv_{}_{}",
            kind.as_slug(),
            short_hash(stable_key.as_bytes())
        ))
    }
}

impl fmt::Display for ProvenanceEvidenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceNodeKind {
    Process,
    Session,
    Workspace,
    Repo,
    Resource,
    Supervisor,
    Actor,
    Host,
}

impl ProvenanceNodeKind {
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Session => "session",
            Self::Workspace => "workspace",
            Self::Repo => "repo",
            Self::Resource => "resource",
            Self::Supervisor => "supervisor",
            Self::Actor => "actor",
            Self::Host => "host",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEdgeKind {
    Spawned,
    SupervisedBy,
    OwnedBy,
    AttachedToWorkspace,
    AttachedToRepo,
    UsesResource,
    ListensOn,
    HoldsLock,
    PartOfSession,
    ObservedOnHost,
    DerivedFrom,
    Impacts,
}

impl ProvenanceEdgeKind {
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::SupervisedBy => "supervised_by",
            Self::OwnedBy => "owned_by",
            Self::AttachedToWorkspace => "attached_to_workspace",
            Self::AttachedToRepo => "attached_to_repo",
            Self::UsesResource => "uses_resource",
            Self::ListensOn => "listens_on",
            Self::HoldsLock => "holds_lock",
            Self::PartOfSession => "part_of_session",
            Self::ObservedOnHost => "observed_on_host",
            Self::DerivedFrom => "derived_from",
            Self::Impacts => "impacts",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEvidenceKind {
    Procfs,
    Ps,
    Lsof,
    Ss,
    Cgroup,
    Systemd,
    Launchd,
    Filesystem,
    Git,
    Env,
    CommandLine,
    Config,
    Derived,
    Manual,
}

impl ProvenanceEvidenceKind {
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::Procfs => "procfs",
            Self::Ps => "ps",
            Self::Lsof => "lsof",
            Self::Ss => "ss",
            Self::Cgroup => "cgroup",
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::Filesystem => "filesystem",
            Self::Git => "git",
            Self::Env => "env",
            Self::CommandLine => "command_line",
            Self::Config => "config",
            Self::Derived => "derived",
            Self::Manual => "manual",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceObservationStatus {
    Observed,
    Derived,
    Missing,
    Partial,
    Conflicted,
    Redacted,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRedactionState {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceProcessRef {
    pub pid: ProcessId,
    pub start_id: StartId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceEvidence {
    pub id: ProvenanceEvidenceId,
    pub kind: ProvenanceEvidenceKind,
    pub source: String,
    pub observed_at: String,
    pub status: ProvenanceObservationStatus,
    pub confidence: ProvenanceConfidence,
    pub redaction: ProvenanceRedactionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProvenanceProcessRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceNode {
    pub id: ProvenanceNodeId,
    pub kind: ProvenanceNodeKind,
    pub label: String,
    pub confidence: ProvenanceConfidence,
    pub redaction: ProvenanceRedactionState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<ProvenanceEvidenceId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceEdge {
    pub id: ProvenanceEdgeId,
    pub kind: ProvenanceEdgeKind,
    pub from: ProvenanceNodeId,
    pub to: ProvenanceNodeId,
    pub confidence: ProvenanceConfidence,
    pub redaction: ProvenanceRedactionState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<ProvenanceEvidenceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from_edge_ids: Vec<ProvenanceEdgeId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceGraphWarning {
    pub code: String,
    pub message: String,
    pub confidence: ProvenanceConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<ProvenanceEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceGraphSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub evidence_count: usize,
    pub redacted_evidence_count: usize,
    pub missing_or_conflicted_evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceGraphSnapshot {
    pub schema_version: String,
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub summary: ProvenanceGraphSummary,
    pub nodes: Vec<ProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
    pub evidence: Vec<ProvenanceEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ProvenanceGraphWarning>,
}

impl ProvenanceGraphSnapshot {
    pub fn new(
        generated_at: String,
        session_id: Option<String>,
        host_id: Option<String>,
        nodes: Vec<ProvenanceNode>,
        edges: Vec<ProvenanceEdge>,
        evidence: Vec<ProvenanceEvidence>,
        warnings: Vec<ProvenanceGraphWarning>,
    ) -> Self {
        let redacted_evidence_count = evidence
            .iter()
            .filter(|item| item.redaction != ProvenanceRedactionState::None)
            .count();
        let missing_or_conflicted_evidence_count = evidence
            .iter()
            .filter(|item| {
                matches!(
                    item.status,
                    ProvenanceObservationStatus::Missing
                        | ProvenanceObservationStatus::Partial
                        | ProvenanceObservationStatus::Conflicted
                )
            })
            .count();

        Self {
            schema_version: PROVENANCE_SCHEMA_VERSION.to_string(),
            generated_at,
            session_id,
            host_id,
            summary: ProvenanceGraphSummary {
                node_count: nodes.len(),
                edge_count: edges.len(),
                evidence_count: evidence.len(),
                redacted_evidence_count,
                missing_or_conflicted_evidence_count,
            },
            nodes,
            edges,
            evidence,
            warnings,
        }
    }
}

fn short_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> ProvenanceGraphSnapshot {
        let evidence_id = ProvenanceEvidenceId::new(
            ProvenanceEvidenceKind::Procfs,
            "procfs:pid=123:start=boot:99:123",
        );
        let process_id =
            ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:123:boot-1:99:123");
        let workspace_id =
            ProvenanceNodeId::new(ProvenanceNodeKind::Workspace, "workspace:/repo/worktree");
        let edge_id = ProvenanceEdgeId::new(
            ProvenanceEdgeKind::AttachedToWorkspace,
            &process_id,
            &workspace_id,
        );

        let evidence = ProvenanceEvidence {
            id: evidence_id.clone(),
            kind: ProvenanceEvidenceKind::Procfs,
            source: "/proc/123/stat".to_string(),
            observed_at: "2026-03-15T01:00:00Z".to_string(),
            status: ProvenanceObservationStatus::Observed,
            confidence: ProvenanceConfidence::High,
            redaction: ProvenanceRedactionState::None,
            process: Some(ProvenanceProcessRef {
                pid: ProcessId(123),
                start_id: StartId("boot-1:99:123".to_string()),
            }),
            attributes: BTreeMap::from([("collector".to_string(), serde_json::json!("procfs"))]),
        };

        let process = ProvenanceNode {
            id: process_id.clone(),
            kind: ProvenanceNodeKind::Process,
            label: "pytest".to_string(),
            confidence: ProvenanceConfidence::High,
            redaction: ProvenanceRedactionState::None,
            evidence_ids: vec![evidence_id.clone()],
            attributes: BTreeMap::from([
                ("pid".to_string(), serde_json::json!(123)),
                ("cmd".to_string(), serde_json::json!("pytest -k foo")),
            ]),
        };

        let workspace = ProvenanceNode {
            id: workspace_id.clone(),
            kind: ProvenanceNodeKind::Workspace,
            label: "/repo/worktree".to_string(),
            confidence: ProvenanceConfidence::Medium,
            redaction: ProvenanceRedactionState::Partial,
            evidence_ids: vec![evidence_id.clone()],
            attributes: BTreeMap::from([("repo_root".to_string(), serde_json::json!("/repo"))]),
        };

        let edge = ProvenanceEdge {
            id: edge_id,
            kind: ProvenanceEdgeKind::AttachedToWorkspace,
            from: process_id,
            to: workspace_id,
            confidence: ProvenanceConfidence::Medium,
            redaction: ProvenanceRedactionState::Partial,
            evidence_ids: vec![evidence_id],
            derived_from_edge_ids: Vec::new(),
            attributes: BTreeMap::from([(
                "reason".to_string(),
                serde_json::json!("cwd_under_workspace"),
            )]),
        };

        ProvenanceGraphSnapshot::new(
            "2026-03-15T01:00:00Z".to_string(),
            Some("pt-20260315-010000-abcd".to_string()),
            Some("host-a".to_string()),
            vec![process, workspace],
            vec![edge],
            vec![evidence],
            vec![ProvenanceGraphWarning {
                code: "workspace_partially_redacted".to_string(),
                message: "workspace label was partially redacted".to_string(),
                confidence: ProvenanceConfidence::Low,
                evidence_ids: Vec::new(),
            }],
        )
    }

    #[test]
    fn deterministic_node_ids_are_stable() {
        let left = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:123");
        let right = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:123");
        let different = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:124");

        assert_eq!(left, right);
        assert_ne!(left, different);
        assert!(left.0.starts_with("pn_process_"));
    }

    #[test]
    fn deterministic_edge_ids_include_edge_kind() {
        let from = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:123");
        let to = ProvenanceNodeId::new(ProvenanceNodeKind::Workspace, "workspace:/repo");
        let edge = ProvenanceEdgeId::new(ProvenanceEdgeKind::AttachedToWorkspace, &from, &to);

        assert!(edge.0.starts_with("pe_attached_to_workspace_"));
    }

    #[test]
    fn graph_summary_counts_redacted_and_partial_evidence() {
        let graph = sample_graph();

        assert_eq!(graph.summary.node_count, 2);
        assert_eq!(graph.summary.edge_count, 1);
        assert_eq!(graph.summary.evidence_count, 1);
        assert_eq!(graph.summary.redacted_evidence_count, 0);
        assert_eq!(graph.summary.missing_or_conflicted_evidence_count, 0);
    }

    #[test]
    fn graph_snapshot_round_trips_through_json() {
        let graph = sample_graph();
        let json = serde_json::to_string_pretty(&graph).expect("serialize graph");
        let parsed: ProvenanceGraphSnapshot =
            serde_json::from_str(&json).expect("deserialize graph");

        assert_eq!(parsed.schema_version, PROVENANCE_SCHEMA_VERSION);
        assert_eq!(parsed, graph);
    }
}
