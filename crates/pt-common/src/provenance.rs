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
/// Schema version for the provenance privacy/redaction policy contract.
pub const PROVENANCE_PRIVACY_POLICY_VERSION: &str = "1.0.0";

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
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRedactionState {
    #[default]
    None,
    Partial,
    Full,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSensitivity {
    PublicOperational,
    OperatorContext,
    LocalPath,
    InfrastructureIdentity,
    SecretAdjacent,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceHandling {
    Allow,
    Summarize,
    Hash,
    Redact,
    Omit,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRetentionClass {
    Ephemeral,
    Session,
    ShortTerm,
    LongTerm,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceConsentRequirement {
    None,
    ExplicitOperator,
    SupportEscalation,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceExplanationEffect {
    None,
    NoteRedacted,
    NoteWithheld,
    SuppressSpecifics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "scope")]
pub enum ProvenanceFieldSelector {
    NodeLabel {
        kind: ProvenanceNodeKind,
    },
    NodeAttribute {
        kind: ProvenanceNodeKind,
        key: String,
    },
    EdgeAttribute {
        kind: ProvenanceEdgeKind,
        key: String,
    },
    EvidenceSource {
        kind: ProvenanceEvidenceKind,
    },
    EvidenceAttribute {
        kind: ProvenanceEvidenceKind,
        key: String,
    },
    SnapshotHostId,
    SnapshotSessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenancePolicyConsequence {
    pub missing_confidence: ProvenanceConfidence,
    pub redacted_confidence: ProvenanceConfidence,
    pub explanation_effect: ProvenanceExplanationEffect,
    pub user_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceFieldPolicy {
    pub selector: ProvenanceFieldSelector,
    pub sensitivity: ProvenanceSensitivity,
    pub collect: ProvenanceHandling,
    pub persist: ProvenanceHandling,
    pub export: ProvenanceHandling,
    pub display: ProvenanceHandling,
    pub log: ProvenanceHandling,
    pub retention: ProvenanceRetentionClass,
    pub consent: ProvenanceConsentRequirement,
    pub consequence: ProvenancePolicyConsequence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenancePrivacyPolicy {
    pub version: String,
    pub local_persistence_days: u32,
    pub field_policies: Vec<ProvenanceFieldPolicy>,
}

impl ProvenancePrivacyPolicy {
    pub fn for_selector(
        &self,
        selector: &ProvenanceFieldSelector,
    ) -> Option<&ProvenanceFieldPolicy> {
        self.field_policies
            .iter()
            .find(|policy| &policy.selector == selector)
    }

    pub fn consent_required_count(&self) -> usize {
        self.field_policies
            .iter()
            .filter(|policy| policy.consent != ProvenanceConsentRequirement::None)
            .count()
    }
}

impl Default for ProvenancePrivacyPolicy {
    fn default() -> Self {
        let rules = vec![
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::NodeLabel {
                    kind: ProvenanceNodeKind::Process,
                },
                sensitivity: ProvenanceSensitivity::PublicOperational,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Allow,
                export: ProvenanceHandling::Summarize,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Summarize,
                retention: ProvenanceRetentionClass::Session,
                consent: ProvenanceConsentRequirement::None,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::SuppressSpecifics,
                    user_note: "process labels may be summarized when provenance is exported or logged".to_string(),
                },
                notes: Some("Process labels stay readable locally but should avoid leaking full raw commands across shareable surfaces.".to_string()),
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::NodeAttribute {
                    kind: ProvenanceNodeKind::Process,
                    key: "cmd".to_string(),
                },
                sensitivity: ProvenanceSensitivity::SecretAdjacent,
                collect: ProvenanceHandling::Summarize,
                persist: ProvenanceHandling::Redact,
                export: ProvenanceHandling::Omit,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Omit,
                retention: ProvenanceRetentionClass::Ephemeral,
                consent: ProvenanceConsentRequirement::SupportEscalation,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::NoteRedacted,
                    user_note: "raw command lines can contain secrets, so user-facing output must prefer normalized explanations over verbatim argv".to_string(),
                },
                notes: Some("Do not persist or export raw argv in provenance artifacts without an explicit support-grade escalation.".to_string()),
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::NodeLabel {
                    kind: ProvenanceNodeKind::Workspace,
                },
                sensitivity: ProvenanceSensitivity::LocalPath,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Low,
                    redacted_confidence: ProvenanceConfidence::Low,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "workspace and repo paths are useful but identifying, so redaction lowers confidence and should be disclosed in explanations".to_string(),
                },
                notes: Some("Workspace labels should preserve relationship semantics without revealing the exact on-disk path.".to_string()),
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::NodeAttribute {
                    kind: ProvenanceNodeKind::Workspace,
                    key: "repo_root".to_string(),
                },
                sensitivity: ProvenanceSensitivity::LocalPath,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Low,
                    redacted_confidence: ProvenanceConfidence::Low,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "repo roots should be represented by stable redacted identifiers on shared surfaces".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::NodeLabel {
                    kind: ProvenanceNodeKind::Host,
                },
                sensitivity: ProvenanceSensitivity::InfrastructureIdentity,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "host identities are useful for fleet provenance but should not be exposed verbatim in shared artifacts".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::EvidenceSource {
                    kind: ProvenanceEvidenceKind::Procfs,
                },
                sensitivity: ProvenanceSensitivity::PublicOperational,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Allow,
                export: ProvenanceHandling::Allow,
                display: ProvenanceHandling::Allow,
                log: ProvenanceHandling::Allow,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::None,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::None,
                    user_note: "collector source names are safe to show when they do not embed sensitive paths or arguments".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::EvidenceSource {
                    kind: ProvenanceEvidenceKind::Git,
                },
                sensitivity: ProvenanceSensitivity::OperatorContext,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Low,
                    redacted_confidence: ProvenanceConfidence::Low,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "git-derived provenance may identify repos, branches, or worktrees and must disclose when policy withholds it".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::EvidenceAttribute {
                    kind: ProvenanceEvidenceKind::Filesystem,
                    key: "path".to_string(),
                },
                sensitivity: ProvenanceSensitivity::LocalPath,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Low,
                    redacted_confidence: ProvenanceConfidence::Low,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "lockfile or pidfile paths should be transformed into stable redacted handles on shared surfaces".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::EvidenceAttribute {
                    kind: ProvenanceEvidenceKind::CommandLine,
                    key: "raw".to_string(),
                },
                sensitivity: ProvenanceSensitivity::SecretAdjacent,
                collect: ProvenanceHandling::Summarize,
                persist: ProvenanceHandling::Redact,
                export: ProvenanceHandling::Omit,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Omit,
                retention: ProvenanceRetentionClass::Ephemeral,
                consent: ProvenanceConsentRequirement::SupportEscalation,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::NoteRedacted,
                    user_note: "command-line evidence should survive only as normalized explanations unless an operator explicitly opts into a support workflow".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::EvidenceAttribute {
                    kind: ProvenanceEvidenceKind::Env,
                    key: "value".to_string(),
                },
                sensitivity: ProvenanceSensitivity::SecretAdjacent,
                collect: ProvenanceHandling::Omit,
                persist: ProvenanceHandling::Omit,
                export: ProvenanceHandling::Omit,
                display: ProvenanceHandling::Omit,
                log: ProvenanceHandling::Omit,
                retention: ProvenanceRetentionClass::Ephemeral,
                consent: ProvenanceConsentRequirement::SupportEscalation,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Unknown,
                    redacted_confidence: ProvenanceConfidence::Unknown,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "env values are treated as too sensitive for provenance; consumers must explain that the signal was intentionally unavailable".to_string(),
                },
                notes: Some("Environment values should influence provenance only through coarse derived facts, never via raw persistence.".to_string()),
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::SnapshotHostId,
                sensitivity: ProvenanceSensitivity::InfrastructureIdentity,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Hash,
                export: ProvenanceHandling::Hash,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Hash,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::ExplicitOperator,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::Medium,
                    redacted_confidence: ProvenanceConfidence::Medium,
                    explanation_effect: ProvenanceExplanationEffect::NoteWithheld,
                    user_note: "host identifiers should be stable enough for grouping while avoiding direct disclosure outside the local machine".to_string(),
                },
                notes: None,
            },
            ProvenanceFieldPolicy {
                selector: ProvenanceFieldSelector::SnapshotSessionId,
                sensitivity: ProvenanceSensitivity::OperatorContext,
                collect: ProvenanceHandling::Allow,
                persist: ProvenanceHandling::Allow,
                export: ProvenanceHandling::Summarize,
                display: ProvenanceHandling::Summarize,
                log: ProvenanceHandling::Summarize,
                retention: ProvenanceRetentionClass::ShortTerm,
                consent: ProvenanceConsentRequirement::None,
                consequence: ProvenancePolicyConsequence {
                    missing_confidence: ProvenanceConfidence::High,
                    redacted_confidence: ProvenanceConfidence::High,
                    explanation_effect: ProvenanceExplanationEffect::SuppressSpecifics,
                    user_note: "session identifiers support replay and debugging but should be summarized on shared surfaces".to_string(),
                },
                notes: None,
            },
        ];

        Self {
            version: PROVENANCE_PRIVACY_POLICY_VERSION.to_string(),
            local_persistence_days: 30,
            field_policies: rules,
        }
    }
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
    pub privacy: ProvenancePrivacyPolicy,
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
            privacy: ProvenancePrivacyPolicy::default(),
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

// ── Per-candidate provenance output contract ────────────────────────
//
// This is the stable machine-readable payload that JSON, TOON, agent,
// and API consumers receive per process candidate.  It replaces inline
// serde_json::json!() construction with typed structs so consumers
// can depend on a schema instead of reverse-engineering ad-hoc JSON.

/// Provenance output for a single candidate process.
///
/// Included in the `provenance_inference` field of each candidate in
/// `pt agent plan` JSON/TOON output.  Every field has a defined
/// semantic so consumers can rely on the schema without inspecting
/// renderer code.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CandidateProvenanceOutput {
    /// Whether provenance inference was active for this candidate.
    pub enabled: bool,

    /// Evidence completeness score [0, 1].
    ///
    /// 1.0 = all expected lineage and resource evidence was collected.
    /// <1.0 = some evidence was missing, partial, redacted, or conflicted.
    /// Consumers should treat low completeness as reduced confidence in
    /// both the score and the blast-radius estimate.
    pub evidence_completeness: f64,

    /// How many confidence-downgrade steps were applied.
    ///
    /// Each step reduces the displayed confidence level by one tier
    /// (VeryHigh→High→Medium→Low).  Caused by missing lineage,
    /// unresolved resource edges, or low-confidence blast-radius.
    pub confidence_penalty_steps: usize,

    /// Human-readable notes explaining each confidence downgrade.
    ///
    /// Examples: "missing lineage provenance", "resource provenance has
    /// 2 unresolved edge(s)", "blast-radius estimate is low-confidence".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_notes: Vec<String>,

    /// Named provenance features that contributed to the posterior.
    ///
    /// Each entry is a feature name like "provenance_ownership_orphaned"
    /// or "provenance_blast_radius_high".  The score terms themselves
    /// (log-likelihood contributions per class) are in the evidence
    /// ledger; this field provides the index for auditability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub score_terms: Vec<String>,

    /// Blast-radius summary for this candidate.
    pub blast_radius: CandidateBlastRadiusOutput,

    /// Redaction state of the provenance evidence for this candidate.
    ///
    /// `none` = all evidence available.
    /// `partial` = some evidence was redacted per privacy policy.
    /// `full` = all provenance evidence was redacted.
    #[serde(default)]
    pub redaction_state: ProvenanceRedactionState,

    /// Score-impact breakdown: how much provenance moved the posterior.
    ///
    /// Absent when provenance had no score impact (no evidence terms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_impact: Option<ProvenanceScoreImpact>,
}

/// Blast-radius output for a single candidate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CandidateBlastRadiusOutput {
    /// Risk score [0, 1].  Higher = more dangerous to kill.
    pub risk_score: f64,

    /// Classified risk level.
    pub risk_level: String,

    /// Confidence in the blast-radius estimate [0, 1].
    pub confidence: f64,

    /// Human-readable summary of the blast radius.
    pub summary: String,

    /// Total number of other processes/resources affected by killing
    /// this candidate (direct + indirect transitive impact).
    pub total_affected: usize,
}

/// How provenance features affected the candidate's posterior score.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceScoreImpact {
    /// Net shift in log-odds(abandoned/useful) from provenance terms.
    ///
    /// Positive = provenance pushed toward abandonment classification.
    /// Negative = provenance pushed toward useful classification.
    pub log_odds_shift: f64,

    /// Per-feature breakdown of score contributions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feature_contributions: Vec<ProvenanceFeatureContribution>,
}

/// A single provenance feature's contribution to the score.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceFeatureContribution {
    /// Feature name (e.g. "provenance_ownership_orphaned").
    pub feature: String,

    /// Log-likelihood contribution toward abandoned classification.
    pub abandoned_ll: f64,

    /// Log-likelihood contribution toward useful classification.
    pub useful_ll: f64,

    /// Net direction: "toward_abandon", "toward_useful", or "neutral".
    pub direction: String,
}

/// Per-feature log-likelihood pair used to build `ProvenanceScoreImpact`.
///
/// This is a minimal input struct so callers don't need to depend on
/// `pt-core`'s `EvidenceTerm` / `ClassScores` types.
#[derive(Debug, Clone)]
pub struct ProvenanceFeatureInput {
    /// Feature name (e.g. "provenance_ownership_orphaned").
    pub feature: String,
    /// Log-likelihood contribution toward the abandoned class.
    pub abandoned_ll: f64,
    /// Log-likelihood contribution toward the useful class.
    pub useful_ll: f64,
}

impl CandidateProvenanceOutput {
    /// Construct a disabled/absent provenance output.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            evidence_completeness: 0.0,
            confidence_penalty_steps: 0,
            confidence_notes: Vec::new(),
            score_terms: Vec::new(),
            blast_radius: CandidateBlastRadiusOutput {
                risk_score: 0.0,
                risk_level: "unknown".to_string(),
                confidence: 0.0,
                summary: "provenance not available".to_string(),
                total_affected: 0,
            },
            redaction_state: ProvenanceRedactionState::None,
            score_impact: None,
        }
    }

    /// Build from provenance adjustment components.
    ///
    /// This is the canonical constructor that main.rs should use instead of
    /// assembling ad-hoc JSON.  It populates `score_impact` from the feature
    /// inputs and computes the net log-odds shift.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        evidence_completeness: f64,
        confidence_penalty_steps: usize,
        confidence_notes: Vec<String>,
        features: &[ProvenanceFeatureInput],
        blast_radius_risk_score: f64,
        blast_radius_risk_level: &str,
        blast_radius_confidence: f64,
        blast_radius_summary: &str,
        blast_radius_total_affected: usize,
        redaction_state: ProvenanceRedactionState,
    ) -> Self {
        let score_terms: Vec<String> = features.iter().map(|f| f.feature.clone()).collect();

        let score_impact = if features.is_empty() {
            None
        } else {
            let mut log_odds_shift = 0.0_f64;
            let contributions: Vec<ProvenanceFeatureContribution> = features
                .iter()
                .map(|f| {
                    let shift = f.abandoned_ll - f.useful_ll;
                    log_odds_shift += shift;
                    let direction = if shift > 0.1 {
                        "toward_abandon"
                    } else if shift < -0.1 {
                        "toward_useful"
                    } else {
                        "neutral"
                    };
                    ProvenanceFeatureContribution {
                        feature: f.feature.clone(),
                        abandoned_ll: f.abandoned_ll,
                        useful_ll: f.useful_ll,
                        direction: direction.to_string(),
                    }
                })
                .collect();

            Some(ProvenanceScoreImpact {
                log_odds_shift,
                feature_contributions: contributions,
            })
        };

        Self {
            enabled: true,
            evidence_completeness,
            confidence_penalty_steps,
            confidence_notes,
            score_terms,
            blast_radius: CandidateBlastRadiusOutput {
                risk_score: blast_radius_risk_score,
                risk_level: blast_radius_risk_level.to_string(),
                confidence: blast_radius_confidence,
                summary: blast_radius_summary.to_string(),
                total_affected: blast_radius_total_affected,
            },
            redaction_state,
            score_impact,
        }
    }
}

// ── Human-readable narrative formatter ───────────────────────────────
//
// Translates `CandidateProvenanceOutput` into structured human-readable
// narratives for CLI, TUI, and report surfaces.  The narrative answers
// four operator questions in order:
//
// 1. **Origin**: Why does this process exist?
// 2. **Suspicion**: Why is it flagged?
// 3. **Blast radius**: What could break if it's killed?
// 4. **Uncertainty**: What don't we know?
//
// Each section uses consistent terminology so human and machine outputs
// never tell different stories.

/// Narrative verbosity level for different display surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrativeVerbosity {
    /// One-line summary for compact CLI output (≤80 chars).
    Compact,
    /// Multi-line summary for standard CLI output (3-5 lines).
    Standard,
    /// Full narrative for reports and verbose/debug modes.
    Full,
}

/// Structured narrative produced from provenance evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceNarrative {
    /// One-line summary suitable for any surface.
    pub headline: String,
    /// Ordered narrative sections.
    pub sections: Vec<NarrativeSection>,
    /// Caveats that must be visible to the user (never truncated).
    pub caveats: Vec<String>,
}

/// A single section of the provenance narrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeSection {
    /// Section heading (e.g., "Blast Radius", "Uncertainty").
    pub heading: String,
    /// Section body text.
    pub body: String,
    /// Glyph for TUI/CLI display.
    pub glyph: String,
}

/// Map a provenance score term to a human-readable label.
///
/// These labels appear in the "Provenance Signals" narrative section.
/// When adding new provenance features to the inference engine, add a
/// corresponding label here so human and machine outputs stay aligned.
fn score_term_label(term: &str) -> &str {
    match term {
        // Ownership / lineage
        "provenance_ownership_orphaned" => "orphaned (no parent process)",
        "provenance_ownership_supervised" => "supervised by init system",
        "provenance_ownership_shell" => "shell-owned (interactive session)",
        "provenance_ownership_agent" => "owned by AI agent session",
        "provenance_ownership_init_child" => "direct child of init/PID 1",
        "provenance_ownership_unknown" => "unknown ownership (no lineage)",
        // Resource / blast radius
        "provenance_active_listener" => "actively listening on network port(s)",
        "provenance_blast_radius_high" => "high blast radius (many dependents)",
        "provenance_blast_radius_low" => "low blast radius (isolated)",
        "provenance_blast_radius_critical" => "critical blast radius (blocks automation)",
        "provenance_shared_lockfiles" => "holds shared lockfile(s)",
        "provenance_shared_memory" => "uses shared memory segments",
        // Workspace / workflow
        "provenance_in_workspace" => "attached to known workspace",
        "provenance_no_workspace" => "no workspace association",
        "provenance_stale_branch" => "on stale/merged branch",
        "provenance_detached_head" => "running from detached HEAD",
        // Workflow family
        "provenance_test_runner" => "test runner process",
        "provenance_dev_server" => "development server",
        "provenance_build_tool" => "build tool process",
        "provenance_system_daemon" => "system daemon",
        // Cross-user / boundary
        "provenance_crossed_user_boundary" => "crossed user boundary (owned by different user)",
        // Catch-all: return the raw term name (stripped of prefix if possible)
        other => other,
    }
}

/// Risk level labels for human display.
fn risk_level_label(level: &str) -> &'static str {
    match level {
        "low" => "low",
        "medium" => "moderate",
        "high" => "high",
        "critical" => "critical",
        _ => "unknown",
    }
}

/// Confidence label for humans.
fn completeness_label(completeness: f64) -> &'static str {
    if completeness >= 0.9 {
        "strong"
    } else if completeness >= 0.7 {
        "moderate"
    } else if completeness >= 0.5 {
        "partial"
    } else {
        "weak"
    }
}

impl ProvenanceNarrative {
    /// Build a narrative from a provenance output.
    pub fn from_output(output: &CandidateProvenanceOutput) -> Self {
        if !output.enabled {
            return Self {
                headline: "Provenance: not available".to_string(),
                sections: Vec::new(),
                caveats: Vec::new(),
            };
        }

        let mut sections = Vec::new();
        let mut caveats = Vec::new();

        // ── Section 1: Suspicion (score terms) ──────────────────────
        if !output.score_terms.is_empty() {
            let term_descriptions: Vec<&str> = output
                .score_terms
                .iter()
                .map(|t| score_term_label(t))
                .collect();

            sections.push(NarrativeSection {
                heading: "Provenance Signals".to_string(),
                body: term_descriptions.join("; "),
                glyph: "🔗".to_string(),
            });
        }

        // ── Section 1b: Score impact (when present) ─────────────────
        if let Some(ref impact) = output.score_impact {
            let direction_label = if impact.log_odds_shift > 0.5 {
                "strongly toward abandonment"
            } else if impact.log_odds_shift > 0.1 {
                "toward abandonment"
            } else if impact.log_odds_shift < -0.5 {
                "strongly toward useful"
            } else if impact.log_odds_shift < -0.1 {
                "toward useful"
            } else {
                "neutral (no strong signal)"
            };

            sections.push(NarrativeSection {
                heading: "Score Impact".to_string(),
                body: format!(
                    "Provenance pushes classification {} (log-odds shift: {:+.2})",
                    direction_label, impact.log_odds_shift
                ),
                glyph: "📊".to_string(),
            });
        }

        // ── Section 2: Blast radius ─────────────────────────────────
        let br = &output.blast_radius;
        let risk_label = risk_level_label(&br.risk_level);
        let br_body = if br.total_affected == 0 {
            format!(
                "{} risk (score {:.0}%). {}",
                capitalize(risk_label),
                br.risk_score * 100.0,
                br.summary
            )
        } else {
            format!(
                "{} risk (score {:.0}%), {} affected. {}",
                capitalize(risk_label),
                br.risk_score * 100.0,
                br.total_affected,
                br.summary
            )
        };

        sections.push(NarrativeSection {
            heading: "Blast Radius".to_string(),
            body: br_body,
            glyph: "🛡".to_string(),
        });

        // ── Section 3: Uncertainty ──────────────────────────────────
        let completeness = completeness_label(output.evidence_completeness);
        if output.evidence_completeness < 0.9 || output.confidence_penalty_steps > 0 {
            let mut uncertainty_parts = vec![format!(
                "Evidence completeness: {} ({:.0}%)",
                completeness,
                output.evidence_completeness * 100.0
            )];

            if output.confidence_penalty_steps > 0 {
                uncertainty_parts.push(format!(
                    "Confidence reduced by {} step(s)",
                    output.confidence_penalty_steps
                ));
            }

            sections.push(NarrativeSection {
                heading: "Uncertainty".to_string(),
                body: uncertainty_parts.join(". "),
                glyph: "⚠".to_string(),
            });
        }

        // ── Caveats (never truncated) ───────────────────────────────
        for note in &output.confidence_notes {
            caveats.push(note.clone());
        }

        if output.redaction_state != ProvenanceRedactionState::None {
            caveats.push(format!(
                "Some provenance evidence was {} per privacy policy",
                match output.redaction_state {
                    ProvenanceRedactionState::Partial => "partially redacted",
                    ProvenanceRedactionState::Full => "fully redacted",
                    ProvenanceRedactionState::None => unreachable!(),
                }
            ));
        }

        // ── Headline ────────────────────────────────────────────────
        let headline = Self::build_headline(output, risk_label, completeness);

        Self {
            headline,
            sections,
            caveats,
        }
    }

    fn build_headline(
        output: &CandidateProvenanceOutput,
        risk_label: &str,
        completeness: &str,
    ) -> String {
        let risk_part = format!("{} blast radius", risk_label);
        let evidence_part = format!("{} evidence", completeness);

        if output.confidence_penalty_steps > 0 {
            format!(
                "Provenance: {}; {} (confidence reduced)",
                risk_part, evidence_part
            )
        } else {
            format!("Provenance: {}; {}", risk_part, evidence_part)
        }
    }

    /// Render the narrative at a given verbosity level.
    pub fn render(&self, verbosity: NarrativeVerbosity) -> String {
        match verbosity {
            NarrativeVerbosity::Compact => self.headline.clone(),
            NarrativeVerbosity::Standard => {
                let mut lines = vec![self.headline.clone()];
                for section in &self.sections {
                    lines.push(format!(
                        "  {} {}: {}",
                        section.glyph, section.heading, section.body
                    ));
                }
                if !self.caveats.is_empty() {
                    lines.push(format!("  ⚠ Caveats: {}", self.caveats.join("; ")));
                }
                lines.join("\n")
            }
            NarrativeVerbosity::Full => {
                let mut lines = vec![self.headline.clone(), String::new()];
                for section in &self.sections {
                    lines.push(format!("{} {}", section.glyph, section.heading));
                    lines.push(format!("  {}", section.body));
                    lines.push(String::new());
                }
                if !self.caveats.is_empty() {
                    lines.push("⚠ Caveats".to_string());
                    for caveat in &self.caveats {
                        lines.push(format!("  • {}", caveat));
                    }
                }
                lines.join("\n")
            }
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
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
        assert_eq!(
            graph.privacy.version,
            PROVENANCE_PRIVACY_POLICY_VERSION.to_string()
        );
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

    #[test]
    fn graph_summary_counts_partial_missing_and_conflicted_evidence() {
        let observed_id =
            ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Procfs, "procfs:pid=11:start=a");
        let partial_id = ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Ps, "ps:pid=11:start=a");
        let missing_id = ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Git, "git:cwd=/repo");
        let conflicted_id =
            ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Derived, "derived:workspace");

        let graph = ProvenanceGraphSnapshot::new(
            "2026-03-15T02:00:00Z".to_string(),
            Some("pt-20260315-020000-wxyz".to_string()),
            Some("host-b".to_string()),
            Vec::new(),
            Vec::new(),
            vec![
                ProvenanceEvidence {
                    id: observed_id,
                    kind: ProvenanceEvidenceKind::Procfs,
                    source: "/proc/11/stat".to_string(),
                    observed_at: "2026-03-15T02:00:00Z".to_string(),
                    status: ProvenanceObservationStatus::Observed,
                    confidence: ProvenanceConfidence::High,
                    redaction: ProvenanceRedactionState::None,
                    process: None,
                    attributes: BTreeMap::new(),
                },
                ProvenanceEvidence {
                    id: partial_id,
                    kind: ProvenanceEvidenceKind::Ps,
                    source: "ps".to_string(),
                    observed_at: "2026-03-15T02:00:00Z".to_string(),
                    status: ProvenanceObservationStatus::Partial,
                    confidence: ProvenanceConfidence::Medium,
                    redaction: ProvenanceRedactionState::Partial,
                    process: None,
                    attributes: BTreeMap::new(),
                },
                ProvenanceEvidence {
                    id: missing_id,
                    kind: ProvenanceEvidenceKind::Git,
                    source: "/repo/.git".to_string(),
                    observed_at: "2026-03-15T02:00:00Z".to_string(),
                    status: ProvenanceObservationStatus::Missing,
                    confidence: ProvenanceConfidence::Low,
                    redaction: ProvenanceRedactionState::None,
                    process: None,
                    attributes: BTreeMap::new(),
                },
                ProvenanceEvidence {
                    id: conflicted_id,
                    kind: ProvenanceEvidenceKind::Derived,
                    source: "graph_reasoner".to_string(),
                    observed_at: "2026-03-15T02:00:00Z".to_string(),
                    status: ProvenanceObservationStatus::Conflicted,
                    confidence: ProvenanceConfidence::Low,
                    redaction: ProvenanceRedactionState::Full,
                    process: None,
                    attributes: BTreeMap::new(),
                },
            ],
            Vec::new(),
        );

        assert_eq!(graph.summary.evidence_count, 4);
        assert_eq!(graph.summary.redacted_evidence_count, 2);
        assert_eq!(graph.summary.missing_or_conflicted_evidence_count, 3);
    }

    #[test]
    fn representative_graph_json_shape_is_stable() {
        let graph = sample_graph();
        let json = serde_json::to_value(&graph).expect("serialize graph to value");

        assert_eq!(json["schema_version"], serde_json::json!("1.0.0"));
        assert_eq!(
            json["generated_at"],
            serde_json::json!("2026-03-15T01:00:00Z")
        );
        assert_eq!(
            json["session_id"],
            serde_json::json!("pt-20260315-010000-abcd")
        );
        assert_eq!(json["host_id"], serde_json::json!("host-a"));
        assert_eq!(
            json["summary"],
            serde_json::json!({
                "node_count": 2,
                "edge_count": 1,
                "evidence_count": 1,
                "redacted_evidence_count": 0,
                "missing_or_conflicted_evidence_count": 0
            })
        );
        assert_eq!(
            json["privacy"]["version"],
            serde_json::json!(PROVENANCE_PRIVACY_POLICY_VERSION)
        );
        assert_eq!(
            json["privacy"]["local_persistence_days"],
            serde_json::json!(30)
        );
        assert_eq!(
            json["privacy"]["field_policies"]
                .as_array()
                .expect("privacy field policies array")
                .len(),
            12
        );
        assert_eq!(json["nodes"][0]["label"], serde_json::json!("pytest"));
        assert_eq!(json["nodes"][1]["redaction"], serde_json::json!("partial"));
        assert_eq!(
            json["edges"][0]["attributes"]["reason"],
            serde_json::json!("cwd_under_workspace")
        );
        assert_eq!(
            json["evidence"][0]["source"],
            serde_json::json!("/proc/123/stat")
        );
        assert_eq!(
            json["warnings"][0]["code"],
            serde_json::json!("workspace_partially_redacted")
        );
    }

    #[test]
    fn privacy_policy_marks_sensitive_fields_with_explicit_handling() {
        let policy = ProvenancePrivacyPolicy::default();
        let workspace_label = policy
            .for_selector(&ProvenanceFieldSelector::NodeLabel {
                kind: ProvenanceNodeKind::Workspace,
            })
            .expect("workspace label policy");

        assert_eq!(
            workspace_label.sensitivity,
            ProvenanceSensitivity::LocalPath
        );
        assert_eq!(workspace_label.persist, ProvenanceHandling::Hash);
        assert_eq!(workspace_label.export, ProvenanceHandling::Hash);
        assert_eq!(
            workspace_label.consent,
            ProvenanceConsentRequirement::ExplicitOperator
        );

        let env_value = policy
            .for_selector(&ProvenanceFieldSelector::EvidenceAttribute {
                kind: ProvenanceEvidenceKind::Env,
                key: "value".to_string(),
            })
            .expect("env value policy");

        assert_eq!(env_value.collect, ProvenanceHandling::Omit);
        assert_eq!(env_value.export, ProvenanceHandling::Omit);
        assert_eq!(
            env_value.consequence.explanation_effect,
            ProvenanceExplanationEffect::NoteWithheld
        );
    }

    #[test]
    fn privacy_policy_counts_rules_that_require_operator_consent() {
        let policy = ProvenancePrivacyPolicy::default();
        assert_eq!(policy.consent_required_count(), 9);
    }

    // ── Narrative formatter tests ───────────────────────────────────

    fn sample_full_provenance() -> CandidateProvenanceOutput {
        CandidateProvenanceOutput {
            enabled: true,
            evidence_completeness: 0.72,
            confidence_penalty_steps: 2,
            confidence_notes: vec![
                "missing lineage provenance".to_string(),
                "resource provenance has 2 unresolved edge(s)".to_string(),
            ],
            score_terms: vec![
                "provenance_ownership_orphaned".to_string(),
                "provenance_blast_radius_low".to_string(),
            ],
            blast_radius: CandidateBlastRadiusOutput {
                risk_score: 0.15,
                risk_level: "low".to_string(),
                confidence: 0.60,
                summary: "Isolated process, no shared resources".to_string(),
                total_affected: 0,
            },
            redaction_state: ProvenanceRedactionState::None,
            score_impact: None,
        }
    }

    #[test]
    fn narrative_disabled_is_short() {
        let output = CandidateProvenanceOutput::disabled();
        let narrative = ProvenanceNarrative::from_output(&output);
        assert_eq!(narrative.headline, "Provenance: not available");
        assert!(narrative.sections.is_empty());
        assert!(narrative.caveats.is_empty());
    }

    #[test]
    fn narrative_has_expected_sections() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);

        let headings: Vec<&str> = narrative
            .sections
            .iter()
            .map(|s| s.heading.as_str())
            .collect();
        assert!(headings.contains(&"Provenance Signals"));
        assert!(headings.contains(&"Blast Radius"));
        assert!(headings.contains(&"Uncertainty"));
    }

    #[test]
    fn narrative_caveats_include_confidence_notes() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);

        assert!(narrative
            .caveats
            .iter()
            .any(|c| c.contains("missing lineage")));
        assert!(narrative
            .caveats
            .iter()
            .any(|c| c.contains("unresolved edge")));
    }

    #[test]
    fn narrative_redaction_caveat_added() {
        let mut output = sample_full_provenance();
        output.redaction_state = ProvenanceRedactionState::Partial;
        let narrative = ProvenanceNarrative::from_output(&output);

        assert!(narrative
            .caveats
            .iter()
            .any(|c| c.contains("partially redacted")));
    }

    #[test]
    fn narrative_compact_is_one_line() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);
        let rendered = narrative.render(NarrativeVerbosity::Compact);
        assert!(!rendered.contains('\n'));
        assert!(
            rendered.len() <= 80,
            "Compact headline should be ≤80 chars, got {} chars: {:?}",
            rendered.len(),
            rendered
        );
    }

    #[test]
    fn narrative_standard_has_sections() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);
        let rendered = narrative.render(NarrativeVerbosity::Standard);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines.len() >= 3); // headline + sections
        assert!(rendered.contains("🔗")); // Score terms glyph
        assert!(rendered.contains("🛡")); // Blast radius glyph
    }

    #[test]
    fn narrative_full_has_all_details() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);
        let rendered = narrative.render(NarrativeVerbosity::Full);
        assert!(rendered.contains("Provenance Signals"));
        assert!(rendered.contains("Blast Radius"));
        assert!(rendered.contains("Uncertainty"));
        assert!(rendered.contains("Caveats"));
        assert!(rendered.contains("missing lineage"));
    }

    #[test]
    fn narrative_headline_mentions_confidence_reduction() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);
        assert!(narrative.headline.contains("confidence reduced"));
    }

    #[test]
    fn narrative_no_uncertainty_section_when_evidence_strong() {
        let mut output = sample_full_provenance();
        output.evidence_completeness = 0.95;
        output.confidence_penalty_steps = 0;
        output.confidence_notes.clear();
        let narrative = ProvenanceNarrative::from_output(&output);

        let headings: Vec<&str> = narrative
            .sections
            .iter()
            .map(|s| s.heading.as_str())
            .collect();
        assert!(!headings.contains(&"Uncertainty"));
    }

    #[test]
    fn narrative_score_terms_use_human_labels() {
        let output = sample_full_provenance();
        let narrative = ProvenanceNarrative::from_output(&output);
        let signals = narrative
            .sections
            .iter()
            .find(|s| s.heading == "Provenance Signals")
            .unwrap();
        assert!(signals.body.contains("orphaned"));
        assert!(signals.body.contains("low blast radius"));
    }

    #[test]
    fn narrative_includes_score_impact_when_present() {
        let mut output = sample_full_provenance();
        output.score_impact = Some(ProvenanceScoreImpact {
            log_odds_shift: 1.25,
            feature_contributions: vec![ProvenanceFeatureContribution {
                feature: "provenance_ownership_orphaned".to_string(),
                abandoned_ll: 0.70,
                useful_ll: -0.55,
                direction: "toward_abandon".to_string(),
            }],
        });

        let narrative = ProvenanceNarrative::from_output(&output);
        let impact_section = narrative
            .sections
            .iter()
            .find(|s| s.heading == "Score Impact")
            .expect("should have Score Impact section");
        assert!(impact_section.body.contains("strongly toward abandonment"));
        assert!(impact_section.body.contains("+1.25"));
    }

    #[test]
    fn narrative_omits_score_impact_when_absent() {
        let output = sample_full_provenance(); // score_impact is None
        let narrative = ProvenanceNarrative::from_output(&output);
        assert!(
            !narrative
                .sections
                .iter()
                .any(|s| s.heading == "Score Impact"),
            "Score Impact section should be absent when score_impact is None"
        );
    }

    #[test]
    fn narrative_score_term_labels_cover_all_known_features() {
        // Verify each known feature maps to a human label, not itself
        let known_terms = [
            "provenance_ownership_orphaned",
            "provenance_ownership_supervised",
            "provenance_ownership_shell",
            "provenance_active_listener",
            "provenance_blast_radius_high",
            "provenance_blast_radius_low",
            "provenance_blast_radius_critical",
            "provenance_shared_lockfiles",
            "provenance_in_workspace",
            "provenance_no_workspace",
            "provenance_test_runner",
            "provenance_dev_server",
            "provenance_build_tool",
            "provenance_crossed_user_boundary",
        ];

        for term in known_terms {
            let label = score_term_label(term);
            assert_ne!(
                label, term,
                "term {term} should have a human-readable label, not return itself"
            );
        }
    }

    // ── CandidateProvenanceOutput contract tests ────────────────────

    #[test]
    fn candidate_provenance_output_disabled_serializes_stably() {
        let output = CandidateProvenanceOutput::disabled();
        let json = serde_json::to_value(&output).expect("serialize disabled output");

        assert_eq!(json["enabled"], serde_json::json!(false));
        assert_eq!(json["evidence_completeness"], serde_json::json!(0.0));
        assert_eq!(json["confidence_penalty_steps"], serde_json::json!(0));
        assert_eq!(json["blast_radius"]["risk_score"], serde_json::json!(0.0));
        assert_eq!(
            json["blast_radius"]["risk_level"],
            serde_json::json!("unknown")
        );
        // Empty vecs should be absent (skip_serializing_if)
        assert!(json.get("confidence_notes").is_none());
        assert!(json.get("score_terms").is_none());
        assert!(json.get("score_impact").is_none());
    }

    #[test]
    fn candidate_provenance_output_full_serializes_stably() {
        let output = CandidateProvenanceOutput {
            enabled: true,
            evidence_completeness: 0.85,
            confidence_penalty_steps: 1,
            confidence_notes: vec!["resource provenance has 2 unresolved edge(s)".to_string()],
            score_terms: vec![
                "provenance_ownership_orphaned".to_string(),
                "provenance_blast_radius_low".to_string(),
            ],
            blast_radius: CandidateBlastRadiusOutput {
                risk_score: 0.12,
                risk_level: "low".to_string(),
                confidence: 0.90,
                summary: "Isolated process with no shared resources".to_string(),
                total_affected: 0,
            },
            redaction_state: ProvenanceRedactionState::None,
            score_impact: Some(ProvenanceScoreImpact {
                log_odds_shift: 0.35,
                feature_contributions: vec![
                    ProvenanceFeatureContribution {
                        feature: "provenance_ownership_orphaned".to_string(),
                        abandoned_ll: 0.70,
                        useful_ll: -0.55,
                        direction: "toward_abandon".to_string(),
                    },
                    ProvenanceFeatureContribution {
                        feature: "provenance_blast_radius_low".to_string(),
                        abandoned_ll: 0.35,
                        useful_ll: -0.25,
                        direction: "toward_abandon".to_string(),
                    },
                ],
            }),
        };

        let json = serde_json::to_value(&output).expect("serialize full output");

        // Top-level fields
        assert_eq!(json["enabled"], serde_json::json!(true));
        assert_eq!(json["evidence_completeness"], serde_json::json!(0.85));
        assert_eq!(json["confidence_penalty_steps"], serde_json::json!(1));
        assert_eq!(json["redaction_state"], serde_json::json!("none"));

        // Confidence notes
        let notes = json["confidence_notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1);

        // Score terms
        let terms = json["score_terms"].as_array().unwrap();
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0], serde_json::json!("provenance_ownership_orphaned"));

        // Blast radius
        assert_eq!(json["blast_radius"]["risk_score"], serde_json::json!(0.12));
        assert_eq!(json["blast_radius"]["risk_level"], serde_json::json!("low"));
        assert_eq!(json["blast_radius"]["total_affected"], serde_json::json!(0));

        // Score impact
        let impact = &json["score_impact"];
        assert_eq!(impact["log_odds_shift"], serde_json::json!(0.35));
        let contributions = impact["feature_contributions"].as_array().unwrap();
        assert_eq!(contributions.len(), 2);
        assert_eq!(
            contributions[0]["direction"],
            serde_json::json!("toward_abandon")
        );
    }

    #[test]
    fn candidate_provenance_output_roundtrips() {
        let output = CandidateProvenanceOutput {
            enabled: true,
            evidence_completeness: 0.72,
            confidence_penalty_steps: 2,
            confidence_notes: vec![
                "missing lineage provenance".to_string(),
                "blast-radius estimate is low-confidence".to_string(),
            ],
            score_terms: vec!["provenance_blast_radius_high".to_string()],
            blast_radius: CandidateBlastRadiusOutput {
                risk_score: 0.78,
                risk_level: "high".to_string(),
                confidence: 0.45,
                summary: "Process shares 3 lockfiles with 5 peers".to_string(),
                total_affected: 5,
            },
            redaction_state: ProvenanceRedactionState::Partial,
            score_impact: None,
        };

        let json_str = serde_json::to_string(&output).expect("serialize");
        let deser: CandidateProvenanceOutput =
            serde_json::from_str(&json_str).expect("deserialize");

        assert_eq!(deser.enabled, output.enabled);
        assert_eq!(deser.evidence_completeness, output.evidence_completeness);
        assert_eq!(
            deser.confidence_penalty_steps,
            output.confidence_penalty_steps
        );
        assert_eq!(deser.confidence_notes, output.confidence_notes);
        assert_eq!(deser.score_terms, output.score_terms);
        assert_eq!(
            deser.blast_radius.risk_score,
            output.blast_radius.risk_score
        );
        assert_eq!(
            deser.blast_radius.risk_level,
            output.blast_radius.risk_level
        );
        assert_eq!(
            deser.blast_radius.total_affected,
            output.blast_radius.total_affected
        );
        assert_eq!(deser.redaction_state, output.redaction_state);
        assert!(deser.score_impact.is_none());
    }

    #[test]
    fn candidate_provenance_json_schema_is_valid() {
        let schema = schemars::schema_for!(CandidateProvenanceOutput);
        let json = serde_json::to_value(&schema).expect("serialize schema");
        assert!(json.get("$schema").is_some() || json.get("title").is_some());
        // Verify key properties exist in schema
        let props = json["properties"].as_object().unwrap();
        assert!(props.contains_key("enabled"));
        assert!(props.contains_key("evidence_completeness"));
        assert!(props.contains_key("blast_radius"));
        assert!(props.contains_key("score_impact"));
    }

    // ── from_parts contract tests ────────────────────────────────────

    #[test]
    fn from_parts_populates_score_impact_from_features() {
        let features = vec![
            ProvenanceFeatureInput {
                feature: "provenance_ownership_orphaned".to_string(),
                abandoned_ll: 0.70,
                useful_ll: -0.55,
            },
            ProvenanceFeatureInput {
                feature: "provenance_blast_radius_low".to_string(),
                abandoned_ll: 0.35,
                useful_ll: -0.25,
            },
        ];

        let output = CandidateProvenanceOutput::from_parts(
            0.85,
            1,
            vec!["resource provenance has 2 unresolved edge(s)".to_string()],
            &features,
            0.12,
            "low",
            0.90,
            "Isolated process with no shared resources",
            0,
            ProvenanceRedactionState::None,
        );

        assert!(output.enabled);
        assert_eq!(output.evidence_completeness, 0.85);
        assert_eq!(output.confidence_penalty_steps, 1);
        assert_eq!(output.score_terms.len(), 2);
        assert_eq!(output.score_terms[0], "provenance_ownership_orphaned");
        assert_eq!(output.blast_radius.risk_level, "low");

        let impact = output
            .score_impact
            .as_ref()
            .expect("score_impact should be Some");
        // Net shift = (0.70 - (-0.55)) + (0.35 - (-0.25)) = 1.25 + 0.60 = 1.85
        assert!((impact.log_odds_shift - 1.85).abs() < 1e-10);
        assert_eq!(impact.feature_contributions.len(), 2);
        assert_eq!(impact.feature_contributions[0].direction, "toward_abandon");
        assert_eq!(impact.feature_contributions[1].direction, "toward_abandon");
    }

    #[test]
    fn from_parts_no_features_means_no_score_impact() {
        let output = CandidateProvenanceOutput::from_parts(
            0.70,
            0,
            Vec::new(),
            &[],
            0.05,
            "low",
            0.80,
            "No impact",
            0,
            ProvenanceRedactionState::None,
        );

        assert!(output.enabled);
        assert!(output.score_impact.is_none());
        assert!(output.score_terms.is_empty());
    }

    #[test]
    fn from_parts_neutral_direction_for_balanced_features() {
        let features = vec![ProvenanceFeatureInput {
            feature: "provenance_ownership_shell".to_string(),
            abandoned_ll: 0.10,
            useful_ll: 0.08,
        }];

        let output = CandidateProvenanceOutput::from_parts(
            0.90,
            0,
            Vec::new(),
            &features,
            0.05,
            "low",
            0.95,
            "No impact",
            0,
            ProvenanceRedactionState::None,
        );

        let impact = output.score_impact.unwrap();
        assert_eq!(impact.feature_contributions[0].direction, "neutral");
    }

    #[test]
    fn from_parts_toward_useful_direction() {
        let features = vec![ProvenanceFeatureInput {
            feature: "provenance_ownership_supervised".to_string(),
            abandoned_ll: -0.70,
            useful_ll: 0.60,
        }];

        let output = CandidateProvenanceOutput::from_parts(
            0.95,
            0,
            Vec::new(),
            &features,
            0.05,
            "low",
            0.99,
            "Supervised process",
            0,
            ProvenanceRedactionState::None,
        );

        let impact = output.score_impact.unwrap();
        assert_eq!(impact.feature_contributions[0].direction, "toward_useful");
        assert!(impact.log_odds_shift < 0.0);
    }

    #[test]
    fn from_parts_serializes_same_as_manual_construction() {
        let features = vec![ProvenanceFeatureInput {
            feature: "provenance_ownership_orphaned".to_string(),
            abandoned_ll: 0.70,
            useful_ll: -0.55,
        }];

        let from_parts = CandidateProvenanceOutput::from_parts(
            0.85,
            1,
            vec!["missing lineage provenance".to_string()],
            &features,
            0.12,
            "low",
            0.90,
            "Isolated process",
            0,
            ProvenanceRedactionState::Partial,
        );

        let json = serde_json::to_value(&from_parts).expect("serialize");

        // Verify all contract fields present
        assert_eq!(json["enabled"], true);
        assert_eq!(json["evidence_completeness"], 0.85);
        assert_eq!(json["confidence_penalty_steps"], 1);
        assert_eq!(json["redaction_state"], "partial");
        assert!(json["confidence_notes"].as_array().unwrap().len() == 1);
        assert!(json["score_terms"].as_array().unwrap().len() == 1);
        assert!(json["score_impact"]["log_odds_shift"].as_f64().is_some());
        assert_eq!(json["blast_radius"]["risk_level"], "low");

        // Round-trip
        let deser: CandidateProvenanceOutput = serde_json::from_value(json).expect("deserialize");
        assert_eq!(deser.enabled, from_parts.enabled);
        assert_eq!(deser.redaction_state, from_parts.redaction_state);
    }
}
