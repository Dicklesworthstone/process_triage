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
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRedactionState {
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
}
