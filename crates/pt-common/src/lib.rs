//! Process Triage common types, IDs, and errors.
//!
//! This crate provides foundational types shared across pt-core modules:
//! - Process identity types with safety guarantees
//! - Session and schema versioning
//! - Common error types
//! - Output format specifications
//! - Configuration loading and validation
//! - Capabilities detection and caching
//! - Command and CWD category taxonomies
//! - Galaxy-brain math transparency types

pub mod blast_radius;
pub mod capabilities;
pub mod categories;
pub mod config;
pub mod error;
pub mod galaxy_brain;
pub mod id;
pub mod lineage_evidence;
pub mod output;
pub mod provenance;
pub mod resource_evidence;
pub mod schema;
pub mod workflow_origin;
pub mod workspace_evidence;

pub use blast_radius::{
    compute_risk_level, summarize_blast_radius, AffectedResource, AffectedService,
    BlastRadiusAssessment, BlastRadiusConfidence, ConfidenceTier, DependencyKind, DependentProcess,
    DirectImpact, EvidenceCitation, EvidenceCoverage, IndirectImpact, ResourceImpactKind,
    RiskLevel, Unknown, UnknownReason, BLAST_RADIUS_COMPUTED, BLAST_RADIUS_EVIDENCE_GAP,
    BLAST_RADIUS_SCHEMA_VERSION,
};
pub use capabilities::{
    Capabilities, CapabilitiesError, CgroupInfo, CgroupVersion, ContainerInfo, CpuArch,
    LaunchdInfo, OsFamily, OsInfo, PathsInfo, PrivilegesInfo, ProcField, ProcFsInfo, PsiInfo,
    SudoInfo, SystemInfo, SystemdInfo, ToolInfo, ToolPermissions, UserInfo,
    CAPABILITIES_SCHEMA_VERSION, DEFAULT_CACHE_TTL_SECS,
};
pub use categories::{
    CategorizationOutput, CategoryMatcher, CategoryTaxonomy, CommandCategory, CommandCategoryDef,
    CommandPattern, CwdCategory, CwdCategoryDef, CwdPattern, PriorHints, CATEGORIES_SCHEMA_VERSION,
};
pub use config::{Config, ConfigPaths, ConfigResolver, ConfigSnapshot, Policy, Priors};
pub use error::{
    format_batch_human, format_error_human, BatchError, BatchResult, BatchSummary, Error,
    ErrorCategory, Result, StructuredError, SuggestedAction,
};
pub use galaxy_brain::{
    CardId, CliHints, CliOutputFormat, CliVerbosity, ComputedValue, Equation, GalaxyBrainData,
    MathCard, MathRenderer, Reference, RenderHints, ReportHints, TuiColorScheme, TuiHints,
    ValueFormat, ValueType, GALAXY_BRAIN_SCHEMA_VERSION,
};
pub use id::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};
pub use lineage_evidence::{
    normalize_lineage, AncestorEntry, LineageCollectionMethod, NormalizedLineage, OwnershipState,
    RawLineageEvidence, SessionContext, SupervisorEvidence, SupervisorKind, TtyEvidence,
    LINEAGE_EVIDENCE_MISSING, LINEAGE_EVIDENCE_NORMALIZED, LINEAGE_EVIDENCE_VERSION,
};
pub use output::OutputFormat;
pub use provenance::{
    CandidateBlastRadiusOutput, CandidateProvenanceOutput, NarrativeSection, NarrativeVerbosity,
    ProvenanceFeatureContribution, ProvenanceFeatureInput, ProvenanceNarrative,
    ProvenanceScoreImpact,
};
pub use provenance::{
    ProvenanceConfidence, ProvenanceConsentRequirement, ProvenanceEdge, ProvenanceEdgeId,
    ProvenanceEdgeKind, ProvenanceEvidence, ProvenanceEvidenceId, ProvenanceEvidenceKind,
    ProvenanceExplanationEffect, ProvenanceFieldPolicy, ProvenanceFieldSelector,
    ProvenanceGraphSnapshot, ProvenanceGraphSummary, ProvenanceGraphWarning, ProvenanceHandling,
    ProvenanceNode, ProvenanceNodeId, ProvenanceNodeKind, ProvenanceObservationStatus,
    ProvenancePolicyConsequence, ProvenancePrivacyPolicy, ProvenanceProcessRef,
    ProvenanceRedactionState, ProvenanceRetentionClass, ProvenanceSensitivity,
    PROVENANCE_PRIVACY_POLICY_VERSION, PROVENANCE_SCHEMA_VERSION,
};
pub use resource_evidence::{
    normalize_resource, stable_resource_id, LockMechanism, NormalizedResource, RawResourceEvidence,
    ResourceCollectionMethod, ResourceDetails, ResourceKind, ResourceState,
    RESOURCE_EVIDENCE_CONFLICT, RESOURCE_EVIDENCE_NORMALIZED, RESOURCE_EVIDENCE_VERSION,
};
pub use schema::SCHEMA_VERSION;
pub use workflow_origin::{
    classify_workflow_origin, strip_wrapper_launchers, ClassificationSignal, WorkflowFamily,
    WorkflowOriginClassification, WORKFLOW_ORIGIN_CLASSIFIED, WORKFLOW_ORIGIN_VERSION,
};
pub use workspace_evidence::{
    is_path_under, normalize_path_for_hashing, normalize_workspace, paths_are_same_location,
    stable_path_id, HeadState, NormalizedWorkspace, PathResolutionError, RawPathEvidence,
    RawWorkspaceEvidence, WorkspaceCollectionMethod, WorkspaceNormalizationResult,
    WORKSPACE_EVIDENCE_MISSING, WORKSPACE_EVIDENCE_NORMALIZED, WORKSPACE_EVIDENCE_VERSION,
    WORKSPACE_PATH_ALIAS_RESOLVED,
};
