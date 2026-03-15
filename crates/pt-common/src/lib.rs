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

pub mod capabilities;
pub mod categories;
pub mod config;
pub mod error;
pub mod galaxy_brain;
pub mod id;
pub mod output;
pub mod provenance;
pub mod schema;

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
pub use output::OutputFormat;
pub use provenance::{
    ProvenanceConfidence, ProvenanceEdge, ProvenanceEdgeId, ProvenanceEdgeKind, ProvenanceEvidence,
    ProvenanceEvidenceId, ProvenanceEvidenceKind, ProvenanceGraphSnapshot, ProvenanceGraphSummary,
    ProvenanceGraphWarning, ProvenanceNode, ProvenanceNodeId, ProvenanceNodeKind,
    ProvenanceObservationStatus, ProvenanceProcessRef, ProvenanceRedactionState,
    PROVENANCE_SCHEMA_VERSION,
};
pub use schema::SCHEMA_VERSION;
