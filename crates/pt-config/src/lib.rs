//! Process Triage configuration loading and validation.
//!
//! This crate provides:
//! - Typed Rust structs for priors.json and policy.json
//! - Config resolution (CLI → env → XDG → defaults)
//! - Schema and semantic validation
//! - Config snapshots for session telemetry
//! - Configuration presets for common deployment scenarios

pub mod policy;
pub mod policy_bundle;
pub mod preset;
pub mod priors;
pub mod provenance;
pub mod resolve;
pub mod snapshot;
pub mod validate;

pub use policy::Policy;
pub use policy_bundle::{PolicyBundle, PolicyBundleError, PolicyMode};
pub use preset::{get_preset, list_presets, PresetError, PresetInfo, PresetName};
pub use priors::Priors;
pub use provenance::{
    EffectiveProvenanceControls, ProvenanceCollectionDepth, ProvenanceControlSurface,
    ProvenanceControlSurfaceKind, ProvenanceControls, ProvenanceDegradationLevel,
    ProvenanceExecutionContext, ProvenanceExplanationVerbosity, ProvenanceExportMode,
    ProvenancePerformanceBudget, ProvenancePersistenceMode, ProvenanceRedactionLevel,
    ProvenanceRolloutPosture, PROVENANCE_CONTROL_MODEL_VERSION,
};
pub use resolve::{resolve_config, ConfigPaths};
pub use snapshot::ConfigSnapshot;
pub use validate::{ValidationError, ValidationResult};

/// Schema version for configuration files.
pub const CONFIG_SCHEMA_VERSION: &str = "1.0.0";
