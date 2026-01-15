//! Process Triage configuration loading and validation.
//!
//! This crate provides:
//! - Typed Rust structs for priors.json and policy.json
//! - Config resolution (CLI → env → XDG → defaults)
//! - Schema and semantic validation
//! - Config snapshots for session telemetry

pub mod policy;
pub mod priors;
pub mod resolve;
pub mod snapshot;
pub mod validate;

pub use policy::Policy;
pub use priors::Priors;
pub use resolve::{ConfigPaths, resolve_config};
pub use snapshot::ConfigSnapshot;
pub use validate::{ValidationError, ValidationResult};

/// Schema version for configuration files.
pub const CONFIG_SCHEMA_VERSION: &str = "1.0.0";
