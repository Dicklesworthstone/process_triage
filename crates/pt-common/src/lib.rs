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

pub mod capabilities;
pub mod categories;
pub mod config;
pub mod error;
pub mod id;
pub mod output;
pub mod schema;

pub use capabilities::{
    Capabilities, CapabilitiesError, CgroupInfo, CgroupVersion, ContainerInfo, CpuArch,
    LaunchdInfo, OsFamily, OsInfo, PathsInfo, PrivilegesInfo, ProcField, ProcFsInfo, PsiInfo,
    SudoInfo, SystemdInfo, SystemInfo, ToolInfo, ToolPermissions, UserInfo,
    CAPABILITIES_SCHEMA_VERSION, DEFAULT_CACHE_TTL_SECS,
};
pub use categories::{
    CategoryMatcher, CategoryTaxonomy, CommandCategory, CommandCategoryDef, CommandPattern,
    CwdCategory, CwdCategoryDef, CwdPattern, PriorHints, CATEGORIES_SCHEMA_VERSION,
};
pub use config::{Config, ConfigPaths, ConfigResolver, ConfigSnapshot, Policy, Priors};
pub use error::{Error, Result};
pub use id::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};
pub use output::OutputFormat;
pub use schema::SCHEMA_VERSION;
