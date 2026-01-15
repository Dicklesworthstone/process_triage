//! Process Triage common types, IDs, and errors.
//!
//! This crate provides foundational types shared across pt-core modules:
//! - Process identity types with safety guarantees
//! - Session and schema versioning
//! - Common error types
//! - Output format specifications

pub mod error;
pub mod id;
pub mod output;
pub mod schema;

pub use error::{Error, Result};
pub use id::{ProcessId, SessionId, StartId};
pub use output::OutputFormat;
pub use schema::SCHEMA_VERSION;
