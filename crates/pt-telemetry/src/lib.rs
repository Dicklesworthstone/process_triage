//! Process Triage telemetry storage.
//!
//! This crate provides:
//! - Arrow schema definitions for telemetry tables
//! - Batched Parquet writer with compression
//! - Path layout and partitioning helpers

pub mod schema;
pub mod writer;

pub use schema::{
    TelemetrySchema, TableName,
    runs_schema, proc_samples_schema, proc_features_schema,
    proc_inference_schema, outcomes_schema, audit_schema,
};
pub use writer::{BatchedWriter, WriterConfig, WriteError};

/// Schema version for telemetry tables.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Default batch size for buffered writes.
pub const DEFAULT_BATCH_SIZE: usize = 1000;

/// Default flush interval in seconds.
pub const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 30;
