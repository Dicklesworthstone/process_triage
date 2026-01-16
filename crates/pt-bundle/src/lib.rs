//! Session bundle writer/reader for process triage.
//!
//! This crate provides portable, auditable, integrity-protected session bundles.
//! A `.ptb` bundle packages a triage session for handoff between agents or humans.
//!
//! # Bundle Format
//!
//! Bundles are ZIP archives containing:
//! - `manifest.json`: Metadata, schema versions, file listing with checksums
//! - `plan.json`: Agent plan (optional)
//! - `summary.json`: One-screen summary
//! - `telemetry/`: Parquet files for telemetry data
//! - `logs/`: JSONL logs (optional)
//! - `report.html`: Generated report (optional)
//!
//! # Export Profiles
//!
//! Three profiles control inclusion and redaction:
//! - `minimal`: Aggregate stats only - safe for public sharing
//! - `safe`: Evidence + features with redaction - for team sharing
//! - `forensic`: Raw evidence with explicit allowlist - for support tickets
//!
//! # Example
//!
//! ```no_run
//! use pt_bundle::{BundleWriter, BundleReader, ExportProfile};
//! use std::path::Path;
//!
//! // Write a bundle
//! let mut writer = BundleWriter::new(
//!     "session-123",
//!     "host-abc",
//!     ExportProfile::Safe,
//! );
//! writer.add_summary(&serde_json::json!({"total": 42})).unwrap();
//! writer.write(Path::new("session.ptb")).unwrap();
//!
//! // Read and verify a bundle
//! let mut reader = BundleReader::open(Path::new("session.ptb")).unwrap();
//! let manifest = reader.manifest();
//! let summary: serde_json::Value = reader.read_summary().unwrap();
//! ```

pub mod error;
pub mod encryption;
pub mod manifest;
pub mod reader;
pub mod writer;

pub use error::{BundleError, Result};
pub use encryption::{decrypt_bytes, encrypt_bytes, is_encrypted};
pub use manifest::{BundleManifest, FileEntry, BUNDLE_SCHEMA_VERSION};
pub use pt_redact::ExportProfile;
pub use reader::BundleReader;
pub use writer::{BundleWriter, FileType};
