//! Process collection and scanning.
//!
//! This module provides the evidence collection layer for process triage:
//! - Quick scan via ps parsing (fast, universal)
//! - Deep scan via /proc inspection (detailed, Linux-only)
//!
//! The collection layer produces structured records that feed into the
//! inference engine for classification.

#[cfg(target_os = "linux")]
mod deep_scan;
#[cfg(target_os = "linux")]
mod proc_parsers;
mod quick_scan;
mod types;

#[cfg(target_os = "linux")]
pub use deep_scan::{deep_scan, DeepScanError, DeepScanOptions, DeepScanRecord};
pub use quick_scan::{quick_scan, QuickScanError, QuickScanOptions};
pub use types::{ProcessRecord, ProcessState, ScanResult, ScanMetadata};
