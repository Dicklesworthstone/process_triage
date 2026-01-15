//! Process Triage Core Library
//!
//! This library provides the core functionality for process triage:
//! - Exit codes for CLI operations
//! - Configuration loading and validation
//! - CLI utilities and helpers
//! - Process collection and scanning
//!
//! The binary entry point is in `main.rs`.

pub mod cli;
pub mod collect;
pub mod config;
pub mod decision;
pub mod exit_codes;
pub mod inference;
pub mod logging;

// Re-export test utilities for integration tests
#[cfg(test)]
pub mod test_utils;
