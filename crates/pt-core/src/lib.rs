//! Process Triage Core Library
//!
//! This library provides the core functionality for process triage:
//! - Exit codes for CLI operations
//! - Configuration loading and validation
//! - CLI utilities and helpers
//! - Process collection and scanning
//! - Capability detection and caching
//!
//! The binary entry point is in `main.rs`.

pub mod action;
pub mod audit;
pub mod capabilities;
pub mod cli;
pub mod collect;
pub mod config;
pub mod decision;
pub mod events;
pub mod exit_codes;
pub mod inbox;
pub mod inference;
pub mod logging;
pub mod plan;
pub mod session;
pub mod supervision;
pub mod verify;

// Re-export test utilities for integration tests
#[cfg(any(test, feature = "test-utils"))]
pub mod test_log;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
