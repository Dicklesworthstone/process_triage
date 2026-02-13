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
pub mod agent_init;
pub mod audit;
pub mod calibrate;
pub mod capabilities;
pub mod cli;
pub mod collect;
pub mod config;
pub mod daemon;
pub mod decision;
pub mod events;
pub mod exit_codes;
pub mod fleet;
pub mod inbox;
pub mod inference;
pub mod install;
pub mod logging;
pub mod mcp;
pub mod output;
pub mod plan;
pub mod replay;
pub mod schema;
pub mod session;
pub mod shadow;
pub mod signature_cli;
pub mod supervision;
pub mod verify;

// TUI module (optional, behind "ui" feature)
#[cfg(feature = "ui")]
pub mod tui;

// Re-export test utilities for integration tests
#[cfg(any(test, feature = "test-utils"))]
pub mod mock_process;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_log;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
