//! Premium TUI for Process Triage using ratatui.
//!
//! This module provides an interactive terminal user interface for process
//! triage operations. It is built on ratatui for rendering with custom
//! widgets for the Process Triage workflow.
//!
//! # Features
//!
//! - Interactive process list with sorting and filtering
//! - Search input with live filtering
//! - Configuration editing via TUI forms
//! - Evidence ledger visualization
//! - Action confirmation dialogs
//!
//! # Module Structure
//!
//! - `app`: Main application state and event loop
//! - `widgets`: Custom widgets for the TUI
//! - `theme`: Color schemes and styling
//! - `events`: Event handling and key bindings

mod app;
mod events;
mod msg;
pub mod layout;
mod theme;
pub mod widgets;

pub use app::{run_tui, run_tui_with_handlers, run_tui_with_refresh, App, AppState};
pub use events::{handle_event, AppAction, KeyBindings};
pub use msg::{ExecutionOutcome, Msg};
pub use layout::{
    Breakpoint, DetailAreas, GalaxyBrainAreas, LayoutState, MainAreas, ResponsiveLayout,
};
pub use theme::{Theme, ThemeMode};

use thiserror::Error;

/// Errors that can occur in the TUI module.
#[derive(Error, Debug)]
pub enum TuiError {
    /// Failed to initialize terminal.
    #[error("terminal initialization failed: {0}")]
    TerminalInit(String),

    /// Failed to restore terminal state.
    #[error("terminal restoration failed: {0}")]
    TerminalRestore(String),

    /// Widget rendering error.
    #[error("widget render error: {0}")]
    WidgetRender(String),

    /// IO error during TUI operation.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for TUI operations.
pub type TuiResult<T> = Result<T, TuiError>;
