//! TUI widgets for Process Triage.
//!
//! This module provides widget wrappers integrating rat-widget components
//! with the Process Triage application state.
//!
//! # Widgets
//!
//! - `SearchInput`: Text input for filtering processes
//! - `ProcessTable`: Table displaying process candidates
//! - `ConfirmDialog`: Confirmation dialog for actions
//! - `ConfigEditor`: Form for editing configuration values

mod aux_panel;
mod config_editor;
mod confirm_dialog;
mod help_overlay;
mod process_detail;
mod process_table;
mod search_input;
mod status_bar;

pub use aux_panel::AuxPanel;
pub use config_editor::{ConfigEditor, ConfigEditorState, ConfigField, ConfigFieldType};
pub use confirm_dialog::{ConfirmChoice, ConfirmDialog, ConfirmDialogState};
pub use help_overlay::HelpOverlay;
pub use process_detail::{DetailView, ProcessDetail};
pub use process_table::{
    ProcessRow, ProcessTable, ProcessTableState, SortColumn, SortOrder, ViewMode,
};
pub use search_input::{SearchInput, SearchInputState};
pub use status_bar::{StatusBar, StatusMode};
