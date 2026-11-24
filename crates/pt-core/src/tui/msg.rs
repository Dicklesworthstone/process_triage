//! Central message type for the ftui Elm-style architecture.
//!
//! This module defines a single `Msg` enum that captures user input, view/state
//! transitions, and async command completions. It is intentionally exhaustive
//! so all transitions can be handled with explicit `match` arms in the model.
//!
//! When adding new variants:
//! - Prefer reusing existing navigation/selection messages over adding key-specific variants
//! - Keep `From<ftui::Event>` mapping shallow (Event -> Msg::KeyPressed/Resized/etc.)
//! - Update `App::update` to handle the new transition explicitly

use std::collections::HashMap;
use std::path::PathBuf;

use ftui::{Event, KeyEvent};

use super::widgets::{DetailView, ProcessRow};

/// Async execution summary returned to the update loop.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOutcome {
    /// Execution mode hint for status messaging (e.g. "dry_run", "shadow", "skeleton").
    /// "feedback" means explicit spare judgments were saved without executing actions.
    /// "feedback_dry_run" and "feedback_shadow" preview those judgments without saving.
    /// When `None`, the outcome represents a real execution attempt.
    pub mode: Option<String>,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
}

/// Display-only host observations and responsible units from one scan.
/// These summaries never authorize a process or a whole-unit action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PressureOverview {
    pub header: Vec<String>,
    pub details: Vec<String>,
    pub units: Vec<PressureUnit>,
}

/// An attributed workload and the candidate rows from this same snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PressureUnit {
    pub id: String,
    pub label: String,
    pub member_pids: Vec<u32>,
    pub summary: String,
    pub details: Vec<String>,
}

/// Rows, pressure observations, and goal metadata from the same completed scan.
#[derive(Debug, Clone, Default)]
pub struct RefreshOutcome {
    pub rows: Vec<ProcessRow>,
    pub pressure: Option<PressureOverview>,
    pub goal_summary: Option<Vec<String>>,
    /// Only the executable goal selection is ranked. An empty map explicitly
    /// recommends no actions; `None` uses the ordinary row recommendations.
    pub goal_selection: Option<HashMap<u32, usize>>,
}

/// One immutable control batch and the durable receipt state reviewed by a user.
/// The backend must revalidate both bindings under the execution lock before
/// restoring anything; display text and counts never authorize a write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoBatch {
    pub session_id: String,
    pub plan_sha256: String,
    pub receipt_fingerprint: String,
    pub created_at: String,
    pub pending: usize,
    pub settled: usize,
    pub unsupported: usize,
    pub unrecorded: usize,
    pub details: Vec<String>,
    pub blocked_reason: Option<String>,
}

/// Persisted controls belonging to this TUI session, including unavailable and
/// already settled batches. Read-only modes may inspect without restoring.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoOverview {
    pub batches: Vec<UndoBatch>,
    pub read_only_reason: Option<String>,
    pub notes: Vec<String>,
}

/// Actual restoration results together with a fresh persisted overview.
/// Partial failures remain successful callback returns with `error` populated,
/// so the UI can retain both completed restorations and pending controls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoRestoreOutcome {
    pub overview: UndoOverview,
    pub session_id: String,
    pub restored: usize,
    pub remaining: usize,
    pub summary: String,
    pub error: Option<String>,
}

/// Single message type used by the ftui model update loop.
#[derive(Debug, Clone)]
pub enum Msg {
    // Input messages
    KeyPressed(KeyEvent),
    Resized {
        width: u16,
        height: u16,
    },
    Tick,
    FocusChanged(bool),
    PasteReceived {
        text: String,
        bracketed: bool,
    },
    ClipboardReceived(String),
    Noop,

    // Navigation messages
    CursorUp,
    CursorDown,
    CursorHome,
    CursorEnd,
    PageUp,
    PageDown,
    HalfPageUp,
    HalfPageDown,

    // Selection messages
    ToggleSelection,
    SelectRecommended,
    SelectAll,
    DeselectAll,
    InvertSelection,

    // Search messages
    EnterSearchMode,
    SearchInput(char),
    SearchBackspace,
    SearchCommit,
    SearchCancel,
    SearchHistoryUp,
    SearchHistoryDown,

    // View messages
    ToggleDetail,
    SetDetailView(DetailView),
    ToggleGoalView,
    ToggleHelp,
    OpenUndo,
    CloseUndo,
    OpenPressure,
    ClosePressure,
    FilterPressureUnit,
    ClearPressureFilter,

    // Action messages
    RequestExecute {
        ticket: u64,
    },
    ConfirmExecute,
    CancelExecute,
    RequestRefresh,
    ExportEvidenceLedger,
    RequestUndoRefresh,
    ShowUndoConfirmation,
    ConfirmUndo,
    CancelUndo,
    RequestUndo {
        ticket: u64,
    },

    // Async result messages
    ProcessesScanned(Vec<ProcessRow>),
    ExecutionComplete {
        ticket: u64,
        result: Result<ExecutionOutcome, String>,
    },
    RefreshComplete {
        ticket: u64,
        result: Result<RefreshOutcome, String>,
    },
    UndoLoaded {
        ticket: u64,
        result: Result<UndoOverview, String>,
    },
    UndoComplete {
        ticket: u64,
        result: Result<UndoRestoreOutcome, String>,
    },
    LedgerExported(Result<PathBuf, String>),

    // Theme messages
    SwitchTheme(String),

    // Focus messages
    FocusNext,
    FocusPrev,

    // System messages
    Quit,
}

impl From<Event> for Msg {
    fn from(event: Event) -> Self {
        match event {
            Event::Key(key) => Msg::KeyPressed(key),
            Event::Resize { width, height } => Msg::Resized { width, height },
            Event::Tick => Msg::Tick,
            Event::Focus(gained) => Msg::FocusChanged(gained),
            Event::Paste(paste) => Msg::PasteReceived {
                text: paste.text,
                bracketed: paste.bracketed,
            },
            Event::Clipboard(clipboard) => Msg::ClipboardReceived(clipboard.content),
            Event::Mouse(_) => Msg::Noop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ftui::{KeyCode, Modifiers};

    fn assert_send_static<T: Send + 'static>() {}

    #[test]
    fn key_event_maps_to_keypressed_msg() {
        let event = Event::Key(KeyEvent::new(KeyCode::Char('q')).with_modifiers(Modifiers::CTRL));
        let msg = Msg::from(event);
        let Msg::KeyPressed(key) = msg else {
            unreachable!("expected Msg::KeyPressed");
        };

        assert!(matches!(key.code, KeyCode::Char('q')));
        assert!(key.modifiers.contains(Modifiers::CTRL));
    }

    #[test]
    fn resize_event_maps_to_resized_msg() {
        let msg = Msg::from(Event::Resize {
            width: 123,
            height: 45,
        });
        let Msg::Resized { width, height } = msg else {
            unreachable!("expected Msg::Resized");
        };

        assert_eq!(width, 123);
        assert_eq!(height, 45);
    }

    #[test]
    fn mouse_event_maps_to_noop() {
        let msg = Msg::from(Event::Mouse(ftui::MouseEvent::new(
            ftui::MouseEventKind::Moved,
            1,
            2,
        )));
        assert!(matches!(msg, Msg::Noop));
    }

    #[test]
    fn async_payloads_are_send_and_static() {
        assert_send_static::<Vec<ProcessRow>>();
        assert_send_static::<Result<ExecutionOutcome, String>>();
        assert_send_static::<Result<RefreshOutcome, String>>();
        assert_send_static::<Result<UndoOverview, String>>();
        assert_send_static::<Result<UndoRestoreOutcome, String>>();
        assert_send_static::<Result<PathBuf, String>>();
    }
}
