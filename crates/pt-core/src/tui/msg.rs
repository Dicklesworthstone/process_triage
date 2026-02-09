//! Central message type for the ftui Elm-style architecture.
//!
//! This module defines a single `Msg` enum that captures user input, view/state
//! transitions, and async command completions. It is intentionally exhaustive
//! so all transitions can be handled with explicit `match` arms in the model.

use std::path::PathBuf;

use ftui::{Event, KeyEvent};

use super::widgets::{DetailView, ProcessRow};

/// Async execution summary returned to the update loop.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOutcome {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
}

/// Single message type used by the ftui model update loop.
#[derive(Debug, Clone)]
pub enum Msg {
    // Input messages
    KeyPressed(KeyEvent),
    Resized { width: u16, height: u16 },
    Tick,
    FocusChanged(bool),
    PasteReceived { text: String, bracketed: bool },
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

    // Action messages
    RequestExecute,
    ConfirmExecute,
    CancelExecute,
    RequestRefresh,
    ExportEvidenceLedger,

    // Async result messages
    ProcessesScanned(Vec<ProcessRow>),
    ExecutionComplete(Result<ExecutionOutcome, String>),
    RefreshComplete(Vec<ProcessRow>),
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
        match msg {
            Msg::KeyPressed(key) => {
                assert!(matches!(key.code, KeyCode::Char('q')));
                assert!(key.modifiers.contains(Modifiers::CTRL));
            }
            _ => panic!("expected Msg::KeyPressed"),
        }
    }

    #[test]
    fn resize_event_maps_to_resized_msg() {
        let msg = Msg::from(Event::Resize {
            width: 123,
            height: 45,
        });
        match msg {
            Msg::Resized { width, height } => {
                assert_eq!(width, 123);
                assert_eq!(height, 45);
            }
            _ => panic!("expected Msg::Resized"),
        }
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
        assert_send_static::<Result<PathBuf, String>>();
    }
}
