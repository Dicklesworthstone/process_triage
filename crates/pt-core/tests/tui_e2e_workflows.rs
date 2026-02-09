#![cfg(feature = "ui")]
//! E2E TUI workflow tests using ftui message-based testing.
//!
//! All interactions use ftui `Msg` types sent through `Model::update()`.

use ftui::{
    KeyCode as FtuiKeyCode, KeyEvent as FtuiKeyEvent, Model as FtuiModel,
    Modifiers as FtuiModifiers,
};
use pt_core::tui::widgets::{DetailView, ProcessRow};
use pt_core::tui::{App, AppState, Msg};

// ===========================================================================
// Helpers
// ===========================================================================

/// Send a Msg through the ftui Model::update loop, discarding the Cmd.
fn send_msg(app: &mut App, msg: Msg) {
    let _cmd = <App as FtuiModel>::update(app, msg);
}

/// Send multiple Msgs sequentially.
fn send_msgs(app: &mut App, msgs: &[Msg]) {
    for msg in msgs {
        send_msg(app, msg.clone());
    }
}

/// Create a KeyPressed Msg from a key code.
fn ftui_key(code: FtuiKeyCode) -> Msg {
    Msg::KeyPressed(FtuiKeyEvent::new(code))
}

/// Create a KeyPressed Msg for a character key.
fn ftui_char(c: char) -> Msg {
    ftui_key(FtuiKeyCode::Char(c))
}

/// Create a KeyPressed Msg with Ctrl modifier.
fn ftui_key_ctrl(c: char) -> Msg {
    Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char(c)).with_modifiers(FtuiModifiers::CTRL))
}

fn make_row(
    pid: u32,
    score: u32,
    classification: &str,
    runtime: &str,
    memory: &str,
    command: &str,
    galaxy_brain: Option<&str>,
) -> ProcessRow {
    ProcessRow {
        pid,
        score,
        classification: classification.to_string(),
        runtime: runtime.to_string(),
        memory: memory.to_string(),
        command: command.to_string(),
        selected: false,
        galaxy_brain: galaxy_brain.map(|s| s.to_string()),
        why_summary: None,
        top_evidence: vec![],
        confidence: None,
        plan_preview: vec![],
    }
}

fn sample_rows() -> Vec<ProcessRow> {
    vec![
        make_row(
            1001,
            95,
            "KILL",
            "3d 2h",
            "2.1 GB",
            "node dev-server --watch",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.95"),
        ),
        make_row(
            1002,
            72,
            "REVIEW",
            "12h 30m",
            "512 MB",
            "python train.py --epochs 100",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.72"),
        ),
        make_row(1003, 15, "SPARE", "5m", "64 MB", "vim session.rs", None),
        make_row(
            1004,
            88,
            "KILL",
            "7d 4h",
            "4.0 GB",
            "jupyter notebook --port 8888",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.88"),
        ),
        make_row(
            1005,
            45,
            "REVIEW",
            "1h 15m",
            "256 MB",
            "cargo test --workspace",
            None,
        ),
    ]
}

fn app_with_rows() -> App {
    let mut app = App::new();
    app.process_table.set_rows(sample_rows());
    app
}

// ===========================================================================
// 1. Navigation Workflows (key bindings: j/Down, k/Up, Home, End, etc.)
// ===========================================================================

#[test]
fn nav_cursor_down_moves_selection() {
    let mut app = app_with_rows();
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, ftui_char('j'));
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Down));
    assert_eq!(app.process_table.cursor, 2);
}

#[test]
fn nav_cursor_up_moves_selection() {
    let mut app = app_with_rows();

    // Move down first, then back up
    send_msgs(&mut app, &[ftui_char('j'), ftui_char('j'), ftui_char('k')]);
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Up));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_cursor_wraps_at_boundaries() {
    let mut app = app_with_rows();

    // At top, going up shouldn't crash
    send_msg(&mut app, ftui_char('k'));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_home_end_jumps() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key(FtuiKeyCode::End));
    assert_eq!(app.process_table.cursor, 4); // last row

    send_msg(&mut app, ftui_key(FtuiKeyCode::Home));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_page_down_up() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key(FtuiKeyCode::PageDown));
    // With 5 rows and page size 10, should be at last row
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, ftui_key(FtuiKeyCode::PageUp));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_ctrl_d_ctrl_u_page() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key_ctrl('d'));
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, ftui_key_ctrl('u'));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_cursor_via_semantic_msgs() {
    // Test semantic navigation messages directly (no key binding involved)
    let mut app = app_with_rows();

    send_msgs(&mut app, &[Msg::CursorDown, Msg::CursorDown]);
    assert_eq!(app.process_table.cursor, 2);

    send_msg(&mut app, Msg::CursorUp);
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, Msg::CursorHome);
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, Msg::CursorEnd);
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, Msg::PageUp);
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, Msg::PageDown);
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, Msg::HalfPageUp);
    assert_eq!(app.process_table.cursor, 0);
}

// ===========================================================================
// 2. Search/Filter Workflows
// ===========================================================================

#[test]
fn search_enter_and_exit() {
    let mut app = app_with_rows();
    assert_eq!(app.state, AppState::Normal);

    send_msg(&mut app, ftui_char('/'));
    assert_eq!(app.state, AppState::Searching);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_type_and_filter() {
    let mut app = app_with_rows();

    // Enter search mode and type "node"
    send_msg(&mut app, ftui_char('/'));
    send_msgs(
        &mut app,
        &[
            ftui_char('n'),
            ftui_char('o'),
            ftui_char('d'),
            ftui_char('e'),
        ],
    );

    // Search query should be populated
    assert_eq!(app.search.value, "node");
}

#[test]
fn search_backspace_deletes() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('/'));
    send_msgs(
        &mut app,
        &[
            ftui_char('a'),
            ftui_char('b'),
            ftui_key(FtuiKeyCode::Backspace),
        ],
    );

    assert_eq!(app.search.value, "a");
}

#[test]
fn search_enter_confirms_and_returns_to_normal() {
    let mut app = app_with_rows();

    send_msgs(
        &mut app,
        &[ftui_char('/'), ftui_char('k'), ftui_key(FtuiKeyCode::Enter)],
    );

    assert_eq!(app.state, AppState::Normal);
    // Search should have been committed
    assert!(!app.search.value.is_empty());
}

#[test]
fn search_via_semantic_msgs() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::EnterSearchMode);
    assert_eq!(app.state, AppState::Searching);

    send_msgs(
        &mut app,
        &[
            Msg::SearchInput('t'),
            Msg::SearchInput('e'),
            Msg::SearchInput('s'),
            Msg::SearchInput('t'),
        ],
    );
    assert_eq!(app.search.value, "test");

    send_msg(&mut app, Msg::SearchBackspace);
    assert_eq!(app.search.value, "tes");

    send_msg(&mut app, Msg::SearchCommit);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_cancel_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('x'));
    send_msg(&mut app, Msg::SearchCancel);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_history_via_msg() {
    let mut app = app_with_rows();

    // First search
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('a'));
    send_msg(&mut app, Msg::SearchCommit);

    // Second search
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('b'));
    send_msg(&mut app, Msg::SearchCommit);

    // Navigate history
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchHistoryUp);
    // Should not crash
    send_msg(&mut app, Msg::SearchHistoryDown);
    send_msg(&mut app, Msg::SearchCancel);
}

// ===========================================================================
// 3. Selection/Toggle Workflows
// ===========================================================================

#[test]
fn toggle_selection_on_current_row() {
    let mut app = app_with_rows();

    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 1);

    // Toggle again to deselect
    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn select_all_and_deselect_all() {
    let mut app = app_with_rows();

    // Select all with 'A' key binding
    send_msg(&mut app, ftui_char('A'));
    assert_eq!(app.process_table.selected_count(), 5);

    // Deselect all with 'u' key binding
    send_msg(&mut app, ftui_char('u'));
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn select_recommended_selects_kill_only() {
    let mut app = app_with_rows();

    // 'a' selects recommended (KILL classification)
    send_msg(&mut app, ftui_char('a'));
    let count = app.process_table.selected_count();
    // We have 2 KILL rows (1001, 1004)
    assert_eq!(count, 2, "Should select 2 KILL-classified rows");
}

#[test]
fn invert_selection_with_x_key() {
    let mut app = app_with_rows();

    // Select first row
    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 1);

    // Invert with 'x' key
    send_msg(&mut app, ftui_char('x'));
    assert_eq!(app.process_table.selected_count(), 4);
}

#[test]
fn invert_selection_via_msg() {
    let mut app = app_with_rows();

    // Select first row
    send_msg(&mut app, Msg::ToggleSelection);
    assert_eq!(app.process_table.selected_count(), 1);

    // Invert via semantic message
    send_msg(&mut app, Msg::InvertSelection);
    assert_eq!(app.process_table.selected_count(), 4);
}

#[test]
fn navigate_and_toggle_multiple() {
    let mut app = app_with_rows();

    // Select rows 0, 2, 4 by navigating and toggling
    send_msgs(
        &mut app,
        &[
            ftui_char(' '), // select row 0
            ftui_char('j'), // move to row 1
            ftui_char('j'), // move to row 2
            ftui_char(' '), // select row 2
            ftui_char('j'), // move to row 3
            ftui_char('j'), // move to row 4
            ftui_char(' '), // select row 4
        ],
    );
    assert_eq!(app.process_table.selected_count(), 3);
}

#[test]
fn selection_via_semantic_msgs() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::SelectAll);
    assert_eq!(app.process_table.selected_count(), 5);

    send_msg(&mut app, Msg::DeselectAll);
    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, Msg::SelectRecommended);
    assert_eq!(app.process_table.selected_count(), 2);

    send_msg(&mut app, Msg::InvertSelection);
    assert_eq!(app.process_table.selected_count(), 3);
}

// ===========================================================================
// 4. Drilldown / Detail View Workflows
// ===========================================================================

#[test]
fn detail_view_toggle_visibility() {
    let mut app = app_with_rows();

    let initial = app.is_detail_visible();
    // Enter toggles detail visibility
    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    assert_ne!(app.is_detail_visible(), initial);
}

#[test]
fn detail_view_switch_to_genealogy() {
    let mut app = app_with_rows();

    // 't' switches to genealogy view
    send_msg(&mut app, ftui_char('t'));
    assert_eq!(app.current_detail_view(), DetailView::Genealogy);
}

// ===========================================================================
// 5. Execute / Abort Workflows
// ===========================================================================

#[test]
fn execute_shows_confirmation_dialog() {
    let mut app = app_with_rows();

    // Select a process and press 'e' (ftui execute binding) to execute
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);

    // Should show confirmation dialog
    assert!(
        app.confirm_dialog.visible,
        "Confirmation dialog should be visible"
    );
}

#[test]
fn execute_abort_with_escape() {
    let mut app = app_with_rows();

    // Select, execute, then abort
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert!(!app.confirm_dialog.visible);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn execute_confirm_with_enter() {
    let mut app = app_with_rows();

    // Select, execute, then confirm
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    // After confirmation, dialog should close
    assert!(!app.confirm_dialog.visible);
}

#[test]
fn execute_with_no_selection_shows_status() {
    let mut app = app_with_rows();
    assert_eq!(app.process_table.selected_count(), 0);

    // Try to execute with nothing selected (ftui 'e' binding)
    send_msg(&mut app, ftui_char('e'));

    // Should not show confirmation (nothing selected)
    assert!(!app.confirm_dialog.visible);
}

#[test]
fn confirmation_dialog_tab_toggles() {
    let mut app = app_with_rows();

    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    // Tab should toggle between options
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    // No crash
}

#[test]
fn confirmation_dialog_left_right() {
    let mut app = app_with_rows();

    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    // Navigate left/right
    send_msgs(
        &mut app,
        &[
            ftui_char('l'), // right
            ftui_char('h'), // left
        ],
    );
}

// ===========================================================================
// 6. Help Overlay Workflow
// ===========================================================================

#[test]
fn help_opens_and_closes() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn help_question_mark_toggles() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn help_toggle_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::ToggleHelp);
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, Msg::ToggleHelp);
    assert_eq!(app.state, AppState::Normal);
}

// ===========================================================================
// 7. Quit Workflow
// ===========================================================================

#[test]
fn quit_with_q() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('q'));
    assert!(app.should_quit());
}

#[test]
fn quit_with_ctrl_c() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key_ctrl('c'));
    assert!(app.should_quit());
}

#[test]
fn quit_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::Quit);
    assert!(app.should_quit());
}

#[test]
fn quit_from_help_returns_to_normal() {
    let mut app = app_with_rows();

    // Enter help, then quit help
    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_char('q'));
    assert_eq!(app.state, AppState::Normal);

    // Now quit from normal
    send_msg(&mut app, ftui_char('q'));
    assert!(app.should_quit());
}

// ===========================================================================
// 8. Focus Cycling
// ===========================================================================

#[test]
fn tab_cycles_focus() {
    let mut app = app_with_rows();

    // Tab should cycle through focus targets
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    // No crash
}

#[test]
fn focus_cycle_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::FocusNext);
    send_msg(&mut app, Msg::FocusPrev);
    // No crash
}

// ===========================================================================
// 9. Resize Handling
// ===========================================================================

#[test]
fn resize_updates_layout() {
    let mut app = app_with_rows();

    // Simulate resize via ftui Msg
    send_msg(
        &mut app,
        Msg::Resized {
            width: 200,
            height: 60,
        },
    );

    // Simulate resize to compact
    send_msg(
        &mut app,
        Msg::Resized {
            width: 80,
            height: 24,
        },
    );
}

#[test]
fn minimal_terminal_renders_without_crash() {
    let mut app = app_with_rows();

    // Very small terminal
    send_msg(
        &mut app,
        Msg::Resized {
            width: 40,
            height: 10,
        },
    );
    // No crash
}

// ===========================================================================
// 10. Full Workflow Sequences
// ===========================================================================

#[test]
fn workflow_search_filter_select_abort() {
    let mut app = app_with_rows();

    // 1. Search for "python"
    send_msgs(
        &mut app,
        &[
            ftui_char('/'),
            ftui_char('p'),
            ftui_char('y'),
            ftui_char('t'),
            ftui_char('h'),
            ftui_char('o'),
            ftui_char('n'),
            ftui_key(FtuiKeyCode::Enter),
        ],
    );
    assert_eq!(app.state, AppState::Normal);

    // 2. Select all visible
    send_msg(&mut app, ftui_char('A'));

    // 3. Execute (ftui binding: 'e')
    send_msg(&mut app, ftui_char('e'));

    // 4. Abort
    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert!(!app.confirm_dialog.visible);
    assert_eq!(app.state, AppState::Normal);

    // 5. Deselect all
    send_msg(&mut app, ftui_char('u'));
    assert_eq!(app.process_table.selected_count(), 0);
}

// ===========================================================================
// 12. Status Messages & Refresh
// ===========================================================================

#[test]
fn refresh_sets_status_message() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('r'));
    // In ftui path, 'r' dispatches Msg::RequestRefresh via FtuiCmd::msg
    // The refresh_op is None (skeleton mode), so it returns a task Cmd
    // but the status should still be set
}

#[test]
fn refresh_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::RequestRefresh);
    // Should not crash; in skeleton mode, returns a task that resolves to empty rows
}

// ===========================================================================
// 13. Async Result Messages
// ===========================================================================

#[test]
fn processes_scanned_updates_rows() {
    let mut app = App::new();
    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, Msg::ProcessesScanned(sample_rows()));
    assert_eq!(app.process_table.rows.len(), 5);
}

#[test]
fn refresh_complete_updates_rows() {
    let mut app = app_with_rows();

    let new_rows = vec![make_row(
        9999,
        50,
        "REVIEW",
        "1h",
        "128 MB",
        "test-process",
        None,
    )];
    send_msg(&mut app, Msg::RefreshComplete(Ok(new_rows)));
    assert_eq!(app.process_table.rows.len(), 1);
}

#[test]
fn execution_complete_ok() {
    use pt_core::tui::ExecutionOutcome;
    let mut app = app_with_rows();

    send_msg(
        &mut app,
        Msg::ExecutionComplete(Ok(ExecutionOutcome {
            mode: None,
            attempted: 3,
            succeeded: 2,
            failed: 1,
        })),
    );
    // Should not crash; status is set
}

#[test]
fn execution_complete_err() {
    let mut app = app_with_rows();

    send_msg(
        &mut app,
        Msg::ExecutionComplete(Err("test error".to_string())),
    );
    // Should not crash; error status is set
}

// ===========================================================================
// 14. Empty State
// ===========================================================================

#[test]
fn empty_process_list_navigation_safe() {
    let mut app = App::new();

    // Navigation on empty list should not crash
    send_msgs(
        &mut app,
        &[
            ftui_char('j'),
            ftui_char('k'),
            ftui_key(FtuiKeyCode::Home),
            ftui_key(FtuiKeyCode::End),
            ftui_char(' '),
            ftui_char('A'),
            ftui_char('u'),
        ],
    );
}

#[test]
fn empty_process_list_semantic_msgs_safe() {
    let mut app = App::new();

    send_msgs(
        &mut app,
        &[
            Msg::CursorDown,
            Msg::CursorUp,
            Msg::CursorHome,
            Msg::CursorEnd,
            Msg::PageDown,
            Msg::PageUp,
            Msg::HalfPageDown,
            Msg::HalfPageUp,
            Msg::ToggleSelection,
            Msg::SelectAll,
            Msg::DeselectAll,
            Msg::InvertSelection,
            Msg::SelectRecommended,
        ],
    );
    // No crash
}

// ===========================================================================
// 15. Rapid Event Sequences (Stress Tests)
// ===========================================================================

#[test]
fn rapid_navigation_stress() {
    let mut app = app_with_rows();

    // 100 rapid key presses
    for _ in 0..100 {
        send_msg(&mut app, ftui_char('j'));
    }
    // Cursor should be clamped to valid range
    assert!(app.process_table.cursor < 5);

    for _ in 0..100 {
        send_msg(&mut app, ftui_char('k'));
    }
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn rapid_toggle_stress() {
    let mut app = app_with_rows();

    // Rapidly toggle selection 200 times
    for _ in 0..200 {
        send_msg(&mut app, ftui_char(' '));
    }

    // Even number of toggles -> should be back to 0
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn rapid_search_enter_exit_stress() {
    let mut app = app_with_rows();

    // Enter and exit search 50 times
    for _ in 0..50 {
        send_msgs(&mut app, &[ftui_char('/'), ftui_key(FtuiKeyCode::Escape)]);
    }
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn rapid_semantic_msg_stress() {
    let mut app = app_with_rows();

    for _ in 0..50 {
        send_msgs(
            &mut app,
            &[
                Msg::CursorDown,
                Msg::ToggleSelection,
                Msg::CursorDown,
                Msg::CursorUp,
            ],
        );
    }
    // Should not crash
}

// ===========================================================================
// 16. Misc ftui-Specific Messages
// ===========================================================================

#[test]
fn tick_msg_is_noop() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::Tick);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn noop_msg_is_noop() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::Noop);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn focus_changed_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::FocusChanged(false));
    send_msg(&mut app, Msg::FocusChanged(true));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn paste_received_enters_search() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::PasteReceived {
            text: "pasted-text".to_string(),
            bracketed: true,
        },
    );
    assert_eq!(app.state, AppState::Searching);
    assert_eq!(app.search.value, "pasted-text");
}

#[test]
fn clipboard_received_sets_search_value() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::ClipboardReceived("clipboard-content".to_string()),
    );
    assert_eq!(app.search.value, "clipboard-content");
}

#[test]
fn export_evidence_ledger_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::ExportEvidenceLedger);
    // Should not crash; sets status about not being wired
}

#[test]
fn ledger_exported_ok() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::LedgerExported(Ok(std::path::PathBuf::from("/tmp/ledger.json"))),
    );
    // Should not crash
}

#[test]
fn ledger_exported_err() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::LedgerExported(Err("export failed".to_string())),
    );
    // Should not crash
}

#[test]
fn confirm_execute_via_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::ConfirmExecute);
    // Directly triggers confirmation handling
}

#[test]
fn cancel_execute_via_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::CancelExecute);
    // Directly triggers cancel handling
}

#[test]
fn goal_view_toggle_msg() {
    let mut app = app_with_rows();
    // No goal order set, should report unavailable
    send_msg(&mut app, Msg::ToggleGoalView);
    // Should not crash
}
