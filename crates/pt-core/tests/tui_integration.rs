#![cfg(feature = "ui")]

use ftui::layout::Rect;
use ftui::widgets::StatefulWidget as FtuiStatefulWidget;
use ftui::{Frame, GraphemePool, KeyCode, KeyEvent, Model as FtuiModel};
use ftui_harness::{assert_snapshot, buffer_to_text};
use pt_core::tui::layout::ResponsiveLayout;
use pt_core::tui::widgets::{
    DetailView, HelpOverlay, ProcessDetail, ProcessRow, ProcessTable, SearchInput, StatusBar,
    StatusMode,
};
use pt_core::tui::{App, AppState, Msg};

fn status_mode(state: AppState) -> StatusMode {
    match state {
        AppState::Normal => StatusMode::Normal,
        AppState::Searching => StatusMode::Searching,
        AppState::Confirming => StatusMode::Confirming,
        AppState::Help => StatusMode::Help,
        AppState::Quitting => StatusMode::Normal,
    }
}

fn render_like_app_to_buffer(app: &mut App, width: u16, height: u16) -> ftui::Buffer {
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    frame.clear();

    let area = Rect::new(0, 0, width, height);
    let layout = ResponsiveLayout::new(area);
    let areas = layout.main_areas();

    // Search input (stateful)
    SearchInput::new()
        .theme(&app.theme)
        .render_ftui(areas.search, &mut frame, &mut app.search);

    // Process table (stateful)
    let table = ProcessTable::new().theme(&app.theme);
    FtuiStatefulWidget::render(&table, areas.list, &mut frame, &mut app.process_table);

    // Detail pane (stateless widget derived from table state)
    if let Some(detail_area) = areas.detail {
        if app.is_detail_visible() {
            let row = app.process_table.current_row();
            let selected = row
                .map(|r| app.process_table.selected.contains(&r.pid))
                .unwrap_or(false);
            ProcessDetail::new()
                .theme(&app.theme)
                .row(row, selected)
                .view(app.current_detail_view())
                .render_ftui(detail_area, &mut frame);
        }
    }

    // Status bar
    StatusBar::new()
        .theme(&app.theme)
        .mode(status_mode(app.state))
        .selected_count(app.process_table.selected_count())
        .render_ftui(areas.status, &mut frame);

    // Help overlay (modal)
    if app.state == AppState::Help {
        HelpOverlay::new()
            .theme(&app.theme)
            .breakpoint(layout.breakpoint())
            .render_ftui(area, &mut frame);
    }

    let Frame { buffer, .. } = frame;
    buffer
}

/// Render via the real Model::view() code path (not manual widget-by-widget).
fn render_app_view(app: &App, width: u16, height: u16) -> ftui::Buffer {
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    <App as FtuiModel>::view(app, &mut frame);
    let Frame { buffer, .. } = frame;
    buffer
}

fn sample_row() -> ProcessRow {
    ProcessRow {
        pid: 4242,
        score: 91,
        classification: "KILL".to_string(),
        runtime: "3h 12m".to_string(),
        memory: "1.2 GB".to_string(),
        command: "node dev server".to_string(),
        selected: false,
        galaxy_brain: Some("Galaxy-Brain Mode\nPosterior Distribution".to_string()),
        why_summary: Some("Old + idle + orphaned".to_string()),
        top_evidence: vec!["PPID=1".to_string(), "Idle>2h".to_string()],
        confidence: Some("high".to_string()),
        plan_preview: vec!["SIGTERM -> SIGKILL".to_string()],
    }
}

#[test]
fn app_renders_galaxy_brain_split() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let _cmd =
        <App as FtuiModel>::update(&mut app, Msg::KeyPressed(KeyEvent::new(KeyCode::Char('g'))));
    assert_eq!(app.state, AppState::Normal);
    assert_eq!(app.current_detail_view(), DetailView::GalaxyBrain);

    let buf = render_like_app_to_buffer(&mut app, 120, 40);
    assert_snapshot!("tui_app_split_galaxy_brain_120x40", &buf);
    assert!(
        buffer_to_text(&buf).contains("Galaxy Brain")
            || buffer_to_text(&buf).contains("Galaxy-Brain Mode")
    );
}

#[test]
fn app_help_overlay_renders() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let _cmd =
        <App as FtuiModel>::update(&mut app, Msg::KeyPressed(KeyEvent::new(KeyCode::Char('?'))));
    assert_eq!(app.state, AppState::Help);

    let buf = render_like_app_to_buffer(&mut app, 100, 30);
    assert_snapshot!("tui_app_help_overlay_100x30", &buf);
    assert!(buffer_to_text(&buf).contains("Process Triage TUI Help"));
}

// ── Tests using the real Model::view() code path ────────────────────

#[test]
fn view_renders_at_standard_breakpoint() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_standard_140x40", &buf);
    // Should contain search box, process table, detail pane, status bar
    assert!(text.contains("Search"), "search widget missing");
    assert!(text.contains("4242") || text.contains("KILL"), "process table missing");
}

#[test]
fn view_renders_at_wide_breakpoint() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let buf = render_app_view(&app, 220, 60);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_wide_220x60", &buf);
    assert!(text.contains("Search"), "search widget missing");
    assert!(text.contains("4242") || text.contains("KILL"), "process table missing");
}

#[test]
fn view_renders_at_compact_breakpoint() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let buf = render_app_view(&app, 100, 30);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_compact_100x30", &buf);
    assert!(text.contains("Search"), "search widget missing");
}

#[test]
fn view_renders_at_minimal_breakpoint() {
    let app = App::new();

    let buf = render_app_view(&app, 60, 20);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_minimal_60x20", &buf);
    // Minimal layout: no detail pane, compact search
    assert!(!text.is_empty(), "minimal view should render something");
}

#[test]
fn view_degrades_for_tiny_terminal() {
    let app = App::new();

    let buf = render_app_view(&app, 30, 8);
    let text = buffer_to_text(&buf);

    // Should show "too small" message instead of crashing
    assert!(
        text.contains("too small"),
        "tiny terminal should show size warning"
    );
}

#[test]
fn view_shows_help_overlay_via_model() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);
    <App as FtuiModel>::update(&mut app, Msg::ToggleHelp);
    assert_eq!(app.state, AppState::Help);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_help_overlay_120x40", &buf);
    assert!(
        text.contains("Process Triage TUI Help"),
        "help overlay should render"
    );
}

#[test]
fn view_shows_search_mode() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);
    <App as FtuiModel>::update(&mut app, Msg::EnterSearchMode);
    <App as FtuiModel>::update(&mut app, Msg::SearchInput('f'));
    <App as FtuiModel>::update(&mut app, Msg::SearchInput('o'));
    assert_eq!(app.state, AppState::Searching);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_searching_120x40", &buf);
    // Search widget should show the typed text
    assert!(text.contains("fo"), "search input should show typed text");
}

#[test]
fn view_renders_with_goal_summary() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);
    app.set_goal_summary(vec![
        "Goal: Kill abandoned dev servers".to_string(),
        "Focus: PIDs with score > 80".to_string(),
    ]);

    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_goal_summary_140x40", &buf);
    assert!(
        text.contains("Kill abandoned dev servers"),
        "goal summary should render"
    );
}

#[test]
fn view_renders_galaxy_brain_via_model() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);
    <App as FtuiModel>::update(
        &mut app,
        Msg::KeyPressed(KeyEvent::new(KeyCode::Char('g'))),
    );
    assert_eq!(app.current_detail_view(), DetailView::GalaxyBrain);

    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_galaxy_brain_140x40", &buf);
    assert!(
        text.contains("Galaxy Brain") || text.contains("Galaxy-Brain Mode"),
        "galaxy brain detail should render"
    );
}

#[test]
fn view_empty_table_renders_cleanly() {
    let app = App::new();

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_empty_table_120x40", &buf);
    // Should render structure even with no processes
    assert!(text.contains("Search"), "search widget should still render");
}

#[test]
fn view_shows_confirm_dialog() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);
    // Select the process and trigger confirmation
    app.process_table.toggle_selection();
    <App as FtuiModel>::update(
        &mut app,
        Msg::KeyPressed(KeyEvent::new(KeyCode::Char('e'))),
    );
    assert_eq!(app.state, AppState::Confirming);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_confirm_dialog_120x40", &buf);
    assert!(
        text.contains("Confirm") || text.contains("Execute"),
        "confirm dialog should render"
    );
}
