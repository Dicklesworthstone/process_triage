#![cfg(feature = "ui")]

use ftui::{Frame, GraphemePool, KeyCode, KeyEvent, Model as FtuiModel};
use ftui_harness::{assert_snapshot, buffer_to_text};
use pt_core::tui::widgets::{DetailView, ProcessRow};
use pt_core::tui::{App, AppState, Msg, Theme, ThemeMode};

/// Render via the real Model::view() code path.
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

    let buf = render_app_view(&app, 120, 40);
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

    let buf = render_app_view(&app, 100, 30);
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
    assert!(
        text.contains("4242") || text.contains("KILL"),
        "process table missing"
    );
}

#[test]
fn view_renders_at_wide_breakpoint() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    let buf = render_app_view(&app, 220, 60);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_wide_220x60", &buf);
    assert!(text.contains("Search"), "search widget missing");
    assert!(
        text.contains("4242") || text.contains("KILL"),
        "process table missing"
    );
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
    <App as FtuiModel>::update(&mut app, Msg::KeyPressed(KeyEvent::new(KeyCode::Char('g'))));
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
    <App as FtuiModel>::update(&mut app, Msg::KeyPressed(KeyEvent::new(KeyCode::Char('e'))));
    assert_eq!(app.state, AppState::Confirming);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_confirm_dialog_120x40", &buf);
    assert!(
        text.contains("Confirm") || text.contains("Execute"),
        "confirm dialog should render"
    );
}

// ── Theme override tests ────────────────────────────────────────────

#[test]
fn theme_override_high_contrast() {
    let mut app = App::new();
    app.theme = Theme::high_contrast();
    app.process_table.set_rows(vec![sample_row()]);

    assert_eq!(app.theme.mode, ThemeMode::HighContrast);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_high_contrast_120x40", &buf);
    assert!(
        text.contains("Search"),
        "search widget should render in HC mode"
    );
    assert!(
        text.contains("4242") || text.contains("KILL"),
        "process table should render in HC mode"
    );
}

#[test]
fn theme_override_light() {
    let mut app = App::new();
    app.theme = Theme::light();
    app.process_table.set_rows(vec![sample_row()]);

    assert_eq!(app.theme.mode, ThemeMode::Light);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_light_theme_120x40", &buf);
    assert!(!text.is_empty(), "light theme should render");
}

#[test]
fn theme_override_no_color() {
    let mut app = App::new();
    app.theme = Theme::no_color();
    app.process_table.set_rows(vec![sample_row()]);

    assert_eq!(app.theme.mode, ThemeMode::NoColor);

    let buf = render_app_view(&app, 120, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_view_no_color_120x40", &buf);
    assert!(!text.is_empty(), "no-color theme should render");
}

#[test]
fn all_themes_validate_wcag_aa() {
    let themes: Vec<Theme> = vec![Theme::dark(), Theme::light(), Theme::high_contrast()];
    for theme in &themes {
        let failures = theme.validate_wcag_aa();
        assert!(
            failures.is_empty(),
            "Theme {:?} WCAG AA failures: {failures:?}",
            theme.mode
        );
    }
}

#[test]
fn high_contrast_theme_validates_wcag_aaa() {
    let theme = Theme::high_contrast();
    let failures = theme.validate_wcag_aaa();
    assert!(
        failures.is_empty(),
        "High contrast WCAG AAA failures: {failures:?}"
    );
}
