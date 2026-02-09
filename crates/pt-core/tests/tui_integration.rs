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
