#![cfg(feature = "ui")]

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use pt_core::tui::widgets::ProcessRow;
use pt_core::tui::{App, AppState};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::Terminal;

fn line_string(buf: &Buffer, area: Rect, y: u16) -> String {
    let mut line = String::new();
    for x in area.x..area.x.saturating_add(area.width) {
        line.push_str(buf[(x, y)].symbol());
    }
    line
}

fn buffer_contains(buf: &Buffer, area: Rect, needle: &str) -> bool {
    for y in area.y..area.y.saturating_add(area.height) {
        if line_string(buf, area, y).contains(needle) {
            return true;
        }
    }
    false
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
    }
}

#[test]
fn app_renders_galaxy_brain_split() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    app.handle_event(Event::Key(KeyEvent::new(
        KeyCode::Char('g'),
        KeyModifiers::NONE,
    )))
    .unwrap();
    assert_eq!(app.state, AppState::Normal);

    terminal.draw(|frame| app.render(frame)).unwrap();

    let buf = terminal.backend().buffer();
    let area = Rect::new(0, 0, 120, 40);
    assert!(buffer_contains(buf, area, "Math Trace"));
    assert!(buffer_contains(buf, area, "Galaxy-Brain Mode"));
}

#[test]
fn app_help_overlay_renders() {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row()]);

    app.handle_event(Event::Key(KeyEvent::new(
        KeyCode::Char('?'),
        KeyModifiers::NONE,
    )))
    .unwrap();
    assert_eq!(app.state, AppState::Help);

    terminal.draw(|frame| app.render(frame)).unwrap();

    let buf = terminal.backend().buffer();
    let area = Rect::new(0, 0, 100, 30);
    assert!(buffer_contains(buf, area, "TUI Help"));
}
