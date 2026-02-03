#![cfg(feature = "ui")]

use pt_core::inference::galaxy_brain::{self, GalaxyBrainConfig, MathMode, Verbosity};
use pt_core::inference::ledger::EvidenceLedger;
use pt_core::inference::posterior::{ClassScores, EvidenceTerm, PosteriorResult};
use pt_core::tui::layout::{Breakpoint, ResponsiveLayout};
use pt_core::tui::widgets::{
    DetailView, ProcessDetail, ProcessRow, ProcessTable, ProcessTableState,
};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::{StatefulWidget, Widget};

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

fn sample_posterior() -> PosteriorResult {
    PosteriorResult {
        posterior: ClassScores {
            useful: 0.12,
            useful_bad: 0.08,
            abandoned: 0.72,
            zombie: 0.08,
        },
        log_posterior: ClassScores {
            useful: -2.1,
            useful_bad: -2.5,
            abandoned: -0.4,
            zombie: -2.4,
        },
        log_odds_abandoned_useful: 1.7,
        evidence_terms: vec![
            EvidenceTerm {
                feature: "age_days".to_string(),
                log_likelihood: ClassScores {
                    useful: -2.8,
                    useful_bad: -2.5,
                    abandoned: -0.6,
                    zombie: -2.4,
                },
            },
            EvidenceTerm {
                feature: "cpu_idle".to_string(),
                log_likelihood: ClassScores {
                    useful: -1.9,
                    useful_bad: -2.1,
                    abandoned: -0.7,
                    zombie: -2.0,
                },
            },
        ],
    }
}

fn sample_trace() -> String {
    let posterior = sample_posterior();
    let ledger = EvidenceLedger::from_posterior_result(&posterior, Some(4242), None);
    let config = GalaxyBrainConfig {
        verbosity: Verbosity::Detail,
        math_mode: MathMode::Ascii,
        max_evidence_terms: 4,
    };
    galaxy_brain::render(&posterior, &ledger, &config)
}

fn sample_row(trace: Option<String>) -> ProcessRow {
    ProcessRow {
        pid: 4242,
        score: 91,
        classification: "KILL".to_string(),
        runtime: "3h 12m".to_string(),
        memory: "1.2 GB".to_string(),
        command: "node dev server".to_string(),
        selected: false,
        galaxy_brain: trace,
    }
}

#[test]
fn detail_galaxy_brain_renders_trace() {
    let area = Rect::new(0, 0, 80, 28);
    let mut buf = Buffer::empty(area);
    let trace = sample_trace();
    let row = sample_row(Some(trace));

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render(area, &mut buf);

    assert!(buffer_contains(&buf, area, "Galaxy Brain"));
    assert!(buffer_contains(&buf, area, "Galaxy-Brain Mode"));
    assert!(buffer_contains(&buf, area, "Posterior Distribution"));
}

#[test]
fn process_table_compact_hides_columns() {
    let area = Rect::new(0, 0, 36, 8);
    let mut buf = Buffer::empty(area);
    let mut state = ProcessTableState::new();
    state.set_rows(vec![sample_row(None)]);

    ProcessTable::new().render(area, &mut buf, &mut state);

    assert!(buffer_contains(&buf, area, "PID"));
    assert!(buffer_contains(&buf, area, "Class"));
    assert!(buffer_contains(&buf, area, "Command"));
    assert!(!buffer_contains(&buf, area, "Runtime"));
    assert!(!buffer_contains(&buf, area, "Memory"));
    assert!(!buffer_contains(&buf, area, "Score"));
}

#[test]
fn process_table_wide_shows_columns() {
    let area = Rect::new(0, 0, 120, 8);
    let mut buf = Buffer::empty(area);
    let mut state = ProcessTableState::new();
    state.set_rows(vec![sample_row(None)]);

    ProcessTable::new().render(area, &mut buf, &mut state);

    assert!(buffer_contains(&buf, area, "Score"));
    assert!(buffer_contains(&buf, area, "Runtime"));
    assert!(buffer_contains(&buf, area, "Memory"));
}

#[test]
fn detail_galaxy_brain_placeholder_when_missing() {
    let area = Rect::new(0, 0, 60, 14);
    let mut buf = Buffer::empty(area);
    let row = sample_row(None);

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render(area, &mut buf);

    assert!(buffer_contains(&buf, area, "math ledger pending"));
}

#[test]
fn detail_galaxy_brain_truncates_long_trace() {
    let area = Rect::new(0, 0, 60, 12);
    let mut buf = Buffer::empty(area);
    let long_trace = (0..40)
        .map(|i| format!("line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    let row = sample_row(Some(long_trace));

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render(area, &mut buf);

    assert!(buffer_contains(&buf, area, "more lines"));
}

#[test]
fn responsive_layout_breakpoints_match_sizes() {
    let compact = ResponsiveLayout::new(Rect::new(0, 0, 80, 24));
    assert_eq!(compact.breakpoint(), Breakpoint::Compact);

    let standard = ResponsiveLayout::new(Rect::new(0, 0, 120, 40));
    assert_eq!(standard.breakpoint(), Breakpoint::Standard);

    let wide = ResponsiveLayout::new(Rect::new(0, 0, 200, 60));
    assert_eq!(wide.breakpoint(), Breakpoint::Wide);
}
