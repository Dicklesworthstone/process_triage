#![cfg(feature = "ui")]

use ftui::layout::Rect;
use ftui::widgets::StatefulWidget as FtuiStatefulWidget;
use ftui::{Frame, GraphemePool};
use ftui_harness::{assert_snapshot, buffer_to_text};
use pt_core::inference::galaxy_brain::{self, GalaxyBrainConfig, MathMode, Verbosity};
use pt_core::inference::ledger::EvidenceLedger;
use pt_core::inference::posterior::{ClassScores, EvidenceTerm, PosteriorResult};
use pt_core::tui::layout::{Breakpoint, ResponsiveLayout};
use pt_core::tui::widgets::{
    DetailView, ProcessDetail, ProcessRow, ProcessTable, ProcessTableState,
};

fn buffer_contains_text(frame: &Frame<'_>, needle: &str) -> bool {
    buffer_to_text(&frame.buffer).contains(needle)
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
        why_summary: Some("Old + idle + orphaned".to_string()),
        top_evidence: vec!["PPID=1".to_string(), "Idle>2h".to_string()],
        confidence: Some("high".to_string()),
        plan_preview: vec!["SIGTERM -> SIGKILL".to_string()],
    }
}

#[test]
fn detail_galaxy_brain_renders_trace() {
    let area = Rect::new(0, 0, 80, 28);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    let trace = sample_trace();
    let row = sample_row(Some(trace));

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render_ftui(area, &mut frame);

    assert_snapshot!("tui_detail_galaxy_brain_trace_80x28", &frame.buffer);
    assert!(buffer_contains_text(&frame, "Galaxy Brain"));
    assert!(buffer_contains_text(&frame, "Galaxy-Brain Mode"));
    assert!(buffer_contains_text(&frame, "Posterior Distribution"));
}

#[test]
fn process_table_compact_hides_columns() {
    let area = Rect::new(0, 0, 36, 8);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    let mut state = ProcessTableState::new();
    state.set_rows(vec![sample_row(None)]);

    let table = ProcessTable::new();
    FtuiStatefulWidget::render(&table, area, &mut frame, &mut state);

    assert_snapshot!("tui_process_table_compact_36x8", &frame.buffer);
    assert!(buffer_contains_text(&frame, "PID"));
    assert!(buffer_contains_text(&frame, "Class"));
    assert!(buffer_contains_text(&frame, "Command"));
    assert!(!buffer_contains_text(&frame, "Runtime"));
    assert!(!buffer_contains_text(&frame, "Memory"));
    assert!(!buffer_contains_text(&frame, "Score"));
}

#[test]
fn process_table_wide_shows_columns() {
    let area = Rect::new(0, 0, 120, 8);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    let mut state = ProcessTableState::new();
    state.set_rows(vec![sample_row(None)]);

    let table = ProcessTable::new();
    FtuiStatefulWidget::render(&table, area, &mut frame, &mut state);

    assert_snapshot!("tui_process_table_wide_120x8", &frame.buffer);
    assert!(buffer_contains_text(&frame, "Score"));
    assert!(buffer_contains_text(&frame, "Runtime"));
    assert!(buffer_contains_text(&frame, "Memory"));
}

#[test]
fn detail_galaxy_brain_placeholder_when_missing() {
    let area = Rect::new(0, 0, 60, 14);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    let row = sample_row(None);

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render_ftui(area, &mut frame);

    assert_snapshot!("tui_detail_galaxy_brain_missing_trace_60x14", &frame.buffer);
    assert!(buffer_contains_text(&frame, "math ledger pending"));
}

#[test]
fn detail_galaxy_brain_truncates_long_trace() {
    // Ensure the detail widget has enough vertical space to render
    // a truncation indicator line.
    let area = Rect::new(0, 0, 60, 24);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    let long_trace = (0..40)
        .map(|i| format!("line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    let row = sample_row(Some(long_trace));

    ProcessDetail::new()
        .row(Some(&row), false)
        .view(DetailView::GalaxyBrain)
        .render_ftui(area, &mut frame);

    assert_snapshot!(
        "tui_detail_galaxy_brain_long_trace_truncates_60x24",
        &frame.buffer
    );
    // Rendering should truncate long traces to fit the viewport.
    assert!(buffer_contains_text(&frame, "line 9"));
    assert!(!buffer_contains_text(&frame, "line 39"));
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
