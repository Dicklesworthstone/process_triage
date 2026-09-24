#![cfg(feature = "ui")]

use ftui::layout::Rect;
use ftui::widgets::StatefulWidget as FtuiStatefulWidget;
use ftui::{Frame, GraphemePool, Model as FtuiModel};
use ftui_harness::{assert_snapshot, buffer_to_text};
use pt_core::inference::galaxy_brain::{self, GalaxyBrainConfig, MathMode, Verbosity};
use pt_core::inference::ledger::EvidenceLedger;
use pt_core::inference::posterior::{ClassScores, EvidenceTerm, PosteriorResult};
use pt_core::tui::layout::{Breakpoint, ResponsiveLayout};
use pt_core::tui::widgets::{DetailView, ProcessRow, ProcessTable, ProcessTableState};
use pt_core::tui::{App, Msg};

// ── Helpers ─────────────────────────────────────────────────────────

/// Render via the real Model::view() code path.
fn render_app_view(app: &App, width: u16, height: u16) -> ftui::Buffer {
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    <App as FtuiModel>::view(app, &mut frame);
    let Frame { buffer, .. } = frame;
    buffer
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
        provenance_headline: None,
        provenance_sections: Vec::new(),
        provenance_caveats: Vec::new(),
        blast_radius_risk: None,
    }
}

// ── Galaxy Brain detail tests (via Model::view()) ───────────────────

#[test]
fn detail_galaxy_brain_renders_trace() {
    let mut app = App::new();
    let trace = sample_trace();
    app.process_table.set_rows(vec![sample_row(Some(trace))]);
    <App as FtuiModel>::update(&mut app, Msg::SetDetailView(DetailView::GalaxyBrain));

    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_golden_galaxy_brain_trace_140x40", &buf);
    assert!(
        text.contains("Galaxy Brain") || text.contains("Galaxy-Brain Mode"),
        "galaxy brain header should render"
    );
    assert!(
        text.contains("Posterior Distribution") || text.contains("posterior"),
        "posterior info should render"
    );
}

#[test]
fn detail_galaxy_brain_placeholder_when_missing() {
    let mut app = App::new();
    app.process_table.set_rows(vec![sample_row(None)]);
    <App as FtuiModel>::update(&mut app, Msg::SetDetailView(DetailView::GalaxyBrain));

    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_golden_galaxy_brain_missing_trace_140x40", &buf);
    assert!(
        text.contains("math ledger pending"),
        "placeholder text should render when trace is missing"
    );
}

#[test]
fn detail_galaxy_brain_truncates_long_trace() {
    let mut app = App::new();
    let long_trace = (0..40)
        .map(|i| format!("line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    app.process_table
        .set_rows(vec![sample_row(Some(long_trace))]);
    <App as FtuiModel>::update(&mut app, Msg::SetDetailView(DetailView::GalaxyBrain));

    // Use standard breakpoint — detail pane gets ~35 rows, which is
    // less than the 40-line trace, so truncation should still occur.
    let buf = render_app_view(&app, 140, 40);
    let text = buffer_to_text(&buf);

    assert_snapshot!("tui_golden_galaxy_brain_long_trace_140x40", &buf);
    assert!(text.contains("line 0"), "early lines should render");
    assert!(
        !text.contains("line 39"),
        "very late lines should be truncated"
    );
}

// ── Process table column visibility (widget-level tests) ────────────
//
// These remain as widget-level tests because they verify the
// ProcessTable widget's internal responsive column-hiding logic at
// specific allocated widths.  The full Model::view() layout allocates
// different widths depending on breakpoint + pane configuration, so
// widget-level rendering gives deterministic control over column
// visibility thresholds.

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
    let text = buffer_to_text(&frame.buffer);
    assert!(text.contains("PID"));
    assert!(text.contains("Class"));
    assert!(text.contains("Command"));
    assert!(!text.contains("Runtime"));
    assert!(!text.contains("Memory"));
    assert!(!text.contains("Score"));
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
    let text = buffer_to_text(&frame.buffer);
    assert!(text.contains("Score"));
    assert!(text.contains("Runtime"));
    assert!(text.contains("Memory"));
}

// ── Layout breakpoint unit test ─────────────────────────────────────

#[test]
fn responsive_layout_breakpoints_match_sizes() {
    let compact = ResponsiveLayout::new(Rect::new(0, 0, 80, 24));
    assert_eq!(compact.breakpoint(), Breakpoint::Compact);

    let standard = ResponsiveLayout::new(Rect::new(0, 0, 120, 40));
    assert_eq!(standard.breakpoint(), Breakpoint::Standard);

    let wide = ResponsiveLayout::new(Rect::new(0, 0, 200, 60));
    assert_eq!(wide.breakpoint(), Breakpoint::Wide);
}
