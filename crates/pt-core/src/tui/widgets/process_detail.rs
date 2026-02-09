//! Detail pane widget for a selected process.
//!
//! Uses ftui's Paragraph and layout primitives for rendering.

use ftui::layout::Constraint as FtuiConstraint;
use ftui::layout::Flex;
use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText};
use ftui::widgets::block::{Alignment as FtuiAlignment, Block as FtuiBlock};
use ftui::widgets::paragraph::Paragraph as FtuiParagraph;
use ftui::widgets::Widget as FtuiWidget;
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;

use crate::tui::theme::Theme;
use crate::tui::widgets::ProcessRow;

/// Detail pane modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailView {
    Summary,
    GalaxyBrain,
    Genealogy,
}

/// Detail pane widget for a selected process.
pub struct ProcessDetail<'a> {
    theme: Option<&'a Theme>,
    row: Option<&'a ProcessRow>,
    selected: bool,
    view: DetailView,
}

impl<'a> Default for ProcessDetail<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ProcessDetail<'a> {
    /// Create a new detail pane widget.
    pub fn new() -> Self {
        Self {
            theme: None,
            row: None,
            selected: false,
            view: DetailView::Summary,
        }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set the selected row and selection state.
    pub fn row(mut self, row: Option<&'a ProcessRow>, selected: bool) -> Self {
        self.row = row;
        self.selected = selected;
        self
    }

    /// Set the detail view mode.
    pub fn view(mut self, view: DetailView) -> Self {
        self.view = view;
        self
    }

    // ── ftui style helpers ──────────────────────────────────────────

    fn classification_ftui_style(&self, classification: &str) -> FtuiStyle {
        if let Some(theme) = self.theme {
            let sheet = theme.stylesheet();
            match classification.to_uppercase().as_str() {
                "KILL" => sheet.get_or_default("classification.kill"),
                "REVIEW" => sheet.get_or_default("classification.review"),
                "SPARE" => sheet.get_or_default("classification.spare"),
                _ => FtuiStyle::default(),
            }
        } else {
            match classification.to_uppercase().as_str() {
                "KILL" => FtuiStyle::new().fg(PackedRgba::rgb(255, 0, 0)).bold(),
                "REVIEW" => FtuiStyle::new().fg(PackedRgba::rgb(255, 255, 0)),
                "SPARE" => FtuiStyle::new().fg(PackedRgba::rgb(0, 255, 0)),
                _ => FtuiStyle::default(),
            }
        }
    }

    fn label_ftui_style(&self) -> FtuiStyle {
        if let Some(theme) = self.theme {
            theme.class("status.warning")
        } else {
            FtuiStyle::new().fg(PackedRgba::rgb(128, 128, 128))
        }
    }

    fn value_ftui_style(&self) -> FtuiStyle {
        if let Some(theme) = self.theme {
            theme.stylesheet().get_or_default("table.header")
        } else {
            FtuiStyle::default()
        }
    }

    // ── ftui rendering ──────────────────────────────────────────────

    /// Render the detail pane using ftui widgets.
    pub fn render_ftui(&self, area: ftui::layout::Rect, frame: &mut ftui::render::frame::Frame) {
        let border_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("border.normal"))
            .unwrap_or_default();

        let block = FtuiBlock::bordered()
            .title(" Detail ")
            .border_style(border_style);

        let inner = block.inner(area);
        FtuiWidget::render(&block, area, frame);

        let Some(row) = self.row else {
            let text: FtuiText = "No process selected".into();
            let message = FtuiParagraph::new(text)
                .style(self.value_ftui_style())
                .alignment(FtuiAlignment::Center);
            FtuiWidget::render(&message, inner, frame);
            return;
        };

        let sections = Flex::vertical()
            .constraints([
                FtuiConstraint::Fixed(4), // Header
                FtuiConstraint::Fixed(4), // Stats
                FtuiConstraint::Min(4),   // Evidence placeholder
                FtuiConstraint::Fixed(3), // Action placeholder
            ])
            .split(inner);

        let selected_label = if self.selected { "yes" } else { "no" };

        // ── Header section ──────────────────────────────────────────

        let header_lines: Vec<FtuiLine> = vec![
            FtuiLine::from_spans([
                FtuiSpan::styled("PID: ", self.label_ftui_style()),
                FtuiSpan::styled(row.pid.to_string(), self.value_ftui_style()),
                FtuiSpan::styled("  ", self.value_ftui_style()),
                FtuiSpan::styled("Class: ", self.label_ftui_style()),
                FtuiSpan::styled(
                    row.classification.clone(),
                    self.classification_ftui_style(&row.classification),
                ),
            ]),
            FtuiLine::from_spans([
                FtuiSpan::styled("Command: ", self.label_ftui_style()),
                FtuiSpan::styled(row.command.clone(), self.value_ftui_style()),
            ]),
            FtuiLine::from_spans([
                FtuiSpan::styled("Selected: ", self.label_ftui_style()),
                FtuiSpan::styled(selected_label, self.value_ftui_style()),
            ]),
        ];

        // ── Stats section ───────────────────────────────────────────

        let stats_lines: Vec<FtuiLine> = vec![
            FtuiLine::from_spans([
                FtuiSpan::styled("Score: ", self.label_ftui_style()),
                FtuiSpan::styled(row.score.to_string(), self.value_ftui_style()),
                FtuiSpan::styled("  ", self.value_ftui_style()),
                FtuiSpan::styled("Runtime: ", self.label_ftui_style()),
                FtuiSpan::styled(row.runtime.clone(), self.value_ftui_style()),
            ]),
            FtuiLine::from_spans([
                FtuiSpan::styled("Memory: ", self.label_ftui_style()),
                FtuiSpan::styled(row.memory.clone(), self.value_ftui_style()),
            ]),
        ];

        // ── View-dependent sections ─────────────────────────────────

        let evidence_height = sections[2].height.max(1) as usize;

        let (evidence_lines, action_lines) = match self.view {
            DetailView::Summary => self.build_summary_sections(row, evidence_height),
            DetailView::GalaxyBrain => self.build_galaxy_brain_sections(row, evidence_height),
            DetailView::Genealogy => self.build_genealogy_sections(),
        };

        // ── Render paragraphs ───────────────────────────────────────

        let header_text: FtuiText = header_lines.into_iter().collect();
        FtuiWidget::render(
            &FtuiParagraph::new(header_text).style(self.value_ftui_style()),
            sections[0],
            frame,
        );

        let stats_text: FtuiText = stats_lines.into_iter().collect();
        FtuiWidget::render(
            &FtuiParagraph::new(stats_text).style(self.value_ftui_style()),
            sections[1],
            frame,
        );

        let evidence_text: FtuiText = evidence_lines.into_iter().collect();
        FtuiWidget::render(
            &FtuiParagraph::new(evidence_text).style(self.value_ftui_style()),
            sections[2],
            frame,
        );

        let action_text: FtuiText = action_lines.into_iter().collect();
        FtuiWidget::render(
            &FtuiParagraph::new(action_text).style(self.value_ftui_style()),
            sections[3],
            frame,
        );
    }

    fn build_summary_sections(
        &self,
        row: &ProcessRow,
        evidence_height: usize,
    ) -> (Vec<FtuiLine>, Vec<FtuiLine>) {
        let mut evidence = Vec::new();
        evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
            "Evidence",
            self.label_ftui_style(),
        )]));

        if let Some(summary) = row.why_summary.as_ref() {
            evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                summary.clone(),
                self.value_ftui_style(),
            )]));
        } else {
            evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                "No evidence summary available",
                self.value_ftui_style(),
            )]));
        }

        for item in &row.top_evidence {
            evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                format!("\u{2022} {}", item),
                self.value_ftui_style(),
            )]));
        }

        if evidence.len() > evidence_height {
            evidence.truncate(evidence_height);
        }

        let mut action = Vec::new();
        action.push(FtuiLine::from_spans([FtuiSpan::styled(
            "Action",
            self.label_ftui_style(),
        )]));

        if !row.plan_preview.is_empty() {
            let first = row.plan_preview.first().cloned().unwrap_or_default();
            action.push(FtuiLine::from_spans([
                FtuiSpan::styled("Plan: ", self.label_ftui_style()),
                FtuiSpan::styled(first, self.value_ftui_style()),
            ]));
            if let Some(second) = row.plan_preview.get(1) {
                let mut line = second.clone();
                if row.plan_preview.len() > 2 {
                    line.push_str(" \u{2026}");
                }
                action.push(FtuiLine::from_spans([FtuiSpan::styled(
                    line,
                    self.value_ftui_style(),
                )]));
            }
        } else {
            action.push(FtuiLine::from_spans([
                FtuiSpan::styled("Recommended: ", self.label_ftui_style()),
                FtuiSpan::styled(row.classification.clone(), self.value_ftui_style()),
            ]));
            if let Some(confidence) = row.confidence.as_ref() {
                action.push(FtuiLine::from_spans([
                    FtuiSpan::styled("Confidence: ", self.label_ftui_style()),
                    FtuiSpan::styled(confidence.clone(), self.value_ftui_style()),
                ]));
            }
        }

        (evidence, action)
    }

    fn build_galaxy_brain_sections(
        &self,
        row: &ProcessRow,
        evidence_height: usize,
    ) -> (Vec<FtuiLine>, Vec<FtuiLine>) {
        let mut evidence = Vec::new();
        evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
            "Galaxy Brain",
            self.label_ftui_style(),
        )]));

        if let Some(trace) = row.galaxy_brain.as_deref() {
            let trace_lines: Vec<&str> = trace.lines().collect();
            let max_lines = evidence_height.saturating_sub(1).max(1);
            for line in trace_lines.iter().take(max_lines) {
                evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                    *line,
                    self.value_ftui_style(),
                )]));
            }
            if trace_lines.len() > max_lines {
                evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                    format!("\u{2026} {} more lines", trace_lines.len() - max_lines),
                    self.label_ftui_style(),
                )]));
            }
        } else {
            evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} math ledger pending",
                self.value_ftui_style(),
            )]));
            evidence.push(FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} posterior odds pending",
                self.value_ftui_style(),
            )]));
        }

        let action = vec![
            FtuiLine::from_spans([FtuiSpan::styled("Notes", self.label_ftui_style())]),
            FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} press g to toggle",
                self.value_ftui_style(),
            )]),
        ];

        (evidence, action)
    }

    fn build_genealogy_sections(&self) -> (Vec<FtuiLine>, Vec<FtuiLine>) {
        let evidence = vec![
            FtuiLine::from_spans([FtuiSpan::styled("Genealogy", self.label_ftui_style())]),
            FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} process tree pending",
                self.value_ftui_style(),
            )]),
            FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} supervisor chain pending",
                self.value_ftui_style(),
            )]),
        ];

        let action = vec![
            FtuiLine::from_spans([FtuiSpan::styled("Notes", self.label_ftui_style())]),
            FtuiLine::from_spans([FtuiSpan::styled(
                "\u{2022} press s to return",
                self.value_ftui_style(),
            )]),
        ];

        (evidence, action)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> ProcessRow {
        ProcessRow {
            pid: 4242,
            score: 91,
            classification: "KILL".to_string(),
            runtime: "3h 12m".to_string(),
            memory: "1.2 GB".to_string(),
            command: "node dev server".to_string(),
            selected: false,
            galaxy_brain: None,
            why_summary: Some("Classified as abandoned with high confidence.".to_string()),
            top_evidence: vec![
                "runtime (2.8 bits toward abandoned)".to_string(),
                "cpu_idle (1.6 bits toward abandoned)".to_string(),
            ],
            confidence: Some("high".to_string()),
            plan_preview: Vec::new(),
        }
    }

    // ── DetailView enum ─────────────────────────────────────────────

    #[test]
    fn detail_view_eq() {
        assert_eq!(DetailView::Summary, DetailView::Summary);
        assert_eq!(DetailView::GalaxyBrain, DetailView::GalaxyBrain);
        assert_eq!(DetailView::Genealogy, DetailView::Genealogy);
        assert_ne!(DetailView::Summary, DetailView::GalaxyBrain);
    }

    // ── ProcessDetail builder ───────────────────────────────────────

    #[test]
    fn detail_default() {
        let d = ProcessDetail::default();
        assert!(d.theme.is_none());
        assert!(d.row.is_none());
        assert!(!d.selected);
        assert_eq!(d.view, DetailView::Summary);
    }

    #[test]
    fn detail_view_builder() {
        let d = ProcessDetail::new().view(DetailView::GalaxyBrain);
        assert_eq!(d.view, DetailView::GalaxyBrain);
    }

    #[test]
    fn detail_row_builder_sets_selected() {
        let row = sample_row();
        let d = ProcessDetail::new().row(Some(&row), true);
        assert!(d.selected);
        assert!(d.row.is_some());
    }

    // ── ftui style helpers (no theme) ───────────────────────────────

    #[test]
    fn ftui_classification_kill_is_red() {
        let d = ProcessDetail::new();
        let style = d.classification_ftui_style("KILL");
        assert_eq!(style.fg, Some(PackedRgba::rgb(255, 0, 0)));
    }

    #[test]
    fn ftui_classification_review_is_yellow() {
        let d = ProcessDetail::new();
        let style = d.classification_ftui_style("REVIEW");
        assert_eq!(style.fg, Some(PackedRgba::rgb(255, 255, 0)));
    }

    #[test]
    fn ftui_classification_spare_is_green() {
        let d = ProcessDetail::new();
        let style = d.classification_ftui_style("SPARE");
        assert_eq!(style.fg, Some(PackedRgba::rgb(0, 255, 0)));
    }

    #[test]
    fn ftui_classification_unknown_is_default() {
        let d = ProcessDetail::new();
        let style = d.classification_ftui_style("OTHER");
        assert_eq!(style, FtuiStyle::default());
    }

    #[test]
    fn ftui_classification_case_insensitive() {
        let d = ProcessDetail::new();
        let style = d.classification_ftui_style("kill");
        assert_eq!(style.fg, Some(PackedRgba::rgb(255, 0, 0)));
    }

    #[test]
    fn ftui_label_style_is_gray() {
        let d = ProcessDetail::new();
        let style = d.label_ftui_style();
        assert_eq!(style.fg, Some(PackedRgba::rgb(128, 128, 128)));
    }

    #[test]
    fn ftui_value_style_is_default() {
        let d = ProcessDetail::new();
        let style = d.value_ftui_style();
        assert_eq!(style, FtuiStyle::default());
    }

    // ── ftui section builders ───────────────────────────────────────

    #[test]
    fn build_summary_evidence_with_summary() {
        let row = sample_row();
        let d = ProcessDetail::new();
        let (evidence, _) = d.build_summary_sections(&row, 10);
        assert!(evidence.len() >= 2);
    }

    #[test]
    fn build_summary_evidence_without_summary() {
        let mut row = sample_row();
        row.why_summary = None;
        row.top_evidence = vec![];
        let d = ProcessDetail::new();
        let (evidence, _) = d.build_summary_sections(&row, 10);
        assert!(evidence.len() >= 2);
    }

    #[test]
    fn build_summary_truncates_to_height() {
        let mut row = sample_row();
        row.top_evidence = (0..20).map(|i| format!("evidence item {}", i)).collect();
        let d = ProcessDetail::new();
        let (evidence, _) = d.build_summary_sections(&row, 5);
        assert!(evidence.len() <= 5);
    }

    #[test]
    fn build_summary_action_with_plan() {
        let mut row = sample_row();
        row.plan_preview = vec!["kill -9 4242".to_string(), "verify gone".to_string()];
        let d = ProcessDetail::new();
        let (_, action) = d.build_summary_sections(&row, 10);
        assert!(action.len() >= 2);
    }

    #[test]
    fn build_summary_action_with_confidence() {
        let row = sample_row();
        let d = ProcessDetail::new();
        let (_, action) = d.build_summary_sections(&row, 10);
        assert!(action.len() >= 3);
    }

    #[test]
    fn build_galaxy_brain_pending() {
        let row = sample_row();
        let d = ProcessDetail::new();
        let (evidence, action) = d.build_galaxy_brain_sections(&row, 10);
        assert!(evidence.len() >= 3);
        assert_eq!(action.len(), 2);
    }

    #[test]
    fn build_galaxy_brain_with_trace() {
        let mut row = sample_row();
        row.galaxy_brain = Some("P(abandoned|evidence) = 0.85\nBF = 5.67".to_string());
        let d = ProcessDetail::new();
        let (evidence, _) = d.build_galaxy_brain_sections(&row, 10);
        assert!(evidence.len() >= 3);
    }

    #[test]
    fn build_genealogy_sections() {
        let d = ProcessDetail::new();
        let (evidence, action) = d.build_genealogy_sections();
        assert_eq!(evidence.len(), 3);
        assert_eq!(action.len(), 2);
    }
}
