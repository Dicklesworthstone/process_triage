//! Auxiliary panel widget for the Wide breakpoint three-pane layout.
//!
//! Shows selection summary, action plan preview, and quick stats.

use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText};
use ftui::widgets::block::Block as FtuiBlock;
use ftui::widgets::paragraph::Paragraph as FtuiParagraph;
use ftui::widgets::Widget as FtuiWidget;
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;

use crate::tui::theme::Theme;
use crate::tui::widgets::ProcessRow;

/// Auxiliary panel widget (Wide breakpoint only).
///
/// Renders selection summary and action preview in the rightmost pane.
pub struct AuxPanel<'a> {
    theme: Option<&'a Theme>,
    rows: &'a [ProcessRow],
    selected_count: usize,
    current_row: Option<&'a ProcessRow>,
}

impl<'a> Default for AuxPanel<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> AuxPanel<'a> {
    /// Create a new aux panel.
    pub fn new() -> Self {
        Self {
            theme: None,
            rows: &[],
            selected_count: 0,
            current_row: None,
        }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set the process rows for aggregate stats.
    pub fn rows(mut self, rows: &'a [ProcessRow]) -> Self {
        self.rows = rows;
        self
    }

    /// Set the selected count.
    pub fn selected_count(mut self, count: usize) -> Self {
        self.selected_count = count;
        self
    }

    /// Set the currently highlighted row.
    pub fn current_row(mut self, row: Option<&'a ProcessRow>) -> Self {
        self.current_row = row;
        self
    }

    // ── Style helpers ───────────────────────────────────────────────

    fn label_style(&self) -> FtuiStyle {
        self.theme
            .map(|t| t.class("status.warning"))
            .unwrap_or_else(|| FtuiStyle::new().fg(PackedRgba::rgb(128, 128, 128)))
    }

    fn value_style(&self) -> FtuiStyle {
        self.theme
            .map(|t| t.stylesheet().get_or_default("table.header"))
            .unwrap_or_default()
    }

    fn classification_style(&self, classification: &str) -> FtuiStyle {
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

    // ── Rendering ───────────────────────────────────────────────────

    /// Render the aux panel.
    pub fn render_ftui(&self, area: ftui::layout::Rect, frame: &mut ftui::render::frame::Frame) {
        let border_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("border.normal"))
            .unwrap_or_default();

        let block = FtuiBlock::bordered()
            .title(" Action Preview ")
            .border_style(border_style);

        let inner = block.inner(area);
        FtuiWidget::render(&block, area, frame);

        let mut lines: Vec<FtuiLine> = Vec::new();

        // ── Selection summary ───────────────────────────────────────
        let total = self.rows.len();
        lines.push(FtuiLine::from_spans([
            FtuiSpan::styled("Selected: ", self.label_style()),
            FtuiSpan::styled(
                format!("{} / {}", self.selected_count, total),
                self.value_style(),
            ),
        ]));
        lines.push(FtuiLine::default());

        // ── Classification breakdown ────────────────────────────────
        let (kill, review, spare) = self.classification_counts();
        if total > 0 {
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("Breakdown", self.label_style()),
            ]));
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("  KILL:   ", self.classification_style("KILL")),
                FtuiSpan::styled(kill.to_string(), self.value_style()),
            ]));
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("  REVIEW: ", self.classification_style("REVIEW")),
                FtuiSpan::styled(review.to_string(), self.value_style()),
            ]));
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("  SPARE:  ", self.classification_style("SPARE")),
                FtuiSpan::styled(spare.to_string(), self.value_style()),
            ]));
            lines.push(FtuiLine::default());
        }

        // ── Current row action preview ──────────────────────────────
        if let Some(row) = self.current_row {
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("Focused: ", self.label_style()),
                FtuiSpan::styled(format!("PID {}", row.pid), self.value_style()),
            ]));

            if let Some(conf) = &row.confidence {
                lines.push(FtuiLine::from_spans([
                    FtuiSpan::styled("  Conf: ", self.label_style()),
                    FtuiSpan::styled(conf.clone(), self.value_style()),
                ]));
            }

            if !row.plan_preview.is_empty() {
                lines.push(FtuiLine::from_spans([
                    FtuiSpan::styled("  Plan:", self.label_style()),
                ]));
                for step in &row.plan_preview {
                    lines.push(FtuiLine::from_spans([
                        FtuiSpan::styled(format!("    {}", step), self.value_style()),
                    ]));
                }
            }
        } else {
            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled("No process focused", self.label_style()),
            ]));
        }

        let text: FtuiText = lines.into_iter().collect();
        let paragraph = FtuiParagraph::new(text);
        FtuiWidget::render(&paragraph, inner, frame);
    }

    /// Count processes by classification.
    fn classification_counts(&self) -> (usize, usize, usize) {
        let mut kill = 0;
        let mut review = 0;
        let mut spare = 0;
        for row in self.rows {
            match row.classification.to_uppercase().as_str() {
                "KILL" => kill += 1,
                "REVIEW" => review += 1,
                "SPARE" => spare += 1,
                _ => {}
            }
        }
        (kill, review, spare)
    }
}
