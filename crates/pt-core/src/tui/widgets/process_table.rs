//! Process table widget for displaying candidate processes.
//!
//! Custom table widget with Process Triage-specific columns and styling.
//! Uses ftui's built-in Table widget as primary rendering, with ratatui
//! legacy compat behind `ui-legacy` feature gate.

use std::collections::{HashMap, HashSet};

use ftui::layout::Constraint as FtuiConstraint;
use ftui::widgets::block::Block as FtuiBlock;
use ftui::widgets::table::{Row as FtuiRow, Table as FtuiTable, TableState as FtuiTableState};
use ftui::widgets::StatefulWidget as FtuiStatefulWidget;
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;
use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText};

#[cfg(feature = "ui-legacy")]
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, StatefulWidget, Widget},
};

use crate::tui::theme::Theme;
use crate::{
    decision::Action,
    plan::{ActionConfidence, ActionRouting, Plan, PlanAction, PreCheck},
};

/// Sort column for the process table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    /// Sort by PID.
    Pid,
    /// Sort by score (default).
    #[default]
    Score,
    /// Sort by classification (Kill, Review, Spare).
    Classification,
    /// Sort by runtime.
    Runtime,
    /// Sort by memory usage.
    Memory,
    /// Sort by command name.
    Command,
}

/// Sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Ascending order.
    Ascending,
    /// Descending order (default for score).
    #[default]
    Descending,
}

/// Primary view ordering for the process table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    /// Sort by suspicion/score (default).
    #[default]
    SuspicionFirst,
    /// Sort by goal contribution/selection.
    GoalFirst,
}

/// A process row for display in the table.
#[derive(Debug, Clone)]
pub struct ProcessRow {
    /// Process ID.
    pub pid: u32,
    /// Process score (0-100+).
    pub score: u32,
    /// Classification label (KILL, REVIEW, SPARE).
    pub classification: String,
    /// Runtime in human-readable format.
    pub runtime: String,
    /// Memory usage in human-readable format.
    pub memory: String,
    /// Command name/line (truncated).
    pub command: String,
    /// Whether this row is selected for action.
    pub selected: bool,
    /// Optional galaxy-brain math trace for drill-down.
    pub galaxy_brain: Option<String>,
    /// Optional summary explaining the classification.
    pub why_summary: Option<String>,
    /// Top evidence lines (human-readable).
    pub top_evidence: Vec<String>,
    /// Confidence label for the classification.
    pub confidence: Option<String>,
    /// Preview lines for the planned actions (stage/prechecks/confidence).
    pub plan_preview: Vec<String>,
}

// ---------------------------------------------------------------------------
// Column layout constants
// ---------------------------------------------------------------------------

const COL_CHECKBOX: u16 = 3;
const COL_PID: u16 = 8;
const COL_SCORE: u16 = 7;
const COL_CLASS: u16 = 8;
const COL_RUNTIME: u16 = 9;
const COL_MEMORY: u16 = 8;
const MIN_COMMAND_WIDTH: u16 = 12;

/// Process table widget for displaying candidates.
#[derive(Debug)]
pub struct ProcessTable<'a> {
    /// Theme for styling.
    theme: Option<&'a Theme>,
    /// Show selection checkboxes.
    show_selection: bool,
}

impl<'a> Default for ProcessTable<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ProcessTable<'a> {
    /// Create a new process table.
    pub fn new() -> Self {
        Self {
            theme: None,
            show_selection: true,
        }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set whether to show selection checkboxes.
    pub fn show_selection(mut self, show: bool) -> Self {
        self.show_selection = show;
        self
    }

    /// Build the title string based on state.
    fn title_string(&self, state: &ProcessTableState) -> String {
        let selected_count = state.selected.len();
        let total_count = state.visible_rows().len();
        let view_label = match state.view_mode {
            ViewMode::SuspicionFirst => "score",
            ViewMode::GoalFirst => "goal",
        };

        if selected_count > 0 {
            format!(
                " Processes [{}/{} selected] [view: {}] [Space: toggle, a: rec, A: all, u: clear, x: invert, e: execute] ",
                selected_count, total_count, view_label
            )
        } else {
            format!(
                " Processes [{}] [view: {}] [Space: toggle, a: rec, A: all, u: clear, x: invert, e: execute] ",
                total_count, view_label
            )
        }
    }

    /// Get classification ftui style.
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

    /// Sort indicator suffix for column headers.
    fn sort_indicator(state: &ProcessTableState, col: SortColumn) -> &'static str {
        if state.sort_column == col {
            match state.sort_order {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    }

    /// Determine which optional columns to show given available width.
    fn column_visibility(&self, available_width: u16) -> (bool, bool, bool) {
        let checkbox_width = if self.show_selection {
            COL_CHECKBOX + 1
        } else {
            0
        };

        // Always-visible: PID, Classification, Command (+ gaps)
        let base_fixed = COL_PID + COL_CLASS;
        let mut show_score = true;
        let mut show_runtime = true;
        let mut show_memory = true;

        // Iteratively drop optional columns until command has enough room
        loop {
            let fixed = base_fixed
                + if show_score { COL_SCORE } else { 0 }
                + if show_runtime { COL_RUNTIME } else { 0 }
                + if show_memory { COL_MEMORY } else { 0 };
            let visible_cols =
                2 + u16::from(show_score) + u16::from(show_runtime) + u16::from(show_memory);
            let gaps = visible_cols + if self.show_selection { 1 } else { 0 };
            let cmd_width = available_width.saturating_sub(fixed + checkbox_width + gaps);

            if cmd_width >= MIN_COMMAND_WIDTH {
                return (show_score, show_runtime, show_memory);
            }

            if show_memory {
                show_memory = false;
                continue;
            }
            if show_runtime {
                show_runtime = false;
                continue;
            }
            if show_score {
                show_score = false;
                continue;
            }
            return (false, false, false);
        }
    }

    /// Build ftui table rows, header, constraints, and highlight style (no block).
    fn build_ftui_table_parts(
        &self,
        state: &ProcessTableState,
        area_width: u16,
    ) -> FtuiTableParts {
        let (show_score, show_runtime, show_memory) = self.column_visibility(area_width);

        let header_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("table.header"))
            .unwrap_or_else(|| FtuiStyle::new().bold());

        let highlight_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("table.selected"))
            .unwrap_or_else(|| FtuiStyle::new().reverse());

        // Build column constraints
        let mut constraints = Vec::new();
        if self.show_selection {
            constraints.push(FtuiConstraint::Fixed(COL_CHECKBOX));
        }
        constraints.push(FtuiConstraint::Fixed(COL_PID));
        if show_score {
            constraints.push(FtuiConstraint::Fixed(COL_SCORE));
        }
        constraints.push(FtuiConstraint::Fixed(COL_CLASS));
        if show_runtime {
            constraints.push(FtuiConstraint::Fixed(COL_RUNTIME));
        }
        if show_memory {
            constraints.push(FtuiConstraint::Fixed(COL_MEMORY));
        }
        constraints.push(FtuiConstraint::Fill);

        // Build header row
        let mut header_cells: Vec<FtuiText> = Vec::new();
        if self.show_selection {
            header_cells.push(FtuiText::raw("[ ]"));
        }
        header_cells.push(FtuiText::raw(format!(
            "PID{}",
            Self::sort_indicator(state, SortColumn::Pid)
        )));
        if show_score {
            header_cells.push(FtuiText::raw(format!(
                "Score{}",
                Self::sort_indicator(state, SortColumn::Score)
            )));
        }
        header_cells.push(FtuiText::raw(format!(
            "Class{}",
            Self::sort_indicator(state, SortColumn::Classification)
        )));
        if show_runtime {
            header_cells.push(FtuiText::raw(format!(
                "Runtime{}",
                Self::sort_indicator(state, SortColumn::Runtime)
            )));
        }
        if show_memory {
            header_cells.push(FtuiText::raw(format!(
                "Memory{}",
                Self::sort_indicator(state, SortColumn::Memory)
            )));
        }
        header_cells.push(FtuiText::raw(format!(
            "Command{}",
            Self::sort_indicator(state, SortColumn::Command)
        )));

        let header = FtuiRow::new(header_cells).style(header_style);

        // Build data rows
        let visible = state.visible_rows();
        let rows: Vec<FtuiRow> = visible
            .iter()
            .enumerate()
            .map(|(_i, row)| {
                let is_selected = state.selected.contains(&row.pid);
                let class_style = self.classification_ftui_style(&row.classification);

                let mut cells: Vec<FtuiText> = Vec::new();

                // Checkbox
                if self.show_selection {
                    let check = if is_selected { "\u{2611}" } else { "\u{2610}" };
                    cells.push(FtuiText::raw(check));
                }

                // PID
                cells.push(FtuiText::raw(row.pid.to_string()));

                // Score
                if show_score {
                    cells.push(FtuiText::raw(row.score.to_string()));
                }

                // Classification (styled)
                cells.push(FtuiText::from_line(FtuiLine::from_spans([
                    FtuiSpan::styled(row.classification.clone(), class_style),
                ])));

                // Runtime
                if show_runtime {
                    cells.push(FtuiText::raw(row.runtime.clone()));
                }

                // Memory
                if show_memory {
                    cells.push(FtuiText::raw(row.memory.clone()));
                }

                // Command
                cells.push(FtuiText::raw(row.command.clone()));

                FtuiRow::new(cells)
            })
            .collect();

        FtuiTableParts {
            rows,
            header,
            constraints,
            highlight_style,
        }
    }

    /// Get the border style from the theme based on focus state.
    fn border_ftui_style(&self, focused: bool) -> FtuiStyle {
        self.theme
            .map(|t| {
                let class = if focused {
                    "border.focused"
                } else {
                    "border.normal"
                };
                t.stylesheet().get_or_default(class)
            })
            .unwrap_or_default()
    }
}

/// Intermediate parts for building an ftui Table (avoids lifetime issues with title).
struct FtuiTableParts {
    rows: Vec<FtuiRow>,
    header: FtuiRow,
    constraints: Vec<FtuiConstraint>,
    highlight_style: FtuiStyle,
}

// ---------------------------------------------------------------------------
// ftui StatefulWidget implementation (primary)
// ---------------------------------------------------------------------------

impl<'a> FtuiStatefulWidget for ProcessTable<'a> {
    type State = ProcessTableState;

    fn render(
        &self,
        area: ftui::layout::Rect,
        frame: &mut ftui::render::frame::Frame,
        state: &mut Self::State,
    ) {
        let title = self.title_string(state);
        let border_style = self.border_ftui_style(state.focused);
        let visible = state.visible_rows();

        if visible.is_empty() {
            let msg = if state.filter.is_some() {
                "No matching processes"
            } else {
                "No process candidates found"
            };
            let muted_style = self
                .theme
                .map(|t| t.class("status.warning"))
                .unwrap_or_default();

            let block = FtuiBlock::bordered()
                .title(&title)
                .border_style(border_style);

            let para = ftui::widgets::paragraph::Paragraph::new(
                FtuiText::from_line(FtuiLine::from_spans([FtuiSpan::styled(msg, muted_style)])),
            )
            .block(block);
            ftui::widgets::Widget::render(&para, area, frame);
            return;
        }

        let parts = self.build_ftui_table_parts(state, area.width);

        let block = FtuiBlock::bordered()
            .title(&title)
            .border_style(border_style);

        let table = FtuiTable::new(parts.rows, parts.constraints)
            .header(parts.header)
            .block(block)
            .highlight_style(parts.highlight_style)
            .column_spacing(1);

        // Map our cursor to ftui's TableState selection
        let mut ftui_state = FtuiTableState::default();
        ftui_state.selected = Some(state.cursor);
        ftui_state.offset = state.scroll_offset;

        FtuiStatefulWidget::render(&table, area, frame, &mut ftui_state);

        // Sync back scroll offset (ftui may clamp it)
        state.scroll_offset = ftui_state.offset;
    }
}

// ---------------------------------------------------------------------------
// Legacy ratatui StatefulWidget (behind feature gate)
// ---------------------------------------------------------------------------

#[cfg(feature = "ui-legacy")]
impl<'a> StatefulWidget for ProcessTable<'a> {
    type State = ProcessTableState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let focused = state.focused;

        // Build block
        let title = self.title_string(state);
        let border_style = if let Some(theme) = self.theme {
            if focused {
                theme.style_border_focused()
            } else {
                theme.style_border()
            }
        } else {
            Style::default().fg(if focused {
                Color::Cyan
            } else {
                Color::DarkGray
            })
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style);
        let inner = block.inner(area);
        block.render(area, buf);

        let visible = state.visible_rows();
        if visible.is_empty() {
            let msg = if state.filter.is_some() {
                "No matching processes"
            } else {
                "No process candidates found"
            };
            let style = if let Some(theme) = self.theme {
                theme.style_muted()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let x = inner.x + (inner.width.saturating_sub(msg.len() as u16)) / 2;
            let y = inner.y + inner.height / 2;

            if y < inner.bottom() && x < inner.right() {
                for (i, ch) in msg.chars().enumerate() {
                    if x + i as u16 >= inner.right() {
                        break;
                    }
                    buf[(x + i as u16, y)].set_char(ch).set_style(style);
                }
            }
            return;
        }

        // Determine column visibility
        let (show_score, show_runtime, show_memory) = self.column_visibility(inner.width);
        let checkbox_width = if self.show_selection {
            COL_CHECKBOX
        } else {
            0
        };
        let col_widths: [u16; 6] = [
            COL_PID,
            COL_SCORE,
            COL_CLASS,
            COL_RUNTIME,
            COL_MEMORY,
            0, // command fills
        ];

        // Header
        let header_style = if let Some(theme) = self.theme {
            theme.style_highlight()
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };

        let mut x = inner.x;
        if self.show_selection {
            write_text(buf, inner.right(), x, inner.y, "[ ]", header_style);
            x += checkbox_width + 1;
        }

        let pid_header = format!("PID{}", Self::sort_indicator(state, SortColumn::Pid));
        write_text(buf, inner.right(), x, inner.y, &pid_header, header_style);
        x += col_widths[0] + 1;

        if show_score {
            let s = format!("Score{}", Self::sort_indicator(state, SortColumn::Score));
            write_text(buf, inner.right(), x, inner.y, &s, header_style);
            x += col_widths[1] + 1;
        }

        let class_header = format!(
            "Class{}",
            Self::sort_indicator(state, SortColumn::Classification)
        );
        write_text(
            buf,
            inner.right(),
            x,
            inner.y,
            &class_header,
            header_style,
        );
        x += col_widths[2] + 1;

        if show_runtime {
            let s = format!(
                "Runtime{}",
                Self::sort_indicator(state, SortColumn::Runtime)
            );
            write_text(buf, inner.right(), x, inner.y, &s, header_style);
            x += col_widths[3] + 1;
        }

        if show_memory {
            let s = format!("Memory{}", Self::sort_indicator(state, SortColumn::Memory));
            write_text(buf, inner.right(), x, inner.y, &s, header_style);
            x += col_widths[4] + 1;
        }

        let cmd_header = format!(
            "Command{}",
            Self::sort_indicator(state, SortColumn::Command)
        );
        write_text(buf, inner.right(), x, inner.y, &cmd_header, header_style);

        // Separator
        let sep_y = inner.y + 1;
        if sep_y < inner.bottom() {
            for dx in 0..inner.width {
                buf[(inner.x + dx, sep_y)]
                    .set_char('─')
                    .set_style(header_style);
            }
        }

        // Compute command column width
        let total_fixed = col_widths[0]
            + col_widths[2]
            + if show_score { col_widths[1] } else { 0 }
            + if show_runtime { col_widths[3] } else { 0 }
            + if show_memory { col_widths[4] } else { 0 };
        let fixed_cols =
            2 + u16::from(show_score) + u16::from(show_runtime) + u16::from(show_memory);
        let gaps = fixed_cols + if self.show_selection { 1 } else { 0 };
        let command_width = inner
            .width
            .saturating_sub(total_fixed + checkbox_width + gaps);

        // Data rows
        let visible_row_count = (inner.height.saturating_sub(2)) as usize;
        let start_row = state.scroll_offset;
        let end_row = (start_row + visible_row_count).min(visible.len());

        for (i, row_idx) in (start_row..end_row).enumerate() {
            let row = &visible[row_idx];
            let y = inner.y + 2 + i as u16;

            if y >= inner.bottom() {
                break;
            }

            let is_cursor = row_idx == state.cursor;
            let is_selected = state.selected.contains(&row.pid);

            let row_style = if is_cursor {
                if let Some(theme) = self.theme {
                    Style::default().bg(theme.highlight).fg(theme.bg)
                } else {
                    Style::default().bg(Color::Cyan).fg(Color::Black)
                }
            } else if let Some(theme) = self.theme {
                theme.style_normal()
            } else {
                Style::default()
            };

            let mut x = inner.x;

            if self.show_selection {
                let check_char = if is_selected { 'x' } else { ' ' };
                write_text(
                    buf,
                    inner.right(),
                    x,
                    y,
                    &format!("[{}]", check_char),
                    row_style,
                );
                x += checkbox_width + 1;
            }

            write_text(buf, inner.right(), x, y, &row.pid.to_string(), row_style);
            x += col_widths[0] + 1;

            if show_score {
                write_text(
                    buf,
                    inner.right(),
                    x,
                    y,
                    &row.score.to_string(),
                    row_style,
                );
                x += col_widths[1] + 1;
            }

            let class_style = if is_cursor {
                row_style
            } else {
                classification_ratatui_style(self.theme, &row.classification)
            };
            write_text(buf, inner.right(), x, y, &row.classification, class_style);
            x += col_widths[2] + 1;

            if show_runtime {
                write_text(buf, inner.right(), x, y, &row.runtime, row_style);
                x += col_widths[3] + 1;
            }

            if show_memory {
                write_text(buf, inner.right(), x, y, &row.memory, row_style);
                x += col_widths[4] + 1;
            }

            let cmd_display: String = row.command.chars().take(command_width as usize).collect();
            write_text(buf, inner.right(), x, y, &cmd_display, row_style);
        }
    }
}

#[cfg(feature = "ui-legacy")]
fn classification_ratatui_style(theme: Option<&Theme>, classification: &str) -> Style {
    if let Some(theme) = theme {
        match classification.to_uppercase().as_str() {
            "KILL" => theme.style_kill(),
            "REVIEW" => theme.style_review(),
            "SPARE" => theme.style_spare(),
            _ => theme.style_normal(),
        }
    } else {
        match classification.to_uppercase().as_str() {
            "KILL" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            "REVIEW" => Style::default().fg(Color::Yellow),
            "SPARE" => Style::default().fg(Color::Green),
            _ => Style::default(),
        }
    }
}

#[cfg(feature = "ui-legacy")]
fn write_text(buf: &mut Buffer, max_x: u16, x: u16, y: u16, text: &str, style: Style) {
    for (i, ch) in text.chars().enumerate() {
        if x + i as u16 >= max_x {
            break;
        }
        buf[(x + i as u16, y)].set_char(ch).set_style(style);
    }
}

// ---------------------------------------------------------------------------
// ProcessTableState
// ---------------------------------------------------------------------------

/// State for the process table widget.
#[derive(Debug)]
pub struct ProcessTableState {
    /// Whether the table is focused.
    pub focused: bool,
    /// All process rows.
    pub rows: Vec<ProcessRow>,
    /// Currently selected PIDs.
    pub selected: HashSet<u32>,
    /// Current cursor position.
    pub cursor: usize,
    /// Scroll offset (first visible row).
    pub scroll_offset: usize,
    /// Sort column.
    pub sort_column: SortColumn,
    /// Sort order.
    pub sort_order: SortOrder,
    /// Current filter query (lowercase).
    pub filter: Option<String>,
    /// Current view mode (score vs goal ordering).
    pub view_mode: ViewMode,
    /// Optional goal-based ordering (pid -> rank).
    goal_rank: Option<HashMap<u32, usize>>,
}

impl Default for ProcessTableState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTableState {
    /// Create a new process table state.
    pub fn new() -> Self {
        Self {
            focused: false,
            rows: Vec::new(),
            selected: HashSet::new(),
            cursor: 0,
            scroll_offset: 0,
            sort_column: SortColumn::Score,
            sort_order: SortOrder::Descending,
            filter: None,
            view_mode: ViewMode::SuspicionFirst,
            goal_rank: None,
        }
    }

    /// Set the rows.
    pub fn set_rows(&mut self, rows: Vec<ProcessRow>) {
        self.rows = rows;
        self.cursor = 0;
        self.scroll_offset = 0;
        self.sort();
    }

    /// Set goal ordering for goal-first view.
    pub fn set_goal_order(&mut self, order: Option<HashMap<u32, usize>>) {
        self.goal_rank = order;
        if self.goal_rank.is_none() && self.view_mode == ViewMode::GoalFirst {
            self.view_mode = ViewMode::SuspicionFirst;
        }
        self.sort();
    }

    /// Toggle view mode (score vs goal).
    pub fn toggle_view_mode(&mut self) {
        self.view_mode = match self.view_mode {
            ViewMode::SuspicionFirst => {
                if self.goal_rank.is_some() {
                    ViewMode::GoalFirst
                } else {
                    ViewMode::SuspicionFirst
                }
            }
            ViewMode::GoalFirst => ViewMode::SuspicionFirst,
        };
        self.sort();
    }

    /// Return true if goal ordering data is available.
    pub fn has_goal_order(&self) -> bool {
        self.goal_rank.is_some()
    }

    /// Human-readable label for current view mode.
    pub fn view_mode_label(&self) -> &'static str {
        match self.view_mode {
            ViewMode::SuspicionFirst => "score",
            ViewMode::GoalFirst => "goal",
        }
    }

    /// Apply a generated plan preview to the rows.
    pub fn apply_plan_preview(&mut self, plan: &Plan) {
        let mut by_pid: HashMap<u32, Vec<&PlanAction>> = HashMap::new();
        for action in &plan.actions {
            by_pid.entry(action.target.pid.0).or_default().push(action);
        }
        for list in by_pid.values_mut() {
            list.sort_by_key(|a| a.stage);
        }

        for row in &mut self.rows {
            if let Some(actions) = by_pid.get(&row.pid) {
                row.plan_preview = build_plan_preview(actions);
            } else {
                row.plan_preview.clear();
            }
        }
    }

    /// Set the filter query.
    pub fn set_filter(&mut self, filter: Option<String>) {
        self.filter = filter;
        self.cursor = 0;
        self.scroll_offset = 0;
    }

    /// Get visible rows (after filtering).
    pub fn visible_rows(&self) -> Vec<&ProcessRow> {
        if let Some(ref filter) = self.filter {
            self.rows
                .iter()
                .filter(|r| {
                    r.command.to_lowercase().contains(filter)
                        || r.classification.to_lowercase().contains(filter)
                        || r.pid.to_string().contains(filter)
                })
                .collect()
        } else {
            self.rows.iter().collect()
        }
    }

    /// Get the currently focused row (after filtering).
    pub fn current_row(&self) -> Option<&ProcessRow> {
        let visible = self.visible_rows();
        visible.get(self.cursor).copied()
    }

    /// Move cursor down.
    pub fn cursor_down(&mut self) {
        let visible_count = self.visible_rows().len();
        if self.cursor + 1 < visible_count {
            self.cursor += 1;
            self.ensure_cursor_visible();
        }
    }

    /// Move cursor up.
    pub fn cursor_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.ensure_cursor_visible();
        }
    }

    /// Move cursor to first row.
    pub fn cursor_home(&mut self) {
        self.cursor = 0;
        self.scroll_offset = 0;
    }

    /// Move cursor to last row.
    pub fn cursor_end(&mut self) {
        let visible_count = self.visible_rows().len();
        if visible_count > 0 {
            self.cursor = visible_count - 1;
            self.ensure_cursor_visible();
        }
    }

    /// Page down.
    pub fn page_down(&mut self, page_size: usize) {
        let visible_count = self.visible_rows().len();
        let new_cursor = (self.cursor + page_size).min(visible_count.saturating_sub(1));
        self.cursor = new_cursor;
        self.ensure_cursor_visible();
    }

    /// Page up.
    pub fn page_up(&mut self, page_size: usize) {
        self.cursor = self.cursor.saturating_sub(page_size);
        self.ensure_cursor_visible();
    }

    /// Ensure cursor is visible within scroll view.
    fn ensure_cursor_visible(&mut self) {
        let visible = 20; // Assume typical visible rows
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + visible {
            self.scroll_offset = self.cursor - visible + 1;
        }
    }

    /// Toggle selection of current row.
    pub fn toggle_selection(&mut self) {
        let visible = self.visible_rows();
        if let Some(row) = visible.get(self.cursor) {
            let pid = row.pid;
            if self.selected.contains(&pid) {
                self.selected.remove(&pid);
            } else {
                self.selected.insert(pid);
            }
        }
    }

    /// Select all visible rows.
    pub fn select_all(&mut self) {
        let pids: Vec<u32> = self.visible_rows().iter().map(|row| row.pid).collect();
        for pid in pids {
            self.selected.insert(pid);
        }
    }

    /// Select all recommended rows (defaults to KILL classification).
    pub fn select_recommended(&mut self) {
        let pids: Vec<u32> = self
            .visible_rows()
            .iter()
            .filter(|row| row.classification.eq_ignore_ascii_case("KILL"))
            .map(|row| row.pid)
            .collect();
        for pid in pids {
            self.selected.insert(pid);
        }
    }

    /// Invert selection for all visible rows.
    pub fn invert_selection(&mut self) {
        let pids: Vec<u32> = self.visible_rows().iter().map(|row| row.pid).collect();
        for pid in pids {
            if self.selected.contains(&pid) {
                self.selected.remove(&pid);
            } else {
                self.selected.insert(pid);
            }
        }
    }

    /// Deselect all rows.
    pub fn deselect_all(&mut self) {
        self.selected.clear();
    }

    /// Get selected PIDs.
    pub fn get_selected(&self) -> Vec<u32> {
        self.selected.iter().copied().collect()
    }

    /// Get count of selected processes.
    pub fn selected_count(&self) -> usize {
        self.selected.len()
    }

    /// Get total count of processes (after filtering).
    pub fn total_count(&self) -> usize {
        self.rows.len()
    }

    /// Set sort column and order.
    pub fn set_sort(&mut self, column: SortColumn, order: SortOrder) {
        self.sort_column = column;
        self.sort_order = order;
        self.sort();
    }

    /// Toggle sort on a column.
    pub fn toggle_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_order = match self.sort_order {
                SortOrder::Ascending => SortOrder::Descending,
                SortOrder::Descending => SortOrder::Ascending,
            };
        } else {
            self.sort_column = column;
            self.sort_order = SortOrder::Descending;
        }
        self.sort();
    }

    /// Sort rows by current column and order.
    fn sort(&mut self) {
        let order = self.sort_order;
        self.rows.sort_by(|a, b| {
            if self.view_mode == ViewMode::GoalFirst {
                if let Some(ranks) = self.goal_rank.as_ref() {
                    let ra = ranks.get(&a.pid).copied().unwrap_or(usize::MAX);
                    let rb = ranks.get(&b.pid).copied().unwrap_or(usize::MAX);
                    let cmp = ra.cmp(&rb);
                    if cmp != std::cmp::Ordering::Equal {
                        return cmp;
                    }
                }
            }
            let cmp = match self.sort_column {
                SortColumn::Pid => a.pid.cmp(&b.pid),
                SortColumn::Score => a.score.cmp(&b.score),
                SortColumn::Classification => a.classification.cmp(&b.classification),
                SortColumn::Runtime => a.runtime.cmp(&b.runtime),
                SortColumn::Memory => a.memory.cmp(&b.memory),
                SortColumn::Command => a.command.cmp(&b.command),
            };
            match order {
                SortOrder::Ascending => cmp,
                SortOrder::Descending => cmp.reverse(),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Plan preview helpers
// ---------------------------------------------------------------------------

fn build_plan_preview(actions: &[&PlanAction]) -> Vec<String> {
    let mut lines = Vec::new();
    for action in actions {
        let stage_label = format!("Stage {}", action.stage);
        let mut summary = format!(
            "{}: {} ({})",
            stage_label,
            action_label(&action.action),
            confidence_label(action.confidence)
        );
        if action.blocked {
            summary.push_str(" [blocked]");
        }
        if action.routing != ActionRouting::Direct {
            summary.push_str(&format!(" [{}]", routing_label(&action.routing)));
        }
        lines.push(summary);

        if !action.pre_checks.is_empty() {
            lines.push(format!(
                "{} prechecks: {}",
                stage_label,
                format_prechecks(&action.pre_checks)
            ));
        }
    }
    lines
}

fn action_label(action: &Action) -> String {
    format!("{:?}", action).to_lowercase()
}

fn confidence_label(confidence: ActionConfidence) -> &'static str {
    match confidence {
        ActionConfidence::Normal => "normal",
        ActionConfidence::Low => "low",
        ActionConfidence::VeryLow => "very_low",
    }
}

fn routing_label(routing: &ActionRouting) -> &'static str {
    match routing {
        ActionRouting::Direct => "direct",
        ActionRouting::ZombieToParent => "zombie_to_parent",
        ActionRouting::ZombieToSupervisor => "zombie_to_supervisor",
        ActionRouting::ZombieInvestigateOnly => "zombie_investigate_only",
        ActionRouting::DStateLowConfidence => "d_state_low_confidence",
    }
}

fn format_prechecks(checks: &[PreCheck]) -> String {
    checks
        .iter()
        .map(precheck_label)
        .collect::<Vec<_>>()
        .join(", ")
}

fn precheck_label(check: &PreCheck) -> &'static str {
    match check {
        PreCheck::VerifyIdentity => "verify_identity",
        PreCheck::CheckNotProtected => "check_not_protected",
        PreCheck::CheckSessionSafety => "check_session_safety",
        PreCheck::CheckDataLossGate => "check_data_loss_gate",
        PreCheck::CheckSupervisor => "check_supervisor",
        PreCheck::CheckAgentSupervision => "check_agent_supervision",
        PreCheck::VerifyProcessState => "verify_process_state",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rows() -> Vec<ProcessRow> {
        vec![
            ProcessRow {
                pid: 1234,
                score: 85,
                classification: "KILL".to_string(),
                runtime: "2h 30m".to_string(),
                memory: "512 MB".to_string(),
                command: "jest --worker".to_string(),
                selected: false,
                galaxy_brain: None,
                why_summary: Some("Classified as abandoned with high confidence.".to_string()),
                top_evidence: vec!["runtime (2.4 bits toward abandoned)".to_string()],
                confidence: Some("high".to_string()),
                plan_preview: Vec::new(),
            },
            ProcessRow {
                pid: 5678,
                score: 35,
                classification: "REVIEW".to_string(),
                runtime: "1h 15m".to_string(),
                memory: "256 MB".to_string(),
                command: "node dev".to_string(),
                selected: false,
                galaxy_brain: None,
                why_summary: None,
                top_evidence: Vec::new(),
                confidence: Some("medium".to_string()),
                plan_preview: Vec::new(),
            },
            ProcessRow {
                pid: 9012,
                score: 15,
                classification: "SPARE".to_string(),
                runtime: "30m".to_string(),
                memory: "128 MB".to_string(),
                command: "cargo build".to_string(),
                selected: false,
                galaxy_brain: None,
                why_summary: None,
                top_evidence: Vec::new(),
                confidence: Some("low".to_string()),
                plan_preview: Vec::new(),
            },
        ]
    }

    #[test]
    fn test_new_state() {
        let state = ProcessTableState::new();
        assert!(state.rows.is_empty());
        assert!(state.selected.is_empty());
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn test_cursor_navigation() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        assert_eq!(state.cursor, 0);

        state.cursor_down();
        assert_eq!(state.cursor, 1);

        state.cursor_down();
        assert_eq!(state.cursor, 2);

        // Should not go past end
        state.cursor_down();
        assert_eq!(state.cursor, 2);

        state.cursor_up();
        assert_eq!(state.cursor, 1);

        state.cursor_home();
        assert_eq!(state.cursor, 0);

        state.cursor_end();
        assert_eq!(state.cursor, 2);
    }

    #[test]
    fn test_selection() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        assert!(state.selected.is_empty());

        state.toggle_selection();
        assert!(state.selected.contains(&1234));

        state.cursor_down();
        state.toggle_selection();
        assert!(state.selected.contains(&5678));

        assert_eq!(state.selected_count(), 2);

        state.deselect_all();
        assert!(state.selected.is_empty());

        state.select_all();
        assert_eq!(state.selected.len(), 3);
    }

    #[test]
    fn test_select_recommended_and_invert() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.select_recommended();
        assert!(state.selected.contains(&1234));
        assert_eq!(state.selected.len(), 1);

        state.invert_selection();
        assert!(!state.selected.contains(&1234));
        assert!(state.selected.contains(&5678));
        assert!(state.selected.contains(&9012));
    }

    #[test]
    fn test_filtering() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // No filter - all visible
        assert_eq!(state.visible_rows().len(), 3);

        // Filter by command
        state.set_filter(Some("node".to_string()));
        assert_eq!(state.visible_rows().len(), 1);
        assert_eq!(state.visible_rows()[0].pid, 5678);

        // Clear filter
        state.set_filter(None);
        assert_eq!(state.visible_rows().len(), 3);
    }

    #[test]
    fn test_current_row_reflects_filter() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Default cursor points at first row
        assert_eq!(state.current_row().unwrap().pid, 1234);

        // Apply filter and confirm current row updates
        state.set_filter(Some("node".to_string()));
        let current = state.current_row().unwrap();
        assert_eq!(current.pid, 5678);
    }

    #[test]
    fn test_sorting() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Default sort: Score descending
        assert_eq!(state.rows[0].pid, 1234); // Score 85
        assert_eq!(state.rows[1].pid, 5678); // Score 35
        assert_eq!(state.rows[2].pid, 9012); // Score 15

        // Sort by PID ascending
        state.set_sort(SortColumn::Pid, SortOrder::Ascending);
        assert_eq!(state.rows[0].pid, 1234);
        assert_eq!(state.rows[1].pid, 5678);
        assert_eq!(state.rows[2].pid, 9012);

        // Toggle sort on Score
        state.toggle_sort(SortColumn::Score);
        assert_eq!(state.sort_column, SortColumn::Score);
        assert_eq!(state.sort_order, SortOrder::Descending);

        // Toggle again to ascending
        state.toggle_sort(SortColumn::Score);
        assert_eq!(state.sort_order, SortOrder::Ascending);
        assert_eq!(state.rows[0].pid, 9012); // Score 15 now first
    }

    // ── Selection persistence tests ──────────────────────────────────

    #[test]
    fn test_selection_persists_across_filter() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Select PID 1234 (KILL row)
        state.toggle_selection();
        assert!(state.selected.contains(&1234));

        // Apply filter that hides the selected row
        state.set_filter(Some("node".to_string()));
        assert_eq!(state.visible_rows().len(), 1);

        // Selection should still contain PID 1234
        assert!(state.selected.contains(&1234));

        // Clear filter
        state.set_filter(None);
        assert!(state.selected.contains(&1234));
    }

    #[test]
    fn test_selection_persists_across_sort() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Select PID 5678
        state.cursor_down();
        state.toggle_selection();
        assert!(state.selected.contains(&5678));

        // Re-sort by PID ascending
        state.set_sort(SortColumn::Pid, SortOrder::Ascending);

        // Selection should still have PID 5678
        assert!(state.selected.contains(&5678));
    }

    // ── Toggle selection edge cases ───────────────────────────────────

    #[test]
    fn test_toggle_selection_removes_pid() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Add then remove
        state.toggle_selection();
        assert!(state.selected.contains(&1234));

        state.toggle_selection();
        assert!(!state.selected.contains(&1234));
        assert!(state.selected.is_empty());
    }

    // ── Filter edge cases ─────────────────────────────────────────────

    #[test]
    fn test_filter_matches_command_case_insensitive() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.set_filter(Some("NODE".to_string()));
        // The filter uses lowercase comparison, but the filter value
        // itself needs to be lowercase for .contains() to match
        state.set_filter(Some("node".to_string()));
        let visible = state.visible_rows();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].command, "node dev");
    }

    #[test]
    fn test_filter_matches_pid_as_string() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.set_filter(Some("5678".to_string()));
        let visible = state.visible_rows();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].pid, 5678);
    }

    #[test]
    fn test_filter_matches_classification() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.set_filter(Some("spare".to_string()));
        let visible = state.visible_rows();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].pid, 9012);
    }

    #[test]
    fn test_get_selected_pids_returns_correct_set() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.toggle_selection(); // PID 1234
        state.cursor_down();
        state.toggle_selection(); // PID 5678

        let mut selected = state.get_selected();
        selected.sort();
        assert_eq!(selected, vec![1234, 5678]);
    }

    #[test]
    fn test_select_recommended_selects_kill_only() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        state.select_recommended();
        let selected = state.get_selected();

        // Only PID 1234 has KILL classification
        assert_eq!(selected.len(), 1);
        assert!(selected.contains(&1234));

        // Verify REVIEW and SPARE are not selected
        assert!(!state.selected.contains(&5678));
        assert!(!state.selected.contains(&9012));
    }

    // ── Sort edge cases ───────────────────────────────────────────────

    #[test]
    fn test_sort_toggle_reverses_order() {
        let mut state = ProcessTableState::new();
        state.set_rows(sample_rows());

        // Default is Score Descending
        assert_eq!(state.sort_column, SortColumn::Score);
        assert_eq!(state.sort_order, SortOrder::Descending);

        // Toggle same column flips direction
        state.toggle_sort(SortColumn::Score);
        assert_eq!(state.sort_order, SortOrder::Ascending);
        // Lowest score first
        assert_eq!(state.rows[0].pid, 9012);

        // Toggle again flips back
        state.toggle_sort(SortColumn::Score);
        assert_eq!(state.sort_order, SortOrder::Descending);
        // Highest score first
        assert_eq!(state.rows[0].pid, 1234);
    }

    // ── Column visibility tests ───────────────────────────────────────

    #[test]
    fn test_column_visibility_wide() {
        let table = ProcessTable::new();
        let (show_score, show_runtime, show_memory) = table.column_visibility(120);
        assert!(show_score);
        assert!(show_runtime);
        assert!(show_memory);
    }

    #[test]
    fn test_column_visibility_narrow() {
        let table = ProcessTable::new();
        // Very narrow should drop optional columns
        let (show_score, show_runtime, show_memory) = table.column_visibility(30);
        assert!(!show_memory || !show_runtime || !show_score);
    }
}
