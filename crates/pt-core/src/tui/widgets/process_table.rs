//! Process table widget for displaying candidate processes.
//!
//! Custom table widget with Process Triage-specific columns and styling.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, StatefulWidget, Widget},
};
use std::collections::{HashMap, HashSet};

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

/// Process table widget for displaying candidates.
#[derive(Debug)]
pub struct ProcessTable<'a> {
    /// Block wrapper.
    block: Option<Block<'a>>,
    /// Theme for styling.
    theme: Option<&'a Theme>,
    /// Column widths (proportional).
    col_widths: [u16; 6],
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
            block: None,
            theme: None,
            col_widths: [6, 6, 12, 10, 10, 0], // PID, Score, Class, Runtime, Mem, Command (fills)
            show_selection: true,
        }
    }

    /// Set the block wrapper.
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
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

    /// Build the styled block based on focus state.
    fn styled_block(&self, focused: bool, state: &ProcessTableState) -> Block<'a> {
        let selected_count = state.selected.len();
        let total_count = state.visible_rows().len();
        let view_label = match state.view_mode {
            ViewMode::SuspicionFirst => "score",
            ViewMode::GoalFirst => "goal",
        };

        let title = if selected_count > 0 {
            format!(
                " Processes [{}/{} selected] [view: {}] [Space: toggle, a: rec, A: all, u: clear, x: invert, e: execute] ",
                selected_count, total_count, view_label
            )
        } else {
            format!(
                " Processes [{}] [view: {}] [Space: toggle, a: rec, A: all, u: clear, x: invert, e: execute] ",
                total_count, view_label
            )
        };

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

        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style)
    }

    /// Get classification style.
    fn classification_style(&self, classification: &str) -> Style {
        if let Some(theme) = self.theme {
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

    fn write_text(buf: &mut Buffer, max_x: u16, x: u16, y: u16, text: &str, style: Style) {
        for (i, ch) in text.chars().enumerate() {
            if x + i as u16 >= max_x {
                break;
            }
            buf[(x + i as u16, y)].set_char(ch).set_style(style);
        }
    }
}

impl<'a> StatefulWidget for ProcessTable<'a> {
    type State = ProcessTableState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let focused = state.focused;
        let block = self
            .block
            .clone()
            .unwrap_or_else(|| self.styled_block(focused, state));
        let inner = block.inner(area);
        block.render(area, buf);

        let visible = state.visible_rows();
        if visible.is_empty() {
            // Render empty state message
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

        // Calculate column visibility and widths
        let checkbox_width = if self.show_selection { 3 } else { 0 };
        let min_command_width: u16 = 12;
        let mut show_score = true;
        let mut show_runtime = true;
        let mut show_memory = true;

        let (_total_fixed, command_width) = loop {
            let fixed_cols =
                2 + u16::from(show_score) + u16::from(show_runtime) + u16::from(show_memory);
            let total_fixed = self.col_widths[0]
                + self.col_widths[2]
                + if show_score { self.col_widths[1] } else { 0 }
                + if show_runtime { self.col_widths[3] } else { 0 }
                + if show_memory { self.col_widths[4] } else { 0 };
            let gaps = fixed_cols + if self.show_selection { 1 } else { 0 };
            let command_width = inner
                .width
                .saturating_sub(total_fixed + checkbox_width + gaps);

            if command_width >= min_command_width {
                break (total_fixed, command_width);
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

            break (total_fixed, command_width);
        };

        // Header row
        let header_style = if let Some(theme) = self.theme {
            theme.style_highlight()
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };

        let sort_indicator = |col: SortColumn| -> &str {
            if state.sort_column == col {
                match state.sort_order {
                    SortOrder::Ascending => " ▲",
                    SortOrder::Descending => " ▼",
                }
            } else {
                ""
            }
        };

        // Render header
        let mut x = inner.x;
        if self.show_selection {
            Self::write_text(buf, inner.right(), x, inner.y, "[ ]", header_style);
            x += checkbox_width + 1;
        }

        let pid_header = format!("PID{}", sort_indicator(SortColumn::Pid));
        Self::write_text(buf, inner.right(), x, inner.y, &pid_header, header_style);
        x += self.col_widths[0] + 1;

        if show_score {
            let score_header = format!("Score{}", sort_indicator(SortColumn::Score));
            Self::write_text(buf, inner.right(), x, inner.y, &score_header, header_style);
            x += self.col_widths[1] + 1;
        }

        let class_header = format!("Class{}", sort_indicator(SortColumn::Classification));
        Self::write_text(buf, inner.right(), x, inner.y, &class_header, header_style);
        x += self.col_widths[2] + 1;

        if show_runtime {
            let runtime_header = format!("Runtime{}", sort_indicator(SortColumn::Runtime));
            Self::write_text(
                buf,
                inner.right(),
                x,
                inner.y,
                &runtime_header,
                header_style,
            );
            x += self.col_widths[3] + 1;
        }

        if show_memory {
            let memory_header = format!("Memory{}", sort_indicator(SortColumn::Memory));
            Self::write_text(buf, inner.right(), x, inner.y, &memory_header, header_style);
            x += self.col_widths[4] + 1;
        }

        let command_header = format!("Command{}", sort_indicator(SortColumn::Command));
        Self::write_text(
            buf,
            inner.right(),
            x,
            inner.y,
            &command_header,
            header_style,
        );

        // Render separator line
        let sep_y = inner.y + 1;
        if sep_y < inner.bottom() {
            for dx in 0..inner.width {
                buf[(inner.x + dx, sep_y)]
                    .set_char('─')
                    .set_style(header_style);
            }
        }

        // Render rows
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

            // Checkbox
            if self.show_selection {
                let check_char = if is_selected { 'x' } else { ' ' };
                Self::write_text(
                    buf,
                    inner.right(),
                    x,
                    y,
                    &format!("[{}]", check_char),
                    row_style,
                );
                x += checkbox_width + 1;
            }

            // PID
            let pid_str = row.pid.to_string();
            Self::write_text(buf, inner.right(), x, y, &pid_str, row_style);
            x += self.col_widths[0] + 1;

            // Score
            if show_score {
                let score_str = row.score.to_string();
                Self::write_text(buf, inner.right(), x, y, &score_str, row_style);
                x += self.col_widths[1] + 1;
            }

            // Classification (with color)
            let class_style = if is_cursor {
                row_style
            } else {
                self.classification_style(&row.classification)
            };
            Self::write_text(buf, inner.right(), x, y, &row.classification, class_style);
            x += self.col_widths[2] + 1;

            // Runtime
            if show_runtime {
                Self::write_text(buf, inner.right(), x, y, &row.runtime, row_style);
                x += self.col_widths[3] + 1;
            }

            // Memory
            if show_memory {
                Self::write_text(buf, inner.right(), x, y, &row.memory, row_style);
                x += self.col_widths[4] + 1;
            }

            // Command (truncated)
            let cmd_display: String = row.command.chars().take(command_width as usize).collect();
            Self::write_text(buf, inner.right(), x, y, &cmd_display, row_style);
        }
    }
}

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
}
