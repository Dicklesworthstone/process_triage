//! Main TUI application state and event loop.
//!
//! Manages the overall TUI application state, terminal setup/teardown,
//! and the main render/event loop.
//!
//! ## ftui Model Contract
//!
//! `App` implements `ftui::Model`:
//! - `init()` initializes model state (and may return a startup `Cmd`)
//! - `update(msg)` applies a single `Msg` and may return a `Cmd`
//! - `view(frame)` renders state into a frame (pure w.r.t. input state)
//! - `subscriptions()` registers periodic ticks and other streams
//!
//! Async work (refresh, execute, evidence export) is injected via closures and executed via
//! `Cmd::task`, returning completion messages back into `update()`.
//!
//! ## Running
//!
//! `run_ftui(...)` wires terminal lifecycle via `ftui::Program`. Inline mode (`--inline`)
//! anchors the UI at the bottom of the terminal so logs/progress can scroll above it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ftui::layout::Rect;
use ftui::runtime::{Every, Subscription};
use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText, WrapMode};
use ftui::widgets::command_palette::{ActionItem, CommandPalette, PaletteAction};
use ftui::widgets::notification_queue::{NotificationQueue, NotificationStack, QueueConfig};
use ftui::widgets::paragraph::Paragraph as FtuiParagraph;
use ftui::widgets::toast::{Toast, ToastIcon, ToastPosition, ToastStyle};
use ftui::widgets::Widget;
use ftui::{
    Cell as FtuiCell, Cmd as FtuiCmd, Event as FtuiEvent, Frame as FtuiFrame,
    KeyCode as FtuiKeyCode, KeyEvent as FtuiKeyEvent, KeyEventKind as FtuiKeyEventKind,
    Model as FtuiModel, Modifiers as FtuiModifiers, Program, ProgramConfig,
};

use super::events::KeyBindings;
use super::layout::{Breakpoint, LayoutState, ResponsiveLayout};
use super::msg::{
    ExecutionOutcome, Msg, PressureOverview, PressureUnit, RefreshOutcome, UndoBatch, UndoOverview,
    UndoRestoreOutcome,
};
use super::theme::Theme;
use super::widgets::{
    AuxPanel, ConfirmChoice, ConfirmDialog, ConfirmDialogState, DetailView, HelpOverlay,
    ProcessDetail, ProcessTable, ProcessTableState, SearchInput, SearchInputState, StatusBar,
    StatusMode,
};
use super::{TuiError, TuiResult};

#[cfg(test)]
use super::widgets::ProcessRow;

/// Focus targets in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusTarget {
    /// Search input field.
    Search,
    /// Process table.
    ProcessList,
}

/// Current application state/mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppState {
    /// Normal browsing mode.
    #[default]
    Normal,
    /// Search input is active.
    Searching,
    /// Confirmation dialog is visible.
    Confirming,
    /// Help overlay is visible.
    Help,
    /// Host pressure and responsible-unit observations from the current scan.
    Pressure,
    /// Durable control batches are visible for inspection and restoration.
    Undo,
    /// A specific immutable control batch is awaiting explicit confirmation.
    ConfirmingUndo,
    /// Application is quitting.
    Quitting,
}

type RefreshOp = Arc<dyn Fn() -> Result<RefreshOutcome, String> + Send + Sync>;
type ExecuteOp =
    Arc<dyn Fn(Vec<u32>, Vec<u32>, Vec<u32>) -> Result<ExecutionOutcome, String> + Send + Sync>;
type UndoInspectOp = Arc<dyn Fn() -> Result<UndoOverview, String> + Send + Sync>;
type UndoRestoreOp = Arc<dyn Fn(UndoBatch) -> Result<UndoRestoreOutcome, String> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PendingOperation {
    #[default]
    Idle,
    Refreshing(u64),
    Executing(u64),
    LoadingUndo(u64),
    RestoringUndo(u64),
}

struct SelectionSnapshot {
    pids: Vec<u32>,
    explicitly_selected: Vec<u32>,
    explicitly_spared: Vec<u32>,
}

struct ConfirmedSelection {
    ticket: u64,
    selection: SelectionSnapshot,
}

struct ConfirmedUndo {
    ticket: u64,
    batch: UndoBatch,
}

/// Main TUI application.
pub struct App {
    /// Current application state.
    pub state: AppState,
    /// Theme for styling.
    pub theme: Theme,
    /// Key bindings configuration.
    pub key_bindings: KeyBindings,
    /// Current focus target.
    focus: FocusTarget,
    /// Search input state.
    pub search: SearchInputState,
    /// Process table state.
    pub process_table: ProcessTableState,
    /// Confirmation dialog state.
    pub confirm_dialog: ConfirmDialogState,
    /// Status message to display.
    status_message: Option<String>,
    /// Whether a redraw is needed.
    needs_redraw: bool,
    operation: PendingOperation,
    last_operation_ticket: u64,
    confirmation_selection: Option<SelectionSnapshot>,
    confirmed_selection: Option<ConfirmedSelection>,
    /// Responsive layout state for tracking breakpoint changes.
    layout_state: LayoutState,
    /// Whether the detail pane is visible.
    detail_visible: bool,
    /// Current detail view mode.
    detail_view: DetailView,
    /// Optional goal summary lines to display.
    goal_summary: Option<Vec<String>>,
    pressure: Option<PressureOverview>,
    /// Zero is the host summary; subsequent entries are responsible units.
    pressure_cursor: usize,
    pressure_detail_offset: usize,
    pressure_filter_label: Option<String>,
    /// Injected refresh operation for ftui Cmd::task (Send + 'static).
    /// Returns new rows and their goal metadata on success.
    refresh_op: Option<RefreshOp>,
    /// Injected execute operation for ftui Cmd::task (Send + 'static).
    /// Takes selected PIDs, explicit positive selections, and explicit spares.
    /// An empty action selection with spares saves feedback without acting.
    execute_op: Option<ExecuteOp>,
    undo_inspect_op: Option<UndoInspectOp>,
    undo_restore_op: Option<UndoRestoreOp>,
    undo_overview: Option<UndoOverview>,
    undo_cursor: usize,
    undo_detail_offset: usize,
    undo_error: Option<String>,
    undo_result: Option<UndoRestoreOutcome>,
    undo_confirmation: Option<UndoBatch>,
    confirmed_undo: Option<ConfirmedUndo>,
    /// Toast notification queue for async operation feedback.
    notifications: NotificationQueue,
    /// Command palette for fuzzy action discovery and execution.
    command_palette: CommandPalette,
    /// Soft latency budget for palette key handling before warning.
    command_palette_event_budget: Duration,
    /// When true, disables animations and uses static indicators.
    /// Activated by `--reduce-motion` CLI flag or `REDUCE_MOTION` env var.
    pub reduce_motion: bool,
    /// When true, enables screen-reader-friendly output (text labels instead of
    /// Unicode icons, verbose announcements, auto-enables reduce_motion).
    /// Activated by `--accessible` CLI flag or `PT_ACCESSIBLE` env var.
    pub accessible: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new application instance.
    pub fn new() -> Self {
        let mut process_table = ProcessTableState::new();
        process_table.focused = true; // Start with process table focused

        let accessible = std::env::var("PT_ACCESSIBLE").is_ok();
        let reduce_motion = accessible
            || std::env::var("REDUCE_MOTION").is_ok()
            || std::env::var("PT_REDUCE_MOTION").is_ok();
        let mut command_palette = Self::build_command_palette();
        command_palette.enable_evidence_tracking(true);

        Self {
            state: AppState::Normal,
            theme: Theme::default(),
            key_bindings: KeyBindings::default(),
            focus: FocusTarget::ProcessList,
            search: SearchInputState::new(),
            process_table,
            confirm_dialog: ConfirmDialogState::new(),
            status_message: None,
            needs_redraw: true,
            operation: PendingOperation::Idle,
            last_operation_ticket: 0,
            confirmation_selection: None,
            confirmed_selection: None,
            // Initialize with reasonable defaults; will be updated on first render
            layout_state: LayoutState::new(80, 24),
            detail_visible: true,
            detail_view: DetailView::Summary,
            goal_summary: None,
            pressure: None,
            pressure_cursor: 0,
            pressure_detail_offset: 0,
            pressure_filter_label: None,
            refresh_op: None,
            execute_op: None,
            undo_inspect_op: None,
            undo_restore_op: None,
            undo_overview: None,
            undo_cursor: 0,
            undo_detail_offset: 0,
            undo_error: None,
            undo_result: None,
            undo_confirmation: None,
            confirmed_undo: None,
            notifications: NotificationQueue::new(QueueConfig {
                max_visible: 3,
                max_queued: 10,
                default_duration: Duration::from_secs(if reduce_motion { 8 } else { 5 }),
                position: ToastPosition::TopRight,
                stagger_offset: if reduce_motion { 0 } else { 1 },
                dedup_window_ms: 1000,
            }),
            command_palette,
            command_palette_event_budget: Duration::from_millis(8),
            reduce_motion,
            accessible,
        }
    }

    fn build_command_palette() -> CommandPalette {
        let mut palette = CommandPalette::new().with_max_visible(12);
        let mut actions = vec![
            ActionItem::new("action.execute", "Execute selected  [e]")
                .with_description("Confirm selected actions and save explicit spare decisions")
                .with_tags(&["execute", "kill", "confirm", "spare", "feedback"])
                .with_category("Actions"),
            ActionItem::new("action.refresh", "Refresh processes  [r]")
                .with_description("Rescan processes and refresh recommendations")
                .with_tags(&["refresh", "rescan"])
                .with_category("Actions"),
            ActionItem::new("action.undo", "Undo recorded controls  [U]")
                .with_description("Inspect saved control batches and confirm restoration")
                .with_tags(&["undo", "restore", "resume", "thaw", "controls"])
                .with_category("Actions"),
            ActionItem::new("navigation.first", "Go to first process  [Home]")
                .with_description("Move cursor to the first process row")
                .with_tags(&["navigate", "top", "home"])
                .with_category("Navigation"),
            ActionItem::new("navigation.last", "Go to last process  [End]")
                .with_description("Move cursor to the last process row")
                .with_tags(&["navigate", "bottom", "end"])
                .with_category("Navigation"),
            ActionItem::new("navigation.page_down", "Page down  [PgDn]")
                .with_description("Move down one page in the process table")
                .with_tags(&["navigate", "page", "down"])
                .with_category("Navigation"),
            ActionItem::new("navigation.page_up", "Page up  [PgUp]")
                .with_description("Move up one page in the process table")
                .with_tags(&["navigate", "page", "up"])
                .with_category("Navigation"),
            ActionItem::new("search.open", "Enter search mode  [/]")
                .with_description("Focus the search input and start filtering")
                .with_tags(&["search", "filter"])
                .with_category("Navigation"),
            ActionItem::new("selection.recommended", "Select recommended  [a]")
                .with_description("Select rows classified as recommended")
                .with_tags(&["select", "recommended"])
                .with_category("Selection"),
            ActionItem::new("selection.all", "Select all  [A]")
                .with_description("Select all visible processes")
                .with_tags(&["select", "all"])
                .with_category("Selection"),
            ActionItem::new("selection.none", "Deselect all  [u]")
                .with_description("Clear current selection")
                .with_tags(&["deselect", "clear"])
                .with_category("Selection"),
            ActionItem::new("selection.invert", "Invert selection  [x]")
                .with_description("Invert selected and unselected rows")
                .with_tags(&["invert", "selection"])
                .with_category("Selection"),
            ActionItem::new("view.toggle_detail", "Toggle detail pane  [Enter]")
                .with_description("Show or hide the process detail pane")
                .with_tags(&["detail", "pane"])
                .with_category("Views"),
            ActionItem::new("view.summary", "Show summary detail  [s]")
                .with_description("Switch detail pane to summary mode")
                .with_tags(&["detail", "summary"])
                .with_category("Views"),
            ActionItem::new("view.genealogy", "Show genealogy detail  [t]")
                .with_description("Switch detail pane to genealogy mode")
                .with_tags(&["detail", "genealogy"])
                .with_category("Views"),
            ActionItem::new("view.galaxy", "Toggle galaxy brain detail  [g]")
                .with_description("Toggle detail pane between summary and galaxy-brain modes")
                .with_tags(&["detail", "galaxy"])
                .with_category("Views"),
            ActionItem::new("view.goal", "Toggle goal view  [v]")
                .with_description("Switch process table between score and goal ordering")
                .with_tags(&["goal", "view", "sort"])
                .with_category("Views"),
            ActionItem::new("view.pressure", "Inspect pressure and workloads  [P]")
                .with_description("Browse host pressure and responsible units from this scan")
                .with_tags(&["pressure", "workload", "unit", "resource"])
                .with_category("Views"),
            ActionItem::new("view.clear_unit", "Clear workload filter  [c]")
                .with_description("Show all process rows, retaining the text search")
                .with_tags(&["filter", "workload", "unit", "clear"])
                .with_category("Views"),
            ActionItem::new("view.help", "Show keyboard shortcuts  [?]")
                .with_description("Open the full help overlay")
                .with_tags(&["help", "shortcuts"])
                .with_category("Views"),
            ActionItem::new("settings.theme.dark", "Switch theme: dark")
                .with_description("Apply the dark theme")
                .with_tags(&["theme", "dark"])
                .with_category("Settings"),
            ActionItem::new("settings.theme.light", "Switch theme: light")
                .with_description("Apply the light theme")
                .with_tags(&["theme", "light"])
                .with_category("Settings"),
            ActionItem::new(
                "settings.theme.high_contrast",
                "Switch theme: high contrast",
            )
            .with_description("Apply high-contrast theme for accessibility")
            .with_tags(&["theme", "contrast", "accessible"])
            .with_category("Settings"),
            ActionItem::new("settings.theme.no_color", "Switch theme: no color")
                .with_description("Disable colors for no-color terminals")
                .with_tags(&["theme", "no-color"])
                .with_category("Settings"),
        ];

        // Deterministic lexical fallback for ties when match scores are equal.
        actions.sort_by(|a, b| a.title.cmp(&b.title).then_with(|| a.id.cmp(&b.id)));
        for action in actions {
            palette.register_action(action);
        }
        palette
    }

    /// Set goal summary lines for display.
    pub fn set_goal_summary(&mut self, lines: Vec<String>) {
        self.goal_summary = if lines.is_empty() { None } else { Some(lines) };
        self.needs_redraw = true;
    }

    /// Clear goal summary display.
    pub fn clear_goal_summary(&mut self) {
        self.goal_summary = None;
        self.needs_redraw = true;
    }

    /// Get the current layout breakpoint.
    pub fn breakpoint(&self) -> Breakpoint {
        self.layout_state.breakpoint()
    }

    /// Returns true if the right-hand detail pane is currently visible.
    pub fn is_detail_visible(&self) -> bool {
        self.detail_visible
    }

    /// Returns the current detail pane mode.
    pub fn current_detail_view(&self) -> DetailView {
        self.detail_view
    }

    /// Update layout state for new terminal size.
    /// Returns true if breakpoint changed.
    pub fn update_layout(&mut self, width: u16, height: u16) -> bool {
        let changed = self.layout_state.update(width, height);
        if changed {
            self.needs_redraw = true;
        }
        changed
    }

    /// Set the theme.
    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    /// Set custom key bindings.
    pub fn with_key_bindings(mut self, bindings: KeyBindings) -> Self {
        self.key_bindings = bindings;
        self
    }

    /// Set the async refresh operation for ftui Cmd::task.
    pub fn set_refresh_op(&mut self, op: RefreshOp) {
        self.refresh_op = Some(op);
    }

    /// Replace one scan atomically, expiring any previous selection and goal.
    pub fn replace_processes(&mut self, outcome: RefreshOutcome) {
        self.invalidate_selection();
        self.process_table.set_rows(outcome.rows);
        self.process_table
            .set_goal_selection(outcome.goal_selection);
        self.goal_summary = outcome.goal_summary;
        self.pressure = outcome.pressure;
        self.pressure_cursor = 0;
        self.pressure_detail_offset = 0;
        self.pressure_filter_label = None;
        if self.state == AppState::Pressure {
            self.state = AppState::Normal;
        }
        self.needs_redraw = true;
    }

    /// Host and workload observations belonging to the currently displayed scan.
    pub fn pressure_overview(&self) -> Option<&PressureOverview> {
        self.pressure.as_ref()
    }

    /// Highlighted workload, or `None` for the host summary.
    pub fn selected_pressure_unit(&self) -> Option<&PressureUnit> {
        self.pressure_cursor
            .checked_sub(1)
            .and_then(|index| self.pressure.as_ref()?.units.get(index))
    }

    fn move_pressure_cursor(&mut self, target: usize) {
        if self.state != AppState::Pressure || !self.operation_is_idle() {
            return;
        }
        let last = self
            .pressure
            .as_ref()
            .map_or(0, |overview| overview.units.len());
        self.pressure_cursor = target.min(last);
        self.pressure_detail_offset = 0;
        self.needs_redraw = true;
    }

    fn scroll_pressure_details(&mut self, forward: bool) {
        if self.state != AppState::Pressure || !self.operation_is_idle() {
            return;
        }
        let width = self.layout_state.size().0.saturating_sub(2);
        let last = self.pressure_detail_lines(width).len().saturating_sub(1);
        self.pressure_detail_offset = if forward {
            self.pressure_detail_offset.saturating_add(4).min(last)
        } else {
            self.pressure_detail_offset.saturating_sub(4)
        };
        self.needs_redraw = true;
    }

    fn filter_pressure_unit(&mut self) {
        if self.state != AppState::Pressure || !self.operation_is_idle() {
            return;
        }
        let Some(unit) = self.selected_pressure_unit() else {
            self.set_status("Host pressure is informational; select a workload to filter rows");
            return;
        };
        let members: std::collections::HashSet<_> = unit.member_pids.iter().copied().collect();
        let members: std::collections::HashSet<_> = self
            .process_table
            .rows
            .iter()
            .filter(|row| members.contains(&row.pid))
            .map(|row| row.pid)
            .collect();
        if members.is_empty() {
            self.set_status("This workload has no candidate rows in this scan; nothing selected");
            return;
        }
        let label = unit.label.clone();
        self.invalidate_selection();
        self.process_table.set_member_filter(Some(members));
        self.pressure_filter_label = Some(label.clone());
        self.state = AppState::Normal;
        self.focus = FocusTarget::ProcessList;
        self.update_focus();
        self.set_status(format!(
            "Workload: {label}; {} visible rows, none selected. c clears the filter",
            self.process_table.visible_rows().len()
        ));
    }

    fn clear_pressure_filter(&mut self) {
        if !self.operation_is_idle() || !matches!(self.state, AppState::Normal | AppState::Pressure)
        {
            return;
        }
        self.invalidate_selection();
        self.process_table.set_member_filter(None);
        self.pressure_filter_label = None;
        self.set_status("Workload filter cleared; text search retained, no processes selected");
    }

    /// Set the async execute operation for ftui Cmd::task.
    pub fn set_execute_op(&mut self, op: ExecuteOp) {
        self.execute_op = Some(op);
    }

    /// Install persisted inspection and guarded restoration callbacks. These run
    /// only as asynchronous operations, never from a render or a direct key.
    pub fn set_undo_ops(&mut self, inspect: UndoInspectOp, restore: UndoRestoreOp) {
        self.undo_inspect_op = Some(inspect);
        self.undo_restore_op = Some(restore);
        self.invalidate_undo_confirmation();
        self.undo_overview = None;
    }

    /// Last completed persisted overview, absent until inspection succeeds.
    pub fn undo_overview(&self) -> Option<&UndoOverview> {
        self.undo_overview.as_ref()
    }

    /// Batch currently highlighted in the undo panel. Selection alone never
    /// authorizes restoration.
    pub fn selected_undo_batch(&self) -> Option<&UndoBatch> {
        self.undo_overview
            .as_ref()
            .and_then(|overview| overview.batches.get(self.undo_cursor))
    }

    fn invalidate_undo_confirmation(&mut self) {
        self.undo_confirmation = None;
        self.confirmed_undo = None;
        if self.state == AppState::ConfirmingUndo {
            self.confirm_dialog.cancel();
            self.state = AppState::Undo;
        }
    }

    fn replace_undo_overview(&mut self, overview: UndoOverview, selected: Option<&str>) {
        let previous = selected.map(str::to_owned).or_else(|| {
            self.selected_undo_batch()
                .map(|batch| batch.session_id.clone())
        });
        self.invalidate_undo_confirmation();
        self.undo_cursor = previous
            .as_ref()
            .and_then(|session| {
                overview
                    .batches
                    .iter()
                    .position(|batch| &batch.session_id == session)
            })
            .unwrap_or(0);
        self.undo_overview = Some(overview);
        self.undo_detail_offset = 0;
        self.undo_error = None;
        self.needs_redraw = true;
    }

    fn undo_block_reason(&self, batch: &UndoBatch) -> Option<String> {
        if self.undo_error.is_some() {
            return Some("Reload saved controls before confirming restoration".to_string());
        }
        if let Some(reason) = self
            .undo_overview
            .as_ref()
            .and_then(|overview| overview.read_only_reason.as_ref())
        {
            return Some(reason.clone());
        }
        if let Some(reason) = &batch.blocked_reason {
            return Some(reason.clone());
        }
        if batch.pending == 0 {
            return Some("No pending restorations in this batch".to_string());
        }
        if batch.session_id.is_empty()
            || batch.plan_sha256.is_empty()
            || batch.receipt_fingerprint.is_empty()
        {
            return Some("Saved control binding is unavailable; reload the panel".to_string());
        }
        None
    }

    fn move_undo_cursor(&mut self, target: usize) {
        if self.state != AppState::Undo || !self.operation_is_idle() {
            return;
        }
        self.invalidate_undo_confirmation();
        let count = self
            .undo_overview
            .as_ref()
            .map_or(0, |overview| overview.batches.len());
        self.undo_cursor = target.min(count.saturating_sub(1));
        self.undo_detail_offset = 0;
        self.needs_redraw = true;
    }

    fn scroll_undo_details(&mut self, forward: bool) {
        if self.state != AppState::Undo || !self.operation_is_idle() {
            return;
        }
        let width = self.layout_state.size().0.saturating_sub(2);
        let last = self.undo_detail_lines(width).len().saturating_sub(1);
        self.undo_detail_offset = if forward {
            self.undo_detail_offset.saturating_add(4).min(last)
        } else {
            self.undo_detail_offset.saturating_sub(4)
        };
        self.needs_redraw = true;
    }

    fn request_undo_refresh(&mut self) -> FtuiCmd<Msg> {
        if !self.operation_is_idle() {
            return FtuiCmd::none();
        }
        self.invalidate_selection();
        self.state = AppState::Undo;
        self.undo_result = None;
        let Some(inspect) = self.undo_inspect_op.clone() else {
            self.undo_error =
                Some("Saved control inspection is unavailable in this build".to_string());
            self.set_status("Undo is unavailable: no inspection backend");
            return FtuiCmd::none();
        };
        let Some(ticket) = self.issue_operation_ticket() else {
            return FtuiCmd::none();
        };
        self.operation = PendingOperation::LoadingUndo(ticket);
        self.set_status("Loading recorded control batches...");
        FtuiCmd::sequence(vec![
            FtuiCmd::log("undo: inspecting saved control batches"),
            FtuiCmd::task_named("inspect-controls", move || Msg::UndoLoaded {
                ticket,
                result: inspect(),
            }),
        ])
    }

    fn show_undo_confirmation(&mut self) {
        if self.state != AppState::Undo || !self.operation_is_idle() {
            return;
        }
        self.invalidate_undo_confirmation();
        let Some(batch) = self.selected_undo_batch().cloned() else {
            self.set_status("No saved control batch selected");
            return;
        };
        if let Some(reason) = self.undo_block_reason(&batch) {
            self.set_status(format!("Restoration unavailable: {reason}"));
            return;
        }
        if self.undo_restore_op.is_none() {
            self.set_status("Restoration unavailable: no execution backend");
            return;
        }
        self.set_status(format!(
            "Confirm restoration of {} pending control(s) in {}?",
            batch.pending, batch.session_id
        ));
        self.undo_confirmation = Some(batch);
        self.confirm_dialog.show();
        self.state = AppState::ConfirmingUndo;
    }

    fn handle_undo_confirmation(&mut self, choice: ConfirmChoice) -> FtuiCmd<Msg> {
        if !self.operation_is_idle() {
            return FtuiCmd::none();
        }
        if self.state != AppState::ConfirmingUndo {
            self.invalidate_undo_confirmation();
            self.set_status("Undo confirmation expired; review the batch again");
            return FtuiCmd::none();
        }
        let batch = self.undo_confirmation.take();
        self.confirm_dialog.hide();
        self.state = AppState::Undo;
        self.confirmed_undo = None;
        if choice == ConfirmChoice::No {
            self.set_status("Restoration cancelled; controls unchanged");
            return FtuiCmd::none();
        }
        let Some(batch) = batch.filter(|batch| self.selected_undo_batch() == Some(batch)) else {
            self.set_status("Undo selection changed; reload and confirm the batch again");
            return FtuiCmd::none();
        };
        if let Some(reason) = self.undo_block_reason(&batch) {
            self.set_status(format!("Restoration unavailable: {reason}"));
            return FtuiCmd::none();
        }
        let Some(ticket) = self.issue_operation_ticket() else {
            return FtuiCmd::none();
        };
        self.set_status(format!("Preparing restoration for {}...", batch.session_id));
        self.confirmed_undo = Some(ConfirmedUndo { ticket, batch });
        FtuiCmd::msg(Msg::RequestUndo { ticket })
    }

    fn request_undo(&mut self, ticket: u64) -> FtuiCmd<Msg> {
        if !self.operation_is_idle() {
            return FtuiCmd::none();
        }
        if self.state != AppState::Undo
            || !self.confirmed_undo.as_ref().is_some_and(|confirmed| {
                confirmed.ticket == ticket
                    && self.selected_undo_batch() == Some(&confirmed.batch)
                    && self.undo_block_reason(&confirmed.batch).is_none()
            })
        {
            self.set_status("Stale restoration request rejected; review and confirm the batch");
            return FtuiCmd::none();
        }
        let Some(confirmed) = self.confirmed_undo.take() else {
            return FtuiCmd::none();
        };
        let Some(restore) = self.undo_restore_op.clone() else {
            self.set_status("Restoration unavailable: no execution backend");
            return FtuiCmd::none();
        };
        self.operation = PendingOperation::RestoringUndo(ticket);
        self.undo_result = None;
        self.set_status(format!(
            "Restoring recorded controls in {}...",
            confirmed.batch.session_id
        ));
        FtuiCmd::sequence(vec![
            FtuiCmd::log(format!(
                "undo: restoring child batch {}",
                confirmed.batch.session_id
            )),
            FtuiCmd::task_named("restore-controls", move || Msg::UndoComplete {
                ticket,
                result: restore(confirmed.batch),
            }),
        ])
    }

    /// Set a status message.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
        self.needs_redraw = true;
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.status_message = None;
        self.needs_redraw = true;
    }

    /// Push a toast notification for transient user feedback.
    fn push_toast(&mut self, message: impl Into<String>, icon: ToastIcon, style: ToastStyle) {
        let dur = if self.reduce_motion { 8 } else { 4 };
        let toast = Toast::new(message)
            .icon(icon)
            .style_variant(style)
            .duration(Duration::from_secs(dur));
        self.notifications.notify(toast);
        self.needs_redraw = true;
    }

    /// Request a redraw.
    pub fn request_redraw(&mut self) {
        self.needs_redraw = true;
    }

    fn issue_operation_ticket(&mut self) -> Option<u64> {
        let Some(ticket) = self.last_operation_ticket.checked_add(1) else {
            self.set_status("Operation ticket limit reached; restart the TUI");
            return None;
        };
        self.last_operation_ticket = ticket;
        Some(ticket)
    }

    fn operation_is_idle(&mut self) -> bool {
        match self.operation {
            PendingOperation::Idle => true,
            PendingOperation::Refreshing(_) => {
                self.set_status("Refresh in progress; wait before selecting or executing");
                false
            }
            PendingOperation::Executing(_) => {
                self.set_status("Execution in progress; wait before refreshing or executing");
                false
            }
            PendingOperation::LoadingUndo(_) => {
                self.set_status("Loading saved controls; wait before another operation");
                false
            }
            PendingOperation::RestoringUndo(_) => {
                self.set_status("Restoration in progress; wait before another operation");
                false
            }
        }
    }

    fn selection_is_available(&mut self) -> bool {
        if !self.operation_is_idle() {
            return false;
        }
        if matches!(self.state, AppState::Confirming | AppState::ConfirmingUndo) {
            self.set_status("Finish or cancel the current confirmation before changing selection");
            return false;
        }
        if matches!(self.state, AppState::Undo | AppState::Pressure) {
            self.set_status("Close the inspection panel before selecting process actions");
            return false;
        }
        true
    }

    fn show_selection_status(&mut self) {
        let selected_count = self.process_table.selected_count();
        let spare_count = self.process_table.get_explicitly_spared().len();
        self.set_status(if spare_count > 0 {
            format!(
                "{} selected; {} spare decision(s) pending. Press e to confirm.",
                selected_count, spare_count
            )
        } else {
            format!("{} process(es) selected", selected_count)
        });
    }

    fn invalidate_selection(&mut self) {
        self.invalidate_undo_confirmation();
        self.confirmation_selection = None;
        self.confirmed_selection = None;
        self.confirm_dialog.cancel();
        self.process_table.deselect_all();
        if self.state == AppState::Confirming {
            self.state = AppState::Normal;
        }
    }

    /// Check if redraw is needed and clear the flag.
    pub fn take_redraw(&mut self) -> bool {
        let needed = self.needs_redraw;
        self.needs_redraw = false;
        needed
    }

    /// Update focus state on widgets.
    fn update_focus(&mut self) {
        self.search.focused = self.focus == FocusTarget::Search;
        self.process_table.focused = self.focus == FocusTarget::ProcessList;
    }

    /// Cycle focus to next widget.
    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            FocusTarget::Search => FocusTarget::ProcessList,
            FocusTarget::ProcessList => FocusTarget::Search,
        };
        self.update_focus();
    }

    fn toggle_detail_visibility(&mut self) {
        self.detail_visible = !self.detail_visible;
        if self.detail_visible {
            self.set_status("Detail pane opened");
        } else {
            self.set_status("Detail pane hidden");
        }
    }

    fn set_detail_view(&mut self, view: DetailView) {
        self.detail_view = view;
        self.detail_visible = true;
    }

    fn announce_accessible(&mut self, message: impl Into<String>) {
        if !self.accessible {
            return;
        }
        let message = message.into();
        tracing::info!(target: "a11y.announce", message = %message, "Accessibility announcement");
        self.set_status(message);
    }

    fn palette_action_label(action_id: &str) -> &str {
        match action_id {
            "action.execute" => "Execute selected",
            "action.refresh" => "Refresh processes",
            "action.undo" => "Undo recorded controls",
            "navigation.first" => "Go to first process",
            "navigation.last" => "Go to last process",
            "navigation.page_down" => "Page down",
            "navigation.page_up" => "Page up",
            "search.open" => "Enter search mode",
            "selection.recommended" => "Select recommended",
            "selection.all" => "Select all",
            "selection.none" => "Deselect all",
            "selection.invert" => "Invert selection",
            "view.toggle_detail" => "Toggle detail pane",
            "view.summary" => "Show summary detail",
            "view.genealogy" => "Show genealogy detail",
            "view.galaxy" => "Toggle galaxy brain detail",
            "view.goal" => "Toggle goal view",
            "view.pressure" => "Inspect pressure and workloads",
            "view.clear_unit" => "Clear workload filter",
            "view.help" => "Show keyboard shortcuts",
            "settings.theme.dark" => "Switch theme dark",
            "settings.theme.light" => "Switch theme light",
            "settings.theme.high_contrast" => "Switch theme high contrast",
            "settings.theme.no_color" => "Switch theme no color",
            _ => "Unknown command",
        }
    }

    fn execute_palette_action(&mut self, action_id: &str) -> FtuiCmd<Msg> {
        if self.state == AppState::ConfirmingUndo {
            self.set_status("Finish or cancel restoration confirmation first");
            return FtuiCmd::none();
        }
        let mut known = true;
        let cmd = match action_id {
            "action.execute" => {
                if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.show_undo_confirmation();
                } else {
                    self.show_execute_confirmation();
                }
                FtuiCmd::none()
            }
            "action.refresh" => self.handle_msg(Msg::RequestRefresh),
            "action.undo" => self.handle_msg(Msg::OpenUndo),
            "view.pressure" => self.handle_msg(Msg::OpenPressure),
            "view.clear_unit" => self.handle_msg(Msg::ClearPressureFilter),

            "navigation.first" => self.handle_msg(Msg::CursorHome),
            "navigation.last" => self.handle_msg(Msg::CursorEnd),
            "navigation.page_down" => self.handle_msg(Msg::PageDown),
            "navigation.page_up" => self.handle_msg(Msg::PageUp),
            "search.open" => {
                if matches!(
                    self.state,
                    AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
                ) {
                    return FtuiCmd::none();
                }
                self.state = AppState::Searching;
                self.focus = FocusTarget::Search;
                self.update_focus();
                FtuiCmd::none()
            }

            "selection.recommended" => self.handle_msg(Msg::SelectRecommended),
            "selection.all" => self.handle_msg(Msg::SelectAll),
            "selection.none" => self.handle_msg(Msg::DeselectAll),
            "selection.invert" => self.handle_msg(Msg::InvertSelection),

            "view.toggle_detail" => {
                self.toggle_detail_visibility();
                FtuiCmd::none()
            }
            "view.summary" => {
                self.set_detail_view(DetailView::Summary);
                FtuiCmd::none()
            }
            "view.genealogy" => {
                self.set_detail_view(DetailView::Genealogy);
                FtuiCmd::none()
            }
            "view.galaxy" => {
                if self.detail_view == DetailView::GalaxyBrain {
                    self.set_detail_view(DetailView::Summary);
                } else {
                    self.set_detail_view(DetailView::GalaxyBrain);
                }
                FtuiCmd::none()
            }
            "view.goal" => {
                if self.process_table.has_goal_order() {
                    self.process_table.toggle_view_mode();
                    self.set_status(format!(
                        "View mode: {}",
                        self.process_table.view_mode_label()
                    ));
                } else {
                    self.set_status("Goal view unavailable");
                }
                FtuiCmd::none()
            }
            "view.help" => {
                self.state = AppState::Help;
                FtuiCmd::none()
            }

            "settings.theme.dark" => {
                self.theme = Theme::dark();
                FtuiCmd::none()
            }
            "settings.theme.light" => {
                self.theme = Theme::light();
                FtuiCmd::none()
            }
            "settings.theme.high_contrast" => {
                self.theme = Theme::high_contrast();
                FtuiCmd::none()
            }
            "settings.theme.no_color" => {
                self.theme = Theme::no_color();
                FtuiCmd::none()
            }

            _ => {
                known = false;
                tracing::warn!(
                    target: "tui.command_palette",
                    action_id,
                    "Unknown command palette action"
                );
                self.set_status(format!("Unknown command: {}", action_id));
                FtuiCmd::none()
            }
        };
        if known {
            self.announce_accessible(format!(
                "Command executed: {}",
                Self::palette_action_label(action_id)
            ));
        }
        cmd
    }

    fn handle_command_palette_key(&mut self, key: FtuiKeyEvent) -> Option<FtuiCmd<Msg>> {
        let open_with_colon = self.state == AppState::Normal
            && !self.command_palette.is_visible()
            && key.code == FtuiKeyCode::Char(':')
            && !key.modifiers.contains(FtuiModifiers::CTRL);
        if open_with_colon {
            self.command_palette.open();
            self.announce_accessible(
                "Command palette opened. Type to search, Enter to run, Escape to close.",
            );
            return Some(FtuiCmd::none());
        }

        let open_with_ctrl_p = self.state == AppState::Normal
            && !self.command_palette.is_visible()
            && key.code == FtuiKeyCode::Char('p')
            && key.modifiers.contains(FtuiModifiers::CTRL);
        let was_visible = self.command_palette.is_visible();
        if !(was_visible || open_with_ctrl_p) {
            return None;
        }

        let start = Instant::now();
        let action = self.command_palette.handle_event(&FtuiEvent::Key(key));
        let elapsed = start.elapsed();
        if elapsed > self.command_palette_event_budget {
            tracing::warn!(
                target: "tui.command_palette",
                latency_ms = elapsed.as_millis(),
                budget_ms = self.command_palette_event_budget.as_millis(),
                "Command palette key handling exceeded soft latency budget"
            );
        }

        match action {
            Some(PaletteAction::Execute(id)) => Some(self.execute_palette_action(&id)),
            Some(PaletteAction::Dismiss) => {
                self.announce_accessible("Command palette closed.");
                Some(FtuiCmd::none())
            }
            None => {
                if was_visible || self.command_palette.is_visible() {
                    if !was_visible && self.command_palette.is_visible() {
                        self.announce_accessible(
                            "Command palette opened. Type to search, Enter to run, Escape to close.",
                        );
                    }
                    Some(FtuiCmd::none())
                } else {
                    None
                }
            }
        }
    }

    /// Apply the current search filter to the process table.
    fn apply_search_filter(&mut self) {
        let query = self.search.value().to_lowercase();
        self.process_table
            .set_filter(if query.is_empty() { None } else { Some(query) });
    }

    /// Show confirmation dialog for executing actions.
    fn show_execute_confirmation(&mut self) {
        if matches!(
            self.state,
            AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
        ) || !self.operation_is_idle()
        {
            return;
        }
        self.confirmed_selection = None;
        let selected_pids = self.process_table.get_selected();
        let explicitly_spared = self.process_table.get_explicitly_spared();
        let selected_count = selected_pids.len();
        let spare_count = explicitly_spared.len();
        if selected_count > 0 || spare_count > 0 {
            self.confirmation_selection = Some(SelectionSnapshot {
                pids: selected_pids,
                explicitly_selected: self.process_table.get_explicitly_selected(),
                explicitly_spared,
            });
            self.confirm_dialog.show();
            self.state = AppState::Confirming;
            self.set_status(if selected_count == 0 {
                format!("Confirm saving {} spare decision(s)?", spare_count)
            } else if spare_count > 0 {
                format!(
                    "Confirm action on {} process(es) and save {} spare decision(s)?",
                    selected_count, spare_count
                )
            } else {
                format!("Confirm action on {} process(es)?", selected_count)
            });
        } else {
            self.confirmation_selection = None;
            self.set_status("No processes selected");
        }
    }

    /// Handle confirmation dialog result.
    fn handle_confirmation(&mut self, choice: ConfirmChoice) -> FtuiCmd<Msg> {
        if matches!(
            self.state,
            AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
        ) {
            return FtuiCmd::none();
        }
        if !self.operation_is_idle() {
            return FtuiCmd::none();
        }
        if choice == ConfirmChoice::Yes && self.state != AppState::Confirming {
            self.confirmation_selection = None;
            self.set_status("Confirmation expired; select processes and confirm again");
            return FtuiCmd::none();
        }
        let selection = self.confirmation_selection.take();
        self.confirm_dialog.hide();
        self.state = AppState::Normal;
        match choice {
            ConfirmChoice::Yes => {
                let Some(selection) = selection.filter(|selection| {
                    !selection.pids.is_empty() || !selection.explicitly_spared.is_empty()
                }) else {
                    self.set_status("Confirmation expired; select processes and confirm again");
                    return FtuiCmd::none();
                };
                let Some(ticket) = self.issue_operation_ticket() else {
                    return FtuiCmd::none();
                };
                let count = selection.pids.len();
                self.confirmed_selection = Some(ConfirmedSelection { ticket, selection });
                self.set_status(if count == 0 {
                    "Preparing to save spare decisions...".to_string()
                } else {
                    format!("Preparing actions for {} process(es)...", count)
                });
                FtuiCmd::msg(Msg::RequestExecute { ticket })
            }
            ConfirmChoice::No => {
                self.confirmed_selection = None;
                self.set_status("Action cancelled");
                FtuiCmd::none()
            }
        }
    }

    /// Check if the application should quit.
    pub fn should_quit(&self) -> bool {
        self.state == AppState::Quitting
    }

    /// Handle a message from the ftui runtime while preserving existing state
    /// transitions from the legacy event handlers.
    fn handle_msg(&mut self, msg: Msg) -> FtuiCmd<Msg> {
        if matches!(
            self.state,
            AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
        ) && matches!(
            &msg,
            Msg::SearchInput(_)
                | Msg::SearchBackspace
                | Msg::SearchCommit
                | Msg::SearchCancel
                | Msg::SearchHistoryUp
                | Msg::SearchHistoryDown
        ) {
            return FtuiCmd::none();
        }
        match msg {
            Msg::KeyPressed(key) => self.handle_ftui_key_event(key),
            Msg::Resized { width, height } => {
                let from_breakpoint = self.layout_state.breakpoint();
                self.update_layout(width, height);
                tracing::debug!(
                    target: "tui.state_transition",
                    ?from_breakpoint,
                    to_breakpoint = ?self.layout_state.breakpoint(),
                    width,
                    height,
                    "Terminal resized"
                );
                FtuiCmd::none()
            }
            Msg::Tick => {
                let actions = self.notifications.tick(Duration::from_secs(5));
                if !actions.is_empty() {
                    self.needs_redraw = true;
                }
                FtuiCmd::none()
            }
            Msg::FocusChanged(gained) => {
                self.set_status(if gained {
                    "Terminal focus gained"
                } else {
                    "Terminal focus lost"
                });
                FtuiCmd::none()
            }
            Msg::PasteReceived { text, .. } => {
                if matches!(
                    self.state,
                    AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
                ) {
                    return FtuiCmd::none();
                }
                self.search.set_value(&text);
                self.state = AppState::Searching;
                self.focus = FocusTarget::Search;
                self.update_focus();
                FtuiCmd::none()
            }
            Msg::ClipboardReceived(content) => {
                self.search.set_value(&content);
                FtuiCmd::none()
            }
            Msg::Noop => FtuiCmd::none(),

            Msg::CursorUp => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(self.pressure_cursor.saturating_sub(1));
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(self.undo_cursor.saturating_sub(1));
                } else {
                    self.process_table.cursor_up();
                }
                FtuiCmd::none()
            }
            Msg::CursorDown => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(self.pressure_cursor.saturating_add(1));
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(self.undo_cursor.saturating_add(1));
                } else {
                    self.process_table.cursor_down();
                }
                FtuiCmd::none()
            }
            Msg::CursorHome => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(0);
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(0);
                } else {
                    self.process_table.cursor_home();
                }
                FtuiCmd::none()
            }
            Msg::CursorEnd => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(usize::MAX);
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(usize::MAX);
                } else {
                    self.process_table.cursor_end();
                }
                FtuiCmd::none()
            }
            Msg::PageUp | Msg::HalfPageUp => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(self.pressure_cursor.saturating_sub(5));
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(self.undo_cursor.saturating_sub(5));
                } else {
                    self.process_table
                        .page_up(self.process_table.last_visible_height);
                }
                FtuiCmd::none()
            }
            Msg::PageDown | Msg::HalfPageDown => {
                if self.state == AppState::Pressure {
                    self.move_pressure_cursor(self.pressure_cursor.saturating_add(5));
                } else if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    self.move_undo_cursor(self.undo_cursor.saturating_add(5));
                } else {
                    self.process_table
                        .page_down(self.process_table.last_visible_height);
                }
                FtuiCmd::none()
            }

            Msg::ToggleSelection => {
                if self.selection_is_available() {
                    self.process_table.toggle_selection();
                    self.show_selection_status();
                }
                FtuiCmd::none()
            }
            Msg::SelectRecommended => {
                if self.selection_is_available() {
                    self.process_table.select_recommended();
                    self.show_selection_status();
                }
                FtuiCmd::none()
            }
            Msg::SelectAll => {
                if self.selection_is_available() {
                    self.process_table.select_all();
                    self.show_selection_status();
                }
                FtuiCmd::none()
            }
            Msg::DeselectAll => {
                if self.selection_is_available() {
                    self.process_table.deselect_all();
                    self.show_selection_status();
                }
                FtuiCmd::none()
            }
            Msg::InvertSelection => {
                if self.selection_is_available() {
                    self.process_table.invert_selection();
                    self.show_selection_status();
                }
                FtuiCmd::none()
            }

            Msg::EnterSearchMode => {
                if matches!(
                    self.state,
                    AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
                ) {
                    return FtuiCmd::none();
                }
                self.state = AppState::Searching;
                self.focus = FocusTarget::Search;
                self.update_focus();
                FtuiCmd::none()
            }
            Msg::SearchInput(c) => {
                self.search.type_char(c);
                FtuiCmd::none()
            }
            Msg::SearchBackspace => {
                self.search.backspace();
                FtuiCmd::none()
            }
            Msg::SearchCommit => {
                self.search.commit();
                self.apply_search_filter();
                self.state = AppState::Normal;
                self.focus = FocusTarget::ProcessList;
                self.update_focus();
                FtuiCmd::none()
            }
            Msg::SearchCancel => {
                self.state = AppState::Normal;
                self.focus = FocusTarget::ProcessList;
                self.update_focus();
                FtuiCmd::none()
            }
            Msg::SearchHistoryUp => {
                self.search.history_prev();
                FtuiCmd::none()
            }
            Msg::SearchHistoryDown => {
                self.search.history_next();
                FtuiCmd::none()
            }

            Msg::ToggleDetail => {
                self.toggle_detail_visibility();
                FtuiCmd::none()
            }
            Msg::SetDetailView(view) => {
                self.set_detail_view(view);
                FtuiCmd::none()
            }
            Msg::ToggleGoalView => {
                if self.process_table.has_goal_order() {
                    self.process_table.toggle_view_mode();
                    self.set_status(format!(
                        "View mode: {}",
                        self.process_table.view_mode_label()
                    ));
                } else {
                    self.set_status("Goal view unavailable");
                }
                FtuiCmd::none()
            }
            Msg::ToggleHelp => {
                if matches!(
                    self.state,
                    AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
                ) {
                    return FtuiCmd::none();
                }
                self.state = if self.state == AppState::Help {
                    AppState::Normal
                } else {
                    AppState::Help
                };
                FtuiCmd::none()
            }

            Msg::OpenPressure => {
                if self.operation_is_idle() {
                    self.invalidate_selection();
                    self.state = AppState::Pressure;
                    self.set_status(
                        "Inspecting this scan's pressure and workloads; no processes selected",
                    );
                }
                FtuiCmd::none()
            }
            Msg::ClosePressure => {
                if self.state == AppState::Pressure && self.operation_is_idle() {
                    self.state = AppState::Normal;
                    self.set_status("Pressure panel closed");
                }
                FtuiCmd::none()
            }
            Msg::FilterPressureUnit => {
                self.filter_pressure_unit();
                FtuiCmd::none()
            }
            Msg::ClearPressureFilter => {
                self.clear_pressure_filter();
                FtuiCmd::none()
            }
            Msg::OpenUndo | Msg::RequestUndoRefresh => self.request_undo_refresh(),
            Msg::CloseUndo => {
                if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo)
                    && self.operation_is_idle()
                {
                    self.invalidate_undo_confirmation();
                    self.state = AppState::Normal;
                    self.set_status("Undo panel closed");
                }
                FtuiCmd::none()
            }
            Msg::ShowUndoConfirmation => {
                self.show_undo_confirmation();
                FtuiCmd::none()
            }
            Msg::ConfirmUndo => self.handle_undo_confirmation(ConfirmChoice::Yes),
            Msg::CancelUndo => self.handle_undo_confirmation(ConfirmChoice::No),
            Msg::RequestUndo { ticket } => self.request_undo(ticket),

            Msg::RequestExecute { ticket } => {
                if !self.operation_is_idle() {
                    return FtuiCmd::none();
                }
                if !self
                    .confirmed_selection
                    .as_ref()
                    .is_some_and(|selection| selection.ticket == ticket)
                {
                    self.set_status(
                        "Stale execution request rejected; confirm the current selection",
                    );
                    return FtuiCmd::none();
                }
                let Some(selection) = self.confirmed_selection.take() else {
                    return FtuiCmd::none();
                };
                let selected_pids = selection.selection.pids;
                let explicitly_selected = selection.selection.explicitly_selected;
                let explicitly_spared = selection.selection.explicitly_spared;
                let selected_count = selected_pids.len();
                let spare_count = explicitly_spared.len();
                self.operation = PendingOperation::Executing(ticket);
                tracing::info!(
                    target: "tui.user_input",
                    action = "execute_requested",
                    selected_count,
                    spare_count,
                    "Confirmed actions and feedback requested"
                );
                if let Some(execute) = self.execute_op.clone() {
                    self.set_status(if selected_count == 0 {
                        format!("Saving {} spare decision(s)...", spare_count)
                    } else {
                        format!("Executing actions on {} process(es)...", selected_count)
                    });
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log(format!(
                            "execute: starting (selected_count={}, spare_count={})",
                            selected_count, spare_count
                        )),
                        FtuiCmd::task_named("execute-selected", move || Msg::ExecutionComplete {
                            ticket,
                            result: execute(selected_pids, explicitly_selected, explicitly_spared),
                        }),
                    ])
                } else {
                    self.set_status(format!(
                        "Execution requested for {} process(es) (skeleton mode)",
                        selected_count
                    ));
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log(format!(
                            "execute: skeleton mode (selected_count={})",
                            selected_count
                        )),
                        FtuiCmd::task_named("execute-selected", move || Msg::ExecutionComplete {
                            ticket,
                            result: Ok(ExecutionOutcome {
                                mode: Some("skeleton".to_string()),
                                attempted: selected_count,
                                succeeded: 0,
                                failed: 0,
                            }),
                        }),
                    ])
                }
            }
            Msg::ConfirmExecute => self.handle_confirmation(ConfirmChoice::Yes),
            Msg::CancelExecute => self.handle_confirmation(ConfirmChoice::No),
            Msg::RequestRefresh => {
                if matches!(self.state, AppState::Undo | AppState::ConfirmingUndo) {
                    return self.request_undo_refresh();
                }
                if !self.operation_is_idle() {
                    return FtuiCmd::none();
                }
                self.invalidate_selection();
                self.process_table.set_member_filter(None);
                self.pressure_filter_label = None;
                if self.state == AppState::Pressure {
                    self.state = AppState::Normal;
                }
                let Some(ticket) = self.issue_operation_ticket() else {
                    return FtuiCmd::none();
                };
                self.operation = PendingOperation::Refreshing(ticket);
                tracing::info!(target: "tui.user_input", action = "refresh_requested", "Refresh requested");
                if let Some(refresh) = self.refresh_op.clone() {
                    self.set_status("Refreshing process list...");
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log("refresh: starting"),
                        FtuiCmd::task_named("refresh-processes", move || Msg::RefreshComplete {
                            ticket,
                            result: refresh(),
                        }),
                    ])
                } else {
                    self.set_status("Refreshing process list (skeleton mode)...");
                    let prior = RefreshOutcome {
                        rows: self.process_table.rows.clone(),
                        pressure: self.pressure.clone(),
                        goal_summary: self.goal_summary.clone(),
                        goal_selection: self.process_table.goal_selection().cloned(),
                    };
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log("refresh: skeleton mode"),
                        FtuiCmd::task_named("refresh-processes", move || Msg::RefreshComplete {
                            ticket,
                            result: Ok(prior),
                        }),
                    ])
                }
            }
            Msg::ExportEvidenceLedger => {
                self.set_status("Evidence ledger export is not wired yet");
                FtuiCmd::none()
            }

            Msg::ProcessesScanned(rows) => {
                if !self.operation_is_idle() {
                    return FtuiCmd::none();
                }
                self.replace_processes(RefreshOutcome {
                    rows,
                    ..RefreshOutcome::default()
                });
                self.set_status("Process list refreshed");
                FtuiCmd::none()
            }
            Msg::RefreshComplete {
                ticket,
                result: Ok(outcome),
            } => {
                if self.operation != PendingOperation::Refreshing(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                let count = outcome.rows.len();
                self.replace_processes(outcome);
                self.set_status(format!("Process list refreshed ({})", count));
                self.push_toast(
                    format!("Refreshed: {} processes", count),
                    ToastIcon::Success,
                    ToastStyle::Success,
                );
                FtuiCmd::log(format!("refresh: complete (rows={})", count))
            }
            Msg::RefreshComplete {
                ticket,
                result: Err(error),
            } => {
                if self.operation != PendingOperation::Refreshing(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                self.invalidate_selection();
                tracing::error!(target: "tui.async_complete", error = %error, "Refresh failed");
                self.set_status(format!("Refresh failed: {}", error));
                self.push_toast(
                    format!("Refresh failed: {}", error),
                    ToastIcon::Error,
                    ToastStyle::Error,
                );
                FtuiCmd::log(format!("refresh: failed ({})", error))
            }
            Msg::ExecutionComplete {
                ticket,
                result: Ok(outcome),
            } => {
                if self.operation != PendingOperation::Executing(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                self.invalidate_selection();
                self.undo_overview = None;
                let status = if let Some(mode) = outcome.mode.as_deref() {
                    match mode {
                        "dry_run" => format!(
                            "Plan saved (dry_run): {} action(s) (no execution)",
                            outcome.attempted
                        ),
                        "shadow" => format!(
                            "Plan saved (shadow): {} action(s) (no execution)",
                            outcome.attempted
                        ),
                        "feedback" => "Spare decisions saved for future scans".to_string(),
                        "feedback_dry_run" => {
                            "Spare feedback preview (dry_run): no decisions saved".to_string()
                        }
                        "feedback_shadow" => {
                            "Spare feedback preview (shadow): no decisions saved".to_string()
                        }
                        "skeleton" => "Execution not wired yet (skeleton mode)".to_string(),
                        other => format!("Execution finished ({})", other),
                    }
                } else {
                    format!(
                        "Execution complete: {} succeeded, {} failed ({} attempted)",
                        outcome.succeeded, outcome.failed, outcome.attempted
                    )
                };
                self.set_status(status.clone());
                let (icon, style) = if outcome.failed > 0 {
                    (ToastIcon::Warning, ToastStyle::Warning)
                } else {
                    (ToastIcon::Success, ToastStyle::Success)
                };
                self.push_toast(status.clone(), icon, style);
                FtuiCmd::log(format!("execute: {}", status))
            }
            Msg::ExecutionComplete {
                ticket,
                result: Err(error),
            } => {
                if self.operation != PendingOperation::Executing(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                self.invalidate_selection();
                self.undo_overview = None;
                tracing::error!(target: "tui.async_complete", error = %error, "Execution failed");
                self.set_status(format!("Execution failed: {}", error));
                self.push_toast(
                    format!("Execution failed: {}", error),
                    ToastIcon::Error,
                    ToastStyle::Error,
                );
                FtuiCmd::log(format!("execute: failed ({})", error))
            }
            Msg::UndoLoaded { ticket, result } => {
                if self.operation != PendingOperation::LoadingUndo(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                match result {
                    Ok(overview) => {
                        let count = overview.batches.len();
                        self.replace_undo_overview(overview, None);
                        self.set_status(format!(
                            "{} saved control batch(es); select one to inspect",
                            count
                        ));
                        FtuiCmd::log(format!("undo: inspected {} saved batches", count))
                    }
                    Err(error) => {
                        self.invalidate_undo_confirmation();
                        self.undo_error = Some(error.clone());
                        self.set_status(format!("Cannot inspect saved controls: {error}"));
                        FtuiCmd::log(format!("undo: inspection failed ({error})"))
                    }
                }
            }
            Msg::UndoComplete { ticket, result } => {
                if self.operation != PendingOperation::RestoringUndo(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                self.invalidate_selection();
                match result {
                    Ok(outcome) => {
                        self.replace_undo_overview(
                            outcome.overview.clone(),
                            Some(&outcome.session_id),
                        );
                        let status = if let Some(error) = &outcome.error {
                            format!(
                                "{} restored; {} pending. {}: {}",
                                outcome.restored, outcome.remaining, outcome.summary, error
                            )
                        } else {
                            format!(
                                "{} restored; {} pending. {}",
                                outcome.restored, outcome.remaining, outcome.summary
                            )
                        };
                        self.set_status(status.clone());
                        self.undo_result = Some(outcome);
                        FtuiCmd::log(format!("undo: {status}"))
                    }
                    Err(error) => {
                        // A callback error may follow a partial write. Never
                        // reuse the reviewed inventory or imply a rollback.
                        self.undo_error = Some(error.clone());
                        self.set_status(format!(
                            "Restoration stopped: {error}. Reload saved controls."
                        ));
                        FtuiCmd::log(format!("undo: restoration error ({error})"))
                    }
                }
            }
            Msg::LedgerExported(Ok(path)) => {
                self.set_status(format!("Evidence ledger exported to {}", path.display()));
                self.push_toast(
                    format!("Ledger exported to {}", path.display()),
                    ToastIcon::Success,
                    ToastStyle::Success,
                );
                FtuiCmd::none()
            }
            Msg::LedgerExported(Err(error)) => {
                self.set_status(format!("Ledger export failed: {}", error));
                self.push_toast(
                    format!("Export failed: {}", error),
                    ToastIcon::Error,
                    ToastStyle::Error,
                );
                FtuiCmd::none()
            }

            Msg::SwitchTheme(name) => {
                self.theme = match name.to_lowercase().as_str() {
                    "light" => Theme::light(),
                    "high_contrast" | "high-contrast" | "hc" => Theme::high_contrast(),
                    "no_color" | "no-color" => Theme::no_color(),
                    _ => Theme::dark(),
                };
                FtuiCmd::none()
            }

            Msg::FocusNext | Msg::FocusPrev => {
                self.cycle_focus();
                FtuiCmd::none()
            }

            Msg::Quit => {
                if matches!(self.operation, PendingOperation::RestoringUndo(_)) {
                    self.set_status("Restoration is still finishing; wait before quitting");
                    return FtuiCmd::none();
                }
                self.state = AppState::Quitting;
                FtuiCmd::quit()
            }
        }
    }

    fn handle_ftui_key_event(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if !matches!(key.kind, FtuiKeyEventKind::Press | FtuiKeyEventKind::Repeat) {
            return FtuiCmd::none();
        }

        if self.state != AppState::ConfirmingUndo {
            if let Some(cmd) = self.handle_command_palette_key(key) {
                return cmd;
            }
        }

        tracing::debug!(
            target: "tui.user_input",
            key_code = ?key.code,
            modifiers = ?key.modifiers,
            app_state = ?self.state,
            focus = ?self.focus,
            "Key event received"
        );

        match self.state {
            AppState::Normal => self.handle_ftui_normal_key(key),
            AppState::Searching => self.handle_ftui_search_key(key),
            AppState::Confirming => self.handle_ftui_confirm_key(key),
            AppState::Help => self.handle_ftui_help_key(key),
            AppState::Pressure => self.handle_ftui_pressure_key(key),
            AppState::Undo => self.handle_ftui_undo_key(key),
            AppState::ConfirmingUndo => self.handle_ftui_confirm_key(key),
            AppState::Quitting => FtuiCmd::quit(),
        }
    }

    fn handle_ftui_normal_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if matches!(key.code, FtuiKeyCode::Escape) || self.key_bindings.is_quit(&key) {
            tracing::info!(target: "tui.user_input", action = "quit", "Quit requested");
            self.state = AppState::Quitting;
            return FtuiCmd::quit();
        }
        if self.key_bindings.is_help(&key) {
            tracing::debug!(target: "tui.user_input", action = "toggle_help", "Help requested");
            self.state = AppState::Help;
            return FtuiCmd::none();
        }
        if self.key_bindings.is_search(&key) {
            tracing::debug!(target: "tui.user_input", action = "enter_search", "Search mode");
            self.state = AppState::Searching;
            self.focus = FocusTarget::Search;
            self.update_focus();
            return FtuiCmd::none();
        }
        if self.key_bindings.is_next(&key) {
            tracing::trace!(target: "tui.user_input", action = "cursor_down");
            self.process_table.cursor_down();
            return FtuiCmd::none();
        }
        if self.key_bindings.is_prev(&key) {
            tracing::trace!(target: "tui.user_input", action = "cursor_up");
            self.process_table.cursor_up();
            return FtuiCmd::none();
        }
        if self.key_bindings.is_toggle(&key) {
            tracing::trace!(target: "tui.user_input", action = "toggle_selection");
            return self.handle_msg(Msg::ToggleSelection);
        }
        if self.key_bindings.is_execute(&key) {
            tracing::info!(target: "tui.user_input", action = "request_execute", selected = self.process_table.selected_count(), "Execute requested");
            self.show_execute_confirmation();
            return FtuiCmd::none();
        }
        if self.key_bindings.is_next_tab(&key) {
            self.cycle_focus();
            return FtuiCmd::none();
        }

        match key.code {
            FtuiKeyCode::Home => self.process_table.cursor_home(),
            FtuiKeyCode::End => self.process_table.cursor_end(),
            FtuiKeyCode::PageDown => self
                .process_table
                .page_down(self.process_table.last_visible_height),
            FtuiKeyCode::PageUp => self
                .process_table
                .page_up(self.process_table.last_visible_height),
            FtuiKeyCode::Char('d') if key.modifiers.contains(FtuiModifiers::CTRL) => self
                .process_table
                .page_down(self.process_table.last_visible_height),
            FtuiKeyCode::Char('u') if key.modifiers.contains(FtuiModifiers::CTRL) => self
                .process_table
                .page_up(self.process_table.last_visible_height),
            FtuiKeyCode::Char('a') => return self.handle_msg(Msg::SelectRecommended),
            FtuiKeyCode::Char('A') => return self.handle_msg(Msg::SelectAll),
            FtuiKeyCode::Char('u') => return self.handle_msg(Msg::DeselectAll),
            FtuiKeyCode::Char('x') => return self.handle_msg(Msg::InvertSelection),
            FtuiKeyCode::Enter => self.toggle_detail_visibility(),
            FtuiKeyCode::Char('r') => return self.handle_msg(Msg::RequestRefresh),
            FtuiKeyCode::Char('U') => return self.handle_msg(Msg::OpenUndo),
            FtuiKeyCode::Char('P') => return self.handle_msg(Msg::OpenPressure),
            FtuiKeyCode::Char('c') => return self.handle_msg(Msg::ClearPressureFilter),
            FtuiKeyCode::Char('s') => self.set_detail_view(DetailView::Summary),
            FtuiKeyCode::Char('t') => self.set_detail_view(DetailView::Genealogy),
            FtuiKeyCode::Char('g') => {
                if self.detail_view == DetailView::GalaxyBrain {
                    self.set_detail_view(DetailView::Summary);
                } else {
                    self.set_detail_view(DetailView::GalaxyBrain);
                }
            }
            FtuiKeyCode::Char('v') => {
                if self.process_table.has_goal_order() {
                    self.process_table.toggle_view_mode();
                    self.set_status(format!(
                        "View mode: {}",
                        self.process_table.view_mode_label()
                    ));
                } else {
                    self.set_status("Goal view unavailable");
                }
            }
            _ => {}
        }
        FtuiCmd::none()
    }

    fn handle_ftui_search_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        match key.code {
            FtuiKeyCode::Escape => {
                self.state = AppState::Normal;
                self.focus = FocusTarget::ProcessList;
                self.update_focus();
            }
            FtuiKeyCode::Enter => {
                self.search.commit();
                self.apply_search_filter();
                self.state = AppState::Normal;
                self.focus = FocusTarget::ProcessList;
                self.update_focus();
            }
            FtuiKeyCode::Up => self.search.history_prev(),
            FtuiKeyCode::Down => self.search.history_next(),
            FtuiKeyCode::Backspace => self.search.backspace(),
            FtuiKeyCode::Char(c) => self.search.type_char(c),
            _ => {}
        }
        FtuiCmd::none()
    }

    fn handle_ftui_confirm_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        match key.code {
            FtuiKeyCode::Left | FtuiKeyCode::Char('h') => self.confirm_dialog.select_left(),
            FtuiKeyCode::Right | FtuiKeyCode::Char('l') => self.confirm_dialog.select_right(),
            FtuiKeyCode::Tab => self.confirm_dialog.toggle(),
            FtuiKeyCode::Enter => {
                let choice = self.confirm_dialog.confirm();
                return if self.state == AppState::ConfirmingUndo {
                    self.handle_undo_confirmation(choice)
                } else {
                    self.handle_confirmation(choice)
                };
            }
            FtuiKeyCode::Escape => {
                return if self.state == AppState::ConfirmingUndo {
                    self.handle_undo_confirmation(ConfirmChoice::No)
                } else {
                    self.handle_confirmation(ConfirmChoice::No)
                };
            }
            _ => {}
        }
        FtuiCmd::none()
    }

    fn handle_ftui_undo_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if matches!(key.code, FtuiKeyCode::Escape | FtuiKeyCode::Char('U'))
            || self.key_bindings.is_quit(&key)
        {
            return self.handle_msg(Msg::CloseUndo);
        }
        if self.key_bindings.is_next(&key) {
            return self.handle_msg(Msg::CursorDown);
        }
        if self.key_bindings.is_prev(&key) {
            return self.handle_msg(Msg::CursorUp);
        }
        match key.code {
            FtuiKeyCode::Home => self.handle_msg(Msg::CursorHome),
            FtuiKeyCode::End => self.handle_msg(Msg::CursorEnd),
            FtuiKeyCode::PageUp => self.handle_msg(Msg::PageUp),
            FtuiKeyCode::PageDown => self.handle_msg(Msg::PageDown),
            FtuiKeyCode::Char('r') => self.handle_msg(Msg::RequestUndoRefresh),
            FtuiKeyCode::Char('[') => {
                self.scroll_undo_details(false);
                FtuiCmd::none()
            }
            FtuiKeyCode::Char(']') => {
                self.scroll_undo_details(true);
                FtuiCmd::none()
            }
            FtuiKeyCode::Enter | FtuiKeyCode::Char('e') => {
                self.handle_msg(Msg::ShowUndoConfirmation)
            }
            _ => FtuiCmd::none(),
        }
    }

    fn handle_ftui_pressure_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if matches!(key.code, FtuiKeyCode::Escape | FtuiKeyCode::Char('P'))
            || self.key_bindings.is_quit(&key)
        {
            return self.handle_msg(Msg::ClosePressure);
        }
        if self.key_bindings.is_next(&key) {
            return self.handle_msg(Msg::CursorDown);
        }
        if self.key_bindings.is_prev(&key) {
            return self.handle_msg(Msg::CursorUp);
        }
        match key.code {
            FtuiKeyCode::Home => self.handle_msg(Msg::CursorHome),
            FtuiKeyCode::End => self.handle_msg(Msg::CursorEnd),
            FtuiKeyCode::PageUp => self.handle_msg(Msg::PageUp),
            FtuiKeyCode::PageDown => self.handle_msg(Msg::PageDown),
            FtuiKeyCode::Enter => self.handle_msg(Msg::FilterPressureUnit),
            FtuiKeyCode::Char('c') => self.handle_msg(Msg::ClearPressureFilter),
            FtuiKeyCode::Char('r') => self.handle_msg(Msg::RequestRefresh),
            FtuiKeyCode::Char('[') => {
                self.scroll_pressure_details(false);
                FtuiCmd::none()
            }
            FtuiKeyCode::Char(']') => {
                self.scroll_pressure_details(true);
                FtuiCmd::none()
            }
            _ => FtuiCmd::none(),
        }
    }

    fn handle_ftui_help_key(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if matches!(
            key.code,
            FtuiKeyCode::Escape | FtuiKeyCode::Char('q') | FtuiKeyCode::Char('?')
        ) {
            self.state = AppState::Normal;
            tracing::debug!(
                target: "tui.state_transition",
                to_state = ?self.state,
                "Leaving help mode"
            );
        }
        FtuiCmd::none()
    }

    fn pressure_detail_lines(&self, width: u16) -> Vec<FtuiLine> {
        let style = self.theme.stylesheet().get_or_default("border.normal");
        let details = if let Some(unit) = self.selected_pressure_unit() {
            let mut lines = vec![unit.summary.clone()];
            if unit.member_pids.is_empty() {
                lines.push(
                    "No candidate rows from this workload are displayed; filtering is unavailable."
                        .to_string(),
                );
            }
            lines.extend(unit.details.iter().cloned());
            lines
        } else if let Some(overview) = &self.pressure {
            overview.details.clone()
        } else {
            vec!["Host pressure observations are unavailable for this snapshot. Refresh to collect a new scan.".to_string()]
        };
        details
            .into_iter()
            .flat_map(|detail| {
                let text: String = detail
                    .chars()
                    .map(|ch| if ch.is_control() { ' ' } else { ch })
                    .collect();
                FtuiLine::from_spans([FtuiSpan::styled(text, style)])
                    .wrap(width as usize, WrapMode::WordChar)
            })
            .collect()
    }

    fn render_pressure_panel(&self, area: Rect, frame: &mut FtuiFrame) {
        let sheet = self.theme.stylesheet();
        let normal = sheet.get_or_default("border.normal");
        let heading = sheet.get_or_default("table.header");
        let selected = sheet.get_or_default("table.selected");
        let block = super::widgets::panel_block()
            .title(" Pressure and responsible workloads ")
            .border_style(normal);
        let inner = block.inner(area);
        block.render(area, frame);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let clean = |text: &str| -> String {
            text.chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect()
        };
        let line = |text: String, style| FtuiLine::from_spans([FtuiSpan::styled(text, style)]);
        let mut lines = vec![line(
            if inner.width >= 76 {
                "j/k browse  [/] details  Enter filter  c clear filter  r refresh  P/Esc close"
                    .to_string()
            } else {
                "j/k browse | [/] details | Enter filter | c clear | Esc close".to_string()
            },
            heading,
        )];
        let units = self
            .pressure
            .as_ref()
            .map_or(&[][..], |overview| overview.units.as_slice());
        let entries = units.len().saturating_add(1);
        let visible = ((inner.height as usize).saturating_sub(5) / 3)
            .clamp(1, 7)
            .min(entries);
        let start = self
            .pressure_cursor
            .saturating_sub(visible.saturating_sub(1));
        let end = start.saturating_add(visible).min(entries);
        lines.push(line(
            format!("Host and workloads {}-{} of {}", start + 1, end, entries),
            heading,
        ));
        for index in start..end {
            let label = if index == 0 {
                "Host pressure".to_string()
            } else {
                let unit = &units[index - 1];
                format!(
                    "{} ({} candidate rows)",
                    clean(&unit.label),
                    unit.member_pids.len()
                )
            };
            lines.push(line(
                format!(
                    "{} {}",
                    if index == self.pressure_cursor {
                        ">"
                    } else {
                        " "
                    },
                    label
                ),
                if index == self.pressure_cursor {
                    selected
                } else {
                    normal
                },
            ));
        }
        let title = self
            .selected_pressure_unit()
            .map_or("Host pressure", |unit| unit.label.as_str());
        lines.push(line(format!("Details: {}", clean(title)), heading));
        let details = self.pressure_detail_lines(inner.width);
        let offset = self
            .pressure_detail_offset
            .min(details.len().saturating_sub(1));
        let shown = (inner.height as usize).saturating_sub(lines.len() + 1);
        lines.push(line(
            format!(
                "Lines {}-{} of {}  ([/] scroll)",
                usize::from(!details.is_empty()) + offset,
                offset.saturating_add(shown).min(details.len()),
                details.len()
            ),
            heading,
        ));
        lines.extend(details.into_iter().skip(offset).take(shown));
        let text: FtuiText = lines.into_iter().collect();
        FtuiParagraph::new(text).render(inner, frame);
    }

    fn undo_detail_lines(&self, width: u16) -> Vec<FtuiLine> {
        let normal = self.theme.stylesheet().get_or_default("border.normal");
        let warning = self.theme.class("status.warning");
        let mut details = Vec::new();
        if let Some(batch) = self.selected_undo_batch() {
            if let Some(reason) = self.undo_block_reason(batch) {
                details.push((format!("Restoration unavailable: {reason}"), warning));
            }
            details.extend(batch.details.iter().cloned().map(|detail| (detail, normal)));
        }
        if let Some(error) = &self.undo_error {
            details.push((format!("Inspection/restoration error: {error}"), warning));
        }
        if let Some(overview) = &self.undo_overview {
            details.extend(overview.notes.iter().cloned().map(|note| (note, warning)));
        }
        details
            .into_iter()
            .flat_map(|(detail, style)| {
                let text: String = detail
                    .chars()
                    .map(|ch| if ch.is_control() { ' ' } else { ch })
                    .collect();
                FtuiLine::from_spans([FtuiSpan::styled(text, style)])
                    .wrap(width as usize, WrapMode::WordChar)
            })
            .collect()
    }

    fn render_undo_panel(&self, area: Rect, frame: &mut FtuiFrame) {
        let sheet = self.theme.stylesheet();
        let block = super::widgets::panel_block()
            .title(" Undo recorded controls ")
            .border_style(sheet.get_or_default("border.normal"));
        let inner = block.inner(area);
        block.render(area, frame);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let normal = sheet.get_or_default("border.normal");
        let heading = sheet.get_or_default("table.header");
        let selected = sheet.get_or_default("table.selected");
        let warning = self.theme.class("status.warning");
        let clean = |text: &str| -> String {
            text.chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect()
        };
        let line = |text: String, style| FtuiLine::from_spans([FtuiSpan::styled(text, style)]);
        let mut lines = vec![line(
            if inner.width >= 76 {
                "j/k batch  [/] details  Enter/e restore  r reload  U/Esc/q close".to_string()
            } else {
                "j/k batch | [/] details | Enter restore | Esc close".to_string()
            },
            heading,
        )];
        if let Some(reason) = self
            .undo_overview
            .as_ref()
            .and_then(|overview| overview.read_only_reason.as_ref())
        {
            lines.push(line(format!("Read only: {}", clean(reason)), warning));
        }
        if let Some(error) = &self.undo_error {
            lines.push(line(
                format!("Cannot use saved controls: {}", clean(error)),
                warning,
            ));
        }
        if let Some(outcome) = &self.undo_result {
            lines.push(line(
                format!(
                    "{} restored; {} pending. {}",
                    outcome.restored,
                    outcome.remaining,
                    clean(&outcome.summary)
                ),
                if outcome.error.is_some() {
                    warning
                } else {
                    heading
                },
            ));
            if let Some(error) = &outcome.error {
                lines.push(line(
                    format!("Restoration stopped: {}", clean(error)),
                    warning,
                ));
            }
        }
        match self.operation {
            PendingOperation::LoadingUndo(_) => lines.push(line(
                "Loading persisted control batches...".to_string(),
                heading,
            )),
            PendingOperation::RestoringUndo(_) => lines.push(line(
                "Restoring the confirmed batch; waiting for persisted results...".to_string(),
                heading,
            )),
            _ => {}
        }
        let batches = self
            .undo_overview
            .as_ref()
            .map_or(&[][..], |overview| overview.batches.as_slice());
        if batches.is_empty() {
            lines.push(FtuiLine::default());
            lines.push(line(
                if self.undo_overview.is_some() {
                    "No durable control batches recorded in this TUI session.".to_string()
                } else {
                    "Saved controls will appear after inspection completes.".to_string()
                },
                normal,
            ));
            lines.push(line(
                "Only recorded reversible controls can be restored here.".to_string(),
                normal,
            ));
        } else {
            let available = (inner.height as usize).saturating_sub(lines.len());
            let visible = (available / 3).clamp(1, 8).min(batches.len());
            let start = self.undo_cursor.saturating_sub(visible.saturating_sub(1));
            let end = (start + visible).min(batches.len());
            lines.push(line(
                format!("Saved batches {}-{} of {}", start + 1, end, batches.len()),
                heading,
            ));
            for (index, batch) in batches.iter().enumerate().take(end).skip(start) {
                let state = if batch.blocked_reason.is_some() {
                    "unavailable".to_string()
                } else if batch.pending > 0 {
                    format!("{} pending", batch.pending)
                } else if batch.settled > 0 {
                    "settled".to_string()
                } else if batch.unsupported > 0 {
                    "unsupported".to_string()
                } else {
                    "no receipts".to_string()
                };
                lines.push(line(
                    format!(
                        "{} {}  {}",
                        if index == self.undo_cursor { ">" } else { " " },
                        clean(&batch.session_id),
                        state
                    ),
                    if index == self.undo_cursor {
                        selected
                    } else {
                        normal
                    },
                ));
            }
            if let Some(batch) = self.selected_undo_batch() {
                lines.push(FtuiLine::default());
                lines.push(line(
                    format!("Selected: {}", clean(&batch.session_id)),
                    heading,
                ));
                lines.push(line(
                    format!(
                        "Pending {} | Settled {} | Unsupported {} | Unrecorded {}",
                        batch.pending, batch.settled, batch.unsupported, batch.unrecorded
                    ),
                    normal,
                ));
                if !batch.created_at.is_empty() {
                    lines.push(line(
                        format!("Created: {}", clean(&batch.created_at)),
                        normal,
                    ));
                }
                let details = self.undo_detail_lines(inner.width);
                if !details.is_empty() {
                    let offset = self.undo_detail_offset.min(details.len().saturating_sub(1));
                    let shown = (inner.height as usize).saturating_sub(lines.len() + 1);
                    let end = offset.saturating_add(shown).min(details.len());
                    lines.push(line(
                        format!(
                            "Details {}-{} of {}  ([/] scroll)",
                            offset + 1,
                            end,
                            details.len()
                        ),
                        heading,
                    ));
                    lines.extend(details.into_iter().skip(offset).take(shown));
                }
            }
        }
        if batches.is_empty() {
            if let Some(overview) = &self.undo_overview {
                for note in &overview.notes {
                    lines.push(line(clean(note), warning));
                }
            }
        }
        let text: FtuiText = lines.into_iter().collect();
        FtuiParagraph::new(text).render(inner, frame);
    }
}

impl FtuiModel for App {
    type Message = Msg;

    fn init(&mut self) -> FtuiCmd<Self::Message> {
        tracing::info!(
            target: "tui.startup",
            terminal_size = ?self.layout_state.size(),
            theme = ?self.theme.mode,
            "TUI model initialized"
        );
        FtuiCmd::none()
    }

    fn update(&mut self, msg: Self::Message) -> FtuiCmd<Self::Message> {
        self.handle_msg(msg)
    }

    fn view(&self, frame: &mut FtuiFrame) {
        let full_area = Rect::new(0, 0, frame.width(), frame.height());
        let layout = ResponsiveLayout::new(full_area);

        // Degrade gracefully for tiny terminals
        if layout.is_too_small() {
            draw_ftui_text(frame, 0, 0, "Terminal too small (min 40x10)");
            return;
        }

        if matches!(
            self.state,
            AppState::Undo | AppState::ConfirmingUndo | AppState::Pressure
        ) {
            let panel_area = Rect::new(
                full_area.x,
                full_area.y,
                full_area.width,
                full_area.height.saturating_sub(1),
            );
            if self.state == AppState::Pressure {
                self.render_pressure_panel(panel_area, frame);
            } else {
                self.render_undo_panel(panel_area, frame);
            }
            let mut status = StatusBar::new().theme(&self.theme);
            if let Some(message) = &self.status_message {
                status = status.message(message);
            }
            status.render_ftui(
                Rect::new(0, full_area.height.saturating_sub(1), full_area.width, 1),
                frame,
            );
            if self.state == AppState::ConfirmingUndo {
                if let Some(batch) = &self.undo_confirmation {
                    let message = format!(
                        "Restore original values for {} pending control(s) in {}?\n\nAlready settled and unsupported records will not be replayed. Restoration stops on the first refusal or failure.",
                        batch.pending, batch.session_id
                    );
                    ConfirmDialog::new()
                        .title("Restore Recorded Controls")
                        .message(&message)
                        .labels("Restore controls", "Cancel")
                        .theme(&self.theme)
                        .render_view(layout.popup_area(80, 55), frame, &self.confirm_dialog);
                }
            }
            if self.command_palette.is_visible() {
                self.command_palette.render(full_area, frame);
            }
            return;
        }

        // Pressure and goal observations always belong to the same displayed scan.
        let mut header_lines: Vec<String> = self
            .pressure
            .as_ref()
            .into_iter()
            .flat_map(|overview| overview.header.iter().take(2).cloned())
            .collect();
        if let Some(label) = &self.pressure_filter_label {
            header_lines.push(format!("Workload filter: {label}  [c clear | P inspect]"));
        }
        if let Some(lines) = &self.goal_summary {
            header_lines.extend(lines.iter().take(4).cloned());
        }
        let areas = layout.main_areas_with_header(header_lines.len() as u16);

        // ── Header (pressure, active workload, and goal summary) ────────
        if let Some(header_area) = areas.header {
            for (i, line) in header_lines.iter().enumerate() {
                if i as u16 >= header_area.height {
                    break;
                }
                let line: String = line
                    .chars()
                    .map(|ch| if ch.is_control() { ' ' } else { ch })
                    .collect();
                draw_ftui_text(frame, header_area.x, header_area.y + i as u16, &line);
            }
        }

        // ── Search input ───────────────────────────────────────────────
        SearchInput::new()
            .theme(&self.theme)
            .render_view(areas.search, frame, &self.search);

        // ── Process table ──────────────────────────────────────────────
        ProcessTable::new()
            .theme(&self.theme)
            .show_selection(true)
            .render_view(areas.list, frame, &self.process_table);

        // ── Detail pane (when visible and layout provides the area) ────
        if self.detail_visible {
            if let Some(detail_area) = areas.detail {
                let current_row = self.process_table.current_row();
                let selected =
                    current_row.is_some_and(|row| self.process_table.selected.contains(&row.pid));
                ProcessDetail::new()
                    .theme(&self.theme)
                    .row(current_row, selected)
                    .view(self.detail_view)
                    .render_ftui(detail_area, frame);
            }
        }

        // ── Aux panel (Wide breakpoint only) ───────────────────────────
        if let Some(aux_area) = areas.aux {
            let current_row = self.process_table.current_row();
            AuxPanel::new()
                .theme(&self.theme)
                .rows(&self.process_table.rows)
                .selected_count(self.process_table.selected_count())
                .current_row(current_row)
                .render_ftui(aux_area, frame);
        }

        // ── Status bar ─────────────────────────────────────────────────
        let status_mode = match self.state {
            AppState::Normal | AppState::Quitting | AppState::Undo | AppState::Pressure => {
                StatusMode::Normal
            }
            AppState::Searching => StatusMode::Searching,
            AppState::Confirming | AppState::ConfirmingUndo => StatusMode::Confirming,
            AppState::Help => StatusMode::Help,
        };
        let mut status_bar = StatusBar::new()
            .theme(&self.theme)
            .mode(status_mode)
            .selected_count(self.process_table.selected_count());
        if let Some(ref filter) = self.process_table.filter {
            status_bar = status_bar.filter(filter);
        }
        if let Some(ref msg) = self.status_message {
            status_bar = status_bar.message(msg);
        }
        status_bar.render_ftui(areas.status, frame);

        // ── Overlays (rendered on top of everything) ───────────────────

        // Help overlay (full-screen)
        if self.state == AppState::Help {
            HelpOverlay::new()
                .theme(&self.theme)
                .breakpoint(layout.breakpoint())
                .render_ftui(full_area, frame);
        }

        // Confirmation dialog (centered popup)
        if self.state == AppState::Confirming {
            let popup_area = layout.popup_area(50, 30);
            let selected_count = self
                .confirmation_selection
                .as_ref()
                .map_or(0, |selection| selection.pids.len());
            let spare_count = self
                .confirmation_selection
                .as_ref()
                .map_or(0, |selection| selection.explicitly_spared.len());
            let (title, msg, confirm_label) = if selected_count == 0 {
                (
                    "Save Feedback",
                    format!(
                        "Remember your spare decisions for {} process(es) in future scans?",
                        spare_count
                    ),
                    "Save feedback",
                )
            } else if spare_count > 0 {
                (
                    "Confirm Execution",
                    format!(
                        "Execute actions on {} selected process(es) and remember {} spare decision(s)?",
                        selected_count, spare_count
                    ),
                    "Yes",
                )
            } else {
                (
                    "Confirm Execution",
                    format!(
                        "Execute actions on {} selected process(es)?",
                        selected_count
                    ),
                    "Yes",
                )
            };
            ConfirmDialog::new()
                .theme(&self.theme)
                .title(title)
                .message(&msg)
                .labels(confirm_label, "No")
                .render_view(popup_area, frame, &self.confirm_dialog);
        }

        // Toast notifications (top-right overlay)
        if !self.notifications.is_empty() {
            NotificationStack::new(&self.notifications).render(full_area, frame);
        }

        // Command palette (top-most overlay)
        if self.command_palette.is_visible() {
            self.command_palette.render(full_area, frame);
        }
    }

    fn subscriptions(&self) -> Vec<Box<dyn Subscription<Self::Message>>> {
        if self.reduce_motion {
            // Skip periodic tick when motion is reduced; toasts use longer
            // static durations and no stagger animation.
            vec![]
        } else {
            vec![Box::new(Every::with_id(
                0x5054_5449_434B,
                Duration::from_secs(5),
                || Msg::Tick,
            ))]
        }
    }
}

fn draw_ftui_text(frame: &mut FtuiFrame, x: u16, y: u16, text: &str) {
    if y >= frame.height() || x >= frame.width() {
        return;
    }

    let mut col = x;
    let max_col = frame.width();
    for ch in text.chars() {
        if col >= max_col {
            break;
        }
        frame.buffer.set(col, y, FtuiCell::from_char(ch));
        col = col.saturating_add(1);
    }
}

/// Run the TUI using the ftui runtime.
///
/// This is the preferred entry point for the TUI. It delegates terminal setup,
/// event polling, and teardown entirely to ftui's `Program` runtime.
///
/// The `App` model implements `ftui::Model`, so it drives the Elm-style
/// init → update → view loop. Callbacks for refresh/execute are wired
/// through `Cmd::task` closures (see bd-2b3l for data wiring).
pub fn run_ftui(app: App, config: ProgramConfig) -> TuiResult<()> {
    let mut program =
        Program::with_config(app, config).map_err(|e| TuiError::TerminalInit(e.to_string()))?;
    program
        .run()
        .map_err(|e| TuiError::TerminalInit(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_new() {
        let app = App::new();
        assert_eq!(app.state, AppState::Normal);
        assert!(!app.should_quit());
    }

    #[test]
    fn test_app_state_transitions() {
        let mut app = App::new();

        app.state = AppState::Searching;
        assert_eq!(app.state, AppState::Searching);

        app.state = AppState::Help;
        assert_eq!(app.state, AppState::Help);

        app.state = AppState::Quitting;
        assert!(app.should_quit());
    }

    #[test]
    fn test_status_message() {
        let mut app = App::new();

        app.set_status("Test message");
        assert_eq!(app.status_message, Some("Test message".to_string()));

        app.clear_status();
        assert!(app.status_message.is_none());
    }

    #[test]
    fn test_redraw_flag() {
        let mut app = App::new();

        assert!(app.take_redraw()); // Initially true
        assert!(!app.take_redraw()); // Now false

        app.request_redraw();
        assert!(app.take_redraw());
    }

    #[test]
    fn test_focus_cycling() {
        let mut app = App::new();

        assert_eq!(app.focus, FocusTarget::ProcessList);

        app.cycle_focus();
        assert_eq!(app.focus, FocusTarget::Search);

        app.cycle_focus();
        assert_eq!(app.focus, FocusTarget::ProcessList);
    }

    #[test]
    fn test_ftui_model_quit_message() {
        let mut app = App::new();
        let cmd = <App as FtuiModel>::update(&mut app, Msg::Quit);
        assert!(matches!(cmd, FtuiCmd::Quit));
        assert!(app.should_quit());
    }

    #[test]
    fn test_ftui_model_tick_subscription_registered() {
        let app = App::new();
        let subs = <App as FtuiModel>::subscriptions(&app);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id(), 0x5054_5449_434B);
    }

    #[test]
    fn test_toggle_help_msg() {
        let mut app = App::new();
        assert_eq!(app.state, AppState::Normal);

        <App as FtuiModel>::update(&mut app, Msg::ToggleHelp);
        assert_eq!(app.state, AppState::Help);

        <App as FtuiModel>::update(&mut app, Msg::ToggleHelp);
        assert_eq!(app.state, AppState::Normal);
    }

    #[test]
    fn test_enter_search_mode_msg() {
        let mut app = App::new();
        <App as FtuiModel>::update(&mut app, Msg::EnterSearchMode);
        assert_eq!(app.state, AppState::Searching);
        assert!(app.search.focused);
        assert!(!app.process_table.focused);
    }

    #[test]
    fn test_search_commit_returns_to_normal() {
        let mut app = App::new();
        <App as FtuiModel>::update(&mut app, Msg::EnterSearchMode);
        <App as FtuiModel>::update(&mut app, Msg::SearchInput('f'));
        <App as FtuiModel>::update(&mut app, Msg::SearchInput('o'));
        <App as FtuiModel>::update(&mut app, Msg::SearchCommit);
        assert_eq!(app.state, AppState::Normal);
        assert!(app.process_table.focused);
    }

    #[test]
    fn test_search_cancel_returns_to_normal() {
        let mut app = App::new();
        <App as FtuiModel>::update(&mut app, Msg::EnterSearchMode);
        <App as FtuiModel>::update(&mut app, Msg::SearchCancel);
        assert_eq!(app.state, AppState::Normal);
        assert!(app.process_table.focused);
    }

    #[test]
    fn test_focus_next_prev_cycle() {
        let mut app = App::new();
        assert!(app.process_table.focused);

        <App as FtuiModel>::update(&mut app, Msg::FocusNext);
        assert!(app.search.focused);
        assert!(!app.process_table.focused);

        <App as FtuiModel>::update(&mut app, Msg::FocusPrev);
        assert!(app.process_table.focused);
        assert!(!app.search.focused);
    }

    #[test]
    fn test_resize_updates_layout() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::Resized {
                width: 200,
                height: 50,
            },
        );
        // Layout breakpoint should update (200 is wide enough for Wide)
        assert_eq!(app.breakpoint(), Breakpoint::Wide);
    }

    #[test]
    fn test_focus_changed_sets_status() {
        let mut app = App::new();
        <App as FtuiModel>::update(&mut app, Msg::FocusChanged(true));
        assert_eq!(app.status_message.as_deref(), Some("Terminal focus gained"));

        <App as FtuiModel>::update(&mut app, Msg::FocusChanged(false));
        assert_eq!(app.status_message.as_deref(), Some("Terminal focus lost"));
    }

    #[test]
    fn test_paste_enters_search_mode() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::PasteReceived {
                text: "hello".to_string(),
                bracketed: true,
            },
        );
        assert_eq!(app.state, AppState::Searching);
        assert_eq!(app.search.value(), "hello");
    }

    #[test]
    fn test_toggle_detail_visibility() {
        let mut app = App::new();
        assert!(app.is_detail_visible());

        <App as FtuiModel>::update(&mut app, Msg::ToggleDetail);
        assert!(!app.is_detail_visible());

        <App as FtuiModel>::update(&mut app, Msg::ToggleDetail);
        assert!(app.is_detail_visible());
    }

    #[test]
    fn test_set_detail_view() {
        let mut app = App::new();
        assert_eq!(app.current_detail_view(), DetailView::Summary);

        <App as FtuiModel>::update(&mut app, Msg::SetDetailView(DetailView::GalaxyBrain));
        assert_eq!(app.current_detail_view(), DetailView::GalaxyBrain);
        assert!(app.is_detail_visible());

        <App as FtuiModel>::update(&mut app, Msg::SetDetailView(DetailView::Genealogy));
        assert_eq!(app.current_detail_view(), DetailView::Genealogy);
    }

    #[test]
    fn test_switch_theme_msg() {
        let mut app = App::new();

        <App as FtuiModel>::update(&mut app, Msg::SwitchTheme("light".to_string()));
        assert_eq!(app.theme.mode, Theme::light().mode);

        <App as FtuiModel>::update(&mut app, Msg::SwitchTheme("high_contrast".to_string()));
        assert_eq!(app.theme.mode, Theme::high_contrast().mode);

        <App as FtuiModel>::update(&mut app, Msg::SwitchTheme("no_color".to_string()));
        assert_eq!(app.theme.mode, Theme::no_color().mode);

        <App as FtuiModel>::update(&mut app, Msg::SwitchTheme("dark".to_string()));
        assert_eq!(app.theme.mode, Theme::dark().mode);
    }

    #[test]
    fn test_noop_does_nothing() {
        let mut app = App::new();
        let state_before = app.state;
        <App as FtuiModel>::update(&mut app, Msg::Noop);
        assert_eq!(app.state, state_before);
    }

    fn make_row(pid: u32) -> ProcessRow {
        ProcessRow {
            pid,
            score: 50,
            classification: "REVIEW".to_string(),
            runtime: "1h".to_string(),
            memory: "10M".to_string(),
            command: format!("proc_{}", pid),
            selected: false,
            galaxy_brain: None,
            why_summary: None,
            top_evidence: vec![],
            confidence: None,
            plan_preview: vec![],
            provenance_headline: None,
            provenance_sections: Vec::new(),
            provenance_caveats: Vec::new(),
            blast_radius_risk: None,
        }
    }

    fn deferred_task(cmd: FtuiCmd<Msg>) -> Box<dyn FnOnce() -> Msg + Send> {
        let FtuiCmd::Sequence(commands) = cmd else {
            panic!("expected a logged asynchronous command");
        };
        let mut task = None;
        for command in commands {
            match command {
                FtuiCmd::Log(_) => {}
                FtuiCmd::Task(_, run) => {
                    assert!(task.is_none(), "one request must schedule exactly one task");
                    task = Some(run);
                }
                other => panic!("unexpected asynchronous command: {other:?}"),
            }
        }
        task.expect("the production update must schedule a task")
    }

    fn confirmed_request(app: &mut App) -> Msg {
        let command = <App as FtuiModel>::update(
            app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        );
        assert!(matches!(command, FtuiCmd::None));
        assert_eq!(app.state, AppState::Confirming);
        <App as FtuiModel>::update(app, Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Left)));
        let command =
            <App as FtuiModel>::update(app, Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Enter)));
        let FtuiCmd::Msg(request @ Msg::RequestExecute { .. }) = command else {
            panic!("confirmation must bind an execution request");
        };
        request
    }

    fn complete_execution_fixture(app: &mut App, result: Result<ExecutionOutcome, String>) {
        app.process_table.set_rows(vec![make_row(42)]);
        app.process_table.select_all();
        app.set_execute_op(Arc::new(move |pids, explicit, spares| {
            assert_eq!(pids, vec![42]);
            assert!(explicit.is_empty());
            assert!(spares.is_empty());
            result.clone()
        }));
        let request = confirmed_request(app);
        let run = deferred_task(<App as FtuiModel>::update(app, request));
        <App as FtuiModel>::update(app, run());
    }

    #[test]
    fn spare_only_feedback_is_cancelable_and_uses_its_confirmed_snapshot_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut app = App::new();
        let mut row = make_row(42);
        row.classification = "KILL".to_string();
        app.process_table.set_rows(vec![row]);
        <App as FtuiModel>::update(&mut app, Msg::SelectRecommended);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
        assert!(app.process_table.get_selected().is_empty());
        assert_eq!(app.process_table.get_explicitly_spared(), vec![42]);

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_e = Arc::clone(&calls);
        app.set_execute_op(Arc::new(move |pids, explicit, spares| {
            assert!(pids.is_empty(), "saving spares must not invent an action");
            assert!(explicit.is_empty());
            assert_eq!(spares, vec![42]);
            calls_e.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionOutcome {
                mode: Some("feedback".to_string()),
                ..ExecutionOutcome::default()
            })
        }));

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        );
        assert_eq!(app.state, AppState::Confirming);
        assert_eq!(app.confirm_dialog.selected, ConfirmChoice::No);
        assert!(app.status_message.as_deref().unwrap().contains("spare"));
        let cancelled = <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Enter)),
        );
        assert!(matches!(cancelled, FtuiCmd::None));
        assert_eq!(app.state, AppState::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let request = confirmed_request(&mut app);
        // Selection can change before the queued task request is delivered; the
        // explicit confirmation still applies only to its frozen spare decision.
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        assert_eq!(app.process_table.get_selected(), vec![42]);
        assert!(app.process_table.get_explicitly_spared().is_empty());
        let save = deferred_task(<App as FtuiModel>::update(&mut app, request.clone()));
        for message in [Msg::RequestRefresh, Msg::ToggleSelection, request.clone()] {
            assert!(matches!(
                <App as FtuiModel>::update(&mut app, message),
                FtuiCmd::None
            ));
        }
        <App as FtuiModel>::update(&mut app, save());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(
            app.status_message.as_deref(),
            Some("Spare decisions saved for future scans")
        );
        assert!(app.process_table.get_explicitly_spared().is_empty());
        assert!(app.process_table.get_selected().is_empty());
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, request),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        );
        assert_eq!(app.state, AppState::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mixed_confirmation_separates_default_actions_explicit_kills_and_spares() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut app = App::new();
        let rows = [(42, 90), (99, 80), (100, 70)]
            .into_iter()
            .map(|(pid, score)| {
                let mut row = make_row(pid);
                row.score = score;
                row.classification = "KILL".to_string();
                row
            })
            .collect();
        app.process_table.set_rows(rows);
        <App as FtuiModel>::update(&mut app, Msg::SelectRecommended);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection); // Spare 42.
        <App as FtuiModel>::update(&mut app, Msg::CursorDown);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection); // Explicit kill 99.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_e = Arc::clone(&calls);
        app.set_execute_op(Arc::new(move |mut pids, explicit, spares| {
            pids.sort_unstable();
            assert_eq!(pids, vec![99, 100]);
            assert_eq!(explicit, vec![99], "default acceptance is not a verdict");
            assert_eq!(spares, vec![42]);
            calls_e.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionOutcome {
                attempted: 2,
                succeeded: 2,
                ..ExecutionOutcome::default()
            })
        }));
        let request = confirmed_request(&mut app);
        <App as FtuiModel>::update(&mut app, Msg::DeselectAll);
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(app.process_table.get_explicitly_spared().is_empty());
        assert!(app.process_table.get_explicitly_selected().is_empty());
    }

    #[test]
    fn spare_feedback_previews_do_not_claim_to_save_labels_or_a_plan() {
        for (mode, expected) in [
            (
                "feedback_dry_run",
                "Spare feedback preview (dry_run): no decisions saved",
            ),
            (
                "feedback_shadow",
                "Spare feedback preview (shadow): no decisions saved",
            ),
        ] {
            let mut app = App::new();
            app.process_table.set_rows(vec![make_row(42)]);
            <App as FtuiModel>::update(&mut app, Msg::SelectAll);
            <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
            app.set_execute_op(Arc::new(move |pids, explicit, spares| {
                assert!(pids.is_empty());
                assert!(explicit.is_empty());
                assert_eq!(spares, vec![42]);
                Ok(ExecutionOutcome {
                    mode: Some(mode.to_string()),
                    ..ExecutionOutcome::default()
                })
            }));
            let request = confirmed_request(&mut app);
            let preview = deferred_task(<App as FtuiModel>::update(&mut app, request));
            <App as FtuiModel>::update(&mut app, preview());
            assert_eq!(app.status_message.as_deref(), Some(expected));
            assert!(app.process_table.get_explicitly_spared().is_empty());
            assert_eq!(app.operation, PendingOperation::Idle);
        }
    }

    #[test]
    fn refresh_discards_spare_judgments_and_their_confirmed_request() {
        let mut app = App::new();
        app.process_table.set_rows(vec![make_row(42)]);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
        let stale = confirmed_request(&mut app);
        app.set_execute_op(Arc::new(|_, _, _| {
            panic!("a refreshed scan must not reuse a prior spare judgment")
        }));
        app.set_refresh_op(Arc::new(|| {
            let mut replacement = make_row(42);
            replacement.command = "replacement incarnation".to_string();
            Ok(RefreshOutcome {
                rows: vec![replacement],
                ..RefreshOutcome::default()
            })
        }));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        assert!(app.process_table.get_explicitly_spared().is_empty());
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, stale.clone()),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(&mut app, refresh());
        assert_eq!(app.process_table.rows[0].command, "replacement incarnation");
        assert!(app.process_table.get_explicitly_spared().is_empty());
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, stale),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        );
        assert_eq!(app.state, AppState::Normal);
    }

    #[test]
    fn test_processes_scanned_updates_table() {
        let mut app = App::new();
        let rows = vec![make_row(42)];
        <App as FtuiModel>::update(&mut app, Msg::ProcessesScanned(rows));
        assert_eq!(app.process_table.rows.len(), 1);
        assert_eq!(app.process_table.rows[0].pid, 42);
    }

    #[test]
    fn test_refresh_complete_ok() {
        let mut app = App::new();
        app.set_refresh_op(Arc::new(|| {
            Ok(RefreshOutcome {
                rows: vec![make_row(99)],
                ..RefreshOutcome::default()
            })
        }));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        <App as FtuiModel>::update(&mut app, refresh());
        assert_eq!(app.process_table.rows.len(), 1);
        assert!(app.status_message.as_deref().unwrap().contains("refreshed"));
    }

    #[test]
    fn test_refresh_complete_err() {
        let mut app = App::new();
        app.set_refresh_op(Arc::new(|| Err("network error".to_string())));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        <App as FtuiModel>::update(&mut app, refresh());
        assert!(app.status_message.as_deref().unwrap().contains("failed"));
    }

    #[test]
    fn refresh_replaces_goal_forecast_and_selection_with_the_same_scan() {
        let kill_row = |pid| {
            let mut row = make_row(pid);
            row.classification = "KILL".to_string();
            row
        };
        let mut app = App::new();
        app.replace_processes(RefreshOutcome {
            rows: vec![kill_row(42), kill_row(99)],
            pressure: None,
            goal_summary: Some(vec!["old forecast".to_string()]),
            goal_selection: Some([(42, 0)].into()),
        });
        <App as FtuiModel>::update(&mut app, Msg::SelectRecommended);
        assert_eq!(app.process_table.get_selected(), vec![42]);
        app.set_refresh_op(Arc::new(move || {
            Ok(RefreshOutcome {
                rows: vec![kill_row(42), kill_row(99)],
                pressure: None,
                goal_summary: Some(vec!["new forecast".to_string()]),
                goal_selection: Some([(99, 0)].into()),
            })
        }));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        let completed = refresh();
        assert_eq!(app.goal_summary.as_ref().unwrap(), &["old forecast"]);
        assert_eq!(app.process_table.selected_count(), 0);
        <App as FtuiModel>::update(&mut app, completed);
        assert_eq!(app.goal_summary.as_ref().unwrap(), &["new forecast"]);
        assert_eq!(app.process_table.selected_count(), 0);
        <App as FtuiModel>::update(&mut app, Msg::SelectRecommended);
        assert_eq!(app.process_table.get_selected(), vec![99]);
        <App as FtuiModel>::update(
            &mut app,
            Msg::RefreshComplete {
                ticket: 0,
                result: Ok(RefreshOutcome::default()),
            },
        );
        assert_eq!(app.goal_summary.as_ref().unwrap(), &["new forecast"]);
        assert_eq!(app.process_table.get_selected(), vec![99]);
        <App as FtuiModel>::update(&mut app, Msg::ProcessesScanned(vec![kill_row(42)]));
        assert!(app.goal_summary.is_none());
        assert!(app.process_table.goal_selection().is_none());
        assert_eq!(app.process_table.selected_count(), 0);
    }

    #[test]
    fn test_execution_complete_ok_real_mode() {
        let mut app = App::new();
        let outcome = ExecutionOutcome {
            mode: None,
            attempted: 3,
            succeeded: 2,
            failed: 1,
        };
        complete_execution_fixture(&mut app, Ok(outcome));
        let status = app.status_message.as_deref().unwrap();
        assert!(status.contains("2 succeeded"));
        assert!(status.contains("1 failed"));
    }

    #[test]
    fn test_execution_complete_dry_run() {
        let mut app = App::new();
        let outcome = ExecutionOutcome {
            mode: Some("dry_run".to_string()),
            attempted: 5,
            succeeded: 0,
            failed: 0,
        };
        complete_execution_fixture(&mut app, Ok(outcome));
        assert!(app.status_message.as_deref().unwrap().contains("dry_run"));
    }

    #[test]
    fn test_execution_complete_err() {
        let mut app = App::new();
        complete_execution_fixture(&mut app, Err("permission denied".to_string()));
        assert!(app.status_message.as_deref().unwrap().contains("failed"));
    }

    #[test]
    fn test_goal_summary_set_clear() {
        let mut app = App::new();
        assert!(app.goal_summary.is_none());

        app.set_goal_summary(vec!["line1".to_string(), "line2".to_string()]);
        assert!(app.goal_summary.is_some());
        assert_eq!(app.goal_summary.as_ref().unwrap().len(), 2);

        app.set_goal_summary(vec![]);
        assert!(app.goal_summary.is_none());

        app.set_goal_summary(vec!["ok".to_string()]);
        app.clear_goal_summary();
        assert!(app.goal_summary.is_none());
    }

    #[test]
    fn refresh_invalidates_pending_confirmation_before_the_task_runs() {
        let mut app = App::new();
        app.process_table.set_rows(vec![make_row(42)]);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        );
        assert!(app.confirm_dialog.visible);
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        assert_eq!(app.process_table.selected_count(), 0);
        assert_eq!(app.state, AppState::Normal);
        assert!(!app.confirm_dialog.visible);
        assert!(app.confirmation_selection.is_none());
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, Msg::ConfirmExecute),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(&mut app, refresh());
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(app.process_table.selected_count(), 0);
    }

    #[test]
    fn refresh_cache_before_display_refuses_old_ticket_and_all_selection_entrypoints() {
        use pt_common::{IdentityQuality, ProcessIdentity, StartId};
        use std::sync::Mutex;

        let mut app = App::new();
        let before = ProcessIdentity::full(
            42,
            StartId("boot:100:42".to_string()),
            1000,
            Some(40),
            Some(40),
            IdentityQuality::Full,
        );
        let mut after = before.clone();
        after.start_id = StartId("boot:200:42".to_string());
        let cache = Arc::new(Mutex::new(before.clone()));
        let executions = Arc::new(Mutex::new(Vec::<ProcessIdentity>::new()));
        app.process_table.set_rows(vec![make_row(42)]);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let stale_request = confirmed_request(&mut app);

        let cache_r = Arc::clone(&cache);
        let after_r = after.clone();
        app.set_refresh_op(Arc::new(move || {
            *cache_r.lock().unwrap() = after_r.clone();
            let mut row = make_row(42);
            row.command = "replacement incarnation".to_string();
            Ok(RefreshOutcome {
                rows: vec![row],
                ..RefreshOutcome::default()
            })
        }));
        let cache_e = Arc::clone(&cache);
        let executions_e = Arc::clone(&executions);
        app.set_execute_op(Arc::new(move |pids, explicit, spares| {
            assert_eq!(pids, vec![42]);
            assert!(explicit.is_empty());
            assert!(spares.is_empty());
            executions_e
                .lock()
                .unwrap()
                .push(cache_e.lock().unwrap().clone());
            Ok(ExecutionOutcome {
                mode: Some("dry_run".to_string()),
                attempted: 1,
                succeeded: 0,
                failed: 0,
            })
        }));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        let completed = refresh();
        assert_eq!(*cache.lock().unwrap(), after);
        assert_eq!(app.process_table.rows[0].command, "proc_42");
        assert_ne!(*cache.lock().unwrap(), before);
        for message in [
            stale_request.clone(),
            Msg::SelectAll,
            Msg::SelectRecommended,
            Msg::InvertSelection,
            Msg::ToggleSelection,
            Msg::ConfirmExecute,
            Msg::ProcessesScanned(vec![make_row(99)]),
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('A'))),
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char(' '))),
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('e'))),
        ] {
            assert!(matches!(
                <App as FtuiModel>::update(&mut app, message),
                FtuiCmd::None
            ));
            assert_eq!(app.process_table.selected_count(), 0);
            assert_eq!(app.process_table.rows[0].pid, 42);
        }
        for action in ["selection.all", "selection.recommended", "action.execute"] {
            assert!(matches!(app.execute_palette_action(action), FtuiCmd::None));
            assert_eq!(app.process_table.selected_count(), 0);
        }
        <App as FtuiModel>::update(&mut app, completed);
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(app.process_table.rows[0].command, "replacement incarnation");
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let fresh_request = confirmed_request(&mut app);
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, stale_request),
            FtuiCmd::None
        ));
        assert!(executions.lock().unwrap().is_empty());
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, fresh_request.clone()));
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, fresh_request.clone()),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(*executions.lock().unwrap(), vec![after]);
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(app.process_table.selected_count(), 0);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let later_request = confirmed_request(&mut app);
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, fresh_request),
            FtuiCmd::None
        ));
        let later = deferred_task(<App as FtuiModel>::update(&mut app, later_request));
        <App as FtuiModel>::update(&mut app, later());
        assert_eq!(executions.lock().unwrap().len(), 2);
    }

    #[test]
    fn execution_serializes_refresh_and_recovers_after_an_actual_task_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut app = App::new();
        app.process_table.set_rows(vec![make_row(42)]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_e = Arc::clone(&calls);
        app.set_execute_op(Arc::new(move |pids, explicit, spares| {
            assert_eq!(pids, vec![42]);
            assert!(explicit.is_empty());
            assert!(spares.is_empty());
            if calls_e.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("dispatch callback failure".to_string())
            } else {
                Ok(ExecutionOutcome {
                    mode: Some("dry_run".to_string()),
                    attempted: 1,
                    succeeded: 0,
                    failed: 0,
                })
            }
        }));
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let request = confirmed_request(&mut app);
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, request.clone()));
        for message in [
            Msg::RequestRefresh,
            request.clone(),
            Msg::ProcessesScanned(vec![make_row(99)]),
            Msg::ConfirmExecute,
            Msg::RefreshComplete {
                ticket: 0,
                result: Ok(RefreshOutcome {
                    rows: vec![make_row(99)],
                    ..RefreshOutcome::default()
                }),
            },
            Msg::ExecutionComplete {
                ticket: 0,
                result: Ok(ExecutionOutcome::default()),
            },
        ] {
            assert!(matches!(
                <App as FtuiModel>::update(&mut app, message),
                FtuiCmd::None
            ));
        }
        assert!(matches!(
            app.execute_palette_action("action.refresh"),
            FtuiCmd::None
        ));
        assert!(matches!(
            <App as FtuiModel>::update(
                &mut app,
                Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char('r'))),
            ),
            FtuiCmd::None
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(app.process_table.rows[0].pid, 42);
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(app.process_table.selected_count(), 0);
        assert!(app
            .status_message
            .as_deref()
            .unwrap()
            .contains("dispatch callback failure"));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        <App as FtuiModel>::update(&mut app, refresh());
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let fresh_request = confirmed_request(&mut app);
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, request),
            FtuiCmd::None
        ));
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, fresh_request));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(app.operation, PendingOperation::Idle);
        assert!(app.status_message.as_deref().unwrap().contains("dry_run"));
    }

    #[test]
    fn refresh_error_and_unrelated_completion_do_not_revive_an_old_confirmation() {
        let mut app = App::new();
        app.process_table.set_rows(vec![make_row(42)]);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let stale_request = confirmed_request(&mut app);
        app.set_refresh_op(Arc::new(|| Err("scan evidence unavailable".to_string())));
        let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
        let active = app.operation;
        assert!(matches!(
            <App as FtuiModel>::update(
                &mut app,
                Msg::ExecutionComplete {
                    ticket: 0,
                    result: Err("stale error".to_string())
                },
            ),
            FtuiCmd::None
        ));
        assert_eq!(app.operation, active);
        <App as FtuiModel>::update(&mut app, refresh());
        assert_eq!(app.operation, PendingOperation::Idle);
        assert_eq!(app.process_table.rows[0].pid, 42);
        assert_eq!(app.process_table.selected_count(), 0);
        assert!(app
            .status_message
            .as_deref()
            .unwrap()
            .contains("scan evidence unavailable"));
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, stale_request),
            FtuiCmd::None
        ));
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let fresh_request = confirmed_request(&mut app);
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, fresh_request));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(app.operation, PendingOperation::Idle);
    }

    #[test]
    fn confirmed_dispatch_keeps_its_selection_and_row_replacement_expires_queued_tickets() {
        use std::sync::Mutex;

        let mut app = App::new();
        app.process_table.set_rows(vec![make_row(42), make_row(99)]);
        let received = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
        let received_e = Arc::clone(&received);
        let labels = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
        let labels_e = Arc::clone(&labels);
        app.set_execute_op(Arc::new(move |pids, explicit, spares| {
            received_e.lock().unwrap().push(pids);
            labels_e.lock().unwrap().push(explicit);
            assert!(spares.is_empty());
            Ok(ExecutionOutcome {
                mode: Some("dry_run".to_string()),
                attempted: 1,
                succeeded: 0,
                failed: 0,
            })
        }));
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
        let confirmed = app.process_table.get_selected();
        assert_eq!(confirmed.len(), 1);
        let request = confirmed_request(&mut app);
        <App as FtuiModel>::update(&mut app, Msg::DeselectAll);
        <App as FtuiModel>::update(&mut app, Msg::CursorDown);
        <App as FtuiModel>::update(&mut app, Msg::ToggleSelection);
        assert_ne!(app.process_table.get_selected(), confirmed);
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(*received.lock().unwrap(), vec![confirmed.clone()]);
        assert_eq!(*labels.lock().unwrap(), vec![confirmed]);

        <App as FtuiModel>::update(&mut app, Msg::ProcessesScanned(vec![make_row(42)]));
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let stale = confirmed_request(&mut app);
        let mut replacement = make_row(42);
        replacement.command = "changed snapshot".to_string();
        <App as FtuiModel>::update(&mut app, Msg::ProcessesScanned(vec![replacement]));
        assert_eq!(app.process_table.selected_count(), 0);
        <App as FtuiModel>::update(&mut app, Msg::SelectAll);
        let fresh = confirmed_request(&mut app);
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, stale),
            FtuiCmd::None
        ));
        assert_eq!(received.lock().unwrap().len(), 1);
        let execute = deferred_task(<App as FtuiModel>::update(&mut app, fresh));
        <App as FtuiModel>::update(&mut app, execute());
        assert_eq!(received.lock().unwrap()[1], vec![42]);
        assert!(labels.lock().unwrap()[1].is_empty());
        assert_eq!(app.operation, PendingOperation::Idle);
    }

    #[test]
    fn test_with_theme_builder() {
        let app = App::new().with_theme(Theme::light());
        assert_eq!(app.theme.mode, Theme::light().mode);
    }

    #[test]
    fn test_key_event_normal_escape_quits() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert_eq!(app.state, AppState::Quitting);
    }

    #[test]
    fn test_key_event_search_escape_exits() {
        let mut app = App::new();
        app.state = AppState::Searching;
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert_eq!(app.state, AppState::Normal);
    }

    #[test]
    fn test_key_event_help_escape_exits() {
        let mut app = App::new();
        app.state = AppState::Help;
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert_eq!(app.state, AppState::Normal);
    }

    #[test]
    fn test_key_event_confirm_escape_cancels() {
        let mut app = App::new();
        app.state = AppState::Confirming;
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert_eq!(app.state, AppState::Normal);
    }

    #[test]
    fn test_command_palette_opens_with_ctrl_p() {
        let mut app = App::new();
        let key = FtuiKeyEvent::new(FtuiKeyCode::Char('p')).with_modifiers(FtuiModifiers::CTRL);
        <App as FtuiModel>::update(&mut app, Msg::KeyPressed(key));
        assert!(app.command_palette.is_visible());
    }

    #[test]
    fn test_command_palette_opens_with_colon() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char(':'))),
        );
        assert!(app.command_palette.is_visible());
    }

    #[test]
    fn test_command_palette_escape_dismisses() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(
                FtuiKeyEvent::new(FtuiKeyCode::Char('p')).with_modifiers(FtuiModifiers::CTRL),
            ),
        );
        assert!(app.command_palette.is_visible());

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert!(!app.command_palette.is_visible());
    }

    #[test]
    fn test_command_palette_executes_select_all_action() {
        let mut app = App::new();
        app.process_table
            .set_rows(vec![make_row(11), make_row(22), make_row(33)]);

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(
                FtuiKeyEvent::new(FtuiKeyCode::Char('p')).with_modifiers(FtuiModifiers::CTRL),
            ),
        );
        app.command_palette.set_query("select all");
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Enter)),
        );

        assert_eq!(app.process_table.selected_count(), 3);
        assert!(!app.command_palette.is_visible());
    }

    #[test]
    fn test_command_palette_announces_open_and_close_in_accessible_mode() {
        let mut app = App::new();
        app.accessible = true;

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(
                FtuiKeyEvent::new(FtuiKeyCode::Char('p')).with_modifiers(FtuiModifiers::CTRL),
            ),
        );
        assert_eq!(
            app.status_message.as_deref(),
            Some("Command palette opened. Type to search, Enter to run, Escape to close.")
        );

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Escape)),
        );
        assert_eq!(
            app.status_message.as_deref(),
            Some("Command palette closed.")
        );
    }

    #[test]
    fn test_command_palette_announces_executed_action_in_accessible_mode() {
        let mut app = App::new();
        app.accessible = true;
        app.process_table
            .set_rows(vec![make_row(11), make_row(22), make_row(33)]);

        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(
                FtuiKeyEvent::new(FtuiKeyCode::Char('p')).with_modifiers(FtuiModifiers::CTRL),
            ),
        );
        app.command_palette.set_query("select all");
        <App as FtuiModel>::update(
            &mut app,
            Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Enter)),
        );

        assert_eq!(app.process_table.selected_count(), 3);
        assert_eq!(
            app.status_message.as_deref(),
            Some("Command executed: Select all")
        );
    }

    #[test]
    fn test_default_impl_matches_new() {
        let a = App::new();
        let b = App::default();
        assert_eq!(a.state, b.state);
        assert_eq!(a.should_quit(), b.should_quit());
    }
}
