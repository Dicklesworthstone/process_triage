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
use ftui::widgets::command_palette::{ActionItem, CommandPalette, PaletteAction};
use ftui::widgets::notification_queue::{NotificationQueue, NotificationStack, QueueConfig};
use ftui::widgets::toast::{Toast, ToastIcon, ToastPosition, ToastStyle};
use ftui::widgets::Widget;
use ftui::{
    Cell as FtuiCell, Cmd as FtuiCmd, Event as FtuiEvent, Frame as FtuiFrame,
    KeyCode as FtuiKeyCode, KeyEvent as FtuiKeyEvent, KeyEventKind as FtuiKeyEventKind,
    Model as FtuiModel, Modifiers as FtuiModifiers, Program, ProgramConfig,
};

use super::events::KeyBindings;
use super::layout::{Breakpoint, LayoutState, ResponsiveLayout};
use super::msg::{ExecutionOutcome, Msg};
use super::theme::Theme;
use super::widgets::{
    AuxPanel, ConfirmChoice, ConfirmDialog, ConfirmDialogState, DetailView, HelpOverlay,
    ProcessDetail, ProcessRow, ProcessTable, ProcessTableState, SearchInput, SearchInputState,
    StatusBar, StatusMode,
};
use super::{TuiError, TuiResult};

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
    /// Application is quitting.
    Quitting,
}

type RefreshOp = Arc<dyn Fn() -> Result<Vec<ProcessRow>, String> + Send + Sync>;
type ExecuteOp = Arc<dyn Fn(Vec<u32>) -> Result<ExecutionOutcome, String> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PendingOperation {
    #[default]
    Idle,
    Refreshing(u64),
    Executing(u64),
}

struct ConfirmedSelection {
    ticket: u64,
    pids: Vec<u32>,
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
    confirmation_selection: Option<Vec<u32>>,
    confirmed_selection: Option<ConfirmedSelection>,
    /// Responsive layout state for tracking breakpoint changes.
    layout_state: LayoutState,
    /// Whether the detail pane is visible.
    detail_visible: bool,
    /// Current detail view mode.
    detail_view: DetailView,
    /// Optional goal summary lines to display.
    goal_summary: Option<Vec<String>>,
    /// Injected refresh operation for ftui Cmd::task (Send + 'static).
    /// Returns new process rows on success.
    refresh_op: Option<RefreshOp>,
    /// Injected execute operation for ftui Cmd::task (Send + 'static).
    /// Takes selected PIDs, returns execution outcome.
    execute_op: Option<ExecuteOp>,
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
            refresh_op: None,
            execute_op: None,
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
                .with_description("Open confirmation dialog for selected processes")
                .with_tags(&["execute", "kill", "confirm"])
                .with_category("Actions"),
            ActionItem::new("action.refresh", "Refresh processes  [r]")
                .with_description("Rescan processes and refresh recommendations")
                .with_tags(&["refresh", "rescan"])
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

    /// Set the async execute operation for ftui Cmd::task.
    pub fn set_execute_op(&mut self, op: ExecuteOp) {
        self.execute_op = Some(op);
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
        }
    }

    fn selection_is_available(&mut self) -> bool {
        if !self.operation_is_idle() {
            return false;
        }
        if self.state == AppState::Confirming {
            self.set_status("Finish or cancel the current confirmation before changing selection");
            return false;
        }
        true
    }

    fn invalidate_selection(&mut self) {
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
            "view.help" => "Show keyboard shortcuts",
            "settings.theme.dark" => "Switch theme dark",
            "settings.theme.light" => "Switch theme light",
            "settings.theme.high_contrast" => "Switch theme high contrast",
            "settings.theme.no_color" => "Switch theme no color",
            _ => "Unknown command",
        }
    }

    fn execute_palette_action(&mut self, action_id: &str) -> FtuiCmd<Msg> {
        self.announce_accessible(format!(
            "Command executed: {}",
            Self::palette_action_label(action_id)
        ));
        match action_id {
            "action.execute" => self.show_execute_confirmation(),
            "action.refresh" => return self.handle_msg(Msg::RequestRefresh),

            "navigation.first" => self.process_table.cursor_home(),
            "navigation.last" => self.process_table.cursor_end(),
            "navigation.page_down" => self
                .process_table
                .page_down(self.process_table.last_visible_height),
            "navigation.page_up" => self
                .process_table
                .page_up(self.process_table.last_visible_height),
            "search.open" => {
                self.state = AppState::Searching;
                self.focus = FocusTarget::Search;
                self.update_focus();
            }

            "selection.recommended" => return self.handle_msg(Msg::SelectRecommended),
            "selection.all" => return self.handle_msg(Msg::SelectAll),
            "selection.none" => return self.handle_msg(Msg::DeselectAll),
            "selection.invert" => return self.handle_msg(Msg::InvertSelection),

            "view.toggle_detail" => self.toggle_detail_visibility(),
            "view.summary" => self.set_detail_view(DetailView::Summary),
            "view.genealogy" => self.set_detail_view(DetailView::Genealogy),
            "view.galaxy" => {
                if self.detail_view == DetailView::GalaxyBrain {
                    self.set_detail_view(DetailView::Summary);
                } else {
                    self.set_detail_view(DetailView::GalaxyBrain);
                }
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
            }
            "view.help" => self.state = AppState::Help,

            "settings.theme.dark" => self.theme = Theme::dark(),
            "settings.theme.light" => self.theme = Theme::light(),
            "settings.theme.high_contrast" => self.theme = Theme::high_contrast(),
            "settings.theme.no_color" => self.theme = Theme::no_color(),

            _ => {
                tracing::warn!(
                    target: "tui.command_palette",
                    action_id,
                    "Unknown command palette action"
                );
                self.set_status(format!("Unknown command: {}", action_id));
            }
        }
        FtuiCmd::none()
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
        if !self.operation_is_idle() {
            return;
        }
        self.confirmed_selection = None;
        let selected_pids = self.process_table.get_selected();
        let selected_count = selected_pids.len();
        if selected_count > 0 {
            self.confirmation_selection = Some(selected_pids);
            self.confirm_dialog.show();
            self.state = AppState::Confirming;
            self.set_status(format!("Confirm action on {} process(es)?", selected_count));
        } else {
            self.confirmation_selection = None;
            self.set_status("No processes selected");
        }
    }

    /// Handle confirmation dialog result.
    fn handle_confirmation(&mut self, choice: ConfirmChoice) -> FtuiCmd<Msg> {
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
                let Some(pids) = selection.filter(|pids| !pids.is_empty()) else {
                    self.set_status("Confirmation expired; select processes and confirm again");
                    return FtuiCmd::none();
                };
                let Some(ticket) = self.issue_operation_ticket() else {
                    return FtuiCmd::none();
                };
                let count = pids.len();
                self.confirmed_selection = Some(ConfirmedSelection { ticket, pids });
                self.set_status(format!("Preparing actions for {} process(es)...", count));
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
                self.process_table.cursor_up();
                FtuiCmd::none()
            }
            Msg::CursorDown => {
                self.process_table.cursor_down();
                FtuiCmd::none()
            }
            Msg::CursorHome => {
                self.process_table.cursor_home();
                FtuiCmd::none()
            }
            Msg::CursorEnd => {
                self.process_table.cursor_end();
                FtuiCmd::none()
            }
            Msg::PageUp | Msg::HalfPageUp => {
                self.process_table
                    .page_up(self.process_table.last_visible_height);
                FtuiCmd::none()
            }
            Msg::PageDown | Msg::HalfPageDown => {
                self.process_table
                    .page_down(self.process_table.last_visible_height);
                FtuiCmd::none()
            }

            Msg::ToggleSelection => {
                if self.selection_is_available() {
                    self.process_table.toggle_selection();
                }
                FtuiCmd::none()
            }
            Msg::SelectRecommended => {
                if self.selection_is_available() {
                    self.process_table.select_recommended();
                }
                FtuiCmd::none()
            }
            Msg::SelectAll => {
                if self.selection_is_available() {
                    self.process_table.select_all();
                }
                FtuiCmd::none()
            }
            Msg::DeselectAll => {
                if self.selection_is_available() {
                    self.process_table.deselect_all();
                }
                FtuiCmd::none()
            }
            Msg::InvertSelection => {
                if self.selection_is_available() {
                    self.process_table.invert_selection();
                }
                FtuiCmd::none()
            }

            Msg::EnterSearchMode => {
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
                self.state = if self.state == AppState::Help {
                    AppState::Normal
                } else {
                    AppState::Help
                };
                FtuiCmd::none()
            }

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
                let selected_pids = selection.pids;
                let selected_count = selected_pids.len();
                self.operation = PendingOperation::Executing(ticket);
                tracing::info!(
                    target: "tui.user_input",
                    action = "execute_requested",
                    selected_count,
                    "Execution requested"
                );
                if let Some(execute) = self.execute_op.clone() {
                    self.set_status(format!(
                        "Executing actions on {} process(es)...",
                        selected_count
                    ));
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log(format!(
                            "execute: starting (selected_count={})",
                            selected_count
                        )),
                        FtuiCmd::task_named("execute-selected", move || Msg::ExecutionComplete {
                            ticket,
                            result: execute(selected_pids),
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
                if !self.operation_is_idle() {
                    return FtuiCmd::none();
                }
                self.invalidate_selection();
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
                    let prior_rows = self.process_table.rows.clone();
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log("refresh: skeleton mode"),
                        FtuiCmd::task_named("refresh-processes", move || Msg::RefreshComplete {
                            ticket,
                            result: Ok(prior_rows),
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
                self.invalidate_selection();
                self.process_table.set_rows(rows);
                self.set_status("Process list refreshed");
                FtuiCmd::none()
            }
            Msg::RefreshComplete {
                ticket,
                result: Ok(rows),
            } => {
                if self.operation != PendingOperation::Refreshing(ticket) {
                    return FtuiCmd::none();
                }
                self.operation = PendingOperation::Idle;
                self.invalidate_selection();
                let count = rows.len();
                self.process_table.set_rows(rows);
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
                tracing::error!(target: "tui.async_complete", error = %error, "Execution failed");
                self.set_status(format!("Execution failed: {}", error));
                self.push_toast(
                    format!("Execution failed: {}", error),
                    ToastIcon::Error,
                    ToastStyle::Error,
                );
                FtuiCmd::log(format!("execute: failed ({})", error))
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
                self.state = AppState::Quitting;
                FtuiCmd::quit()
            }
        }
    }

    fn handle_ftui_key_event(&mut self, key: FtuiKeyEvent) -> FtuiCmd<Msg> {
        if !matches!(key.kind, FtuiKeyEventKind::Press | FtuiKeyEventKind::Repeat) {
            return FtuiCmd::none();
        }

        if let Some(cmd) = self.handle_command_palette_key(key) {
            return cmd;
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
                return self.handle_confirmation(choice);
            }
            FtuiKeyCode::Escape => {
                return self.handle_confirmation(ConfirmChoice::No);
            }
            _ => {}
        }
        FtuiCmd::none()
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

        // Compute areas with optional goal-summary header
        let header_height = self
            .goal_summary
            .as_ref()
            .map(|lines| lines.len().min(4) as u16)
            .unwrap_or(0);
        let areas = layout.main_areas_with_header(header_height);

        // ── Header (goal summary) ──────────────────────────────────────
        if let (Some(header_area), Some(lines)) = (areas.header, &self.goal_summary) {
            for (i, line) in lines.iter().enumerate() {
                if i as u16 >= header_area.height {
                    break;
                }
                draw_ftui_text(frame, header_area.x, header_area.y + i as u16, line);
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
                let selected = current_row.map(|r| r.selected).unwrap_or(false);
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
            AppState::Normal | AppState::Quitting => StatusMode::Normal,
            AppState::Searching => StatusMode::Searching,
            AppState::Confirming => StatusMode::Confirming,
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
            let msg = format!(
                "Execute actions on {} selected process(es)?",
                self.process_table.selected_count()
            );
            ConfirmDialog::new()
                .theme(&self.theme)
                .title("Confirm Execution")
                .message(&msg)
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
        app.set_execute_op(Arc::new(move |pids| {
            assert_eq!(pids, vec![42]);
            result.clone()
        }));
        let request = confirmed_request(app);
        let run = deferred_task(<App as FtuiModel>::update(app, request));
        <App as FtuiModel>::update(app, run());
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
        app.set_refresh_op(Arc::new(|| Ok(vec![make_row(99)])));
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
            Ok(vec![row])
        }));
        let cache_e = Arc::clone(&cache);
        let executions_e = Arc::clone(&executions);
        app.set_execute_op(Arc::new(move |pids| {
            assert_eq!(pids, vec![42]);
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
        app.set_execute_op(Arc::new(move |pids| {
            assert_eq!(pids, vec![42]);
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
                result: Ok(vec![make_row(99)]),
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
        app.set_execute_op(Arc::new(move |pids| {
            received_e.lock().unwrap().push(pids);
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
        assert_eq!(*received.lock().unwrap(), vec![confirmed]);

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
