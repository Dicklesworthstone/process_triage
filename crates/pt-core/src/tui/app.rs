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
use std::time::Duration;

use ftui::runtime::{Every, Subscription};
use ftui::widgets::notification_queue::{NotificationQueue, QueueConfig};
use ftui::widgets::toast::{Toast, ToastIcon, ToastPosition, ToastStyle};
use ftui::widgets::notification_queue::NotificationStack;
use ftui::widgets::Widget;
use ftui::{
    Cell as FtuiCell, Cmd as FtuiCmd, Frame as FtuiFrame, KeyCode as FtuiKeyCode,
    KeyEvent as FtuiKeyEvent, KeyEventKind as FtuiKeyEventKind, Model as FtuiModel,
    Modifiers as FtuiModifiers, Program, ProgramConfig,
};
use ftui::core::geometry::Rect;

use super::events::KeyBindings;
use super::layout::{Breakpoint, LayoutState};
use super::msg::{ExecutionOutcome, Msg};
use super::theme::Theme;
use super::widgets::{
    ConfirmChoice, ConfirmDialogState, DetailView, ProcessRow, ProcessTableState, SearchInputState,
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
    /// Whether a refresh has been requested.
    refresh_requested: bool,
    /// Whether an execute action has been requested.
    execute_requested: bool,
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
            refresh_requested: false,
            execute_requested: false,
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
                default_duration: Duration::from_secs(5),
                position: ToastPosition::TopRight,
                stagger_offset: 1,
                dedup_window_ms: 1000,
            }),
        }
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
        let toast = Toast::new(message)
            .icon(icon)
            .style_variant(style)
            .duration(Duration::from_secs(4));
        self.notifications.notify(toast);
        self.needs_redraw = true;
    }

    /// Request a redraw.
    pub fn request_redraw(&mut self) {
        self.needs_redraw = true;
    }

    /// Request a refresh of the process list.
    pub fn request_refresh(&mut self) {
        self.refresh_requested = true;
        self.needs_redraw = true;
    }

    /// Check and clear refresh request.
    pub fn take_refresh(&mut self) -> bool {
        let requested = self.refresh_requested;
        self.refresh_requested = false;
        requested
    }

    /// Request execution of selected actions.
    pub fn request_execute(&mut self) {
        self.execute_requested = true;
        self.needs_redraw = true;
    }

    /// Check and clear execute request.
    pub fn take_execute(&mut self) -> bool {
        let requested = self.execute_requested;
        self.execute_requested = false;
        requested
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

    /// Apply the current search filter to the process table.
    fn apply_search_filter(&mut self) {
        let query = self.search.value().to_lowercase();
        self.process_table
            .set_filter(if query.is_empty() { None } else { Some(query) });
    }

    /// Show confirmation dialog for executing actions.
    fn show_execute_confirmation(&mut self) {
        let selected_count = self.process_table.selected_count();
        if selected_count > 0 {
            self.confirm_dialog.show();
            self.state = AppState::Confirming;
            self.set_status(format!("Confirm action on {} process(es)?", selected_count));
        } else {
            self.set_status("No processes selected");
        }
    }

    /// Handle confirmation dialog result.
    fn handle_confirmation(&mut self, choice: ConfirmChoice) {
        match choice {
            ConfirmChoice::Yes => {
                let count = self.process_table.selected_count();
                self.set_status(format!("Preparing actions for {} process(es)...", count));
                self.request_execute();
            }
            ConfirmChoice::No => {
                self.set_status("Action cancelled");
            }
        }
        self.state = AppState::Normal;
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
                self.process_table.page_up(10);
                FtuiCmd::none()
            }
            Msg::PageDown | Msg::HalfPageDown => {
                self.process_table.page_down(10);
                FtuiCmd::none()
            }

            Msg::ToggleSelection => {
                self.process_table.toggle_selection();
                FtuiCmd::none()
            }
            Msg::SelectRecommended => {
                self.process_table.select_recommended();
                FtuiCmd::none()
            }
            Msg::SelectAll => {
                self.process_table.select_all();
                FtuiCmd::none()
            }
            Msg::DeselectAll => {
                self.process_table.deselect_all();
                FtuiCmd::none()
            }
            Msg::InvertSelection => {
                self.process_table.invert_selection();
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

            Msg::RequestExecute => {
                let selected_pids = self.process_table.get_selected();
                let selected_count = selected_pids.len();
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
                        FtuiCmd::task_named("execute-selected", move || {
                            Msg::ExecutionComplete(execute(selected_pids))
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
                        FtuiCmd::task_named("execute-selected", move || {
                            Msg::ExecutionComplete(Ok(ExecutionOutcome {
                                mode: Some("skeleton".to_string()),
                                attempted: selected_count,
                                succeeded: 0,
                                failed: 0,
                            }))
                        }),
                    ])
                }
            }
            Msg::ConfirmExecute => {
                self.handle_confirmation(ConfirmChoice::Yes);
                FtuiCmd::none()
            }
            Msg::CancelExecute => {
                self.handle_confirmation(ConfirmChoice::No);
                FtuiCmd::none()
            }
            Msg::RequestRefresh => {
                tracing::info!(target: "tui.user_input", action = "refresh_requested", "Refresh requested");
                if let Some(refresh) = self.refresh_op.clone() {
                    self.set_status("Refreshing process list...");
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log("refresh: starting"),
                        FtuiCmd::task_named("refresh-processes", move || {
                            Msg::RefreshComplete(refresh())
                        }),
                    ])
                } else {
                    self.set_status("Refreshing process list (skeleton mode)...");
                    let prior_rows = self.process_table.rows.clone();
                    FtuiCmd::sequence(vec![
                        FtuiCmd::log("refresh: skeleton mode"),
                        FtuiCmd::task_named("refresh-processes", move || {
                            Msg::RefreshComplete(Ok(prior_rows))
                        }),
                    ])
                }
            }
            Msg::ExportEvidenceLedger => {
                self.set_status("Evidence ledger export is not wired yet");
                FtuiCmd::none()
            }

            Msg::ProcessesScanned(rows) => {
                self.process_table.set_rows(rows);
                self.set_status("Process list refreshed");
                FtuiCmd::none()
            }
            Msg::RefreshComplete(Ok(rows)) => {
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
            Msg::RefreshComplete(Err(error)) => {
                tracing::error!(target: "tui.async_complete", error = %error, "Refresh failed");
                self.set_status(format!("Refresh failed: {}", error));
                self.push_toast(
                    format!("Refresh failed: {}", error),
                    ToastIcon::Error,
                    ToastStyle::Error,
                );
                FtuiCmd::log(format!("refresh: failed ({})", error))
            }
            Msg::ExecutionComplete(Ok(outcome)) => {
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
            Msg::ExecutionComplete(Err(error)) => {
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
            self.process_table.toggle_selection();
            return FtuiCmd::none();
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
            FtuiKeyCode::PageDown => self.process_table.page_down(10),
            FtuiKeyCode::PageUp => self.process_table.page_up(10),
            FtuiKeyCode::Char('d') if key.modifiers.contains(FtuiModifiers::CTRL) => {
                self.process_table.page_down(10)
            }
            FtuiKeyCode::Char('u') if key.modifiers.contains(FtuiModifiers::CTRL) => {
                self.process_table.page_up(10)
            }
            FtuiKeyCode::Char('a') => self.process_table.select_recommended(),
            FtuiKeyCode::Char('A') => self.process_table.select_all(),
            FtuiKeyCode::Char('u') => self.process_table.deselect_all(),
            FtuiKeyCode::Char('x') => self.process_table.invert_selection(),
            FtuiKeyCode::Enter => self.toggle_detail_visibility(),
            FtuiKeyCode::Char('r') => return FtuiCmd::msg(Msg::RequestRefresh),
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
                self.handle_confirmation(choice);
                if self.take_execute() {
                    return FtuiCmd::msg(Msg::RequestExecute);
                }
            }
            FtuiKeyCode::Escape => {
                self.confirm_dialog.cancel();
                self.state = AppState::Normal;
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
        frame.clear();
        draw_ftui_text(frame, 0, 0, "Process Triage - ftui model");
        draw_ftui_text(frame, 0, 1, &format!("State: {:?}", self.state));

        let status = self
            .status_message
            .as_deref()
            .unwrap_or("Ready | Press ? for help");
        draw_ftui_text(frame, 0, 2, status);

        // Render toast notifications as overlay
        if !self.notifications.is_empty() {
            let area = Rect::new(0, 0, frame.width(), frame.height());
            NotificationStack::new(&self.notifications).render(area, frame);
        }
    }

    fn subscriptions(&self) -> Vec<Box<dyn Subscription<Self::Message>>> {
        vec![Box::new(Every::with_id(
            0x5054_5449_434B,
            Duration::from_secs(5),
            || Msg::Tick,
        ))]
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
        }
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
        let rows = vec![make_row(99)];
        <App as FtuiModel>::update(&mut app, Msg::RefreshComplete(Ok(rows)));
        assert_eq!(app.process_table.rows.len(), 1);
        assert!(app.status_message.as_deref().unwrap().contains("refreshed"));
    }

    #[test]
    fn test_refresh_complete_err() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::RefreshComplete(Err("network error".to_string())),
        );
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
        <App as FtuiModel>::update(&mut app, Msg::ExecutionComplete(Ok(outcome)));
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
        <App as FtuiModel>::update(&mut app, Msg::ExecutionComplete(Ok(outcome)));
        assert!(app.status_message.as_deref().unwrap().contains("dry_run"));
    }

    #[test]
    fn test_execution_complete_err() {
        let mut app = App::new();
        <App as FtuiModel>::update(
            &mut app,
            Msg::ExecutionComplete(Err("permission denied".to_string())),
        );
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
    fn test_request_refresh_take_refresh() {
        let mut app = App::new();
        assert!(!app.take_refresh());

        app.request_refresh();
        assert!(app.take_refresh());
        assert!(!app.take_refresh()); // consumed
    }

    #[test]
    fn test_request_execute_take_execute() {
        let mut app = App::new();
        assert!(!app.take_execute());

        app.request_execute();
        assert!(app.take_execute());
        assert!(!app.take_execute()); // consumed
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
    fn test_default_impl_matches_new() {
        let a = App::new();
        let b = App::default();
        assert_eq!(a.state, b.state);
        assert_eq!(a.should_quit(), b.should_quit());
    }
}
