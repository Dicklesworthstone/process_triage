//! Main TUI application state and event loop.
//!
//! Manages the overall TUI application state, terminal setup/teardown,
//! and the main render/event loop.

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::Rect,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

use super::events::KeyBindings;
use super::layout::{Breakpoint, LayoutState, ResponsiveLayout};
use super::theme::Theme;
use super::widgets::{
    ConfirmChoice, ConfirmDialog, ConfirmDialogState, DetailView, ProcessDetail, ProcessTable,
    ProcessTableState, SearchInput, SearchInputState,
};
use super::{TuiError, TuiResult};

/// Focus targets in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusTarget {
    /// Search input field.
    Search,
    /// Process table.
    ProcessList,
    /// Action panel.
    Actions,
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
        }
    }

    /// Get the current layout breakpoint.
    pub fn breakpoint(&self) -> Breakpoint {
        self.layout_state.breakpoint()
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
            FocusTarget::Actions => FocusTarget::Search,
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

    /// Handle a terminal event.
    pub fn handle_event(&mut self, event: Event) -> TuiResult<()> {
        // Handle resize events first (SIGWINCH)
        if let Event::Resize(width, height) = event {
            self.update_layout(width, height);
            self.needs_redraw = true;
            return Ok(());
        }

        // If confirmation dialog is visible, route events there first
        if self.confirm_dialog.visible {
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Left | KeyCode::Char('h') => {
                            self.confirm_dialog.select_left();
                        }
                        KeyCode::Right | KeyCode::Char('l') => {
                            self.confirm_dialog.select_right();
                        }
                        KeyCode::Tab => {
                            self.confirm_dialog.toggle();
                        }
                        KeyCode::Enter => {
                            let choice = self.confirm_dialog.confirm();
                            self.handle_confirmation(choice);
                        }
                        KeyCode::Esc => {
                            self.confirm_dialog.cancel();
                            self.state = AppState::Normal;
                        }
                        _ => {}
                    }
                }
            }
            self.needs_redraw = true;
            return Ok(());
        }

        // Handle based on current state
        match self.state {
            AppState::Searching => {
                self.handle_search_event(event)?;
            }
            AppState::Help => {
                if let Event::Key(key) = event {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                                self.state = AppState::Normal;
                            }
                            _ => {}
                        }
                    }
                }
            }
            AppState::Normal => {
                self.handle_normal_event(event)?;
            }
            AppState::Quitting | AppState::Confirming => {}
        }

        self.needs_redraw = true;
        Ok(())
    }

    /// Handle events in normal mode.
    fn handle_normal_event(&mut self, event: Event) -> TuiResult<()> {
        if let Event::Key(key) = event {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    // Navigation
                    KeyCode::Char('j') | KeyCode::Down => {
                        self.process_table.cursor_down();
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.process_table.cursor_up();
                    }
                    KeyCode::Home => {
                        self.process_table.cursor_home();
                    }
                    KeyCode::End => {
                        self.process_table.cursor_end();
                    }
                    KeyCode::PageDown => {
                        self.process_table.page_down(10);
                    }
                    KeyCode::PageUp => {
                        self.process_table.page_up(10);
                    }
                    KeyCode::Char('d')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        self.process_table.page_down(10);
                    }
                    KeyCode::Char('u')
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        self.process_table.page_up(10);
                    }
                    KeyCode::Char('n') => {
                        self.process_table.cursor_down();
                    }
                    KeyCode::Char('N') => {
                        self.process_table.cursor_up();
                    }

                    // Selection
                    KeyCode::Char(' ') => {
                        self.process_table.toggle_selection();
                    }
                    KeyCode::Char('a') => {
                        self.process_table.select_recommended();
                    }
                    KeyCode::Char('A') => {
                        self.process_table.select_all();
                    }
                    KeyCode::Char('u') => {
                        self.process_table.deselect_all();
                    }
                    KeyCode::Char('x') => {
                        self.process_table.invert_selection();
                    }

                    // Search
                    KeyCode::Char('/') => {
                        self.state = AppState::Searching;
                        self.focus = FocusTarget::Search;
                        self.update_focus();
                    }

                    // Focus cycling
                    KeyCode::Tab => {
                        self.cycle_focus();
                    }

                    // Actions
                    KeyCode::Enter => {
                        self.toggle_detail_visibility();
                    }
                    KeyCode::Char('e') => {
                        self.show_execute_confirmation();
                    }
                    KeyCode::Char('r') => {
                        self.set_status("Refreshing process list...");
                        self.request_refresh();
                    }
                    KeyCode::Char('s') => {
                        self.set_detail_view(DetailView::Summary);
                    }
                    KeyCode::Char('t') => {
                        self.set_detail_view(DetailView::Genealogy);
                    }
                    KeyCode::Char('g') => {
                        if self.detail_view == DetailView::GalaxyBrain {
                            self.set_detail_view(DetailView::Summary);
                        } else {
                            self.set_detail_view(DetailView::GalaxyBrain);
                        }
                    }

                    // Help
                    KeyCode::Char('?') => {
                        self.state = AppState::Help;
                    }

                    // Quit
                    KeyCode::Char('q') | KeyCode::Esc => {
                        self.state = AppState::Quitting;
                    }

                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Handle search input events.
    fn handle_search_event(&mut self, event: Event) -> TuiResult<()> {
        if let Event::Key(key) = event {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Esc => {
                        self.state = AppState::Normal;
                        self.focus = FocusTarget::ProcessList;
                        self.update_focus();
                    }
                    KeyCode::Enter => {
                        self.search.commit();
                        self.apply_search_filter();
                        self.state = AppState::Normal;
                        self.focus = FocusTarget::ProcessList;
                        self.update_focus();
                    }
                    KeyCode::Up => {
                        self.search.history_prev();
                    }
                    KeyCode::Down => {
                        self.search.history_next();
                    }
                    KeyCode::Backspace => {
                        self.search.backspace();
                    }
                    KeyCode::Char(c) => {
                        self.search.type_char(c);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
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

    /// Render the application.
    pub fn render(&mut self, frame: &mut Frame) {
        let size = frame.area();

        // Update layout state for current terminal size
        self.update_layout(size.width, size.height);

        // Create responsive layout calculator
        let layout = ResponsiveLayout::new(size);

        // Check if terminal is too small
        if layout.is_too_small() {
            self.render_too_small_message(frame, size);
            return;
        }

        // Get layout areas based on current breakpoint
        let areas = layout.main_areas();

        // Render main content areas
        self.render_search(frame, areas.search);
        let list_area = if !self.detail_visible {
            if let Some(detail) = areas.detail {
                let extra_width = detail.width + areas.aux.map(|a| a.width).unwrap_or(0);
                Rect::new(
                    areas.list.x,
                    areas.list.y,
                    areas.list.width.saturating_add(extra_width),
                    areas.list.height,
                )
            } else {
                areas.list
            }
        } else {
            areas.list
        };
        self.render_process_table(frame, list_area);
        self.render_status_bar(frame, areas.status);

        // Render detail pane when available (medium/large)
        if self.detail_visible {
            if let Some(detail) = areas.detail {
                self.render_detail_pane(frame, detail);
            }
            if let Some(aux) = areas.aux {
                self.render_aux_pane(frame, aux);
            }
        }

        // Render overlays using responsive popup areas
        if self.confirm_dialog.visible {
            let popup_area = layout.popup_area(60, 50);
            self.render_confirm_dialog(frame, popup_area);
        }

        if self.state == AppState::Help {
            let help_area = layout.popup_area(50, 60);
            self.render_help_overlay(frame, help_area);
        }
    }

    /// Render message when terminal is too small.
    fn render_too_small_message(&self, frame: &mut Frame, area: Rect) {
        let message = Paragraph::new("Terminal too small.\nResize for full view.")
            .style(self.theme.style_muted())
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(message, area);
    }

    /// Render detail pane with current selection.
    fn render_detail_pane(&self, frame: &mut Frame, area: Rect) {
        let row = self.process_table.current_row();
        let selected = row
            .map(|r| self.process_table.selected.contains(&r.pid))
            .unwrap_or(false);
        if self.detail_view == DetailView::GalaxyBrain {
            let layout = ResponsiveLayout::new(area);
            let gb = layout.galaxy_brain_areas();

            let math_text = row
                .and_then(|r| r.galaxy_brain.as_deref())
                .unwrap_or("No math trace available.");

            let math_block = Block::default()
                .borders(Borders::ALL)
                .title(" Math Trace ")
                .border_style(self.theme.style_border());

            let math_panel = Paragraph::new(math_text)
                .block(math_block)
                .style(self.theme.style_normal())
                .wrap(Wrap { trim: false });

            frame.render_widget(math_panel, gb.math);

            let summary = ProcessDetail::new()
                .theme(&self.theme)
                .row(row, selected)
                .view(DetailView::Summary);
            frame.render_widget(summary, gb.explanation);
            return;
        }

        let detail = ProcessDetail::new()
            .theme(&self.theme)
            .row(row, selected)
            .view(self.detail_view);

        frame.render_widget(detail, area);
    }

    /// Render auxiliary pane (action preview/summary) when available.
    fn render_aux_pane(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Actions ")
            .border_style(self.theme.style_border());
        let mut lines = Vec::new();
        if let Some(row) = self.process_table.current_row() {
            if row.plan_preview.is_empty() {
                lines.push(format!("PID {} • plan not generated", row.pid));
                lines.push("Press e to generate plan".to_string());
            } else {
                lines.push(format!("PID {} • action preview", row.pid));
                for line in &row.plan_preview {
                    lines.push(format!("• {}", line));
                }
            }
        } else {
            lines.push("No process selected".to_string());
        }

        let pane = Paragraph::new(lines.join("\n"))
            .block(block)
            .style(self.theme.style_muted())
            .wrap(Wrap { trim: false });

        frame.render_widget(pane, area);
    }

    /// Render the search input.
    fn render_search(&mut self, frame: &mut Frame, area: Rect) {
        let search = SearchInput::new()
            .theme(&self.theme)
            .placeholder("Type to search processes...");
        frame.render_stateful_widget(search, area, &mut self.search);
    }

    /// Render the process table.
    fn render_process_table(&mut self, frame: &mut Frame, area: Rect) {
        let table = ProcessTable::new().theme(&self.theme);
        frame.render_stateful_widget(table, area, &mut self.process_table);
    }

    /// Render the status bar.
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let status_text = self
            .status_message
            .as_deref()
            .unwrap_or("Ready | Press ? for help");
        let status_style = self.theme.style_muted();
        let status = Paragraph::new(status_text).style(status_style);
        frame.render_widget(status, area);
    }

    /// Render the confirmation dialog.
    fn render_confirm_dialog(&mut self, frame: &mut Frame, area: Rect) {
        let selected = self.process_table.get_selected();
        let details = if selected.len() <= 5 {
            selected
                .iter()
                .map(|pid| format!("PID {}", pid))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            format!("{} processes selected", selected.len())
        };

        let dialog = ConfirmDialog::new()
            .theme(&self.theme)
            .title("Confirm Action")
            .message("Are you sure you want to execute the action on the selected processes?")
            .details(&details)
            .labels("Execute", "Cancel");

        // Clear background and render dialog at the pre-computed area
        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_stateful_widget(dialog, area, &mut self.confirm_dialog);
    }

    /// Render the help overlay.
    fn render_help_overlay(&self, frame: &mut Frame, area: Rect) {
        // Adapt help text based on breakpoint
        let help_text = match self.layout_state.breakpoint() {
            Breakpoint::Minimal => {
                // Compact help for small terminals
                r#"
Navigation: j/k/Home/End
Search: /
Select: Space/a/A/u/x
Execute: e
Detail: Enter
Views: s/t/g
Help: ?  Quit: q
"#
            }
            _ => {
                // Full help for medium/large terminals
                r#"
  Process Triage TUI Help

  Navigation:
    j/Down      Move down
    k/Up        Move up
    Home        Go to top
    End         Go to bottom
    Ctrl+d      Page down
    Ctrl+u      Page up
    Tab         Cycle focus
    n/N         Next/prev match

  Actions:
    /           Start search
    Space       Toggle selection
    a           Select recommended
    A           Select all
    u           Unselect all
    x           Invert selection
    e           Execute action
    r           Refresh list
    Enter       Toggle detail pane
    s           Summary view
    t           Genealogy view
    g           Galaxy-brain view

  General:
    ?           Toggle help
    q/Esc       Quit
"#
            }
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Help ")
            .border_style(self.theme.style_border_focused());

        let help = Paragraph::new(help_text)
            .block(block)
            .style(self.theme.style_normal());

        // Clear background and render at the pre-computed responsive area
        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_widget(help, area);
    }

    /// Check if the application should quit.
    pub fn should_quit(&self) -> bool {
        self.state == AppState::Quitting
    }
}

/// Initialize the terminal for TUI rendering.
fn init_terminal() -> TuiResult<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().map_err(|e| TuiError::TerminalInit(e.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| TuiError::TerminalInit(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map_err(|e| TuiError::TerminalInit(e.to_string()))
}

/// Restore the terminal to its original state.
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> TuiResult<()> {
    disable_raw_mode().map_err(|e| TuiError::TerminalRestore(e.to_string()))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .map_err(|e| TuiError::TerminalRestore(e.to_string()))?;
    terminal
        .show_cursor()
        .map_err(|e| TuiError::TerminalRestore(e.to_string()))?;
    Ok(())
}

/// Run the TUI application.
///
/// This is the main entry point for the TUI. It sets up the terminal,
/// runs the event loop, and restores the terminal on exit.
pub fn run_tui(mut app: App) -> TuiResult<()> {
    run_tui_with_handlers(&mut app, |_| Ok(()), |_| Ok(()))
}

pub fn run_tui_with_refresh<F>(app: &mut App, mut on_refresh: F) -> TuiResult<()>
where
    F: FnMut(&mut App) -> TuiResult<()>,
{
    run_tui_with_handlers(app, &mut on_refresh, |_| Ok(()))
}

pub fn run_tui_with_handlers<F, G>(
    app: &mut App,
    mut on_refresh: F,
    mut on_execute: G,
) -> TuiResult<()>
where
    F: FnMut(&mut App) -> TuiResult<()>,
    G: FnMut(&mut App) -> TuiResult<()>,
{
    let mut terminal = init_terminal()?;

    let result = run_event_loop(&mut terminal, app, &mut on_refresh, &mut on_execute);

    // Always try to restore terminal, even if loop failed
    let restore_result = restore_terminal(&mut terminal);

    // Return first error if any
    result?;
    restore_result
}

/// Main event loop.
fn run_event_loop<F, G>(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    on_refresh: &mut F,
    on_execute: &mut G,
) -> TuiResult<()>
where
    F: FnMut(&mut App) -> TuiResult<()>,
    G: FnMut(&mut App) -> TuiResult<()>,
{
    loop {
        if app.take_redraw() {
            terminal.draw(|frame| app.render(frame))?;
        }

        // Poll for events with timeout
        if event::poll(Duration::from_millis(100))? {
            let event = event::read()?;
            app.handle_event(event)?;
        }

        if app.take_refresh() {
            on_refresh(app)?;
            app.request_redraw();
        }

        if app.take_execute() {
            on_execute(app)?;
            app.request_redraw();
        }

        if app.should_quit() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};

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
    fn test_toggle_galaxy_brain_view() {
        let mut app = App::new();
        assert_eq!(app.detail_view, DetailView::Summary);

        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Char('g'),
            KeyModifiers::NONE,
        )))
        .unwrap();
        assert_eq!(app.detail_view, DetailView::GalaxyBrain);
        assert!(app.detail_visible);

        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Char('g'),
            KeyModifiers::NONE,
        )))
        .unwrap();
        assert_eq!(app.detail_view, DetailView::Summary);
    }

    #[test]
    fn test_toggle_detail_visibility_with_enter() {
        let mut app = App::new();
        let initial = app.detail_visible;
        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )))
        .unwrap();
        assert_eq!(app.detail_visible, !initial);
    }

    #[test]
    fn test_help_overlay_toggle() {
        let mut app = App::new();
        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Char('?'),
            KeyModifiers::NONE,
        )))
        .unwrap();
        assert_eq!(app.state, AppState::Help);

        app.handle_event(Event::Key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
        )))
        .unwrap();
        assert_eq!(app.state, AppState::Normal);
    }
}
