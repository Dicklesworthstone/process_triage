//! Event handling for the Process Triage TUI.
//!
//! Provides keyboard event handling with customizable key bindings.

use ftui::{Event, KeyCode, KeyEvent, Modifiers};

/// Configurable key bindings for TUI navigation.
#[derive(Debug, Clone)]
pub struct KeyBindings {
    /// Key to quit the application.
    pub quit: Vec<KeyEvent>,
    /// Key to confirm selection.
    pub confirm: Vec<KeyEvent>,
    /// Key to cancel/go back.
    pub cancel: Vec<KeyEvent>,
    /// Key to show help.
    pub help: Vec<KeyEvent>,
    /// Key to focus search input.
    pub search: Vec<KeyEvent>,
    /// Key to select next item.
    pub next: Vec<KeyEvent>,
    /// Key to select previous item.
    pub prev: Vec<KeyEvent>,
    /// Key to toggle selection.
    pub toggle: Vec<KeyEvent>,
    /// Key to select all.
    pub select_all: Vec<KeyEvent>,
    /// Key to deselect all.
    pub deselect_all: Vec<KeyEvent>,
    /// Key to execute selected actions.
    pub execute: Vec<KeyEvent>,
    /// Key to switch to next tab/pane.
    pub next_tab: Vec<KeyEvent>,
    /// Key to switch to previous tab/pane.
    pub prev_tab: Vec<KeyEvent>,
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self {
            quit: vec![
                KeyEvent::new(KeyCode::Char('q')),
                KeyEvent::new(KeyCode::Char('c')).with_modifiers(Modifiers::CTRL),
            ],
            confirm: vec![KeyEvent::new(KeyCode::Enter)],
            cancel: vec![KeyEvent::new(KeyCode::Escape)],
            help: vec![
                KeyEvent::new(KeyCode::Char('?')),
                KeyEvent::new(KeyCode::F(1)),
            ],
            search: vec![KeyEvent::new(KeyCode::Char('/'))],
            next: vec![
                KeyEvent::new(KeyCode::Down),
                KeyEvent::new(KeyCode::Char('j')),
            ],
            prev: vec![
                KeyEvent::new(KeyCode::Up),
                KeyEvent::new(KeyCode::Char('k')),
            ],
            toggle: vec![KeyEvent::new(KeyCode::Char(' '))],
            // Match legacy behavior in `tui/app.rs`.
            select_all: vec![KeyEvent::new(KeyCode::Char('A'))],
            deselect_all: vec![KeyEvent::new(KeyCode::Char('u'))],
            execute: vec![KeyEvent::new(KeyCode::Char('e'))],
            next_tab: vec![KeyEvent::new(KeyCode::Tab)],
            prev_tab: vec![KeyEvent::new(KeyCode::BackTab)],
        }
    }
}

impl KeyBindings {
    fn matches_any(bindings: &[KeyEvent], key: &KeyEvent) -> bool {
        // Ignore KeyEventKind when matching: ftui will emit both Press and Repeat,
        // and we want bindings to apply to either.
        //
        // Modifier matching allows an extra SHIFT bit. Many terminals report SHIFT
        // even when the shifted character is already encoded in KeyCode::Char('?').
        bindings
            .iter()
            .any(|b| b.code == key.code && mods_match(b.modifiers, key.modifiers))
    }

    /// Check if a key event matches any quit binding.
    pub fn is_quit(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.quit, key)
    }

    /// Check if a key event matches any confirm binding.
    pub fn is_confirm(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.confirm, key)
    }

    /// Check if a key event matches any cancel binding.
    pub fn is_cancel(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.cancel, key)
    }

    /// Check if a key event matches any help binding.
    pub fn is_help(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.help, key)
    }

    /// Check if a key event matches any search binding.
    pub fn is_search(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.search, key)
    }

    /// Check if a key event matches any next binding.
    pub fn is_next(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.next, key)
    }

    /// Check if a key event matches any prev binding.
    pub fn is_prev(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.prev, key)
    }

    /// Check if a key event matches any toggle binding.
    pub fn is_toggle(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.toggle, key)
    }

    /// Check if a key event matches any execute binding.
    pub fn is_execute(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.execute, key)
    }

    /// Check if a key event matches any next-tab binding.
    pub fn is_next_tab(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.next_tab, key)
    }

    /// Check if a key event matches any prev-tab binding.
    pub fn is_prev_tab(&self, key: &KeyEvent) -> bool {
        Self::matches_any(&self.prev_tab, key)
    }
}

fn mods_match(binding: Modifiers, observed: Modifiers) -> bool {
    observed == binding || observed == (binding | Modifiers::SHIFT)
}

/// Application-level action resulting from event handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAction {
    /// No action needed.
    None,
    /// Quit the application.
    Quit,
    /// Show help dialog.
    ShowHelp,
    /// Execute selected actions.
    Execute,
    /// Focus changed to another widget.
    FocusChanged,
    /// Data needs to be refreshed.
    Refresh,
    /// State changed, redraw needed.
    Redraw,
}

/// Handle a terminal event and return the resulting action.
pub fn handle_event(event: Event, bindings: &KeyBindings) -> AppAction {
    match event {
        Event::Key(key) => handle_key_event(&key, bindings),
        Event::Mouse(_mouse) => {
            // Mouse events are handled by individual widgets
            AppAction::None
        }
        Event::Resize { .. } => AppAction::Redraw,
        _ => AppAction::None,
    }
}

fn handle_key_event(key: &KeyEvent, bindings: &KeyBindings) -> AppAction {
    if bindings.is_quit(key) {
        return AppAction::Quit;
    }
    if bindings.is_help(key) {
        return AppAction::ShowHelp;
    }
    if bindings.is_execute(key) {
        return AppAction::Execute;
    }

    AppAction::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_bindings() {
        let bindings = KeyBindings::default();

        // Test quit bindings
        let q_key = KeyEvent::new(KeyCode::Char('q'));
        assert!(bindings.is_quit(&q_key));

        let ctrl_c = KeyEvent::new(KeyCode::Char('c')).with_modifiers(Modifiers::CTRL);
        assert!(bindings.is_quit(&ctrl_c));

        // Esc is cancel by default; app state decides whether it quits.
        let esc = KeyEvent::new(KeyCode::Escape);
        assert!(!bindings.is_quit(&esc));
        assert!(bindings.is_cancel(&esc));

        // Test navigation
        let down = KeyEvent::new(KeyCode::Down);
        assert!(bindings.is_next(&down));

        let j = KeyEvent::new(KeyCode::Char('j'));
        assert!(bindings.is_next(&j));
    }

    #[test]
    fn test_handle_quit_event() {
        let bindings = KeyBindings::default();
        let quit_event = Event::Key(KeyEvent::new(KeyCode::Char('q')));

        let action = handle_event(quit_event, &bindings);
        assert_eq!(action, AppAction::Quit);
    }

    #[test]
    fn test_resize_triggers_redraw() {
        let bindings = KeyBindings::default();
        let resize_event = Event::Resize {
            width: 80,
            height: 24,
        };

        let action = handle_event(resize_event, &bindings);
        assert_eq!(action, AppAction::Redraw);
    }

    #[test]
    fn test_help_bindings() {
        let bindings = KeyBindings::default();

        let question = KeyEvent::new(KeyCode::Char('?'));
        assert!(bindings.is_help(&question));

        let f1 = KeyEvent::new(KeyCode::F(1));
        assert!(bindings.is_help(&f1));

        let f2 = KeyEvent::new(KeyCode::F(2));
        assert!(!bindings.is_help(&f2));
    }

    #[test]
    fn test_navigation_bindings() {
        let bindings = KeyBindings::default();

        assert!(bindings.is_next(&KeyEvent::new(KeyCode::Down)));
        assert!(bindings.is_next(&KeyEvent::new(KeyCode::Char('j'))));
        assert!(!bindings.is_next(&KeyEvent::new(KeyCode::Up)));

        assert!(bindings.is_prev(&KeyEvent::new(KeyCode::Up)));
        assert!(bindings.is_prev(&KeyEvent::new(KeyCode::Char('k'))));
        assert!(!bindings.is_prev(&KeyEvent::new(KeyCode::Down)));
    }

    #[test]
    fn test_selection_bindings() {
        let bindings = KeyBindings::default();

        assert!(bindings.is_toggle(&KeyEvent::new(KeyCode::Char(' '))));
        assert!(!bindings.is_toggle(&KeyEvent::new(KeyCode::Char('x'))));
    }

    #[test]
    fn test_execute_binding() {
        let bindings = KeyBindings::default();

        let e_key = KeyEvent::new(KeyCode::Char('e'));
        assert!(bindings.is_execute(&e_key));

        let action = handle_event(Event::Key(e_key), &bindings);
        assert_eq!(action, AppAction::Execute);
    }

    #[test]
    fn test_help_event_returns_show_help() {
        let bindings = KeyBindings::default();
        let help_event = Event::Key(KeyEvent::new(KeyCode::Char('?')));

        let action = handle_event(help_event, &bindings);
        assert_eq!(action, AppAction::ShowHelp);
    }

    #[test]
    fn test_tab_bindings() {
        let bindings = KeyBindings::default();

        assert!(bindings.is_next_tab(&KeyEvent::new(KeyCode::Tab)));
        assert!(!bindings.is_next_tab(&KeyEvent::new(KeyCode::BackTab)));

        assert!(bindings.is_prev_tab(&KeyEvent::new(KeyCode::BackTab)));
        assert!(!bindings.is_prev_tab(&KeyEvent::new(KeyCode::Tab)));
    }

    #[test]
    fn test_confirm_cancel_bindings() {
        let bindings = KeyBindings::default();

        assert!(bindings.is_confirm(&KeyEvent::new(KeyCode::Enter)));
        assert!(!bindings.is_confirm(&KeyEvent::new(KeyCode::Escape)));

        assert!(bindings.is_cancel(&KeyEvent::new(KeyCode::Escape)));
        assert!(!bindings.is_cancel(&KeyEvent::new(KeyCode::Enter)));
    }

    #[test]
    fn test_search_binding() {
        let bindings = KeyBindings::default();

        assert!(bindings.is_search(&KeyEvent::new(KeyCode::Char('/'))));
        assert!(!bindings.is_search(&KeyEvent::new(KeyCode::Char('s'))));
    }

    #[test]
    fn test_shift_modifier_tolerance() {
        let bindings = KeyBindings::default();

        // '?' with SHIFT should still match (terminals often report SHIFT+/)
        let shifted_q = KeyEvent::new(KeyCode::Char('?')).with_modifiers(Modifiers::SHIFT);
        assert!(bindings.is_help(&shifted_q));
    }

    #[test]
    fn test_unbound_key_returns_none() {
        let bindings = KeyBindings::default();
        let unbound = Event::Key(KeyEvent::new(KeyCode::Char('z')));

        let action = handle_event(unbound, &bindings);
        assert_eq!(action, AppAction::None);
    }

    #[test]
    fn test_mods_match_exact() {
        assert!(mods_match(Modifiers::CTRL, Modifiers::CTRL));
        assert!(mods_match(Modifiers::empty(), Modifiers::empty()));
    }

    #[test]
    fn test_mods_match_shift_tolerance() {
        assert!(mods_match(Modifiers::empty(), Modifiers::SHIFT));
        assert!(mods_match(
            Modifiers::CTRL,
            Modifiers::CTRL | Modifiers::SHIFT
        ));
    }

    #[test]
    fn test_mods_match_rejects_alt() {
        assert!(!mods_match(Modifiers::empty(), Modifiers::ALT));
        assert!(!mods_match(Modifiers::CTRL, Modifiers::ALT));
    }
}
