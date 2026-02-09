//! Search input widget for filtering processes.
//!
//! Uses ftui's built-in TextInput as the primary rendering path, with
//! ratatui legacy compat behind the `ui-legacy` feature gate.

use ftui::widgets::block::Block as FtuiBlock;
use ftui::widgets::input::TextInput as FtuiTextInput;
use ftui::widgets::Widget as FtuiWidget;
use ftui::Style as FtuiStyle;

#[cfg(feature = "ui-legacy")]
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, StatefulWidget, Widget},
};

use crate::tui::theme::Theme;

/// Search input widget for filtering the process list.
#[derive(Debug)]
pub struct SearchInput<'a> {
    /// Placeholder text when empty.
    placeholder: &'a str,
    /// Theme for styling.
    theme: Option<&'a Theme>,
}

impl<'a> Default for SearchInput<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> SearchInput<'a> {
    /// Create a new search input.
    pub fn new() -> Self {
        Self {
            placeholder: "Search processes...",
            theme: None,
        }
    }

    /// Set the placeholder text.
    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = placeholder;
        self
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Render using ftui widgets.
    pub fn render_ftui(
        &self,
        area: ftui::layout::Rect,
        frame: &mut ftui::render::frame::Frame,
        state: &mut SearchInputState,
    ) {
        let focused = state.focused;

        let title = if focused {
            " Search [Enter to filter] "
        } else {
            " Search "
        };

        let border_style = self
            .theme
            .map(|t| {
                let class = if focused {
                    "border.focused"
                } else {
                    "border.normal"
                };
                t.stylesheet().get_or_default(class)
            })
            .unwrap_or_default();

        let block = FtuiBlock::bordered()
            .title(title)
            .border_style(border_style);

        let inner = block.inner(area);
        FtuiWidget::render(&block, area, frame);

        // Configure the ftui TextInput for rendering
        let input_style = self
            .theme
            .map(|t| {
                if focused {
                    t.stylesheet().get_or_default("table.header")
                } else {
                    FtuiStyle::default()
                }
            })
            .unwrap_or_default();

        let placeholder_style = self
            .theme
            .map(|t| t.class("status.warning"))
            .unwrap_or_default();

        let cursor_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("table.selected"))
            .unwrap_or_else(|| FtuiStyle::new().reverse());

        // Build a fresh TextInput widget configured for this render
        let text_input = FtuiTextInput::new()
            .with_value(state.value.clone())
            .with_placeholder(self.placeholder)
            .with_style(input_style)
            .with_placeholder_style(placeholder_style)
            .with_cursor_style(cursor_style)
            .with_focused(focused);

        FtuiWidget::render(&text_input, inner, frame);
    }
}

// ---------------------------------------------------------------------------
// Legacy ratatui StatefulWidget (behind feature gate)
// ---------------------------------------------------------------------------

#[cfg(feature = "ui-legacy")]
impl<'a> StatefulWidget for SearchInput<'a> {
    type State = SearchInputState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let focused = state.focused;

        let title = if focused {
            " Search [Enter to filter] "
        } else {
            " Search "
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

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style);

        let inner = block.inner(area);
        block.render(area, buf);

        let input_style = if let Some(theme) = self.theme {
            if focused {
                theme.style_highlight()
            } else {
                theme.style_normal()
            }
        } else {
            Style::default()
        };

        if state.value.is_empty() && !focused {
            let placeholder_style = if let Some(theme) = self.theme {
                theme.style_muted()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            for (i, ch) in self.placeholder.chars().enumerate() {
                if inner.x + i as u16 >= inner.right() {
                    break;
                }
                buf[(inner.x + i as u16, inner.y)]
                    .set_char(ch)
                    .set_style(placeholder_style);
            }
        } else {
            let display = if focused {
                format!("{}_", state.value)
            } else {
                state.value.clone()
            };

            for (i, ch) in display.chars().enumerate() {
                if inner.x + i as u16 >= inner.right() {
                    break;
                }
                buf[(inner.x + i as u16, inner.y)]
                    .set_char(ch)
                    .set_style(input_style);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SearchInputState
// ---------------------------------------------------------------------------

/// State for the search input widget.
#[derive(Debug, Clone)]
pub struct SearchInputState {
    /// Current input value.
    pub value: String,
    /// Whether the input is focused.
    pub focused: bool,
    /// Search history (last N searches).
    history: Vec<String>,
    /// Current position in history (for up/down navigation).
    history_pos: Option<usize>,
}

impl Default for SearchInputState {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchInputState {
    /// Create a new search input state.
    pub fn new() -> Self {
        Self {
            value: String::new(),
            focused: false,
            history: Vec::new(),
            history_pos: None,
        }
    }

    /// Get the current search value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Set the search value.
    pub fn set_value(&mut self, value: &str) {
        self.value = value.to_string();
    }

    /// Clear the search input.
    pub fn clear(&mut self) {
        self.value.clear();
        self.history_pos = None;
    }

    /// Type a character into the input.
    pub fn type_char(&mut self, ch: char) {
        self.value.push(ch);
    }

    /// Delete the last character.
    pub fn backspace(&mut self) {
        self.value.pop();
    }

    /// Commit current search to history.
    pub fn commit(&mut self) {
        if !self.value.is_empty() {
            // Remove if already in history
            let value = self.value.clone();
            self.history.retain(|h| h != &value);
            // Add to front
            self.history.insert(0, value);
            // Limit history size
            if self.history.len() > 10 {
                self.history.pop();
            }
        }
        self.history_pos = None;
    }

    /// Navigate to previous search in history.
    pub fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }

        let new_pos = match self.history_pos {
            None => 0,
            Some(pos) if pos + 1 < self.history.len() => pos + 1,
            Some(pos) => pos,
        };

        self.history_pos = Some(new_pos);
        self.value = self.history[new_pos].clone();
    }

    /// Navigate to next search in history.
    pub fn history_next(&mut self) {
        match self.history_pos {
            None => {}
            Some(0) => {
                self.history_pos = None;
                self.value.clear();
            }
            Some(pos) => {
                self.history_pos = Some(pos - 1);
                self.value = self.history[pos - 1].clone();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_input_state_new() {
        let state = SearchInputState::new();
        assert_eq!(state.value(), "");
        assert!(state.history.is_empty());
    }

    #[test]
    fn test_set_and_get_value() {
        let mut state = SearchInputState::new();
        state.set_value("test query");
        assert_eq!(state.value(), "test query");
    }

    #[test]
    fn test_clear() {
        let mut state = SearchInputState::new();
        state.set_value("test");
        state.clear();
        assert_eq!(state.value(), "");
    }

    #[test]
    fn test_type_and_backspace() {
        let mut state = SearchInputState::new();
        state.type_char('a');
        state.type_char('b');
        state.type_char('c');
        assert_eq!(state.value(), "abc");

        state.backspace();
        assert_eq!(state.value(), "ab");
    }

    #[test]
    fn test_history() {
        let mut state = SearchInputState::new();

        state.set_value("first");
        state.commit();

        state.set_value("second");
        state.commit();

        state.set_value("third");
        state.commit();

        assert_eq!(state.history.len(), 3);
        assert_eq!(state.history[0], "third");
        assert_eq!(state.history[1], "second");
        assert_eq!(state.history[2], "first");
    }

    #[test]
    fn test_history_navigation() {
        let mut state = SearchInputState::new();

        state.set_value("first");
        state.commit();
        state.set_value("second");
        state.commit();

        state.clear();

        state.history_prev();
        assert_eq!(state.value(), "second");

        state.history_prev();
        assert_eq!(state.value(), "first");

        state.history_next();
        assert_eq!(state.value(), "second");

        state.history_next();
        assert_eq!(state.value(), "");
    }

    #[test]
    fn test_backspace_on_empty_is_noop() {
        let mut state = SearchInputState::new();
        assert_eq!(state.value(), "");
        state.backspace();
        assert_eq!(state.value(), "");
    }

    #[test]
    fn test_history_max_size_evicts_oldest() {
        let mut state = SearchInputState::new();

        // Fill history beyond the 10-item limit
        for i in 0..12 {
            state.set_value(&format!("query_{}", i));
            state.commit();
        }

        // History should be capped at 10
        assert_eq!(state.history.len(), 10);
        // Most recent should be first
        assert_eq!(state.history[0], "query_11");
        // Oldest entries should have been evicted
        assert!(!state.history.contains(&"query_0".to_string()));
        assert!(!state.history.contains(&"query_1".to_string()));
    }

    #[test]
    fn test_history_deduplication() {
        let mut state = SearchInputState::new();

        state.set_value("query");
        state.commit();

        state.set_value("other");
        state.commit();

        state.set_value("query");
        state.commit();

        // Should have only 2 entries, with "query" at front
        assert_eq!(state.history.len(), 2);
        assert_eq!(state.history[0], "query");
        assert_eq!(state.history[1], "other");
    }
}
