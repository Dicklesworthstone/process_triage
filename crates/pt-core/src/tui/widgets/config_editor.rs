//! Configuration editor widget.
//!
//! Form-based editor for modifying Process Triage configuration values.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, StatefulWidget, Widget},
};

use crate::tui::theme::Theme;

/// A configuration field with name, value, and type.
#[derive(Debug, Clone)]
pub struct ConfigField {
    /// Field name.
    pub name: String,
    /// Current value as string.
    pub value: String,
    /// Field type for validation.
    pub field_type: ConfigFieldType,
    /// Description/help text.
    pub description: String,
    /// Whether the field has been modified.
    pub modified: bool,
    /// Validation error message (if any).
    pub error: Option<String>,
}

/// Type of configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFieldType {
    /// Text string.
    Text,
    /// Integer number.
    Integer,
    /// Floating point number.
    Float,
    /// Boolean (yes/no).
    Boolean,
    /// Selection from fixed options.
    Select,
}

/// Configuration editor widget.
#[derive(Debug)]
pub struct ConfigEditor<'a> {
    /// Block wrapper.
    block: Option<Block<'a>>,
    /// Theme for styling.
    theme: Option<&'a Theme>,
}

impl<'a> Default for ConfigEditor<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ConfigEditor<'a> {
    /// Create a new config editor.
    pub fn new() -> Self {
        Self {
            block: None,
            theme: None,
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

    fn styled_block(&self, focused: bool, modified: bool) -> Block<'a> {
        let title = if modified {
            " Configuration [modified] "
        } else {
            " Configuration "
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
}

impl<'a> StatefulWidget for ConfigEditor<'a> {
    type State = ConfigEditorState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let focused = state.focused;
        let any_modified = state.fields.iter().any(|f| f.modified);
        let block = self
            .block
            .clone()
            .unwrap_or_else(|| self.styled_block(focused, any_modified));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 2 || inner.height == 0 {
            return;
        }

        if state.fields.is_empty() {
            let msg = "No configuration fields";
            let style = if let Some(theme) = self.theme {
                theme.style_muted()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let x = inner.x + (inner.width.saturating_sub(msg.len() as u16)) / 2;
            let y = inner.y + inner.height / 2;

            if y < inner.bottom() {
                for (i, ch) in msg.chars().enumerate() {
                    if x + i as u16 >= inner.right() {
                        break;
                    }
                    buf[(x + i as u16, y)].set_char(ch).set_style(style);
                }
            }
            return;
        }

        // Render fields
        let name_width = 20.min(inner.width / 3);
        let value_start = inner.x + name_width + 2;

        for (i, field) in state.fields.iter().enumerate() {
            let y = inner.y + i as u16;
            if y >= inner.bottom() {
                break;
            }

            let is_cursor = i == state.cursor;

            // Field name
            let name_style = if is_cursor {
                if let Some(theme) = self.theme {
                    theme.style_highlight()
                } else {
                    Style::default().add_modifier(Modifier::BOLD)
                }
            } else if let Some(theme) = self.theme {
                theme.style_normal()
            } else {
                Style::default()
            };

            for (j, ch) in field.name.chars().enumerate() {
                if inner.x + j as u16 >= value_start.saturating_sub(1) {
                    break;
                }
                buf[(inner.x + j as u16, y)]
                    .set_char(ch)
                    .set_style(name_style);
            }

            // Separator
            let sep_x = value_start.saturating_sub(1);
            if sep_x < inner.right() {
                buf[(sep_x, y)].set_char(':').set_style(name_style);
            }

            // Field value
            let value_style = if field.error.is_some() {
                if let Some(theme) = self.theme {
                    theme.style_error()
                } else {
                    Style::default().fg(Color::Red)
                }
            } else if field.modified {
                if let Some(theme) = self.theme {
                    theme.style_warning()
                } else {
                    Style::default().fg(Color::Yellow)
                }
            } else if let Some(theme) = self.theme {
                theme.style_normal()
            } else {
                Style::default()
            };

            // Add cursor indicator if editing this field
            let value_display = if is_cursor && state.editing {
                format!("{}_", field.value)
            } else {
                field.value.clone()
            };

            for (j, ch) in value_display.chars().enumerate() {
                if value_start + j as u16 >= inner.right() {
                    break;
                }
                buf[(value_start + j as u16, y)]
                    .set_char(ch)
                    .set_style(value_style);
            }
        }

        // Render error message if present
        if let Some(ref field) = state.fields.get(state.cursor) {
            if let Some(ref error) = field.error {
                let error_y = inner.bottom().saturating_sub(1);
                if error_y > inner.y {
                    let error_style = if let Some(theme) = self.theme {
                        theme.style_error()
                    } else {
                        Style::default().fg(Color::Red)
                    };

                    for (i, ch) in error.chars().enumerate() {
                        if inner.x + i as u16 >= inner.right() {
                            break;
                        }
                        buf[(inner.x + i as u16, error_y)]
                            .set_char(ch)
                            .set_style(error_style);
                    }
                }
            }
        }
    }
}

/// State for the config editor widget.
#[derive(Debug)]
pub struct ConfigEditorState {
    /// Whether the editor is focused.
    pub focused: bool,
    /// Configuration fields.
    pub fields: Vec<ConfigField>,
    /// Current cursor position.
    pub cursor: usize,
    /// Whether currently editing a field.
    pub editing: bool,
}

impl Default for ConfigEditorState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigEditorState {
    /// Create a new config editor state.
    pub fn new() -> Self {
        Self {
            focused: false,
            fields: Vec::new(),
            cursor: 0,
            editing: false,
        }
    }

    /// Set the fields.
    pub fn set_fields(&mut self, fields: Vec<ConfigField>) {
        self.fields = fields;
        self.cursor = 0;
        self.editing = false;
    }

    /// Move cursor down.
    pub fn cursor_down(&mut self) {
        if !self.editing && self.cursor + 1 < self.fields.len() {
            self.cursor += 1;
        }
    }

    /// Move cursor up.
    pub fn cursor_up(&mut self) {
        if !self.editing && self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// Start editing current field.
    pub fn start_edit(&mut self) {
        if !self.fields.is_empty() {
            self.editing = true;
        }
    }

    /// Stop editing.
    pub fn stop_edit(&mut self) {
        self.editing = false;
        self.validate_current();
    }

    /// Cancel editing and revert changes.
    pub fn cancel_edit(&mut self) {
        self.editing = false;
        // Revert would need original value storage
    }

    /// Type a character into current field.
    pub fn type_char(&mut self, ch: char) {
        if self.editing {
            if let Some(field) = self.fields.get_mut(self.cursor) {
                field.value.push(ch);
                field.modified = true;
                field.error = None;
            }
        }
    }

    /// Delete last character from current field.
    pub fn backspace(&mut self) {
        if self.editing {
            if let Some(field) = self.fields.get_mut(self.cursor) {
                field.value.pop();
                field.modified = true;
                field.error = None;
            }
        }
    }

    /// Validate current field value.
    fn validate_current(&mut self) {
        if let Some(field) = self.fields.get_mut(self.cursor) {
            field.error = match field.field_type {
                ConfigFieldType::Integer => {
                    if field.value.parse::<i64>().is_err() {
                        Some("Invalid integer".to_string())
                    } else {
                        None
                    }
                }
                ConfigFieldType::Float => {
                    if field.value.parse::<f64>().is_err() {
                        Some("Invalid number".to_string())
                    } else {
                        None
                    }
                }
                ConfigFieldType::Boolean => {
                    let v = field.value.to_lowercase();
                    if !["true", "false", "yes", "no", "1", "0"].contains(&v.as_str()) {
                        Some("Must be true/false".to_string())
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }
    }

    /// Check if any field has been modified.
    pub fn is_modified(&self) -> bool {
        self.fields.iter().any(|f| f.modified)
    }

    /// Check if all fields are valid.
    pub fn is_valid(&self) -> bool {
        self.fields.iter().all(|f| f.error.is_none())
    }

    /// Get modified fields.
    pub fn get_modified(&self) -> Vec<&ConfigField> {
        self.fields.iter().filter(|f| f.modified).collect()
    }

    /// Mark all fields as saved (not modified).
    pub fn mark_saved(&mut self) {
        for field in &mut self.fields {
            field.modified = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields() -> Vec<ConfigField> {
        vec![
            ConfigField {
                name: "min_score".to_string(),
                value: "50".to_string(),
                field_type: ConfigFieldType::Integer,
                description: "Minimum score threshold".to_string(),
                modified: false,
                error: None,
            },
            ConfigField {
                name: "auto_kill".to_string(),
                value: "false".to_string(),
                field_type: ConfigFieldType::Boolean,
                description: "Auto-kill high-confidence targets".to_string(),
                modified: false,
                error: None,
            },
        ]
    }

    #[test]
    fn test_new_state() {
        let state = ConfigEditorState::new();
        assert!(state.fields.is_empty());
        assert_eq!(state.cursor, 0);
        assert!(!state.editing);
    }

    #[test]
    fn test_cursor_navigation() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());

        assert_eq!(state.cursor, 0);

        state.cursor_down();
        assert_eq!(state.cursor, 1);

        state.cursor_down();
        assert_eq!(state.cursor, 1); // Can't go past end

        state.cursor_up();
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn test_editing() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());

        state.start_edit();
        assert!(state.editing);

        state.type_char('1');
        assert_eq!(state.fields[0].value, "501");
        assert!(state.fields[0].modified);

        state.backspace();
        assert_eq!(state.fields[0].value, "50");

        state.stop_edit();
        assert!(!state.editing);
    }

    #[test]
    fn test_validation() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());

        state.start_edit();
        state.fields[0].value = "not_a_number".to_string();
        state.stop_edit();

        assert!(state.fields[0].error.is_some());
        assert!(!state.is_valid());
    }
}
