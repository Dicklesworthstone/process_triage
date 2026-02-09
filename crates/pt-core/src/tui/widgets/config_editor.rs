//! Configuration editor widget.
//!
//! Form-based editor for modifying Process Triage configuration values.
//! Uses ftui's Block and Paragraph for rendering.

use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText};
use ftui::widgets::block::{Alignment as FtuiAlignment, Block as FtuiBlock};
use ftui::widgets::paragraph::Paragraph as FtuiParagraph;
use ftui::widgets::Widget as FtuiWidget;
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;

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
        Self { theme: None }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    // ── ftui style helpers ──────────────────────────────────────────

    fn border_ftui_style(&self, focused: bool) -> FtuiStyle {
        if let Some(theme) = self.theme {
            let sheet = theme.stylesheet();
            if focused {
                sheet.get_or_default("border.focused")
            } else {
                sheet.get_or_default("border.normal")
            }
        } else if focused {
            FtuiStyle::new().fg(PackedRgba::rgb(0, 255, 255))
        } else {
            FtuiStyle::new().fg(PackedRgba::rgb(128, 128, 128))
        }
    }

    fn name_ftui_style(&self, is_cursor: bool) -> FtuiStyle {
        if is_cursor {
            if let Some(theme) = self.theme {
                theme.stylesheet().get_or_default("table.header")
            } else {
                FtuiStyle::new().bold()
            }
        } else if let Some(theme) = self.theme {
            theme.stylesheet().get_or_default("border.normal")
        } else {
            FtuiStyle::default()
        }
    }

    fn value_ftui_style(&self, field: &ConfigField) -> FtuiStyle {
        if field.error.is_some() {
            if let Some(theme) = self.theme {
                theme.stylesheet().get_or_default("status.error")
            } else {
                FtuiStyle::new().fg(PackedRgba::rgb(255, 0, 0))
            }
        } else if field.modified {
            if let Some(theme) = self.theme {
                theme.class("status.warning")
            } else {
                FtuiStyle::new().fg(PackedRgba::rgb(255, 255, 0))
            }
        } else if let Some(theme) = self.theme {
            theme.stylesheet().get_or_default("border.normal")
        } else {
            FtuiStyle::default()
        }
    }

    fn muted_ftui_style(&self) -> FtuiStyle {
        if let Some(theme) = self.theme {
            theme.class("status.warning")
        } else {
            FtuiStyle::new().fg(PackedRgba::rgb(128, 128, 128))
        }
    }

    fn error_ftui_style(&self) -> FtuiStyle {
        if let Some(theme) = self.theme {
            theme.stylesheet().get_or_default("status.error")
        } else {
            FtuiStyle::new().fg(PackedRgba::rgb(255, 0, 0))
        }
    }

    // ── ftui rendering ──────────────────────────────────────────────

    /// Render the config editor using ftui widgets.
    pub fn render_ftui(
        &self,
        area: ftui::layout::Rect,
        frame: &mut ftui::render::frame::Frame,
        state: &mut ConfigEditorState,
    ) {
        let focused = state.focused;
        let any_modified = state.fields.iter().any(|f| f.modified);

        let title = if any_modified {
            " Configuration [modified] "
        } else {
            " Configuration "
        };

        let block = FtuiBlock::bordered()
            .title(title)
            .border_style(self.border_ftui_style(focused));

        let inner = block.inner(area);
        FtuiWidget::render(&block, area, frame);

        if inner.width < 2 || inner.height == 0 {
            return;
        }

        if state.fields.is_empty() {
            let text: FtuiText = "No configuration fields".into();
            let msg = FtuiParagraph::new(text)
                .style(self.muted_ftui_style())
                .alignment(FtuiAlignment::Center);
            FtuiWidget::render(&msg, inner, frame);
            return;
        }

        // Build field lines
        let mut lines: Vec<FtuiLine> = Vec::new();
        let max_visible = inner.height as usize;

        for (i, field) in state.fields.iter().enumerate() {
            if lines.len() >= max_visible.saturating_sub(1) {
                break;
            }

            let is_cursor = i == state.cursor;
            let name_style = self.name_ftui_style(is_cursor);
            let val_style = self.value_ftui_style(field);

            let value_display = if is_cursor && state.editing {
                format!("{}_", field.value)
            } else {
                field.value.clone()
            };

            lines.push(FtuiLine::from_spans([
                FtuiSpan::styled(field.name.clone(), name_style),
                FtuiSpan::styled(": ", name_style),
                FtuiSpan::styled(value_display, val_style),
            ]));
        }

        // Add error line if present
        if let Some(ref field) = state.fields.get(state.cursor) {
            if let Some(ref error) = field.error {
                if lines.len() < max_visible {
                    lines.push(FtuiLine::from_spans([FtuiSpan::styled(
                        error.clone(),
                        self.error_ftui_style(),
                    )]));
                }
            }
        }

        let text: FtuiText = lines.into_iter().collect();
        FtuiWidget::render(
            &FtuiParagraph::new(text).style(FtuiStyle::default()),
            inner,
            frame,
        );
    }

}

// ---------------------------------------------------------------------------
// ConfigEditorState
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // ── State tests ─────────────────────────────────────────────────

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

    // ── Additional state tests ──────────────────────────────────────

    #[test]
    fn test_is_modified() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());
        assert!(!state.is_modified());

        state.start_edit();
        state.type_char('x');
        assert!(state.is_modified());
    }

    #[test]
    fn test_mark_saved() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());
        state.start_edit();
        state.type_char('x');
        state.stop_edit();
        assert!(state.is_modified());

        state.mark_saved();
        assert!(!state.is_modified());
    }

    #[test]
    fn test_get_modified() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());
        assert!(state.get_modified().is_empty());

        state.start_edit();
        state.type_char('x');
        state.stop_edit();

        let modified = state.get_modified();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].name, "min_score");
    }

    #[test]
    fn test_boolean_validation() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());
        state.cursor_down(); // Move to auto_kill (Boolean)

        state.start_edit();
        state.fields[1].value = "invalid".to_string();
        state.stop_edit();

        assert!(state.fields[1].error.is_some());
        assert!(state.fields[1]
            .error
            .as_ref()
            .unwrap()
            .contains("true/false"));
    }

    #[test]
    fn test_float_validation() {
        let mut state = ConfigEditorState::new();
        let mut fields = sample_fields();
        fields.push(ConfigField {
            name: "threshold".to_string(),
            value: "0.75".to_string(),
            field_type: ConfigFieldType::Float,
            description: "Score threshold".to_string(),
            modified: false,
            error: None,
        });
        state.set_fields(fields);
        state.cursor_down();
        state.cursor_down(); // Move to threshold (Float)

        state.start_edit();
        state.fields[2].value = "abc".to_string();
        state.stop_edit();

        assert!(state.fields[2].error.is_some());
    }

    #[test]
    fn test_cursor_locked_while_editing() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());

        state.start_edit();
        state.cursor_down();
        assert_eq!(state.cursor, 0); // Cursor doesn't move while editing
    }

    #[test]
    fn test_start_edit_empty_fields() {
        let mut state = ConfigEditorState::new();
        state.start_edit();
        assert!(!state.editing); // Can't edit with no fields
    }

    #[test]
    fn test_cancel_edit() {
        let mut state = ConfigEditorState::new();
        state.set_fields(sample_fields());
        state.start_edit();
        state.cancel_edit();
        assert!(!state.editing);
    }

    // ── Builder tests ───────────────────────────────────────────────

    #[test]
    fn test_editor_defaults() {
        let e = ConfigEditor::new();
        assert!(e.theme.is_none());
    }

    #[test]
    fn test_default_impl() {
        let e = ConfigEditor::default();
        assert!(e.theme.is_none());
    }

    #[test]
    fn test_field_type_eq() {
        assert_eq!(ConfigFieldType::Integer, ConfigFieldType::Integer);
        assert_ne!(ConfigFieldType::Integer, ConfigFieldType::Float);
    }
}
