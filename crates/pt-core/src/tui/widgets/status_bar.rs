//! Status bar widget.
//!
//! Bottom-of-screen status bar showing selection count, filter status,
//! mode indicator, and context-sensitive key hints. Uses ftui's StatusLine
//! for rendering.

use ftui::widgets::Widget as FtuiWidget;

use crate::tui::theme::Theme;

// ---------------------------------------------------------------------------
// Mode enum (mirrors AppState for status display)
// ---------------------------------------------------------------------------

/// Display mode for the status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusMode {
    /// Normal browsing.
    #[default]
    Normal,
    /// Search input active.
    Searching,
    /// Confirmation dialog visible.
    Confirming,
    /// Help overlay visible.
    Help,
}

impl StatusMode {
    /// Display label for the mode.
    pub fn label(self) -> &'static str {
        match self {
            StatusMode::Normal => "Normal",
            StatusMode::Searching => "Search",
            StatusMode::Confirming => "Confirm",
            StatusMode::Help => "Help",
        }
    }

    /// Context-sensitive key hints for this mode.
    pub fn hints(self) -> &'static [(&'static str, &'static str)] {
        match self {
            StatusMode::Normal => &[
                ("?", "help"),
                ("e", "execute"),
                ("r", "refresh"),
                ("q", "quit"),
            ],
            StatusMode::Searching => &[
                ("Enter", "commit"),
                ("Esc", "cancel"),
                ("\u{2191}\u{2193}", "history"),
            ],
            StatusMode::Confirming => &[("Tab", "switch"), ("Enter", "confirm"), ("Esc", "cancel")],
            StatusMode::Help => &[("?", "close"), ("Esc", "close")],
        }
    }
}

// ---------------------------------------------------------------------------
// StatusBar widget
// ---------------------------------------------------------------------------

/// Status bar widget for the bottom of the TUI.
#[derive(Debug)]
pub struct StatusBar<'a> {
    /// Theme for styling.
    theme: Option<&'a Theme>,
    /// Current mode.
    mode: StatusMode,
    /// Number of selected processes.
    selected_count: usize,
    /// Active filter text (if any).
    filter: Option<&'a str>,
    /// Custom status message (overrides auto-generated content).
    message: Option<&'a str>,
}

impl<'a> Default for StatusBar<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> StatusBar<'a> {
    /// Create a new status bar.
    pub fn new() -> Self {
        Self {
            theme: None,
            mode: StatusMode::Normal,
            selected_count: 0,
            filter: None,
            message: None,
        }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set the current mode.
    pub fn mode(mut self, mode: StatusMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the selected process count.
    pub fn selected_count(mut self, count: usize) -> Self {
        self.selected_count = count;
        self
    }

    /// Set the active filter text.
    pub fn filter(mut self, filter: &'a str) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set a custom status message (overrides auto-generated content).
    pub fn message(mut self, message: &'a str) -> Self {
        self.message = Some(message);
        self
    }

    // ── Content builders ──────────────────────────────────────────────

    /// Build the left-side status text.
    pub fn build_left_text(&self) -> String {
        if let Some(msg) = self.message {
            return msg.to_string();
        }

        let mut parts = Vec::new();

        if self.selected_count > 0 {
            parts.push(format!("{} selected", self.selected_count));
        }

        if let Some(filter) = self.filter {
            if !filter.is_empty() {
                parts.push(format!("Filter: \"{}\"", filter));
            }
        }

        if parts.is_empty() {
            "Ready".to_string()
        } else {
            parts.join(" \u{2502} ")
        }
    }

    /// Build the mode indicator text.
    pub fn build_mode_text(&self) -> String {
        format!("[{}]", self.mode.label())
    }

    /// Build the hints text.
    pub fn build_hints_text(&self) -> String {
        self.mode
            .hints()
            .iter()
            .map(|(key, action)| format!("{}: {}", key, action))
            .collect::<Vec<_>>()
            .join("  ")
    }

    // ── ftui rendering ────────────────────────────────────────────────

    /// Render using ftui StatusLine.
    ///
    /// Note: this builds a single-line Paragraph instead of StatusLine because
    /// StatusLine requires `&'a str` references that outlive the dynamic strings
    /// we compute per-frame. The visual result is identical.
    pub fn render_ftui(&self, area: ftui::layout::Rect, frame: &mut ftui::render::frame::Frame) {
        let style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("status.normal"))
            .unwrap_or_default();

        let text = if let Some(msg) = self.message {
            format!("{} | Press ? for help", msg)
        } else {
            let left = self.build_left_text();
            let mode = self.build_mode_text();
            let hints = self.build_hints_text();
            format!("{} \u{2502} {} \u{2502} {}", left, mode, hints)
        };

        let paragraph = ftui::widgets::paragraph::Paragraph::new(text).style(style);
        FtuiWidget::render(&paragraph, area, frame);
    }

}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_status_bar() {
        let bar = StatusBar::new();
        assert_eq!(bar.mode, StatusMode::Normal);
        assert_eq!(bar.selected_count, 0);
        assert!(bar.filter.is_none());
        assert!(bar.message.is_none());
    }

    #[test]
    fn test_default_impl() {
        let bar = StatusBar::default();
        assert_eq!(bar.mode, StatusMode::Normal);
    }

    #[test]
    fn test_build_left_ready_when_empty() {
        let bar = StatusBar::new();
        assert_eq!(bar.build_left_text(), "Ready");
    }

    #[test]
    fn test_build_left_with_selected() {
        let bar = StatusBar::new().selected_count(3);
        assert_eq!(bar.build_left_text(), "3 selected");
    }

    #[test]
    fn test_build_left_with_filter() {
        let bar = StatusBar::new().filter("python");
        assert_eq!(bar.build_left_text(), "Filter: \"python\"");
    }

    #[test]
    fn test_build_left_with_both() {
        let bar = StatusBar::new().selected_count(5).filter("node");
        let text = bar.build_left_text();
        assert!(text.contains("5 selected"));
        assert!(text.contains("Filter: \"node\""));
    }

    #[test]
    fn test_build_left_custom_message() {
        let bar = StatusBar::new().selected_count(3).message("Custom status");
        assert_eq!(bar.build_left_text(), "Custom status");
    }

    #[test]
    fn test_build_mode_text() {
        assert_eq!(
            StatusBar::new().mode(StatusMode::Normal).build_mode_text(),
            "[Normal]"
        );
        assert_eq!(
            StatusBar::new()
                .mode(StatusMode::Searching)
                .build_mode_text(),
            "[Search]"
        );
        assert_eq!(
            StatusBar::new()
                .mode(StatusMode::Confirming)
                .build_mode_text(),
            "[Confirm]"
        );
        assert_eq!(
            StatusBar::new().mode(StatusMode::Help).build_mode_text(),
            "[Help]"
        );
    }

    #[test]
    fn test_mode_labels() {
        assert_eq!(StatusMode::Normal.label(), "Normal");
        assert_eq!(StatusMode::Searching.label(), "Search");
        assert_eq!(StatusMode::Confirming.label(), "Confirm");
        assert_eq!(StatusMode::Help.label(), "Help");
    }

    #[test]
    fn test_mode_hints_normal() {
        let hints = StatusMode::Normal.hints();
        assert!(hints.iter().any(|(k, _)| *k == "?"));
        assert!(hints.iter().any(|(k, _)| *k == "e"));
        assert!(hints.iter().any(|(k, _)| *k == "q"));
    }

    #[test]
    fn test_mode_hints_searching() {
        let hints = StatusMode::Searching.hints();
        assert!(hints.iter().any(|(_, a)| *a == "commit"));
        assert!(hints.iter().any(|(_, a)| *a == "cancel"));
        assert!(hints.iter().any(|(_, a)| *a == "history"));
    }

    #[test]
    fn test_mode_hints_confirming() {
        let hints = StatusMode::Confirming.hints();
        assert!(hints.iter().any(|(_, a)| *a == "switch"));
        assert!(hints.iter().any(|(_, a)| *a == "confirm"));
    }

    #[test]
    fn test_build_hints_text() {
        let bar = StatusBar::new().mode(StatusMode::Normal);
        let hints = bar.build_hints_text();
        assert!(hints.contains("?: help"));
        assert!(hints.contains("e: execute"));
        assert!(hints.contains("q: quit"));
    }

    #[test]
    fn test_empty_filter_not_shown() {
        let bar = StatusBar::new().filter("");
        assert_eq!(bar.build_left_text(), "Ready");
    }

    #[test]
    fn test_mode_default_is_normal() {
        assert_eq!(StatusMode::default(), StatusMode::Normal);
    }

}
