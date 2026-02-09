//! Help overlay widget.
//!
//! Modal overlay showing keyboard shortcuts and navigation help.
//! Uses ftui's Modal + Block + Paragraph for rendering.

use ftui::text::{Line as FtuiLine, Span as FtuiSpan, Text as FtuiText};
use ftui::widgets::block::Block as FtuiBlock;
use ftui::widgets::modal::{Modal, ModalPosition, ModalSizeConstraints};
use ftui::widgets::paragraph::Paragraph as FtuiParagraph;
use ftui::widgets::Widget as FtuiWidget;
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;

use crate::tui::layout::Breakpoint;
use crate::tui::theme::Theme;

// ---------------------------------------------------------------------------
// Help content
// ---------------------------------------------------------------------------

/// A single keybinding entry.
#[derive(Debug, Clone)]
struct Binding {
    key: &'static str,
    desc: &'static str,
}

/// A section of related keybindings.
#[derive(Debug, Clone)]
struct Section {
    title: &'static str,
    bindings: &'static [Binding],
}

const NAVIGATION: &[Binding] = &[
    Binding {
        key: "j / Down",
        desc: "Move down",
    },
    Binding {
        key: "k / Up",
        desc: "Move up",
    },
    Binding {
        key: "Home",
        desc: "Go to top",
    },
    Binding {
        key: "End",
        desc: "Go to bottom",
    },
    Binding {
        key: "Ctrl+d",
        desc: "Page down",
    },
    Binding {
        key: "Ctrl+u",
        desc: "Page up",
    },
    Binding {
        key: "Tab",
        desc: "Cycle focus",
    },
    Binding {
        key: "n / N",
        desc: "Next/prev match",
    },
];

const ACTIONS: &[Binding] = &[
    Binding {
        key: "/",
        desc: "Start search",
    },
    Binding {
        key: "Space",
        desc: "Toggle selection",
    },
    Binding {
        key: "a",
        desc: "Select recommended",
    },
    Binding {
        key: "A",
        desc: "Select all",
    },
    Binding {
        key: "u",
        desc: "Unselect all",
    },
    Binding {
        key: "x",
        desc: "Invert selection",
    },
    Binding {
        key: "e",
        desc: "Execute action",
    },
    Binding {
        key: "r",
        desc: "Refresh list",
    },
    Binding {
        key: "Enter",
        desc: "Toggle detail pane",
    },
    Binding {
        key: "s",
        desc: "Summary view",
    },
    Binding {
        key: "t",
        desc: "Genealogy view",
    },
    Binding {
        key: "g",
        desc: "Galaxy-brain view",
    },
    Binding {
        key: "v",
        desc: "Toggle goal view",
    },
];

const GENERAL: &[Binding] = &[
    Binding {
        key: "?",
        desc: "Toggle help",
    },
    Binding {
        key: "q / Esc",
        desc: "Quit",
    },
];

const SECTIONS: &[Section] = &[
    Section {
        title: "Navigation",
        bindings: NAVIGATION,
    },
    Section {
        title: "Actions",
        bindings: ACTIONS,
    },
    Section {
        title: "General",
        bindings: GENERAL,
    },
];

/// Key column width for full layout.
const KEY_COL_WIDTH: usize = 12;

// ---------------------------------------------------------------------------
// HelpOverlay widget
// ---------------------------------------------------------------------------

/// Help overlay widget showing keyboard shortcuts.
#[derive(Debug)]
pub struct HelpOverlay<'a> {
    /// Theme for styling.
    theme: Option<&'a Theme>,
    /// Current breakpoint for adaptive layout.
    breakpoint: Breakpoint,
}

impl<'a> Default for HelpOverlay<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> HelpOverlay<'a> {
    /// Create a new help overlay.
    pub fn new() -> Self {
        Self {
            theme: None,
            breakpoint: Breakpoint::Standard,
        }
    }

    /// Set the theme.
    pub fn theme(mut self, theme: &'a Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Set the breakpoint for adaptive layout.
    pub fn breakpoint(mut self, breakpoint: Breakpoint) -> Self {
        self.breakpoint = breakpoint;
        self
    }

    // ── Content builders ──────────────────────────────────────────────

    /// Build compact help text lines for small terminals.
    pub fn build_compact_lines() -> Vec<FtuiLine> {
        vec![
            FtuiLine::raw("Navigation: j/k/Home/End"),
            FtuiLine::raw("Search: /"),
            FtuiLine::raw("Select: Space/a/A/u/x"),
            FtuiLine::raw("Execute: e"),
            FtuiLine::raw("Detail: Enter"),
            FtuiLine::raw("Views: s/t/g  Mode: v"),
            FtuiLine::raw("Help: ?  Quit: q"),
        ]
    }

    /// Build full help text lines with formatted sections.
    pub fn build_full_lines(theme: Option<&Theme>) -> Vec<FtuiLine> {
        let title_style = theme
            .map(|t| t.stylesheet().get_or_default("table.header"))
            .unwrap_or_else(|| FtuiStyle::new().bold());

        let key_style = theme
            .map(|t| t.stylesheet().get_or_default("table.selected"))
            .unwrap_or_else(|| FtuiStyle::new().fg(PackedRgba::rgb(0, 255, 255)).bold());

        let desc_style = theme
            .map(|t| {
                let sheet = t.stylesheet();
                sheet.get_or_default("border.normal")
            })
            .unwrap_or_default();

        let mut lines = Vec::new();

        // Title
        lines.push(FtuiLine::from_spans([FtuiSpan::styled(
            "  Process Triage TUI Help",
            title_style,
        )]));
        lines.push(FtuiLine::raw(""));

        for section in SECTIONS {
            // Section header
            lines.push(FtuiLine::from_spans([FtuiSpan::styled(
                format!("  {}:", section.title),
                title_style,
            )]));

            for binding in section.bindings {
                let padded_key = format!("    {:width$}", binding.key, width = KEY_COL_WIDTH);
                lines.push(FtuiLine::from_spans([
                    FtuiSpan::styled(padded_key, key_style),
                    FtuiSpan::styled(binding.desc, desc_style),
                ]));
            }

            lines.push(FtuiLine::raw(""));
        }

        lines
    }

    // ── ftui rendering ────────────────────────────────────────────────

    /// Render the help overlay using ftui Modal + Paragraph.
    pub fn render_ftui(&self, area: ftui::layout::Rect, frame: &mut ftui::render::frame::Frame) {
        let lines = match self.breakpoint {
            Breakpoint::Minimal => Self::build_compact_lines(),
            _ => Self::build_full_lines(self.theme),
        };

        let border_style = self
            .theme
            .map(|t| t.stylesheet().get_or_default("border.focused"))
            .unwrap_or_else(|| FtuiStyle::new().fg(PackedRgba::rgb(0, 255, 255)));

        let text_style = self
            .theme
            .map(|t| {
                let sheet = t.stylesheet();
                sheet.get_or_default("border.normal")
            })
            .unwrap_or_default();

        let block = FtuiBlock::bordered()
            .title(" Help ")
            .border_style(border_style);

        let text: FtuiText = lines.into_iter().collect();
        let paragraph = FtuiParagraph::new(text).style(text_style).block(block);

        // Size constraints: 50% width, 60% height (matching current app.rs usage)
        let size = ModalSizeConstraints::new()
            .min_width(30)
            .max_width((area.width as f32 * 0.5) as u16)
            .min_height(10)
            .max_height((area.height as f32 * 0.6) as u16);

        let modal = Modal::new(paragraph)
            .position(ModalPosition::Center)
            .size(size);

        FtuiWidget::render(&modal, area, frame);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract plain text from ftui Lines for test assertions.
    fn lines_to_string(lines: &[FtuiLine]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_compact_lines_has_all_categories() {
        let lines = HelpOverlay::build_compact_lines();
        assert!(!lines.is_empty());

        let text = lines_to_string(&lines);
        assert!(text.contains("Navigation"));
        assert!(text.contains("Search"));
        assert!(text.contains("Select"));
        assert!(text.contains("Execute"));
        assert!(text.contains("Help"));
        assert!(text.contains("Quit"));
    }

    #[test]
    fn test_full_lines_has_all_sections() {
        let lines = HelpOverlay::build_full_lines(None);
        let text = lines_to_string(&lines);

        assert!(text.contains("Process Triage TUI Help"));
        assert!(text.contains("Navigation:"));
        assert!(text.contains("Actions:"));
        assert!(text.contains("General:"));
    }

    #[test]
    fn test_full_lines_has_all_bindings() {
        let lines = HelpOverlay::build_full_lines(None);
        let text = lines_to_string(&lines);

        // Spot-check key bindings from each section
        assert!(text.contains("j / Down"));
        assert!(text.contains("Move down"));
        assert!(text.contains("Space"));
        assert!(text.contains("Toggle selection"));
        assert!(text.contains("Toggle help"));
        assert!(text.contains("q / Esc"));
    }

    #[test]
    fn test_full_lines_binding_count() {
        let lines = HelpOverlay::build_full_lines(None);
        let total_bindings: usize = SECTIONS.iter().map(|s| s.bindings.len()).sum();
        // Lines = title + blank + (section_header + bindings + blank) per section
        let expected = 1 + 1 + SECTIONS.len() * 1 + total_bindings + SECTIONS.len();
        assert_eq!(lines.len(), expected);
    }

    #[test]
    fn test_default_breakpoint_is_standard() {
        let overlay = HelpOverlay::new();
        assert_eq!(overlay.breakpoint, Breakpoint::Standard);
    }

    #[test]
    fn test_builder_sets_breakpoint() {
        let overlay = HelpOverlay::new().breakpoint(Breakpoint::Minimal);
        assert_eq!(overlay.breakpoint, Breakpoint::Minimal);
    }

    #[test]
    fn test_default_impl() {
        let overlay = HelpOverlay::default();
        assert!(overlay.theme.is_none());
        assert_eq!(overlay.breakpoint, Breakpoint::Standard);
    }

    #[test]
    fn test_sections_cover_all_bindings() {
        // Verify the static data is well-formed
        for section in SECTIONS {
            assert!(!section.title.is_empty());
            assert!(!section.bindings.is_empty());
            for binding in section.bindings {
                assert!(!binding.key.is_empty());
                assert!(!binding.desc.is_empty());
            }
        }
    }

    #[test]
    fn test_compact_vs_full_line_count() {
        let compact = HelpOverlay::build_compact_lines();
        let full = HelpOverlay::build_full_lines(None);
        // Full should have significantly more lines than compact
        assert!(full.len() > compact.len());
    }
}
