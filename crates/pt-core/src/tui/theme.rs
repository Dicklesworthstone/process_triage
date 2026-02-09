//! Theme and styling for the Process Triage TUI.
//!
//! Provides consistent colors and styles across all widgets using ftui's
//! Theme/StyleSheet system with WCAG accessibility validation.

use ftui::style::{
    contrast_ratio, meets_wcag_aa, meets_wcag_aaa, ColorProfile, Rgb as FtuiRgb, StyleSheet,
    Theme as FtuiTheme, ThemeBuilder,
};
use ftui::PackedRgba;
use ftui::Style as FtuiStyle;

/// Theme mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    /// Light theme for high ambient light.
    Light,
    /// Dark theme (default).
    #[default]
    Dark,
    /// High contrast for accessibility (WCAG AAA).
    HighContrast,
    /// No color — respects `NO_COLOR` environment variable.
    NoColor,
}

/// Domain-specific RGB color definitions for WCAG validation.
#[derive(Debug, Clone)]
struct ClassificationColors {
    kill: FtuiRgb,
    review: FtuiRgb,
    spare: FtuiRgb,
    bg: FtuiRgb,
    fg: FtuiRgb,
}

/// Theme configuration for the TUI.
///
/// Wraps ftui's `Theme` and `StyleSheet` with WCAG-validated color schemes.
#[derive(Debug, Clone)]
pub struct Theme {
    /// Current theme mode.
    pub mode: ThemeMode,

    // --- ftui theme system ---
    ftui_theme: FtuiTheme,
    stylesheet: StyleSheet,
    classification: ClassificationColors,
}

impl Default for Theme {
    fn default() -> Self {
        Self::from_env()
    }
}

// ---------------------------------------------------------------------------
// RGB constants for domain-specific colors
// ---------------------------------------------------------------------------

// Dark theme classification colors
const DARK_BG: FtuiRgb = FtuiRgb::new(30, 30, 30);
const DARK_FG: FtuiRgb = FtuiRgb::new(220, 220, 220);
const DARK_KILL: FtuiRgb = FtuiRgb::new(255, 80, 80);
const DARK_REVIEW: FtuiRgb = FtuiRgb::new(255, 200, 50);
const DARK_SPARE: FtuiRgb = FtuiRgb::new(80, 220, 80);
const DARK_HIGHLIGHT: FtuiRgb = FtuiRgb::new(0, 200, 200);
const DARK_MUTED: FtuiRgb = FtuiRgb::new(128, 128, 128);
const DARK_BORDER: FtuiRgb = FtuiRgb::new(80, 80, 80);
const DARK_BORDER_FOCUSED: FtuiRgb = FtuiRgb::new(0, 200, 200);

// Light theme classification colors
const LIGHT_BG: FtuiRgb = FtuiRgb::new(255, 255, 255);
const LIGHT_FG: FtuiRgb = FtuiRgb::new(30, 30, 30);
const LIGHT_KILL: FtuiRgb = FtuiRgb::new(200, 0, 0);
const LIGHT_REVIEW: FtuiRgb = FtuiRgb::new(140, 100, 0);
const LIGHT_SPARE: FtuiRgb = FtuiRgb::new(0, 128, 0);
const LIGHT_HIGHLIGHT: FtuiRgb = FtuiRgb::new(0, 80, 200);
const LIGHT_MUTED: FtuiRgb = FtuiRgb::new(128, 128, 128);
const LIGHT_BORDER: FtuiRgb = FtuiRgb::new(180, 180, 180);
const LIGHT_BORDER_FOCUSED: FtuiRgb = FtuiRgb::new(0, 80, 200);

// High contrast classification colors (WCAG AAA: 7:1 minimum)
const HC_BG: FtuiRgb = FtuiRgb::new(0, 0, 0);
const HC_FG: FtuiRgb = FtuiRgb::new(255, 255, 255);
const HC_KILL: FtuiRgb = FtuiRgb::new(255, 100, 100);
const HC_REVIEW: FtuiRgb = FtuiRgb::new(255, 255, 80);
const HC_SPARE: FtuiRgb = FtuiRgb::new(100, 255, 100);
const HC_HIGHLIGHT: FtuiRgb = FtuiRgb::new(255, 255, 0);
const HC_MUTED: FtuiRgb = FtuiRgb::new(200, 200, 200);
const HC_BORDER: FtuiRgb = FtuiRgb::new(255, 255, 255);
const HC_BORDER_FOCUSED: FtuiRgb = FtuiRgb::new(255, 255, 0);

impl Theme {
    /// Auto-detect theme from environment variables.
    ///
    /// Priority:
    /// 1. `NO_COLOR` set → NoColor theme
    /// 2. `PT_HIGH_CONTRAST` set → HighContrast theme
    /// 3. Default → Dark theme
    pub fn from_env() -> Self {
        if std::env::var("NO_COLOR").is_ok() {
            return Self::no_color();
        }
        if std::env::var("PT_HIGH_CONTRAST").is_ok() {
            return Self::high_contrast();
        }
        Self::dark()
    }

    /// Create a dark theme (default).
    pub fn dark() -> Self {
        let ftui_theme = ThemeBuilder::new()
            .background(ftui::Color::rgb(DARK_BG.r, DARK_BG.g, DARK_BG.b))
            .text(ftui::Color::rgb(DARK_FG.r, DARK_FG.g, DARK_FG.b))
            .error(ftui::Color::rgb(DARK_KILL.r, DARK_KILL.g, DARK_KILL.b))
            .warning(ftui::Color::rgb(
                DARK_REVIEW.r,
                DARK_REVIEW.g,
                DARK_REVIEW.b,
            ))
            .success(ftui::Color::rgb(DARK_SPARE.r, DARK_SPARE.g, DARK_SPARE.b))
            .primary(ftui::Color::rgb(
                DARK_HIGHLIGHT.r,
                DARK_HIGHLIGHT.g,
                DARK_HIGHLIGHT.b,
            ))
            .text_muted(ftui::Color::rgb(DARK_MUTED.r, DARK_MUTED.g, DARK_MUTED.b))
            .border(ftui::Color::rgb(
                DARK_BORDER.r,
                DARK_BORDER.g,
                DARK_BORDER.b,
            ))
            .border_focused(ftui::Color::rgb(
                DARK_BORDER_FOCUSED.r,
                DARK_BORDER_FOCUSED.g,
                DARK_BORDER_FOCUSED.b,
            ))
            .build();

        let classification = ClassificationColors {
            kill: DARK_KILL,
            review: DARK_REVIEW,
            spare: DARK_SPARE,
            bg: DARK_BG,
            fg: DARK_FG,
        };

        let sheet = build_stylesheet(&classification, false);

        Self {
            mode: ThemeMode::Dark,
            ftui_theme,
            stylesheet: sheet,
            classification,
        }
    }

    /// Create a light theme.
    pub fn light() -> Self {
        let ftui_theme = ThemeBuilder::new()
            .background(ftui::Color::rgb(LIGHT_BG.r, LIGHT_BG.g, LIGHT_BG.b))
            .text(ftui::Color::rgb(LIGHT_FG.r, LIGHT_FG.g, LIGHT_FG.b))
            .error(ftui::Color::rgb(LIGHT_KILL.r, LIGHT_KILL.g, LIGHT_KILL.b))
            .warning(ftui::Color::rgb(
                LIGHT_REVIEW.r,
                LIGHT_REVIEW.g,
                LIGHT_REVIEW.b,
            ))
            .success(ftui::Color::rgb(
                LIGHT_SPARE.r,
                LIGHT_SPARE.g,
                LIGHT_SPARE.b,
            ))
            .primary(ftui::Color::rgb(
                LIGHT_HIGHLIGHT.r,
                LIGHT_HIGHLIGHT.g,
                LIGHT_HIGHLIGHT.b,
            ))
            .text_muted(ftui::Color::rgb(
                LIGHT_MUTED.r,
                LIGHT_MUTED.g,
                LIGHT_MUTED.b,
            ))
            .border(ftui::Color::rgb(
                LIGHT_BORDER.r,
                LIGHT_BORDER.g,
                LIGHT_BORDER.b,
            ))
            .border_focused(ftui::Color::rgb(
                LIGHT_BORDER_FOCUSED.r,
                LIGHT_BORDER_FOCUSED.g,
                LIGHT_BORDER_FOCUSED.b,
            ))
            .build();

        let classification = ClassificationColors {
            kill: LIGHT_KILL,
            review: LIGHT_REVIEW,
            spare: LIGHT_SPARE,
            bg: LIGHT_BG,
            fg: LIGHT_FG,
        };

        let sheet = build_stylesheet(&classification, false);

        Self {
            mode: ThemeMode::Light,
            ftui_theme,
            stylesheet: sheet,
            classification,
        }
    }

    /// Create a high contrast theme (WCAG AAA: 7:1 minimum ratio).
    pub fn high_contrast() -> Self {
        let ftui_theme = ThemeBuilder::new()
            .background(ftui::Color::rgb(HC_BG.r, HC_BG.g, HC_BG.b))
            .text(ftui::Color::rgb(HC_FG.r, HC_FG.g, HC_FG.b))
            .error(ftui::Color::rgb(HC_KILL.r, HC_KILL.g, HC_KILL.b))
            .warning(ftui::Color::rgb(HC_REVIEW.r, HC_REVIEW.g, HC_REVIEW.b))
            .success(ftui::Color::rgb(HC_SPARE.r, HC_SPARE.g, HC_SPARE.b))
            .primary(ftui::Color::rgb(
                HC_HIGHLIGHT.r,
                HC_HIGHLIGHT.g,
                HC_HIGHLIGHT.b,
            ))
            .text_muted(ftui::Color::rgb(HC_MUTED.r, HC_MUTED.g, HC_MUTED.b))
            .border(ftui::Color::rgb(HC_BORDER.r, HC_BORDER.g, HC_BORDER.b))
            .border_focused(ftui::Color::rgb(
                HC_BORDER_FOCUSED.r,
                HC_BORDER_FOCUSED.g,
                HC_BORDER_FOCUSED.b,
            ))
            .build();

        let classification = ClassificationColors {
            kill: HC_KILL,
            review: HC_REVIEW,
            spare: HC_SPARE,
            bg: HC_BG,
            fg: HC_FG,
        };

        let sheet = build_stylesheet(&classification, true);

        Self {
            mode: ThemeMode::HighContrast,
            ftui_theme,
            stylesheet: sheet,
            classification,
        }
    }

    /// Create a no-color theme for terminals without color support.
    /// Respects the `NO_COLOR` environment variable (<https://no-color.org/>).
    pub fn no_color() -> Self {
        let ftui_theme = ThemeBuilder::new().build();

        let classification = ClassificationColors {
            kill: FtuiRgb::new(255, 255, 255),
            review: FtuiRgb::new(255, 255, 255),
            spare: FtuiRgb::new(255, 255, 255),
            bg: FtuiRgb::new(0, 0, 0),
            fg: FtuiRgb::new(255, 255, 255),
        };

        let sheet = build_no_color_stylesheet();

        Self {
            mode: ThemeMode::NoColor,
            ftui_theme,
            stylesheet: sheet,
            classification,
        }
    }

    // --- ftui integration accessors ---

    /// Access the underlying ftui theme.
    pub fn ftui_theme(&self) -> &FtuiTheme {
        &self.ftui_theme
    }

    /// Access the stylesheet with named style classes.
    pub fn stylesheet(&self) -> &StyleSheet {
        &self.stylesheet
    }

    /// Get an ftui style by class name from the stylesheet.
    pub fn class(&self, name: &str) -> FtuiStyle {
        self.stylesheet.get_or_default(name)
    }

    /// Get the current color profile based on terminal capabilities.
    pub fn color_profile() -> ColorProfile {
        ColorProfile::detect()
    }

    // --- WCAG validation ---

    /// Validate that all classification colors meet WCAG AA (4.5:1 ratio)
    /// against the theme's background color.
    pub fn validate_wcag_aa(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let bg = self.classification.bg;

        for (name, fg) in [
            ("kill", self.classification.kill),
            ("review", self.classification.review),
            ("spare", self.classification.spare),
            ("text", self.classification.fg),
        ] {
            if !meets_wcag_aa(fg, bg) {
                let ratio = contrast_ratio(fg, bg);
                failures.push(format!(
                    "{name} ({fg:?}) on bg ({bg:?}) fails WCAG AA: {ratio:.2}:1 < 4.5:1"
                ));
            }
        }

        failures
    }

    /// Validate that all classification colors meet WCAG AAA (7:1 ratio)
    /// against the theme's background color.
    pub fn validate_wcag_aaa(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let bg = self.classification.bg;

        for (name, fg) in [
            ("kill", self.classification.kill),
            ("review", self.classification.review),
            ("spare", self.classification.spare),
            ("text", self.classification.fg),
        ] {
            if !meets_wcag_aaa(fg, bg) {
                let ratio = contrast_ratio(fg, bg);
                failures.push(format!(
                    "{name} ({fg:?}) on bg ({bg:?}) fails WCAG AAA: {ratio:.2}:1 < 7.0:1"
                ));
            }
        }

        failures
    }
}

// ---------------------------------------------------------------------------
// StyleSheet builders
// ---------------------------------------------------------------------------

/// Build the standard stylesheet with classification-aware styles.
fn build_stylesheet(colors: &ClassificationColors, bold_classifications: bool) -> StyleSheet {
    let sheet = StyleSheet::new();

    let kill_style = if bold_classifications {
        FtuiStyle::new()
            .fg(PackedRgba::rgb(colors.kill.r, colors.kill.g, colors.kill.b))
            .bold()
    } else {
        FtuiStyle::new()
            .fg(PackedRgba::rgb(colors.kill.r, colors.kill.g, colors.kill.b))
            .bold()
    };

    let review_style = FtuiStyle::new().fg(PackedRgba::rgb(
        colors.review.r,
        colors.review.g,
        colors.review.b,
    ));

    let spare_style = FtuiStyle::new().fg(PackedRgba::rgb(
        colors.spare.r,
        colors.spare.g,
        colors.spare.b,
    ));

    // Classification styles
    sheet.define("classification.kill", kill_style);
    sheet.define("classification.review", review_style);
    sheet.define("classification.spare", spare_style);

    // Table styles
    sheet.define(
        "table.header",
        FtuiStyle::new()
            .fg(PackedRgba::rgb(colors.fg.r, colors.fg.g, colors.fg.b))
            .bold(),
    );
    sheet.define(
        "table.selected",
        FtuiStyle::new().bg(PackedRgba::rgb(60, 60, 60)),
    );

    // Search
    sheet.define(
        "search.highlight",
        FtuiStyle::new()
            .bg(PackedRgba::rgb(80, 80, 0))
            .fg(PackedRgba::rgb(255, 255, 255)),
    );

    // Status indicators
    sheet.define(
        "status.error",
        FtuiStyle::new()
            .fg(PackedRgba::rgb(colors.kill.r, colors.kill.g, colors.kill.b))
            .bold(),
    );
    sheet.define(
        "status.warning",
        FtuiStyle::new().fg(PackedRgba::rgb(
            colors.review.r,
            colors.review.g,
            colors.review.b,
        )),
    );
    sheet.define(
        "status.success",
        FtuiStyle::new().fg(PackedRgba::rgb(
            colors.spare.r,
            colors.spare.g,
            colors.spare.b,
        )),
    );

    // Borders
    sheet.define("border.normal", FtuiStyle::new());
    sheet.define("border.focused", FtuiStyle::new().bold());

    sheet
}

/// Build a stylesheet for NO_COLOR mode using only text attributes.
fn build_no_color_stylesheet() -> StyleSheet {
    let sheet = StyleSheet::new();

    // Use bold, underline, and reverse instead of colors
    sheet.define("classification.kill", FtuiStyle::new().bold().underline());
    sheet.define("classification.review", FtuiStyle::new().bold());
    sheet.define("classification.spare", FtuiStyle::new());

    sheet.define("table.header", FtuiStyle::new().bold());
    sheet.define("table.selected", FtuiStyle::new().reverse());
    sheet.define("search.highlight", FtuiStyle::new().reverse());

    sheet.define("status.error", FtuiStyle::new().bold().underline());
    sheet.define("status.warning", FtuiStyle::new().bold());
    sheet.define("status.success", FtuiStyle::new());

    sheet.define("border.normal", FtuiStyle::new());
    sheet.define("border.focused", FtuiStyle::new().bold());

    sheet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_theme_is_dark_or_env_driven() {
        // Default respects env vars, but with no env vars set it should be dark
        // (or whatever from_env produces in the test environment)
        let theme = Theme::default();
        // Just verify it constructs successfully
        assert!(!theme.stylesheet.is_empty());
    }

    #[test]
    fn test_dark_theme_mode() {
        let theme = Theme::dark();
        assert_eq!(theme.mode, ThemeMode::Dark);
    }

    #[test]
    fn test_light_theme_mode() {
        let theme = Theme::light();
        assert_eq!(theme.mode, ThemeMode::Light);
    }

    #[test]
    fn test_high_contrast_theme_mode() {
        let theme = Theme::high_contrast();
        assert_eq!(theme.mode, ThemeMode::HighContrast);
    }

    #[test]
    fn test_no_color_theme_mode() {
        let theme = Theme::no_color();
        assert_eq!(theme.mode, ThemeMode::NoColor);
    }

    #[test]
    fn test_dark_theme_classification_colors_meet_wcag_aa() {
        let theme = Theme::dark();
        let failures = theme.validate_wcag_aa();
        assert!(
            failures.is_empty(),
            "Dark theme WCAG AA failures: {failures:?}"
        );
    }

    #[test]
    fn test_light_theme_classification_colors_meet_wcag_aa() {
        let theme = Theme::light();
        let failures = theme.validate_wcag_aa();
        assert!(
            failures.is_empty(),
            "Light theme WCAG AA failures: {failures:?}"
        );
    }

    #[test]
    fn test_high_contrast_theme_meets_wcag_aaa() {
        let theme = Theme::high_contrast();
        let failures = theme.validate_wcag_aaa();
        assert!(
            failures.is_empty(),
            "High contrast WCAG AAA failures: {failures:?}"
        );
    }

    #[test]
    fn test_stylesheet_has_all_required_classes() {
        let required = [
            "classification.kill",
            "classification.review",
            "classification.spare",
            "table.header",
            "table.selected",
            "search.highlight",
            "status.error",
            "status.warning",
            "status.success",
            "border.normal",
            "border.focused",
        ];

        for theme in [Theme::dark(), Theme::light(), Theme::high_contrast()] {
            for class in &required {
                assert!(
                    theme.stylesheet().contains(class),
                    "Theme {:?} missing stylesheet class: {class}",
                    theme.mode
                );
            }
        }
    }

    #[test]
    fn test_no_color_stylesheet_has_required_classes() {
        let theme = Theme::no_color();
        let required = [
            "classification.kill",
            "classification.review",
            "classification.spare",
            "table.header",
            "table.selected",
        ];
        for class in &required {
            assert!(
                theme.stylesheet().contains(class),
                "NoColor theme missing class: {class}"
            );
        }
    }

    #[test]
    fn test_theme_class_accessor() {
        let theme = Theme::dark();
        // Should return a valid style (not panic)
        let _style = theme.class("classification.kill");
        // Missing class returns default style without panic
        let _default = theme.class("nonexistent.class");
    }

    #[test]
    fn test_contrast_ratios_are_reasonable() {
        // Verify our color constants produce reasonable contrast ratios
        let dark_kill_ratio = contrast_ratio(DARK_KILL, DARK_BG);
        assert!(
            dark_kill_ratio > 4.5,
            "Dark kill ratio {dark_kill_ratio:.2} < 4.5"
        );

        let light_kill_ratio = contrast_ratio(LIGHT_KILL, LIGHT_BG);
        assert!(
            light_kill_ratio > 4.5,
            "Light kill ratio {light_kill_ratio:.2} < 4.5"
        );

        let hc_kill_ratio = contrast_ratio(HC_KILL, HC_BG);
        assert!(
            hc_kill_ratio > 7.0,
            "HC kill ratio {hc_kill_ratio:.2} < 7.0"
        );
    }

    #[test]
    fn test_high_contrast_all_colors_aaa_against_bg() {
        let pairs = [
            ("kill", HC_KILL, HC_BG),
            ("review", HC_REVIEW, HC_BG),
            ("spare", HC_SPARE, HC_BG),
            ("fg", HC_FG, HC_BG),
            ("muted", HC_MUTED, HC_BG),
            ("highlight", HC_HIGHLIGHT, HC_BG),
            ("border", HC_BORDER, HC_BG),
        ];

        for (name, fg, bg) in pairs {
            let ratio = contrast_ratio(fg, bg);
            assert!(
                ratio >= 7.0,
                "HC {name} contrast {ratio:.2}:1 < 7.0:1 (AAA)"
            );
        }
    }

    #[test]
    fn test_theme_modes_have_distinct_backgrounds() {
        let dark = Theme::dark();
        let light = Theme::light();
        let hc = Theme::high_contrast();

        assert_ne!(dark.classification.bg, light.classification.bg);
        assert_ne!(dark.classification.bg, hc.classification.bg);
    }

}
