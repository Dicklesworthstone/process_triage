//! Galaxy-brain mode math transparency types.
//!
//! This module defines types for the "galaxy-brain" mode that exposes
//! full mathematical reasoning of the inference engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema version for galaxy-brain data.
pub const GALAXY_BRAIN_SCHEMA_VERSION: &str = "1.0.0";

/// Stable card identifiers for programmatic access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardId {
    /// Posterior class probability breakdown.
    PosteriorCore,
    /// Time-varying hazard rates with Gamma posteriors.
    HazardTimeVarying,
    /// Conformal prediction intervals for runtime/CPU.
    ConformalInterval,
    /// Conformal classification prediction sets.
    ConformalClassSet,
    /// E-values and anytime-valid FDR control.
    EValuesFdr,
    /// Alpha-investing online testing budget.
    AlphaInvesting,
    /// Value of information for next probe.
    Voi,
}

impl CardId {
    /// Get all card IDs in display order.
    pub fn all() -> &'static [CardId] {
        &[
            CardId::PosteriorCore,
            CardId::HazardTimeVarying,
            CardId::ConformalInterval,
            CardId::ConformalClassSet,
            CardId::EValuesFdr,
            CardId::AlphaInvesting,
            CardId::Voi,
        ]
    }

    /// Get the default title for this card.
    pub fn default_title(&self) -> &'static str {
        match self {
            CardId::PosteriorCore => "Posterior Class Probabilities",
            CardId::HazardTimeVarying => "Time-Varying Hazard Rates",
            CardId::ConformalInterval => "Conformal Prediction Intervals",
            CardId::ConformalClassSet => "Conformal Classification Set",
            CardId::EValuesFdr => "E-values and Anytime-Valid FDR",
            CardId::AlphaInvesting => "Alpha-Investing Budget State",
            CardId::Voi => "Value of Information",
        }
    }

    /// Get the index in display order.
    pub fn index(&self) -> usize {
        Self::all().iter().position(|c| c == self).unwrap_or(0)
    }
}

/// Full galaxy-brain data for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalaxyBrainData {
    /// Schema version.
    pub schema_version: String,

    /// Process ID this data applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<i32>,

    /// Session ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// When this snapshot was generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,

    /// Math transparency cards.
    pub cards: Vec<MathCard>,

    /// Rendering hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render_hints: Option<RenderHints>,
}

impl Default for GalaxyBrainData {
    fn default() -> Self {
        Self {
            schema_version: GALAXY_BRAIN_SCHEMA_VERSION.to_string(),
            process_id: None,
            session_id: None,
            generated_at: None,
            cards: Vec::new(),
            render_hints: None,
        }
    }
}

/// A single math transparency card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MathCard {
    /// Stable card identifier.
    pub id: CardId,

    /// Human-readable title.
    pub title: String,

    /// Optional subtitle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,

    /// LaTeX equations showing the math.
    pub equations: Vec<Equation>,

    /// Concrete computed values.
    pub values: HashMap<String, ComputedValue>,

    /// One-line plain-English explanation.
    pub intuition: String,

    /// Optional longer explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Optional warnings about computation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Optional academic references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,

    /// Whether collapsed by default in TUI.
    #[serde(default)]
    pub collapsed_by_default: bool,
}

impl MathCard {
    /// Create a new card with the given ID.
    pub fn new(id: CardId) -> Self {
        Self {
            id,
            title: id.default_title().to_string(),
            subtitle: None,
            equations: Vec::new(),
            values: HashMap::new(),
            intuition: String::new(),
            details: None,
            warnings: Vec::new(),
            references: Vec::new(),
            collapsed_by_default: false,
        }
    }

    /// Add an equation to the card.
    pub fn with_equation(mut self, equation: Equation) -> Self {
        self.equations.push(equation);
        self
    }

    /// Add a computed value to the card.
    pub fn with_value(mut self, key: impl Into<String>, value: ComputedValue) -> Self {
        self.values.insert(key.into(), value);
        self
    }

    /// Set the intuition string.
    pub fn with_intuition(mut self, intuition: impl Into<String>) -> Self {
        self.intuition = intuition.into();
        self
    }
}

/// A mathematical equation with rendering information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Equation {
    /// LaTeX/KaTeX source.
    pub latex: String,

    /// True for block display, false for inline.
    #[serde(default = "default_true")]
    pub display_mode: bool,

    /// Optional label (e.g., "Bayes rule").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// ASCII fallback for terminals without math rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ascii_fallback: Option<String>,
}

impl Equation {
    /// Create a new display equation.
    pub fn display(latex: impl Into<String>) -> Self {
        Self {
            latex: latex.into(),
            display_mode: true,
            label: None,
            ascii_fallback: None,
        }
    }

    /// Create a new inline equation.
    pub fn inline(latex: impl Into<String>) -> Self {
        Self {
            latex: latex.into(),
            display_mode: false,
            label: None,
            ascii_fallback: None,
        }
    }

    /// Add a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Add an ASCII fallback.
    pub fn with_ascii(mut self, ascii: impl Into<String>) -> Self {
        self.ascii_fallback = Some(ascii.into());
        self
    }
}

/// A concrete computed numeric value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputedValue {
    /// The computed value.
    pub value: ValueType,

    /// Unit of measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Display format.
    #[serde(default)]
    pub format: ValueFormat,

    /// Decimal precision.
    #[serde(default = "default_precision")]
    pub precision: u8,

    /// Human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// LaTeX symbol used in equations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,

    /// Plain-English interpretation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<String>,
}

impl ComputedValue {
    /// Create a scalar value.
    pub fn scalar(value: f64) -> Self {
        Self {
            value: ValueType::Scalar(value),
            unit: None,
            format: ValueFormat::Decimal,
            precision: 4,
            label: None,
            symbol: None,
            interpretation: None,
        }
    }

    /// Create a probability value (0-1).
    pub fn probability(value: f64) -> Self {
        Self {
            value: ValueType::Scalar(value),
            unit: Some("probability".to_string()),
            format: ValueFormat::Percentage,
            precision: 2,
            label: None,
            symbol: None,
            interpretation: None,
        }
    }

    /// Create a log value.
    pub fn log_value(value: f64) -> Self {
        Self {
            value: ValueType::Scalar(value),
            unit: None,
            format: ValueFormat::Log,
            precision: 4,
            label: None,
            symbol: None,
            interpretation: None,
        }
    }

    /// Create a duration value.
    pub fn duration_secs(value: f64) -> Self {
        Self {
            value: ValueType::Scalar(value),
            unit: Some("seconds".to_string()),
            format: ValueFormat::Duration,
            precision: 1,
            label: None,
            symbol: None,
            interpretation: None,
        }
    }

    /// Create an array value.
    pub fn array(values: Vec<f64>) -> Self {
        Self {
            value: ValueType::Array(values),
            unit: None,
            format: ValueFormat::Decimal,
            precision: 4,
            label: None,
            symbol: None,
            interpretation: None,
        }
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the symbol.
    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.symbol = Some(symbol.into());
        self
    }

    /// Set the interpretation.
    pub fn with_interpretation(mut self, interp: impl Into<String>) -> Self {
        self.interpretation = Some(interp.into());
        self
    }
}

/// Value types for computed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValueType {
    /// Single scalar value.
    Scalar(f64),
    /// Array of values.
    Array(Vec<f64>),
    /// Structured object (for complex values).
    Object(serde_json::Value),
}

/// Display format for values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueFormat {
    /// Decimal (e.g., 0.1234).
    #[default]
    Decimal,
    /// Percentage (e.g., 12.34%).
    Percentage,
    /// Scientific notation (e.g., 1.23e-4).
    Scientific,
    /// Log value (e.g., log: -2.34).
    Log,
    /// Duration (e.g., 1h 23m 45s).
    Duration,
}

/// A reference to external documentation or paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// Reference title.
    pub title: String,

    /// URL to the reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Author names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,

    /// Publication year.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year: Option<u16>,

    /// Additional note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Rendering hints for different outputs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenderHints {
    /// TUI-specific hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tui: Option<TuiHints>,

    /// CLI-specific hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli: Option<CliHints>,

    /// Report-specific hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ReportHints>,
}

/// TUI-specific rendering hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiHints {
    /// Color scheme for syntax highlighting.
    #[serde(default)]
    pub color_scheme: TuiColorScheme,

    /// Use Unicode math symbols.
    #[serde(default = "default_true")]
    pub use_unicode_math: bool,

    /// Show LaTeX equations.
    #[serde(default = "default_true")]
    pub show_equations: bool,

    /// Compact display for smaller terminals.
    #[serde(default)]
    pub compact_mode: bool,

    /// Keybinding to toggle galaxy-brain mode.
    #[serde(default = "default_keybind")]
    pub keybind_toggle: String,
}

impl Default for TuiHints {
    fn default() -> Self {
        Self {
            color_scheme: TuiColorScheme::Math,
            use_unicode_math: true,
            show_equations: true,
            compact_mode: false,
            keybind_toggle: "g".to_string(),
        }
    }
}

/// TUI color schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuiColorScheme {
    /// Math-focused colors.
    #[default]
    Math,
    /// Code-like colors.
    Code,
    /// Default terminal colors.
    Default,
}

/// CLI-specific rendering hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliHints {
    /// Output format.
    #[serde(default)]
    pub output_format: CliOutputFormat,

    /// Use ANSI colors.
    #[serde(default = "default_true")]
    pub use_color: bool,

    /// Verbosity level.
    #[serde(default)]
    pub verbosity: CliVerbosity,
}

impl Default for CliHints {
    fn default() -> Self {
        Self {
            output_format: CliOutputFormat::Plain,
            use_color: true,
            verbosity: CliVerbosity::Normal,
        }
    }
}

/// CLI output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliOutputFormat {
    /// Plain text.
    #[default]
    Plain,
    /// JSON.
    Json,
    /// Markdown.
    Markdown,
}

/// CLI verbosity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliVerbosity {
    /// Summary only.
    Summary,
    /// Normal detail.
    #[default]
    Normal,
    /// Full verbose output.
    Verbose,
}

/// Report-specific rendering hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportHints {
    /// Math rendering library.
    #[serde(default)]
    pub math_renderer: MathRenderer,

    /// Show full derivations.
    #[serde(default)]
    pub show_derivations: bool,

    /// Enable interactive charts.
    #[serde(default = "default_true")]
    pub interactive_charts: bool,

    /// HTML tab ID.
    #[serde(default = "default_tab_id")]
    pub tab_id: String,
}

impl Default for ReportHints {
    fn default() -> Self {
        Self {
            math_renderer: MathRenderer::Katex,
            show_derivations: false,
            interactive_charts: true,
            tab_id: "galaxy-brain".to_string(),
        }
    }
}

/// Math rendering libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MathRenderer {
    /// KaTeX (faster).
    #[default]
    Katex,
    /// MathJax (more complete).
    Mathjax,
}

// Helper functions for serde defaults
fn default_true() -> bool {
    true
}

fn default_precision() -> u8 {
    4
}

fn default_keybind() -> String {
    "g".to_string()
}

fn default_tab_id() -> String {
    "galaxy-brain".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_id_all() {
        let all = CardId::all();
        assert_eq!(all.len(), 7);
        assert_eq!(all[0], CardId::PosteriorCore);
        assert_eq!(all[6], CardId::Voi);
    }

    #[test]
    fn test_card_default_title() {
        assert_eq!(
            CardId::PosteriorCore.default_title(),
            "Posterior Class Probabilities"
        );
        assert_eq!(CardId::Voi.default_title(), "Value of Information");
    }

    #[test]
    fn test_math_card_builder() {
        let card = MathCard::new(CardId::PosteriorCore)
            .with_equation(Equation::display(r"\log P(C|x) = ..."))
            .with_value(
                "posterior_useful",
                ComputedValue::probability(0.42).with_symbol(r"P(useful|x)"),
            )
            .with_intuition("42% chance this process is useful.");

        assert_eq!(card.id, CardId::PosteriorCore);
        assert_eq!(card.equations.len(), 1);
        assert!(card.values.contains_key("posterior_useful"));
        assert!(card.intuition.contains("42%"));
    }

    #[test]
    fn test_computed_value_formats() {
        let prob = ComputedValue::probability(0.95);
        assert_eq!(prob.format, ValueFormat::Percentage);

        let log = ComputedValue::log_value(-2.34);
        assert_eq!(log.format, ValueFormat::Log);

        let dur = ComputedValue::duration_secs(3600.0);
        assert_eq!(dur.unit, Some("seconds".to_string()));
    }

    #[test]
    fn test_galaxy_brain_data_serialization() {
        let mut data = GalaxyBrainData::default();
        data.process_id = Some(12345);
        data.cards.push(
            MathCard::new(CardId::PosteriorCore)
                .with_intuition("Test intuition"),
        );

        let json = serde_json::to_string_pretty(&data).unwrap();
        assert!(json.contains("posterior_core"));
        assert!(json.contains("12345"));

        let parsed: GalaxyBrainData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.process_id, Some(12345));
        assert_eq!(parsed.cards.len(), 1);
    }

    #[test]
    fn test_equation_builder() {
        let eq = Equation::display(r"\alpha + \beta")
            .with_label("Sum of parameters")
            .with_ascii("alpha + beta");

        assert!(eq.display_mode);
        assert_eq!(eq.label, Some("Sum of parameters".to_string()));
        assert_eq!(eq.ascii_fallback, Some("alpha + beta".to_string()));
    }

    #[test]
    fn test_render_hints_defaults() {
        let hints = RenderHints::default();
        assert!(hints.tui.is_none());

        let tui = TuiHints::default();
        assert!(tui.use_unicode_math);
        assert_eq!(tui.keybind_toggle, "g");
    }
}
