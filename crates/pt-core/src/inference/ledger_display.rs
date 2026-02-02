//! Evidence ledger display with drill-down.
//!
//! Organises evidence by category (resources, timing, context, behaviour,
//! network) and renders structured views with Bayes factor weights.
//! Supports summary, category-panel, and full-detail views plus filtering
//! by evidence type or strength.

use serde::{Deserialize, Serialize};

use super::ledger::{BayesFactorEntry, Classification, Confidence, EvidenceLedger};

// ---------------------------------------------------------------------------
// Evidence categories
// ---------------------------------------------------------------------------

/// High-level evidence category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    Resource,
    Timing,
    Context,
    Behavior,
    Network,
    Other,
}

impl EvidenceCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Resource => "Resource Usage",
            Self::Timing => "Timing",
            Self::Context => "Context",
            Self::Behavior => "Behavior",
            Self::Network => "Network",
            Self::Other => "Other",
        }
    }
}

/// Classify a feature name into a category.
pub fn categorize_feature(feature: &str) -> EvidenceCategory {
    let f = feature.to_lowercase();
    if f.contains("cpu") || f.contains("memory") || f.contains("rss")
        || f.contains("vsz") || f.starts_with("io") || f.contains("_io")
        || f.starts_with("fd") || f.contains("_fd")
    {
        EvidenceCategory::Resource
    } else if f.contains("age") || f.contains("elapsed") || f.contains("runtime")
        || f.contains("idle") || f.contains("burst") || f.contains("uptime")
    {
        EvidenceCategory::Timing
    } else if f.contains("ppid") || f.contains("orphan") || f.contains("cgroup")
        || f.contains("user") || f.contains("parent") || f.contains("uid")
    {
        EvidenceCategory::Context
    } else if f.contains("state") || f.contains("zombie") || f.contains("signal")
        || f.contains("restart") || f.contains("file") || f.contains("child")
        || f.contains("thread") || f.contains("spawn")
    {
        EvidenceCategory::Behavior
    } else if f.contains("net") || f.contains("socket") || f.contains("port")
        || f.contains("tcp") || f.contains("udp") || f.contains("listen")
    {
        EvidenceCategory::Network
    } else {
        EvidenceCategory::Other
    }
}

// ---------------------------------------------------------------------------
// Display items
// ---------------------------------------------------------------------------

/// A single evidence item enriched with category and display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub feature: String,
    pub category: EvidenceCategory,
    pub bf: f64,
    pub log_bf: f64,
    pub delta_bits: f64,
    pub direction: String,
    pub strength: String,
    /// Normalised weight (0..1) showing this item's share of total evidence.
    pub weight: f64,
}

/// A category panel grouping related evidence items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryPanel {
    pub category: EvidenceCategory,
    pub label: String,
    pub items: Vec<EvidenceItem>,
    /// Sum of absolute delta_bits for all items in this category.
    pub total_bits: f64,
}

/// Filter criteria for evidence display.
#[derive(Debug, Clone, Default)]
pub struct EvidenceFilter {
    /// Only show items in these categories (empty = all).
    pub categories: Vec<EvidenceCategory>,
    /// Minimum absolute delta_bits to include.
    pub min_strength_bits: f64,
    /// Substring match on feature name (case-insensitive).
    pub name_pattern: Option<String>,
    /// Maximum items to return.
    pub limit: Option<usize>,
}

/// Configuration for ledger display rendering.
#[derive(Debug, Clone)]
pub struct LedgerDisplayConfig {
    /// Number of top contributors shown in the summary row.
    pub summary_top_n: usize,
    /// Whether to include the "Other" category in panels.
    pub show_other_category: bool,
}

impl Default for LedgerDisplayConfig {
    fn default() -> Self {
        Self {
            summary_top_n: 3,
            show_other_category: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Core display structure
// ---------------------------------------------------------------------------

/// Complete ledger display ready for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerDisplay {
    pub classification: Classification,
    pub confidence: Confidence,
    /// Top N contributors (summary row).
    pub summary_items: Vec<EvidenceItem>,
    /// Evidence organised into category panels.
    pub panels: Vec<CategoryPanel>,
    /// Total evidence in bits (sum of absolute delta_bits).
    pub total_evidence_bits: f64,
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Build a `LedgerDisplay` from an `EvidenceLedger`.
pub fn build_display(ledger: &EvidenceLedger, config: &LedgerDisplayConfig) -> LedgerDisplay {
    let total_abs: f64 = ledger
        .bayes_factors
        .iter()
        .map(|bf| bf.delta_bits.abs())
        .sum();
    let total_abs_safe = if total_abs == 0.0 { 1.0 } else { total_abs };

    // Convert to EvidenceItems.
    let items: Vec<EvidenceItem> = ledger
        .bayes_factors
        .iter()
        .map(|bf| EvidenceItem {
            feature: bf.feature.clone(),
            category: categorize_feature(&bf.feature),
            bf: bf.bf,
            log_bf: bf.log_bf,
            delta_bits: bf.delta_bits,
            direction: bf.direction.clone(),
            strength: bf.strength.clone(),
            weight: bf.delta_bits.abs() / total_abs_safe,
        })
        .collect();

    // Summary: top N by absolute delta_bits.
    let mut sorted = items.clone();
    sorted.sort_by(|a, b| {
        b.delta_bits
            .abs()
            .partial_cmp(&a.delta_bits.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let summary_items: Vec<EvidenceItem> = sorted.into_iter().take(config.summary_top_n).collect();

    // Group into category panels.
    let mut panels = build_panels(&items, config);
    // Sort panels by total_bits descending.
    panels.sort_by(|a, b| {
        b.total_bits
            .partial_cmp(&a.total_bits)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    LedgerDisplay {
        classification: ledger.classification,
        confidence: ledger.confidence,
        summary_items,
        panels,
        total_evidence_bits: total_abs,
    }
}

fn build_panels(items: &[EvidenceItem], config: &LedgerDisplayConfig) -> Vec<CategoryPanel> {
    use std::collections::HashMap;
    let mut groups: HashMap<EvidenceCategory, Vec<EvidenceItem>> = HashMap::new();
    for item in items {
        if !config.show_other_category && item.category == EvidenceCategory::Other {
            continue;
        }
        groups.entry(item.category).or_default().push(item.clone());
    }

    groups
        .into_iter()
        .map(|(cat, mut items)| {
            // Sort items within panel by absolute delta_bits descending.
            items.sort_by(|a, b| {
                b.delta_bits
                    .abs()
                    .partial_cmp(&a.delta_bits.abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let total_bits: f64 = items.iter().map(|i| i.delta_bits.abs()).sum();
            CategoryPanel {
                category: cat,
                label: cat.label().to_string(),
                items,
                total_bits,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/// Filter evidence items from a ledger display.
pub fn filter_evidence(display: &LedgerDisplay, filter: &EvidenceFilter) -> Vec<EvidenceItem> {
    let all_items: Vec<&EvidenceItem> = display.panels.iter().flat_map(|p| &p.items).collect();

    let pattern_lower = filter.name_pattern.as_ref().map(|p| p.to_lowercase());

    let mut result: Vec<EvidenceItem> = all_items
        .into_iter()
        .filter(|item| {
            // Category filter.
            if !filter.categories.is_empty() && !filter.categories.contains(&item.category) {
                return false;
            }
            // Strength filter.
            if item.delta_bits.abs() < filter.min_strength_bits {
                return false;
            }
            // Name pattern filter.
            if let Some(ref pat) = pattern_lower {
                if !item.feature.to_lowercase().contains(pat) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    // Sort by absolute delta_bits descending.
    result.sort_by(|a, b| {
        b.delta_bits
            .abs()
            .partial_cmp(&a.delta_bits.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some(limit) = filter.limit {
        result.truncate(limit);
    }

    result
}

// ---------------------------------------------------------------------------
// Text rendering
// ---------------------------------------------------------------------------

/// Render the ledger display as a formatted text string.
pub fn render_text(display: &LedgerDisplay) -> String {
    let mut lines = Vec::new();

    // Header.
    lines.push(format!(
        "Evidence Ledger: {:?} ({}) — {:.1} bits total",
        display.classification, display.confidence, display.total_evidence_bits,
    ));
    lines.push(String::new());

    // Summary row.
    lines.push("Top contributors:".to_string());
    for item in &display.summary_items {
        lines.push(format!(
            "  {:20} {:>+6.2} bits  ({:.0}%)  [{}]",
            item.feature,
            item.delta_bits,
            item.weight * 100.0,
            item.strength,
        ));
    }

    // Category panels.
    for panel in &display.panels {
        lines.push(String::new());
        lines.push(format!(
            "── {} ({:.1} bits) ──",
            panel.label, panel.total_bits,
        ));
        for item in &panel.items {
            let arrow = if item.log_bf > 0.0 { "↑" } else { "↓" };
            lines.push(format!(
                "  {:20} BF={:>8.2}  {}{:.1} bits  [{}]",
                item.feature,
                item.bf,
                arrow,
                item.delta_bits.abs(),
                item.strength,
            ));
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::{ClassScores, PosteriorResult};
    use std::collections::HashMap;

    fn mock_ledger() -> EvidenceLedger {
        EvidenceLedger {
            posterior: PosteriorResult {
                posterior: ClassScores {
                    useful: 0.05,
                    useful_bad: 0.03,
                    abandoned: 0.87,
                    zombie: 0.05,
                },
                log_posterior: ClassScores::default(),
                log_odds_abandoned_useful: 2.86,
                evidence_terms: vec![],
            },
            classification: Classification::Abandoned,
            confidence: Confidence::High,
            bayes_factors: vec![
                BayesFactorEntry {
                    feature: "cpu_occupancy".to_string(),
                    bf: 6.69,
                    log_bf: 1.9,
                    delta_bits: 2.74,
                    direction: "supports abandoned".to_string(),
                    strength: "strong".to_string(),
                },
                BayesFactorEntry {
                    feature: "age_elapsed".to_string(),
                    bf: 4.95,
                    log_bf: 1.6,
                    delta_bits: 2.31,
                    direction: "supports abandoned".to_string(),
                    strength: "strong".to_string(),
                },
                BayesFactorEntry {
                    feature: "net_sockets".to_string(),
                    bf: 0.3,
                    log_bf: -1.2,
                    delta_bits: -1.73,
                    direction: "supports useful".to_string(),
                    strength: "substantial".to_string(),
                },
                BayesFactorEntry {
                    feature: "orphan_ppid".to_string(),
                    bf: 2.0,
                    log_bf: 0.69,
                    delta_bits: 1.0,
                    direction: "supports abandoned".to_string(),
                    strength: "weak".to_string(),
                },
                BayesFactorEntry {
                    feature: "fd_count".to_string(),
                    bf: 1.5,
                    log_bf: 0.4,
                    delta_bits: 0.58,
                    direction: "supports abandoned".to_string(),
                    strength: "weak".to_string(),
                },
            ],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        }
    }

    #[test]
    fn test_categorize_features() {
        assert_eq!(categorize_feature("cpu_occupancy"), EvidenceCategory::Resource);
        assert_eq!(categorize_feature("age_elapsed"), EvidenceCategory::Timing);
        assert_eq!(categorize_feature("orphan_ppid"), EvidenceCategory::Context);
        assert_eq!(categorize_feature("net_sockets"), EvidenceCategory::Network);
        assert_eq!(categorize_feature("state_flag"), EvidenceCategory::Behavior);
        assert_eq!(categorize_feature("unknown_xyz"), EvidenceCategory::Other);
    }

    #[test]
    fn test_build_display() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        assert_eq!(display.classification, Classification::Abandoned);
        assert_eq!(display.confidence, Confidence::High);
        assert_eq!(display.summary_items.len(), 3);
        assert!(!display.panels.is_empty());
        assert!(display.total_evidence_bits > 0.0);
    }

    #[test]
    fn test_summary_top_n() {
        let ledger = mock_ledger();
        let config = LedgerDisplayConfig {
            summary_top_n: 2,
            ..Default::default()
        };
        let display = build_display(&ledger, &config);
        assert_eq!(display.summary_items.len(), 2);
        // First item should be the strongest.
        assert_eq!(display.summary_items[0].feature, "cpu_occupancy");
    }

    #[test]
    fn test_panels_sorted_by_total_bits() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        for w in display.panels.windows(2) {
            assert!(w[0].total_bits >= w[1].total_bits);
        }
    }

    #[test]
    fn test_weight_sums_to_one() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        let total_weight: f64 = display
            .panels
            .iter()
            .flat_map(|p| &p.items)
            .map(|i| i.weight)
            .sum();
        assert!((total_weight - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_filter_by_category() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        let filter = EvidenceFilter {
            categories: vec![EvidenceCategory::Resource],
            ..Default::default()
        };
        let results = filter_evidence(&display, &filter);
        assert!(results.iter().all(|i| i.category == EvidenceCategory::Resource));
        assert!(!results.is_empty());
    }

    #[test]
    fn test_filter_by_strength() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        let filter = EvidenceFilter {
            min_strength_bits: 2.0,
            ..Default::default()
        };
        let results = filter_evidence(&display, &filter);
        assert!(results.iter().all(|i| i.delta_bits.abs() >= 2.0));
    }

    #[test]
    fn test_filter_by_name() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        let filter = EvidenceFilter {
            name_pattern: Some("cpu".to_string()),
            ..Default::default()
        };
        let results = filter_evidence(&display, &filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].feature, "cpu_occupancy");
    }

    #[test]
    fn test_filter_limit() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        let filter = EvidenceFilter {
            limit: Some(2),
            ..Default::default()
        };
        let results = filter_evidence(&display, &filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_render_text() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());
        let text = render_text(&display);

        assert!(text.contains("Evidence Ledger"));
        assert!(text.contains("Abandoned"));
        assert!(text.contains("Top contributors"));
        assert!(text.contains("cpu_occupancy"));
        assert!(text.contains("bits"));
    }

    #[test]
    fn test_empty_ledger() {
        let ledger = EvidenceLedger {
            posterior: PosteriorResult {
                posterior: ClassScores::default(),
                log_posterior: ClassScores::default(),
                log_odds_abandoned_useful: 0.0,
                evidence_terms: vec![],
            },
            classification: Classification::Useful,
            confidence: Confidence::Low,
            bayes_factors: vec![],
            top_evidence: vec![],
            why_summary: String::new(),
            evidence_glyphs: HashMap::new(),
        };
        let display = build_display(&ledger, &LedgerDisplayConfig::default());

        assert!(display.summary_items.is_empty());
        assert!(display.panels.is_empty());
        assert_eq!(display.total_evidence_bits, 0.0);
    }

    #[test]
    fn test_hide_other_category() {
        let mut ledger = mock_ledger();
        ledger.bayes_factors.push(BayesFactorEntry {
            feature: "mystery_signal".to_string(),
            bf: 2.0,
            log_bf: 0.69,
            delta_bits: 1.0,
            direction: "supports abandoned".to_string(),
            strength: "weak".to_string(),
        });

        let config = LedgerDisplayConfig {
            show_other_category: false,
            ..Default::default()
        };
        let display = build_display(&ledger, &config);
        assert!(display
            .panels
            .iter()
            .all(|p| p.category != EvidenceCategory::Other));
    }

    #[test]
    fn test_serialization() {
        let ledger = mock_ledger();
        let display = build_display(&ledger, &LedgerDisplayConfig::default());
        let json = serde_json::to_string(&display).unwrap();
        let restored: LedgerDisplay = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.classification, Classification::Abandoned);
        assert_eq!(restored.summary_items.len(), display.summary_items.len());
    }
}
