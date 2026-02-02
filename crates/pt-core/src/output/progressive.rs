//! Progressive disclosure rendering for process candidates.
//!
//! Four information layers with increasing detail:
//! - Layer 1 (Table): one-line compact view per candidate.
//! - Layer 2 (Expanded): short evidence summary + risk badge.
//! - Layer 3 (Detail): full drill-down with evidence ledger, tree, plan.
//! - Layer 4 (GalaxyBrain): equations + substituted numbers.
//!
//! Each layer is a pure data struct that renderers (TUI, JSON, plain text)
//! can consume independently.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Disclosure layers
// ---------------------------------------------------------------------------

/// Disclosure level selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    Table = 1,
    Expanded = 2,
    Detail = 3,
    GalaxyBrain = 4,
}

impl DisclosureLevel {
    pub fn next(self) -> Self {
        match self {
            Self::Table => Self::Expanded,
            Self::Expanded => Self::Detail,
            Self::Detail => Self::GalaxyBrain,
            Self::GalaxyBrain => Self::GalaxyBrain,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Table => Self::Table,
            Self::Expanded => Self::Table,
            Self::Detail => Self::Expanded,
            Self::GalaxyBrain => Self::Detail,
        }
    }
}

/// Layer 1: compact table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRow {
    pub action: String,
    pub pid: u32,
    pub age_display: String,
    pub memory_display: String,
    pub command: String,
    pub top_posterior: f64,
    pub top_class: String,
    pub delta_expected_loss: Option<f64>,
}

/// Layer 2: expanded row with evidence tags and risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandedRow {
    pub table: TableRow,
    pub evidence_tags: Vec<String>,
    pub risk_badge: String,
    pub confidence_badge: String,
}

/// Layer 3: full detail pane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailPane {
    pub expanded: ExpandedRow,
    /// Evidence ledger entries (feature, bits, direction).
    pub evidence_ledger: Vec<EvidenceEntry>,
    /// Expected loss breakdown by action.
    pub expected_loss_table: Option<LossTable>,
    /// Process tree summary.
    pub process_tree_summary: Option<String>,
    /// Action plan steps.
    pub action_plan: Vec<String>,
    /// Flip conditions summary.
    pub flip_conditions: Vec<String>,
}

/// Layer 4: galaxy-brain full math trace (opaque string from galaxy_brain module).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalaxyBrainPane {
    pub detail: DetailPane,
    pub math_trace: String,
}

/// Evidence entry for the detail pane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub feature: String,
    pub bits: f64,
    pub direction: String,
    pub strength: String,
}

/// Expected loss table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossTable {
    pub keep: f64,
    pub pause: f64,
    pub kill: f64,
    pub recommended: String,
}

// ---------------------------------------------------------------------------
// Rendering to text
// ---------------------------------------------------------------------------

/// Render a table row as a compact one-liner.
pub fn render_table_row(row: &TableRow) -> String {
    let del = row
        .delta_expected_loss
        .map(|d| format!("  ΔEL={:+.0}", d))
        .unwrap_or_default();
    format!(
        "[{}] PID:{}  {}  {}  {}  P({})={:.2}{}",
        row.action, row.pid, row.age_display, row.memory_display,
        row.command, row.top_class, row.top_posterior, del,
    )
}

/// Render an expanded row (table row + evidence tags).
pub fn render_expanded_row(row: &ExpandedRow) -> String {
    let table_line = render_table_row(&row.table);
    let tags = row.evidence_tags.join(" · ");
    format!(
        "{}\n  {} · risk: {} · confidence: {}",
        table_line, tags, row.risk_badge, row.confidence_badge,
    )
}

/// Render a detail pane as multi-line text.
pub fn render_detail_pane(pane: &DetailPane) -> String {
    let mut lines = Vec::new();
    lines.push(render_expanded_row(&pane.expanded));

    if !pane.evidence_ledger.is_empty() {
        lines.push(String::new());
        lines.push("  Evidence:".to_string());
        for e in &pane.evidence_ledger {
            lines.push(format!(
                "    {:20} {:>+6.1} bits  [{}]  {}",
                e.feature, e.bits, e.strength, e.direction,
            ));
        }
    }

    if let Some(ref loss) = pane.expected_loss_table {
        lines.push(String::new());
        lines.push(format!(
            "  Expected loss: keep={:.1}  pause={:.1}  kill={:.1}  → {}",
            loss.keep, loss.pause, loss.kill, loss.recommended,
        ));
    }

    if let Some(ref tree) = pane.process_tree_summary {
        lines.push(String::new());
        lines.push(format!("  Tree: {}", tree));
    }

    if !pane.flip_conditions.is_empty() {
        lines.push(String::new());
        lines.push("  Flip conditions:".to_string());
        for fc in &pane.flip_conditions {
            lines.push(format!("    - {}", fc));
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

    fn sample_table_row() -> TableRow {
        TableRow {
            action: "KILL".to_string(),
            pid: 12345,
            age_display: "11d".to_string(),
            memory_display: "2048M".to_string(),
            command: "bun test --watch".to_string(),
            top_posterior: 0.94,
            top_class: "ab".to_string(),
            delta_expected_loss: Some(-35.0),
        }
    }

    fn sample_expanded() -> ExpandedRow {
        ExpandedRow {
            table: sample_table_row(),
            evidence_tags: vec![
                "test_runner".to_string(),
                "tty_lost".to_string(),
                "io_idle".to_string(),
            ],
            risk_badge: "CAUTION".to_string(),
            confidence_badge: "HIGH".to_string(),
        }
    }

    fn sample_detail() -> DetailPane {
        DetailPane {
            expanded: sample_expanded(),
            evidence_ledger: vec![
                EvidenceEntry {
                    feature: "cpu_occupancy".to_string(),
                    bits: 2.74,
                    direction: "supports abandoned".to_string(),
                    strength: "strong".to_string(),
                },
            ],
            expected_loss_table: Some(LossTable {
                keep: 28.2,
                pause: 15.1,
                kill: 6.4,
                recommended: "kill".to_string(),
            }),
            process_tree_summary: Some("3 children, 1 grandchild".to_string()),
            action_plan: vec!["SIGTERM → wait 5s → SIGKILL".to_string()],
            flip_conditions: vec!["remove cpu_occupancy → drops 12pp".to_string()],
        }
    }

    #[test]
    fn test_table_row_rendering() {
        let output = render_table_row(&sample_table_row());
        assert!(output.contains("[KILL]"));
        assert!(output.contains("PID:12345"));
        assert!(output.contains("P(ab)=0.94"));
        assert!(output.contains("ΔEL=-35"));
    }

    #[test]
    fn test_table_row_no_delta() {
        let mut row = sample_table_row();
        row.delta_expected_loss = None;
        let output = render_table_row(&row);
        assert!(!output.contains("ΔEL"));
    }

    #[test]
    fn test_expanded_row_rendering() {
        let output = render_expanded_row(&sample_expanded());
        assert!(output.contains("test_runner"));
        assert!(output.contains("risk: CAUTION"));
        assert!(output.contains("confidence: HIGH"));
    }

    #[test]
    fn test_detail_pane_rendering() {
        let output = render_detail_pane(&sample_detail());
        assert!(output.contains("Evidence:"));
        assert!(output.contains("cpu_occupancy"));
        assert!(output.contains("Expected loss"));
        assert!(output.contains("kill=6.4"));
        assert!(output.contains("Tree:"));
        assert!(output.contains("Flip conditions:"));
    }

    #[test]
    fn test_disclosure_level_navigation() {
        assert_eq!(DisclosureLevel::Table.next(), DisclosureLevel::Expanded);
        assert_eq!(DisclosureLevel::Expanded.next(), DisclosureLevel::Detail);
        assert_eq!(DisclosureLevel::Detail.next(), DisclosureLevel::GalaxyBrain);
        assert_eq!(DisclosureLevel::GalaxyBrain.next(), DisclosureLevel::GalaxyBrain);

        assert_eq!(DisclosureLevel::Table.prev(), DisclosureLevel::Table);
        assert_eq!(DisclosureLevel::Expanded.prev(), DisclosureLevel::Table);
        assert_eq!(DisclosureLevel::GalaxyBrain.prev(), DisclosureLevel::Detail);
    }

    #[test]
    fn test_disclosure_level_ordering() {
        assert!(DisclosureLevel::Table < DisclosureLevel::Expanded);
        assert!(DisclosureLevel::Expanded < DisclosureLevel::Detail);
        assert!(DisclosureLevel::Detail < DisclosureLevel::GalaxyBrain);
    }

    #[test]
    fn test_serialization() {
        let row = sample_table_row();
        let json = serde_json::to_string(&row).unwrap();
        let restored: TableRow = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pid, 12345);
    }

    #[test]
    fn test_detail_pane_empty_optional_sections() {
        let pane = DetailPane {
            expanded: sample_expanded(),
            evidence_ledger: vec![],
            expected_loss_table: None,
            process_tree_summary: None,
            action_plan: vec![],
            flip_conditions: vec![],
        };
        let output = render_detail_pane(&pane);
        assert!(!output.contains("Evidence:"));
        assert!(!output.contains("Expected loss"));
        assert!(!output.contains("Tree:"));
    }
}
