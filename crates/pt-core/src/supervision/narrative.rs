//! Genealogy narrative rendering for process ancestry chains.
//!
//! This module provides deterministic, human-readable summaries of a process'
//! ancestry chain for agent/human explainability.

use super::AncestryEntry;

/// Narrative verbosity presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrativeStyle {
    /// Minimal summary: only target + immediate parent.
    Brief,
    /// Default summary: include full chain.
    Standard,
    /// Detailed summary (currently same as standard).
    Detailed,
}

/// Render a genealogy narrative with standard verbosity.
pub fn render_narrative(chain: &[AncestryEntry]) -> String {
    render_narrative_with_style(chain, NarrativeStyle::Standard)
}

/// Render a genealogy narrative with a selected style.
pub fn render_narrative_with_style(chain: &[AncestryEntry], style: NarrativeStyle) -> String {
    if chain.is_empty() {
        return "No ancestry information available.".to_string();
    }

    let target = &chain[0];
    if chain.len() == 1 {
        return format!(
            "Process '{}' (PID {}) has no recorded parent.",
            target.comm, target.pid.0
        );
    }

    let limit = match style {
        NarrativeStyle::Brief => 2,
        NarrativeStyle::Standard | NarrativeStyle::Detailed => chain.len(),
    };

    let mut narrative = format!(
        "Process '{}' (PID {}) was spawned by '{}' (PID {})",
        target.comm,
        target.pid.0,
        chain[1].comm,
        chain[1].pid.0
    );

    if chain.len() == 2 && chain[1].pid.0 == 1 {
        narrative.push_str(" and appears orphaned (parent is init)");
    }

    if limit > 2 {
        for entry in chain.iter().skip(2).take(limit - 2) {
            narrative.push_str(&format!(
                ", which was spawned by '{}' (PID {})",
                entry.comm, entry.pid.0
            ));
        }
    }

    if limit < chain.len() {
        narrative.push_str(&format!(
            ", and {} more ancestor(s)",
            chain.len().saturating_sub(limit)
        ));
    }

    narrative.push('.');
    narrative
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::ProcessId;

    fn entry(pid: u32, comm: &str) -> AncestryEntry {
        AncestryEntry {
            pid: ProcessId(pid),
            comm: comm.to_string(),
            cmdline: None,
        }
    }

    #[test]
    fn narrative_empty_chain() {
        let narrative = render_narrative(&[]);
        assert!(narrative.contains("No ancestry information"));
    }

    #[test]
    fn narrative_orphan_detection() {
        let chain = vec![entry(1234, "node"), entry(1, "init")];
        let narrative = render_narrative(&chain);
        assert!(narrative.contains("orphaned"));
    }

    #[test]
    fn narrative_brief_truncates() {
        let chain = vec![
            entry(100, "node"),
            entry(90, "bash"),
            entry(1, "init"),
        ];
        let narrative = render_narrative_with_style(&chain, NarrativeStyle::Brief);
        assert!(narrative.contains("and 1 more ancestor"));
    }
}
