//! Golden snapshot tests for the provenance output contract (bd-86bi).
//!
//! These tests verify that `CandidateProvenanceOutput` serialization matches
//! committed golden files.  If a rendering change is intentional, update the
//! fixture and re-run.

mod support;

use pt_common::{
    CandidateBlastRadiusOutput, CandidateProvenanceOutput, NarrativeVerbosity,
    ProvenanceFeatureContribution, ProvenanceNarrative, ProvenanceRedactionState,
    ProvenanceScoreImpact,
};
use serde_json::Value;
use support::provenance_fixture::provenance_fixture_path;

fn load_golden(name: &str) -> Value {
    let path = provenance_fixture_path(name);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read golden file {}: {}", path.display(), e));
    serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("parse golden file {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Structured output contract snapshots
// ---------------------------------------------------------------------------

#[test]
fn disabled_output_matches_golden() {
    let output = CandidateProvenanceOutput::disabled();
    let actual = serde_json::to_value(&output).expect("serialize");
    let expected = load_golden("provenance_output_disabled.json");
    assert_eq!(
        actual, expected,
        "CandidateProvenanceOutput::disabled() drifted from golden snapshot"
    );
}

#[test]
fn full_output_matches_golden() {
    let output = CandidateProvenanceOutput {
        enabled: true,
        evidence_completeness: 0.85,
        confidence_penalty_steps: 1,
        confidence_notes: vec!["resource provenance has 2 unresolved edge(s)".to_string()],
        score_terms: vec![
            "provenance_ownership_orphaned".to_string(),
            "provenance_blast_radius_low".to_string(),
        ],
        blast_radius: CandidateBlastRadiusOutput {
            risk_score: 0.12,
            risk_level: "low".to_string(),
            confidence: 0.90,
            summary: "Isolated process with no shared resources".to_string(),
            total_affected: 0,
        },
        redaction_state: ProvenanceRedactionState::None,
        score_impact: Some(ProvenanceScoreImpact {
            log_odds_shift: 0.35,
            feature_contributions: vec![
                ProvenanceFeatureContribution {
                    feature: "provenance_ownership_orphaned".to_string(),
                    abandoned_ll: 0.70,
                    useful_ll: -0.55,
                    direction: "toward_abandon".to_string(),
                },
                ProvenanceFeatureContribution {
                    feature: "provenance_blast_radius_low".to_string(),
                    abandoned_ll: 0.35,
                    useful_ll: -0.25,
                    direction: "toward_abandon".to_string(),
                },
            ],
        }),
    };

    let actual = serde_json::to_value(&output).expect("serialize");
    let expected = load_golden("provenance_output_full.json");
    assert_eq!(
        actual, expected,
        "Full CandidateProvenanceOutput drifted from golden snapshot"
    );
}

#[test]
fn redacted_high_blast_output_matches_golden() {
    let output = CandidateProvenanceOutput {
        enabled: true,
        evidence_completeness: 0.45,
        confidence_penalty_steps: 3,
        confidence_notes: vec![
            "missing lineage provenance".to_string(),
            "resource provenance has 3 unresolved edge(s)".to_string(),
            "blast-radius estimate is low-confidence".to_string(),
        ],
        score_terms: vec!["provenance_blast_radius_high".to_string()],
        blast_radius: CandidateBlastRadiusOutput {
            risk_score: 0.82,
            risk_level: "high".to_string(),
            confidence: 0.35,
            summary: "Process shares 5 lockfiles with 8 peers".to_string(),
            total_affected: 8,
        },
        redaction_state: ProvenanceRedactionState::Partial,
        score_impact: Some(ProvenanceScoreImpact {
            log_odds_shift: -0.10,
            feature_contributions: vec![ProvenanceFeatureContribution {
                feature: "provenance_blast_radius_high".to_string(),
                abandoned_ll: -0.75,
                useful_ll: 0.65,
                direction: "toward_useful".to_string(),
            }],
        }),
    };

    let actual = serde_json::to_value(&output).expect("serialize");
    let expected = load_golden("provenance_output_redacted_high_blast.json");
    assert_eq!(
        actual, expected,
        "Redacted/high-blast CandidateProvenanceOutput drifted from golden snapshot"
    );
}

// ---------------------------------------------------------------------------
// Narrative rendering snapshots
// ---------------------------------------------------------------------------

fn sample_provenance_for_narrative() -> CandidateProvenanceOutput {
    CandidateProvenanceOutput {
        enabled: true,
        evidence_completeness: 0.72,
        confidence_penalty_steps: 2,
        confidence_notes: vec![
            "missing lineage provenance".to_string(),
            "resource provenance has 2 unresolved edge(s)".to_string(),
        ],
        score_terms: vec![
            "provenance_ownership_orphaned".to_string(),
            "provenance_blast_radius_low".to_string(),
        ],
        blast_radius: CandidateBlastRadiusOutput {
            risk_score: 0.15,
            risk_level: "low".to_string(),
            confidence: 0.60,
            summary: "Isolated process, no shared resources".to_string(),
            total_affected: 0,
        },
        redaction_state: ProvenanceRedactionState::None,
        score_impact: None,
    }
}

#[test]
fn narrative_compact_is_single_line_under_80_chars() {
    let output = sample_provenance_for_narrative();
    let narrative = ProvenanceNarrative::from_output(&output);
    let rendered = narrative.render(NarrativeVerbosity::Compact);
    assert!(!rendered.contains('\n'), "Compact should be one line");
    assert!(
        rendered.len() <= 80,
        "Compact headline should be ≤80 chars, got {} chars: {:?}",
        rendered.len(),
        rendered
    );
}

#[test]
fn narrative_standard_includes_all_sections() {
    let output = sample_provenance_for_narrative();
    let narrative = ProvenanceNarrative::from_output(&output);
    let rendered = narrative.render(NarrativeVerbosity::Standard);
    assert!(
        rendered.contains("Provenance Signals"),
        "missing signals section"
    );
    assert!(
        rendered.contains("Blast Radius"),
        "missing blast radius section"
    );
    assert!(
        rendered.contains("Uncertainty"),
        "missing uncertainty section"
    );
    assert!(rendered.contains("Caveats"), "missing caveats");
}

#[test]
fn narrative_full_includes_details_and_caveats() {
    let output = sample_provenance_for_narrative();
    let narrative = ProvenanceNarrative::from_output(&output);
    let rendered = narrative.render(NarrativeVerbosity::Full);
    assert!(
        rendered.contains("orphaned"),
        "should translate score term to human label"
    );
    assert!(
        rendered.contains("low blast radius"),
        "should translate blast radius term"
    );
    assert!(
        rendered.contains("missing lineage"),
        "caveats should appear"
    );
    assert!(
        rendered.contains("unresolved edge"),
        "caveats should appear"
    );
}

#[test]
fn narrative_disabled_is_minimal() {
    let output = CandidateProvenanceOutput::disabled();
    let narrative = ProvenanceNarrative::from_output(&output);
    let rendered = narrative.render(NarrativeVerbosity::Full);
    assert_eq!(rendered.trim(), "Provenance: not available");
}

#[test]
fn narrative_redaction_caveat_surfaces() {
    let mut output = sample_provenance_for_narrative();
    output.redaction_state = ProvenanceRedactionState::Partial;
    let narrative = ProvenanceNarrative::from_output(&output);
    assert!(
        narrative.caveats.iter().any(|c| c.contains("redacted")),
        "Partial redaction must produce a caveat"
    );
}

#[test]
fn narrative_score_impact_section_present_when_populated() {
    let mut output = sample_provenance_for_narrative();
    output.score_impact = Some(ProvenanceScoreImpact {
        log_odds_shift: 1.2,
        feature_contributions: vec![ProvenanceFeatureContribution {
            feature: "provenance_ownership_orphaned".to_string(),
            abandoned_ll: 0.70,
            useful_ll: -0.55,
            direction: "toward_abandon".to_string(),
        }],
    });
    let narrative = ProvenanceNarrative::from_output(&output);
    let rendered = narrative.render(NarrativeVerbosity::Standard);
    assert!(
        rendered.contains("Score Impact"),
        "Score Impact section should appear when score_impact is populated"
    );
}
