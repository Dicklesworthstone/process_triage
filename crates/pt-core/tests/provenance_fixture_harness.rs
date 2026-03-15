//! Provenance fixture harness tests for bd-ppcl.16.

mod support;

use pt_common::{
    ProvenanceConfidence, ProvenanceConsentRequirement, PROVENANCE_PRIVACY_POLICY_VERSION,
};
use support::provenance_fixture::{load_provenance_graph_fixture, load_provenance_trace_fixture};

#[test]
fn provenance_graph_fixture_covers_redacted_missing_and_conflicted_cases() {
    let fixture = load_provenance_graph_fixture("provenance_privacy_snapshot.json");

    assert_eq!(fixture.schema_version, "1.0.0");
    assert_eq!(fixture.privacy.version, PROVENANCE_PRIVACY_POLICY_VERSION);
    assert!(fixture.summary.redacted_evidence_count >= 1);
    assert!(fixture.summary.missing_or_conflicted_evidence_count >= 2);
    assert!(fixture
        .privacy
        .field_policies
        .iter()
        .any(|policy| policy.consent != ProvenanceConsentRequirement::None));
    assert!(fixture
        .warnings
        .iter()
        .any(|warning| warning.code == "workspace_withheld_by_policy"));
    assert!(fixture
        .warnings
        .iter()
        .any(|warning| warning.confidence == ProvenanceConfidence::Low));
}

#[test]
fn provenance_debug_trace_fixture_uses_canonical_event_vocabulary() {
    let events = load_provenance_trace_fixture("provenance_debug_trace.jsonl");

    assert_eq!(events.len(), 4, "expected canonical provenance debug trace");

    let names: Vec<&str> = events
        .iter()
        .map(|event| event["event"].as_str().expect("event name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "provenance_fixture_loaded",
            "provenance_evidence_redacted",
            "provenance_evidence_missing",
            "provenance_confidence_downgraded"
        ]
    );

    for event in &events {
        assert!(event["timestamp"].is_string(), "timestamp required");
        assert!(event["session_id"].is_string(), "session_id required");
        assert!(
            event["privacy_version"].is_string(),
            "privacy_version required"
        );
        assert!(event["message"].is_string(), "message required");
    }

    let downgrade = events
        .iter()
        .find(|event| event["event"] == "provenance_confidence_downgraded")
        .expect("downgrade event");
    assert_eq!(downgrade["before"], "high");
    assert_eq!(downgrade["after"], "low");
}
