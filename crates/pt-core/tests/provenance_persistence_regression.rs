//! Regression tests for provenance persistence failure modes.
//!
//! Covers corruption, truncation, version-skew, omission, and
//! redaction-path behavior to ensure replay remains trustworthy.

mod support;

use pt_common::{
    ProvenanceConfidence, ProvenanceEdge, ProvenanceEdgeId, ProvenanceEdgeKind, ProvenanceEvidence,
    ProvenanceEvidenceId, ProvenanceEvidenceKind, ProvenanceGraphSnapshot, ProvenanceGraphWarning,
    ProvenanceNode, ProvenanceNodeId, ProvenanceNodeKind, ProvenanceObservationStatus,
    ProvenanceRedactionState, PROVENANCE_SCHEMA_VERSION,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helper: build a minimal valid provenance graph
// ---------------------------------------------------------------------------

fn minimal_graph() -> ProvenanceGraphSnapshot {
    let evidence_id =
        ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Procfs, "procfs:pid=42:start=1:42");
    let process_id = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:42:1:42");

    let evidence = ProvenanceEvidence {
        id: evidence_id.clone(),
        kind: ProvenanceEvidenceKind::Procfs,
        source: "/proc/42/stat".to_string(),
        observed_at: "2026-03-16T00:00:00Z".to_string(),
        status: ProvenanceObservationStatus::Observed,
        confidence: ProvenanceConfidence::High,
        redaction: ProvenanceRedactionState::None,
        process: None,
        attributes: BTreeMap::new(),
    };

    let process = ProvenanceNode {
        id: process_id.clone(),
        kind: ProvenanceNodeKind::Process,
        label: "pytest".to_string(),
        confidence: ProvenanceConfidence::High,
        redaction: ProvenanceRedactionState::None,
        evidence_ids: vec![evidence_id],
        attributes: BTreeMap::from([("pid".to_string(), serde_json::json!(42))]),
    };

    ProvenanceGraphSnapshot::new(
        "2026-03-16T00:00:00Z".to_string(),
        Some("test-session".to_string()),
        Some("test-host".to_string()),
        vec![process],
        Vec::new(),
        vec![evidence],
        Vec::new(),
    )
}

fn graph_with_redacted_evidence() -> ProvenanceGraphSnapshot {
    let evidence_id =
        ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Git, "git:workspace:redacted");
    let process_id = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:99:1:99");
    let workspace_id = ProvenanceNodeId::new(ProvenanceNodeKind::Workspace, "workspace:redacted");

    let evidence = ProvenanceEvidence {
        id: evidence_id.clone(),
        kind: ProvenanceEvidenceKind::Git,
        source: "<git:redacted>".to_string(),
        observed_at: "2026-03-16T00:00:00Z".to_string(),
        status: ProvenanceObservationStatus::Redacted,
        confidence: ProvenanceConfidence::Low,
        redaction: ProvenanceRedactionState::Full,
        process: None,
        attributes: BTreeMap::from([("reason".to_string(), serde_json::json!("policy_withheld"))]),
    };

    let process = ProvenanceNode {
        id: process_id.clone(),
        kind: ProvenanceNodeKind::Process,
        label: "dev-server".to_string(),
        confidence: ProvenanceConfidence::High,
        redaction: ProvenanceRedactionState::None,
        evidence_ids: vec![evidence_id.clone()],
        attributes: BTreeMap::new(),
    };

    let workspace = ProvenanceNode {
        id: workspace_id.clone(),
        kind: ProvenanceNodeKind::Workspace,
        label: "<workspace:redacted>".to_string(),
        confidence: ProvenanceConfidence::Low,
        redaction: ProvenanceRedactionState::Full,
        evidence_ids: vec![evidence_id.clone()],
        attributes: BTreeMap::new(),
    };

    let edge = ProvenanceEdge {
        id: ProvenanceEdgeId::new(
            ProvenanceEdgeKind::AttachedToWorkspace,
            &process_id,
            &workspace_id,
        ),
        kind: ProvenanceEdgeKind::AttachedToWorkspace,
        from: process_id,
        to: workspace_id,
        confidence: ProvenanceConfidence::Low,
        redaction: ProvenanceRedactionState::Partial,
        evidence_ids: vec![evidence_id],
        derived_from_edge_ids: Vec::new(),
        attributes: BTreeMap::new(),
    };

    let warning = ProvenanceGraphWarning {
        code: "workspace_withheld_by_policy".to_string(),
        message: "workspace provenance was withheld by privacy policy".to_string(),
        confidence: ProvenanceConfidence::Low,
        evidence_ids: Vec::new(),
    };

    ProvenanceGraphSnapshot::new(
        "2026-03-16T00:00:00Z".to_string(),
        Some("test-session".to_string()),
        Some("test-host".to_string()),
        vec![process, workspace],
        vec![edge],
        vec![evidence],
        vec![warning],
    )
}

// ---------------------------------------------------------------------------
// Scenario: JSON round-trip preserves all fields
// ---------------------------------------------------------------------------

#[test]
fn provenance_json_round_trip_preserves_all_fields() {
    let graph = minimal_graph();
    let json = serde_json::to_string_pretty(&graph).expect("serialize");
    let parsed: ProvenanceGraphSnapshot = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(parsed.schema_version, PROVENANCE_SCHEMA_VERSION);
    assert_eq!(parsed.summary.node_count, graph.summary.node_count);
    assert_eq!(parsed.summary.edge_count, graph.summary.edge_count);
    assert_eq!(parsed.summary.evidence_count, graph.summary.evidence_count);
    assert_eq!(parsed.nodes.len(), graph.nodes.len());
    assert_eq!(parsed.edges.len(), graph.edges.len());
    assert_eq!(parsed.evidence.len(), graph.evidence.len());
    assert_eq!(parsed, graph);
}

// ---------------------------------------------------------------------------
// Scenario: corrupted JSON is detected
// ---------------------------------------------------------------------------

#[test]
fn corrupted_json_fails_to_parse() {
    let result = serde_json::from_str::<ProvenanceGraphSnapshot>("not valid json");
    assert!(result.is_err());
}

#[test]
fn truncated_json_fails_to_parse() {
    let graph = minimal_graph();
    let json = serde_json::to_string(&graph).expect("serialize");
    // Truncate to half length
    let truncated = &json[..json.len() / 2];
    let result = serde_json::from_str::<ProvenanceGraphSnapshot>(truncated);
    assert!(result.is_err());
}

#[test]
fn empty_json_object_fails_to_parse() {
    let result = serde_json::from_str::<ProvenanceGraphSnapshot>("{}");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Scenario: missing required fields detected
// ---------------------------------------------------------------------------

#[test]
fn missing_schema_version_fails() {
    let json = r#"{
        "generated_at": "2026-03-16T00:00:00Z",
        "privacy": {"version": "1.0.0", "local_persistence_days": 30, "field_policies": []},
        "summary": {"node_count": 0, "edge_count": 0, "evidence_count": 0, "redacted_evidence_count": 0, "missing_or_conflicted_evidence_count": 0},
        "nodes": [],
        "edges": [],
        "evidence": []
    }"#;
    let result = serde_json::from_str::<ProvenanceGraphSnapshot>(json);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Scenario: redacted evidence is preserved through persistence
// ---------------------------------------------------------------------------

#[test]
fn redacted_evidence_survives_round_trip() {
    let graph = graph_with_redacted_evidence();

    assert_eq!(graph.summary.redacted_evidence_count, 1);
    assert_eq!(graph.summary.missing_or_conflicted_evidence_count, 0);
    assert_eq!(graph.warnings.len(), 1);

    let json = serde_json::to_string_pretty(&graph).expect("serialize");
    let parsed: ProvenanceGraphSnapshot = serde_json::from_str(&json).expect("deserialize");

    // Redacted evidence must survive
    assert_eq!(
        parsed.summary.redacted_evidence_count,
        graph.summary.redacted_evidence_count
    );
    assert_eq!(parsed.evidence[0].redaction, ProvenanceRedactionState::Full);
    assert_eq!(
        parsed.evidence[0].status,
        ProvenanceObservationStatus::Redacted
    );
    assert_eq!(parsed.evidence[0].confidence, ProvenanceConfidence::Low);

    // Warnings must survive
    assert_eq!(parsed.warnings.len(), 1);
    assert_eq!(parsed.warnings[0].code, "workspace_withheld_by_policy");
}

// ---------------------------------------------------------------------------
// Scenario: empty graph (no processes found) is valid
// ---------------------------------------------------------------------------

#[test]
fn empty_graph_round_trips() {
    let graph = ProvenanceGraphSnapshot::new(
        "2026-03-16T00:00:00Z".to_string(),
        Some("empty-session".to_string()),
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    assert_eq!(graph.summary.node_count, 0);
    assert_eq!(graph.summary.edge_count, 0);

    let json = serde_json::to_string(&graph).expect("serialize");
    let parsed: ProvenanceGraphSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, graph);
}

// ---------------------------------------------------------------------------
// Scenario: schema version mismatch is detectable
// ---------------------------------------------------------------------------

#[test]
fn schema_version_mismatch_is_detectable_after_parse() {
    let mut graph = minimal_graph();
    graph.schema_version = "2.0.0".to_string(); // Future version

    let json = serde_json::to_string(&graph).expect("serialize");
    let parsed: ProvenanceGraphSnapshot = serde_json::from_str(&json).expect("deserialize");

    // Parsing succeeds (forward-compatible) but version differs
    assert_ne!(parsed.schema_version, PROVENANCE_SCHEMA_VERSION);
    // Consumer should check version before trusting the data
}

// ---------------------------------------------------------------------------
// Scenario: extra unknown fields are tolerated (forward compatibility)
// ---------------------------------------------------------------------------

#[test]
fn extra_fields_are_tolerated() {
    let graph = minimal_graph();
    let mut json_value = serde_json::to_value(&graph).expect("to value");

    // Add an unknown field
    json_value["future_field"] = serde_json::json!("some new data");
    json_value["another_future"] = serde_json::json!(42);

    let json = serde_json::to_string(&json_value).expect("serialize");

    // Should parse without error (serde default denies unknown fields,
    // but ProvenanceGraphSnapshot doesn't use #[serde(deny_unknown_fields)])
    let parsed: ProvenanceGraphSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.schema_version, PROVENANCE_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Scenario: summary counts match actual data
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_match_actual_data() {
    let graph = graph_with_redacted_evidence();

    assert_eq!(graph.summary.node_count, graph.nodes.len());
    assert_eq!(graph.summary.edge_count, graph.edges.len());
    assert_eq!(graph.summary.evidence_count, graph.evidence.len());

    let actual_redacted = graph
        .evidence
        .iter()
        .filter(|e| e.redaction != ProvenanceRedactionState::None)
        .count();
    assert_eq!(graph.summary.redacted_evidence_count, actual_redacted);
}

// ---------------------------------------------------------------------------
// Scenario: bundle provenance round-trip
// ---------------------------------------------------------------------------

#[test]
fn provenance_graph_can_be_serialized_for_bundle_inclusion() {
    let graph = graph_with_redacted_evidence();

    // Simulate what bundle writer does: serialize to JSON bytes
    let json_bytes = serde_json::to_vec_pretty(&graph).expect("serialize to bytes");

    // Simulate integrity check
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&json_bytes);
    let integrity = hex::encode(hasher.finalize());
    assert_eq!(integrity.len(), 64);

    // Simulate what bundle reader does: deserialize from bytes
    let restored: ProvenanceGraphSnapshot =
        serde_json::from_slice(&json_bytes).expect("deserialize from bytes");
    assert_eq!(restored, graph);

    // Verify integrity matches
    let restored_bytes = serde_json::to_vec_pretty(&restored).expect("re-serialize");
    let mut hasher2 = Sha256::new();
    hasher2.update(&restored_bytes);
    let integrity2 = hex::encode(hasher2.finalize());
    assert_eq!(integrity, integrity2, "integrity hash should be stable");
}

// ---------------------------------------------------------------------------
// Scenario: node/edge/evidence ID stability across serialization
// ---------------------------------------------------------------------------

#[test]
fn provenance_ids_are_stable_across_serialization() {
    let id1 = ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:42:boot:1:42");
    let json = serde_json::to_string(&id1).expect("serialize");
    let id2: ProvenanceNodeId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id1, id2);

    let eid1 = ProvenanceEvidenceId::new(ProvenanceEvidenceKind::Procfs, "procfs:42");
    let json = serde_json::to_string(&eid1).expect("serialize");
    let eid2: ProvenanceEvidenceId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eid1, eid2);
}
