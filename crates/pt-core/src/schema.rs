//! JSON Schema generation for agent output types.
//!
//! This module provides functions to generate JSON Schema definitions
//! for all agent-facing output types. These schemas enable:
//!
//! - Agent validation of pt output
//! - Code generation for consuming pt data
//! - Documentation of the output format
//!
//! # Usage
//!
//! ```bash
//! # List available schema types
//! pt schema --list
//!
//! # Generate schema for a specific type
//! pt schema Plan
//! pt schema DecisionOutcome
//!
//! # Generate all schemas
//! pt schema --all
//! ```

use schemars::schema_for;
use serde_json::Value;
use std::collections::BTreeMap;

// Re-export types that have schemas
pub use crate::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
pub use crate::decision::causal_interventions::{
    InterventionOutcome, ProcessClass, RecoveryExpectation, RecoveryTable,
};
pub use crate::decision::cvar::{CvarLoss, RiskSensitiveOutcome};
pub use crate::decision::dro::{DroLoss, DroOutcome};
pub use crate::decision::expected_loss::{
    Action, ActionFeasibility, DecisionOutcome, DecisionRationale, DisabledAction, ExpectedLoss,
    SprtBoundary,
};
pub use crate::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts,
    DStateDiagnostics, GatesSummary, Plan, PlanAction, PreCheck,
};
pub use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};

/// Available schema types with their descriptions.
pub fn available_schemas() -> Vec<(&'static str, &'static str)> {
    vec![
        // Core identity types
        ("ProcessId", "Process ID wrapper"),
        ("StartId", "Unique process incarnation identifier"),
        ("SessionId", "Triage session identifier"),
        ("IdentityQuality", "Quality/provenance of process identity"),
        ("ProcessIdentity", "Complete process identity tuple"),
        // Scan types
        ("ProcessState", "Unix process state (R, S, D, Z, T, I, X)"),
        ("ProcessRecord", "Single process record from scan"),
        ("ScanMetadata", "Metadata about a scan operation"),
        ("ScanResult", "Complete scan result with processes and metadata"),
        // Decision types
        ("Action", "Available process actions (keep, pause, kill, etc.)"),
        (
            "DisabledAction",
            "Action that was disabled with reason",
        ),
        (
            "ActionFeasibility",
            "Feasibility status for an action",
        ),
        ("ExpectedLoss", "Expected loss for a single action"),
        ("SprtBoundary", "SPRT decision boundary parameters"),
        (
            "DecisionRationale",
            "Rationale for decision including priors and posteriors",
        ),
        (
            "DecisionOutcome",
            "Complete decision outcome with action and rationale",
        ),
        // Risk-sensitive types
        ("CvarLoss", "CVaR computation result for risk-sensitive control"),
        (
            "RiskSensitiveOutcome",
            "Risk-sensitive decision outcome",
        ),
        ("DroLoss", "DRO computation result"),
        ("DroOutcome", "Distributionally robust optimization outcome"),
        // Causal intervention types
        ("ProcessClass", "Process classification (useful, abandoned, zombie)"),
        (
            "RecoveryExpectation",
            "Expected recovery probability for an action",
        ),
        ("RecoveryTable", "Recovery expectations for all actions"),
        (
            "InterventionOutcome",
            "Outcome of a causal intervention",
        ),
        // Plan types
        ("Plan", "Complete action plan with staged actions"),
        ("PlanAction", "Single action in a plan"),
        ("GatesSummary", "Safety gate summary"),
        ("ActionTimeouts", "Timeout configuration for actions"),
        ("PreCheck", "Pre-action check specification"),
        ("ActionRouting", "Routing for unkillable processes"),
        ("ActionConfidence", "Confidence level for an action"),
        ("ActionRationale", "Rationale explaining why an action was chosen"),
        ("ActionHook", "Pre/post action hooks"),
        (
            "DStateDiagnostics",
            "Diagnostics for D-state (disk sleep) processes",
        ),
    ]
}

/// Generate JSON Schema for a type by name.
///
/// Returns the schema as a serde_json::Value, or None if the type is unknown.
pub fn generate_schema(type_name: &str) -> Option<Value> {
    let schema = match type_name {
        // Core identity types
        "ProcessId" => schema_for!(ProcessId),
        "StartId" => schema_for!(StartId),
        "SessionId" => schema_for!(SessionId),
        "IdentityQuality" => schema_for!(IdentityQuality),
        "ProcessIdentity" => schema_for!(ProcessIdentity),
        // Scan types
        "ProcessState" => schema_for!(ProcessState),
        "ProcessRecord" => schema_for!(ProcessRecord),
        "ScanMetadata" => schema_for!(ScanMetadata),
        "ScanResult" => schema_for!(ScanResult),
        // Decision types
        "Action" => schema_for!(Action),
        "DisabledAction" => schema_for!(DisabledAction),
        "ActionFeasibility" => schema_for!(ActionFeasibility),
        "ExpectedLoss" => schema_for!(ExpectedLoss),
        "SprtBoundary" => schema_for!(SprtBoundary),
        "DecisionRationale" => schema_for!(DecisionRationale),
        "DecisionOutcome" => schema_for!(DecisionOutcome),
        // Risk-sensitive types
        "CvarLoss" => schema_for!(CvarLoss),
        "RiskSensitiveOutcome" => schema_for!(RiskSensitiveOutcome),
        "DroLoss" => schema_for!(DroLoss),
        "DroOutcome" => schema_for!(DroOutcome),
        // Causal intervention types
        "ProcessClass" => schema_for!(ProcessClass),
        "RecoveryExpectation" => schema_for!(RecoveryExpectation),
        "RecoveryTable" => schema_for!(RecoveryTable),
        "InterventionOutcome" => schema_for!(InterventionOutcome),
        // Plan types
        "Plan" => schema_for!(Plan),
        "PlanAction" => schema_for!(PlanAction),
        "GatesSummary" => schema_for!(GatesSummary),
        "ActionTimeouts" => schema_for!(ActionTimeouts),
        "PreCheck" => schema_for!(PreCheck),
        "ActionRouting" => schema_for!(ActionRouting),
        "ActionConfidence" => schema_for!(ActionConfidence),
        "ActionRationale" => schema_for!(ActionRationale),
        "ActionHook" => schema_for!(ActionHook),
        "DStateDiagnostics" => schema_for!(DStateDiagnostics),
        _ => return None,
    };

    Some(serde_json::to_value(schema).expect("schema serialization should not fail"))
}

/// Generate all schemas as a map from type name to schema.
pub fn generate_all_schemas() -> BTreeMap<String, Value> {
    let mut schemas = BTreeMap::new();
    for (name, _desc) in available_schemas() {
        if let Some(schema) = generate_schema(name) {
            schemas.insert(name.to_string(), schema);
        }
    }
    schemas
}

/// Schema output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFormat {
    /// Pretty-printed JSON (default)
    Json,
    /// Compact single-line JSON
    JsonCompact,
}

/// Format a schema value for output.
pub fn format_schema(schema: &Value, format: SchemaFormat) -> String {
    match format {
        SchemaFormat::Json => serde_json::to_string_pretty(schema).unwrap(),
        SchemaFormat::JsonCompact => serde_json::to_string(schema).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_schemas_generate() {
        // Every listed schema should generate successfully
        for (name, _desc) in available_schemas() {
            let schema = generate_schema(name);
            assert!(
                schema.is_some(),
                "Schema for '{}' should generate",
                name
            );
        }
    }

    #[test]
    fn test_unknown_schema_returns_none() {
        assert!(generate_schema("UnknownType").is_none());
        assert!(generate_schema("").is_none());
    }

    #[test]
    fn test_schema_has_required_fields() {
        // Check that generated schemas have the expected JSON Schema structure
        let schema = generate_schema("ProcessRecord").unwrap();

        // Should be an object with "$schema" or "type" field
        assert!(
            schema.get("$schema").is_some() || schema.get("type").is_some(),
            "Schema should have $schema or type field"
        );
    }

    #[test]
    fn test_generate_all_schemas() {
        let all = generate_all_schemas();
        assert!(!all.is_empty());

        // Should have at least the core types
        assert!(all.contains_key("Plan"));
        assert!(all.contains_key("DecisionOutcome"));
        assert!(all.contains_key("ProcessRecord"));
    }

    #[test]
    fn test_format_schema() {
        let schema = generate_schema("Action").unwrap();

        let pretty = format_schema(&schema, SchemaFormat::Json);
        let compact = format_schema(&schema, SchemaFormat::JsonCompact);

        // Pretty should have newlines, compact should not
        assert!(pretty.contains('\n'));
        assert!(!compact.contains('\n'));
    }
}
