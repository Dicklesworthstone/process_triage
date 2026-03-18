//! Provenance control surfaces, rollout defaults, and effective posture resolution.

use pt_common::ProvenanceConsentRequirement;
use serde::{Deserialize, Serialize};

/// Schema version for the provenance control contract.
pub const PROVENANCE_CONTROL_MODEL_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRolloutPosture {
    Disabled,
    Conservative,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceExecutionContext {
    Scan,
    DeepScan,
    Daemon,
    Fleet,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceCollectionDepth {
    None,
    Minimal,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenancePersistenceMode {
    None,
    SessionOnly,
    SessionAndBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceExportMode {
    None,
    Redacted,
    Consented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRedactionLevel {
    Strict,
    Balanced,
    Detailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceExplanationVerbosity {
    Off,
    Summary,
    Standard,
    Verbose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceControlSurfaceKind {
    ConfigKey,
    EnvironmentVariable,
    CliFlag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceControlSurface {
    pub kind: ProvenanceControlSurfaceKind,
    pub name: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceControls {
    pub version: String,
    pub posture: ProvenanceRolloutPosture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_depth: Option<ProvenanceCollectionDepth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistence: Option<ProvenancePersistenceMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export: Option<ProvenanceExportMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_level: Option<ProvenanceRedactionLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation_verbosity: Option<ProvenanceExplanationVerbosity>,
    #[serde(default)]
    pub allow_consent_prompt: bool,
    #[serde(default = "default_allow_downgrades")]
    pub allow_degraded_fallbacks: bool,
}

fn default_allow_downgrades() -> bool {
    true
}

impl Default for ProvenanceControls {
    fn default() -> Self {
        Self {
            version: PROVENANCE_CONTROL_MODEL_VERSION.to_string(),
            posture: ProvenanceRolloutPosture::Conservative,
            collection_depth: None,
            persistence: None,
            export: None,
            redaction_level: None,
            explanation_verbosity: None,
            allow_consent_prompt: false,
            allow_degraded_fallbacks: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveProvenanceControls {
    pub version: String,
    pub context: ProvenanceExecutionContext,
    pub posture: ProvenanceRolloutPosture,
    pub collection_depth: ProvenanceCollectionDepth,
    pub persistence: ProvenancePersistenceMode,
    pub export: ProvenanceExportMode,
    pub redaction_level: ProvenanceRedactionLevel,
    pub explanation_verbosity: ProvenanceExplanationVerbosity,
    pub consent_requirement: ProvenanceConsentRequirement,
    pub debug_event: String,
    pub forced_downgrades: Vec<String>,
}

impl ProvenanceControls {
    pub fn resolve_for_context(
        &self,
        context: ProvenanceExecutionContext,
    ) -> EffectiveProvenanceControls {
        let mut effective = EffectiveProvenanceControls::baseline(self.posture, context);

        if let Some(depth) = self.collection_depth {
            effective.collection_depth = depth;
        }
        if let Some(persistence) = self.persistence {
            effective.persistence = persistence;
        }
        if let Some(export) = self.export {
            effective.export = export;
        }
        if let Some(redaction) = self.redaction_level {
            effective.redaction_level = redaction;
        }
        if let Some(verbosity) = self.explanation_verbosity {
            effective.explanation_verbosity = verbosity;
        }

        effective.enforce_coherence(self.allow_consent_prompt);
        effective.apply_context_caps(context, self.allow_degraded_fallbacks);
        effective.version = self.version.clone();
        effective
    }

    pub fn documented_surfaces() -> Vec<ProvenanceControlSurface> {
        vec![
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.posture",
                "Top-level rollout posture: disabled, conservative, standard, or deep.",
            ),
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.collection_depth",
                "Override collection depth for runtime provenance gathering.",
            ),
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.persistence",
                "Choose whether provenance stays ephemeral, session-only, or bundle-eligible.",
            ),
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.export",
                "Control whether exports omit provenance, include redacted provenance, or require consent.",
            ),
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.redaction_level",
                "Select strict, balanced, or detailed disclosure behavior.",
            ),
            surface(
                ProvenanceControlSurfaceKind::ConfigKey,
                "provenance.explanation_verbosity",
                "Choose off, summary, standard, or verbose explanation output.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_POSTURE",
                "Environment override for rollout posture across all commands.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_DEPTH",
                "Environment override for collection depth.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_PERSIST",
                "Environment override for persistence posture.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_EXPORT",
                "Environment override for export posture.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_REDACTION",
                "Environment override for redaction level.",
            ),
            surface(
                ProvenanceControlSurfaceKind::EnvironmentVariable,
                "PT_PROVENANCE_EXPLAIN",
                "Environment override for explanation verbosity.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-posture",
                "Per-invocation rollout posture override.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-depth",
                "Per-invocation provenance collection-depth override.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-persist",
                "Per-invocation persistence override.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-export",
                "Per-invocation export override.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-redaction",
                "Per-invocation redaction override.",
            ),
            surface(
                ProvenanceControlSurfaceKind::CliFlag,
                "--provenance-explain",
                "Per-invocation explanation-verbosity override.",
            ),
        ]
    }
}

fn surface(
    kind: ProvenanceControlSurfaceKind,
    name: &str,
    purpose: &str,
) -> ProvenanceControlSurface {
    ProvenanceControlSurface {
        kind,
        name: name.to_string(),
        purpose: purpose.to_string(),
    }
}

impl EffectiveProvenanceControls {
    fn baseline(
        posture: ProvenanceRolloutPosture,
        context: ProvenanceExecutionContext,
    ) -> EffectiveProvenanceControls {
        let (collection_depth, persistence, export, redaction_level, explanation_verbosity) =
            match posture {
                ProvenanceRolloutPosture::Disabled => (
                    ProvenanceCollectionDepth::None,
                    ProvenancePersistenceMode::None,
                    ProvenanceExportMode::None,
                    ProvenanceRedactionLevel::Strict,
                    ProvenanceExplanationVerbosity::Off,
                ),
                ProvenanceRolloutPosture::Conservative => (
                    ProvenanceCollectionDepth::Minimal,
                    ProvenancePersistenceMode::SessionOnly,
                    ProvenanceExportMode::None,
                    ProvenanceRedactionLevel::Strict,
                    ProvenanceExplanationVerbosity::Summary,
                ),
                ProvenanceRolloutPosture::Standard => (
                    ProvenanceCollectionDepth::Standard,
                    ProvenancePersistenceMode::SessionOnly,
                    ProvenanceExportMode::Redacted,
                    ProvenanceRedactionLevel::Balanced,
                    ProvenanceExplanationVerbosity::Standard,
                ),
                ProvenanceRolloutPosture::Deep => (
                    ProvenanceCollectionDepth::Deep,
                    ProvenancePersistenceMode::SessionAndBundle,
                    ProvenanceExportMode::Consented,
                    ProvenanceRedactionLevel::Detailed,
                    ProvenanceExplanationVerbosity::Verbose,
                ),
            };

        EffectiveProvenanceControls {
            version: PROVENANCE_CONTROL_MODEL_VERSION.to_string(),
            context,
            posture,
            collection_depth,
            persistence,
            export,
            redaction_level,
            explanation_verbosity,
            consent_requirement: ProvenanceConsentRequirement::None,
            debug_event: "provenance_control_posture_resolved".to_string(),
            forced_downgrades: Vec::new(),
        }
    }

    fn enforce_coherence(&mut self, allow_consent_prompt: bool) {
        if self.collection_depth == ProvenanceCollectionDepth::None {
            self.persistence = ProvenancePersistenceMode::None;
            self.export = ProvenanceExportMode::None;
            self.explanation_verbosity = ProvenanceExplanationVerbosity::Off;
        }

        if self.persistence == ProvenancePersistenceMode::None
            && self.export == ProvenanceExportMode::Consented
        {
            self.export = ProvenanceExportMode::Redacted;
            self.forced_downgrades
                .push("consented export downgraded because persistence is disabled".to_string());
        }

        self.consent_requirement = if self.export == ProvenanceExportMode::Consented {
            if allow_consent_prompt {
                ProvenanceConsentRequirement::ExplicitOperator
            } else {
                self.export = ProvenanceExportMode::Redacted;
                self.forced_downgrades.push(
                    "consented export downgraded because consent prompts are disabled".to_string(),
                );
                ProvenanceConsentRequirement::None
            }
        } else {
            ProvenanceConsentRequirement::None
        };
    }

    fn apply_context_caps(
        &mut self,
        context: ProvenanceExecutionContext,
        allow_degraded_fallbacks: bool,
    ) {
        let cap = |label: &str,
                   current_depth: &mut ProvenanceCollectionDepth,
                   max_depth: ProvenanceCollectionDepth,
                   current_persistence: &mut ProvenancePersistenceMode,
                   max_persistence: ProvenancePersistenceMode,
                   current_export: &mut ProvenanceExportMode,
                   max_export: ProvenanceExportMode,
                   current_redaction: &mut ProvenanceRedactionLevel,
                   max_redaction: ProvenanceRedactionLevel,
                   current_verbosity: &mut ProvenanceExplanationVerbosity,
                   max_verbosity: ProvenanceExplanationVerbosity,
                   downgrades: &mut Vec<String>| {
            if *current_depth > max_depth {
                *current_depth = max_depth;
                downgrades.push(format!("{label}: collection depth downgraded for context"));
            }
            if *current_persistence > max_persistence {
                *current_persistence = max_persistence;
                downgrades.push(format!("{label}: persistence downgraded for context"));
            }
            if *current_export > max_export {
                *current_export = max_export;
                downgrades.push(format!("{label}: export downgraded for context"));
            }
            if *current_redaction > max_redaction {
                *current_redaction = max_redaction;
                downgrades.push(format!("{label}: redaction detail downgraded for context"));
            }
            if *current_verbosity > max_verbosity {
                *current_verbosity = max_verbosity;
                downgrades.push(format!(
                    "{label}: explanation verbosity downgraded for context"
                ));
            }
        };

        match context {
            ProvenanceExecutionContext::Scan => cap(
                "scan",
                &mut self.collection_depth,
                ProvenanceCollectionDepth::Standard,
                &mut self.persistence,
                ProvenancePersistenceMode::SessionOnly,
                &mut self.export,
                ProvenanceExportMode::Redacted,
                &mut self.redaction_level,
                ProvenanceRedactionLevel::Detailed,
                &mut self.explanation_verbosity,
                ProvenanceExplanationVerbosity::Standard,
                &mut self.forced_downgrades,
            ),
            ProvenanceExecutionContext::DeepScan => cap(
                "deep_scan",
                &mut self.collection_depth,
                ProvenanceCollectionDepth::Deep,
                &mut self.persistence,
                ProvenancePersistenceMode::SessionAndBundle,
                &mut self.export,
                ProvenanceExportMode::Consented,
                &mut self.redaction_level,
                ProvenanceRedactionLevel::Detailed,
                &mut self.explanation_verbosity,
                ProvenanceExplanationVerbosity::Verbose,
                &mut self.forced_downgrades,
            ),
            ProvenanceExecutionContext::Daemon => cap(
                "daemon",
                &mut self.collection_depth,
                ProvenanceCollectionDepth::Minimal,
                &mut self.persistence,
                ProvenancePersistenceMode::SessionOnly,
                &mut self.export,
                ProvenanceExportMode::None,
                &mut self.redaction_level,
                ProvenanceRedactionLevel::Strict,
                &mut self.explanation_verbosity,
                ProvenanceExplanationVerbosity::Summary,
                &mut self.forced_downgrades,
            ),
            ProvenanceExecutionContext::Fleet => cap(
                "fleet",
                &mut self.collection_depth,
                ProvenanceCollectionDepth::Standard,
                &mut self.persistence,
                ProvenancePersistenceMode::SessionOnly,
                &mut self.export,
                ProvenanceExportMode::Redacted,
                &mut self.redaction_level,
                ProvenanceRedactionLevel::Balanced,
                &mut self.explanation_verbosity,
                ProvenanceExplanationVerbosity::Standard,
                &mut self.forced_downgrades,
            ),
            ProvenanceExecutionContext::Report => cap(
                "report",
                &mut self.collection_depth,
                ProvenanceCollectionDepth::None,
                &mut self.persistence,
                ProvenancePersistenceMode::SessionAndBundle,
                &mut self.export,
                ProvenanceExportMode::Consented,
                &mut self.redaction_level,
                ProvenanceRedactionLevel::Detailed,
                &mut self.explanation_verbosity,
                ProvenanceExplanationVerbosity::Verbose,
                &mut self.forced_downgrades,
            ),
        }

        if !allow_degraded_fallbacks && !self.forced_downgrades.is_empty() {
            self.collection_depth = ProvenanceCollectionDepth::None;
            self.persistence = ProvenancePersistenceMode::None;
            self.export = ProvenanceExportMode::None;
            self.redaction_level = ProvenanceRedactionLevel::Strict;
            self.explanation_verbosity = ProvenanceExplanationVerbosity::Off;
            self.consent_requirement = ProvenanceConsentRequirement::None;
            self.forced_downgrades
                .push("posture disabled because degraded fallbacks are forbidden".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Performance budgets and degradation strategy (bd-ppcl.13)
// ---------------------------------------------------------------------------

/// Per-context time budgets for provenance subsystem stages.
///
/// Each execution context has explicit limits. When a stage exceeds its
/// budget, the subsystem degrades gracefully rather than blocking the
/// scan pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenancePerformanceBudget {
    /// Maximum milliseconds for lineage collection per candidate.
    pub lineage_collection_ms: u64,
    /// Maximum milliseconds for resource evidence collection per candidate.
    pub resource_collection_ms: u64,
    /// Maximum milliseconds for graph construction (total).
    pub graph_construction_ms: u64,
    /// Maximum milliseconds for blast-radius estimation per candidate.
    pub blast_radius_ms: u64,
    /// Maximum milliseconds for narrative rendering per candidate.
    pub narrative_render_ms: u64,
    /// Maximum milliseconds for the entire provenance pipeline (total).
    pub total_pipeline_ms: u64,
}

impl ProvenancePerformanceBudget {
    /// Budget for quick scan: tight limits, shed expensive probes first.
    pub fn quick_scan() -> Self {
        Self {
            lineage_collection_ms: 5,
            resource_collection_ms: 10,
            graph_construction_ms: 50,
            blast_radius_ms: 5,
            narrative_render_ms: 2,
            total_pipeline_ms: 200,
        }
    }

    /// Budget for deep scan: generous limits, collect everything.
    pub fn deep_scan() -> Self {
        Self {
            lineage_collection_ms: 50,
            resource_collection_ms: 100,
            graph_construction_ms: 500,
            blast_radius_ms: 50,
            narrative_render_ms: 10,
            total_pipeline_ms: 2000,
        }
    }

    /// Budget for daemon mode: very tight, minimize overhead.
    pub fn daemon() -> Self {
        Self {
            lineage_collection_ms: 2,
            resource_collection_ms: 5,
            graph_construction_ms: 20,
            blast_radius_ms: 2,
            narrative_render_ms: 1,
            total_pipeline_ms: 100,
        }
    }

    /// Budget for fleet mode: moderate limits per host.
    pub fn fleet() -> Self {
        Self {
            lineage_collection_ms: 10,
            resource_collection_ms: 20,
            graph_construction_ms: 100,
            blast_radius_ms: 10,
            narrative_render_ms: 5,
            total_pipeline_ms: 500,
        }
    }

    /// Get the appropriate budget for an execution context.
    pub fn for_context(context: ProvenanceExecutionContext) -> Self {
        match context {
            ProvenanceExecutionContext::Scan => Self::quick_scan(),
            ProvenanceExecutionContext::DeepScan => Self::deep_scan(),
            ProvenanceExecutionContext::Daemon => Self::daemon(),
            ProvenanceExecutionContext::Fleet => Self::fleet(),
            ProvenanceExecutionContext::Report => Self::deep_scan(), // Reports use pre-collected data
        }
    }
}

/// What to shed when the pipeline exceeds its time budget.
///
/// Ordered from least-impactful to most-impactful. The pipeline sheds
/// stages in order until it fits within the remaining budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceDegradationLevel {
    /// Full provenance: all stages run.
    Full,
    /// Skip narrative rendering (output raw contract only).
    SkipNarrative,
    /// Skip blast-radius estimation (report risk as unknown).
    SkipBlastRadius,
    /// Skip resource collection (lineage only).
    SkipResources,
    /// Skip all provenance (return disabled output).
    Disabled,
}

impl ProvenanceDegradationLevel {
    /// Whether this level still produces a blast-radius estimate.
    pub fn has_blast_radius(self) -> bool {
        self < Self::SkipBlastRadius
    }

    /// Whether this level still produces narrative rendering.
    pub fn has_narrative(self) -> bool {
        self < Self::SkipNarrative
    }

    /// Whether provenance is active at all.
    pub fn is_active(self) -> bool {
        self < Self::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_defaults_keep_scan_safe() {
        let controls = ProvenanceControls::default();
        let effective = controls.resolve_for_context(ProvenanceExecutionContext::Scan);

        assert_eq!(
            effective.collection_depth,
            ProvenanceCollectionDepth::Minimal
        );
        assert_eq!(
            effective.persistence,
            ProvenancePersistenceMode::SessionOnly
        );
        assert_eq!(effective.export, ProvenanceExportMode::None);
        assert_eq!(effective.redaction_level, ProvenanceRedactionLevel::Strict);
        assert_eq!(
            effective.explanation_verbosity,
            ProvenanceExplanationVerbosity::Summary
        );
    }

    #[test]
    fn daemon_forces_non_exporting_strict_posture() {
        let controls = ProvenanceControls {
            posture: ProvenanceRolloutPosture::Deep,
            allow_consent_prompt: true,
            ..ProvenanceControls::default()
        };
        let effective = controls.resolve_for_context(ProvenanceExecutionContext::Daemon);

        assert_eq!(
            effective.collection_depth,
            ProvenanceCollectionDepth::Minimal
        );
        assert_eq!(effective.export, ProvenanceExportMode::None);
        assert_eq!(effective.redaction_level, ProvenanceRedactionLevel::Strict);
        assert!(effective
            .forced_downgrades
            .iter()
            .any(|item| item.contains("daemon")));
    }

    #[test]
    fn consented_export_requires_prompt_support() {
        let controls = ProvenanceControls {
            posture: ProvenanceRolloutPosture::Deep,
            allow_consent_prompt: false,
            ..ProvenanceControls::default()
        };
        let effective = controls.resolve_for_context(ProvenanceExecutionContext::DeepScan);

        assert_eq!(effective.export, ProvenanceExportMode::Redacted);
        assert_eq!(
            effective.consent_requirement,
            ProvenanceConsentRequirement::None
        );
        assert!(effective
            .forced_downgrades
            .iter()
            .any(|item| item.contains("consent prompts")));
    }

    #[test]
    fn report_context_only_disables_new_collection() {
        let controls = ProvenanceControls {
            posture: ProvenanceRolloutPosture::Standard,
            ..ProvenanceControls::default()
        };
        let effective = controls.resolve_for_context(ProvenanceExecutionContext::Report);

        assert_eq!(effective.collection_depth, ProvenanceCollectionDepth::None);
        assert_eq!(effective.export, ProvenanceExportMode::Redacted);
        assert_eq!(
            effective.explanation_verbosity,
            ProvenanceExplanationVerbosity::Standard
        );
    }

    #[test]
    fn documented_surfaces_expose_config_env_and_cli_layers() {
        let surfaces = ProvenanceControls::documented_surfaces();
        assert!(surfaces
            .iter()
            .any(|surface| surface.name == "provenance.posture"));
        assert!(surfaces
            .iter()
            .any(|surface| surface.name == "PT_PROVENANCE_POSTURE"));
        assert!(surfaces
            .iter()
            .any(|surface| surface.name == "--provenance-posture"));
    }

    // ── Performance budget tests (bd-ppcl.13) ────────────────────────

    #[test]
    fn quick_scan_budget_is_tightest() {
        let quick = ProvenancePerformanceBudget::quick_scan();
        let deep = ProvenancePerformanceBudget::deep_scan();
        assert!(quick.total_pipeline_ms < deep.total_pipeline_ms);
        assert!(quick.lineage_collection_ms < deep.lineage_collection_ms);
        assert!(quick.resource_collection_ms < deep.resource_collection_ms);
    }

    #[test]
    fn daemon_budget_is_tighter_than_quick_scan() {
        let daemon = ProvenancePerformanceBudget::daemon();
        let quick = ProvenancePerformanceBudget::quick_scan();
        assert!(daemon.total_pipeline_ms < quick.total_pipeline_ms);
    }

    #[test]
    fn budget_for_context_returns_correct_presets() {
        let scan = ProvenancePerformanceBudget::for_context(ProvenanceExecutionContext::Scan);
        let deep = ProvenancePerformanceBudget::for_context(ProvenanceExecutionContext::DeepScan);
        assert_eq!(scan.total_pipeline_ms, 200);
        assert_eq!(deep.total_pipeline_ms, 2000);
    }

    #[test]
    fn degradation_level_ordering() {
        assert!(ProvenanceDegradationLevel::Full < ProvenanceDegradationLevel::SkipNarrative);
        assert!(ProvenanceDegradationLevel::SkipNarrative < ProvenanceDegradationLevel::SkipBlastRadius);
        assert!(ProvenanceDegradationLevel::SkipBlastRadius < ProvenanceDegradationLevel::SkipResources);
        assert!(ProvenanceDegradationLevel::SkipResources < ProvenanceDegradationLevel::Disabled);
    }

    #[test]
    fn degradation_level_capabilities() {
        assert!(ProvenanceDegradationLevel::Full.has_blast_radius());
        assert!(ProvenanceDegradationLevel::Full.has_narrative());
        assert!(ProvenanceDegradationLevel::Full.is_active());

        assert!(ProvenanceDegradationLevel::SkipNarrative.has_blast_radius());
        assert!(!ProvenanceDegradationLevel::SkipNarrative.has_narrative());

        assert!(!ProvenanceDegradationLevel::SkipBlastRadius.has_blast_radius());

        assert!(!ProvenanceDegradationLevel::Disabled.is_active());
    }

    #[test]
    fn budget_serialization_roundtrip() {
        let budget = ProvenancePerformanceBudget::quick_scan();
        let json = serde_json::to_string(&budget).expect("serialize budget");
        let deser: ProvenancePerformanceBudget =
            serde_json::from_str(&json).expect("deserialize budget");
        assert_eq!(deser.total_pipeline_ms, budget.total_pipeline_ms);
    }
}
