//! One scoring path for every surface that rates a process.
//!
//! `agent plan`, the TUI (`pt run`) and its deep-scan probe advice, `agent explain`,
//! `agent snapshot`, `agent watch` and the MCP tools all score processes through
//! [`Scorer`], so a process gets the same posterior and classification whichever
//! command looks at it (GH #13: only `agent plan` applied signatures and provenance).
//!
//! A score combines:
//! 1. the class prior: a human verdict learned for the command pattern
//!    ([`DecisionStore`]), else a matching signature's priors (or its fast path), else
//!    the configured priors;
//! 2. the snapshot evidence (CPU, runtime, orphan, TTY, state, plus deep-scan signals
//!    when the caller collected them);
//! 3. desktop-application ownership (Linux): a process in an XDG application unit of
//!    the graphical session (`app-*.scope` / `app-*.service` under `user@UID.service`)
//!    without a terminal is an app someone has open (GH #12);
//! 4. on Linux, provenance evidence (lineage ownership, listeners, blast radius) when
//!    the caller collected it with [`Scorer::collect_provenance`].

use std::path::Path;

use crate::collect::ProcessRecord;
use crate::config::{Policy, Priors, ResolvedConfig};
use crate::decision::decision_store::{DecisionStore, LearnedPrior};
use crate::inference::{
    apply_evidence_terms, compute_posterior_with_overrides, try_signature_fast_path, ClassScores,
    Evidence, EvidenceLedger, EvidenceTerm, FastPathConfig, FastPathSkipReason, PosteriorResult,
    PriorContext,
};
use crate::supervision::signature::{
    MatchLevel, ProcessMatchContext, SignatureDatabase, SignatureMatch,
};

#[cfg(target_os = "linux")]
pub use provenance::{
    build_provenance_bundle, derive_provenance_adjustment, ProvenanceInferenceBundle,
    ProvenanceScoreAdjustment,
};

/// Evidence-term name for desktop-application ownership.
pub const DESKTOP_APP_FEATURE: &str = "desktop_app_session";

/// Built-in signatures plus the user signatures in `config_dir` (see
/// [`crate::signature_cli::user_signatures_path`]), and a warning per user signature
/// that could not be added.
pub fn load_signature_database(config_dir: &Path) -> (SignatureDatabase, Vec<String>) {
    let mut db = SignatureDatabase::with_defaults();
    let mut warnings = Vec::new();
    if let Some(schema) = crate::signature_cli::load_user_signatures(config_dir) {
        for signature in schema.signatures {
            let name = signature.name.clone();
            if let Err(err) = db.add(signature) {
                warnings.push(format!("skipping invalid user signature '{name}': {err}"));
            }
        }
    }
    (db, warnings)
}

/// The signature fast-path settings of a policy.
pub fn fast_path_config(policy: &Policy) -> FastPathConfig {
    let fast_path = &policy.signature_fast_path;
    FastPathConfig {
        enabled: fast_path.enabled,
        min_confidence_threshold: fast_path.min_confidence_threshold,
        require_explicit_priors: fast_path.require_explicit_priors,
    }
}

/// Stable label for a signature match level.
pub fn match_level_label(level: MatchLevel) -> &'static str {
    match level {
        MatchLevel::None => "none",
        MatchLevel::GenericCategory => "generic_category",
        MatchLevel::CommandOnly => "command_only",
        MatchLevel::CommandPlusArgs => "command_plus_args",
        MatchLevel::ExactCommand => "exact_command",
        MatchLevel::MultiPattern => "multi_pattern",
    }
}

/// Stable label for why the signature fast path was not taken.
pub fn fast_path_skip_reason_label(reason: FastPathSkipReason) -> &'static str {
    match reason {
        FastPathSkipReason::Disabled => "disabled",
        FastPathSkipReason::NoMatch => "no_match",
        FastPathSkipReason::ScoreBelowThreshold => "score_below_threshold",
        FastPathSkipReason::NoPriors => "no_priors",
    }
}

/// The XDG application unit a live process runs in, when it is a desktop application:
/// in an `app-*` unit of the user's service manager and without a controlling
/// terminal (a command typed into a terminal emulator shares the emulator's unit but
/// has the terminal's TTY). Linux only; `None` elsewhere.
pub fn desktop_app_unit_for(proc: &ProcessRecord) -> Option<String> {
    if proc.has_tty() {
        return None;
    }
    let path = crate::collect::read_systemd_cgroup_path(proc.pid.0)?;
    crate::collect::desktop_app_unit(&path).map(str::to_string)
}

/// Evidence that a process is a desktop application the graphical session started:
/// it lives as long as someone keeps it open, so being old and idle is expected.
fn desktop_app_term() -> EvidenceTerm {
    EvidenceTerm {
        feature: DESKTOP_APP_FEATURE.to_string(),
        log_likelihood: ClassScores {
            useful: 0.60,
            useful_bad: 0.20,
            abandoned: -0.70,
            zombie: -0.20,
        },
    }
}

/// Whether the signature that set a process's class prior expects it to be left
/// behind (e.g. the built-in test runners: `likely_abandoned`). A desktop
/// application unit then only says who started the process, not that someone is
/// using it: a jest that an editor extension spawned inside the editor's `app-*`
/// unit and that has been stuck for hours is still a stuck jest.
fn signature_expects_abandoned(sig_match: &SignatureMatch<'_>, priors: &Priors) -> bool {
    let sig_priors = &sig_match.signature.priors;
    let Some(abandoned) = sig_priors.abandoned.as_ref() else {
        return false;
    };
    let useful = sig_priors
        .useful
        .as_ref()
        .map_or(priors.classes.useful.prior_prob, |useful| useful.mean());
    abandoned.mean() > useful
}

/// A process's score, with everything that went into it.
#[derive(Debug, Clone)]
pub struct ProcessScore<'a> {
    pub posterior: PosteriorResult,
    pub ledger: EvidenceLedger,
    /// Where the class prior came from (`global`, `signature`, `user` for a learned
    /// verdict, or `signature_fast_path`).
    pub prior_source: String,
    pub signature: Option<SignatureMatch<'a>>,
    pub learned_prior: Option<LearnedPrior>,
    pub fast_path_used: bool,
    pub fast_path_skip_reason: Option<&'static str>,
    /// The desktop application unit, when the process is a desktop application.
    pub desktop_app: Option<String>,
    /// Whether the desktop-application ownership term was applied. It is withheld
    /// when the signature that set the prior expects the process to be abandoned.
    pub desktop_app_credited: bool,
    /// Provenance adjustment, when the scorer collected provenance.
    #[cfg(target_os = "linux")]
    pub provenance: Option<ProvenanceScoreAdjustment>,
}

/// Scores processes the same way on every surface. See the module docs.
#[derive(Debug, Clone)]
pub struct Scorer {
    pub priors: Priors,
    pub decisions: DecisionStore,
    pub signatures: SignatureDatabase,
    pub fast_path: FastPathConfig,
    #[cfg(target_os = "linux")]
    provenance: Option<ProvenanceInferenceBundle>,
}

impl Scorer {
    pub fn new(
        priors: Priors,
        decisions: DecisionStore,
        signatures: SignatureDatabase,
        fast_path: FastPathConfig,
    ) -> Self {
        Self {
            priors,
            decisions,
            signatures,
            fast_path,
            #[cfg(target_os = "linux")]
            provenance: None,
        }
    }

    /// The scorer for a loaded configuration: its priors and fast-path policy, the
    /// learned verdicts and user signatures in its config directory. Returns warnings
    /// for inputs that could not be read (the scorer then goes on without them).
    pub fn from_config(config: &ResolvedConfig) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let decisions = match DecisionStore::load(&config.config_dir) {
            Ok(store) => store,
            Err(err) => {
                warnings.push(format!("ignoring unreadable decision store: {err}"));
                DecisionStore::default()
            }
        };
        let (signatures, signature_warnings) = load_signature_database(&config.config_dir);
        warnings.extend(signature_warnings);
        (
            Self::new(
                config.priors.clone(),
                decisions,
                signatures,
                fast_path_config(&config.policy),
            ),
            warnings,
        )
    }

    /// Collect provenance (lineage, resources, blast radius) for the processes about
    /// to be scored. Linux only; a no-op elsewhere. Without it, scores carry no
    /// provenance terms.
    pub fn collect_provenance(&mut self, processes: &[&ProcessRecord]) {
        #[cfg(target_os = "linux")]
        {
            self.provenance = Some(build_provenance_bundle(processes));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = processes;
        }
    }

    /// Score one process from its evidence (usually `Evidence::from_snapshot`, plus
    /// any deep-scan signals). `None` if the posterior cannot be computed.
    pub fn score(&self, proc: &ProcessRecord, evidence: Evidence) -> Option<ProcessScore<'_>> {
        self.score_with_desktop(proc, evidence, desktop_app_unit_for(proc))
    }

    fn score_with_desktop(
        &self,
        proc: &ProcessRecord,
        mut evidence: Evidence,
        desktop_app: Option<String>,
    ) -> Option<ProcessScore<'_>> {
        let pid = proc.pid.0;
        if desktop_app.is_some() {
            // A desktop application never has a controlling terminal, so its absence
            // says nothing about abandonment.
            evidence.tty = None;
        }

        let mut match_ctx = ProcessMatchContext::with_comm(&proc.comm);
        if !proc.cmd.is_empty() {
            match_ctx = match_ctx.cmdline(&proc.cmd);
        }
        let signature = self.signatures.best_match(&match_ctx);

        let learned_prior = self
            .decisions
            .learned_prior(&proc.comm, &proc.cmd, &self.priors);
        let learned_overrides = learned_prior
            .as_ref()
            .map(|learned| DecisionStore::overrides_for(learned, &self.priors));
        let prior_context = PriorContext {
            global_priors: &self.priors,
            signature_match: signature.as_ref(),
            category_defaults: None,
            user_overrides: learned_overrides.as_ref(),
        };

        // A human verdict on this pattern outranks the signature fast path.
        let mut fast_path_skip_reason = None;
        let fast_path = match signature.as_ref().filter(|_| learned_prior.is_none()) {
            Some(sig_match) => match try_signature_fast_path(&self.fast_path, Some(sig_match), pid)
            {
                Ok(result) => result,
                Err(reason) => {
                    fast_path_skip_reason = Some(fast_path_skip_reason_label(reason));
                    None
                }
            },
            None => None,
        };
        let fast_path_used = fast_path.is_some();
        let (mut posterior, mut ledger, prior_source) = match fast_path {
            Some(fast_path) => (
                fast_path.posterior,
                fast_path.ledger,
                "signature_fast_path".to_string(),
            ),
            None => {
                let (result, source_info) =
                    compute_posterior_with_overrides(&prior_context, &evidence).ok()?;
                let ledger = EvidenceLedger::from_posterior_result(&result, Some(pid), None);
                (result, ledger, source_info.source.to_string())
            }
        };

        // Only when the signature actually set the prior (not a learned verdict, and
        // not a match too weak for its priors to apply).
        let signature_set_prior =
            matches!(prior_source.as_str(), "signature" | "signature_fast_path");
        let abandon_signature = signature
            .as_ref()
            .filter(|sig_match| {
                signature_set_prior && signature_expects_abandoned(sig_match, &self.priors)
            })
            .map(|sig_match| sig_match.signature.name.clone());
        let mut desktop_app_credited = false;
        if desktop_app.is_some() && abandon_signature.is_none() {
            if let Ok(adjusted) = apply_evidence_terms(&posterior, [desktop_app_term()]) {
                posterior = adjusted;
                ledger = EvidenceLedger::from_posterior_result(&posterior, Some(pid), None);
                desktop_app_credited = true;
            }
        }

        #[cfg(target_os = "linux")]
        // Only processes the provenance was collected for: an empty lineage would read
        // as "nothing depends on it" and push toward abandoned.
        let provenance = self
            .provenance
            .as_ref()
            .filter(|bundle| bundle.lineages.contains_key(&pid))
            .map(|bundle| {
                let mut adjustment = derive_provenance_adjustment(pid, bundle);
                // The base `orphan` term already carries "reparented to init"; counting the
                // lineage's orphaned verdict again double-counts one fact under naive Bayes.
                // Keep it only when it adds information (lineage sees an orphan that the
                // base check does not, e.g. reparented to a user subreaper).
                if proc.is_orphan() {
                    adjustment
                        .evidence_terms
                        .retain(|t| t.feature != "provenance_ownership_orphaned");
                }
                // Desktop-application ownership is the more specific ownership fact.
                if desktop_app.is_some() {
                    adjustment
                        .evidence_terms
                        .retain(|t| !t.feature.starts_with("provenance_ownership_"));
                }
                provenance::apply_adjustment(pid, &adjustment, &mut posterior, &mut ledger);
                adjustment
            });

        if let Some(unit) = desktop_app.as_deref() {
            let line = match abandon_signature.as_deref() {
                Some(name) => format!(
                    "Desktop application unit ({unit}), no desktop-app credit: signature '{name}' expects it to be abandoned"
                ),
                None => format!("Desktop application ({unit}) started by the graphical session"),
            };
            ledger.top_evidence.insert(0, line);
            ledger
                .evidence_glyphs
                .insert(DESKTOP_APP_FEATURE.to_string(), "🖥".to_string());
        }

        if let Some(sig_match) = signature.as_ref() {
            if !fast_path_used {
                ledger.top_evidence.insert(
                    0,
                    format!(
                        "Signature match: {} (score={:.2}, level={})",
                        sig_match.signature.name,
                        sig_match.score,
                        match_level_label(sig_match.level)
                    ),
                );
                ledger.why_summary = format!(
                    "Matched signature '{}' (score {:.2}, level {}, prior source {}). {}",
                    sig_match.signature.name,
                    sig_match.score,
                    match_level_label(sig_match.level),
                    prior_source,
                    ledger.why_summary
                );
            }
        }

        Some(ProcessScore {
            posterior,
            ledger,
            prior_source,
            signature,
            learned_prior,
            fast_path_used,
            fast_path_skip_reason,
            desktop_app,
            desktop_app_credited,
            #[cfg(target_os = "linux")]
            provenance,
        })
    }
}

#[cfg(target_os = "linux")]
mod provenance {
    use std::collections::HashMap;

    use pt_common::{
        normalize_lineage, CandidateProvenanceOutput, OwnershipState, ProvenanceConfidence,
        ProvenanceFeatureInput, ProvenanceRedactionState, RawLineageEvidence,
    };

    use crate::collect::{
        collect_fd_ipc_resources, collect_lineage_for_pid, collect_listener_resources_from,
        collect_local_resource_evidence, detect_listener_conflicts, parse_fd, NetworkSnapshot,
        ProcessRecord, SharedResourceGraph,
    };
    use crate::decision::{
        estimate_blast_radius, BlastRadiusEstimate, BlastRadiusEstimatorConfig, RiskLevel,
    };
    use crate::inference::{
        apply_evidence_terms, ClassScores, Confidence, EvidenceLedger, EvidenceTerm,
        PosteriorResult,
    };

    /// Lineage and shared-resource evidence for a set of processes.
    #[derive(Debug, Clone)]
    pub struct ProvenanceInferenceBundle {
        pub resource_graph: SharedResourceGraph,
        pub lineages: HashMap<u32, RawLineageEvidence>,
        pub children: HashMap<u32, Vec<u32>>,
    }

    /// Provenance-derived evidence terms and confidence caveats for one process.
    #[derive(Debug, Clone)]
    pub struct ProvenanceScoreAdjustment {
        pub evidence_terms: Vec<EvidenceTerm>,
        pub evidence_completeness: f64,
        pub confidence_penalty_steps: usize,
        pub confidence_notes: Vec<String>,
        pub blast_radius: BlastRadiusEstimate,
    }

    impl ProvenanceScoreAdjustment {
        /// Convert to the stable output contract type for JSON/TOON/agent consumers.
        ///
        /// Delegates to `CandidateProvenanceOutput::from_parts` so the contract
        /// logic (direction thresholds, score-impact construction) lives in one
        /// place in pt-common rather than being duplicated here.
        pub fn to_candidate_output(&self) -> CandidateProvenanceOutput {
            let feature_inputs: Vec<ProvenanceFeatureInput> = self
                .evidence_terms
                .iter()
                .map(|term| ProvenanceFeatureInput {
                    feature: term.feature.clone(),
                    abandoned_ll: term.log_likelihood.abandoned,
                    useful_ll: term.log_likelihood.useful,
                })
                .collect();

            CandidateProvenanceOutput::from_parts(
                self.evidence_completeness,
                self.confidence_penalty_steps,
                self.confidence_notes.clone(),
                &feature_inputs,
                self.blast_radius.risk_score,
                &format!("{:?}", self.blast_radius.risk_level).to_lowercase(),
                self.blast_radius.confidence,
                &self.blast_radius.summary,
                self.blast_radius.total_affected,
                ProvenanceRedactionState::None,
            )
        }
    }

    /// Collect lineage and shared-resource evidence for `processes`.
    pub fn build_provenance_bundle(processes: &[&ProcessRecord]) -> ProvenanceInferenceBundle {
        let mut lineages = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut per_process_resources: Vec<(u32, Vec<pt_common::RawResourceEvidence>)> = Vec::new();
        let mut all_resources = Vec::new();
        // One socket-table snapshot for the whole scan (was re-parsed per process).
        let network_snapshot = NetworkSnapshot::collect();

        for proc in processes {
            let pid = proc.pid.0;
            children.entry(proc.ppid.0).or_default().push(pid);
            lineages.insert(pid, collect_lineage_for_pid(pid));

            let fd_info = parse_fd(pid);
            let mut resources = collect_local_resource_evidence(pid, fd_info.as_ref());
            resources.extend(collect_listener_resources_from(pid, &network_snapshot));
            resources.extend(collect_fd_ipc_resources(pid));
            all_resources.extend(resources.iter().cloned());
            per_process_resources.push((pid, resources));
        }

        let index_of_pid: HashMap<u32, usize> = per_process_resources
            .iter()
            .enumerate()
            .map(|(i, (pid, _))| (*pid, i))
            .collect();
        for conflict in detect_listener_conflicts(&all_resources) {
            if let Some((_, resources)) = index_of_pid
                .get(&conflict.owner_pid)
                .map(|&i| &mut per_process_resources[i])
            {
                if let Some(existing) = resources
                    .iter_mut()
                    .find(|resource| resource.key == conflict.key && resource.kind == conflict.kind)
                {
                    existing.state = conflict.state;
                    existing.observed_at = conflict.observed_at.clone();
                } else {
                    resources.push(conflict);
                }
            }
        }

        let resource_graph = SharedResourceGraph::from_evidence(&per_process_resources);

        ProvenanceInferenceBundle {
            resource_graph,
            lineages,
            children,
        }
    }

    fn provenance_confidence_score(confidence: ProvenanceConfidence) -> f64 {
        match confidence {
            ProvenanceConfidence::High => 1.0,
            ProvenanceConfidence::Medium => 0.75,
            ProvenanceConfidence::Low => 0.45,
            ProvenanceConfidence::Unknown => 0.2,
        }
    }

    fn downgrade_confidence(confidence: Confidence, steps: usize) -> Confidence {
        let mut downgraded = confidence;
        for _ in 0..steps {
            downgraded = match downgraded {
                Confidence::VeryHigh => Confidence::High,
                Confidence::High => Confidence::Medium,
                Confidence::Medium | Confidence::Low => Confidence::Low,
            };
        }
        downgraded
    }

    fn provenance_term(
        feature: &str,
        useful: f64,
        useful_bad: f64,
        abandoned: f64,
        zombie: f64,
    ) -> EvidenceTerm {
        EvidenceTerm {
            feature: feature.to_string(),
            log_likelihood: ClassScores {
                useful,
                useful_bad,
                abandoned,
                zombie,
            },
        }
    }

    /// Provenance evidence terms and confidence caveats for `pid`.
    pub fn derive_provenance_adjustment(
        pid: u32,
        bundle: &ProvenanceInferenceBundle,
    ) -> ProvenanceScoreAdjustment {
        let lineage = bundle.lineages.get(&pid);
        let normalized_lineage = lineage.map(normalize_lineage);
        let child_pids = bundle
            .children
            .get(&pid)
            .map(|children| children.as_slice())
            .unwrap_or(&[]);

        let mut resolved_resources = 0usize;
        let mut unresolved_resources = 0usize;
        let mut conflict_resources = 0usize;

        if let Some(keys) = bundle.resource_graph.process_resources.get(&pid) {
            for key in keys {
                let Some(resource) = bundle.resource_graph.resources.get(key) else {
                    continue;
                };
                let Some(holder_state) =
                    resource.holder_states.iter().find(|state| state.pid == pid)
                else {
                    continue;
                };
                match holder_state.state {
                    pt_common::ResourceState::Active | pt_common::ResourceState::Stale => {
                        resolved_resources += 1;
                    }
                    pt_common::ResourceState::Partial | pt_common::ResourceState::Missing => {
                        unresolved_resources += 1;
                    }
                    pt_common::ResourceState::Conflicted => {
                        unresolved_resources += 1;
                        conflict_resources += 1;
                    }
                }
            }
        }

        let lineage_confidence = normalized_lineage
            .as_ref()
            .map(|lineage| lineage.confidence)
            .unwrap_or(ProvenanceConfidence::Unknown);
        let lineage_score = provenance_confidence_score(lineage_confidence);
        let resource_score = if resolved_resources + unresolved_resources == 0 {
            0.7
        } else {
            resolved_resources as f64 / (resolved_resources + unresolved_resources) as f64
        };
        let mut evidence_completeness = ((lineage_score + resource_score) / 2.0).clamp(0.0, 1.0);

        let mut confidence_notes = Vec::new();
        let mut confidence_penalty_steps = 0usize;

        if lineage.is_none() {
            confidence_notes.push("missing lineage provenance".to_string());
            confidence_penalty_steps += 1;
        }
        if unresolved_resources > 0 {
            confidence_notes.push(format!(
                "resource provenance has {unresolved_resources} unresolved edge(s)"
            ));
            confidence_penalty_steps += 1;
        }
        if let Some(normalized_lineage) = normalized_lineage.as_ref() {
            if !normalized_lineage.downgrade_reasons.is_empty() {
                confidence_notes.extend(normalized_lineage.downgrade_reasons.iter().cloned());
                confidence_penalty_steps += 1;
            }
        }
        if conflict_resources > 0 {
            confidence_notes.push(format!(
                "resource provenance has {conflict_resources} conflicting edge(s)"
            ));
        }

        if !confidence_notes.is_empty() {
            evidence_completeness = (evidence_completeness - 0.1).clamp(0.0, 1.0);
        }

        let blast_radius = estimate_blast_radius(
            pid,
            &bundle.resource_graph,
            lineage,
            child_pids,
            evidence_completeness,
            &BlastRadiusEstimatorConfig::default(),
        );

        if blast_radius.confidence < 0.5 {
            confidence_notes.push("blast-radius estimate is low-confidence".to_string());
            confidence_penalty_steps += 1;
        }

        let mut evidence_terms = Vec::new();
        if let Some(normalized_lineage) = normalized_lineage.as_ref() {
            match &normalized_lineage.ownership {
                OwnershipState::Orphaned => {
                    evidence_terms.push(provenance_term(
                        "provenance_ownership_orphaned",
                        -0.55,
                        -0.10,
                        0.70,
                        0.20,
                    ));
                }
                OwnershipState::Supervised { .. }
                | OwnershipState::InitChild
                | OwnershipState::AgentOwned { .. } => {
                    evidence_terms.push(provenance_term(
                        "provenance_ownership_supervised",
                        0.60,
                        0.20,
                        -0.70,
                        -0.20,
                    ));
                }
                OwnershipState::ShellOwned { .. } => {
                    evidence_terms.push(provenance_term(
                        "provenance_ownership_shell",
                        0.35,
                        0.15,
                        -0.35,
                        -0.10,
                    ));
                }
                OwnershipState::Unknown => {}
            }
        }

        if blast_radius.direct.components.listener_count > 0 {
            evidence_terms.push(provenance_term(
                "provenance_active_listener",
                0.55,
                0.20,
                -0.60,
                -0.15,
            ));
        }

        match blast_radius.risk_level {
            RiskLevel::High | RiskLevel::Critical => {
                evidence_terms.push(provenance_term(
                    "provenance_blast_radius_high",
                    0.65,
                    0.30,
                    -0.75,
                    -0.20,
                ));
            }
            RiskLevel::Low if blast_radius.total_affected == 0 => {
                evidence_terms.push(provenance_term(
                    "provenance_blast_radius_low",
                    -0.25,
                    -0.05,
                    0.35,
                    0.10,
                ));
            }
            RiskLevel::Medium | RiskLevel::Low => {}
        }

        ProvenanceScoreAdjustment {
            evidence_terms,
            evidence_completeness,
            confidence_penalty_steps: confidence_penalty_steps.min(3),
            confidence_notes,
            blast_radius,
        }
    }

    /// Fold a provenance adjustment into a posterior and its ledger.
    pub(super) fn apply_adjustment(
        pid: u32,
        adjustment: &ProvenanceScoreAdjustment,
        posterior: &mut PosteriorResult,
        ledger: &mut EvidenceLedger,
    ) {
        if !adjustment.evidence_terms.is_empty() {
            match apply_evidence_terms(posterior, adjustment.evidence_terms.clone()) {
                Ok(adjusted) => {
                    *posterior = adjusted;
                    *ledger = EvidenceLedger::from_posterior_result(posterior, Some(pid), None);
                }
                Err(err) => {
                    tracing::debug!(
                        pid,
                        error = %err,
                        "Failed to apply provenance-derived evidence terms"
                    );
                }
            }
        }

        if adjustment.confidence_penalty_steps > 0 {
            ledger.confidence =
                downgrade_confidence(ledger.confidence, adjustment.confidence_penalty_steps);
            if !adjustment.confidence_notes.is_empty() {
                let joined = adjustment.confidence_notes.join("; ");
                ledger
                    .top_evidence
                    .push(format!("Provenance confidence downgrade: {joined}"));
                ledger.why_summary =
                    format!("{} Provenance caveats: {}.", ledger.why_summary, joined);
            }
        }

        for term in &adjustment.evidence_terms {
            let glyph = if term.feature.contains("blast_radius") {
                "🛡"
            } else {
                "🔗"
            };
            ledger
                .evidence_glyphs
                .insert(term.feature.clone(), glyph.to_string());
        }

        tracing::debug!(
            pid,
            evidence_completeness = adjustment.evidence_completeness,
            blast_radius_risk = adjustment.blast_radius.risk_score,
            blast_radius_confidence = adjustment.blast_radius.confidence,
            blast_radius_level = ?adjustment.blast_radius.risk_level,
            confidence_penalty_steps = adjustment.confidence_penalty_steps,
            score_terms = ?adjustment
                .evidence_terms
                .iter()
                .map(|term| term.feature.clone())
                .collect::<Vec<_>>(),
            notes = ?adjustment.confidence_notes,
            "Applied provenance-derived scoring adjustments"
        );

        // Explanation-trace diagnostics: per-feature evidence selection events so
        // provenance decisions can be diagnosed from the trace log.
        for term in &adjustment.evidence_terms {
            let net_shift = term.log_likelihood.abandoned - term.log_likelihood.useful;
            let direction = if net_shift > 0.1 {
                "toward_abandon"
            } else if net_shift < -0.1 {
                "toward_useful"
            } else {
                "neutral"
            };
            tracing::trace!(
                pid,
                feature = %term.feature,
                abandoned_ll = term.log_likelihood.abandoned,
                useful_ll = term.log_likelihood.useful,
                net_shift = net_shift,
                direction = direction,
                "provenance_evidence_selected"
            );
        }

        if adjustment.confidence_penalty_steps > 0 {
            tracing::trace!(
                pid,
                steps = adjustment.confidence_penalty_steps,
                reasons = ?adjustment.confidence_notes,
                evidence_completeness = adjustment.evidence_completeness,
                "provenance_confidence_downgraded"
            );
        }

        if adjustment.blast_radius.total_affected > 0 {
            tracing::trace!(
                pid,
                risk_score = adjustment.blast_radius.risk_score,
                risk_level = ?adjustment.blast_radius.risk_level,
                total_affected = adjustment.blast_radius.total_affected,
                confidence = adjustment.blast_radius.confidence,
                summary = %adjustment.blast_radius.summary,
                "provenance_blast_radius_computed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::ProcessState;
    use crate::decision::decision_store::Verdict;
    use crate::supervision::signature::{SignaturePriors, SupervisorSignature};
    use crate::supervision::SupervisorCategory;
    use pt_common::{ProcessId, StartId};
    use std::time::Duration;

    fn record(pid: u32, comm: &str, cmd: &str, age: Duration) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(4000),
            uid: 1000,
            user: "alice".to_string(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId::from_linux("test-boot-id", 1_234_567_890, pid),
            comm: comm.to_string(),
            cmd: cmd.to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 200 * 1024 * 1024,
            vsz_bytes: 400 * 1024 * 1024,
            tty: None,
            start_time_unix: 1_234_567_890,
            elapsed: age,
            source: "test".to_string(),
            container_info: None,
        }
    }

    // Tests call `score_with_desktop` so the result never depends on the cgroup of
    // whatever real process holds the test PID on the host.
    fn scorer(signatures: SignatureDatabase) -> Scorer {
        Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            signatures,
            FastPathConfig {
                enabled: false,
                min_confidence_threshold: 0.9,
                require_explicit_priors: true,
            },
        )
    }

    const FOUR_DAYS: Duration = Duration::from_secs(4 * 24 * 3600);

    /// GH #12: an idle desktop app open for days (slack in its uwsm app scope) was
    /// rated abandoned (0.61) from runtime and "no TTY". As a desktop application it
    /// no longer clears the plan's 0.7 intervention threshold.
    #[test]
    fn desktop_app_is_not_abandoned_for_being_old_and_idle() {
        let scorer = scorer(SignatureDatabase::with_defaults());
        let slack = record(5100, "slack", "/usr/lib/slack/slack", FOUR_DAYS);

        let plain = scorer
            .score_with_desktop(&slack, Evidence::from_snapshot(&slack), None)
            .expect("score");
        let desktop = scorer
            .score_with_desktop(
                &slack,
                Evidence::from_snapshot(&slack),
                Some("app-Hyprland-slack-4821.scope".to_string()),
            )
            .expect("score");

        assert!(
            desktop.posterior.posterior.abandoned < plain.posterior.posterior.abandoned,
            "desktop {:?} vs plain {:?}",
            desktop.posterior.posterior,
            plain.posterior.posterior
        );
        assert!(
            desktop.posterior.posterior.intervention_probability() < 0.7,
            "desktop app still a candidate: {:?}",
            desktop.posterior.posterior
        );
        let features: Vec<&str> = desktop
            .posterior
            .evidence_terms
            .iter()
            .map(|t| t.feature.as_str())
            .collect();
        assert!(features.contains(&DESKTOP_APP_FEATURE), "{features:?}");
        assert!(desktop.ledger.top_evidence[0].contains("app-Hyprland-slack-4821.scope"));
        assert_eq!(
            desktop.desktop_app.as_deref(),
            Some("app-Hyprland-slack-4821.scope")
        );
        assert!(desktop.desktop_app_credited);
    }

    fn has_desktop_term(score: &ProcessScore<'_>) -> bool {
        score
            .posterior
            .evidence_terms
            .iter()
            .any(|t| t.feature == DESKTOP_APP_FEATURE)
    }

    /// A stuck jest that an editor extension spawned inside the editor's `app-*` unit
    /// is still a stuck jest: the built-in jest signature expects it to be abandoned,
    /// so the unit earns it no "someone is using this" credit.
    #[test]
    fn desktop_unit_gives_no_credit_when_signature_expects_abandoned() {
        let scorer = scorer(SignatureDatabase::with_defaults());
        let jest = record(
            5150,
            "node",
            "node /home/alice/app/node_modules/.bin/jest --runInBand",
            FOUR_DAYS,
        );
        let unit = "app-code-4821.scope".to_string();

        let plain = scorer
            .score_with_desktop(&jest, Evidence::from_snapshot(&jest), None)
            .expect("score");
        let desktop = scorer
            .score_with_desktop(&jest, Evidence::from_snapshot(&jest), Some(unit.clone()))
            .expect("score");

        assert_eq!(desktop.prior_source, "signature");
        assert!(!desktop.desktop_app_credited);
        assert!(!has_desktop_term(&desktop));
        assert_eq!(desktop.desktop_app.as_deref(), Some(unit.as_str()));
        assert!(
            desktop
                .ledger
                .top_evidence
                .iter()
                .any(|line| line.contains("no desktop-app credit")
                    && line.contains("signature 'jest'")),
            "{:?}",
            desktop.ledger.top_evidence
        );
        assert!(
            desktop.posterior.posterior.intervention_probability() >= 0.7,
            "stuck jest in an app unit fell below the plan threshold: {:?}",
            desktop.posterior.posterior
        );
        // Only "no TTY" is neutralized; the unit does not pull it toward useful.
        assert!(
            desktop.posterior.posterior.useful <= plain.posterior.posterior.useful + 0.05,
            "desktop {:?} vs plain {:?}",
            desktop.posterior.posterior,
            plain.posterior.posterior
        );
    }

    /// Signatures that expect the process to be in use keep the credit, and a
    /// learned verdict (which replaces the signature prior) restores it.
    #[test]
    fn desktop_credit_kept_for_useful_signatures_and_learned_verdicts() {
        let mut db = SignatureDatabase::with_defaults();
        db.add(
            SupervisorSignature::new("editor-helper", SupervisorCategory::Ide)
                .with_process_patterns(vec!["^edhelper$"])
                .with_priors(SignaturePriors::likely_useful()),
        )
        .expect("valid signature");
        let mut scorer = scorer(db);
        let unit = Some("app-code-4821.scope".to_string());

        let helper = record(5160, "edhelper", "edhelper --stdio", FOUR_DAYS);
        let score = scorer
            .score_with_desktop(&helper, Evidence::from_snapshot(&helper), unit.clone())
            .expect("score");
        assert_eq!(score.prior_source, "signature");
        assert!(score.desktop_app_credited && has_desktop_term(&score));
        drop(score);

        let jest = record(
            5170,
            "node",
            "node /home/alice/app/node_modules/.bin/jest --watch",
            FOUR_DAYS,
        );
        for _ in 0..3 {
            scorer
                .decisions
                .record(&jest.comm, &jest.cmd, Verdict::Spare);
        }
        let score = scorer
            .score_with_desktop(&jest, Evidence::from_snapshot(&jest), unit)
            .expect("score");
        assert_eq!(score.prior_source, "user");
        assert!(score.desktop_app_credited && has_desktop_term(&score));
    }

    /// A signature's priors reach every surface through the scorer (GH #13/#16): a
    /// user signature marking a process "useful" lowers its score.
    #[test]
    fn user_signature_priors_change_the_score() {
        let herdr = record(5200, "herdr", "herdr server", FOUR_DAYS);
        let baseline_scorer = scorer(SignatureDatabase::with_defaults());
        let baseline = baseline_scorer
            .score_with_desktop(&herdr, Evidence::from_snapshot(&herdr), None)
            .expect("score");
        assert_eq!(baseline.prior_source, "global");

        let mut db = SignatureDatabase::with_defaults();
        db.add(
            SupervisorSignature::new("herdr-server", SupervisorCategory::Terminal)
                .with_process_patterns(vec!["^herdr$"])
                .with_arg_patterns(vec!["server"])
                .with_priors(SignaturePriors::likely_useful()),
        )
        .expect("valid signature");
        let sig_scorer = scorer(db);
        let with_sig = sig_scorer
            .score_with_desktop(&herdr, Evidence::from_snapshot(&herdr), None)
            .expect("score");
        assert_eq!(with_sig.prior_source, "signature");
        assert_eq!(
            with_sig
                .signature
                .as_ref()
                .map(|m| m.signature.name.as_str()),
            Some("herdr-server")
        );
        assert!(
            with_sig.posterior.posterior.abandoned < baseline.posterior.posterior.abandoned,
            "signature {:?} vs baseline {:?}",
            with_sig.posterior.posterior,
            baseline.posterior.posterior
        );
        assert!(with_sig.ledger.why_summary.contains("herdr-server"));
    }

    /// A learned human verdict outranks signature priors on every surface.
    #[test]
    fn learned_verdicts_outrank_signatures() {
        let jest = record(
            5300,
            "node",
            "node /home/alice/app/node_modules/.bin/jest --watch",
            FOUR_DAYS,
        );
        let mut scorer = scorer(SignatureDatabase::with_defaults());
        let before = scorer
            .score_with_desktop(&jest, Evidence::from_snapshot(&jest), None)
            .expect("score");
        assert_eq!(before.prior_source, "signature");
        let abandoned_before = before.posterior.posterior.abandoned;
        drop(before);

        for _ in 0..5 {
            scorer
                .decisions
                .record(&jest.comm, &jest.cmd, Verdict::Spare);
        }
        let after = scorer
            .score_with_desktop(&jest, Evidence::from_snapshot(&jest), None)
            .expect("score");
        assert_eq!(after.prior_source, "user");
        assert!(after.learned_prior.is_some());
        assert!(after.posterior.posterior.abandoned < abandoned_before);
    }

    /// The Electron `.webpack` directory no longer drags in webpack's "likely
    /// abandoned" priors (GH #15).
    #[test]
    fn electron_worker_keeps_global_priors() {
        let worker = record(
            5400,
            "node",
            "/home/alice/.lmstudio/.internal/utils/node /opt/lm-studio/resources/app/.webpack/lib/llmworker.js",
            FOUR_DAYS,
        );
        let scorer = scorer(SignatureDatabase::with_defaults());
        let score = scorer
            .score_with_desktop(&worker, Evidence::from_snapshot(&worker), None)
            .expect("score");
        assert!(score.signature.is_none());
        assert_eq!(score.prior_source, "global");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod provenance_tests {
    use super::*;
    use crate::collect::SharedResourceGraph;
    use pt_common::{
        AncestorEntry, LineageCollectionMethod, LockMechanism, ProvenanceConfidence,
        RawLineageEvidence, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
        ResourceKind, ResourceState, SupervisorEvidence, SupervisorKind,
    };
    use std::collections::HashMap;

    fn lock_ev(pid: u32, path: &str, state: ResourceState) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Lockfile,
            key: path.to_string(),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcFd,
            state,
            details: ResourceDetails::Lockfile {
                path: path.to_string(),
                mechanism: LockMechanism::Existence,
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn listener_ev(pid: u32, port: u16) -> RawResourceEvidence {
        RawResourceEvidence {
            kind: ResourceKind::Listener,
            key: format!("tcp:0.0.0.0:{port}"),
            owner_pid: pid,
            collection_method: ResourceCollectionMethod::ProcNet,
            state: ResourceState::Active,
            details: ResourceDetails::Listener {
                protocol: "tcp".to_string(),
                port,
                bind_address: "0.0.0.0".to_string(),
            },
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn lineage(pid: u32, ppid: u32, supervisor: Option<SupervisorEvidence>) -> RawLineageEvidence {
        RawLineageEvidence {
            pid,
            ppid,
            pgid: pid,
            sid: pid,
            uid: 1000,
            user: Some("ubuntu".to_string()),
            tty: None,
            supervisor,
            ancestors: if ppid > 1 {
                vec![AncestorEntry {
                    pid: ppid,
                    comm: "bash".to_string(),
                    uid: 1000,
                }]
            } else {
                Vec::new()
            },
            collection_method: LineageCollectionMethod::Synthetic,
            observed_at: "2026-03-17T00:00:00Z".to_string(),
        }
    }

    fn feature_names(adjustment: &ProvenanceScoreAdjustment) -> Vec<&str> {
        adjustment
            .evidence_terms
            .iter()
            .map(|term| term.feature.as_str())
            .collect()
    }

    #[test]
    fn orphaned_low_blast_radius_elevates_abandonment_features() {
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(100, lineage(100, 1, None))]),
            children: HashMap::new(),
        };

        let adjustment = derive_provenance_adjustment(100, &bundle);
        let features = feature_names(&adjustment);

        assert!(features.contains(&"provenance_ownership_orphaned"));
        assert!(features.contains(&"provenance_blast_radius_low"));
        assert!(adjustment.confidence_penalty_steps >= 1);
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("PPID=1") || note.contains("ancestor chain")));
    }

    #[test]
    fn reparented_orphan_with_init_ancestor_is_not_scored_supervised() {
        // The collector walks ancestors up to and including PID 1, so a real orphan
        // always has a non-empty chain. It used to be classified InitChild and earn
        // the "supervised" term (+useful), cancelling the base orphan evidence.
        let mut orphan = lineage(400, 1, None);
        orphan.sid = 350; // kept the session of the shell that spawned it
        orphan.ancestors = vec![AncestorEntry {
            pid: 1,
            comm: "systemd".to_string(),
            uid: 0,
        }];
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(400, orphan)]),
            children: HashMap::new(),
        };

        let features = feature_names(&derive_provenance_adjustment(400, &bundle)).join(",");
        assert!(features.contains("provenance_ownership_orphaned"), "{features}");
        assert!(!features.contains("provenance_ownership_supervised"), "{features}");
    }

    #[test]
    fn supervised_listener_suppresses_false_positive_path() {
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[(
                200,
                vec![listener_ev(200, 8080)],
            )]),
            lineages: HashMap::from([(
                200,
                lineage(
                    200,
                    2,
                    Some(SupervisorEvidence {
                        kind: SupervisorKind::Systemd,
                        unit_name: Some("api.service".to_string()),
                        auto_restart: Some(true),
                        confidence: ProvenanceConfidence::High,
                    }),
                ),
            )]),
            children: HashMap::new(),
        };

        let adjustment = derive_provenance_adjustment(200, &bundle);
        let features = feature_names(&adjustment);

        assert!(features.contains(&"provenance_ownership_supervised"));
        assert!(features.contains(&"provenance_active_listener"));
        assert!(adjustment.evidence_completeness >= 0.8);
    }

    #[test]
    fn missing_and_conflicted_provenance_downgrades_confidence() {
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[(
                300,
                vec![lock_ev(300, "/tmp/shared.lock", ResourceState::Conflicted)],
            )]),
            lineages: HashMap::new(),
            children: HashMap::new(),
        };

        let adjustment = derive_provenance_adjustment(300, &bundle);

        assert!(adjustment.confidence_penalty_steps >= 2);
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("missing lineage provenance")));
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("unresolved edge")));
    }
}
