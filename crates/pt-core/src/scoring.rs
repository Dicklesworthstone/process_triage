//! One scoring path for every surface that rates a process.
//!
//! `agent plan`, the TUI (`pt run`) and its deep-scan probe advice, `agent explain`,
//! `agent snapshot`, `agent watch` and the MCP tools all score processes through
//! [`Scorer`], so a process gets the same posterior and classification whichever
//! command looks at it (GH #13: only `agent plan` applied signatures and provenance).
//!
//! A score combines:
//! 1. the class prior: a human verdict learned for the command pattern
//!    ([`DecisionStore`]), else a matching signature's priors, else
//!    the configured priors;
//! 2. the snapshot evidence (CPU, runtime, orphan, TTY, state, plus deep-scan signals
//!    when the caller collected them);
//! 3. desktop-application ownership (Linux): a process in an XDG application unit of
//!    the graphical session (`app-*.scope` / `app-*.service` under `user@UID.service`)
//!    without a terminal is an app someone has open (GH #12);
//! 4. on Linux, provenance evidence (lineage ownership, listeners, blast radius) when
//!    the caller collected it with [`Scorer::collect_provenance`].
//!
//! Signature shortcut candidates are verified through ordinary inference. Its
//! probabilities and full evidence ledger are retained, including when the most
//! likely class agrees with the signature.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::action::SystemdUserServiceBinding;
use crate::collect::duplicates::{DuplicateWorkSnapshot, ProcessWorkDiagnosis};
use crate::collect::protected::{FilterResult, ProtectedFilter};
use crate::collect::{ProcessActivity, ProcessRecord, ScanResult};
use crate::config::{Policy, Priors, ResolvedConfig};
use crate::decision::decision_store::{DecisionStore, LearnedPrior};
use crate::decision::respawn_loop::{RespawnHistorySnapshot, RespawnLoopSummary};
use crate::inference::posterior::compute_posterior_with_activity_expectations;
use crate::inference::{
    apply_evidence_terms, resolve_priors, try_signature_fast_path, ClassScores, Classification,
    CpuEvidence, Evidence, EvidenceLedger, EvidenceTerm, FastPathConfig, FastPathResult,
    FastPathSkipReason, PosteriorResult, PriorContext,
};
use crate::supervision::signature::{
    BetaParams, MatchLevel, ProcessExpectations, ProcessMatchContext, SignatureDatabase,
    SignatureMatch, SupervisorSignature,
};

#[cfg(target_os = "linux")]
pub use provenance::{
    build_provenance_bundle, derive_provenance_adjustment, ProvenanceInferenceBundle,
    ProvenanceScoreAdjustment,
};

/// Evidence-term name for desktop-application ownership.
pub const DESKTOP_APP_FEATURE: &str = "desktop_app_session";

/// Load the complete active signature model from one coherent configuration
/// snapshot. Explicit user signatures override custom/imported patterns, then
/// learned patterns, then shipped defaults; disabled names suppress all layers.
pub fn try_load_signature_database(config_dir: &Path) -> Result<SignatureDatabase, String> {
    let catalog = crate::supervision::pattern_persistence::SignatureCatalog::load(config_dir)
        .map_err(|error| format!("could not load signature configuration: {error}"))?;
    catalog
        .active_database()
        .map_err(|error| format!("could not activate signature configuration: {error}"))
}

/// Best-effort read-only variant with an explicit warning for a failed model.
/// A malformed or changing input activates no signatures: falling back to
/// defaults could revive a name whose disable state could not be read. Live
/// inference and action planning must use [`try_load_signature_database`].
pub fn load_signature_database(config_dir: &Path) -> (SignatureDatabase, Vec<String>) {
    match try_load_signature_database(config_dir) {
        Ok(database) => (database, Vec::new()),
        Err(error) => (SignatureDatabase::new(), vec![error]),
    }
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

/// Explain why a signature candidate cannot replace the shared inference result.
/// A matching command and its age do not verify current behavior. Use the
/// existing likelihoods for observed activity/state/context, without introducing
/// another scoring model or a tolerance that could hide an action-boundary change.
fn signature_verification_reason(
    candidate: &FastPathResult,
    observed: &PosteriorResult,
) -> (&'static str, &'static str) {
    let mut informative = false;
    for term in observed.evidence_terms.iter().filter(|term| {
        matches!(
            term.feature.as_str(),
            "cpu" | "io_active" | "state_flag" | "net" | "tty" | "orphan" | "queue_saturated"
        )
    }) {
        let scores = term.log_likelihood;
        let proposed = match candidate.classification {
            Classification::Useful => scores.useful,
            Classification::UsefulBad => scores.useful_bad,
            Classification::Abandoned => scores.abandoned,
            Classification::Zombie => scores.zombie,
        };
        let alternatives = [
            scores.useful,
            scores.useful_bad,
            scores.abandoned,
            scores.zombie,
        ];
        // An absent optional likelihood model can yield equal scores even when
        // the input contains a reading; that does not verify the signature.
        informative |= alternatives.iter().any(|score| *score != proposed);
        if alternatives.iter().any(|score| *score > proposed) {
            return (
                "conflicting_current_evidence",
                "Current observations contradict the signature shortcut; retained the measured posterior and full evidence ledger",
            );
        }
    }
    if !informative {
        (
            "no_current_evidence",
            "No informative current observations verify the signature; retained ordinary inference with unknown signals omitted",
        )
    } else if observed.posterior != candidate.posterior.posterior {
        (
            "current_evidence_changes_posterior",
            "Current observations change class probabilities; retained the measured posterior and full evidence ledger",
        )
    } else {
        (
            "verified_with_inference",
            "Signature probabilities agree with current observations; retained the verification and its full evidence ledger",
        )
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

/// z-score of the 99th percentile of the standard normal distribution.
const Z_99: f64 = 2.326_347_874_040_841;

/// Probability that a normal run of a signature's process would have finished by
/// `age_secs`, under a log-normal lifetime with median `typical_lifetime_seconds` and
/// 99th percentile `max_normal_lifetime_seconds`. `None` unless both are set and the
/// maximum exceeds the typical lifetime.
fn normal_run_finished_by(expectations: &ProcessExpectations, age_secs: f64) -> Option<f64> {
    let typical = expectations.typical_lifetime_seconds? as f64;
    let max = expectations.max_normal_lifetime_seconds? as f64;
    if typical <= 0.0 || max <= typical {
        return None;
    }
    if age_secs <= 0.0 {
        return Some(0.0);
    }
    let mu = typical.ln();
    let sigma = (max.ln() - mu) / Z_99;
    Some(pt_math::normal_cdf((age_secs.ln() - mu) / sigma))
}

/// A signature whose processes are usually left behind (a test runner, a build) sets
/// that prior for a process that has outlived a normal run, not for one still inside
/// it: a four-minute-old `cargo build` is not "likely abandoned". Blend each class
/// prior the signature sets with the global one, weighting the signature by the
/// probability that a normal run would have finished by now; past the 99th
/// percentile this is the signature's own prior. Concentrations are kept.
fn age_gated_signature(
    signature: &SupervisorSignature,
    global: &Priors,
    weight: f64,
) -> SupervisorSignature {
    let blend = |sig: &Option<BetaParams>, global_prob: f64| {
        sig.as_ref().map(|beta| {
            let concentration = beta.alpha + beta.beta;
            let mean = (1.0 - weight) * global_prob + weight * beta.mean();
            BetaParams::new(mean * concentration, (1.0 - mean) * concentration)
        })
    };
    let mut gated = signature.clone();
    let classes = &global.classes;
    gated.priors.useful = blend(&signature.priors.useful, classes.useful.prior_prob);
    gated.priors.useful_bad = blend(&signature.priors.useful_bad, classes.useful_bad.prior_prob);
    gated.priors.abandoned = blend(&signature.priors.abandoned, classes.abandoned.prior_prob);
    gated.priors.zombie = blend(&signature.priors.zombie, classes.zombie.prior_prob);
    gated
}

/// A process's score, with everything that went into it.
#[derive(Debug, Clone)]
pub struct ProcessScore<'a> {
    pub posterior: PosteriorResult,
    pub ledger: EvidenceLedger,
    /// The orphan fact actually scored, after reconciling snapshot and lineage
    /// observations. Explanations must not recompute it from PPID alone.
    pub orphaned: Option<bool>,
    /// Identity-bound windowed activity, including reasons for missing signals.
    /// None when no window was requested; then snapshot CPU remains the input.
    pub activity: Option<ProcessActivity>,
    /// Recent work attributed to this recognized agent root, never to its children.
    /// This supports conservative Keep advice without changing class probabilities.
    pub agent_activity: Option<AgentActivityUnit>,
    /// Where the class prior came from (`global`, `signature`, or `user` for a learned
    /// verdict).
    pub prior_source: String,
    pub signature: Option<SignatureMatch<'a>>,
    /// When the matched signature expects its processes to be left behind and states
    /// a normal lifetime: the weight its prior got for this process's age (the
    /// probability a normal run would have finished by now). `None` otherwise.
    pub signature_age_weight: Option<f64>,
    pub learned_prior: Option<LearnedPrior>,
    /// Observed kill/respawn history for this command and exact parent incarnation.
    /// This informs action utility and review, never the class posterior.
    pub respawn_history: Option<RespawnLoopSummary>,
    /// Identity-bound duplicate/competing-work diagnosis. This informs review
    /// and preservation of useful work, never the abandonment posterior.
    pub work: Option<ProcessWorkDiagnosis>,
    /// Observed pipe peers and a bounded path to recent downstream activity.
    /// This is a preservation signal, never an abandonment likelihood.
    pub pipe_liveness: Option<PipeLivenessEvidence>,
    /// A separately observed service route; it never changes class probabilities.
    pub supervisor_restart: Option<SystemdUserServiceBinding>,
    pub supervisor_restart_unavailable: Option<String>,
    /// Whether shared inference was bypassed. Signature candidates currently
    /// require verification, so scoring retains that inference and reports false.
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

/// Observations consumed by the shared scorer, bound to one process incarnation.
///
/// These contain derived provenance evidence, not raw collector inputs. Keeping
/// them explicit lets a recorded scan use the production scoring path without
/// consulting the replay machine's PIDs, cgroups, activity or resource graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringObservations {
    pub pid: u32,
    pub ppid: u32,
    pub start_id: pt_common::StartId,
    pub uid: u32,
    // Explicit null is meaningful; omitted fields are incomplete recordings.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pgid: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub sid: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub desktop_app: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub activity: Option<ProcessActivity>,
    /// Older recordings do not contain an agent census; absence stays unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_activity: Option<AgentActivityUnit>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub respawn_history: Option<RespawnLoopSummary>,
    /// Older recordings contain no work census. Absence is unknown, not proof
    /// that the process was the only build of its workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<ProcessWorkDiagnosis>,
    /// Older recordings have no descriptor census; absence remains unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe_liveness: Option<PipeLivenessEvidence>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub supervisor_restart: Option<SystemdUserServiceBinding>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub supervisor_restart_unavailable: Option<String>,
    #[cfg(target_os = "linux")]
    #[serde(deserialize_with = "Option::deserialize")]
    pub provenance: Option<ProvenanceScoreAdjustment>,
}

impl ScoringObservations {
    pub fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.pid == process.pid.0
            && self.ppid == process.ppid.0
            && self.start_id == process.start_id
            && self.uid == process.uid
            && self.pgid == process.pgid
            && self.sid == process.sid
            && self
                .activity
                .as_ref()
                .is_none_or(|activity| activity.matches_record(process))
            && self
                .agent_activity
                .as_ref()
                .is_none_or(|activity| activity.matches_record(process))
            && self
                .work
                .as_ref()
                .is_none_or(|work| work.matches_record(process))
            && self
                .pipe_liveness
                .as_ref()
                .is_none_or(|pipes| pipes.matches_record(process))
    }
}

/// One verified descriptor relationship, oriented from writer to reader.
/// Holding a read endpoint does not establish that this pipe was read recently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeLivenessHop {
    pub writer: pt_common::ProcessIdentity,
    pub writer_fd: u32,
    pub reader: pt_common::ProcessIdentity,
    pub reader_fd: u32,
    pub inode: u64,
}

/// Captured pipe observations for one incarnation. Positive paths can justify
/// retaining a producer even when the census is partial. Missing paths cannot
/// establish abandonment, inactivity, or the absence of other consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeLivenessEvidence {
    pub identity: pt_common::ProcessIdentity,
    pub identity_verified: bool,
    pub readers: Vec<PipeLivenessHop>,
    pub writers: Vec<PipeLivenessHop>,
    /// A shortest observed stdout/stderr path to a distinct active consumer.
    pub path: Vec<PipeLivenessHop>,
    pub active_consumer: Option<ProcessActivity>,
    pub census_complete: bool,
    pub collection_complete: bool,
    pub scope: String,
    pub unavailable: Vec<String>,
}

const PIPE_LIVENESS_MAX_HOPS: usize = 32;
const PIPE_LIVENESS_SCOPE: &str = "linux_procfs_leader_pipe_peers";

fn pipe_identity_parts(identity: &pt_common::ProcessIdentity) -> Option<(&str, u64)> {
    if identity.quality != pt_common::IdentityQuality::Full || identity.pid.0 == 0 {
        return None;
    }
    let mut parts = identity.start_id.0.split(':');
    let boot = parts
        .next()
        .filter(|boot| !boot.is_empty() && !matches!(*boot, "unknown" | "synthetic"))?;
    let ticks = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none() && pid == identity.pid.0).then_some((boot, ticks))
}

fn pipe_record_identity(process: &ProcessRecord) -> Option<pt_common::ProcessIdentity> {
    let identity = pt_common::ProcessIdentity::full(
        process.pid.0,
        process.start_id.clone(),
        process.uid,
        process.pgid,
        process.sid,
        pt_common::IdentityQuality::Full,
    );
    pipe_identity_parts(&identity)?;
    Some(identity)
}

/// Admit only positive, completed measurements. Native-ps averages and unknown
/// or contradictory samples never become evidence of an active pipe consumer.
fn pipe_consumer_activity_observed(activity: &ProcessActivity) -> bool {
    if activity.source != "procfs_window" || activity.requested_window_ms == 0 {
        return false;
    }
    let completed = |seconds: Option<f64>| {
        seconds.is_some_and(|seconds| {
            seconds.is_finite()
                && seconds > 0.0
                && seconds >= activity.requested_window_ms as f64 / 1000.0
        })
    };
    let cpu = activity.cpu_error.is_none()
        && completed(activity.cpu_window_seconds)
        && activity.cpu_ticks.is_some_and(|ticks| ticks > 0)
        && activity
            .cpu_percent
            .is_some_and(|percent| percent.is_finite() && percent > 0.0);
    let io = activity.io_error.is_none()
        && completed(activity.io_window_seconds)
        && activity.io_active == Some(true)
        && activity
            .io_read_bytes
            .zip(activity.io_write_bytes)
            .is_some_and(|(read, write)| read > 0 || write > 0)
        && activity
            .read_bytes_per_second
            .zip(activity.write_bytes_per_second)
            .is_some_and(|(read, write)| {
                read.is_finite()
                    && read >= 0.0
                    && write.is_finite()
                    && write >= 0.0
                    && (read > 0.0 || write > 0.0)
            });
    cpu || io
}

#[cfg(target_os = "linux")]
fn pipe_population(
    population: &[ProcessRecord],
) -> BTreeMap<crate::collect::pipe_liveness::PipeProcessIdentity, &ProcessRecord> {
    let mut unique = BTreeMap::new();
    for process in population {
        unique
            .entry(process.pid.0)
            .and_modify(|record| *record = None)
            .or_insert(Some(process));
    }
    unique
        .values()
        .filter_map(|process| *process)
        .filter(|process| {
            !matches!(
                process.state,
                crate::collect::ProcessState::Zombie
                    | crate::collect::ProcessState::Dead
                    | crate::collect::ProcessState::Unknown
            )
        })
        .filter_map(|process| {
            let identity = pipe_record_identity(process)?;
            let (_, start_ticks) = pipe_identity_parts(&identity)?;
            Some((
                crate::collect::pipe_liveness::PipeProcessIdentity {
                    pid: process.pid.0,
                    start_ticks,
                    uid: process.uid,
                },
                process,
            ))
        })
        .collect()
}

impl PipeLivenessEvidence {
    pub fn matches_record(&self, process: &ProcessRecord) -> bool {
        !matches!(
            process.state,
            crate::collect::ProcessState::Zombie
                | crate::collect::ProcessState::Dead
                | crate::collect::ProcessState::Unknown
        ) && pipe_record_identity(process).as_ref() == Some(&self.identity)
            && self.valid_observation()
    }

    fn valid_observation(&self) -> bool {
        let Some((boot, _)) = pipe_identity_parts(&self.identity) else {
            return false;
        };
        if self.scope != PIPE_LIVENESS_SCOPE {
            return false;
        }
        let valid_hop = |hop: &PipeLivenessHop| {
            hop.inode > 0
                && hop.writer.pid != hop.reader.pid
                && pipe_identity_parts(&hop.writer).is_some_and(|parts| parts.0 == boot)
                && pipe_identity_parts(&hop.reader).is_some_and(|parts| parts.0 == boot)
        };
        if self
            .readers
            .iter()
            .any(|hop| !valid_hop(hop) || hop.writer != self.identity)
            || self
                .writers
                .iter()
                .any(|hop| !valid_hop(hop) || hop.reader != self.identity)
        {
            return false;
        }
        if !self.identity_verified
            && (!self.readers.is_empty() || !self.writers.is_empty() || !self.path.is_empty())
        {
            return false;
        }
        if self.path.is_empty() {
            return self.active_consumer.is_none();
        }
        if self.path.len() > PIPE_LIVENESS_MAX_HOPS || !self.identity_verified {
            return false;
        }
        let mut previous = &self.identity;
        let mut seen = std::collections::BTreeSet::from([self.identity.pid.0]);
        for hop in &self.path {
            if !valid_hop(hop)
                || hop.writer != *previous
                || !matches!(hop.writer_fd, 1 | 2)
                || !seen.insert(hop.reader.pid.0)
            {
                return false;
            }
            previous = &hop.reader;
        }
        self.readers.contains(&self.path[0])
            && self.active_consumer.as_ref().is_some_and(|activity| {
                activity.pid == previous.pid.0
                    && activity.start_id == previous.start_id
                    && activity.uid == previous.uid
                    && pipe_consumer_activity_observed(activity)
            })
    }

    pub fn preserves_active_consumer(&self) -> bool {
        !self.path.is_empty() && self.valid_observation()
    }

    pub fn observation_summary(&self) -> Option<String> {
        if !self.preserves_active_consumer() {
            return None;
        }
        let consumer = self.path.last()?.reader.pid.0;
        Some(format!(
            "Observed stdout/stderr pipe path to process {consumer} with activity in the shared sample through {} verified pipe link(s); process activity does not prove traffic on this pipe",
            self.path.len(),
        ))
    }

    pub fn review_reason(&self) -> Option<String> {
        self.observation_summary()
            .map(|summary| format!("{summary}; preserve the producer for review"))
    }
}

/// Scores processes the same way on every surface. See the module docs.
#[derive(Debug, Clone)]
pub struct Scorer {
    pub priors: Priors,
    pub decisions: DecisionStore,
    pub signatures: SignatureDatabase,
    pub fast_path: FastPathConfig,
    evaluation_time: Option<chrono::DateTime<chrono::Utc>>,
    activity_window: Option<Duration>,
    activity: BTreeMap<u32, ProcessActivity>,
    agent_activity: BTreeMap<u32, AgentActivityUnit>,
    agent_session_window_seconds: u64,
    respawn_history: BTreeMap<u32, (pt_common::StartId, u32, RespawnLoopSummary)>,
    work: Option<DuplicateWorkSnapshot>,
    pipe_liveness: BTreeMap<u32, PipeLivenessEvidence>,
    supervisor_restarts: BTreeMap<u32, SupervisorRestartObservation>,
    #[cfg(target_os = "linux")]
    provenance: Option<ProvenanceInferenceBundle>,
}

/// Observed CPU/storage-I/O activity, not an abandonment or supervision verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentActivityState {
    ActivityObserved,
    NoActivityObservedInWindow,
    Unknown,
}

/// A sum over observed members, with an independently reported complete total.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentActivityMeasurement {
    /// Sum of usable measurements, or null when none were available or it overflowed.
    pub observed: Option<f64>,
    /// Present only when every member was measured and census/ancestry are complete.
    pub total: Option<f64>,
    pub observed_members: usize,
}

impl AgentActivityMeasurement {
    fn observe(&mut self, value: Option<f64>) {
        let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) else {
            return;
        };
        self.observed = if self.observed_members == 0 {
            Some(value)
        } else {
            self.observed
                .map(|sum| sum + value)
                .filter(|sum| sum.is_finite())
        };
        self.observed_members += 1;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentActivityUsage {
    /// One fully occupied CPU core is 1.0.
    pub cpu_cores: AgentActivityMeasurement,
    pub read_bytes_per_second: AgentActivityMeasurement,
    pub write_bytes_per_second: AgentActivityMeasurement,
    /// Sum of snapshot RSS for attributed members; shared pages may be counted twice.
    pub observed_rss_bytes: u64,
    pub rss_sum_saturated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentChildComposition {
    /// Direct children in this unit; excludes separately reported nested agents.
    pub direct_children: usize,
    /// All attributed descendants, excluding the root and nested agent trees.
    pub descendants: usize,
    pub active_descendants: usize,
    /// Descendants matching the existing built-in MCP server signature.
    pub known_mcp_server_descendants: usize,
    pub active_mcp_server_descendants: usize,
    pub other_descendants: usize,
    pub active_other_descendants: usize,
    /// Nearest nested agent roots; their resources belong to their own units.
    pub nested_agent_roots: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentActivityCoverage {
    pub cpu_observed_members: usize,
    pub storage_io_observed_members: usize,
    pub fully_observed_members: usize,
    pub active_members: usize,
    /// Members with neither positive activity nor complete usable zero measurements.
    pub unknown_activity_members: usize,
    pub ancestry_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActivityUnit {
    /// Includes the process incarnation so a reused PID cannot retain a unit ID.
    pub id: String,
    pub kind: String,
    pub root: pt_common::ProcessIdentity,
    pub root_state: crate::collect::ProcessState,
    pub age_seconds: u64,
    /// Requested CPU/I/O sampling window; never the terminal-idle threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_window_ms: Option<u64>,
    /// Effective transcript lookback, including when no transcript was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_window_seconds: Option<u64>,
    /// Independently verified metadata, including with CPU sampling disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_activity: Option<crate::collect::protected::AgentSessionActivity>,
    pub activity: AgentActivityState,
    pub member_count: usize,
    pub composition: AgentChildComposition,
    pub coverage: AgentActivityCoverage,
    pub usage: AgentActivityUsage,
    pub unavailable: Vec<String>,
}

impl AgentActivityUnit {
    /// An activity report belongs only to its original recognized agent root.
    /// Descendants, a reused PID, or a changed job/session cannot inherit it.
    pub fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.root.pid == process.pid
            && self.root.start_id == process.start_id
            && self.root.uid == process.uid
            && self.root.pgid == process.pgid
            && self.root.sid == process.sid
            && crate::collect::protected::agent_kind(&process.cmd) == Some(self.kind.as_str())
    }
}

/// Positive activity is evidence for retaining an agent. A quiet short window
/// cannot establish abandonment, and missing observations cannot establish quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLivenessState {
    Live,
    NoActivityObservedInWindow,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLivenessSource {
    RecentTerminalActivity,
    RecentSessionTranscriptActivity,
    ProcessActivity,
    DescendantActivity,
}

/// One assessment for CLI, TUI, watch and explanations. This is an observation,
/// not a calibrated likelihood term or permission to act on a quiet agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentLiveness {
    pub status: AgentLivenessState,
    /// Null when evidence is unavailable; false means only that no activity was
    /// observed during the reported window, never that the agent is abandoned.
    pub live: Option<bool>,
    pub tty: Option<String>,
    pub tty_idle_seconds: Option<u64>,
    /// Terminal-activity lookback only, separate from the short CPU/I/O sample.
    pub terminal_window_seconds: u64,
    pub requested_activity_window_ms: Option<u64>,
    pub sources: Vec<AgentLivenessSource>,
    pub reason: String,
    pub activity: Option<AgentActivityUnit>,
    pub unavailable: Vec<String>,
}

pub const AGENT_LIVE_TERMINAL_WINDOW_SECONDS: u64 = 30 * 60;

/// Assess current terminal activity alongside an already sampled agent unit.
/// Saved explanations retain the original assessment instead of calling this.
pub fn agent_liveness(
    process: &ProcessRecord,
    activity: Option<&AgentActivityUnit>,
) -> Option<AgentLiveness> {
    crate::collect::protected::agent_kind(&process.cmd)?;
    #[cfg(unix)]
    let tty_idle_seconds = process
        .tty
        .as_deref()
        .and_then(crate::collect::protected::tty_idle_seconds);
    #[cfg(not(unix))]
    let tty_idle_seconds = None;
    assess_agent_liveness(
        process,
        activity,
        tty_idle_seconds,
        AGENT_LIVE_TERMINAL_WINDOW_SECONDS,
    )
}

pub fn assess_agent_liveness(
    process: &ProcessRecord,
    activity: Option<&AgentActivityUnit>,
    tty_idle_seconds: Option<u64>,
    terminal_window_seconds: u64,
) -> Option<AgentLiveness> {
    crate::collect::protected::agent_kind(&process.cmd)?;
    let activity = activity.filter(|unit| {
        unit.matches_record(process)
            && unit.root.quality == pt_common::IdentityQuality::Full
            && agent_start_parts(process)
                .is_some_and(|(boot, _)| !matches!(boot, "unknown" | "synthetic"))
    });
    let sampled_activity =
        activity.filter(|unit| unit.sampling_window_ms.is_some_and(|window| window > 0));
    let session_activity = activity.and_then(|unit| unit.session_activity.as_ref());
    let session_window_seconds = activity
        .and_then(|unit| unit.session_window_seconds)
        .or_else(|| session_activity.map(|session| session.window_seconds))
        .unwrap_or(crate::config::policy::DEFAULT_AGENT_SESSION_WINDOW_SECONDS);
    let session_observed = session_window_seconds == 0
        || session_activity.is_some_and(|session| {
            session.matches_record(process)
                && session
                    .recently_modified_within(session_window_seconds)
                    .is_some()
        });
    let mut sources = Vec::new();
    let mut reasons = Vec::new();
    if !matches!(
        process.state,
        crate::collect::ProcessState::Zombie
            | crate::collect::ProcessState::Dead
            | crate::collect::ProcessState::Unknown
    ) {
        if process.tty.is_some()
            && tty_idle_seconds.is_some_and(|idle| idle < terminal_window_seconds)
        {
            sources.push(AgentLivenessSource::RecentTerminalActivity);
            reasons.push("terminal has recent activity".to_string());
        }
        if let Some(session) = session_activity.filter(|session| {
            session.matches_record(process)
                && session.recently_modified_within(session_window_seconds) == Some(true)
        }) {
            sources.push(AgentLivenessSource::RecentSessionTranscriptActivity);
            reasons.push(
                match session.source {
                    Some(crate::collect::protected::AgentSessionActivitySource::ExplicitSessionArgument) => {
                        "a startup-selected session transcript was recently modified"
                    }
                    _ => "an open session transcript was recently modified",
                }
                .to_string(),
            );
        }
        if let Some(unit) = sampled_activity.filter(|unit| {
            unit.activity == AgentActivityState::ActivityObserved
                && unit.coverage.active_members > 0
        }) {
            if unit.coverage.active_members > unit.composition.active_descendants {
                sources.push(AgentLivenessSource::ProcessActivity);
                reasons.push("the agent made measurable CPU or I/O progress".to_string());
            }
            if unit.composition.active_descendants > 0 {
                sources.push(AgentLivenessSource::DescendantActivity);
                reasons.push(format!(
                    "{} attributed child process(es) made measurable CPU or I/O progress",
                    unit.composition.active_descendants
                ));
            }
        }
    }
    let terminal_observed = process.tty.is_none() || tty_idle_seconds.is_some();
    let status = if !sources.is_empty() {
        AgentLivenessState::Live
    } else if terminal_observed
        && session_observed
        && sampled_activity
            .is_some_and(|unit| unit.activity == AgentActivityState::NoActivityObservedInWindow)
    {
        AgentLivenessState::NoActivityObservedInWindow
    } else {
        AgentLivenessState::Unknown
    };
    let live = match status {
        AgentLivenessState::Live => Some(true),
        AgentLivenessState::NoActivityObservedInWindow => Some(false),
        AgentLivenessState::Unknown => None,
    };
    let reason = match status {
        AgentLivenessState::Live => format!("Keep: AI agent CLI {}", reasons.join("; ")),
        AgentLivenessState::NoActivityObservedInWindow => format!(
            "No activity observed in the {}ms sampling window; a quiet sampling window does not establish abandonment",
            sampled_activity.and_then(|unit| unit.sampling_window_ms).unwrap_or(0)
        ),
        AgentLivenessState::Unknown =>
            "Agent liveness is unknown because recent activity evidence is incomplete".to_string(),
    };
    let mut unavailable = activity.map_or_else(
        || vec!["identity-bound agent activity census is unavailable".to_string()],
        |unit| unit.unavailable.clone(),
    );
    match session_activity {
        Some(session) => {
            unavailable.extend(session.unavailable.iter().cloned());
            if session_window_seconds > 0 && !session.matches_record(process) {
                unavailable
                    .push("identity-bound session transcript evidence is unavailable".to_string());
            }
        }
        None if session_window_seconds > 0 => {
            unavailable.push("session transcript activity was not captured".to_string());
        }
        None => {}
    }
    if !terminal_observed {
        unavailable.push("terminal activity could not be read".to_string());
    }
    Some(AgentLiveness {
        status,
        live,
        tty: process.tty.clone(),
        tty_idle_seconds,
        terminal_window_seconds,
        requested_activity_window_ms: activity.and_then(|unit| unit.sampling_window_ms),
        sources,
        reason,
        activity: activity.cloned(),
        unavailable,
    })
}

/// Read-only activity of recognized agent CLIs and their observed same-user trees.
/// Positive observations support retaining the root, never inherited descendant
/// protection. No field changes class probabilities or permits an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActivityReport {
    pub units: Vec<AgentActivityUnit>,
    pub input_processes: usize,
    pub census_complete: bool,
    pub attributed_processes: usize,
    pub excluded_duplicate_pids: usize,
    pub ancestry_unavailable_processes: usize,
    pub sampling_window_ms: Option<u64>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct AgentLineage {
    owner: Option<u32>,
    parent_agent: Option<u32>,
    unavailable: bool,
    cyclic: bool,
}

/// Validate start tokens before using them to order a parent/child observation.
fn agent_start_parts(process: &ProcessRecord) -> Option<(&str, u64)> {
    let mut parts = process.start_id.0.split(':');
    let boot = parts.next().filter(|boot| !boot.is_empty())?;
    let start = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none() && pid == process.pid.0).then_some((boot, start))
}

/// Resolve the census once, retaining nearest-agent boundaries and rejecting
/// ambiguous parents. Iterative memoization also bounds long chains and cycles.
fn agent_lineages(
    processes: &BTreeMap<u32, Option<&ProcessRecord>>,
    roots: &BTreeMap<u32, &str>,
) -> BTreeMap<u32, AgentLineage> {
    let mut resolved: BTreeMap<u32, AgentLineage> = BTreeMap::new();
    for (&pid, process) in processes {
        if process.is_none() || resolved.contains_key(&pid) {
            continue;
        }
        let mut path = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut current = pid;
        let mut terminal = loop {
            if let Some(known) = resolved.get(&current) {
                break *known;
            }
            if !seen.insert(current) {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: true,
                    cyclic: true,
                };
            }
            let Some(process) = processes.get(&current).copied().flatten() else {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: true,
                    cyclic: false,
                };
            };
            path.push(current);
            let parent_pid = process.ppid.0;
            if parent_pid == 0 || (parent_pid == 1 && !processes.contains_key(&1)) {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: false,
                    cyclic: false,
                };
            }
            let Some(parent) = processes.get(&parent_pid).copied().flatten() else {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: true,
                    cyclic: false,
                };
            };
            // Ownership does not cross an observed user boundary. This says
            // nothing about the independent supervision/protection evidence.
            if parent.uid != process.uid {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: false,
                    cyclic: false,
                };
            }
            let ordered = agent_start_parts(process)
                .zip(agent_start_parts(parent))
                .is_some_and(|((boot, start), (parent_boot, parent_start))| {
                    boot == parent_boot && parent_start <= start
                });
            if !ordered {
                break AgentLineage {
                    owner: None,
                    parent_agent: None,
                    unavailable: true,
                    cyclic: false,
                };
            }
            current = parent_pid;
        };
        while let Some(member) = path.pop() {
            let parent_agent = terminal.owner;
            if roots.contains_key(&member) && !terminal.cyclic {
                // A recognized root establishes its own observed unit even if
                // its upstream shell is absent from this census.
                terminal.owner = Some(member);
                terminal.unavailable = false;
            }
            terminal.parent_agent = parent_agent;
            resolved.insert(member, terminal);
        }
    }
    resolved
}

#[derive(Debug, Clone)]
struct SupervisorRestartObservation {
    target: pt_common::ProcessIdentity,
    binding: Option<SystemdUserServiceBinding>,
    unavailable: Option<String>,
}

/// Resolve protected processes using the same census and verified restart
/// observations on all live planning and inspection surfaces. An incomplete
/// census cannot establish eligibility for a supervisor-managed restart.
pub fn filter_planning_scan(
    filter: &ProtectedFilter,
    scan: &ScanResult,
    scorer: &mut Scorer,
) -> FilterResult {
    scorer.collect_supervisor_restarts(if scan.metadata.warnings.is_empty() {
        &scan.processes
    } else {
        &[]
    });
    filter.filter_scan_result_with_restarts(scan, |process| scorer.supervisor_restart_for(process))
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
            evaluation_time: None,
            activity_window: None,
            activity: BTreeMap::new(),
            agent_activity: BTreeMap::new(),
            agent_session_window_seconds:
                crate::config::policy::DEFAULT_AGENT_SESSION_WINDOW_SECONDS,
            respawn_history: BTreeMap::new(),
            work: None,
            pipe_liveness: BTreeMap::new(),
            supervisor_restarts: BTreeMap::new(),
            #[cfg(target_os = "linux")]
            provenance: None,
        }
    }

    /// Construct a scorer from already loaded models and the complete policy.
    /// Interactive refreshes can replace learned verdicts without losing the
    /// same policy-controlled observations used by plan, explain and replay.
    pub fn from_policy(
        priors: Priors,
        decisions: DecisionStore,
        signatures: SignatureDatabase,
        policy: &Policy,
    ) -> Self {
        Self::new(priors, decisions, signatures, fast_path_config(policy))
            .with_agent_session_window(policy.guardrails.agent_session_window_seconds)
    }

    /// Configure transcript freshness independently of the CPU/I/O sample.
    /// A zero lookback disables transcript collection and its retention signal.
    pub fn with_agent_session_window(mut self, window_seconds: u64) -> Self {
        self.agent_session_window_seconds = window_seconds;
        self.agent_activity.clear();
        self
    }

    /// Freeze learned-verdict decay for a paired evaluation. Live constructors
    /// leave this unset and continue using the current time for every score.
    pub fn with_evaluation_time(mut self, evaluated_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.evaluation_time = Some(evaluated_at);
        self
    }

    /// Load a complete scorer, refusing unreadable or changing model inputs.
    /// The priors and signature catalog must belong to the same fleet import
    /// generation even when an import commits between their separate reads.
    pub fn try_from_config(config: &ResolvedConfig) -> Result<Self, String> {
        let verify_generation = || {
            let current = crate::fleet::transfer::configuration_generation(&config.config_dir)
                .map_err(|error| format!("could not load scoring configuration: {error}"))?;
            if current != config.transfer_generation {
                return Err(
                    "configuration changed after priors were loaded; retry with a fresh configuration"
                        .to_string(),
                );
            }
            Ok(())
        };
        verify_generation()?;
        let decisions = DecisionStore::load(&config.config_dir)
            .map_err(|error| format!("could not load decision store: {error}"))?;
        let signatures = try_load_signature_database(&config.config_dir)?;
        verify_generation()?;
        Ok(Self::from_policy(
            config.priors.clone(),
            decisions,
            signatures,
            &config.policy,
        ))
    }

    /// Best-effort scorer for read-only comparisons that inspect every returned
    /// warning. A failed input is omitted, so this is not a complete configured
    /// model; live inference and action planning use [`Self::try_from_config`].
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
            Self::from_policy(config.priors.clone(), decisions, signatures, &config.policy),
            warnings,
        )
    }

    /// Collect target lineage against the complete observed process population.
    /// Age, protection and sampling filters select only `targets`; they must not
    /// remove resource holders or children from dependency reasoning. An incomplete
    /// census can establish observed dependencies, never that a target is isolated.
    /// Linux only; a no-op elsewhere.
    pub fn collect_provenance(
        &mut self,
        targets: &[&ProcessRecord],
        population: &[ProcessRecord],
        census_complete: bool,
    ) {
        #[cfg(target_os = "linux")]
        {
            self.provenance = Some(build_provenance_bundle(
                targets,
                population,
                census_complete,
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (targets, population, census_complete);
        }
    }

    /// Replace the full workload census on every scan. The caller collects it
    /// over the population, before age/protection/posterior filters; otherwise a
    /// protected lock holder could disappear from a duplicate group's advice.
    pub fn set_workload_snapshot(&mut self, snapshot: DuplicateWorkSnapshot) {
        self.work = Some(snapshot);
    }

    /// Never transfer a duplicate role to a reused PID or changed job identity.
    pub fn workload_diagnosis_for(&self, process: &ProcessRecord) -> Option<ProcessWorkDiagnosis> {
        self.work.as_ref()?.diagnosis_for(process)
    }

    /// Discover read-only service capabilities once per census. A refresh drops
    /// every earlier binding, including failures and reused process identities.
    pub fn collect_supervisor_restarts(&mut self, processes: &[ProcessRecord]) {
        self.supervisor_restarts.clear();
        let mut seen = std::collections::HashSet::new();
        let mut ambiguous = std::collections::HashSet::new();
        for process in processes {
            if !seen.insert(process.pid.0) {
                ambiguous.insert(process.pid.0);
            }
        }
        for process in processes {
            if ambiguous.contains(&process.pid.0) {
                continue;
            }
            let target = pt_common::ProcessIdentity::full(
                process.pid.0,
                process.start_id.clone(),
                process.uid,
                process.pgid,
                process.sid,
                if process.start_id.0.starts_with("unknown:")
                    || process.start_id.0.starts_with("synthetic:")
                {
                    pt_common::IdentityQuality::NoBootId
                } else {
                    pt_common::IdentityQuality::Full
                },
            );
            let (binding, unavailable) = match crate::action::discover_systemd_user_restart(&target)
            {
                Ok(binding) => (binding, None),
                Err(error) => (None, Some(error.to_string())),
            };
            if binding.is_some() || unavailable.is_some() {
                self.supervisor_restarts.insert(
                    process.pid.0,
                    SupervisorRestartObservation {
                        target,
                        binding,
                        unavailable,
                    },
                );
            }
        }
    }

    fn supervisor_restart_observation(
        &self,
        process: &ProcessRecord,
    ) -> Option<&SupervisorRestartObservation> {
        self.supervisor_restarts
            .get(&process.pid.0)
            .filter(|observed| {
                observed.target.start_id == process.start_id
                    && observed.target.uid == process.uid
                    && observed.target.pgid == process.pgid
                    && observed.target.sid == process.sid
            })
    }

    pub fn supervisor_restart_for(
        &self,
        process: &ProcessRecord,
    ) -> Option<&SystemdUserServiceBinding> {
        self.supervisor_restart_observation(process)?
            .binding
            .as_ref()
    }

    pub fn supervisor_restart_unavailable_for(&self, process: &ProcessRecord) -> Option<&str> {
        self.supervisor_restart_observation(process)?
            .unavailable
            .as_deref()
    }

    /// Join persisted remediation outcomes to one complete process census.
    /// Parent lookup is shared by the batch, and every refresh drops old joins.
    pub fn collect_respawn_history(
        &mut self,
        history: Option<&RespawnHistorySnapshot>,
        processes: &[ProcessRecord],
        observed_at: chrono::DateTime<chrono::Utc>,
    ) {
        self.respawn_history.clear();
        let Some(history) = history else {
            return;
        };
        let mut parents = BTreeMap::new();
        for process in processes {
            parents
                .entry(process.pid.0)
                .and_modify(|parent| *parent = None)
                .or_insert(Some(process));
        }
        for process in processes {
            if parents.get(&process.pid.0).copied().flatten().is_none() {
                continue;
            }
            if let Some(summary) = history.for_process_with_parent(
                process,
                parents.get(&process.ppid.0).copied().flatten(),
                observed_at,
            ) {
                self.respawn_history.insert(
                    process.pid.0,
                    (process.start_id.clone(), process.uid, summary),
                );
            }
        }
    }

    /// A reused PID or a reparented child must not inherit an earlier join.
    pub fn respawn_history_for(&self, process: &ProcessRecord) -> Option<&RespawnLoopSummary> {
        self.respawn_history
            .get(&process.pid.0)
            .filter(|(start_id, uid, summary)| {
                *start_id == process.start_id
                    && *uid == process.uid
                    && summary.parent.pid == process.ppid
                    && summary
                        .command
                        .split_whitespace()
                        .eq(process.cmd.split_whitespace())
            })
            .map(|(_, _, summary)| summary)
    }

    /// Collect recent CPU and storage-I/O evidence once for the entire batch.
    ///
    /// Linux uses one shared wait, with PID/start ID/UID checked around each
    /// counter sample. A missing Linux sample suppresses the corresponding
    /// evidence instead of reusing a lifetime average or claiming inactivity.
    /// Other platforms retain explicitly labelled native-ps CPU evidence.
    /// A zero window clears previous measurements and selects snapshot behavior.
    pub fn collect_activity(&mut self, processes: &[&ProcessRecord], window: Duration) {
        self.activity.clear();
        self.agent_activity.clear();
        self.pipe_liveness.clear();
        self.activity_window = (!window.is_zero()).then_some(window);
        if window.is_zero() || processes.is_empty() {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            self.activity = crate::collect::tick_delta::sample_process_activity(processes, window);
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.activity = processes
                .iter()
                .map(|process| {
                    let mut activity = ProcessActivity::unavailable(
                        process,
                        window,
                        "windowed activity collection is unsupported on this platform",
                    );
                    activity.cpu_percent = (process.cpu_percent.is_finite()
                        && process.cpu_percent >= 0.0)
                        .then_some(process.cpu_percent);
                    activity.cpu_error = Some(
                        "windowed CPU collection is unsupported; using native ps CPU".to_string(),
                    );
                    (process.pid.0, activity)
                })
                .collect();
        }
    }

    /// Observe pipe peers after the shared activity window has ended, so procfs
    /// traversal cannot inflate its CPU/I/O denominators. Never age-filter the
    /// population: a young or protected consumer still depends on its producer.
    pub fn collect_pipe_liveness(
        &mut self,
        population: &[ProcessRecord],
        census_complete: bool,
    ) {
        self.pipe_liveness.clear();
        #[cfg(target_os = "linux")]
        {
            let eligible = pipe_population(population);
            let identities: Vec<_> = eligible.keys().copied().collect();
            let snapshot = crate::collect::pipe_liveness::collect_pipe_liveness(
                &identities,
                &crate::collect::pipe_liveness::PipeCollectionLimits::default(),
            );
            self.prepare_pipe_liveness(&eligible, census_complete, &snapshot);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (population, census_complete);
    }

    /// Build serializable evidence only from this collection and the shared,
    /// identity-bound sample. This pure adapter is also used by fixture tests.
    #[cfg(target_os = "linux")]
    fn prepare_pipe_liveness(
        &mut self,
        eligible: &BTreeMap<
            crate::collect::pipe_liveness::PipeProcessIdentity,
            &ProcessRecord,
        >,
        census_complete: bool,
        snapshot: &crate::collect::pipe_liveness::PipeLivenessSnapshot,
    ) {
        use crate::collect::pipe_liveness::PipeProcessIdentity;
        self.pipe_liveness.clear();
        let verified_identity = |key: &PipeProcessIdentity| {
            let process = eligible.get(key)?;
            let identity = pipe_record_identity(process)?;
            let (boot, _) = pipe_identity_parts(&identity)?;
            let observed = snapshot.processes.get(&key.pid)?;
            (snapshot.boot_id.as_deref() == Some(boot)
                && observed.identity == *key
                && observed.identity_verified)
                .then_some(identity)
        };
        let activity_samples = &self.activity;
        let sampling_window = self.activity_window;
        let valid_sample = |key: &PipeProcessIdentity| {
            verified_identity(key)?;
            let process = eligible.get(key)?;
            let activity = activity_samples.get(&key.pid)?;
            let window_ms = sampling_window?.as_millis();
            (window_ms > 0
                && u128::from(activity.requested_window_ms) == window_ms
                && activity.matches_record(process)
                && pipe_consumer_activity_observed(activity))
                .then_some(activity)
        };
        let active = eligible
            .keys()
            .copied()
            .filter(|key| valid_sample(key).is_some())
            .collect();
        let paths = snapshot.active_downstream_paths(&active, PIPE_LIVENESS_MAX_HOPS);
        let output_hop =
            |writer: &PipeProcessIdentity, peer: &crate::collect::pipe_liveness::PipePeer| {
                Some(PipeLivenessHop {
                    writer: verified_identity(writer)?,
                    writer_fd: peer.local_fd,
                    reader: verified_identity(&peer.identity)?,
                    reader_fd: peer.peer_fd,
                    inode: peer.inode,
                })
            };
        for (key, process) in eligible {
            let Some(identity) = pipe_record_identity(process) else {
                continue;
            };
            let observed = snapshot
                .processes
                .get(&key.pid)
                .filter(|observed| observed.identity == *key);
            let identity_verified = verified_identity(key).is_some();
            let mut unavailable: Vec<_> = snapshot.unavailable.iter().take(8).cloned().collect();
            if let Some(observed) = observed {
                unavailable.extend(observed.unavailable.iter().take(8).cloned());
            }
            if !identity_verified {
                unavailable.push(
                    "The current boot and process incarnation were not verified; pipe peers remain unknown"
                        .to_string(),
                );
            }
            if !census_complete {
                unavailable.push(
                    "The process census is incomplete; unobserved consumers remain unknown"
                        .to_string(),
                );
            }
            if sampling_window.is_none() {
                unavailable.push(
                    "No shared activity window was requested; downstream activity remains unknown"
                        .to_string(),
                );
            }
            let readers: Vec<_> = observed
                .into_iter()
                .flat_map(|observed| &observed.readers)
                .filter_map(|peer| output_hop(key, peer))
                .collect();
            let writers: Vec<_> = observed
                .into_iter()
                .flat_map(|observed| &observed.writers)
                .filter_map(|peer| {
                    Some(PipeLivenessHop {
                        writer: verified_identity(&peer.identity)?,
                        writer_fd: peer.peer_fd,
                        reader: verified_identity(key)?,
                        reader_fd: peer.local_fd,
                        inode: peer.inode,
                    })
                })
                .collect();
            let mut writer = *key;
            let path = paths.get(key).and_then(|peers| {
                peers
                    .iter()
                    .map(|peer| {
                        let hop = output_hop(&writer, peer)?;
                        writer = peer.identity;
                        Some(hop)
                    })
                    .collect::<Option<Vec<_>>>()
            });
            let active_consumer = path
                .as_ref()
                .filter(|path| !path.is_empty())
                .and_then(|_| valid_sample(&writer))
                .cloned();
            let evidence = PipeLivenessEvidence {
                identity,
                identity_verified,
                readers,
                writers,
                path: if active_consumer.is_some() {
                    path.unwrap_or_default()
                } else {
                    Vec::new()
                },
                active_consumer,
                census_complete,
                collection_complete: snapshot.complete
                    && observed.is_some_and(|observed| observed.complete)
                    && identity_verified,
                scope: PIPE_LIVENESS_SCOPE.to_string(),
                unavailable,
            };
            if evidence.matches_record(process) {
                self.pipe_liveness.insert(key.pid, evidence);
            }
        }
    }

    /// A stale cached observation cannot protect a replacement process.
    pub fn pipe_liveness_for(&self, process: &ProcessRecord) -> Option<&PipeLivenessEvidence> {
        self.pipe_liveness
            .get(&process.pid.0)
            .filter(|evidence| evidence.matches_record(process))
    }

    /// Return activity only for this incarnation. An enabled window with a
    /// missing or replaced PID yields explicit unknown measurements.
    pub fn activity_for(&self, process: &ProcessRecord) -> Option<ProcessActivity> {
        let window = self.activity_window?;
        Some(match self.activity.get(&process.pid.0) {
            Some(activity) if activity.matches_record(process) => activity.clone(),
            Some(_) => ProcessActivity::unavailable(
                process,
                window,
                "sampled activity belongs to a different process incarnation",
            ),
            None => ProcessActivity::unavailable(
                process,
                window,
                "process was not included in the activity sampling window",
            ),
        })
    }

    /// Retain root-only activity from the same full census as rate collection.
    /// Refreshing rates clears this cache; callers must rebuild it before scoring.
    pub fn prepare_agent_activity(
        &mut self,
        population: &[ProcessRecord],
        census_complete: bool,
    ) -> AgentActivityReport {
        let mut report = self.agent_activity_report(population, census_complete);
        let by_pid: BTreeMap<_, _> = population
            .iter()
            .map(|process| (process.pid.0, process))
            .collect();
        // Duplicate PID records were already excluded by the pure report.
        let roots: Vec<_> = report
            .units
            .iter()
            .filter_map(|unit| {
                by_pid
                    .get(&unit.root.pid.0)
                    .copied()
                    .filter(|process| unit.matches_record(process))
            })
            .collect();
        let mut sessions = crate::collect::protected::collect_agent_session_activity(
            &roots,
            self.agent_session_window_seconds,
        );
        for unit in &mut report.units {
            unit.session_activity = sessions.remove(&unit.root.pid.0);
        }
        self.agent_activity = report
            .units
            .iter()
            .map(|unit| (unit.root.pid.0, unit.clone()))
            .collect();
        report
    }

    pub fn agent_activity_for(&self, process: &ProcessRecord) -> Option<&AgentActivityUnit> {
        self.agent_activity
            .get(&process.pid.0)
            .filter(|unit| unit.matches_record(process))
    }

    /// Describe recognized agent trees using only this census and activity that
    /// was already sampled. Pass the full census before candidate/protection
    /// filters, and report an incomplete scan as `census_complete = false`.
    /// No collector, inference update, or action policy is invoked here.
    pub fn agent_activity_report(
        &self,
        processes: &[ProcessRecord],
        census_complete: bool,
    ) -> AgentActivityReport {
        let mut by_pid = BTreeMap::new();
        for process in processes {
            by_pid
                .entry(process.pid.0)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(process));
        }
        let excluded_duplicate_pids = by_pid.values().filter(|record| record.is_none()).count();
        let roots: BTreeMap<u32, &str> = by_pid
            .iter()
            .filter_map(|(&pid, process)| {
                crate::collect::protected::agent_kind(&process.as_ref()?.cmd)
                    .map(|kind| (pid, kind))
            })
            .collect();
        let lineages = agent_lineages(&by_pid, &roots);
        let ancestry_unavailable_processes = lineages
            .values()
            .filter(|lineage| lineage.unavailable)
            .count();
        let ancestry_complete = excluded_duplicate_pids == 0 && ancestry_unavailable_processes == 0;
        let sampling_window_ms = self
            .activity_window
            .filter(|window| !window.is_zero())
            .map(|window| u64::try_from(window.as_millis()).unwrap_or(u64::MAX));
        let mut units: BTreeMap<u32, AgentActivityUnit> = roots
            .iter()
            .filter_map(|(&pid, &kind)| {
                let process = by_pid.get(&pid).copied().flatten()?;
                let quality = match agent_start_parts(process) {
                    Some(("unknown" | "synthetic", _)) => pt_common::IdentityQuality::NoBootId,
                    Some(_) => pt_common::IdentityQuality::Full,
                    None => pt_common::IdentityQuality::PidOnly,
                };
                Some((
                    pid,
                    AgentActivityUnit {
                        id: format!("agent:{}:{}:{}", process.uid, pid, process.start_id),
                        kind: kind.to_string(),
                        root: pt_common::ProcessIdentity::full(
                            pid,
                            process.start_id.clone(),
                            process.uid,
                            process.pgid,
                            process.sid,
                            quality,
                        ),
                        root_state: process.state,
                        age_seconds: process.elapsed_seconds(),
                        sampling_window_ms,
                        session_window_seconds: Some(self.agent_session_window_seconds),
                        session_activity: None,
                        activity: AgentActivityState::Unknown,
                        member_count: 0,
                        composition: AgentChildComposition::default(),
                        coverage: AgentActivityCoverage {
                            ancestry_complete,
                            ..AgentActivityCoverage::default()
                        },
                        usage: AgentActivityUsage::default(),
                        unavailable: Vec::new(),
                    },
                ))
            })
            .collect();

        for process in by_pid.values().filter_map(|record| *record) {
            let owner = if roots.contains_key(&process.pid.0) {
                Some(process.pid.0)
            } else {
                lineages
                    .get(&process.pid.0)
                    .and_then(|lineage| lineage.owner)
            };
            let Some(unit) = owner.and_then(|owner| units.get_mut(&owner)) else {
                continue;
            };
            unit.member_count += 1;
            match unit.usage.observed_rss_bytes.checked_add(process.rss_bytes) {
                Some(sum) => unit.usage.observed_rss_bytes = sum,
                None => {
                    unit.usage.observed_rss_bytes = u64::MAX;
                    unit.usage.rss_sum_saturated = true;
                }
            }

            // Lifetime-averaged `ps` CPU, stale incarnations, malformed counters,
            // and samples from another window must not be described as recent work.
            let sample = self.activity.get(&process.pid.0).filter(|sample| {
                sampling_window_ms
                    .is_some_and(|window| window > 0 && sample.requested_window_ms == window)
                    && sample.source == "procfs_window"
                    && sample.matches_record(process)
                    && agent_start_parts(process).is_some()
            });
            let cpu = sample.and_then(|sample| {
                if sample.cpu_error.is_none()
                    && sample.cpu_ticks.is_some()
                    && sample
                        .cpu_window_seconds
                        .is_some_and(|seconds| seconds.is_finite() && seconds > 0.0)
                {
                    sample
                        .cpu_percent
                        .filter(|percent| percent.is_finite() && *percent >= 0.0)
                } else {
                    None
                }
            });
            let io = sample.and_then(|sample| {
                if sample.io_error.is_none()
                    && sample.io_active.is_some()
                    && sample
                        .io_window_seconds
                        .is_some_and(|seconds| seconds.is_finite() && seconds > 0.0)
                {
                    sample
                        .read_bytes_per_second
                        .zip(sample.write_bytes_per_second)
                        .filter(|(read, write)| {
                            read.is_finite() && *read >= 0.0 && write.is_finite() && *write >= 0.0
                        })
                } else {
                    None
                }
            });
            let active = cpu.is_some_and(|percent| percent > 0.0)
                || io.is_some_and(|(read, write)| read > 0.0 || write > 0.0)
                || (io.is_some() && sample.is_some_and(|sample| sample.io_active == Some(true)));
            unit.coverage.cpu_observed_members += usize::from(cpu.is_some());
            unit.coverage.storage_io_observed_members += usize::from(io.is_some());
            unit.coverage.fully_observed_members += usize::from(cpu.is_some() && io.is_some());
            unit.coverage.active_members += usize::from(active);
            unit.coverage.unknown_activity_members +=
                usize::from(!active && (cpu.is_none() || io.is_none()));
            unit.usage
                .cpu_cores
                .observe(cpu.map(|percent| percent / 100.0));
            unit.usage
                .read_bytes_per_second
                .observe(io.map(|(read, _)| read));
            unit.usage
                .write_bytes_per_second
                .observe(io.map(|(_, write)| write));

            if process.pid.0 != unit.root.pid.0 {
                unit.composition.descendants += 1;
                unit.composition.direct_children += usize::from(process.ppid == unit.root.pid);
                unit.composition.active_descendants += usize::from(active);
                let context = ProcessMatchContext::with_comm(&process.comm).cmdline(&process.cmd);
                let mcp = self
                    .signatures
                    .match_process(&context)
                    .iter()
                    .any(|matched| {
                        matched.signature.builtin && matched.signature.name == "mcp-server"
                    });
                if mcp {
                    unit.composition.known_mcp_server_descendants += 1;
                    unit.composition.active_mcp_server_descendants += usize::from(active);
                } else {
                    unit.composition.other_descendants += 1;
                    unit.composition.active_other_descendants += usize::from(active);
                }
            }
        }
        for &root in roots.keys() {
            if let Some(parent) = lineages
                .get(&root)
                .filter(|lineage| !lineage.cyclic)
                .and_then(|lineage| lineage.parent_agent)
                .and_then(|pid| units.get_mut(&pid))
            {
                parent.composition.nested_agent_roots += 1;
            }
        }

        for unit in units.values_mut() {
            let complete = census_complete && ancestry_complete;
            unit.activity = if unit.coverage.active_members > 0 {
                AgentActivityState::ActivityObserved
            } else if complete && unit.coverage.fully_observed_members == unit.member_count {
                AgentActivityState::NoActivityObservedInWindow
            } else {
                AgentActivityState::Unknown
            };
            for measurement in [
                &mut unit.usage.cpu_cores,
                &mut unit.usage.read_bytes_per_second,
                &mut unit.usage.write_bytes_per_second,
            ] {
                if complete && measurement.observed_members == unit.member_count {
                    measurement.total = measurement.observed;
                }
            }
            if [
                &unit.usage.cpu_cores,
                &unit.usage.read_bytes_per_second,
                &unit.usage.write_bytes_per_second,
            ]
            .iter()
            .any(|measurement| measurement.observed_members > 0 && measurement.observed.is_none())
            {
                unit.unavailable
                    .push("an activity rate sum exceeded finite numeric capacity".to_string());
            }
            if !census_complete {
                unit.unavailable
                    .push("process census is incomplete".to_string());
            }
            if !ancestry_complete {
                unit.unavailable
                    .push("ambiguous or missing ancestry may omit additional members".to_string());
            }
            if unit.coverage.cpu_observed_members != unit.member_count {
                unit.unavailable.push(format!(
                    "windowed CPU unavailable for {} of {} members",
                    unit.member_count - unit.coverage.cpu_observed_members,
                    unit.member_count
                ));
            }
            if unit.coverage.storage_io_observed_members != unit.member_count {
                unit.unavailable.push(format!(
                    "windowed storage I/O unavailable for {} of {} members",
                    unit.member_count - unit.coverage.storage_io_observed_members,
                    unit.member_count
                ));
            }
            if unit.usage.rss_sum_saturated {
                unit.unavailable
                    .push("snapshot RSS sum exceeded u64 capacity".to_string());
            }
        }

        AgentActivityReport {
            attributed_processes: units.values().map(|unit| unit.member_count).sum(),
            units: units.into_values().collect(),
            input_processes: processes.len(),
            census_complete,
            excluded_duplicate_pids,
            ancestry_unavailable_processes,
            sampling_window_ms,
            limitations: vec![
                "No observed CPU/storage I/O during one short window does not establish abandonment; agents may be waiting for input, network traffic, or remote tools.".to_string(),
                "Nearest recognized agent roots own separate same-user trees; nested agent resources are not counted in their parent unit.".to_string(),
                "Snapshot RSS sums may count shared pages repeatedly and do not estimate reclaimable memory.".to_string(),
            ],
        }
    }

    /// Map a kernel observation into this scorer's configured state categories.
    pub fn snapshot_evidence(&self, proc: &ProcessRecord) -> Evidence {
        Evidence::from_snapshot_with_priors(proc, &self.priors)
    }

    /// Score one process from its evidence (usually `snapshot_evidence`, plus
    /// any deep-scan signals). `None` if the posterior cannot be computed.
    pub fn score(&self, proc: &ProcessRecord, evidence: Evidence) -> Option<ProcessScore<'_>> {
        self.score_with_desktop(proc, evidence, desktop_app_unit_for(proc))
    }

    /// Retain the exact observations this scorer would use for a process.
    /// Desktop placement is supplied explicitly; this method performs no I/O.
    pub fn recorded_observations(
        &self,
        process: &ProcessRecord,
        desktop_app: Option<String>,
    ) -> ScoringObservations {
        ScoringObservations {
            pid: process.pid.0,
            ppid: process.ppid.0,
            start_id: process.start_id.clone(),
            uid: process.uid,
            pgid: process.pgid,
            sid: process.sid,
            desktop_app,
            activity: self.activity_for(process),
            agent_activity: self.agent_activity_for(process).cloned(),
            respawn_history: self.respawn_history_for(process).cloned(),
            work: self.workload_diagnosis_for(process),
            pipe_liveness: self.pipe_liveness_for(process).cloned(),
            supervisor_restart: self.supervisor_restart_for(process).cloned(),
            supervisor_restart_unavailable: self
                .supervisor_restart_unavailable_for(process)
                .map(str::to_string),
            #[cfg(target_os = "linux")]
            provenance: self
                .provenance
                .as_ref()
                .filter(|bundle| {
                    bundle
                        .target_identities
                        .get(&process.pid.0)
                        .is_some_and(|identity| {
                            identity.start_id == process.start_id
                                && identity.uid == process.uid
                                && identity.pgid == process.pgid
                                && identity.sid == process.sid
                        })
                        && bundle.target_ppids.get(&process.pid.0) == Some(&process.ppid.0)
                })
                .map(|bundle| derive_provenance_adjustment(process.pid.0, bundle)),
        }
    }

    fn score_with_desktop(
        &self,
        proc: &ProcessRecord,
        evidence: Evidence,
        desktop_app: Option<String>,
    ) -> Option<ProcessScore<'_>> {
        self.score_recorded(
            proc,
            evidence,
            self.recorded_observations(proc, desktop_app),
        )
    }

    /// Score captured observations through the same implementation as live
    /// scoring. No collector is called and no live PID is inspected here.
    /// Priors, signatures and human verdicts come from this scorer's configuration.
    pub fn score_recorded(
        &self,
        proc: &ProcessRecord,
        mut evidence: Evidence,
        observations: ScoringObservations,
    ) -> Option<ProcessScore<'_>> {
        if !observations.matches_record(proc) {
            return None;
        }
        let pid = proc.pid.0;
        let desktop_app = observations.desktop_app;
        let activity = observations.activity;
        let mut agent_activity = observations.agent_activity;
        if let Some(unit) = &mut agent_activity {
            unit.session_window_seconds = Some(self.agent_session_window_seconds);
            if let Some(session) = &mut unit.session_activity {
                // Apply this policy to captured timestamps without consulting
                // the live clock or filesystem during replay.
                session.window_seconds = self.agent_session_window_seconds;
            }
        }
        let respawn_history = observations.respawn_history;
        let work = observations.work;
        let pipe_liveness = observations.pipe_liveness;
        if let Some(activity) = &activity {
            let (state, _) = proc.decision_state(Some(activity));
            if state != proc.state {
                evidence.state_flag = Evidence::state_flag_with_priors(state, &self.priors);
            }
            evidence.cpu = activity
                .cpu_occupancy_fraction()
                .map(|occupancy| CpuEvidence::Fraction { occupancy });
            evidence.io_active = activity.io_active;
        }
        if desktop_app.is_some() {
            // A desktop application never has a controlling terminal, so its absence
            // says nothing about abandonment.
            evidence.tty = None;
        }

        #[cfg(target_os = "linux")]
        let provenance = observations.provenance.map(|mut adjustment| {
            if desktop_app.is_some() {
                // Desktop-application ownership is the more specific ownership
                // fact, as it is for the other lineage ownership terms below.
                adjustment
                    .evidence_terms
                    .retain(|term| !term.feature.starts_with("provenance_ownership_"));
            } else {
                // A job adopted by systemd --user has PPID != 1. Its normalized
                // lineage resolves the same orphan fact as reparenting to init;
                // it must not coexist with the snapshot's orphan=false term.
                // Recognized supervision can likewise disprove a snapshot-only
                // orphan guess. Unknown lineage does not invent either verdict.
                if let Some(orphaned) = adjustment.orphaned {
                    evidence.orphan = Some(orphaned);
                }
                adjustment
                    .evidence_terms
                    .retain(|term| term.feature != "provenance_ownership_orphaned");
            }
            adjustment
        });
        let orphaned = evidence.orphan;

        let mut match_ctx = ProcessMatchContext::with_comm(&proc.comm);
        if !proc.cmd.is_empty() {
            match_ctx = match_ctx.cmdline(&proc.cmd);
        }
        let signature = self.signatures.best_match(&match_ctx);
        let signature_age_weight = signature
            .as_ref()
            .filter(|sig_match| signature_expects_abandoned(sig_match, &self.priors))
            .and_then(|sig_match| {
                normal_run_finished_by(
                    &sig_match.signature.expectations,
                    proc.elapsed.as_secs_f64(),
                )
            });
        let gated_signature =
            signature
                .as_ref()
                .zip(signature_age_weight)
                .map(|(sig_match, weight)| {
                    age_gated_signature(sig_match.signature, &self.priors, weight)
                });
        let gated_match =
            signature
                .as_ref()
                .zip(gated_signature.as_ref())
                .map(|(sig_match, gated)| SignatureMatch {
                    signature: gated,
                    level: sig_match.level,
                    score: sig_match.score,
                    details: sig_match.details.clone(),
                });
        let prior_signature = gated_match.as_ref().or(signature.as_ref());

        let learned_prior = self.decisions.learned_prior_at(
            &proc.comm,
            &proc.cmd,
            &self.priors,
            self.evaluation_time.unwrap_or_else(chrono::Utc::now),
        );
        let learned_overrides = learned_prior
            .as_ref()
            .map(|learned| DecisionStore::overrides_for(learned, &self.priors));
        let prior_context = PriorContext {
            global_priors: &self.priors,
            signature_match: prior_signature,
            category_defaults: None,
            user_overrides: learned_overrides.as_ref(),
        };

        // A human verdict on this pattern outranks the signature candidate.
        let mut fast_path_skip_reason = None;
        let signature_candidate = match prior_signature.filter(|_| learned_prior.is_none()) {
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
        // A signature match establishes a prior, not fresh activity or kernel
        // state. Always verify it through the same likelihoods as other scores.
        // Even an unchanged winning class can hide a probability change that
        // crosses an action threshold; retain the computed probabilities and
        // complete ledger rather than returning the prior-only shortcut.
        // The expectation concerns measured recent activity. A native ps
        // average covers the process lifetime and cannot establish a quiet
        // window. Match the workload by command or arguments, including
        // interpreted servers such as node running the Vite executable.
        let expectations = signature
            .as_ref()
            .filter(|matched| matched.details.process_name_matched || matched.details.args_matched)
            .map(|matched| &matched.signature.expectations);
        let window = activity
            .as_ref()
            .filter(|sample| sample.source == "procfs_window");
        let idle_cpu_normal = expectations.is_some_and(|expected| expected.idle_cpu_normal)
            && window.is_some_and(|sample| sample.cpu_ticks.is_some() && evidence.cpu.is_some());
        let idle_disk_io_normal = expectations.is_some_and(|expected| expected.idle_disk_io_normal)
            && window.is_some_and(|sample| {
                sample.io_active == Some(false)
                    && sample.io_error.is_none()
                    // Older recordings store the measured rates alone.
                    && sample.read_bytes_per_second == Some(0.0)
                    && sample.write_bytes_per_second == Some(0.0)
                    && sample.io_read_bytes.is_none_or(|bytes| bytes == 0)
                    && sample.io_write_bytes.is_none_or(|bytes| bytes == 0)
                    && sample.requested_window_ms > 0
                    && sample
                        .io_window_seconds
                        .is_some_and(|secs| secs.is_finite() && secs >= sample.requested_window_ms as f64 / 1000.0)
            });
        let resolved = resolve_priors(&prior_context);
        let mut posterior = compute_posterior_with_activity_expectations(
            &resolved.priors,
            &evidence,
            idle_cpu_normal,
            idle_disk_io_normal,
        )
        .ok()?;
        let mut ledger = EvidenceLedger::from_posterior_result(&posterior, Some(pid), None);
        let prior_source = resolved.source_info.source.to_string();
        let signature_verification = signature_candidate
            .as_ref()
            .map(|candidate| signature_verification_reason(candidate, &posterior));
        if let Some((reason, _)) = signature_verification {
            fast_path_skip_reason = Some(reason);
        }

        // Only when the signature actually set the prior (not a learned verdict, and
        // not a match too weak for its priors to apply).
        let signature_set_prior = prior_source == "signature";
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
        let provenance = provenance.inspect(|adjustment| {
            provenance::apply_adjustment(pid, adjustment, &mut posterior, &mut ledger);
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
        if idle_cpu_normal {
            ledger.top_evidence.push(
                "The matched signature expects idle CPU. Windowed CPU can support active work, but a quiet window contributes no evidence for abandonment."
                    .to_string(),
            );
        }
        if idle_disk_io_normal {
            ledger.top_evidence.push(
                "The matched signature can wait without disk I/O. Zero bytes read and written during this window do not count against useful work."
                    .to_string(),
            );
        }
        if let Some((_, explanation)) = signature_verification {
            ledger.top_evidence.push(explanation.to_string());
            ledger.why_summary.push_str(&format!(" {explanation}."));
        }

        // The age weight only shaped the prior when the signature set it.
        let signature_age_weight = signature_age_weight.filter(|_| signature_set_prior);
        if let Some(weight) = signature_age_weight {
            ledger.top_evidence.push(format!(
                "Signature prior weighted {:.2} by age: {:.0}% of normal runs have finished by now",
                weight,
                weight * 100.0
            ));
        }

        if let Some(activity) = &activity {
            let cpu = match (activity.cpu_percent, activity.cpu_window_seconds) {
                (Some(percent), Some(seconds)) => {
                    format!("CPU {percent:.2}% over {seconds:.3}s")
                }
                (Some(percent), None) => format!("native ps CPU {percent:.2}% (not windowed)"),
                _ => format!(
                    "CPU unavailable: {}",
                    activity.cpu_error.as_deref().unwrap_or("no usable sample")
                ),
            };
            let io = match (
                activity.read_bytes_per_second,
                activity.write_bytes_per_second,
                activity.io_window_seconds,
            ) {
                (Some(read), Some(written), Some(seconds)) => format!(
                    "storage I/O {read:.0} read B/s, {written:.0} write B/s over {seconds:.3}s"
                ),
                _ => format!(
                    "storage I/O unavailable: {}",
                    activity.io_error.as_deref().unwrap_or("no usable sample")
                ),
            };
            ledger.top_evidence.push(format!(
                "Activity ({}; requested {}ms): {cpu}; {io}",
                activity.source, activity.requested_window_ms
            ));
            if activity.source == "procfs_window" {
                let capacity = match (
                    activity.normalized_cpu_occupancy(),
                    activity.cpu_occupancy.as_ref(),
                ) {
                    (Some(occupancy), Some(crate::collect::CpuOccupancy::Observed {
                        effective_cores, effective_parallelism, threads, ..
                    })) => format!(
                        "CPU occupancy {:.2}% of {:.3} effective cores (min of {} threads and {:.3} observed core capacity); uniform thread affinities and quota scope were stable at both window endpoints",
                        occupancy * 100.0, effective_parallelism, threads, effective_cores
                    ),
                    (_, Some(crate::collect::CpuOccupancy::Unavailable { reason })) => {
                        format!("CPU occupancy unavailable: {reason}; raw CPU rate is display-only")
                    }
                    _ => "CPU occupancy unavailable: missing or invalid recorded capacity; raw CPU rate is display-only".to_string(),
                };
                ledger.top_evidence.push(capacity);
            }
        }

        if let Some(history) = &respawn_history {
            ledger.top_evidence.push(history.review_message.clone());
            if history.detection.is_loop {
                ledger
                    .why_summary
                    .push_str(&format!(" {}", history.review_message));
            }
        }

        if let Some(diagnosis) = &work {
            if let Some(reason) = &diagnosis.review_reason {
                ledger.top_evidence.push(reason.clone());
                ledger.why_summary.push_str(&format!(" {reason}"));
            }
        }

        if let Some(reason) = pipe_liveness
            .as_ref()
            .and_then(|pipes| pipes.observation_summary())
        {
            ledger.top_evidence.push(reason.clone());
            ledger.why_summary.push_str(&format!(" {reason}"));
        }

        if let Some(liveness) = assess_agent_liveness(
            proc,
            agent_activity.as_ref(),
            None,
            AGENT_LIVE_TERMINAL_WINDOW_SECONDS,
        ) {
            if liveness.live == Some(true) {
                ledger.top_evidence.push(liveness.reason.clone());
                ledger
                    .why_summary
                    .push_str(&format!(" {}", liveness.reason));
            }
        }

        Some(ProcessScore {
            posterior,
            ledger,
            orphaned,
            activity,
            agent_activity,
            prior_source,
            signature,
            signature_age_weight,
            learned_prior,
            respawn_history,
            work,
            pipe_liveness,
            supervisor_restart: observations.supervisor_restart,
            supervisor_restart_unavailable: observations.supervisor_restart_unavailable,
            fast_path_used: false,
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
    use std::collections::{BTreeMap, HashMap, HashSet};

    use pt_common::{
        normalize_lineage, CandidateProvenanceOutput, IdentityQuality, OwnershipState,
        ProcessIdentity, ProvenanceConfidence, ProvenanceFeatureInput, ProvenanceRedactionState,
        RawLineageEvidence, RawResourceEvidence,
    };

    use crate::action::{IdentityProvider, LiveIdentityProvider};
    use crate::collect::network_resource_collector::{
        collect_fd_ipc_resources_with_runner, collect_listener_resources_for_identity,
    };
    use crate::collect::resource_collector::{
        collect_local_resource_evidence_with_runner, resource_probe_runner,
    };
    use crate::collect::{
        collect_lineage_for_pid, detect_listener_conflicts, parse_fd, NetworkSnapshot,
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
    #[derive(Debug, Clone, Default)]
    pub struct ProvenanceInferenceBundle {
        pub resource_graph: SharedResourceGraph,
        pub lineages: HashMap<u32, RawLineageEvidence>,
        /// Lineage could not be bound to the scanned process incarnation.
        pub lineage_unavailable: HashMap<u32, String>,
        pub children: HashMap<u32, Vec<u32>>,
        /// Only requested scoring targets receive provenance adjustments. Peers
        /// observed for dependency analysis never become candidates implicitly.
        pub target_identities: HashMap<u32, ProcessIdentity>,
        /// Parent identity from the same census; reparenting invalidates cached
        /// ancestry even when process birth and job-control identity are unchanged.
        pub target_ppids: HashMap<u32, u32>,
        /// Number of distinct PIDs in the unfiltered observed population.
        pub population_count: usize,
        /// False for a partial, ambiguous or unavailable census. Default is unknown.
        pub census_complete: bool,
        /// Failed network observations are not empty resource inventories.
        pub network_errors: HashMap<u32, String>,
        /// Missing/failed probes are confidence caveats, never absent resources.
        pub resource_unavailable: HashMap<u32, Vec<String>>,
    }

    /// Provenance-derived evidence terms and confidence caveats for one process.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct ProvenanceScoreAdjustment {
        /// Normalized lineage's orphan verdict. Unknown/missing lineage is null,
        /// not evidence that a parent is alive. Required in recorded observations
        /// so an incomplete capture cannot silently acquire a negative verdict.
        #[serde(deserialize_with = "Option::deserialize")]
        pub orphaned: Option<bool>,
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

    fn process_identity(process: &ProcessRecord) -> ProcessIdentity {
        let quality = match super::agent_start_parts(process) {
            Some(("unknown" | "synthetic", _)) => IdentityQuality::NoBootId,
            Some(_) => IdentityQuality::Full,
            None => IdentityQuality::PidOnly,
        };
        ProcessIdentity::full(
            process.pid.0,
            process.start_id.clone(),
            process.uid,
            process.pgid,
            process.sid,
            quality,
        )
    }

    /// Read ancestry only while the original process identity remains valid.
    /// Resource collectors have separate validation and availability reporting.
    pub(super) fn collect_bound_lineage(
        process: &ProcessRecord,
        identity_provider: &dyn IdentityProvider,
        collect: impl FnOnce(u32) -> RawLineageEvidence,
    ) -> Result<RawLineageEvidence, &'static str> {
        let quality = match super::agent_start_parts(process) {
            Some(("unknown" | "synthetic", _)) => pt_common::IdentityQuality::NoBootId,
            Some(_) => pt_common::IdentityQuality::Full,
            None => pt_common::IdentityQuality::PidOnly,
        };
        let identity = pt_common::ProcessIdentity::full(
            process.pid.0,
            process.start_id.clone(),
            process.uid,
            process.pgid,
            process.sid,
            quality,
        );
        if !identity.can_safely_revalidate() {
            return Err("process birth identity is unavailable for lineage collection");
        }
        if !matches!(identity_provider.revalidate(&identity), Ok(true)) {
            return Err("identity changed or unavailable before lineage collection");
        }
        let lineage = collect(process.pid.0);
        if !matches!(identity_provider.revalidate(&identity), Ok(true)) {
            return Err("identity changed or unavailable during lineage collection");
        }
        if lineage.pid != process.pid.0
            || lineage.ppid != process.ppid.0
            || lineage.uid != process.uid
            || process.pgid.is_some_and(|pgid| pgid != lineage.pgid)
            || process.sid.is_some_and(|sid| sid != lineage.sid)
        {
            return Err("lineage PID, parent, owner, or session differs from scan");
        }
        Ok(lineage)
    }

    /// Bracket all provenance probes with the same complete process identity.
    /// A failed bracket discards the entire observation, including positive
    /// edges: they may belong to a replacement process and cannot be attached
    /// to the earlier scan. The caller retains the failure as missing coverage.
    pub(super) fn with_provenance_identity<T>(
        proc_root: &std::path::Path,
        boot_id: &str,
        process: &ProcessRecord,
        collect: impl FnOnce(&pt_common::ProcessIdentity) -> T,
    ) -> Result<T, String> {
        if uuid::Uuid::parse_str(boot_id).is_err() {
            return Err("provenance requires an observed boot identity".to_string());
        }
        let pid = process.pid.0;
        let process_dir = proc_root.join(pid.to_string());
        let read_identity = || {
            crate::collect::network::read_network_process_identity(&process_dir, pid)
                .map_err(|error| format!("provenance process identity unavailable: {error}"))
        };
        let before = read_identity()?;
        if process.start_id != pt_common::StartId::from_linux(boot_id, before.2, pid)
            || process.uid != before.3
        {
            return Err("provenance process identity no longer matches the scan".to_string());
        }
        let expected = pt_common::ProcessIdentity::full(
            pid,
            process.start_id.clone(),
            process.uid,
            process.pgid,
            process.sid,
            pt_common::IdentityQuality::Full,
        );
        let observed = collect(&expected);
        if read_identity()? != before {
            return Err("process identity changed during provenance collection".to_string());
        }
        Ok(observed)
    }

    /// One identity-bound observation. Keep failures alongside positive evidence;
    /// an unreadable peer cannot establish that a target has no dependents.
    pub(super) struct ProcessProvenance {
        pub identity: ProcessIdentity,
        pub lineage: Option<RawLineageEvidence>,
        pub lineage_error: Option<String>,
        pub resources: Vec<RawResourceEvidence>,
        pub network_error: Option<String>,
        pub unavailable: Vec<String>,
    }

    /// Collect lineage for targets and shared resources for every census member.
    /// Socket tables and the finite optional-filesystem budget are shared by the
    /// entire scan, including protected, young, other-user and unselected peers.
    pub fn build_provenance_bundle(
        targets: &[&ProcessRecord],
        population: &[ProcessRecord],
        census_complete: bool,
    ) -> ProvenanceInferenceBundle {
        let resource_runner = resource_probe_runner();
        let identity_provider = LiveIdentityProvider::new();
        let network_snapshot = if targets.is_empty() {
            NetworkSnapshot::default()
        } else {
            NetworkSnapshot::collect()
        };
        let proc_root = std::path::Path::new("/proc");
        let boot_id = std::fs::read_to_string(proc_root.join("sys/kernel/random/boot_id"))
            .unwrap_or_default();

        build_provenance_bundle_with(
            targets,
            population,
            census_complete,
            |process, is_target| {
                with_provenance_identity(proc_root, boot_id.trim(), process, |expected| {
                    let pid = process.pid.0;
                    let identity = process_identity(process);
                    if !identity.can_safely_revalidate() {
                        return Err(
                            "process birth identity is unavailable for provenance collection"
                                .to_string(),
                        );
                    }
                    let validate = || match identity_provider.revalidate(&identity) {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(
                            "process identity is missing or changed during provenance collection"
                                .to_string(),
                        ),
                        Err(error) => Err(format!(
                            "process identity unavailable during provenance collection: {error}"
                        )),
                    };
                    validate()?;
                    let (lineage, lineage_error) = if is_target {
                        match collect_bound_lineage(
                            process,
                            &identity_provider,
                            collect_lineage_for_pid,
                        ) {
                            Ok(lineage) => (Some(lineage), None),
                            Err(reason) => (None, Some(reason.to_string())),
                        }
                    } else {
                        (None, None)
                    };
                    let fd_info = parse_fd(pid);
                    let mut resources = collect_local_resource_evidence_with_runner(
                        pid,
                        fd_info.as_ref(),
                        &resource_runner,
                    );
                    let network_error = match collect_listener_resources_for_identity(
                        expected,
                        &network_snapshot,
                    ) {
                        Ok(observed) => {
                            resources.extend(observed.resources);
                            (!observed.unavailable.is_empty())
                                .then(|| observed.unavailable.join("; "))
                        }
                        Err(error) => Some(error.to_string()),
                    };
                    let mut ipc = collect_fd_ipc_resources_with_runner(pid, &resource_runner);
                    if fd_info.as_ref().is_none_or(|info| {
                        info.truncated || info.by_type.values().sum::<usize>() != info.count
                    }) {
                        ipc.unavailable
                            .push("file_descriptor_evidence_incomplete".to_string());
                    }
                    resources.extend(ipc.resources);
                    // Never retain resources from a replacement process, even when the
                    // first identity check or the scan's own observation was valid.
                    validate()?;
                    Ok(ProcessProvenance {
                        identity,
                        lineage,
                        lineage_error,
                        resources,
                        network_error,
                        unavailable: ipc.unavailable,
                    })
                })?
            },
        )
    }

    /// Assemble the same census graph for live collection and deterministic
    /// fixtures. The callback observes one PID once; it cannot expand candidacy.
    pub(super) fn build_provenance_bundle_with<F>(
        targets: &[&ProcessRecord],
        population: &[ProcessRecord],
        census_complete: bool,
        mut observe: F,
    ) -> ProvenanceInferenceBundle
    where
        F: FnMut(&ProcessRecord, bool) -> Result<ProcessProvenance, String>,
    {
        let mut bundle = ProvenanceInferenceBundle {
            census_complete,
            ..Default::default()
        };
        if targets.is_empty() {
            return bundle;
        }
        let mut population_by_pid = BTreeMap::new();
        for process in population {
            population_by_pid
                .entry(process.pid.0)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(process));
        }
        bundle.population_count = population_by_pid.len();

        let mut ambiguous_targets = HashSet::new();
        for target in targets {
            let pid = target.pid.0;
            let identity = process_identity(target);
            if bundle
                .target_identities
                .get(&pid)
                .is_some_and(|previous| previous != &identity)
                || bundle
                    .target_ppids
                    .get(&pid)
                    .is_some_and(|previous| *previous != target.ppid.0)
            {
                ambiguous_targets.insert(pid);
            }
            if population_by_pid
                .get(&pid)
                .copied()
                .flatten()
                .is_some_and(|process| {
                    process_identity(process) == identity && process.ppid == target.ppid
                })
            {
                bundle.target_identities.insert(pid, identity);
                bundle.target_ppids.insert(pid, target.ppid.0);
            } else {
                bundle.census_complete = false;
                ambiguous_targets.insert(pid);
            }
        }
        for pid in ambiguous_targets {
            bundle.target_identities.remove(&pid);
            bundle.target_ppids.remove(&pid);
            bundle.resource_unavailable.insert(
                pid,
                vec![
                    "requested target identity is absent or ambiguous in the process census"
                        .to_string(),
                ],
            );
        }

        let mut per_process_resources = Vec::new();
        let mut all_resources = Vec::new();
        // Targets consume optional probe budgets first. All peers still receive
        // their own observation and any exhausted budget is retained as unknown.
        let ordered = population_by_pid
            .iter()
            .filter(|(pid, _)| bundle.target_identities.contains_key(*pid))
            .chain(
                population_by_pid
                    .iter()
                    .filter(|(pid, _)| !bundle.target_identities.contains_key(*pid)),
            )
            .map(|(&pid, &process)| (pid, process))
            .collect::<Vec<_>>();
        for (pid, process) in ordered {
            let Some(process) = process else {
                bundle.census_complete = false;
                bundle.resource_unavailable.insert(
                    pid,
                    vec![
                        "duplicate PID in the process census; dependency identity is ambiguous"
                            .to_string(),
                    ],
                );
                continue;
            };
            if process.pid != process.ppid {
                bundle.children.entry(process.ppid.0).or_default().push(pid);
            } else {
                bundle.census_complete = false;
            }
            let is_target = bundle.target_identities.contains_key(&pid);
            let observed = observe(process, is_target).and_then(|mut observed| {
                if observed.identity != process_identity(process)
                    || observed
                        .resources
                        .iter()
                        .any(|resource| resource.owner_pid != pid)
                {
                    Err(
                        "provenance observation belongs to a different process identity"
                            .to_string(),
                    )
                } else {
                    if observed.lineage.as_ref().is_some_and(|lineage| {
                        lineage.pid != pid
                            || lineage.ppid != process.ppid.0
                            || lineage.uid != process.uid
                            || process.pgid.is_some_and(|pgid| pgid != lineage.pgid)
                            || process.sid.is_some_and(|sid| sid != lineage.sid)
                    }) {
                        observed.lineage = None;
                        observed.lineage_error = Some(
                            "lineage PID, parent, owner, or session differs from scan".to_string(),
                        );
                    }
                    Ok(observed)
                }
            });
            match observed {
                Ok(observed) => {
                    if is_target {
                        match (observed.lineage, observed.lineage_error) {
                            (_, Some(reason)) => {
                                bundle.lineage_unavailable.insert(pid, reason);
                            }
                            (Some(lineage), None) => {
                                bundle.lineages.insert(pid, lineage);
                            }
                            (None, None) => {
                                bundle
                                    .lineage_unavailable
                                    .insert(pid, "lineage observation unavailable".to_string());
                            }
                        }
                    }
                    if let Some(reason) = observed.network_error {
                        bundle.network_errors.insert(pid, reason);
                    }
                    if !observed.unavailable.is_empty() {
                        bundle
                            .resource_unavailable
                            .entry(pid)
                            .or_default()
                            .extend(observed.unavailable);
                    }
                    all_resources.extend(observed.resources.iter().cloned());
                    per_process_resources.push((pid, observed.resources));
                }
                Err(reason) => {
                    if is_target {
                        bundle.lineage_unavailable.insert(pid, reason.clone());
                    }
                    bundle.network_errors.insert(pid, reason.clone());
                    bundle
                        .resource_unavailable
                        .entry(pid)
                        .or_default()
                        .push(reason);
                }
            }
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

        bundle.resource_graph = SharedResourceGraph::from_evidence(&per_process_resources);
        bundle
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
        let orphaned = normalized_lineage
            .as_ref()
            .and_then(|lineage| match &lineage.ownership {
                OwnershipState::Unknown => None,
                OwnershipState::Orphaned => Some(true),
                _ => Some(false),
            });
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
        let mut resource_score = if bundle.network_errors.contains_key(&pid) {
            // Even an apparently empty graph may hide every network dependency
            // when this process's namespace, descriptors or tables were unreadable.
            0.0
        } else if resolved_resources + unresolved_resources == 0 {
            0.7
        } else {
            resolved_resources as f64 / (resolved_resources + unresolved_resources) as f64
        };
        let mut confidence_notes = Vec::new();
        let mut confidence_penalty_steps = 0usize;
        if !bundle.census_complete {
            resource_score = 0.0;
            confidence_notes.push(
                "process census is incomplete or ambiguous; unobserved dependents may exist"
                    .to_string(),
            );
            confidence_penalty_steps += 1;
        }
        // Any participant with missing IPC observations can hide a shared edge.
        let resource_collection_complete = bundle
            .resource_unavailable
            .values()
            .all(|notes| notes.is_empty());

        if let Some(unavailable) = bundle
            .resource_unavailable
            .get(&pid)
            .filter(|notes| !notes.is_empty())
        {
            resource_score = resource_score.min(0.5);
            confidence_notes.extend(
                unavailable
                    .iter()
                    .map(|reason| format!("resource collection incomplete: {reason}")),
            );
            confidence_penalty_steps += 1;
        } else if !resource_collection_complete {
            resource_score = resource_score.min(0.5);
            let unavailable_peers = bundle
                .resource_unavailable
                .values()
                .filter(|notes| !notes.is_empty())
                .count();
            confidence_notes.push(format!(
                "resource collection incomplete: {unavailable_peers} other process observation(s) unavailable"
            ));
            confidence_penalty_steps += 1;
        }
        // Missing peers can hide shared resources even when this target was
        // observed completely. Retain the actual scan coverage in confidence.
        let observed_population = bundle.population_count.max(bundle.lineages.len());
        let network_coverage = if bundle.network_errors.is_empty() {
            1.0
        } else if observed_population == 0 {
            0.0
        } else {
            observed_population.saturating_sub(bundle.network_errors.len()) as f64
                / observed_population as f64
        };
        let resource_score = resource_score * network_coverage;
        let mut evidence_completeness = ((lineage_score + resource_score) / 2.0).clamp(0.0, 1.0);

        if let Some(reason) = bundle.network_errors.get(&pid) {
            confidence_notes.push(format!(
                "network resource evidence unavailable for PID {pid}: {reason}"
            ));
            confidence_penalty_steps += 1;
        } else if !bundle.network_errors.is_empty() {
            confidence_notes.push(format!(
                "network resource graph is incomplete: {} other process observation(s) unavailable",
                bundle.network_errors.len()
            ));
            confidence_penalty_steps += 1;
        }
        if lineage.is_none() {
            confidence_notes.push(
                bundle
                    .lineage_unavailable
                    .get(&pid)
                    .map(|reason| format!("lineage unavailable: {reason}"))
                    .unwrap_or_else(|| "missing lineage provenance".to_string()),
            );
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
            RiskLevel::Low
                if blast_radius.total_affected == 0
                    && child_pids.is_empty()
                    && bundle.census_complete
                    && bundle.network_errors.is_empty()
                    && resource_collection_complete
                    && unresolved_resources == 0 =>
            {
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
            orphaned,
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

    #[test]
    fn snapshot_scores_follow_named_kernel_states_across_model_orders_and_encodings() {
        let reference = scorer(SignatureDatabase::new());
        let mut reordered = reference.clone();
        let flags = reordered.priors.state_flags.as_mut().unwrap();
        flags.flag_names = ["X", "Z", "R", "I", "D", "T", "S"]
            .map(str::to_string)
            .to_vec();
        let order = [6, 3, 0, 5, 2, 4, 1];
        for class in [
            &mut flags.useful,
            &mut flags.useful_bad,
            &mut flags.abandoned,
            &mut flags.zombie,
        ] {
            let alpha = &mut class.as_mut().unwrap().alpha;
            *alpha = order.map(|i| alpha[i]).to_vec();
        }

        let mut process = record(4212, "worker", "worker", Duration::from_secs(60));
        for (state, expected_index) in [
            (ProcessState::Running, 2),
            (ProcessState::Sleeping, 6),
            (ProcessState::DiskSleep, 4),
            (ProcessState::Zombie, 1),
            (ProcessState::Stopped, 5),
            (ProcessState::Idle, 3),
            (ProcessState::Dead, 0),
        ] {
            process.state = state;
            let evidence = reordered.snapshot_evidence(&process);
            assert_eq!(evidence.state_flag, Some(expected_index));
            let observed = reference.recorded_observations(&process, None);
            let expected = reference
                .score_recorded(
                    &process,
                    reference.snapshot_evidence(&process),
                    observed.clone(),
                )
                .unwrap();
            let actual = reordered
                .score_recorded(&process, evidence, observed)
                .unwrap();
            let left = actual.posterior.posterior;
            let right = expected.posterior.posterior;
            for (a, b) in [
                (left.useful, right.useful),
                (left.useful_bad, right.useful_bad),
                (left.abandoned, right.abandoned),
                (left.zombie, right.zombie),
            ] {
                assert!((a - b).abs() < 1e-12, "{state:?}: {left:?} != {right:?}");
            }
            assert_eq!(actual.ledger.classification, expected.ledger.classification);
            let explanation =
                crate::inference::build_process_explanation(&process, &reordered.priors);
            assert_eq!(explanation["evidence"]["state_flag"], expected_index);
            assert_eq!(
                explanation["classification"],
                actual.ledger.classification.label()
            );
        }
    }

    #[test]
    fn sampled_d_state_uses_the_active_model_for_live_and_replayed_scores() {
        use crate::collect::{LeaderWait, ProcessPressureActivity, WaitClass};

        // D is deliberately away from the built-in index. A model may omit
        // D, or represent it twice in a way this observation cannot resolve.
        for (names, expected_index) in [
            (["R", "S", "T", "Z", "I", "X", "D"], Some(6)),
            (["R", "S", "T", "Z", "I", "X", "other"], None),
            (["R", "S", "T", "Z", "I", "D", "DiskSleep"], None),
        ] {
            let mut model = scorer(SignatureDatabase::new());
            model.priors.state_flags.as_mut().unwrap().flag_names =
                names.map(str::to_string).to_vec();
            let mut process = record(4212, "worker", "worker", Duration::from_secs(60));
            let mut activity = agent_activity_sample(&process, 0.0, 0.0);
            activity.pressure = Some(ProcessPressureActivity {
                leader_wait: Some(LeaderWait {
                    state: ProcessState::DiskSleep,
                    class: WaitClass::Uninterruptible,
                    wchan: Some("io_schedule".into()),
                }),
                ..Default::default()
            });
            model.activity_window = Some(Duration::from_millis(500));
            model.activity.insert(process.pid.0, activity);
            for quick in [
                ProcessState::Running, ProcessState::Sleeping, ProcessState::DiskSleep,
                ProcessState::Stopped, ProcessState::Idle, ProcessState::Unknown,
                ProcessState::Zombie, ProcessState::Dead,
            ] {
                process.state = quick;
                let evidence = model.snapshot_evidence(&process);
                let captured = model.recorded_observations(&process, None);
                let mut expected_process = process.clone();
                if !matches!(quick, ProcessState::Zombie | ProcessState::Dead) {
                    expected_process.state = ProcessState::DiskSleep;
                    assert_eq!(model.snapshot_evidence(&expected_process).state_flag, expected_index);
                }
                let mut baseline = captured.clone();
                baseline.activity.as_mut().unwrap().pressure = None;
                let expected = model
                    .score_recorded(&expected_process, model.snapshot_evidence(&expected_process), baseline)
                    .unwrap();
                let live = model.score_with_desktop(&process, evidence.clone(), None).unwrap();
                let replayed = model.score_recorded(&process, evidence, captured).unwrap();
                assert_eq!(live.posterior.evidence_terms, expected.posterior.evidence_terms, "{quick:?}");
                assert_eq!(replayed.posterior.evidence_terms, expected.posterior.evidence_terms, "{quick:?}");
            }
        }
    }

    #[test]
    fn unmodeled_ambiguous_and_unknown_kernel_states_leave_other_evidence_intact() {
        let mut custom = scorer(SignatureDatabase::new());
        let flags = custom.priors.state_flags.as_mut().unwrap();
        flags.flag_names = ["Zombie", "T", "t"].map(str::to_string).to_vec();
        for class in [
            &mut flags.useful,
            &mut flags.useful_bad,
            &mut flags.abandoned,
            &mut flags.zombie,
        ] {
            class.as_mut().unwrap().alpha.truncate(3);
        }
        let mut process = record(4212, "worker", "worker", Duration::from_secs(60));
        for state in [
            ProcessState::Sleeping,
            ProcessState::Stopped,
            ProcessState::Unknown,
        ] {
            process.state = state;
            let evidence = custom.snapshot_evidence(&process);
            assert_eq!(evidence.state_flag, None);
            let observed = custom.recorded_observations(&process, None);
            let score = custom.score_recorded(&process, evidence, observed).unwrap();
            let terms = &score.posterior.evidence_terms;
            assert!(terms.iter().any(|term| term.feature == "runtime"));
            assert!(terms.iter().all(|term| term.feature != "state_flag"));
        }
    }

    fn agent_record(pid: u32, parent: u32, command: &str) -> ProcessRecord {
        let mut process = record(
            pid,
            command.split_whitespace().next().unwrap(),
            command,
            FOUR_DAYS,
        );
        process.ppid = ProcessId(parent);
        process.rss_bytes = u64::from(pid) * 1024;
        process
    }

    fn agent_activity_sample(process: &ProcessRecord, cpu: f64, read: f64) -> ProcessActivity {
        ProcessActivity {
            pid: process.pid.0,
            start_id: process.start_id.clone(),
            uid: process.uid,
            source: "procfs_window".to_string(),
            requested_window_ms: 500,
            cpu_percent: Some(cpu),
            cpu_ticks: Some(if cpu > 0.0 { 1 } else { 0 }),
            cpu_window_seconds: Some(0.5),
            cpu_occupancy: None,
            io_window_seconds: Some(0.5),
            io_read_bytes: None,
            io_write_bytes: None,
            read_bytes_per_second: Some(read),
            write_bytes_per_second: Some(0.0),
            io_active: Some(read > 0.0),
            cpu_error: None,
            io_error: None,
            pressure: None,
        }
    }

    fn agent_activity_scorer(processes: &[ProcessRecord]) -> Scorer {
        // These CPU/I/O fixtures have synthetic PIDs, not live transcripts.
        let mut result = scorer(SignatureDatabase::with_defaults()).with_agent_session_window(0);
        result.activity_window = Some(Duration::from_millis(500));
        result.activity = processes
            .iter()
            .map(|process| (process.pid.0, agent_activity_sample(process, 0.0, 0.0)))
            .collect();
        result
    }

    fn session_activity_sample(
        process: &ProcessRecord,
        age_seconds: i64,
        window_seconds: u64,
    ) -> crate::collect::protected::AgentSessionActivity {
        use sha2::Digest;
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-01-27T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        crate::collect::protected::AgentSessionActivity {
            identity: pt_common::ProcessIdentity::full(
                process.pid.0,
                process.start_id.clone(),
                process.uid,
                process.pgid,
                process.sid,
                pt_common::IdentityQuality::Full,
            ),
            ppid: process.ppid.0,
            command_sha256: hex::encode(sha2::Sha256::digest(process.cmd.as_bytes())),
            source: Some(
                crate::collect::protected::AgentSessionActivitySource::HeldWritableDescriptor,
            ),
            identity_verified: true,
            observed_at,
            window_seconds,
            transcript_count: 1,
            latest_modified_at: Some(observed_at - chrono::Duration::seconds(age_seconds)),
            unavailable: Vec::new(),
        }
    }

    #[test]
    fn policy_construction_and_refresh_apply_session_retention_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::config::load_config(&crate::config::ConfigOptions {
            config_dir: Some(directory.path().to_path_buf()),
            ..Default::default()
        })
        .unwrap();
        let process = agent_record(100, 1, "codex exec review");
        let capture = scorer(SignatureDatabase::with_defaults());
        let mut observations = capture.recorded_observations(&process, None);
        let mut unit = capture
            .agent_activity_report(std::slice::from_ref(&process), true)
            .units
            .remove(0);
        unit.session_activity = Some(session_activity_sample(&process, 600, 1800));
        observations.agent_activity = Some(unit);

        for (window, expected_live) in [
            (0, None),
            (600, None),
            (601, Some(true)),
            (7200, Some(true)),
        ] {
            config.policy.guardrails.agent_session_window_seconds = window;
            config.policy.signature_fast_path.enabled = false;
            let interactive = Scorer::from_policy(
                config.priors.clone(),
                DecisionStore::default(),
                SignatureDatabase::with_defaults(),
                &config.policy,
            );
            let (configured, warnings) = Scorer::from_config(&config);
            assert!(warnings.is_empty(), "{warnings:?}");

            for candidate in [interactive, configured] {
                // The TUI clones its configured scorer on refresh, then replaces
                // only the latest explicitly learned verdicts.
                let mut refreshed = candidate.clone();
                refreshed.decisions = DecisionStore::default();
                for current in [&candidate, &refreshed] {
                    assert!(!current.fast_path.enabled);
                    let score = current
                        .score_recorded(
                            &process,
                            Evidence::from_snapshot(&process),
                            observations.clone(),
                        )
                        .unwrap();
                    let live =
                        assess_agent_liveness(&process, score.agent_activity.as_ref(), None, 1800)
                            .unwrap();
                    assert_eq!(live.live, expected_live, "policy lookback {window}");
                    assert_eq!(
                        live.sources
                            .contains(&AgentLivenessSource::RecentSessionTranscriptActivity),
                        expected_live == Some(true),
                    );
                    assert_eq!(
                        score
                            .ledger
                            .why_summary
                            .contains("an open session transcript was recently modified"),
                        expected_live == Some(true),
                    );
                }
            }
        }
    }

    #[test]
    fn session_liveness_survives_zero_cpu_window_and_frozen_replay_without_changing_posterior() {
        let processes = [
            agent_record(100, 1, "codex exec review"),
            agent_record(101, 100, "cargo build"),
        ];
        let process = &processes[0];
        let mut measured = scorer(SignatureDatabase::with_defaults());
        assert_eq!(
            measured.agent_session_window_seconds,
            crate::config::policy::DEFAULT_AGENT_SESSION_WINDOW_SECONDS
        );
        measured.collect_activity(&[], Duration::ZERO);
        let before = measured
            .score_with_desktop(process, Evidence::from_snapshot(process), None)
            .unwrap()
            .posterior
            .posterior;
        let mut unit = measured
            .agent_activity_report(&processes, true)
            .units
            .remove(0);
        unit.session_activity = Some(session_activity_sample(process, 600, 1800));
        measured.agent_activity.insert(process.pid.0, unit);
        let score = measured
            .score_with_desktop(process, Evidence::from_snapshot(process), None)
            .unwrap();
        let live =
            assess_agent_liveness(process, score.agent_activity.as_ref(), None, 1800).unwrap();
        assert_eq!(live.live, Some(true));
        assert_eq!(live.requested_activity_window_ms, None);
        assert_eq!(
            live.sources,
            vec![AgentLivenessSource::RecentSessionTranscriptActivity]
        );
        assert!(score.ledger.why_summary.contains(&live.reason));
        assert_eq!(
            serde_json::to_value(score.posterior.posterior).unwrap(),
            serde_json::to_value(before).unwrap()
        );
        assert!(measured.agent_activity_for(&processes[1]).is_none());
        assert!(agent_liveness(&processes[1], score.agent_activity.as_ref()).is_none());

        let encoded = serde_json::to_value(measured.recorded_observations(process, None)).unwrap();
        for (window_seconds, expected_live) in [(1800, Some(true)), (600, None), (0, None)] {
            let replay = scorer(SignatureDatabase::with_defaults())
                .with_agent_session_window(window_seconds)
                .with_evaluation_time(
                    chrono::DateTime::parse_from_rfc3339("2040-01-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                );
            let score = replay
                .score_recorded(
                    process,
                    Evidence::from_snapshot(process),
                    serde_json::from_value(encoded.clone()).unwrap(),
                )
                .unwrap();
            let live =
                assess_agent_liveness(process, score.agent_activity.as_ref(), None, 1800).unwrap();
            assert_eq!(
                live.live, expected_live,
                "session lookback {window_seconds}"
            );
            assert_eq!(
                score
                    .agent_activity
                    .as_ref()
                    .unwrap()
                    .session_activity
                    .as_ref()
                    .unwrap()
                    .window_seconds,
                window_seconds
            );
        }
        let mut legacy = encoded;
        let legacy_unit = legacy["agent_activity"].as_object_mut().unwrap();
        legacy_unit.remove("session_activity");
        legacy_unit.remove("session_window_seconds");
        let legacy: ScoringObservations = serde_json::from_value(legacy).unwrap();
        assert!(legacy.agent_activity.unwrap().session_activity.is_none());

        measured.collect_activity(&[], Duration::ZERO);
        assert!(measured.agent_activity_for(process).is_none());
    }

    #[test]
    fn explicit_session_activity_keeps_its_source_through_replay() {
        use crate::collect::protected::{AgentSessionActivity, AgentSessionActivitySource};

        let process = agent_record(100, 1, "pi --session /workspace/selected.jsonl");
        let measured = scorer(SignatureDatabase::with_defaults());
        let mut session = session_activity_sample(&process, 600, 1800);
        session.source = Some(AgentSessionActivitySource::ExplicitSessionArgument);
        let mut unit = measured
            .agent_activity_report(std::slice::from_ref(&process), true)
            .units
            .remove(0);
        unit.session_activity = Some(session.clone());
        let mut captured = measured.recorded_observations(&process, None);
        captured.agent_activity = Some(unit);
        let encoded = serde_json::to_string(&captured).unwrap();
        assert!(encoded.contains("explicit_session_argument"));

        let replay = scorer(SignatureDatabase::with_defaults()).with_evaluation_time(
            chrono::DateTime::parse_from_rfc3339("2040-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let score = replay
            .score_recorded(
                &process,
                Evidence::from_snapshot(&process),
                serde_json::from_str(&encoded).unwrap(),
            )
            .unwrap();
        let live =
            assess_agent_liveness(&process, score.agent_activity.as_ref(), None, 1800).unwrap();
        assert_eq!(live.live, Some(true));
        assert_eq!(live.requested_activity_window_ms, None);
        assert!(live.reason.contains("startup-selected session transcript"));
        assert!(!live.reason.contains("open session transcript"));
        assert!(score.ledger.why_summary.contains(&live.reason));

        // Older capture digests must not change when a newly optional source
        // was absent. Absence continues to describe the original FD-only data.
        let mut legacy = serde_json::to_value(&session).unwrap();
        legacy.as_object_mut().unwrap().remove("source");
        let decoded: AgentSessionActivity = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(decoded.source, None);
        assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    }

    #[test]
    fn session_liveness_boundary_unavailable_and_wrong_identity_remain_unknown() {
        let process = agent_record(100, 1, "claude --continue");
        let measured = scorer(SignatureDatabase::with_defaults());
        let mut unit = measured
            .agent_activity_report(std::slice::from_ref(&process), true)
            .units
            .remove(0);
        for (age, window, expected) in [
            (1799, 1800, Some(true)),
            (1800, 1800, None),
            (3600, 1800, None),
            (-1, 1800, None),
            (0, 0, None),
        ] {
            unit.session_window_seconds = Some(window);
            unit.session_activity = Some(session_activity_sample(&process, age, window));
            assert_eq!(
                assess_agent_liveness(&process, Some(&unit), None, 1800)
                    .unwrap()
                    .live,
                expected,
                "age {age}, lookback {window}"
            );
        }
        unit.session_window_seconds = Some(1800);
        unit.session_activity = Some(session_activity_sample(&process, 1, 1800));
        for variant in 0..8 {
            let mut changed = process.clone();
            match variant {
                0 => changed.start_id = StartId::from_linux("test-boot-id", 999, 100),
                1 => changed.uid += 1,
                2 => changed.pgid = Some(999),
                3 => changed.sid = Some(999),
                4 => changed.ppid = ProcessId(999),
                5 => changed.cmd = "claude --resume another".to_string(),
                6 => changed.state = ProcessState::Zombie,
                _ => changed.state = ProcessState::Dead,
            }
            assert_eq!(
                assess_agent_liveness(&changed, Some(&unit), None, 1800)
                    .unwrap()
                    .live,
                None,
                "identity variant {variant}"
            );
        }
        for variant in 0..4 {
            let mut unavailable = session_activity_sample(&process, 1, 1800);
            match variant {
                0 => unavailable.identity_verified = false,
                1 => unavailable.transcript_count = 0,
                2 => unavailable.latest_modified_at = None,
                _ => unavailable.identity.quality = pt_common::IdentityQuality::PidOnly,
            }
            unit.session_activity = Some(unavailable);
            assert_eq!(
                assess_agent_liveness(&process, Some(&unit), None, 1800)
                    .unwrap()
                    .live,
                None,
                "unavailable variant {variant}"
            );
        }
    }

    #[test]
    fn session_liveness_never_negates_cpu_or_terminal_and_policy_zero_is_independent() {
        let mut process = agent_record(100, 1, "codex");
        process.tty = Some("pts/7".to_string());
        let mut measured = agent_activity_scorer(std::slice::from_ref(&process));
        measured
            .activity
            .insert(100, agent_activity_sample(&process, 100.0, 0.0));
        let mut unit = measured
            .agent_activity_report(std::slice::from_ref(&process), true)
            .units
            .remove(0);
        for window in [0, 1800] {
            unit.session_window_seconds = Some(window);
            unit.session_activity = Some(session_activity_sample(&process, 3600, window));
            let live = assess_agent_liveness(&process, Some(&unit), None, 1800).unwrap();
            assert_eq!(live.live, Some(true));
            assert_eq!(live.sources, vec![AgentLivenessSource::ProcessActivity]);
        }
        for state in [
            ProcessState::Zombie,
            ProcessState::Dead,
            ProcessState::Unknown,
        ] {
            let mut invalid = process.clone();
            invalid.state = state;
            let live = assess_agent_liveness(&invalid, Some(&unit), Some(1), 1800).unwrap();
            assert_ne!(live.live, Some(true));
            assert!(live.sources.is_empty());
        }
        unit.sampling_window_ms = None;
        let live = assess_agent_liveness(&process, Some(&unit), Some(1), 1800).unwrap();
        assert_eq!(
            live.sources,
            vec![AgentLivenessSource::RecentTerminalActivity]
        );

        let mut disabled = measured.with_agent_session_window(0);
        let report = disabled.prepare_agent_activity(std::slice::from_ref(&process), true);
        let session = report.units[0].session_activity.as_ref().unwrap();
        assert_eq!(session.recently_modified(), None);
        assert!(session
            .unavailable
            .iter()
            .any(|reason| reason.contains("disabled")));
        assert_eq!(
            assess_agent_liveness(&process, Some(&report.units[0]), None, 1800)
                .unwrap()
                .sources,
            vec![AgentLivenessSource::ProcessActivity]
        );
    }

    #[test]
    fn enabled_missing_transcript_keeps_overall_liveness_unknown_after_quiet_cpu_sample() {
        let process = agent_record(100, 1, "claude");
        let measured = agent_activity_scorer(std::slice::from_ref(&process));
        let mut unit = measured
            .agent_activity_report(std::slice::from_ref(&process), true)
            .units
            .remove(0);
        assert_eq!(
            unit.activity,
            AgentActivityState::NoActivityObservedInWindow
        );
        unit.session_window_seconds = Some(1800);
        let assess = |unit: &AgentActivityUnit| {
            assess_agent_liveness(&process, Some(unit), None, 1800).unwrap()
        };
        assert_eq!(assess(&unit).live, None);
        let mut unavailable = session_activity_sample(&process, 0, 1800);
        unavailable.identity_verified = false;
        unavailable.unavailable = vec!["descriptor evidence could not be read".to_string()];
        unit.session_activity = Some(unavailable);
        assert_eq!(assess(&unit).status, AgentLivenessState::Unknown);
        assert_eq!(
            unit.activity,
            AgentActivityState::NoActivityObservedInWindow
        );

        unit.session_window_seconds = Some(0);
        assert_eq!(assess(&unit).live, Some(false));
        unit.session_window_seconds = Some(1800);
        unit.session_activity = Some(session_activity_sample(&process, 1800, 1800));
        assert_eq!(assess(&unit).live, Some(false));
        unit.session_activity
            .as_mut()
            .unwrap()
            .unavailable
            .push("another task could not be inspected".to_string());
        assert_eq!(assess(&unit).live, None);

        // A disabled policy also applies to captures predating session metadata.
        unit.session_activity = None;
        unit.session_window_seconds = None;
        let mut captured = measured.recorded_observations(&process, None);
        captured.agent_activity = Some(unit);
        let disabled = measured.with_agent_session_window(0);
        let score = disabled
            .score_recorded(&process, Evidence::from_snapshot(&process), captured)
            .unwrap();
        assert_eq!(
            assess(score.agent_activity.as_ref().unwrap()).live,
            Some(false)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_pi_session_keeps_closed_transcript_and_replays_after_exit() {
        use crate::collect::protected::AgentSessionActivitySource;
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Child, Command, ExitStatus, Stdio};
        use std::time::Instant;

        let cached_lookup = crate::collect::protected::cached_session_lookup_available_for_test();

        struct OwnedChild {
            child: Child,
            reaped: bool,
        }
        impl OwnedChild {
            fn poll(&mut self) -> Option<ExitStatus> {
                let status = self.child.try_wait().unwrap();
                self.reaped |= status.is_some();
                status
            }

            fn wait(&mut self, duration: Duration, label: &str) -> ExitStatus {
                let deadline = Instant::now() + duration;
                loop {
                    if let Some(status) = self.poll() {
                        return status;
                    }
                    assert!(Instant::now() < deadline, "{label} timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if !self.reaped {
                    // SAFETY: each command created its own process group.
                    // The unreaped leader pins this PID until wait, so group
                    // cleanup cannot target a reused unrelated process group.
                    unsafe {
                        libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                    }
                    let _ = self.child.wait();
                }
            }
        }

        // A native fixture is necessary: an interpreter or sleep process does
        // not accept Pi's actual argv. Compile this small owned helper with the
        // C toolchain already required by the Rust workspace's native crates.
        const HELPER: &str = r#"#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--session") != 0) return 2;
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 3;
    if (write(fd, "{}\n", 3) != 3 || close(fd) != 0) return 4;
    if (write(STDOUT_FILENO, "R", 1) != 1) return 5;
    char byte;
    while (read(STDIN_FILENO, &byte, 1) < 0 && errno == EINTR) {}
    return 0;
}
"#;
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("pi-session-fixture");
        let mut compiler = OwnedChild {
            child: Command::new("cc")
                .args(["-x", "c", "-std=gnu99", "-O0", "-o"])
                .arg(&helper)
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .process_group(0)
                .spawn()
                .expect("native Pi session fixture requires a working C compiler (cc)"),
            reaped: false,
        };
        compiler
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(HELPER.as_bytes())
            .unwrap();
        assert!(
            compiler
                .wait(Duration::from_secs(10), "native fixture compilation")
                .success(),
            "native Pi session fixture compilation failed; a working C compiler (cc) is required"
        );

        let transcript = directory.path().join("selected.jsonl");
        let mut child = OwnedChild {
            child: Command::new(&helper)
                .arg0("pi")
                .arg("--session")
                .arg(&transcript)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap(),
            reaped: false,
        };
        let mut ready = child.child.stdout.take().unwrap();
        // SAFETY: ready owns this descriptor; both fcntl operations use valid
        // integer flags and do not extend its lifetime beyond the pipe handle.
        let flags = unsafe { libc::fcntl(ready.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(ready.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < deadline,
                "native fixture readiness timed out"
            );
            let mut marker = [0_u8; 1];
            match ready.read(&mut marker) {
                Ok(1) => {
                    assert_eq!(marker, [b'R']);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => panic!("native fixture readiness failed: {result:?}"),
            }
            assert!(
                child.poll().is_none(),
                "native fixture exited before readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let scan = crate::collect::quick_scan(&crate::collect::QuickScanOptions {
            pids: vec![child.child.id()],
            timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        })
        .unwrap();
        let process = scan.processes.into_iter().next().unwrap();
        assert_eq!(
            process.cmd,
            format!("pi --session {}", transcript.display())
        );
        for descriptor in std::fs::read_dir(format!("/proc/{}/fd", process.pid.0)).unwrap() {
            let target = std::fs::read_link(descriptor.unwrap().path()).unwrap();
            assert_ne!(
                target, transcript,
                "fixture must close the transcript before collection"
            );
        }

        let mut measured = scorer(SignatureDatabase::with_defaults());
        measured.collect_activity(&[&process], Duration::ZERO);
        measured.prepare_agent_activity(std::slice::from_ref(&process), false);
        let score = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        let live =
            assess_agent_liveness(&process, score.agent_activity.as_ref(), None, 1800).unwrap();
        let assert_liveness = |live: &AgentLiveness| {
            assert_eq!(live.requested_activity_window_ms, None);
            if cached_lookup {
                assert_eq!(live.live, Some(true), "{live:?}");
                assert_eq!(
                    live.sources,
                    [AgentLivenessSource::RecentSessionTranscriptActivity]
                );
                assert!(live.reason.contains("startup-selected session transcript"));
            } else {
                assert_eq!(live.live, None, "{live:?}");
                assert_eq!(live.status, AgentLivenessState::Unknown);
                assert!(live.sources.is_empty());
                assert!(!live.reason.starts_with("Keep:"));
                assert!(live
                    .unavailable
                    .iter()
                    .any(|reason| reason == "session_explicit_path_cached_lookup_unavailable"));
            }
        };
        assert_liveness(&live);
        let session = score
            .agent_activity
            .as_ref()
            .unwrap()
            .session_activity
            .as_ref()
            .unwrap();
        assert_eq!(
            session.source,
            Some(AgentSessionActivitySource::ExplicitSessionArgument)
        );
        assert_eq!(session.identity_verified, cached_lookup);
        assert_eq!(session.transcript_count, usize::from(cached_lookup));
        let captured =
            serde_json::to_string(&measured.recorded_observations(&process, None)).unwrap();
        assert!(!captured.contains(transcript.to_str().unwrap()));
        // Releasing the owned input pipe lets the helper exit normally. Replay
        // must continue to use the captured observation after its PID is gone.
        drop(child.child.stdin.take());
        assert!(child
            .wait(Duration::from_secs(5), "native fixture shutdown")
            .success());
        let replay_scorer = scorer(SignatureDatabase::with_defaults());
        let replay = replay_scorer
            .score_recorded(
                &process,
                Evidence::from_snapshot(&process),
                serde_json::from_str(&captured).unwrap(),
            )
            .unwrap();
        let replay_live =
            assess_agent_liveness(&process, replay.agent_activity.as_ref(), None, 1800).unwrap();
        assert_liveness(&replay_live);
        assert_eq!(
            replay
                .ledger
                .why_summary
                .contains("startup-selected session transcript"),
            cached_lookup
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_session_transcript_keeps_owned_agent_with_cpu_sampling_disabled() {
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let transcript = directory.path().join(
            "sessions/2026/01/27/rollout-2026-01-27T12-30-00-019c017a-84b0-7710-8bba-47ea1175fee3.jsonl",
        );
        std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        let child = OwnedChild(
            std::process::Command::new("bash")
                .arg("-c")
                .arg("exec 3>>\"$1\"; printf '{}\\n' >&3; exec -a codex sleep 60")
                .arg("session-transcript-test")
                .arg(&transcript)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let process = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "owned agent did not become ready"
            );
            let scan = crate::collect::quick_scan(&crate::collect::QuickScanOptions {
                pids: vec![child.0.id()],
                timeout: Some(Duration::from_millis(500)),
                ..Default::default()
            })
            .unwrap();
            if let Some(process) = scan
                .processes
                .into_iter()
                .find(|process| process.comm == "sleep" && process.cmd == "codex 60")
            {
                break process;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut measured = scorer(SignatureDatabase::with_defaults());
        measured.collect_activity(&[&process], Duration::ZERO);
        measured.prepare_agent_activity(std::slice::from_ref(&process), false);
        let score = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        let live =
            assess_agent_liveness(&process, score.agent_activity.as_ref(), None, 1800).unwrap();
        assert_eq!(live.live, Some(true), "{live:?}");
        assert_eq!(live.requested_activity_window_ms, None);
        assert_eq!(
            live.sources,
            vec![AgentLivenessSource::RecentSessionTranscriptActivity]
        );
        assert!(score.ledger.why_summary.contains(&live.reason));
    }

    #[test]
    fn agent_liveness_uses_child_progress_only_for_its_root_without_changing_posteriors() {
        let processes = vec![
            agent_record(100, 1, "claude --continue"),
            agent_record(101, 100, "cargo build"),
            agent_record(102, 100, "codex exec review"),
            agent_record(103, 102, "rustc lib.rs"),
        ];
        let mut measured = agent_activity_scorer(&processes);
        measured
            .activity
            .insert(101, agent_activity_sample(&processes[1], 100.0, 4096.0));
        let before = measured
            .score_with_desktop(&processes[0], Evidence::from_snapshot(&processes[0]), None)
            .unwrap();
        let before_posterior = before.posterior.posterior;
        measured.prepare_agent_activity(&processes, true);
        let score = measured
            .score_with_desktop(&processes[0], Evidence::from_snapshot(&processes[0]), None)
            .unwrap();
        let live = assess_agent_liveness(
            &processes[0],
            score.agent_activity.as_ref(),
            None,
            AGENT_LIVE_TERMINAL_WINDOW_SECONDS,
        )
        .unwrap();
        assert_eq!(live.status, AgentLivenessState::Live);
        assert_eq!(live.live, Some(true));
        assert_eq!(live.requested_activity_window_ms, Some(500));
        assert_eq!(live.terminal_window_seconds, 1800);
        assert_eq!(live.sources, vec![AgentLivenessSource::DescendantActivity]);
        assert!(live.reason.contains("1 attributed child"));
        assert!(score.ledger.why_summary.contains(&live.reason));
        assert_eq!(
            serde_json::to_value(score.posterior.posterior).unwrap(),
            serde_json::to_value(before_posterior).unwrap(),
            "observed work is a retention reason, not an invented likelihood"
        );
        assert!(measured.agent_activity_for(&processes[1]).is_none());
        assert!(agent_liveness(&processes[1], score.agent_activity.as_ref()).is_none());
        let nested = assess_agent_liveness(
            &processes[2],
            measured.agent_activity_for(&processes[2]),
            None,
            AGENT_LIVE_TERMINAL_WINDOW_SECONDS,
        )
        .unwrap();
        assert_eq!(
            nested.live,
            Some(false),
            "sibling work cannot make a nested agent live"
        );
        assert_eq!(
            nested.status,
            AgentLivenessState::NoActivityObservedInWindow
        );

        // Persisting/replaying the observation keeps the original attribution.
        let recorded = measured.recorded_observations(&processes[0], None);
        let roundtrip: ScoringObservations =
            serde_json::from_value(serde_json::to_value(&recorded).unwrap()).unwrap();
        let replayed = scorer(SignatureDatabase::with_defaults())
            .score_recorded(
                &processes[0],
                Evidence::from_snapshot(&processes[0]),
                roundtrip,
            )
            .unwrap()
            .agent_activity
            .unwrap();
        assert_eq!(replayed.activity, AgentActivityState::ActivityObserved);
        assert_eq!(replayed.composition.active_descendants, 1);
    }

    #[test]
    fn agent_liveness_keeps_unknown_distinct_from_quiet_and_accepts_positive_partial_evidence() {
        let mut process = agent_record(100, 1, "claude");
        process.tty = Some("pts/7".to_string());
        let processes = [process.clone()];
        let mut measured = agent_activity_scorer(&processes);
        measured.prepare_agent_activity(&processes, true);
        let assess = |activity: Option<&AgentActivityUnit>, idle| {
            assess_agent_liveness(&process, activity, idle, AGENT_LIVE_TERMINAL_WINDOW_SECONDS)
                .unwrap()
        };
        let missing_terminal = assess(measured.agent_activity_for(&process), None);
        assert_eq!(missing_terminal.live, None);
        assert_eq!(missing_terminal.status, AgentLivenessState::Unknown);
        assert!(missing_terminal
            .unavailable
            .iter()
            .any(|reason| reason.contains("terminal")));
        let quiet = assess(measured.agent_activity_for(&process), Some(1800));
        assert_eq!(quiet.live, Some(false));
        assert!(quiet.reason.contains("does not establish abandonment"));
        let terminal_only = assess(None, Some(1799));
        assert_eq!(terminal_only.live, Some(true));
        assert_eq!(
            terminal_only.sources,
            vec![AgentLivenessSource::RecentTerminalActivity]
        );
        assert_eq!(assess(None, Some(1800)).live, None);

        let mut sample = agent_activity_sample(&process, 100.0, 0.0);
        sample.io_error = Some("permission denied".to_string());
        sample.io_active = None;
        measured.activity.insert(process.pid.0, sample);
        measured.prepare_agent_activity(&processes, false);
        let positive = assess(measured.agent_activity_for(&process), None);
        assert_eq!(positive.live, Some(true));
        assert_eq!(positive.sources, vec![AgentLivenessSource::ProcessActivity]);
        assert!(!positive.unavailable.is_empty());
        measured.collect_activity(&[], Duration::ZERO);
        assert!(measured.agent_activity_for(&process).is_none());
        assert_eq!(
            assess(measured.agent_activity_for(&process), None).live,
            None
        );
    }

    #[test]
    fn agent_liveness_rejects_reused_moved_unknown_and_zombie_roots() {
        let process = agent_record(100, 1, "codex");
        let mut measured = agent_activity_scorer(std::slice::from_ref(&process));
        measured
            .activity
            .insert(100, agent_activity_sample(&process, 100.0, 0.0));
        measured.prepare_agent_activity(std::slice::from_ref(&process), true);
        let unit = measured.agent_activity_for(&process).unwrap();
        for variant in 0..5 {
            let mut changed = process.clone();
            match variant {
                0 => changed.start_id = StartId::from_linux("test-boot-id", 999, 100),
                1 => changed.uid += 1,
                2 => changed.pgid = Some(999),
                3 => changed.sid = Some(999),
                _ => changed.cmd = "claude".to_string(),
            }
            assert!(
                measured.agent_activity_for(&changed).is_none(),
                "variant {variant}"
            );
            let assessment = assess_agent_liveness(&changed, Some(unit), None, 1800).unwrap();
            assert_eq!(assessment.live, None, "variant {variant}");
            assert!(assessment.activity.is_none());
        }
        let mut running = process.clone();
        running.state = ProcessState::Running;
        assert!(measured.agent_activity_for(&running).is_some());
        assert_eq!(
            assess_agent_liveness(&running, Some(unit), None, 1800)
                .unwrap()
                .live,
            Some(true),
            "ordinary scheduler-state changes do not change process identity"
        );
        let mut unknown = process.clone();
        unknown.start_id = StartId::from_linux("unknown", 1_234_567_890, 100);
        let mut unknown_unit = unit.clone();
        unknown_unit.root.start_id = unknown.start_id.clone();
        unknown_unit.root.quality = pt_common::IdentityQuality::NoBootId;
        assert_eq!(
            assess_agent_liveness(&unknown, Some(&unknown_unit), None, 1800)
                .unwrap()
                .live,
            None
        );
        let mut zombie = process;
        zombie.state = ProcessState::Zombie;
        zombie.tty = Some("pts/7".to_string());
        assert_ne!(
            assess_agent_liveness(&zombie, Some(unit), Some(0), 1800)
                .unwrap()
                .live,
            Some(true)
        );
    }

    #[test]
    fn agent_activity_attributes_child_work_without_double_counting_nested_agents() {
        let processes = vec![
            agent_record(100, 1, "claude --continue"),
            agent_record(101, 100, "cargo build"),
            agent_record(
                102,
                100,
                "node /usr/lib/@modelcontextprotocol/server-filesystem/index.js",
            ),
            agent_record(103, 100, "codex exec review"),
            agent_record(104, 103, "rustc lib.rs"),
        ];
        let mut measured = agent_activity_scorer(&processes);
        measured
            .activity
            .insert(101, agent_activity_sample(&processes[1], 100.0, 4096.0));
        measured
            .activity
            .insert(103, agent_activity_sample(&processes[3], 300.0, 0.0));
        measured
            .activity
            .insert(104, agent_activity_sample(&processes[4], 200.0, 0.0));
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.units.len(), 2);
        assert_eq!(report.attributed_processes, processes.len());
        let parent = &report.units[0];
        assert_eq!(parent.root.pid.0, 100);
        assert_eq!(parent.kind, "claude");
        assert_eq!(parent.age_seconds, FOUR_DAYS.as_secs());
        assert_eq!(parent.activity, AgentActivityState::ActivityObserved);
        assert_eq!(parent.member_count, 3);
        assert_eq!(parent.composition.direct_children, 2);
        assert_eq!(parent.composition.descendants, 2);
        assert_eq!(parent.composition.active_descendants, 1);
        assert_eq!(parent.composition.known_mcp_server_descendants, 1);
        assert_eq!(parent.composition.active_mcp_server_descendants, 0);
        assert_eq!(parent.composition.other_descendants, 1);
        assert_eq!(parent.composition.active_other_descendants, 1);
        assert_eq!(parent.composition.nested_agent_roots, 1);
        assert_eq!(parent.usage.cpu_cores.total, Some(1.0));
        assert_eq!(parent.usage.read_bytes_per_second.total, Some(4096.0));
        assert_eq!(parent.usage.observed_rss_bytes, (100 + 101 + 102) * 1024);
        let nested = &report.units[1];
        assert_eq!(nested.root.pid.0, 103);
        assert_eq!(nested.member_count, 2);
        assert_eq!(nested.usage.cpu_cores.total, Some(5.0));
        assert_eq!(nested.composition.nested_agent_roots, 0);

        let mut reordered = processes.clone();
        reordered.reverse();
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::to_value(measured.agent_activity_report(&reordered, true)).unwrap()
        );
    }

    #[test]
    fn agent_activity_zero_window_is_only_an_observation_and_requires_complete_evidence() {
        let processes = vec![
            agent_record(100, 1, "claude"),
            agent_record(
                101,
                100,
                "node /usr/lib/@modelcontextprotocol/server-filesystem/index.js",
            ),
        ];
        let measured = agent_activity_scorer(&processes);
        let report = measured.agent_activity_report(&processes, true);
        let unit = &report.units[0];
        assert_eq!(
            unit.activity,
            AgentActivityState::NoActivityObservedInWindow
        );
        assert_eq!(unit.coverage.fully_observed_members, 2);
        assert_eq!(unit.composition.known_mcp_server_descendants, 1);
        assert_eq!(unit.composition.other_descendants, 0);
        assert_eq!(unit.usage.cpu_cores.total, Some(0.0));
        assert!(unit.unavailable.is_empty());
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value["units"][0]["activity"],
            "no_activity_observed_in_window"
        );
        assert!(report
            .limitations
            .iter()
            .any(|text| text.contains("does not establish abandonment")));

        let partial = measured.agent_activity_report(&processes, false);
        assert_eq!(partial.units[0].activity, AgentActivityState::Unknown);
        assert_eq!(partial.units[0].usage.cpu_cores.observed, Some(0.0));
        assert_eq!(partial.units[0].usage.cpu_cores.total, None);

        let unsampled =
            scorer(SignatureDatabase::with_defaults()).agent_activity_report(&processes, true);
        assert_eq!(unsampled.sampling_window_ms, None);
        assert_eq!(unsampled.units[0].activity, AgentActivityState::Unknown);
        assert_eq!(unsampled.units[0].usage.cpu_cores.observed, None);
        assert_eq!(unsampled.units[0].coverage.unknown_activity_members, 2);
    }

    #[test]
    fn agent_activity_keeps_partial_positive_evidence_but_never_fills_missing_rates_with_zero() {
        let processes = vec![
            agent_record(100, 1, "claude"),
            agent_record(101, 100, "cargo build"),
        ];
        let mut measured = agent_activity_scorer(&processes);
        measured.activity.remove(&100);
        let mut child = agent_activity_sample(&processes[1], 25.0, 0.0);
        child.io_error = Some("permission denied".to_string());
        child.read_bytes_per_second = None;
        child.write_bytes_per_second = None;
        child.io_active = None;
        measured.activity.insert(101, child);
        let report = measured.agent_activity_report(&processes, true);
        let unit = &report.units[0];
        assert_eq!(unit.activity, AgentActivityState::ActivityObserved);
        assert_eq!(unit.coverage.cpu_observed_members, 1);
        assert_eq!(unit.coverage.storage_io_observed_members, 0);
        assert_eq!(unit.coverage.fully_observed_members, 0);
        assert_eq!(unit.coverage.unknown_activity_members, 1);
        assert_eq!(unit.composition.active_other_descendants, 1);
        assert_eq!(unit.usage.cpu_cores.observed, Some(0.25));
        assert_eq!(unit.usage.cpu_cores.total, None);
        assert_eq!(unit.usage.read_bytes_per_second.observed, None);

        measured.activity.get_mut(&101).unwrap().cpu_percent = Some(0.0);
        assert_eq!(
            measured.agent_activity_report(&processes, true).units[0].activity,
            AgentActivityState::Unknown
        );
    }

    #[test]
    fn agent_activity_rejects_stale_native_and_invalid_window_measurements() {
        let process = agent_record(100, 1, "codex");
        let mut measured = agent_activity_scorer(std::slice::from_ref(&process));
        for variant in 0..7 {
            let mut sample = agent_activity_sample(&process, 100.0, 1024.0);
            match variant {
                0 => sample.start_id = StartId::from_linux("test-boot-id", 999, 100),
                1 => sample.uid += 1,
                2 => sample.source = "ps_lifetime_fallback".to_string(),
                3 => sample.requested_window_ms = 1000,
                4 => {
                    sample.cpu_percent = Some(f64::NAN);
                    sample.read_bytes_per_second = Some(f64::INFINITY);
                }
                5 => {
                    sample.cpu_window_seconds = Some(0.0);
                    sample.io_window_seconds = Some(-1.0);
                }
                _ => {
                    sample.cpu_error = Some("counter moved backwards".to_string());
                    sample.io_error = Some("permission denied".to_string());
                }
            }
            measured.activity.insert(100, sample);
            let report = measured.agent_activity_report(std::slice::from_ref(&process), true);
            assert_eq!(
                report.units[0].activity,
                AgentActivityState::Unknown,
                "variant {variant}"
            );
            assert_eq!(
                report.units[0].coverage.fully_observed_members, 0,
                "variant {variant}"
            );
            assert_eq!(
                report.units[0].usage.cpu_cores.observed, None,
                "variant {variant}"
            );
            assert_eq!(
                report.units[0].usage.read_bytes_per_second.observed, None,
                "variant {variant}"
            );
        }
    }

    #[test]
    fn agent_activity_missing_reused_and_cyclic_ancestry_cannot_claim_a_complete_tree() {
        let root = agent_record(100, 1, "claude");
        let child = agent_record(101, 100, "cargo build");
        let mut missing = agent_record(102, 999, "rustc lib.rs");
        let mut processes = vec![root.clone(), child.clone(), missing.clone()];
        let measured = agent_activity_scorer(&processes);
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.ancestry_unavailable_processes, 1);
        assert_eq!(report.units[0].member_count, 2);
        assert_eq!(report.units[0].activity, AgentActivityState::Unknown);

        missing.ppid = ProcessId(100);
        missing.start_id = StartId::from_linux("test-boot-id", 1, 102);
        processes[2] = missing;
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.ancestry_unavailable_processes, 1);
        assert_eq!(report.units[0].member_count, 2);
        assert!(!report.units[0].coverage.ancestry_complete);

        processes = vec![root, child];
        processes[0].ppid = ProcessId(101);
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.ancestry_unavailable_processes, 2);
        assert_eq!(report.units[0].member_count, 1);
        assert_eq!(report.units[0].activity, AgentActivityState::Unknown);
        assert_eq!(report.units[0].composition.nested_agent_roots, 0);
    }

    #[test]
    fn agent_activity_excludes_duplicate_pid_records_and_preserves_incarnation_ids() {
        let root = agent_record(100, 1, "claude");
        let child = agent_record(101, 100, "cargo build");
        let mut duplicate = child.clone();
        duplicate.start_id = StartId::from_linux("test-boot-id", 2_000_000_000, 101);
        let processes = vec![root.clone(), child, duplicate];
        let measured = agent_activity_scorer(&processes);
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.excluded_duplicate_pids, 1);
        assert_eq!(report.units[0].member_count, 1);
        assert_eq!(report.units[0].activity, AgentActivityState::Unknown);
        assert_eq!(report.units[0].usage.cpu_cores.total, None);

        let before = measured.agent_activity_report(std::slice::from_ref(&root), true);
        let mut reused = root;
        reused.start_id = StartId::from_linux("test-boot-id", 2_000_000_000, 100);
        let after = measured.agent_activity_report(std::slice::from_ref(&reused), true);
        assert_ne!(before.units[0].id, after.units[0].id);
        assert_eq!(after.units[0].activity, AgentActivityState::Unknown);
        assert_eq!(after.units[0].usage.cpu_cores.observed, None);
    }

    #[test]
    fn agent_activity_keeps_user_boundaries_and_reports_saturated_resource_sums() {
        let mut root = agent_record(100, 1, "claude");
        root.rss_bytes = u64::MAX;
        let child = agent_record(101, 100, "cargo build");
        let mut different_user = agent_record(102, 100, "rustc lib.rs");
        different_user.uid = 2000;
        let processes = vec![root, child, different_user];
        let mut measured = agent_activity_scorer(&processes);
        for process in &processes {
            measured
                .activity
                .insert(process.pid.0, agent_activity_sample(process, 0.0, f64::MAX));
        }
        let report = measured.agent_activity_report(&processes, true);
        assert_eq!(report.attributed_processes, 2);
        let unit = &report.units[0];
        assert_eq!(unit.member_count, 2);
        assert_eq!(unit.composition.descendants, 1);
        assert_eq!(unit.activity, AgentActivityState::ActivityObserved);
        assert_eq!(unit.usage.observed_rss_bytes, u64::MAX);
        assert!(unit.usage.rss_sum_saturated);
        assert_eq!(unit.usage.read_bytes_per_second.observed_members, 2);
        assert_eq!(unit.usage.read_bytes_per_second.observed, None);
        assert_eq!(unit.usage.read_bytes_per_second.total, None);
        assert_eq!(unit.unavailable.len(), 2);
        serde_json::to_string(&report).expect("no non-finite value reaches JSON");
    }

    fn work_diagnosis(process: &ProcessRecord) -> ProcessWorkDiagnosis {
        use crate::collect::duplicates::record_command_digest;
        serde_json::from_value(serde_json::json!({
            "identity": pt_common::ProcessIdentity::full(
                process.pid.0,
                process.start_id.clone(),
                process.uid,
                process.pgid,
                process.sid,
                pt_common::IdentityQuality::Full,
            ),
            "parent_pid": process.ppid.0,
            "record_command_sha256": record_command_digest(process),
            "duplicate_group_id": "observed-duplicate-group",
            "duplicate_role": "preferred_newest",
            "competing_group_ids": [],
            "review_reason": "Preserve the newest observed independent build; review older copies.",
        }))
        .unwrap()
    }

    #[test]
    fn workload_diagnostics_survive_recording_without_changing_probabilities() {
        let scorer = scorer(SignatureDatabase::with_defaults());
        let process = record(9001, "cargo", "cargo build --all-targets", FOUR_DAYS);
        let mut observations = scorer.recorded_observations(&process, None);
        let before = scorer
            .score_recorded(
                &process,
                Evidence::from_snapshot(&process),
                observations.clone(),
            )
            .unwrap();
        observations.work = Some(work_diagnosis(&process));
        let recorded: ScoringObservations =
            serde_json::from_slice(&serde_json::to_vec(&observations).unwrap()).unwrap();
        let after = scorer
            .score_recorded(&process, Evidence::from_snapshot(&process), recorded)
            .unwrap();
        assert_eq!(before.posterior.posterior, after.posterior.posterior);
        assert_eq!(
            serde_json::to_value(&before.posterior.evidence_terms).unwrap(),
            serde_json::to_value(&after.posterior.evidence_terms).unwrap(),
        );
        assert_eq!(before.ledger.classification, after.ledger.classification);
        assert!(after
            .ledger
            .why_summary
            .contains("newest observed independent build"));
        assert!(after.work.unwrap().preserves_work());
    }

    #[test]
    fn recorded_work_diagnosis_rejects_reused_identity_and_changed_work() {
        let scorer = scorer(SignatureDatabase::new());
        let process = record(9001, "cargo", "cargo check", FOUR_DAYS);
        let mut observations = scorer.recorded_observations(&process, None);
        observations.work = Some(work_diagnosis(&process));
        for changed in ["start", "uid", "parent", "group", "session", "argv", "comm"] {
            let mut other = process.clone();
            match changed {
                "start" => other.start_id = StartId::from_linux("test-boot-id", 987, 9001),
                "uid" => other.uid += 1,
                "parent" => other.ppid.0 += 1,
                "group" => other.pgid = Some(7),
                "session" => other.sid = Some(7),
                "argv" => other.cmd = "cargo build".to_string(),
                "comm" => other.comm = "different".to_string(),
                _ => unreachable!(),
            }
            assert!(
                scorer
                    .score_recorded(
                        &other,
                        Evidence::from_snapshot(&other),
                        observations.clone()
                    )
                    .is_none(),
                "stale workload diagnosis survived changed {changed}"
            );
        }
    }

    #[test]
    fn older_recording_has_unknown_work_diagnosis() {
        let scorer = scorer(SignatureDatabase::new());
        let process = record(9001, "cargo", "cargo check", FOUR_DAYS);
        let mut recorded =
            serde_json::to_value(scorer.recorded_observations(&process, None)).unwrap();
        recorded.as_object_mut().unwrap().remove("work");
        let restored: ScoringObservations = serde_json::from_value(recorded.clone()).unwrap();
        assert!(restored.work.is_none());
        // Review labels bind the canonical capture hash. Loading an older
        // recording must not insert a new null field and invalidate its labels.
        assert_eq!(serde_json::to_value(&restored).unwrap(), recorded);
        assert!(scorer
            .score_recorded(&process, Evidence::from_snapshot(&process), restored)
            .is_some());
    }

    #[test]
    fn configuration_returns_signature_load_failures_in_model_warnings() {
        let directory =
            std::env::temp_dir().join(format!("pt-scorer-signatures-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        eprintln!(
            "retained scorer signature evidence: {}",
            directory.display()
        );
        let config = crate::config::load_config(&crate::config::ConfigOptions {
            config_dir: Some(directory.clone()),
            ..Default::default()
        })
        .unwrap();
        let (_, warnings) = Scorer::from_config(&config);
        assert!(
            warnings.is_empty(),
            "absent optional signatures: {warnings:?}"
        );

        std::fs::write(directory.join("signatures.json"), b"{ broken JSON").unwrap();
        let (scorer, warnings) = Scorer::from_config(&config);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("failed to parse user signatures"));
        assert!(warnings[0].contains("signatures.json"));
        assert!(scorer.signatures.is_empty());
        assert!(Scorer::try_from_config(&config).is_err());

        let unreadable = directory.join("unreadable");
        std::fs::create_dir_all(unreadable.join("signatures.json")).unwrap();
        let (_, warnings) = load_signature_database(&unreadable);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("failed to read user signatures"));
    }

    #[test]
    fn persisted_patterns_change_inference_without_overriding_human_verdicts() {
        use crate::supervision::pattern_persistence::PatternLibrary;

        let directory = std::env::temp_dir().join(format!(
            "pt-scorer-pattern-inference-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        eprintln!(
            "retained pattern inference evidence: {}",
            directory.display()
        );
        let options = crate::config::ConfigOptions {
            config_dir: Some(directory.clone()),
            ..Default::default()
        };
        let original = crate::config::load_config(&options).unwrap();
        let before_scorer = Scorer::try_from_config(&original).unwrap();
        let process = record(
            5290,
            "catalog-worker",
            "catalog-worker --job alpha",
            FOUR_DAYS,
        );
        let unrelated = record(
            5291,
            "unrelated-catalog-worker",
            "unrelated-catalog-worker",
            FOUR_DAYS,
        );
        let before = before_scorer
            .score_with_desktop(&process, Evidence::default(), None)
            .unwrap();
        let before_unrelated = before_scorer
            .score_with_desktop(&unrelated, Evidence::default(), None)
            .unwrap();
        assert_eq!(before.prior_source, "global");

        let mut library = PatternLibrary::new(&directory);
        library
            .add_learned(
                SupervisorSignature::new("pattern-only", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^catalog-worker$"])
                    .with_priors(SignaturePriors::likely_abandoned())
                    .with_confidence(0.4),
            )
            .unwrap();
        library.save().unwrap();
        let changed = Scorer::try_from_config(&original).unwrap_err();
        assert!(
            changed.contains("configuration changed after priors were loaded"),
            "{changed}"
        );
        let fresh = crate::config::load_config(&options).unwrap();
        let imported = Scorer::try_from_config(&fresh).unwrap();
        let after = imported
            .score_with_desktop(&process, Evidence::default(), None)
            .unwrap();
        assert_eq!(after.prior_source, "signature");
        assert_eq!(
            after.signature.as_ref().unwrap().signature.name,
            "pattern-only"
        );
        assert_eq!(
            after
                .signature
                .as_ref()
                .unwrap()
                .signature
                .confidence_weight,
            0.4
        );
        assert!(after.posterior.posterior.abandoned > before.posterior.posterior.abandoned);
        let after_unrelated = imported
            .score_with_desktop(&unrelated, Evidence::default(), None)
            .unwrap();
        assert_eq!(
            after_unrelated.posterior.posterior,
            before_unrelated.posterior.posterior
        );

        let mut decisions = DecisionStore::load(&directory).unwrap();
        for _ in 0..3 {
            decisions.record(&process.comm, &process.cmd, Verdict::Spare);
        }
        decisions.save().unwrap();
        let reviewed = Scorer::try_from_config(&fresh).unwrap();
        let with_verdict = reviewed
            .score_with_desktop(&process, Evidence::default(), None)
            .unwrap();
        assert_eq!(with_verdict.prior_source, "user");
        assert!(with_verdict.posterior.posterior.abandoned < after.posterior.posterior.abandoned);
    }

    #[test]
    fn invalid_disable_state_cannot_fall_back_to_shipped_signatures() {
        let directory =
            std::env::temp_dir().join(format!("pt-scorer-disabled-model-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(directory.join("patterns")).unwrap();
        eprintln!("retained disabled model evidence: {}", directory.display());
        let path = directory.join("patterns/disabled.json");
        std::fs::write(&path, b"{ malformed disabled names").unwrap();
        let config = crate::config::load_config(&crate::config::ConfigOptions {
            config_dir: Some(directory.clone()),
            ..Default::default()
        })
        .unwrap();
        let strict = Scorer::try_from_config(&config).unwrap_err();
        assert!(strict.contains("disabled signatures"), "{strict}");
        let (database, warnings) = load_signature_database(&directory);
        assert!(database.is_empty());
        assert_eq!(warnings.len(), 1);
        assert_eq!(std::fs::read(path).unwrap(), b"{ malformed disabled names");
    }

    #[cfg(unix)]
    #[test]
    fn dangling_model_files_return_warnings_instead_of_empty_models() {
        let directory =
            std::env::temp_dir().join(format!("pt-scorer-broken-links-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        eprintln!("retained model link evidence: {}", directory.display());
        for file in ["signatures.json", "decisions.json"] {
            let config_dir = directory.join(file);
            std::fs::create_dir(&config_dir).unwrap();
            let target = config_dir.join("missing-target.json");
            let path = config_dir.join(file);
            std::os::unix::fs::symlink(&target, &path).unwrap();
            let config = crate::config::load_config(&crate::config::ConfigOptions {
                config_dir: Some(config_dir.clone()),
                ..Default::default()
            })
            .unwrap();
            let (_, warnings) = Scorer::from_config(&config);
            assert_eq!(warnings.len(), 1, "{file}: {warnings:?}");
            assert!(warnings[0].contains(file), "{warnings:?}");
            if file == "decisions.json" {
                assert!(DecisionStore::load(&config_dir).is_err());
            }
            assert!(std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(!target.exists());
        }
    }

    #[test]
    fn recorded_observations_preserve_activity_and_desktop_after_cache_changes() {
        let process = record(5100, "slack", "/usr/lib/slack/slack", FOUR_DAYS);
        let mut measured = scorer(SignatureDatabase::new());
        measured.activity_window = Some(Duration::from_millis(500));
        measured
            .activity
            .insert(process.pid.0, sampled_idle(&process));
        let desktop = Some("app-recorded-slack.scope".to_string());
        let observations = measured.recorded_observations(&process, desktop.clone());
        let expected = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), desktop)
            .unwrap()
            .ledger;
        let json = serde_json::to_vec(&observations).unwrap();
        let restored: ScoringObservations = serde_json::from_slice(&json).unwrap();

        measured.activity_window = None;
        measured.activity.clear();
        let actual = measured
            .score_recorded(&process, Evidence::from_snapshot(&process), restored)
            .unwrap();
        assert_eq!(actual.ledger, expected);
        assert_eq!(actual.activity.unwrap().cpu_percent, Some(0.0));
        assert!(actual.desktop_app_credited);
        assert_eq!(
            actual.desktop_app.as_deref(),
            Some("app-recorded-slack.scope")
        );
    }

    #[test]
    fn recorded_observations_reject_omitted_nullable_fields() {
        let process = record(5102, "worker", "worker --job", FOUR_DAYS);
        let observations = scorer(SignatureDatabase::new()).recorded_observations(&process, None);
        let serialized = serde_json::to_value(&observations).unwrap();
        // Null is a recorded absence, but an omitted field is not an observation.
        let complete: ScoringObservations = serde_json::from_value(serialized.clone()).unwrap();
        assert!(complete.matches_record(&process));
        for field in serialized.as_object().unwrap().keys() {
            let mut incomplete = serialized.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<ScoringObservations>(incomplete).is_err(),
                "missing {field} must not silently become an absent observation"
            );
        }
    }

    #[test]
    fn recorded_observations_reject_another_incarnation_or_job_group() {
        let process = record(5101, "worker", "worker --job", FOUR_DAYS);
        let measured = scorer(SignatureDatabase::new());
        let observations = measured.recorded_observations(&process, None);
        for field in ["pid", "start_id", "uid", "pgid", "sid"] {
            let mut changed = observations.clone();
            match field {
                "pid" => changed.pid += 1,
                "start_id" => {
                    changed.start_id = StartId::from_linux("different-boot", 1, process.pid.0);
                }
                "uid" => changed.uid += 1,
                "pgid" => changed.pgid = Some(99),
                "sid" => changed.sid = Some(99),
                _ => unreachable!(),
            }
            assert!(
                measured
                    .score_recorded(&process, Evidence::from_snapshot(&process), changed)
                    .is_none(),
                "{field} must not inherit recorded scoring inputs"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn persisted_respawn_join_preserves_posterior_and_rejects_stale_scope() {
        use crate::decision::respawn_loop::RespawnHistoryStore;
        use crate::decision::Action;
        use crate::plan::PlanAction;
        use crate::verify::SavedActionOutcome;
        use pt_common::ProcessIdentity;

        let at = |seconds| chrono::DateTime::from_timestamp(seconds, 0).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = RespawnHistoryStore::from_data_dir(directory.path());
        let mut parent = record(4000, "bash", "bash respawner.sh", FOUR_DAYS);
        parent.start_id = StartId::from_linux("test-boot-id", 1, 4000);
        parent.start_time_unix = 1;
        let parent_identity = ProcessIdentity::new(4000, parent.start_id.clone(), parent.uid);
        let mut current = Vec::new();
        for index in 0..2_u32 {
            let killed_at = 1000 + i64::from(index) * 2;
            let target_pid = 5000 + index;
            let target = ProcessIdentity::new(
                target_pid,
                StartId::from_linux("test-boot-id", killed_at as u64 - 1, target_pid),
                1000,
            );
            let action: PlanAction = serde_json::from_value(serde_json::json!({
                "action_id": format!("kill-{index}"),
                "target": target,
                "action": "kill",
                "order": 0,
                "stage": 0,
                "timeouts": {"preflight_ms": 2000, "execute_ms": 10000, "verify_ms": 5000},
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
            }))
            .unwrap();
            let execution = SavedActionOutcome {
                action_id: action.action_id.clone(),
                pid: target_pid,
                status: "success".to_string(),
                action: Some(Action::Kill),
                target: Some(target),
                original_zombie_target: None,
                command: Some("sleep 600".to_string()),
                parent_pid: Some(4000),
                parent_identity: Some(parent_identity.clone()),
                executed_at: Some(at(killed_at)),
                execution_clock: None,
                time_ms: Some(1),
                supervisor_restart: None,
            };
            let replacement_pid = 6000 + index;
            let mut replacement = record(replacement_pid, "sleep", "sleep 600", FOUR_DAYS);
            replacement.ppid = parent.pid;
            replacement.start_id =
                StartId::from_linux("test-boot-id", killed_at as u64 + 1, replacement_pid);
            replacement.start_time_unix = killed_at + 1;
            current = vec![replacement, parent.clone()];
            let observed = store
                .ingest_verified_respawn(
                    &action,
                    &execution,
                    &current,
                    &format!("session-{index}"),
                    at(killed_at + 2),
                )
                .unwrap()
                .unwrap();
            assert!(observed.inserted);
        }
        let now = at(1010);
        let history = RespawnHistoryStore::from_data_dir(directory.path())
            .load(now)
            .unwrap();
        let mut measured = scorer(SignatureDatabase::with_defaults());
        let evidence = Evidence::from_snapshot(&current[0]);
        let baseline = serde_json::to_value(
            measured
                .score_with_desktop(&current[0], evidence.clone(), None)
                .unwrap()
                .posterior
                .posterior,
        )
        .unwrap();
        measured.collect_respawn_history(Some(&history), &current, now);
        let scored = measured
            .score_with_desktop(&current[0], evidence, None)
            .unwrap();
        assert_eq!(
            serde_json::to_value(scored.posterior.posterior).unwrap(),
            baseline
        );
        let summary = scored.respawn_history.as_ref().unwrap();
        assert!(summary.detection.is_loop);
        assert_eq!(summary.detection.loop_count, 2);
        assert!((summary.detection.kill_utility_multiplier - 0.68).abs() < 1e-6);
        assert!(scored
            .ledger
            .top_evidence
            .iter()
            .any(|text| text.contains("Spawner PID 4000")));

        let mut changed_command = current[0].clone();
        changed_command.cmd = "sleep 6000".to_string();
        assert!(measured.respawn_history_for(&changed_command).is_none());
        let mut reused_pid = current[0].clone();
        reused_pid.start_id = StartId::from_linux("test-boot-id", 9999, reused_pid.pid.0);
        assert!(measured.respawn_history_for(&reused_pid).is_none());
        let mut ambiguous = current.clone();
        ambiguous.push(parent.clone());
        measured.collect_respawn_history(Some(&history), &ambiguous, now);
        assert!(measured.respawn_history_for(&current[0]).is_none());
        let mut reused_parent = current.clone();
        reused_parent[1].start_id = StartId::from_linux("test-boot-id", 9999, 4000);
        measured.collect_respawn_history(Some(&history), &reused_parent, now);
        assert!(measured.respawn_history_for(&current[0]).is_none());
        measured.collect_respawn_history(Some(&history), &current, now);
        assert!(measured.respawn_history_for(&current[0]).is_some());
        measured.collect_respawn_history(None, &current, now);
        assert!(measured.respawn_history_for(&current[0]).is_none());
    }

    fn sampled_idle(process: &ProcessRecord) -> ProcessActivity {
        let mut activity =
            ProcessActivity::unavailable(process, Duration::from_millis(500), "fixture");
        activity.source = "procfs_window".to_string();
        activity.cpu_percent = Some(0.0);
        activity.cpu_ticks = Some(0);
        activity.cpu_window_seconds = Some(0.5);
        activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Observed {
            occupancy: 0.0,
            effective_cores: 1.0,
            effective_parallelism: 1.0,
            online_cores: 1,
            affinity_cores: 1,
            affinity_parallelism: None,
            quota_cores: None,
            threads: 1,
        });
        activity.io_window_seconds = Some(0.5);
        activity.io_read_bytes = Some(0);
        activity.io_write_bytes = Some(0);
        activity.read_bytes_per_second = Some(0.0);
        activity.write_bytes_per_second = Some(0.0);
        activity.io_active = Some(false);
        activity.cpu_error = None;
        activity.io_error = None;
        activity
    }

    fn pipe_evidence_fixture(
        producer: &ProcessRecord,
        consumer: &ProcessRecord,
    ) -> PipeLivenessEvidence {
        let hop = PipeLivenessHop {
            writer: pipe_record_identity(producer).unwrap(),
            writer_fd: 1,
            reader: pipe_record_identity(consumer).unwrap(),
            reader_fd: 0,
            inode: 9001,
        };
        let mut activity = sampled_idle(consumer);
        activity.cpu_ticks = Some(2);
        activity.cpu_percent = Some(4.0);
        PipeLivenessEvidence {
            identity: hop.writer.clone(),
            identity_verified: true,
            readers: vec![hop.clone()],
            writers: Vec::new(),
            path: vec![hop],
            active_consumer: Some(activity),
            census_complete: true,
            collection_complete: true,
            scope: PIPE_LIVENESS_SCOPE.to_string(),
            unavailable: Vec::new(),
        }
    }

    #[test]
    fn pipe_liveness_is_preservation_advice_and_round_trips_without_changing_posterior() {
        let producer = record(6101, "producer", "producer", FOUR_DAYS);
        let consumer = record(6102, "consumer", "consumer", Duration::from_secs(10));
        let reference = scorer(SignatureDatabase::new());
        let evidence = reference.snapshot_evidence(&producer);
        let expected = reference
            .score_with_desktop(&producer, evidence.clone(), None)
            .unwrap();
        let mut measured = reference.clone();
        let mut pipes = pipe_evidence_fixture(&producer, &consumer);
        // A positive path survives a partial census. Partiality never licenses
        // a negative claim about unobserved readers or inactive consumers.
        pipes.census_complete = false;
        pipes.collection_complete = false;
        measured.pipe_liveness.insert(producer.pid.0, pipes);
        let observed = measured.recorded_observations(&producer, None);
        let serialized = serde_json::to_value(&observed).unwrap();
        let captured: ScoringObservations = serde_json::from_value(serialized.clone()).unwrap();
        let actual = reference
            .score_recorded(&producer, evidence.clone(), captured)
            .unwrap();
        assert_eq!(actual.posterior.posterior, expected.posterior.posterior);
        assert_eq!(
            serde_json::to_value(&actual.posterior.evidence_terms).unwrap(),
            serde_json::to_value(&expected.posterior.evidence_terms).unwrap()
        );
        assert!(actual.pipe_liveness.unwrap().preserves_active_consumer());
        assert!(actual.ledger.top_evidence.iter().any(|line| {
            line.contains("6102") && line.contains("does not prove traffic")
        }));
        assert!(reference.pipe_liveness_for(&producer).is_none());

        let mut older = serialized;
        older.as_object_mut().unwrap().remove("pipe_liveness");
        let older: ScoringObservations = serde_json::from_value(older).unwrap();
        assert!(older.pipe_liveness.is_none());
        let replayed = reference.score_recorded(&producer, evidence, older).unwrap();
        assert_eq!(replayed.posterior.posterior, expected.posterior.posterior);
    }

    #[test]
    fn pipe_liveness_cache_rejects_replaced_identity_and_clears_on_new_window() {
        let producer = record(6101, "producer", "producer", FOUR_DAYS);
        let consumer = record(6102, "consumer", "consumer", FOUR_DAYS);
        let mut measured = scorer(SignatureDatabase::new());
        measured.pipe_liveness.insert(
            producer.pid.0,
            pipe_evidence_fixture(&producer, &consumer),
        );
        assert!(measured.pipe_liveness_for(&producer).is_some());
        for field in ["start", "uid", "pgid", "sid"] {
            let mut changed = producer.clone();
            match field {
                "start" => changed.start_id = StartId::from_linux("test-boot-id", 999, 6101),
                "uid" => changed.uid += 1,
                "pgid" => changed.pgid = Some(99),
                "sid" => changed.sid = Some(99),
                _ => unreachable!(),
            }
            assert!(measured.pipe_liveness_for(&changed).is_none(), "{field}");
        }
        measured.collect_activity(&[], Duration::ZERO);
        assert!(measured.pipe_liveness_for(&producer).is_none());
        measured.pipe_liveness.insert(
            producer.pid.0,
            pipe_evidence_fixture(&producer, &consumer),
        );
        measured.collect_activity(&[], Duration::from_millis(500));
        assert!(measured.pipe_liveness_for(&producer).is_none());
    }

    #[test]
    fn pipe_liveness_rejects_malformed_paths_and_unverified_activity_in_replay() {
        let producer = record(6101, "producer", "producer", FOUR_DAYS);
        let consumer = record(6102, "consumer", "consumer", FOUR_DAYS);
        let reference = scorer(SignatureDatabase::new());
        for mutation in 0..11 {
            let mut pipes = pipe_evidence_fixture(&producer, &consumer);
            match mutation {
                0 => pipes.identity_verified = false,
                1 => pipes.path[0].writer_fd = 0,
                2 => pipes.path[0].inode = 0,
                3 => pipes.path[0].reader = pipes.identity.clone(),
                4 => {
                    pipes.path[0].reader.start_id =
                        StartId::from_linux("other-boot", 1_234_567_890, 6102);
                }
                5 => pipes.active_consumer.as_mut().unwrap().uid += 1,
                6 => {
                    pipes.active_consumer.as_mut().unwrap().source =
                        "ps_lifetime_fallback".to_string();
                }
                7 => pipes.active_consumer.as_mut().unwrap().requested_window_ms = 0,
                8 => pipes.active_consumer.as_mut().unwrap().cpu_ticks = Some(0),
                9 => pipes.active_consumer.as_mut().unwrap().cpu_window_seconds = Some(0.1),
                10 => {
                    pipes.active_consumer.as_mut().unwrap().cpu_error =
                        Some("counter identity changed".to_string());
                }
                _ => unreachable!(),
            }
            assert!(!pipes.preserves_active_consumer(), "mutation {mutation}");
            let mut observed = reference.recorded_observations(&producer, None);
            observed.pipe_liveness = Some(pipes);
            assert!(reference
                .score_recorded(&producer, reference.snapshot_evidence(&producer), observed)
                .is_none(), "mutation {mutation}");
        }
    }

    #[test]
    fn pipe_liveness_requires_positive_completed_cpu_or_storage_measurements() {
        let consumer = record(6102, "consumer", "consumer", FOUR_DAYS);
        let mut sample = sampled_idle(&consumer);
        assert!(!pipe_consumer_activity_observed(&sample));
        sample.io_active = Some(true);
        assert!(!pipe_consumer_activity_observed(&sample));
        sample.io_read_bytes = Some(1024);
        sample.read_bytes_per_second = Some(2048.0);
        assert!(pipe_consumer_activity_observed(&sample));
        for value in [None, Some(0.0), Some(0.1), Some(f64::NAN), Some(f64::INFINITY)] {
            let mut invalid = sample.clone();
            invalid.io_window_seconds = value;
            assert!(!pipe_consumer_activity_observed(&invalid));
        }
        sample.io_error = Some("unavailable".to_string());
        assert!(!pipe_consumer_activity_observed(&sample));
        sample.cpu_ticks = Some(1);
        sample.cpu_percent = Some(2.0);
        assert!(pipe_consumer_activity_observed(&sample));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pipe_population_excludes_ambiguous_dead_and_weak_identities() {
        let live = record(6101, "producer", "producer", FOUR_DAYS);
        let mut dead = record(6102, "dead", "dead", FOUR_DAYS);
        dead.state = ProcessState::Zombie;
        let mut weak = record(6103, "weak", "weak", FOUR_DAYS);
        weak.start_id = StartId::from_linux("unknown", 123, 6103);
        let mut unknown = record(6104, "unknown", "unknown", FOUR_DAYS);
        unknown.state = ProcessState::Unknown;
        let population = [live.clone(), dead, weak, unknown];
        let eligible = pipe_population(&population);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible.keys().next().unwrap().pid, live.pid.0);
        assert!(pipe_population(&[live.clone(), live]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pipe_snapshot_adapter_reaches_young_consumers_and_keeps_unknown_activity_unknown() {
        use crate::collect::pipe_liveness::{
            PipeAccess, PipeEndpoint, PipeLivenessSnapshot, PipePeer, ProcessPipeLiveness,
        };
        let population = [
            record(6101, "producer", "producer", FOUR_DAYS),
            record(6102, "filter", "filter", FOUR_DAYS),
            record(6103, "consumer", "consumer", Duration::from_secs(10)),
        ];
        let eligible = pipe_population(&population);
        let keys: Vec<_> = eligible.keys().copied().collect();
        let mut snapshot = PipeLivenessSnapshot {
            boot_id: Some("test-boot-id".to_string()),
            processes: keys
                .iter()
                .map(|&identity| {
                    (
                        identity.pid,
                        ProcessPipeLiveness {
                            identity,
                            identity_verified: true,
                            endpoints: Vec::new(),
                            readers: Vec::new(),
                            writers: Vec::new(),
                            complete: true,
                            unavailable: Vec::new(),
                        },
                    )
                })
                .collect(),
            complete: true,
            unavailable: Vec::new(),
            descriptors_inspected: 8,
            elapsed: Duration::from_millis(1),
        };
        for (index, pair) in keys.windows(2).enumerate() {
            let inode = 9001 + index as u64;
            let writer = snapshot.processes.get_mut(&pair[0].pid).unwrap();
            writer.endpoints.push(PipeEndpoint {
                fd: 1,
                inode,
                access: PipeAccess::Write,
            });
            writer.readers.push(PipePeer {
                identity: pair[1],
                local_fd: 1,
                peer_fd: 0,
                inode,
            });
            let reader = snapshot.processes.get_mut(&pair[1].pid).unwrap();
            reader.endpoints.push(PipeEndpoint {
                fd: 0,
                inode,
                access: PipeAccess::Read,
            });
            reader.writers.push(PipePeer {
                identity: pair[0],
                local_fd: 0,
                peer_fd: 1,
                inode,
            });
        }
        let mut activity = sampled_idle(&population[2]);
        activity.cpu_ticks = Some(2);
        activity.cpu_percent = Some(4.0);
        let mut measured = scorer(SignatureDatabase::new());
        measured.activity_window = Some(Duration::from_millis(500));
        measured.activity.insert(6103, activity.clone());
        measured.prepare_pipe_liveness(&eligible, false, &snapshot);
        let producer = measured.pipe_liveness_for(&population[0]).unwrap();
        assert!(producer.preserves_active_consumer());
        assert_eq!(producer.path.len(), 2);
        assert_eq!(producer.active_consumer.as_ref().unwrap().pid, 6103);
        assert!(!producer.census_complete);
        assert!(measured
            .pipe_liveness_for(&population[1])
            .unwrap()
            .preserves_active_consumer());
        assert!(!measured
            .pipe_liveness_for(&population[2])
            .unwrap()
            .preserves_active_consumer());

        for mutation in 0..5 {
            let mut changed = activity.clone();
            let mut observation = snapshot.clone();
            match mutation {
                0 => changed.source = "ps_lifetime_fallback".to_string(),
                1 => changed.start_id = StartId::from_linux("test-boot-id", 999, 6103),
                2 => changed.requested_window_ms = 1000,
                3 => observation.boot_id = Some("different-boot".to_string()),
                4 => {
                    observation.processes.get_mut(&6103).unwrap().identity_verified = false;
                }
                _ => unreachable!(),
            }
            measured.activity.insert(6103, changed);
            measured.prepare_pipe_liveness(&eligible, true, &observation);
            assert!(!measured
                .pipe_liveness_for(&population[0])
                .unwrap()
                .preserves_active_consumer(), "mutation {mutation}");
        }
        measured.activity.clear();
        measured.prepare_pipe_liveness(&eligible, true, &snapshot);
        let unknown = measured.pipe_liveness_for(&population[0]).unwrap();
        assert_eq!(unknown.readers.len(), 1);
        assert!(unknown.path.is_empty());
        assert!(unknown.active_consumer.is_none());
    }

    fn configured_signature_scorer(priors: SignaturePriors) -> Scorer {
        let mut signatures = SignatureDatabase::new();
        signatures
            .add(
                SupervisorSignature::new("worker", SupervisorCategory::Other)
                    .with_process_patterns(vec![r"^worker$"])
                    .with_confidence(1.0)
                    .with_priors(priors),
            )
            .unwrap();
        let mut scorer = scorer(signatures);
        // The supported custom policy reaches the exact-name match at 0.85.
        // Production's default 0.90 threshold and matching context are unchanged.
        scorer.fast_path = FastPathConfig::with_threshold(0.85);
        scorer
    }

    fn strongly_abandoned_signature() -> SignaturePriors {
        SignaturePriors {
            useful: Some(BetaParams::new(1.0, 999.0)),
            useful_bad: Some(BetaParams::new(1.0, 999.0)),
            abandoned: Some(BetaParams::new(997.0, 3.0)),
            zombie: Some(BetaParams::new(1.0, 999.0)),
        }
    }

    #[test]
    fn configured_signature_cannot_discard_fresh_cpu_or_io_likelihoods() {
        let process = record(1234, "worker", "worker --job", FOUR_DAYS);
        for feature in ["cpu", "io_active"] {
            let mut measured = configured_signature_scorer(strongly_abandoned_signature());
            let mut activity =
                ProcessActivity::unavailable(&process, Duration::from_millis(500), "fixture");
            activity.source = "procfs_window".to_string();
            if feature == "cpu" {
                activity.cpu_percent = Some(80.0);
                activity.cpu_ticks = Some(40);
                activity.cpu_window_seconds = Some(0.5);
                activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Observed {
                    occupancy: 0.8,
                    effective_cores: 1.0,
                    effective_parallelism: 1.0,
                    online_cores: 1,
                    affinity_cores: 1,
                    affinity_parallelism: None,
                    quota_cores: None,
                    threads: 1,
                });
                activity.cpu_error = None;
            } else {
                activity.io_active = Some(true);
                activity.read_bytes_per_second = Some(4096.0);
                activity.write_bytes_per_second = Some(1024.0);
                activity.io_window_seconds = Some(0.5);
                activity.io_error = None;
            }
            measured.activity_window = Some(Duration::from_millis(500));
            measured.activity.insert(process.pid.0, activity);
            let mut reference = measured.clone();
            reference.fast_path = FastPathConfig::disabled();
            let incoming = Evidence {
                cpu: Some(CpuEvidence::Fraction { occupancy: 0.0 }),
                io_active: Some(false),
                ..Evidence::default()
            };
            let expected = reference
                .score_with_desktop(&process, incoming.clone(), None)
                .unwrap();
            let actual = measured
                .score_with_desktop(&process, incoming, None)
                .unwrap();
            let shortcut = try_signature_fast_path(
                &measured.fast_path,
                actual.signature.as_ref(),
                process.pid.0,
            )
            .unwrap()
            .unwrap();

            assert!(!actual.fast_path_used);
            assert_eq!(actual.prior_source, "signature");
            assert_eq!(
                actual.fast_path_skip_reason,
                Some("conflicting_current_evidence")
            );
            assert_eq!(actual.posterior, expected.posterior);
            assert_eq!(actual.ledger.posterior, expected.ledger.posterior);
            assert!(actual
                .posterior
                .evidence_terms
                .iter()
                .any(|term| term.feature == feature));
            // The class can still agree while prior-only confidence would be
            // higher and could pass a downstream action threshold incorrectly.
            assert_eq!(actual.ledger.classification, shortcut.classification);
            assert!(
                actual.posterior.posterior.abandonment_probability()
                    < shortcut.posterior.posterior.abandonment_probability()
            );
            assert!(!actual.ledger.why_summary.contains("bypassed"));
        }
    }

    #[test]
    fn configured_signature_cannot_hide_zombie_or_disk_sleep_state() {
        let measured = configured_signature_scorer(SignaturePriors::likely_useful());
        let mut reference = measured.clone();
        reference.fast_path = FastPathConfig::disabled();
        for state in [ProcessState::Zombie, ProcessState::DiskSleep] {
            let mut process = record(1234, "worker", "worker --job", FOUR_DAYS);
            process.state = state;
            let evidence = Evidence {
                state_flag: Evidence::from_snapshot(&process).state_flag,
                ..Evidence::default()
            };
            let expected = reference
                .score_with_desktop(&process, evidence.clone(), None)
                .unwrap();
            let actual = measured
                .score_with_desktop(&process, evidence, None)
                .unwrap();
            assert!(!actual.fast_path_used);
            assert_eq!(
                actual.fast_path_skip_reason,
                Some("conflicting_current_evidence")
            );
            assert_eq!(actual.posterior, expected.posterior);
            assert!(actual
                .ledger
                .posterior
                .evidence_terms
                .iter()
                .any(|term| term.feature == "state_flag"));
            if state == ProcessState::Zombie {
                assert_eq!(actual.ledger.classification, Classification::Zombie);
            }
        }
    }

    #[test]
    fn agreeing_signature_keeps_probability_updates_and_complete_ledger() {
        let measured = configured_signature_scorer(SignaturePriors {
            useful: Some(BetaParams::new(90.0, 10.0)),
            useful_bad: Some(BetaParams::new(3.0, 97.0)),
            abandoned: Some(BetaParams::new(4.0, 96.0)),
            zombie: Some(BetaParams::new(3.0, 97.0)),
        });
        let process = record(1234, "worker", "worker --job", FOUR_DAYS);
        let actual = measured
            .score_with_desktop(
                &process,
                Evidence {
                    io_active: Some(true),
                    ..Evidence::default()
                },
                None,
            )
            .unwrap();
        let shortcut = try_signature_fast_path(
            &measured.fast_path,
            actual.signature.as_ref(),
            process.pid.0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(actual.ledger.classification, shortcut.classification);
        assert!(!actual.fast_path_used);
        assert_eq!(
            actual.fast_path_skip_reason,
            Some("current_evidence_changes_posterior")
        );
        assert_ne!(actual.posterior.posterior, shortcut.posterior.posterior);
        assert!(actual
            .ledger
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature == "io_active"));
    }

    #[test]
    fn unknown_window_cannot_validate_signature_or_restore_stale_activity() {
        let mut process = record(1234, "worker", "worker --job", FOUR_DAYS);
        process.cpu_percent = 90.0;
        let mut measured = configured_signature_scorer(strongly_abandoned_signature());
        measured.collect_activity(&[], Duration::from_millis(500));
        let mut reference = measured.clone();
        reference.fast_path = FastPathConfig::disabled();
        let incoming = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.9 }),
            io_active: Some(true),
            runtime_seconds: Some(process.elapsed.as_secs_f64()),
            ..Evidence::default()
        };
        let expected = reference
            .score_with_desktop(&process, incoming.clone(), None)
            .unwrap();
        let actual = measured
            .score_with_desktop(&process, incoming, None)
            .unwrap();
        assert!(!actual.fast_path_used);
        assert_eq!(actual.fast_path_skip_reason, Some("no_current_evidence"));
        assert_eq!(actual.posterior, expected.posterior);
        assert!(actual
            .posterior
            .evidence_terms
            .iter()
            .all(|term| term.feature != "cpu" && term.feature != "io_active"));
        let activity = actual.activity.as_ref().unwrap();
        assert!(activity.cpu_percent.is_none());
        assert!(activity.io_active.is_none());
        assert!(actual
            .ledger
            .top_evidence
            .iter()
            .any(|line| line.contains("CPU unavailable") && line.contains("I/O unavailable")));

        let empty = measured
            .score_with_desktop(&process, Evidence::default(), None)
            .unwrap();
        assert!(!empty.fast_path_used);
        assert_eq!(empty.fast_path_skip_reason, Some("no_current_evidence"));
        assert!(empty
            .posterior
            .evidence_terms
            .iter()
            .all(|term| term.feature == "prior"));
    }

    #[test]
    fn unmodeled_reading_does_not_verify_signature() {
        let process = record(1234, "worker", "worker --job", FOUR_DAYS);
        let mut measured = configured_signature_scorer(SignaturePriors::likely_useful());
        measured.priors.classes.useful.io_active_beta = None;
        measured.priors.classes.useful_bad.io_active_beta = None;
        measured.priors.classes.abandoned.io_active_beta = None;
        measured.priors.classes.zombie.io_active_beta = None;
        let actual = measured
            .score_with_desktop(
                &process,
                Evidence {
                    io_active: Some(true),
                    ..Evidence::default()
                },
                None,
            )
            .unwrap();
        assert!(!actual.fast_path_used);
        assert_eq!(actual.fast_path_skip_reason, Some("no_current_evidence"));
    }

    #[test]
    fn configured_signature_cannot_bypass_evidence_validation_errors() {
        let measured = configured_signature_scorer(strongly_abandoned_signature());
        let process = record(1234, "worker", "worker --job", FOUR_DAYS);
        for evidence in [
            Evidence {
                cpu: Some(CpuEvidence::Fraction {
                    occupancy: f64::NAN,
                }),
                ..Evidence::default()
            },
            Evidence {
                state_flag: Some(usize::MAX),
                ..Evidence::default()
            },
        ] {
            assert!(measured
                .score_with_desktop(&process, evidence, None)
                .is_none());
        }
    }

    #[test]
    fn windowed_activity_overrides_lifetime_cpu_and_cumulative_io_evidence() {
        let mut process = record(1234, "worker", "worker", FOUR_DAYS);
        process.cpu_percent = 90.0;
        let incoming = Evidence {
            io_active: Some(true),
            ..Evidence::from_snapshot(&process)
        };
        let reference = scorer(SignatureDatabase::new());
        let expected = reference
            .score_with_desktop(
                &process,
                Evidence {
                    cpu: Some(CpuEvidence::Fraction { occupancy: 0.0 }),
                    io_active: Some(false),
                    ..incoming.clone()
                },
                None,
            )
            .unwrap();
        let stale = reference
            .score_with_desktop(&process, incoming.clone(), None)
            .unwrap();
        let mut measured = scorer(SignatureDatabase::new());
        measured.activity_window = Some(Duration::from_millis(500));
        measured
            .activity
            .insert(process.pid.0, sampled_idle(&process));
        let actual = measured
            .score_with_desktop(&process, incoming, None)
            .unwrap();
        assert_eq!(actual.posterior.posterior, expected.posterior.posterior);
        assert_ne!(actual.posterior.posterior, stale.posterior.posterior);
        let activity = actual.activity.as_ref().unwrap();
        assert_eq!(activity.cpu_percent, Some(0.0));
        assert_eq!(activity.io_active, Some(false));
        assert!(actual
            .ledger
            .top_evidence
            .iter()
            .any(|line| line.contains("procfs_window") && line.contains("over 0.500s")));
    }

    #[test]
    fn replayed_quota_busy_cpu_uses_recorded_capacity_and_preserves_display_percent() {
        let process = record(1234, "worker", "worker", FOUR_DAYS);
        let measured = scorer(SignatureDatabase::new());
        let mut observations = measured.recorded_observations(&process, None);
        let mut activity = sampled_idle(&process);
        activity.cpu_percent = Some(10.0);
        activity.cpu_ticks = Some(5);
        activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Observed {
            occupancy: 1.0,
            effective_cores: 0.1,
            effective_parallelism: 0.1,
            online_cores: 32,
            affinity_cores: 8,
            affinity_parallelism: None,
            quota_cores: Some(0.1),
            threads: 4,
        });
        observations.activity = Some(activity);
        // The serialized observation, not this test machine's CPU limits,
        // determines the replay posterior and its explanation.
        let observations: ScoringObservations =
            serde_json::from_slice(&serde_json::to_vec(&observations).unwrap()).unwrap();
        let incoming = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.1 }),
            ..Evidence::default()
        };
        let actual = measured
            .score_recorded(&process, incoming, observations)
            .unwrap();
        let expected = measured
            .score_with_desktop(
                &process,
                Evidence {
                    cpu: Some(CpuEvidence::Fraction { occupancy: 1.0 }),
                    io_active: Some(false),
                    ..Evidence::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(actual.posterior.posterior, expected.posterior.posterior);
        assert_eq!(actual.activity.as_ref().unwrap().cpu_percent, Some(10.0));
        assert_eq!(
            actual.activity.as_ref().unwrap().cpu_occupancy_fraction(),
            Some(1.0)
        );
        assert!(actual
            .ledger
            .top_evidence
            .iter()
            .any(|line| line.contains("CPU occupancy 100.00%") && line.contains("0.100")));
    }

    #[test]
    fn windowed_cpu_does_not_support_abandonment_of_an_idle_normal_server() {
        let scorer = scorer_for_defaults();
        let server = record(1234, "postgres", "postgres", FOUR_DAYS);
        let build = record(2345, "cargo", "cargo build", FOUR_DAYS);
        let vite = record(3456, "node", "node /app/node_modules/.bin/vite", FOUR_DAYS);
        for process in [&server, &vite, &build] {
            for percent in [0.0, 2.0, 10.0, 40.0, 80.0] {
                let mut sample = sampled_idle(process);
                sample.cpu_percent = Some(percent);
                sample.cpu_ticks = Some((percent / 2.0) as u64);
                if let Some(crate::collect::CpuOccupancy::Observed { occupancy, .. }) =
                    &mut sample.cpu_occupancy
                {
                    *occupancy = percent / 100.0;
                }
                let mut observations = scorer.recorded_observations(process, None);
                observations.activity = Some(sample);
                let score = scorer
                    .score_recorded(process, Evidence::from_snapshot(process), observations)
                    .unwrap();
                let cpu = score
                    .posterior
                    .evidence_terms
                    .iter()
                    .find(|term| term.feature == "cpu")
                    .unwrap()
                    .log_likelihood;
                if process.pid != build.pid {
                    assert!(cpu.abandoned <= cpu.useful && cpu.abandoned <= cpu.useful_bad);
                    assert_eq!(cpu.zombie, cpu.abandoned);
                    if percent == 0.0 {
                        assert_eq!(cpu.abandoned, cpu.useful);
                        assert_eq!(cpu.abandoned, cpu.useful_bad);
                    } else if percent == 80.0 {
                        assert!(cpu.useful > cpu.abandoned);
                    }
                } else if percent == 0.0 {
                    assert!(
                        cpu.abandoned > cpu.useful,
                        "idle build still carries evidence"
                    );
                }
                assert_eq!(
                    score
                        .ledger
                        .top_evidence
                        .iter()
                        .any(|line| line.contains("expects idle CPU")),
                    process.pid != build.pid
                );
            }
        }
    }

    #[test]
    fn quiet_disk_io_expectation_changes_only_measured_silence() {
        let make_scorer = |idle_disk_io_normal| {
            let mut db = SignatureDatabase::new();
            db.add(
                SupervisorSignature::new("service", SupervisorCategory::Other)
                    .with_process_patterns(vec![r"^service$"])
                    .with_expectations(ProcessExpectations {
                        idle_disk_io_normal,
                        ..Default::default()
                    }),
            )
            .unwrap();
            scorer(db)
        };
        let baseline = make_scorer(false);
        let candidate = make_scorer(true);
        let process = record(1234, "service", "service", FOUR_DAYS);
        for case in [
            "idle",
            "legacy",
            "active",
            "missing",
            "snapshot",
            "partial",
            "conflicting",
            "short",
        ] {
            let mut observations = baseline.recorded_observations(&process, None);
            let mut sample = sampled_idle(&process);
            match case {
                "active" => {
                    sample.io_active = Some(true);
                    sample.io_read_bytes = Some(4096);
                    sample.read_bytes_per_second = Some(8192.0);
                }
                "missing" => {
                    sample.io_active = None;
                    sample.io_error = Some("counter unavailable".into());
                }
                "legacy" => {
                    sample.io_read_bytes = None;
                    sample.io_write_bytes = None;
                }
                "partial" => sample.read_bytes_per_second = None,
                "conflicting" => sample.io_write_bytes = Some(4096),
                "short" => sample.io_window_seconds = Some(0.05),
                _ => {}
            }
            if case != "snapshot" {
                observations.activity = Some(sample);
            }
            let evidence = Evidence {
                io_active: Some(false),
                ..Evidence::from_snapshot(&process)
            };
            let original = baseline
                .score_recorded(&process, evidence.clone(), observations.clone())
                .unwrap();
            let adjusted = candidate
                .score_recorded(&process, evidence, observations)
                .unwrap();
            assert_eq!(
                adjusted
                    .ledger
                    .top_evidence
                    .iter()
                    .any(|message| message.contains("can wait without disk I/O")),
                matches!(case, "idle" | "legacy"),
                "{case}"
            );
            if matches!(case, "idle" | "legacy") {
                assert!(
                    adjusted.posterior.posterior.abandonment_probability()
                        < original.posterior.posterior.abandonment_probability()
                );
                for (before, after) in original
                    .posterior
                    .evidence_terms
                    .iter()
                    .zip(&adjusted.posterior.evidence_terms)
                {
                    if before.feature == "io_active" {
                        let ll = after.log_likelihood;
                        assert!(ll.useful.min(ll.useful_bad) >= ll.abandoned.max(ll.zombie));
                    } else {
                        assert_eq!(before, after);
                    }
                }
            } else {
                assert_eq!(
                    original.posterior.evidence_terms, adjusted.posterior.evidence_terms,
                    "{case}"
                );
                assert_eq!(
                    original.posterior.posterior, adjusted.posterior.posterior,
                    "{case}"
                );
                assert_eq!(
                    adjusted
                        .posterior
                        .evidence_terms
                        .iter()
                        .any(|term| term.feature == "io_active"),
                    case != "missing"
                );
            }
        }
    }

    #[test]
    fn idle_normal_rule_requires_a_window_and_preserves_non_cpu_evidence() {
        let scorer = scorer_for_defaults();
        let mut process = record(1234, "postgres", "postgres", FOUR_DAYS);
        process.state = crate::collect::ProcessState::Zombie;
        let mut evidence = Evidence::from_snapshot(&process);
        evidence.cpu = Some(CpuEvidence::Fraction { occupancy: 0.0 });
        let baseline = scorer
            .score_with_desktop(&process, evidence.clone(), None)
            .unwrap();
        let raw_cpu = baseline
            .posterior
            .evidence_terms
            .iter()
            .find(|term| term.feature == "cpu")
            .unwrap();
        assert!(raw_cpu.log_likelihood.abandoned > raw_cpu.log_likelihood.useful);

        let mut observations = scorer.recorded_observations(&process, None);
        observations.activity = Some(sampled_idle(&process));
        let score = scorer
            .score_recorded(&process, evidence, observations)
            .unwrap();
        for feature in ["runtime", "state_flag"] {
            let before = baseline
                .posterior
                .evidence_terms
                .iter()
                .find(|term| term.feature == feature)
                .unwrap();
            let after = score
                .posterior
                .evidence_terms
                .iter()
                .find(|term| term.feature == feature)
                .unwrap();
            assert_eq!(before.log_likelihood, after.log_likelihood);
        }
    }

    #[test]
    fn missing_or_invalid_recorded_capacity_never_becomes_idle_or_one_core_evidence() {
        let process = record(1234, "worker", "worker", FOUR_DAYS);
        let measured = scorer(SignatureDatabase::new());
        for invalid in [
            "missing",
            "unavailable",
            "zero_capacity",
            "zero_threads",
            "nonfinite",
            "wrong_fraction",
            "wrong_parallelism",
            "short_window",
        ] {
            let mut activity = sampled_idle(&process);
            activity.cpu_percent = Some(10.0);
            activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Observed {
                occupancy: 1.0,
                effective_cores: 0.1,
                effective_parallelism: 0.1,
                online_cores: 8,
                affinity_cores: 2,
                affinity_parallelism: None,
                quota_cores: Some(0.1),
                threads: 1,
            });
            match invalid {
                "missing" => activity.cpu_occupancy = None,
                "unavailable" => {
                    activity.cpu_occupancy = Some(crate::collect::CpuOccupancy::Unavailable {
                        reason: "quota hierarchy unreadable".into(),
                    })
                }
                "short_window" => activity.cpu_window_seconds = Some(0.1),
                _ => {
                    if let Some(crate::collect::CpuOccupancy::Observed {
                        affinity_cores,
                        threads,
                        occupancy,
                        effective_parallelism,
                        ..
                    }) = activity.cpu_occupancy.as_mut()
                    {
                        match invalid {
                            "zero_capacity" => *affinity_cores = 0,
                            "zero_threads" => *threads = 0,
                            "nonfinite" => *occupancy = f64::NAN,
                            "wrong_fraction" => *occupancy = 0.1,
                            "wrong_parallelism" => *effective_parallelism = 1.0,
                            _ => unreachable!(),
                        }
                    }
                }
            }
            let mut observations = measured.recorded_observations(&process, None);
            observations.activity = Some(activity);
            let actual = measured
                .score_recorded(
                    &process,
                    Evidence {
                        cpu: Some(CpuEvidence::Fraction { occupancy: 0.1 }),
                        ..Evidence::default()
                    },
                    observations,
                )
                .unwrap();
            assert!(
                actual
                    .posterior
                    .evidence_terms
                    .iter()
                    .all(|term| term.feature != "cpu"),
                "{invalid}"
            );
            assert_eq!(
                actual.activity.as_ref().unwrap().cpu_percent,
                Some(10.0),
                "{invalid}"
            );
            assert_eq!(
                actual.activity.as_ref().unwrap().cpu_occupancy_fraction(),
                None,
                "{invalid}"
            );
            assert!(
                actual
                    .ledger
                    .top_evidence
                    .iter()
                    .any(|line| line.contains("CPU occupancy unavailable")),
                "{invalid}"
            );
        }
    }

    #[test]
    fn explicit_native_cpu_fallback_retains_its_label_and_fraction() {
        let process = record(1234, "worker", "worker", FOUR_DAYS);
        let mut activity = sampled_idle(&process);
        activity.source = "ps_lifetime_fallback".into();
        activity.cpu_percent = Some(40.0);
        activity.cpu_occupancy = None;
        activity.cpu_window_seconds = None;
        assert_eq!(activity.cpu_occupancy_fraction(), Some(0.4));
        activity.source = "unknown".into();
        assert_eq!(activity.cpu_occupancy_fraction(), None);
    }

    #[test]
    fn missing_activity_suppresses_terms_instead_of_claiming_idle_or_using_lifetime() {
        let mut process = record(1234, "worker", "worker", FOUR_DAYS);
        process.cpu_percent = 90.0;
        let incoming = Evidence {
            io_active: Some(true),
            ..Evidence::from_snapshot(&process)
        };
        let reference = scorer(SignatureDatabase::new());
        let expected = reference
            .score_with_desktop(
                &process,
                Evidence {
                    cpu: None,
                    io_active: None,
                    ..incoming.clone()
                },
                None,
            )
            .unwrap();
        let mut measured = scorer(SignatureDatabase::new());
        // An enabled but empty batch must not lend old evidence to a later PID.
        measured.collect_activity(&[], Duration::from_millis(500));
        let actual = measured
            .score_with_desktop(&process, incoming, None)
            .unwrap();
        assert_eq!(actual.posterior.posterior, expected.posterior.posterior);
        let activity = actual.activity.unwrap();
        assert!(activity.cpu_percent.is_none());
        assert!(activity.io_active.is_none());
        assert!(activity.cpu_error.unwrap().contains("not included"));
        assert!(actual
            .ledger
            .top_evidence
            .iter()
            .any(|line| line.contains("CPU unavailable") && line.contains("I/O unavailable")));
    }

    #[test]
    fn activity_cache_refuses_reused_pid_and_changed_owner() {
        let process = record(1234, "worker", "worker", FOUR_DAYS);
        let mut measured = scorer(SignatureDatabase::new());
        measured.activity_window = Some(Duration::from_millis(500));
        measured
            .activity
            .insert(process.pid.0, sampled_idle(&process));
        assert_eq!(
            measured.activity_for(&process).unwrap().cpu_percent,
            Some(0.0)
        );
        for changed in ["start", "owner"] {
            let mut replacement = process.clone();
            if changed == "start" {
                replacement.start_id = StartId::from_linux("test-boot-id", 98765, process.pid.0);
            } else {
                replacement.uid += 1;
            }
            let activity = measured.activity_for(&replacement).unwrap();
            assert!(activity.cpu_percent.is_none());
            assert!(activity.io_active.is_none());
            assert!(activity
                .cpu_error
                .unwrap()
                .contains("different process incarnation"));
        }
    }

    #[test]
    fn zero_window_clears_old_samples_and_restores_snapshot_scoring() {
        let mut process = record(1234, "worker", "worker", FOUR_DAYS);
        process.cpu_percent = 90.0;
        let reference = scorer(SignatureDatabase::new());
        let expected = reference
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        let mut measured = scorer(SignatureDatabase::new());
        measured.activity_window = Some(Duration::from_millis(500));
        measured
            .activity
            .insert(process.pid.0, sampled_idle(&process));
        measured.collect_activity(&[&process], Duration::ZERO);
        assert!(measured.activity.is_empty());
        let actual = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        assert!(actual.activity.is_none());
        assert_eq!(actual.posterior.posterior, expected.posterior.posterior);
    }

    #[test]
    fn normal_run_lifetime_is_lognormal_between_typical_and_max() {
        let build = ProcessExpectations::short_lived_task(); // typical 300 s, max 3600 s
        let at = |secs: f64| normal_run_finished_by(&build, secs).expect("lifetime model");
        assert!((at(300.0) - 0.5).abs() < 1e-9, "median");
        assert!((at(3600.0) - 0.99).abs() < 1e-6, "99th percentile");
        assert_eq!(at(0.0), 0.0);
        assert!(at(10.0) < 0.01);
        assert!(at(30.0) < at(300.0) && at(300.0) < at(3600.0) && at(3600.0) < at(86_400.0));

        assert_eq!(
            normal_run_finished_by(&ProcessExpectations::default(), 1000.0),
            None
        );
        let daemon = ProcessExpectations::daemon();
        assert_eq!(normal_run_finished_by(&daemon, 1000.0), None);
    }

    /// Young and stuck instances of the same command: the young one must stay well
    /// below an ungated stuck-signature prior (and an active young run must stay
    /// below the 0.7 candidate threshold), while the stuck one keeps the full prior.
    fn assert_age_gated(comm: &str, cmd: &str, signature: &str, young_secs: u64, stuck_secs: u64) {
        let scorer = scorer(SignatureDatabase::with_defaults());
        let young = record(5200, comm, cmd, Duration::from_secs(young_secs));
        let mut active_young = young.clone();
        active_young.cpu_percent = 65.0;
        let stuck = record(5201, comm, cmd, Duration::from_secs(stuck_secs));
        let young_score = scorer
            .score_with_desktop(&young, Evidence::from_snapshot(&young), None)
            .expect("score");
        let active_young_score = scorer
            .score_with_desktop(&active_young, Evidence::from_snapshot(&active_young), None)
            .expect("score");
        let stuck_score = scorer
            .score_with_desktop(&stuck, Evidence::from_snapshot(&stuck), None)
            .expect("score");

        assert_eq!(
            young_score
                .signature
                .as_ref()
                .map(|m| m.signature.name.as_str()),
            Some(signature)
        );
        let young_weight = young_score.signature_age_weight.expect("age weight");
        let stuck_weight = stuck_score.signature_age_weight.expect("age weight");
        assert!(young_weight < 0.5, "{signature}: {young_weight}");
        assert!(stuck_weight > 0.99, "{signature}: {stuck_weight}");

        let young_p = young_score.posterior.posterior.abandonment_probability();
        let active_young_p = active_young_score
            .posterior
            .posterior
            .abandonment_probability();
        let stuck_p = stuck_score.posterior.posterior.abandonment_probability();
        assert!(
            active_young_p < 0.7,
            "{signature}: an active young run is a plan candidate: {:?}",
            active_young_score.posterior.posterior
        );
        assert!(
            young_p < stuck_p,
            "{signature}: young run ({young_p}) inherited the stuck prior ({stuck_p})"
        );
        assert!(
            stuck_p >= 0.7,
            "{signature}: a stuck run lost its prior: {:?}",
            stuck_score.posterior.posterior
        );
    }

    /// hetzner1, 2026-10-04: a 265 s old `rch exec -- cargo build` (the build runs on a
    /// remote worker, so the local process idles without a TTY) scored P(abandoned or
    /// zombie) 0.85, carried by the cargo-build signature's "likely abandoned" prior
    /// (+2.0 bits). It is now an rch client (remote runs can last hours) whose prior
    /// only applies once it has outlived a normal run.
    #[test]
    fn young_remote_build_does_not_inherit_the_stuck_build_prior() {
        assert_age_gated(
            "rch",
            "rch exec -- cargo build -p fs-cli --bin frankensim",
            "rch-exec",
            265,
            6 * 3600,
        );
    }

    #[test]
    fn young_local_build_does_not_inherit_the_stuck_build_prior() {
        assert_age_gated(
            "cargo",
            "cargo build --release",
            "cargo-build",
            265,
            3 * 3600,
        );
    }

    /// The age gate never touches a signature whose processes are expected to keep
    /// running, nor one that states no lifetime.
    #[test]
    fn age_gate_only_applies_to_left_behind_signatures_with_lifetimes() {
        let mut db = SignatureDatabase::new();
        let no_lifetime = SupervisorSignature::new("stuck-thing", SupervisorCategory::Other)
            .with_process_patterns(vec!["^stuckthing$"])
            .with_priors(SignaturePriors::likely_abandoned());
        db.add(no_lifetime).expect("add");
        let scorer = scorer(db);
        let proc = record(
            5300,
            "stuckthing",
            "stuckthing --serve",
            Duration::from_secs(60),
        );
        let score = scorer
            .score_with_desktop(&proc, Evidence::from_snapshot(&proc), None)
            .expect("score");
        assert_eq!(score.prior_source, "signature");
        assert_eq!(score.signature_age_weight, None);

        let defaults = scorer_for_defaults();
        let vite = record(
            5301,
            "node",
            "node /app/node_modules/.bin/vite",
            Duration::from_secs(60),
        );
        let score = defaults
            .score_with_desktop(&vite, Evidence::from_snapshot(&vite), None)
            .expect("score");
        assert_eq!(score.signature_age_weight, None);
    }

    fn scorer_for_defaults() -> Scorer {
        scorer(SignatureDatabase::with_defaults())
    }

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
    use super::provenance::{build_provenance_bundle_with, ProcessProvenance};
    use super::*;
    use crate::collect::SharedResourceGraph;
    use crate::mock_process::MockProcessBuilder;
    use pt_common::{
        AncestorEntry, LineageCollectionMethod, LockMechanism, ProvenanceConfidence,
        RawLineageEvidence, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
        ResourceKind, ResourceState, SupervisorEvidence, SupervisorKind,
    };
    use std::collections::HashMap;

    fn provenance_identity(process: &ProcessRecord) -> pt_common::ProcessIdentity {
        pt_common::ProcessIdentity::full(
            process.pid.0,
            process.start_id.clone(),
            process.uid,
            process.pgid,
            process.sid,
            pt_common::IdentityQuality::Full,
        )
    }

    fn observed_process(process: &ProcessRecord, target: bool) -> ProcessProvenance {
        let mut observed_lineage = lineage(process.pid.0, process.ppid.0, None);
        observed_lineage.uid = process.uid;
        observed_lineage.pgid = process.pgid.unwrap_or(0);
        observed_lineage.sid = process.sid.unwrap_or(0);
        ProcessProvenance {
            identity: provenance_identity(process),
            lineage: target.then_some(observed_lineage),
            lineage_error: None,
            resources: Vec::new(),
            network_error: None,
            unavailable: Vec::new(),
        }
    }

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
    fn filtered_and_sampled_targets_keep_full_population_dependencies() {
        let population = vec![
            MockProcessBuilder::new()
                .pid(100)
                .ppid(10)
                .comm("target")
                .elapsed_secs(7200)
                .build(),
            MockProcessBuilder::new()
                .pid(200)
                .ppid(10)
                .comm("protected-peer")
                .elapsed_secs(7200)
                .build(),
            MockProcessBuilder::new()
                .pid(300)
                .ppid(100)
                .comm("young-child")
                .elapsed_secs(1)
                .build(),
            MockProcessBuilder::new()
                .pid(400)
                .ppid(10)
                .uid(2000)
                .comm("other-user")
                .elapsed_secs(7200)
                .build(),
        ];
        let filter = crate::collect::ProtectedFilter::new(&[], &[], &[200], &[]).unwrap();
        let filtered = filter.filter_with_observations(
            &population,
            &Default::default(),
            |_| crate::collect::CgroupRole::Unknown,
            |_| None,
        );
        assert_eq!(filtered.filtered.len(), 1);
        let eligible: Vec<_> = filtered
            .passed
            .iter()
            .filter(|process| process.elapsed.as_secs() >= 3600)
            .collect();
        assert_eq!(eligible.len(), 2);
        let observe = |process: &ProcessRecord, target| {
            let mut observed = observed_process(process, target);
            let paths: &[&str] = match process.pid.0 {
                100 => &["/a.lock", "/c.lock"],
                200 => &["/a.lock", "/b.lock"],
                300 => &["/b.lock"],
                400 => &["/c.lock"],
                _ => unreachable!(),
            };
            observed.resources = paths
                .iter()
                .map(|path| lock_ev(process.pid.0, path, ResourceState::Active))
                .collect();
            Ok(observed)
        };
        let all = build_provenance_bundle_with(&eligible, &population, true, observe);
        let sampled = build_provenance_bundle_with(&eligible[..1], &population, true, observe);
        assert_eq!(all.population_count, 4);
        assert_eq!(sampled.target_identities.len(), 1);
        assert_eq!(
            sampled.lineages.len(),
            1,
            "peers are not additional scoring targets"
        );
        assert_eq!(sampled.children[&100], vec![300]);
        assert_eq!(
            sampled.resource_graph.co_holders(100),
            std::collections::HashSet::from([200, 400])
        );
        let mut all_estimate = derive_provenance_adjustment(100, &all);
        let mut sample_estimate = derive_provenance_adjustment(100, &sampled);
        assert_eq!(sample_estimate.blast_radius.total_affected, 3);
        assert_eq!(
            sample_estimate.blast_radius.direct.components.child_count,
            1
        );
        // Direct co-holders come from a set; compare their identities independently
        // of that set's iteration order when checking the two scoring populations.
        all_estimate
            .blast_radius
            .direct
            .blast_radius
            .affected_pids
            .sort_unstable();
        sample_estimate
            .blast_radius
            .direct
            .blast_radius
            .affected_pids
            .sort_unstable();
        assert_eq!(
            serde_json::to_value(&all_estimate).unwrap(),
            serde_json::to_value(&sample_estimate).unwrap(),
            "sampling changes scoring targets, not the observed dependency graph"
        );
        assert!(!feature_names(&sample_estimate).contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn partial_census_or_unreadable_unselected_peer_never_establishes_isolation() {
        let population = vec![
            MockProcessBuilder::new().pid(100).ppid(10).build(),
            MockProcessBuilder::new().pid(200).ppid(10).build(),
        ];
        let targets = [&population[0]];
        let complete =
            build_provenance_bundle_with(&targets, &population, true, |process, target| {
                Ok(observed_process(process, target))
            });
        assert!(feature_names(&derive_provenance_adjustment(100, &complete))
            .contains(&"provenance_blast_radius_low"));

        let partial =
            build_provenance_bundle_with(&targets, &population, false, |process, target| {
                Ok(observed_process(process, target))
            });
        let incomplete = derive_provenance_adjustment(100, &partial);
        assert!(!feature_names(&incomplete).contains(&"provenance_blast_radius_low"));
        assert!(incomplete
            .confidence_notes
            .iter()
            .any(|note| note.contains("process census is incomplete")));

        let unreadable =
            build_provenance_bundle_with(&targets, &population, true, |process, target| {
                if process.pid.0 == 200 {
                    Err("peer descriptors are not readable".to_string())
                } else {
                    Ok(observed_process(process, target))
                }
            });
        assert!(unreadable.network_errors.contains_key(&200));
        let unknown = derive_provenance_adjustment(100, &unreadable);
        assert!(!feature_names(&unknown).contains(&"provenance_blast_radius_low"));
        assert!(
            unknown.evidence_completeness
                < derive_provenance_adjustment(100, &complete).evidence_completeness
        );
    }

    #[test]
    fn provenance_rejects_replaced_peers_and_never_transfers_scoring_identity() {
        let population = vec![
            MockProcessBuilder::new().pid(100).ppid(10).build(),
            MockProcessBuilder::new().pid(200).ppid(10).build(),
        ];
        for mismatch in ["birth", "uid", "pgid", "sid"] {
            let bundle = build_provenance_bundle_with(
                &[&population[0]],
                &population,
                true,
                |process, target| {
                    let mut observed = observed_process(process, target);
                    observed.resources.push(lock_ev(
                        process.pid.0,
                        "/shared.lock",
                        ResourceState::Active,
                    ));
                    if process.pid.0 == 200 {
                        match mismatch {
                            "birth" => {
                                observed.identity.start_id =
                                    pt_common::StartId::from_linux("new-boot", 123, 200)
                            }
                            "uid" => observed.identity.uid += 1,
                            "pgid" => observed.identity.pgid = Some(999),
                            "sid" => observed.identity.sid = Some(999),
                            _ => unreachable!(),
                        }
                    }
                    Ok(observed)
                },
            );
            assert!(
                bundle.resource_graph.co_holders(100).is_empty(),
                "{mismatch}"
            );
            assert!(bundle.resource_unavailable.contains_key(&200), "{mismatch}");
            assert!(!feature_names(&derive_provenance_adjustment(100, &bundle))
                .contains(&"provenance_blast_radius_low"));
        }

        let mut scorer = Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        );
        scorer.provenance = Some(build_provenance_bundle_with(
            &[&population[0]],
            &population,
            true,
            |process, target| Ok(observed_process(process, target)),
        ));
        assert!(scorer
            .recorded_observations(&population[0], None)
            .provenance
            .is_some());
        assert!(scorer
            .recorded_observations(&population[1], None)
            .provenance
            .is_none());
        for mismatch in ["birth", "uid", "pgid", "sid", "ppid"] {
            let mut replaced = population[0].clone();
            match mismatch {
                "birth" => replaced.start_id = pt_common::StartId::from_linux("new-boot", 123, 100),
                "uid" => replaced.uid += 1,
                "pgid" => replaced.pgid = Some(999),
                "sid" => replaced.sid = Some(999),
                "ppid" => replaced.ppid = pt_common::ProcessId(999),
                _ => unreachable!(),
            }
            assert!(
                scorer
                    .recorded_observations(&replaced, None)
                    .provenance
                    .is_none(),
                "{mismatch}"
            );
        }
    }

    #[test]
    fn lineage_failures_keep_bound_resources_and_report_missing_ancestry() {
        let population = vec![
            MockProcessBuilder::new().pid(100).ppid(10).build(),
            MockProcessBuilder::new().pid(200).ppid(10).build(),
        ];
        for failure in ["unavailable", "parent_changed"] {
            let bundle = build_provenance_bundle_with(
                &[&population[0]],
                &population,
                true,
                |process, target| {
                    let mut observed = observed_process(process, target);
                    observed.resources.push(lock_ev(
                        process.pid.0,
                        "/shared.lock",
                        ResourceState::Active,
                    ));
                    if target {
                        if failure == "unavailable" {
                            observed.lineage = None;
                            observed.lineage_error = Some("ancestry unavailable".to_string());
                        } else {
                            observed.lineage.as_mut().unwrap().ppid = 999;
                        }
                    }
                    Ok(observed)
                },
            );
            assert!(!bundle.lineages.contains_key(&100));
            assert!(bundle.lineage_unavailable.contains_key(&100));
            assert_eq!(
                bundle.resource_graph.co_holders(100),
                std::collections::HashSet::from([200])
            );
            let adjustment = derive_provenance_adjustment(100, &bundle);
            assert_eq!(adjustment.orphaned, None);
            assert_eq!(adjustment.blast_radius.total_affected, 1);
            assert!(!feature_names(&adjustment)
                .iter()
                .any(|feature| feature.starts_with("provenance_ownership_")));
            assert!(adjustment
                .confidence_notes
                .iter()
                .any(|note| note.contains("lineage unavailable")));
        }
    }

    #[test]
    fn ambiguous_census_and_empty_targets_do_not_invent_complete_evidence() {
        let process = MockProcessBuilder::new().pid(100).ppid(10).build();
        let bundle = build_provenance_bundle_with(
            &[&process],
            &[process.clone(), process.clone()],
            true,
            |_, _| panic!("ambiguous identities must not be probed"),
        );
        assert!(!bundle.census_complete);
        assert!(bundle.target_identities.is_empty());
        assert!(bundle.resource_unavailable.contains_key(&100));
        let empty =
            build_provenance_bundle_with(&[], std::slice::from_ref(&process), true, |_, _| {
                panic!("no targets means no provenance work")
            });
        assert!(empty.resource_graph.resources.is_empty());
        assert!(empty.lineages.is_empty());
    }

    #[test]
    fn live_provenance_keeps_protected_holder_of_an_owned_childs_lock() {
        use std::process::{Child, Command, Stdio};
        struct OwnedChild(Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let held_path = temporary.path().join("provenance-held.lock");
        let held = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&held_path)
            .unwrap();
        let child = OwnedChild(
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::from(held.try_clone().unwrap()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let scan =
            crate::collect::quick_scan(&crate::collect::QuickScanOptions::default()).unwrap();
        let target = scan
            .processes
            .iter()
            .find(|process| process.pid.0 == child.0.id())
            .expect("owned child is present in the census");
        let parent = scan
            .processes
            .iter()
            .find(|process| process.pid.0 == std::process::id())
            .expect("protected test parent is present in the census");
        let filter = crate::collect::ProtectedFilter::new(&[], &[], &[parent.pid.0], &[]).unwrap();
        assert!(filter.is_protected(parent).is_some());
        let bundle = build_provenance_bundle(
            &[target],
            &scan.processes,
            scan.metadata.warnings.is_empty(),
        );
        assert!(
            bundle
                .resource_graph
                .co_holders(target.pid.0)
                .contains(&parent.pid.0),
            "the inherited held file must link to its protected holder: {:?}",
            bundle.resource_unavailable
        );
        assert!(!bundle.target_identities.contains_key(&parent.pid.0));
        let adjustment = derive_provenance_adjustment(target.pid.0, &bundle);
        assert!(adjustment.blast_radius.total_affected >= 1);
        assert!(!feature_names(&adjustment).contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn orphaned_low_blast_radius_elevates_abandonment_features() {
        // Reparented to init, still in its spawner's session: an orphan even without
        // a readable ancestor chain.
        let mut orphan = lineage(100, 1, None);
        orphan.sid = 90;
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(100, orphan)]),
            children: HashMap::new(),
            census_complete: true,
            ..Default::default()
        };

        let adjustment = derive_provenance_adjustment(100, &bundle);
        let features = feature_names(&adjustment);

        assert!(features.contains(&"provenance_ownership_orphaned"));
        assert!(features.contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn failed_network_probe_is_preserved_through_live_provenance_collection() {
        let missing = crate::mock_process::MockProcessBuilder::new()
            .pid(u32::MAX)
            .comm("missing-worker")
            .build();
        let bundle = build_provenance_bundle(&[&missing], std::slice::from_ref(&missing), true);
        assert!(bundle.network_errors.contains_key(&missing.pid.0));
        let adjustment = derive_provenance_adjustment(missing.pid.0, &bundle);
        assert!(!feature_names(&adjustment).contains(&"provenance_blast_radius_low"));
        assert!(adjustment.confidence_penalty_steps > 0);
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("network resource evidence unavailable")));
        assert!(!bundle.lineages.contains_key(&missing.pid.0));
        assert!(!feature_names(&adjustment)
            .iter()
            .any(|feature| feature.starts_with("provenance_ownership_")));
    }

    fn provenance_identity_fixture() -> (tempfile::TempDir, ProcessRecord) {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let process_dir = root.path().join("42");
        std::fs::create_dir(&process_dir).unwrap();
        std::fs::write(
            process_dir.join("stat"),
            "42 (owned fixture) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 123 0 0",
        )
        .unwrap();
        let process = crate::mock_process::MockProcessBuilder::new()
            .pid(42)
            .ppid(1)
            .uid(std::fs::metadata(&process_dir).unwrap().uid())
            .start_id(pt_common::StartId::from_linux(
                "12345678-1234-1234-1234-123456789abc",
                123,
                42,
            ))
            .build();
        (root, process)
    }

    #[test]
    fn provenance_requires_the_scanned_birth_boot_and_owner_before_collecting() {
        use super::provenance::with_provenance_identity;
        const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
        let (root, process) = provenance_identity_fixture();
        let collected = with_provenance_identity(root.path(), BOOT, &process, |expected| {
            assert_eq!(expected.start_id, process.start_id);
            assert_eq!(expected.uid, process.uid);
            vec![listener_ev(42, 8080)]
        })
        .unwrap();
        assert_eq!(collected.len(), 1);

        for change in ["birth", "boot", "owner", "embedded_pid", "unavailable_boot"] {
            let mut stale = process.clone();
            let mut boot = BOOT;
            match change {
                "birth" => stale.start_id = pt_common::StartId::from_linux(BOOT, 122, 42),
                "boot" => {
                    stale.start_id = pt_common::StartId::from_linux(
                        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        123,
                        42,
                    );
                }
                "owner" => stale.uid = stale.uid.wrapping_add(1),
                "embedded_pid" => stale.start_id = pt_common::StartId::from_linux(BOOT, 123, 43),
                "unavailable_boot" => boot = "unknown",
                _ => unreachable!(),
            }
            let mut collected = false;
            let observed = with_provenance_identity(root.path(), boot, &stale, |_| {
                collected = true;
            });
            assert!(observed.is_err(), "{change}");
            assert!(
                !collected,
                "must reject {change} before probing the replacement"
            );
        }
    }

    #[test]
    fn provenance_discards_all_edges_when_identity_changes_during_collection() {
        use super::provenance::with_provenance_identity;
        const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
        for change in ["birth", "directory", "unreadable"] {
            let (root, process) = provenance_identity_fixture();
            let process_dir = root.path().join("42");
            let observed = with_provenance_identity(root.path(), BOOT, &process, |_| {
                let resources = vec![listener_ev(42, 8080)];
                match change {
                    "birth" => std::fs::write(
                        process_dir.join("stat"),
                        "42 (replacement) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 124 0 0",
                    )
                    .unwrap(),
                    "directory" => {
                        std::fs::rename(&process_dir, root.path().join("old-process")).unwrap();
                        std::fs::create_dir(&process_dir).unwrap();
                        std::fs::copy(
                            root.path().join("old-process/stat"),
                            process_dir.join("stat"),
                        )
                        .unwrap();
                    }
                    "unreadable" => {
                        std::fs::rename(process_dir.join("stat"), process_dir.join("old-stat"))
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                resources
            });
            assert!(
                observed.is_err(),
                "{change} must discard the collected edges"
            );
        }
    }

    #[test]
    fn live_provenance_does_not_attach_a_current_process_to_a_stale_scan_record() {
        let pid = std::process::id();
        let stale = crate::mock_process::MockProcessBuilder::new()
            .pid(pid)
            .start_id(pt_common::StartId::from_linux(
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                0,
                pid,
            ))
            .build();
        let bundle = build_provenance_bundle(&[&stale], std::slice::from_ref(&stale), true);
        assert!(bundle.lineages.is_empty());
        assert!(bundle.resource_graph.process_resources.is_empty());
        assert_eq!(bundle.population_count, 1);
        assert!(bundle.target_identities.contains_key(&pid));
        assert!(bundle.lineage_unavailable.contains_key(&pid));
        assert!(bundle.network_errors.contains_key(&pid));
        assert!(bundle.resource_unavailable.contains_key(&pid));
        let adjustment = derive_provenance_adjustment(pid, &bundle);
        assert!(adjustment.evidence_terms.is_empty());
        assert!(adjustment.confidence_penalty_steps > 0);

        let mut scorer = Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        );
        scorer.provenance = Some(bundle);
        let observations = scorer.recorded_observations(&stale, None);
        let recorded = observations.provenance.as_ref().unwrap();
        assert!(recorded.evidence_terms.is_empty());
        assert!(recorded.confidence_penalty_steps > 0);
        assert!(recorded
            .confidence_notes
            .iter()
            .any(|note| note.contains("identity no longer matches the scan")));
        let measured = scorer
            .score_recorded(
                &stale,
                Evidence::from_snapshot(&stale),
                observations.clone(),
            )
            .unwrap()
            .ledger;
        let restored = serde_json::from_value(serde_json::to_value(observations).unwrap()).unwrap();
        scorer.provenance = None;
        let replayed = scorer
            .score_recorded(&stale, Evidence::from_snapshot(&stale), restored)
            .unwrap();
        assert_eq!(replayed.ledger, measured);
    }

    #[test]
    fn incomplete_network_graph_never_proves_isolation() {
        let mut orphan = lineage(100, 1, None);
        orphan.sid = 90;
        let mut bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(100, orphan), (200, lineage(200, 2, None))]),
            children: HashMap::new(),
            network_errors: HashMap::new(),
            census_complete: true,
            ..Default::default()
        };
        let complete = derive_provenance_adjustment(100, &bundle);
        assert!(feature_names(&complete).contains(&"provenance_blast_radius_low"));

        for unreadable_pid in [100, 200] {
            bundle.network_errors = HashMap::from([(
                unreadable_pid,
                "namespace descriptor table unavailable".to_string(),
            )]);
            let incomplete = derive_provenance_adjustment(100, &bundle);
            assert!(!feature_names(&incomplete).contains(&"provenance_blast_radius_low"));
            assert!(feature_names(&incomplete).contains(&"provenance_ownership_orphaned"));
            assert!(incomplete.evidence_completeness < complete.evidence_completeness);
            assert!(incomplete.confidence_penalty_steps > complete.confidence_penalty_steps);
            assert!(incomplete
                .confidence_notes
                .iter()
                .any(|note| note.contains("network resource")));
        }

        // Positive observations remain useful even when a different participant
        // could not be inspected. Missing evidence only forbids absence claims.
        bundle.resource_graph =
            SharedResourceGraph::from_evidence(&[(100, vec![listener_ev(100, 8080)])]);
        let incomplete = derive_provenance_adjustment(100, &bundle);
        assert!(feature_names(&incomplete).contains(&"provenance_active_listener"));
        assert!(!feature_names(&incomplete).contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn recorded_scoring_retains_unavailable_network_evidence() {
        let process = crate::mock_process::MockProcessBuilder::new()
            .pid(100)
            .ppid(90)
            .comm("worker")
            .elapsed(Duration::from_secs(7200))
            .build();
        let mut scorer = Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        );
        scorer.provenance = Some(ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(100, lineage(100, 90, None))]),
            children: HashMap::new(),
            network_errors: HashMap::from([(100, "unclassified socket inode".to_string())]),
            target_identities: HashMap::from([(100, provenance_identity(&process))]),
            target_ppids: HashMap::from([(100, process.ppid.0)]),
            census_complete: true,
            ..Default::default()
        });
        let observations = scorer.recorded_observations(&process, None);
        let measured = scorer
            .score_recorded(
                &process,
                Evidence::from_snapshot(&process),
                observations.clone(),
            )
            .unwrap()
            .ledger;
        let restored: ScoringObservations =
            serde_json::from_value(serde_json::to_value(observations).unwrap()).unwrap();
        let recorded_provenance = restored.provenance.as_ref().unwrap();
        assert!(!feature_names(recorded_provenance).contains(&"provenance_blast_radius_low"));
        assert!(recorded_provenance
            .confidence_notes
            .iter()
            .any(|note| note.contains("unclassified socket inode")));
        scorer.provenance = None;
        let replayed = scorer
            .score_recorded(&process, Evidence::from_snapshot(&process), restored)
            .unwrap();
        assert_eq!(replayed.ledger, measured);
    }

    /// Its own session leader under PID 1 with no readable chain (hidepid): as likely
    /// an init-started daemon as an orphan, so no orphan term, and lowered confidence.
    #[test]
    fn chainless_session_leader_under_init_is_not_scored_orphaned() {
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(100, lineage(100, 1, None))]),
            children: HashMap::new(),
            ..Default::default()
        };

        let adjustment = derive_provenance_adjustment(100, &bundle);
        let features = feature_names(&adjustment);

        assert!(!features.contains(&"provenance_ownership_orphaned"));
        assert!(adjustment.confidence_penalty_steps >= 1);
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("ancestor chain")));
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
            ..Default::default()
        };

        let features = feature_names(&derive_provenance_adjustment(400, &bundle)).join(",");
        assert!(
            features.contains("provenance_ownership_orphaned"),
            "{features}"
        );
        assert!(
            !features.contains("provenance_ownership_supervised"),
            "{features}"
        );
    }

    /// A job orphaned under `systemd --user` (a child subreaper) has ppid != 1, so the
    /// base orphan check misses it; the lineage's orphan term is what carries it.
    #[test]
    fn job_reparented_to_user_subreaper_gets_the_orphan_term() {
        let mut orphan = lineage(500, 2000, None);
        orphan.sid = 450;
        orphan.ancestors = vec![
            AncestorEntry {
                pid: 2000,
                comm: "systemd".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 1,
                comm: "systemd".to_string(),
                uid: 0,
            },
        ];
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[]),
            lineages: HashMap::from([(500, orphan)]),
            children: HashMap::new(),
            ..Default::default()
        };

        let features = feature_names(&derive_provenance_adjustment(500, &bundle)).join(",");
        assert!(
            features.contains("provenance_ownership_orphaned"),
            "{features}"
        );
    }

    fn adopted_job(ppid: u32) -> (ProcessRecord, RawLineageEvidence) {
        let process = crate::mock_process::MockProcessBuilder::new()
            .pid(500)
            .ppid(ppid)
            .pgid(450)
            .sid(450)
            .comm("worker")
            .cmd("worker --job")
            .elapsed(Duration::from_secs(7200))
            .build();
        let mut observed = lineage(500, ppid, None);
        observed.pgid = 450;
        observed.sid = 450;
        observed.ancestors = vec![AncestorEntry {
            pid: ppid,
            comm: "systemd".to_string(),
            uid: if ppid == 1 { 0 } else { process.uid },
        }];
        (process, observed)
    }

    fn scorer_with_lineage(process: &ProcessRecord, observed: RawLineageEvidence) -> Scorer {
        let mut scorer = Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        );
        scorer.provenance = Some(ProvenanceInferenceBundle {
            lineages: HashMap::from([(observed.pid, observed)]),
            target_identities: HashMap::from([(process.pid.0, provenance_identity(process))]),
            target_ppids: HashMap::from([(process.pid.0, process.ppid.0)]),
            population_count: 1,
            census_complete: true,
            ..Default::default()
        });
        scorer
    }

    #[test]
    fn subreaper_orphan_scores_like_an_orphan_of_init() {
        let mut init_posterior = None;
        let mut init_blast_radius = None;
        for ppid in [1, 2000] {
            let (process, observed) = adopted_job(ppid);
            let evidence = Evidence::from_snapshot(&process);
            assert_eq!(evidence.orphan, Some(ppid == 1));
            let mut scorer = scorer_with_lineage(&process, observed);
            scorer.provenance.as_mut().unwrap().resource_graph =
                SharedResourceGraph::from_evidence(&[
                    (500, vec![listener_ev(500, 8080)]),
                    (
                        600,
                        vec![
                            listener_ev(600, 8080),
                            lock_ev(600, "/shared.lock", ResourceState::Active),
                        ],
                    ),
                    (
                        700,
                        vec![lock_ev(700, "/shared.lock", ResourceState::Active)],
                    ),
                ]);
            let score = scorer
                .score_with_desktop(&process, evidence, None)
                .expect("the same adopted job must score under either reaper");
            assert_eq!(score.orphaned, Some(true));
            assert_eq!(
                score
                    .posterior
                    .evidence_terms
                    .iter()
                    .filter(|term| term.feature.contains("orphan"))
                    .map(|term| term.feature.as_str())
                    .collect::<Vec<_>>(),
                ["orphan"],
                "one orphan fact must produce exactly one likelihood"
            );
            assert_eq!(
                score
                    .ledger
                    .bayes_factors
                    .iter()
                    .filter(|term| term.feature.contains("orphan"))
                    .map(|term| term.feature.as_str())
                    .collect::<Vec<_>>(),
                ["orphan"],
                "the explanation must not contain contradictory orphan facts"
            );
            assert!(!feature_names(score.provenance.as_ref().unwrap())
                .contains(&"provenance_ownership_orphaned"));
            let blast_radius = &score.provenance.as_ref().unwrap().blast_radius;
            assert!(blast_radius.total_affected > 0);
            assert!(blast_radius.direct.components.is_orphan);
            if let Some(expected) = init_blast_radius {
                assert_eq!(blast_radius.risk_score, expected);
            } else {
                init_blast_radius = Some(blast_radius.risk_score);
            }
            if let Some(expected) = &init_posterior {
                assert_eq!(&score.posterior, expected);
            } else {
                init_posterior = Some(score.posterior.clone());
            }
        }
    }

    #[test]
    fn recognized_supervision_resolves_snapshot_orphan_guess() {
        for ppid in [1, 2000] {
            let (process, mut observed) = adopted_job(ppid);
            observed.supervisor = Some(SupervisorEvidence {
                kind: SupervisorKind::Systemd,
                unit_name: Some("worker.service".to_string()),
                auto_restart: Some(true),
                confidence: ProvenanceConfidence::High,
            });
            let scorer = scorer_with_lineage(&process, observed);
            let score = scorer
                .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
                .unwrap();
            assert_eq!(score.orphaned, Some(false));
            let features = feature_names(score.provenance.as_ref().unwrap());
            assert!(features.contains(&"provenance_ownership_supervised"));
            assert!(!features.contains(&"provenance_ownership_orphaned"));
            let orphan = score
                .ledger
                .bayes_factors
                .iter()
                .find(|term| term.feature == "orphan")
                .unwrap();
            assert!(orphan.log_bf < 0.0, "a supervised service is not abandoned");
        }
    }

    #[test]
    fn unknown_and_desktop_lineage_do_not_invent_orphanhood() {
        let (process, mut observed) = adopted_job(2000);
        observed.ancestors.clear();
        let scorer = scorer_with_lineage(&process, observed);
        let score = scorer
            .score_with_desktop(
                &process,
                Evidence {
                    orphan: None,
                    ..Evidence::from_snapshot(&process)
                },
                None,
            )
            .unwrap();
        assert_eq!(score.provenance.as_ref().unwrap().orphaned, None);
        assert_eq!(score.orphaned, None);
        assert!(!score
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature.contains("orphan")));
        let attached = scorer
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        assert_eq!(attached.orphaned, Some(false));

        let (process, observed) = adopted_job(2000);
        let scorer = scorer_with_lineage(&process, observed);
        let score = scorer
            .score_with_desktop(
                &process,
                Evidence::from_snapshot(&process),
                Some("app-worker.scope".to_string()),
            )
            .unwrap();
        assert_eq!(score.orphaned, Some(false));
        assert!(score.desktop_app_credited);
        assert!(!score
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature.starts_with("provenance_ownership_")));
    }

    #[test]
    fn recorded_orphan_verdict_replays_and_rejects_reused_identity() {
        let (process, observed) = adopted_job(2000);
        let mut scorer = scorer_with_lineage(&process, observed);
        let observations = scorer.recorded_observations(&process, None);
        assert_eq!(
            observations.provenance.as_ref().unwrap().orphaned,
            Some(true)
        );
        let expected = scorer
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap()
            .ledger;
        let encoded = serde_json::to_value(&observations).unwrap();
        let restored: ScoringObservations = serde_json::from_value(encoded.clone()).unwrap();
        scorer.provenance = None;
        let replayed = scorer
            .score_recorded(
                &process,
                Evidence::from_snapshot(&process),
                restored.clone(),
            )
            .unwrap();
        assert_eq!(replayed.orphaned, Some(true));
        assert_eq!(replayed.ledger, expected);

        let mut reused = process.clone();
        reused.start_id = pt_common::StartId::from_linux("new-boot", 99, reused.pid.0);
        assert!(scorer
            .score_recorded(&reused, Evidence::from_snapshot(&reused), restored.clone())
            .is_none());
        let mut reparented = process.clone();
        reparented.ppid = pt_common::ProcessId(3000);
        assert!(scorer
            .score_recorded(&reparented, Evidence::from_snapshot(&reparented), restored)
            .is_none());

        let mut incomplete = encoded;
        incomplete["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("orphaned");
        let error = serde_json::from_value::<ScoringObservations>(incomplete).unwrap_err();
        assert!(error.to_string().contains("orphaned"));
    }

    #[test]
    fn lineage_collection_requires_identity_before_and_after_reading() {
        struct ObservedIdentity {
            checks: std::cell::Cell<usize>,
            valid: [bool; 2],
        }
        impl crate::action::IdentityProvider for ObservedIdentity {
            fn revalidate(
                &self,
                _target: &pt_common::ProcessIdentity,
            ) -> Result<bool, crate::action::ActionError> {
                let index = self.checks.get();
                self.checks.set(index + 1);
                Ok(self.valid[index])
            }
        }
        let (process, observed) = adopted_job(2000);
        for valid in [[false, true], [true, false], [true, true]] {
            let provider = ObservedIdentity {
                checks: std::cell::Cell::new(0),
                valid,
            };
            let collected = std::cell::Cell::new(false);
            let result = provenance::collect_bound_lineage(&process, &provider, |_| {
                collected.set(true);
                observed.clone()
            });
            assert_eq!(collected.get(), valid[0]);
            assert_eq!(provider.checks.get(), if valid[0] { 2 } else { 1 });
            assert_eq!(result.is_ok(), valid[0] && valid[1]);
        }

        let identity = pt_common::ProcessIdentity::full(
            process.pid.0,
            process.start_id.clone(),
            process.uid,
            process.pgid,
            process.sid,
            pt_common::IdentityQuality::Full,
        );
        let provider = crate::action::StaticIdentityProvider::default().with_identity(identity);
        for field in ["pid", "ppid", "uid", "pgid", "sid"] {
            let mut changed = observed.clone();
            match field {
                "pid" => changed.pid += 1,
                "ppid" => changed.ppid += 1,
                "uid" => changed.uid += 1,
                "pgid" => changed.pgid += 1,
                "sid" => changed.sid += 1,
                _ => unreachable!(),
            }
            let result = provenance::collect_bound_lineage(&process, &provider, |_| changed);
            assert!(result.is_err(), "changed {field} must not supply ancestry");
        }
        let mut unbound = process.clone();
        unbound.start_id = pt_common::StartId("unknown".to_string());
        let provider = ObservedIdentity {
            checks: std::cell::Cell::new(0),
            valid: [true, true],
        };
        assert!(provenance::collect_bound_lineage(&unbound, &provider, |_| {
            panic!("an unbound PID must not supply ancestry")
        })
        .is_err());
        assert_eq!(provider.checks.get(), 0);
    }

    #[test]
    fn unavailable_lineage_is_recorded_without_erasing_resource_observations() {
        let (process, observed) = adopted_job(2000);
        let mut scorer = scorer_with_lineage(&process, observed);
        let bundle = scorer.provenance.as_mut().unwrap();
        bundle.lineages.clear();
        bundle.lineage_unavailable.insert(
            process.pid.0,
            "identity changed or unavailable during lineage collection".to_string(),
        );
        bundle.resource_graph = SharedResourceGraph::from_evidence(&[(
            process.pid.0,
            vec![listener_ev(process.pid.0, 8080)],
        )]);
        let score = scorer
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        let adjustment = score.provenance.as_ref().unwrap();
        assert_eq!(adjustment.orphaned, None);
        assert!(feature_names(adjustment).contains(&"provenance_active_listener"));
        assert!(!feature_names(adjustment)
            .iter()
            .any(|feature| feature.starts_with("provenance_ownership_")));
        assert!(adjustment
            .confidence_notes
            .iter()
            .any(|note| note.contains("identity changed or unavailable")));
        assert!(adjustment.confidence_penalty_steps > 0);
    }

    #[test]
    fn supervised_listener_suppresses_false_positive_path() {
        let bundle = ProvenanceInferenceBundle {
            census_complete: true,
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
            ..Default::default()
        };

        let adjustment = derive_provenance_adjustment(200, &bundle);
        let features = feature_names(&adjustment);

        assert!(features.contains(&"provenance_ownership_supervised"));
        assert!(features.contains(&"provenance_active_listener"));
        assert!(adjustment.evidence_completeness >= 0.8);
    }

    #[test]
    fn failed_resource_probes_do_not_establish_low_blast_radius() {
        let mut bundle = ProvenanceInferenceBundle {
            lineages: HashMap::from([(200, lineage(200, 2, None)), (300, lineage(300, 2, None))]),
            census_complete: true,
            ..Default::default()
        };
        let complete = derive_provenance_adjustment(200, &bundle);
        assert!(feature_names(&complete).contains(&"provenance_blast_radius_low"));

        bundle.resource_unavailable.insert(300, Vec::new());
        let empty_peer = derive_provenance_adjustment(200, &bundle);
        assert!(feature_names(&empty_peer).contains(&"provenance_blast_radius_low"));
        assert_eq!(
            empty_peer.evidence_completeness,
            complete.evidence_completeness
        );
        assert_eq!(
            empty_peer.confidence_penalty_steps,
            complete.confidence_penalty_steps
        );
        assert_eq!(empty_peer.confidence_notes, complete.confidence_notes);

        for unreadable_pid in [200, 300] {
            bundle.resource_unavailable = HashMap::from([(
                unreadable_pid,
                vec!["fd_ipc_metadata_unavailable: budget exhausted".into()],
            )]);
            let incomplete = derive_provenance_adjustment(200, &bundle);
            assert!(!feature_names(&incomplete).contains(&"provenance_blast_radius_low"));
            assert!(incomplete.evidence_completeness < complete.evidence_completeness);
            assert!(incomplete.confidence_penalty_steps > complete.confidence_penalty_steps);
            assert!(incomplete
                .confidence_notes
                .iter()
                .any(|note| note.contains("resource collection incomplete")));
            let expected_caveat = if unreadable_pid == 200 {
                "budget exhausted"
            } else {
                "1 other process observation(s) unavailable"
            };
            assert!(incomplete
                .confidence_notes
                .iter()
                .any(|note| note.contains(expected_caveat)));
        }

        // An unavailable peer does not erase the target's positive observations.
        bundle.resource_graph =
            SharedResourceGraph::from_evidence(&[(200, vec![listener_ev(200, 8080)])]);
        let with_listener = derive_provenance_adjustment(200, &bundle);
        assert!(feature_names(&with_listener).contains(&"provenance_active_listener"));
        assert!(!feature_names(&with_listener).contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn partial_resource_evidence_does_not_establish_low_blast_radius() {
        let bundle = ProvenanceInferenceBundle {
            resource_graph: SharedResourceGraph::from_evidence(&[(
                200,
                vec![lock_ev(200, "/tmp/unknown.lock", ResourceState::Partial)],
            )]),
            lineages: HashMap::from([(200, lineage(200, 2, None))]),
            ..Default::default()
        };
        let adjustment = derive_provenance_adjustment(200, &bundle);
        assert!(!feature_names(&adjustment).contains(&"provenance_blast_radius_low"));
    }

    #[test]
    fn recorded_scoring_preserves_provenance_without_the_live_resource_graph() {
        let process = crate::mock_process::MockProcessBuilder::new()
            .pid(200)
            .ppid(2)
            .comm("worker")
            .cmd("worker --serve")
            .elapsed(Duration::from_secs(7200))
            .build();
        let mut measured = Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        );
        measured.provenance = Some(ProvenanceInferenceBundle {
            target_identities: HashMap::from([(process.pid.0, provenance_identity(&process))]),
            target_ppids: HashMap::from([(process.pid.0, process.ppid.0)]),
            census_complete: true,
            resource_graph: SharedResourceGraph::from_evidence(&[(
                process.pid.0,
                vec![listener_ev(process.pid.0, 8080)],
            )]),
            lineages: HashMap::from([(process.pid.0, lineage(process.pid.0, 2, None))]),
            children: HashMap::new(),
            resource_unavailable: HashMap::from([(
                process.pid.0,
                vec!["fd_ipc_metadata_unavailable: budget exhausted".into()],
            )]),
            ..Default::default()
        });
        let observations = measured.recorded_observations(&process, None);
        let expected = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap()
            .ledger;
        let restored: ScoringObservations =
            serde_json::from_value(serde_json::to_value(&observations).unwrap()).unwrap();

        measured.provenance = None;
        let without = measured
            .score_with_desktop(&process, Evidence::from_snapshot(&process), None)
            .unwrap();
        assert!(!without
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature.starts_with("provenance_")));
        let replayed = measured
            .score_recorded(&process, Evidence::from_snapshot(&process), restored)
            .unwrap();
        assert_eq!(replayed.ledger, expected);
        assert!(replayed
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature == "provenance_active_listener"));
        assert!(replayed.ledger.why_summary.contains("budget exhausted"));
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
            ..Default::default()
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
