//! Learned kill/spare decisions per command pattern ("pt learns from your decisions").
//!
//! Human verdicts (an explicit `pt-core agent label`, or an action a human
//! confirmed in the TUI) are counted per normalized command pattern at three
//! specificity levels (exact / standard / broad, via [`CommandNormalizer`]). When a
//! process matching a pattern is evaluated again, the counts become a Beta-Binomial
//! posterior for "this kind of process is abandoned", which replaces the class
//! prior for that process through the existing user-override path.
//!
//! Robot/agent-applied actions are deliberately NOT recorded: learning from the
//! model's own decisions would reinforce its own mistakes.
//!
//! Storage: `<config_dir>/decisions.json`, the file the `pt history` / `pt clear`
//! wrapper commands read and reset.
//!
//! Verified signal outcomes use the separate [`TermGraceStore`]. They describe
//! cleanup latency and never alter the human abandonment prior above.

use crate::config::priors::Priors;
use crate::inference::prior_override::UserPriorOverrides;
use crate::supervision::pattern_learning::{CommandNormalizer, LearningKeyMode, SpecificityLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// File name of the decision store inside the config directory.
pub const DECISIONS_FILE: &str = "decisions.json";

/// Separate, private signal history; it contains opaque identities, not commands.
pub const TERM_GRACE_FILE: &str = "signal-history.json";
pub const MIN_TERM_GRACE_SAMPLES: usize = 8;
pub const MAX_TERM_GRACE_SAMPLES: usize = 64;
const MAX_TERM_GRACE_OBSERVATIONS: usize = 4_096;
const MAX_TERM_GRACE_HISTORY_BYTES: u64 = 4 * 1024 * 1024;
const TERM_GRACE_HISTORY_DAYS: i64 = 30;

/// A successful termination either observed exit after TERM, or required KILL
/// after the entire approved grace. Escalation durations are censored evidence,
/// never successful cleanup times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TermGraceResult {
    Exited { observed_ms: u64 },
    Escalated,
}

/// Replayable observation from one verified execution. Construction checks the
/// immutable action, its captured command identity, and the runner's receipt.
/// No command text, process identifiers or human verdicts are persisted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermGraceObservation {
    observation_id: String,
    pattern_id: String,
    executed_at: chrono::DateTime<chrono::Utc>,
    configured_grace_ms: u64,
    result: TermGraceResult,
}

impl TermGraceObservation {
    /// Only call after real execution and effect verification. `executed_at`
    /// must come from that execution's receipt, including when replaying it.
    /// Legacy, ignored, unknown, failed or mismatched receipts teach nothing.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_execution(
        session_id: &str,
        executed_at: chrono::DateTime<chrono::Utc>,
        action: &crate::plan::PlanAction,
        command_identity: &pt_common::ProcessIdentity,
        comm: &str,
        cmdline: &str,
        result: &crate::action::ActionResult,
        signal: &crate::action::signal::SignalExecutionOutcome,
    ) -> Option<Self> {
        use crate::action::signal::{SignalDisposition, SignalEscalationReason};
        if pt_common::SessionId::parse(session_id).is_none()
            || executed_at.timestamp_millis() < 0
            || action.action != crate::decision::Action::Kill
            || action.routing != crate::plan::ActionRouting::Direct
            || action.blocked
            || action.original_zombie_target.is_some()
            || action.supervisor_restart.is_some()
            || action.target.quality != pt_common::IdentityQuality::Full
            || command_identity != &action.target
            || result.status != crate::action::ActionStatus::Success
            || result.action_id != action.action_id
            || signal.action_id != action.action_id
            || signal.target.as_ref() != Some(&action.target)
            || action
                .timeouts
                .term_grace_command_sha256
                .as_ref()
                .is_some_and(|expected| signal.term_command_sha256.as_ref() != Some(expected))
            || !signal.sigterm_delivered
            || !matches!(
                signal.sigterm_disposition,
                SignalDisposition::Default | SignalDisposition::Caught
            )
            || signal.sigterm_recheck.is_some_and(|disposition| {
                !matches!(
                    disposition,
                    SignalDisposition::Default | SignalDisposition::Caught
                )
            })
            || action.validate_signal_timing().is_err()
            || action.timeouts.term_grace_ms != Some(signal.configured_grace_ms)
        {
            return None;
        }
        let observed_ms = signal.observed_grace_ms?;
        if observed_ms > signal.execution_elapsed_ms {
            return None;
        }
        let termination = match (
            signal.sigkill_delivered,
            signal.escalation_reason,
            signal.term_exit_observed_ms,
        ) {
            (false, None, Some(exit_ms))
                if exit_ms <= observed_ms && exit_ms <= signal.configured_grace_ms =>
            {
                TermGraceResult::Exited {
                    observed_ms: exit_ms,
                }
            }
            (true, Some(SignalEscalationReason::GraceExpired), None)
                if observed_ms >= signal.configured_grace_ms =>
            {
                TermGraceResult::Escalated
            }
            _ => return None,
        };
        let identity = serde_json::to_vec(&action.target).ok()?;
        let mut digest = Sha256::new();
        for part in [
            session_id.as_bytes(),
            action.action_id.as_bytes(),
            identity.as_slice(),
        ] {
            digest.update((part.len() as u64).to_le_bytes());
            digest.update(part);
        }
        Some(Self {
            observation_id: hex::encode(digest.finalize()),
            pattern_id: term_grace_pattern_id(comm, cmdline)?,
            executed_at,
            configured_grace_ms: signal.configured_grace_ms,
            result: termination,
        })
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !is_sha256_id(&self.observation_id) || !is_sha256_id(&self.pattern_id) {
            return Err("signal history identifiers must be SHA256 digests");
        }
        if self.executed_at.timestamp_millis() < 0 {
            return Err("signal history execution time predates the Unix epoch");
        }
        crate::config::policy::validate_term_grace_ms(self.configured_grace_ms)?;
        if let TermGraceResult::Exited { observed_ms } = self.result {
            if observed_ms > self.configured_grace_ms {
                return Err("successful TERM exit exceeds its approved grace");
            }
        }
        Ok(())
    }

    fn retention_key(&self) -> TermGraceWatermark {
        TermGraceWatermark {
            executed_at: self.executed_at,
            observation_id: self.observation_id.clone(),
        }
    }
}

fn is_sha256_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn term_grace_pattern_id(comm: &str, cmdline: &str) -> Option<String> {
    if comm.trim().is_empty() || cmdline.trim().is_empty() {
        return None;
    }
    // Human prior normalization intentionally drops some arguments and paths.
    // Cleanup timing cannot borrow that generalization: a different interpreter
    // program or input may need a longer shutdown. Preserve every captured byte
    // and argument boundary available here, without persisting the private text.
    let mut digest = Sha256::new();
    for part in [comm.as_bytes(), cmdline.as_bytes()] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    Some(hex::encode(digest.finalize()))
}

/// Why sufficient recent observations support shortening a future plan's grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TermGraceRecommendationReason {
    SuccessfulExitQuantile,
    RepeatedEscalation,
}

/// Timing evidence for plan provenance, without private command patterns.
#[derive(Debug, Clone, Serialize)]
pub struct TermGraceRecommendation {
    pub grace_ms: u64,
    pub pattern_id: String,
    pub sample_count: usize,
    pub term_successes: usize,
    pub term_escalations: usize,
    /// Mean of Beta(1 + successful TERM exits, 1 + full-grace escalations).
    pub term_sufficient_posterior_mean: f64,
    pub successful_exit_quantile_ms: Option<u64>,
    pub reason: TermGraceRecommendationReason,
}

/// The oldest discarded (timestamp, opaque receipt ID). Replays older than this
/// boundary remain ignored even after their individual deduplication IDs expire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TermGraceWatermark {
    executed_at: chrono::DateTime<chrono::Utc>,
    observation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TermGraceHistory {
    version: u32,
    discarded_through: Option<TermGraceWatermark>,
    observations: BTreeMap<String, TermGraceObservation>,
}

impl Default for TermGraceHistory {
    fn default() -> Self {
        Self {
            version: 1,
            discarded_through: None,
            observations: BTreeMap::new(),
        }
    }
}

/// Bounded signal history, deliberately separate from [`DecisionStore`]. Saves
/// reread under a lock and merge pending receipts without double-counting them.
#[derive(Debug, Clone)]
pub struct TermGraceStore {
    path: PathBuf,
    history: TermGraceHistory,
    pending: BTreeMap<String, TermGraceObservation>,
}

impl TermGraceStore {
    /// Missing history is a cold start. Malformed or inaccessible history is an
    /// error, so callers can report that learning fell back to configured grace.
    pub fn load(config_dir: &Path) -> Result<Self, DecisionStoreError> {
        let path = config_dir.join(TERM_GRACE_FILE);
        let history = read_term_grace_history(&path)?;
        Ok(Self {
            path,
            history,
            pending: BTreeMap::new(),
        })
    }

    /// Add one receipt, once. The same receipt with different facts is rejected;
    /// evicted old receipts are ignored, not counted again on session replay.
    pub fn record(
        &mut self,
        observation: TermGraceObservation,
    ) -> Result<bool, DecisionStoreError> {
        if self.pending.len() >= MAX_TERM_GRACE_OBSERVATIONS
            && !self
                .history
                .observations
                .contains_key(&observation.observation_id)
        {
            return Err(term_grace_invalid(
                &self.path,
                &observation.observation_id,
                "save pending signal observations before adding more",
            ));
        }
        if !merge_term_grace_observation(&self.path, &mut self.history, &observation)? {
            return Ok(false);
        }
        self.pending
            .insert(observation.observation_id.clone(), observation);
        Ok(true)
    }

    /// Merge under the store lock and atomically replace a private, synced file.
    /// Pending receipts remain available for retry if any persistence step fails.
    pub fn save(&mut self) -> Result<(), DecisionStoreError> {
        use std::io::Write;

        if self.pending.is_empty() {
            return Ok(());
        }
        let directory = self.path.parent().ok_or_else(|| {
            term_grace_invalid(
                &self.path,
                "history",
                "signal history has no parent directory",
            )
        })?;
        std::fs::create_dir_all(directory).map_err(|source| term_grace_io(directory, source))?;
        let _lock = StoreLock::acquire_private(&self.path)?;
        let mut merged = read_term_grace_history(&self.path)?;
        for observation in self.pending.values() {
            merge_term_grace_observation(&self.path, &mut merged, observation)?;
        }
        let mut text = serde_json::to_vec_pretty(&merged)
            .map_err(|error| term_grace_invalid(&self.path, "history", &error.to_string()))?;
        text.push(b'\n');
        if text.len() as u64 > MAX_TERM_GRACE_HISTORY_BYTES {
            return Err(term_grace_invalid(
                &self.path,
                "history",
                "serialized signal history exceeds its byte limit",
            ));
        }
        let temporary = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|source| term_grace_io(&temporary, source))?;
        file.write_all(&text)
            .and_then(|()| file.sync_all())
            .map_err(|source| term_grace_io(&temporary, source))?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|source| term_grace_io(&self.path, source))?;
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| term_grace_io(directory, source))?;
        self.history = merged;
        self.pending.clear();
        Ok(())
    }

    /// Recommend for a newly constructed plan only. `upper_grace_ms` is always
    /// the policy's configured TERM grace, not a learned or previously saved
    /// value. None preserves that cap for cold, stale or mixed evidence.
    pub fn recommend(
        &self,
        comm: &str,
        cmdline: &str,
        upper_grace_ms: u64,
        min_grace_ms: u64,
        min_samples: usize,
    ) -> Result<Option<TermGraceRecommendation>, &'static str> {
        self.recommend_at(
            comm,
            cmdline,
            upper_grace_ms,
            min_grace_ms,
            min_samples,
            chrono::Utc::now(),
        )
    }

    fn recommend_at(
        &self,
        comm: &str,
        cmdline: &str,
        upper_grace_ms: u64,
        min_grace_ms: u64,
        min_samples: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<TermGraceRecommendation>, &'static str> {
        crate::config::policy::validate_term_grace_ms(upper_grace_ms)?;
        crate::config::policy::validate_term_grace_ms(min_grace_ms)?;
        if !(MIN_TERM_GRACE_SAMPLES..=MAX_TERM_GRACE_SAMPLES).contains(&min_samples) {
            return Err("adaptive TERM grace requires between 8 and 64 samples");
        }
        let Some(pattern_id) = term_grace_pattern_id(comm, cmdline) else {
            return Ok(None);
        };
        let earliest = now - chrono::Duration::days(TERM_GRACE_HISTORY_DAYS);
        let mut observations: Vec<_> = self
            .history
            .observations
            .values()
            .filter(|observation| {
                observation.pattern_id == pattern_id
                    && observation.executed_at >= earliest
                    && observation.executed_at <= now
            })
            .collect();
        observations.sort_by_key(|observation| observation.retention_key());
        let observations: Vec<_> = observations
            .into_iter()
            .rev()
            .take(MAX_TERM_GRACE_SAMPLES)
            .collect();
        let sample_count = observations.len();
        if sample_count < min_samples {
            return Ok(None);
        }
        let mut exits: Vec<_> = observations
            .iter()
            .filter_map(|observation| match observation.result {
                TermGraceResult::Exited { observed_ms } => Some(observed_ms),
                TermGraceResult::Escalated => None,
            })
            .collect();
        let term_successes = exits.len();
        let term_escalations = sample_count - term_successes;
        let minimum = min_grace_ms.min(upper_grace_ms);
        let (grace_ms, successful_exit_quantile_ms, reason) = if term_escalations == 0 {
            exits.sort_unstable();
            // The 99th percentile is the slowest observed success within this
            // deliberately small window. Preserve a substantial cleanup margin.
            let rank = (exits.len() * 99).div_ceil(100).saturating_sub(1);
            let quantile = exits[rank];
            let with_margin = quantile.saturating_add(500_u64.max(quantile.div_ceil(4)));
            (
                with_margin.clamp(minimum, upper_grace_ms),
                Some(quantile),
                TermGraceRecommendationReason::SuccessfulExitQuantile,
            )
        } else if term_successes == 0
            && observations
                .iter()
                .filter(|observation| observation.configured_grace_ms >= upper_grace_ms)
                .count()
                >= min_samples
        {
            // Failures observed only after an already shortened grace cannot
            // prove that waiting the full current policy cap would be futile.
            (
                minimum,
                None,
                TermGraceRecommendationReason::RepeatedEscalation,
            )
        } else {
            // Censored failures mixed with successes call for the full cap;
            // treating the failures as fast exits would make adaptation unsafe.
            return Ok(None);
        };
        Ok(Some(TermGraceRecommendation {
            grace_ms,
            pattern_id,
            sample_count,
            term_successes,
            term_escalations,
            term_sufficient_posterior_mean: (term_successes + 1) as f64 / (sample_count + 2) as f64,
            successful_exit_quantile_ms,
            reason,
        }))
    }
}

fn term_grace_io(path: &Path, source: std::io::Error) -> DecisionStoreError {
    DecisionStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn term_grace_invalid(path: &Path, key: &str, message: &str) -> DecisionStoreError {
    DecisionStoreError::InvalidData {
        path: path.to_path_buf(),
        entry_id: source_id(key),
        message: message.to_string(),
    }
}

fn read_term_grace_history(path: &Path) -> Result<TermGraceHistory, DecisionStoreError> {
    use std::io::Read;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(path) {
                Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                    Ok(TermGraceHistory::default())
                }
                _ => Err(term_grace_io(path, error)),
            };
        }
        Err(error) => return Err(term_grace_io(path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| term_grace_io(path, source))?;
    if !metadata.is_file() || metadata.len() > MAX_TERM_GRACE_HISTORY_BYTES {
        return Err(term_grace_invalid(
            path,
            "history",
            "signal history must be a bounded regular file",
        ));
    }
    let mut text = Vec::new();
    file.take(MAX_TERM_GRACE_HISTORY_BYTES + 1)
        .read_to_end(&mut text)
        .map_err(|source| term_grace_io(path, source))?;
    if text.len() as u64 > MAX_TERM_GRACE_HISTORY_BYTES {
        return Err(term_grace_invalid(
            path,
            "history",
            "signal history exceeds its byte limit",
        ));
    }
    let history: TermGraceHistory =
        serde_json::from_slice(&text).map_err(|error| DecisionStoreError::Parse {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if history.version != 1 || history.observations.len() > MAX_TERM_GRACE_OBSERVATIONS {
        return Err(term_grace_invalid(
            path,
            "history",
            "unsupported or oversized signal history",
        ));
    }
    if history.discarded_through.as_ref().is_some_and(|watermark| {
        !is_sha256_id(&watermark.observation_id) || watermark.executed_at.timestamp_millis() < 0
    }) {
        return Err(term_grace_invalid(
            path,
            "history",
            "invalid signal history retention watermark",
        ));
    }
    for (id, observation) in &history.observations {
        observation
            .validate()
            .map_err(|reason| term_grace_invalid(path, id, reason))?;
        if id != &observation.observation_id
            || history
                .discarded_through
                .as_ref()
                .is_some_and(|watermark| observation.retention_key() <= *watermark)
        {
            return Err(term_grace_invalid(
                path,
                id,
                "signal history receipt conflicts with its identity or retention boundary",
            ));
        }
    }
    Ok(history)
}

fn merge_term_grace_observation(
    path: &Path,
    history: &mut TermGraceHistory,
    observation: &TermGraceObservation,
) -> Result<bool, DecisionStoreError> {
    let id = &observation.observation_id;
    observation
        .validate()
        .map_err(|reason| term_grace_invalid(path, id, reason))?;
    if let Some(previous) = history.observations.get(id) {
        return if previous == observation {
            Ok(false)
        } else {
            Err(term_grace_invalid(
                path,
                id,
                "replayed signal receipt has conflicting facts",
            ))
        };
    }
    if history
        .discarded_through
        .as_ref()
        .is_some_and(|watermark| observation.retention_key() <= *watermark)
    {
        return Ok(false);
    }
    history.observations.insert(id.clone(), observation.clone());
    if history.observations.len() > MAX_TERM_GRACE_OBSERVATIONS {
        let oldest = history
            .observations
            .values()
            .map(TermGraceObservation::retention_key)
            .min()
            .expect("overfull history contains an oldest receipt");
        history.observations.remove(&oldest.observation_id);
        history.discarded_through = Some(oldest);
    }
    Ok(true)
}

/// Pseudo-observations given to the global prior when combining it with counts.
/// With 2, one human "kill" moves P(abandoned) from a global 0.25 to 0.5.
pub const PRIOR_STRENGTH: f64 = 2.0;

/// Bounds on a learned P(abandoned): no amount of labeling makes a pattern certain,
/// so live evidence (CPU, TTY, children, state) can still overturn the prior.
pub const LEARNED_PRIOR_MIN: f64 = 0.02;
pub const LEARNED_PRIOR_MAX: f64 = 0.95;

/// Each verdict loses half its weight for every this many days since it was given, so
/// habits that changed long ago fade back toward the global prior.
pub const DECAY_HALF_LIFE_DAYS: f64 = 180.0;

/// A broad pattern (the program name plus a few primary flags, so it also covers
/// unrelated runs of the same interpreter) only sets the prior once at least this
/// many distinct specific patterns support the same verdict direction. A kill of
/// `node x.js` and a spare of `node y.js` do not establish an interpreter-wide habit.
pub const MIN_SOURCES_FOR_GENERALIZATION: usize = 2;

/// A source needs at least half an effective verdict of net support. A lone fresh
/// verdict remains material for one half-life; ties and vanishing old votes cannot
/// establish consensus merely because their source identifiers were remembered.
pub const MIN_SOURCE_SUPPORT_FOR_GENERALIZATION: f64 = 0.5;

/// Distinct source patterns remembered per key, without keeping a verdict history.
const MAX_TRACKED_SOURCES: usize = 16;

fn parse_ts(ts: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Decay factor from `since` to `now` (1.0 if `since` is unknown or in the future).
fn decay_weight(since: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> f64 {
    let Some(ts) = parse_ts(since) else {
        return 1.0;
    };
    let age_days = (now - ts).num_seconds().max(0) as f64 / 86_400.0;
    0.5_f64.powf(age_days / DECAY_HALF_LIFE_DAYS)
}

/// Stable short id of a pattern key (FNV-1a 64), used to count distinct sources.
fn source_id(key: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A human verdict about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Kill,
    Spare,
}

/// Sufficient statistics for one specific pattern contributing to a broader key.
/// Both sums are measured at the containing [`PatternCounts::updated_at`] and
/// decay with the same half-life as that key's aggregate counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceWeights {
    pub kill: f64,
    pub spare: f64,
}

impl SourceWeights {
    fn direction(&self, decay: f64) -> Option<Verdict> {
        if !self.kill.is_finite() || !self.spare.is_finite() || self.kill < 0.0 || self.spare < 0.0
        {
            return None;
        }
        let support = (self.kill - self.spare) * decay;
        if support >= MIN_SOURCE_SUPPORT_FOR_GENERALIZATION {
            Some(Verdict::Kill)
        } else if support <= -MIN_SOURCE_SUPPORT_FOR_GENERALIZATION {
            Some(Verdict::Spare)
        } else {
            None
        }
    }
}

/// Counts for one pattern key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PatternCounts {
    pub kill: u32,
    pub spare: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Decayed kill / spare weights as of `updated_at`: every verdict decays from the
    /// time it was given (exponential decay is memoryless, so these sums are exact).
    /// Absent in files written before they existed; the raw counts stand in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_weight: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spare_weight: Option<f64>,
    /// Bounded evidence per most-specific source, keyed by its stable short id.
    /// Legacy `sources` arrays carried no verdict directions and are intentionally
    /// not migrated into votes. Only new labels can establish their consensus.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_weights: BTreeMap<String, SourceWeights>,
}

impl PatternCounts {
    fn total(&self) -> u64 {
        u64::from(self.kill) + u64::from(self.spare)
    }

    /// Validate the whole entry before any source is trimmed or used as a prior.
    /// Raw counts saturate independently, so legitimate effective weights can
    /// exceed them. Their nonnegative, finite sums are the numerical invariant.
    fn validate(&self) -> Result<(), &'static str> {
        if self.updated_at.is_some() && parse_ts(self.updated_at.as_deref()).is_none() {
            return Err("updated_at must be an RFC 3339 timestamp");
        }
        let kill = self.kill_weight.unwrap_or(f64::from(self.kill));
        let spare = self.spare_weight.unwrap_or(f64::from(self.spare));
        if !kill.is_finite() || kill < 0.0 {
            return Err("kill_weight must be finite and nonnegative");
        }
        if !spare.is_finite() || spare < 0.0 {
            return Err("spare_weight must be finite and nonnegative");
        }
        if !(kill + spare).is_finite() {
            return Err("combined kill and spare weights must be finite");
        }
        for source in self.source_weights.values() {
            if !source.kill.is_finite() || source.kill < 0.0 {
                return Err("source_weights.kill must be finite and nonnegative");
            }
            if !source.spare.is_finite() || source.spare < 0.0 {
                return Err("source_weights.spare must be finite and nonnegative");
            }
            if !(source.kill + source.spare).is_finite() {
                return Err("combined source weights must be finite");
            }
        }
        Ok(())
    }

    /// Decayed (kill, spare) weights at `now`.
    fn weights_at(&self, now: chrono::DateTime<chrono::Utc>) -> (f64, f64) {
        let decay = decay_weight(self.updated_at.as_deref(), now);
        (
            self.kill_weight.unwrap_or(f64::from(self.kill)) * decay,
            self.spare_weight.unwrap_or(f64::from(self.spare)) * decay,
        )
    }

    fn supports_generalization(&self, now: chrono::DateTime<chrono::Utc>, global: f64) -> bool {
        let (kill, spare) = self.weights_at(now);
        let Some(direction) = (SourceWeights { kill, spare }).direction(1.0) else {
            return false;
        };
        // The aggregate must actually move the prior in the agreed direction.
        // For example, a narrow spare majority can still raise a low global prior.
        let probability = ((kill + PRIOR_STRENGTH * global) / (kill + spare + PRIOR_STRENGTH))
            .clamp(LEARNED_PRIOR_MIN, LEARNED_PRIOR_MAX);
        let prior_shift = probability - global;
        if !prior_shift.is_finite()
            || match direction {
                Verdict::Kill => prior_shift <= 0.0,
                Verdict::Spare => prior_shift >= 0.0,
            }
        {
            return false;
        }
        let decay = decay_weight(self.updated_at.as_deref(), now);
        self.source_weights
            .values()
            .filter(|source| source.direction(decay) == Some(direction))
            .take(MIN_SOURCES_FOR_GENERALIZATION)
            .count()
            >= MIN_SOURCES_FOR_GENERALIZATION
    }

    fn bound_sources(&mut self) {
        // Retain the lowest stable ids, so bounded merging is deterministic even
        // when independently loaded writers save in a different order.
        while self.source_weights.len() > MAX_TRACKED_SOURCES {
            self.source_weights.pop_last();
        }
    }
}

/// On-disk entry: current format (counts) or the legacy wrapper format ("kill"/"spare").
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredEntry {
    Counts(PatternCounts),
    Legacy(Verdict),
}

/// Errors reading or writing the decision store.
#[derive(Debug, thiserror::Error)]
pub enum DecisionStoreError {
    #[error("decision store I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("decision store at {path} is not a JSON object: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("decision store at {path} has invalid entry {entry_id}: {message}")]
    InvalidData {
        path: PathBuf,
        /// An opaque key identifier; command patterns may contain private text.
        entry_id: String,
        message: String,
    },
}

/// What the learned prior was derived from (for explanations / plan JSON).
#[derive(Debug, Clone, Serialize)]
pub struct LearnedPrior {
    pub pattern_key: String,
    /// Matching pattern level: exact, standard, or broad.
    pub specificity: &'static str,
    pub kill: u32,
    pub spare: u32,
    /// Effective weight per verdict after age decay (1.0 = all labeled just now).
    pub weight: f64,
    /// Sum of decayed human-verdict weights, excluding the global pseudo-counts.
    pub effective_sample_count: f64,
    /// Posterior mean P(abandoned or zombie) after combining with the global prior.
    pub abandonment_prior: f64,
}

/// Learned decisions keyed by `"<level>|<normalized name>|<normalized args>"`.
#[derive(Debug, Clone, Default)]
pub struct DecisionStore {
    path: PathBuf,
    entries: BTreeMap<String, PatternCounts>,
    /// Verdicts recorded since the last save, merged into the on-disk file on save.
    pending: BTreeMap<String, PatternCounts>,
}

fn validate_entry(
    path: &Path,
    key: &str,
    counts: &PatternCounts,
) -> Result<(), DecisionStoreError> {
    counts
        .validate()
        .map_err(|message| DecisionStoreError::InvalidData {
            path: path.to_path_buf(),
            entry_id: source_id(key),
            message: message.to_string(),
        })
}

fn read_entries(path: &Path) -> Result<BTreeMap<String, PatternCounts>, DecisionStoreError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) => {
            // A dangling configured symlink must not erase the learned model
            // by masquerading as an absent optional file.
            let source = if source.kind() == std::io::ErrorKind::NotFound {
                match std::fs::symlink_metadata(path) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(BTreeMap::new());
                    }
                    Err(metadata_error) => metadata_error,
                    Ok(_) => source,
                }
            } else {
                source
            };
            return Err(DecisionStoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let raw: BTreeMap<String, StoredEntry> =
        serde_json::from_str(&text).map_err(|e| DecisionStoreError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    raw.into_iter()
        .map(|(k, v)| {
            let mut counts = match v {
                StoredEntry::Counts(c) => c,
                StoredEntry::Legacy(Verdict::Kill) => PatternCounts {
                    kill: 1,
                    last: Some(Verdict::Kill),
                    ..Default::default()
                },
                StoredEntry::Legacy(Verdict::Spare) => PatternCounts {
                    spare: 1,
                    last: Some(Verdict::Spare),
                    ..Default::default()
                },
            };
            validate_entry(path, &k, &counts)?;
            counts.bound_sources();
            Ok((k, counts))
        })
        .collect()
}

/// Add `delta`'s verdicts to `into`: both weight sums are decayed to the later of the
/// two timestamps and added there; `last` is the verdict of the later one.
fn add_counts(into: &mut PatternCounts, delta: &PatternCounts) {
    let into_ts = parse_ts(into.updated_at.as_deref());
    let delta_ts = parse_ts(delta.updated_at.as_deref());
    let at = into_ts.max(delta_ts);
    let into_decay = at.map_or(1.0, |t| decay_weight(into.updated_at.as_deref(), t));
    let delta_decay = at.map_or(1.0, |t| decay_weight(delta.updated_at.as_deref(), t));
    let (ik, is) = at.map_or_else(
        || {
            (
                into.kill_weight.unwrap_or(f64::from(into.kill)),
                into.spare_weight.unwrap_or(f64::from(into.spare)),
            )
        },
        |t| into.weights_at(t),
    );
    let (dk, ds) = at.map_or_else(
        || {
            (
                delta.kill_weight.unwrap_or(f64::from(delta.kill)),
                delta.spare_weight.unwrap_or(f64::from(delta.spare)),
            )
        },
        |t| delta.weights_at(t),
    );
    into.kill = into.kill.saturating_add(delta.kill);
    into.spare = into.spare.saturating_add(delta.spare);
    into.kill_weight = Some(ik + dk);
    into.spare_weight = Some(is + ds);
    if delta.last.is_some() && delta_ts >= into_ts {
        into.last = delta.last;
    }
    if let Some(t) = at {
        into.updated_at = Some(t.to_rfc3339());
    }
    for source in into.source_weights.values_mut() {
        source.kill *= into_decay;
        source.spare *= into_decay;
    }
    for (id, source) in &delta.source_weights {
        let merged = into.source_weights.entry(id.clone()).or_default();
        merged.kill += source.kill * delta_decay;
        merged.spare += source.spare * delta_decay;
    }
}

/// Exclusive advisory lock on `<store>.lock`, held until dropped.
struct StoreLock(#[allow(dead_code)] std::fs::File);

impl StoreLock {
    fn acquire(store_path: &Path) -> Result<Self, DecisionStoreError> {
        Self::acquire_with_privacy(store_path, false)
    }

    fn acquire_private(store_path: &Path) -> Result<Self, DecisionStoreError> {
        Self::acquire_with_privacy(store_path, true)
    }

    fn acquire_with_privacy(store_path: &Path, private: bool) -> Result<Self, DecisionStoreError> {
        let lock_path = store_path.with_extension("json.lock");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&lock_path)
            .map_err(|source| DecisionStoreError::Io {
                path: lock_path.clone(),
                source,
            })?;
        if private
            && !file
                .metadata()
                .map_err(|source| term_grace_io(&lock_path, source))?
                .is_file()
        {
            return Err(term_grace_invalid(
                &lock_path,
                "lock",
                "signal history lock must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: flock on a file descriptor we own; blocks until the lock is free.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(DecisionStoreError::Io {
                    path: lock_path,
                    source: std::io::Error::last_os_error(),
                });
            }
        }
        // The lock is released when the file descriptor is closed.
        Ok(Self(file))
    }
}

impl DecisionStore {
    /// Load the store from `<config_dir>/decisions.json` (missing file = empty).
    pub fn load(config_dir: &Path) -> Result<Self, DecisionStoreError> {
        let path = config_dir.join(DECISIONS_FILE);
        let entries = read_entries(&path)?;
        Ok(Self {
            path,
            entries,
            pending: BTreeMap::new(),
        })
    }

    /// Merge verdicts recorded since the last save into the file: under an exclusive
    /// lock, re-read it (other writers may have added decisions), add ours, and
    /// replace it atomically. Concurrent writers never lose each other's verdicts.
    pub fn save(&mut self) -> Result<(), DecisionStoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|source| DecisionStoreError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        }
        let _lock = StoreLock::acquire(&self.path)?;
        let mut merged = read_entries(&self.path)?;
        for (key, delta) in &self.pending {
            validate_entry(&self.path, key, delta)?;
            let counts = merged.entry(key.clone()).or_default();
            add_counts(counts, delta);
            // Two finite inputs can overflow when concurrent writers merge.
            // Refuse before serialization can replace nonfinite weights with
            // null, which would reload as unweighted raw counts.
            validate_entry(&self.path, key, counts)?;
            counts.bound_sources();
        }
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        let text = serde_json::to_string_pretty(&merged).expect("counts serialize");
        std::fs::write(&tmp, format!("{text}\n")).map_err(|source| DecisionStoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|source| DecisionStoreError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.entries = merged;
        self.pending.clear();
        Ok(())
    }

    /// Number of distinct pattern keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no decisions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot the loaded counts for evaluation provenance without rereading
    /// the file or including its location. Pending verdicts are already reflected
    /// in these entries; callers must not publish their private command patterns.
    pub(crate) fn evaluation_snapshot(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.entries)
    }

    /// Pattern keys for a process, most specific first.
    pub fn pattern_keys(comm: &str, cmdline: &str) -> Vec<String> {
        let normalizer = CommandNormalizer::new();
        let key_mode = normalizer.learning_key_mode(comm, cmdline);
        let mut candidates = normalizer.generate_candidates(comm, cmdline);
        candidates.sort_by_key(|c| c.level.priority_offset());
        candidates
            .into_iter()
            .map(|c| {
                let level = match c.level {
                    SpecificityLevel::Exact => "exact",
                    SpecificityLevel::Standard => "standard",
                    SpecificityLevel::Broad => "broad",
                };
                let arguments = if key_mode != LearningKeyMode::Existing
                    && c.level != SpecificityLevel::Broad
                {
                    // Source, script arguments and option operands can contain
                    // private literals. Preserve the complete identity without
                    // copying it into the durable learning store. Length prefixes
                    // distinguish pattern boundaries independently of contents.
                    let mut digest = Sha256::new();
                    for argument in &c.arg_patterns {
                        digest.update((argument.len() as u64).to_le_bytes());
                        digest.update(argument.as_bytes());
                    }
                    let namespace = if key_mode == LearningKeyMode::InlineProgram {
                        "inline"
                    } else {
                        "program-v2"
                    };
                    format!("{namespace}:{}", hex::encode(digest.finalize()))
                } else if key_mode == LearningKeyMode::InlineProgram {
                    // Previous broad keys mixed inline source with script jobs
                    // and tracked source ids from the lossy old normalization.
                    // Do not combine those votes with new opaque identities:
                    // one job labeled before and after an upgrade is still one
                    // source, not the two needed to establish a broad habit.
                    format!("inline:{}", c.arg_patterns.join(" "))
                } else if key_mode == LearningKeyMode::OpaqueInterpreter {
                    // The old exact/standard keys could omit this entire script
                    // or mistake an option operand for its identity. Never mix
                    // those old source IDs with the newly preserved invocation.
                    format!("program-v2:{}", c.arg_patterns.join(" "))
                } else {
                    c.arg_patterns.join(" ")
                };
                format!("{level}|{}|{arguments}", c.process_pattern)
            })
            .collect()
    }

    /// Record a human verdict for a process at every specificity level.
    pub fn record(&mut self, comm: &str, cmdline: &str, verdict: Verdict) {
        self.record_at(comm, cmdline, verdict, chrono::Utc::now());
    }

    fn record_at(
        &mut self,
        comm: &str,
        cmdline: &str,
        verdict: Verdict,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        let keys = Self::pattern_keys(comm, cmdline);
        let Some(most_specific) = keys.first() else {
            return;
        };
        let delta = PatternCounts {
            kill: u32::from(verdict == Verdict::Kill),
            spare: u32::from(verdict == Verdict::Spare),
            last: Some(verdict),
            updated_at: Some(at.to_rfc3339()),
            kill_weight: None,
            spare_weight: None,
            source_weights: BTreeMap::from([(
                source_id(most_specific),
                SourceWeights {
                    kill: f64::from(u32::from(verdict == Verdict::Kill)),
                    spare: f64::from(u32::from(verdict == Verdict::Spare)),
                },
            )]),
        };
        for key in keys {
            let counts = self.entries.entry(key.clone()).or_default();
            add_counts(counts, &delta);
            counts.bound_sources();
            let pending = self.pending.entry(key).or_default();
            add_counts(pending, &delta);
            pending.bound_sources();
        }
    }

    /// Learned prior for a process: decayed counts of the most specific pattern with
    /// decisions that may speak for it, combined with the global prior (Beta-Binomial
    /// posterior mean). Exact and standard patterns always may; a broad one needs
    /// material, concordant evidence from `MIN_SOURCES_FOR_GENERALIZATION` distinct
    /// specific patterns, agreeing with the aggregate prior's direction.
    pub fn learned_prior(
        &self,
        comm: &str,
        cmdline: &str,
        global: &Priors,
    ) -> Option<LearnedPrior> {
        self.learned_prior_at(comm, cmdline, global, chrono::Utc::now())
    }

    pub(crate) fn learned_prior_at(
        &self,
        comm: &str,
        cmdline: &str,
        global: &Priors,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<LearnedPrior> {
        let g = &global.classes;
        let global_ab = (g.abandoned.prior_prob + g.zombie.prior_prob).clamp(1e-6, 1.0 - 1e-6);
        Self::pattern_keys(comm, cmdline)
            .into_iter()
            .find_map(|key| {
                self.entries
                    .get(&key)
                    .filter(|c| c.total() > 0)
                    .filter(|c| {
                        !key.starts_with("broad|") || c.supports_generalization(now, global_ab)
                    })
                    .map(|c| (key, c))
            })
            .map(|(key, c)| {
                let (kill_w, spare_w) = c.weights_at(now);
                let p = (kill_w + PRIOR_STRENGTH * global_ab) / (kill_w + spare_w + PRIOR_STRENGTH);
                let p = p.clamp(LEARNED_PRIOR_MIN, LEARNED_PRIOR_MAX);
                LearnedPrior {
                    specificity: if key.starts_with("exact|") {
                        "exact"
                    } else if key.starts_with("standard|") {
                        "standard"
                    } else {
                        "broad"
                    },
                    pattern_key: key,
                    kill: c.kill,
                    spare: c.spare,
                    // Two u32 counts fit exactly in f64, including their sum.
                    weight: (kill_w + spare_w) / c.total() as f64,
                    effective_sample_count: kill_w + spare_w,
                    abandonment_prior: p,
                }
            })
    }

    /// Class-prior overrides implementing a learned prior: the abandoned+zombie mass
    /// becomes `abandonment_prior`, split in the global ratio; the rest keeps the
    /// global useful : useful_bad ratio.
    pub fn overrides_for(learned: &LearnedPrior, global: &Priors) -> UserPriorOverrides {
        let g = &global.classes;
        let p = learned.abandonment_prior.clamp(1e-6, 1.0 - 1e-6);
        let ab_mass = (g.abandoned.prior_prob + g.zombie.prior_prob).max(1e-12);
        let ok_mass = (g.useful.prior_prob + g.useful_bad.prior_prob).max(1e-12);
        UserPriorOverrides {
            abandoned: Some(p * g.abandoned.prior_prob / ab_mass),
            zombie: Some(p * g.zombie.prior_prob / ab_mass),
            useful: Some((1.0 - p) * g.useful.prior_prob / ok_mass),
            useful_bad: Some((1.0 - p) * g.useful_bad.prior_prob / ok_mass),
        }
    }

    /// `global` with its class priors replaced by the learned prior for this process,
    /// or `None` when no human decision matches its command pattern.
    pub fn priors_for(&self, comm: &str, cmdline: &str, global: &Priors) -> Option<Priors> {
        let learned = self.learned_prior(comm, cmdline, global)?;
        let o = Self::overrides_for(&learned, global);
        let mut priors = global.clone();
        let c = &mut priors.classes;
        (c.useful.prior_prob, c.useful_bad.prior_prob) = (o.useful?, o.useful_bad?);
        (c.abandoned.prior_prob, c.zombie.prior_prob) = (o.abandoned?, o.zombie?);
        Some(priors)
    }
}

#[cfg(all(test, unix))]
mod term_grace_tests {
    use super::*;
    use crate::action::signal::{
        SignalDisposition, SignalEscalationReason, SignalExecutionOutcome,
    };
    use crate::action::{ActionResult, ActionStatus};
    use crate::plan::{
        ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts, PlanAction,
    };

    const COMMAND: &str = "node /srv/PRIVATE_TERM_TIMING_CANARY.js --worker";
    const SESSION: &str = "pt-20260601-000000-abcd";

    fn execution(
        index: u32,
        exit_ms: Option<u64>,
        grace_ms: u64,
    ) -> (PlanAction, ActionResult, SignalExecutionOutcome) {
        let pid = 10_000 + index;
        let target = pt_common::ProcessIdentity::new(
            pid,
            pt_common::StartId::from_linux("11111111-2222-4333-8444-555555555555", 100, pid),
            1000,
        );
        let action = PlanAction {
            action_id: format!("act-{index:016x}"),
            target: target.clone(),
            action: crate::decision::Action::Kill,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts {
                term_grace_ms: Some(grace_ms),
                ..ActionTimeouts::default()
            },
            pre_checks: vec![],
            rationale: ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: vec![],
            on_failure: vec![],
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
            supervisor_restart: None,
            memory_cap: None,
        };
        let elapsed = exit_ms.unwrap_or(grace_ms + 10);
        let result = ActionResult {
            action_id: action.action_id.clone(),
            status: ActionStatus::Success,
            time_ms: u128::from(elapsed + 20),
            details: None,
        };
        let signal = SignalExecutionOutcome {
            action_id: action.action_id.clone(),
            target: Some(target),
            term_command_sha256: None,
            sigterm_disposition: SignalDisposition::Caught,
            sigterm_recheck: None,
            configured_grace_ms: grace_ms,
            observed_grace_ms: Some(elapsed),
            term_exit_observed_ms: exit_ms,
            sigterm_delivered: true,
            sigcont_delivered: false,
            sigkill_delivered: exit_ms.is_none(),
            escalation_reason: exit_ms
                .is_none()
                .then_some(SignalEscalationReason::GraceExpired),
            execution_elapsed_ms: elapsed + 10,
        };
        (action, result, signal)
    }

    fn at(index: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::Duration::seconds(index)
    }

    fn observation(index: u32, exit_ms: Option<u64>, grace_ms: u64) -> TermGraceObservation {
        let (action, result, signal) = execution(index, exit_ms, grace_ms);
        TermGraceObservation::from_execution(
            SESSION,
            at(i64::from(index)),
            &action,
            &action.target,
            "node",
            COMMAND,
            &result,
            &signal,
        )
        .unwrap()
    }

    #[test]
    fn signal_learning_requires_verified_matching_uncensored_receipts() {
        let (action, result, signal) = execution(1, Some(120), 5_000);
        let accept = |action: &PlanAction,
                      source: &pt_common::ProcessIdentity,
                      result: &ActionResult,
                      signal: &SignalExecutionOutcome| {
            TermGraceObservation::from_execution(
                SESSION,
                at(1),
                action,
                source,
                "node",
                COMMAND,
                result,
                signal,
            )
        };
        assert!(accept(&action, &action.target, &result, &signal).is_some());
        for status in [
            ActionStatus::Timeout,
            ActionStatus::Failed,
            ActionStatus::IdentityMismatch,
            ActionStatus::Skipped,
        ] {
            let mut failed = result.clone();
            failed.status = status;
            assert!(accept(&action, &action.target, &failed, &signal).is_none());
        }
        for disposition in [SignalDisposition::Ignored, SignalDisposition::Unknown] {
            let mut uncertain = signal.clone();
            uncertain.sigterm_disposition = disposition;
            assert!(accept(&action, &action.target, &result, &uncertain).is_none());
        }
        let mut replacement = action.target.clone();
        replacement.start_id = pt_common::StartId::from_linux("other-boot", 100, replacement.pid.0);
        assert!(accept(&action, &replacement, &result, &signal).is_none());
        let mut mismatch = signal.clone();
        mismatch.target = Some(replacement);
        assert!(accept(&action, &action.target, &result, &mismatch).is_none());
        mismatch = signal.clone();
        mismatch.action_id = "different-action".into();
        assert!(accept(&action, &action.target, &result, &mismatch).is_none());
        mismatch = signal.clone();
        mismatch.configured_grace_ms = 1_000;
        assert!(accept(&action, &action.target, &result, &mismatch).is_none());
        mismatch = signal.clone();
        mismatch.sigterm_delivered = false;
        assert!(accept(&action, &action.target, &result, &mismatch).is_none());
        mismatch = signal.clone();
        mismatch.term_exit_observed_ms = None;
        assert!(accept(&action, &action.target, &result, &mismatch).is_none());
        let (escalated_action, escalated_result, mut escalated) = execution(1, None, 5_000);
        assert!(accept(
            &escalated_action,
            &action.target,
            &escalated_result,
            &escalated
        )
        .is_some());
        escalated.observed_grace_ms = Some(100);
        assert!(accept(
            &escalated_action,
            &action.target,
            &escalated_result,
            &escalated
        )
        .is_none());
        let mut routed = action.clone();
        routed.routing = ActionRouting::DStateLowConfidence;
        assert!(accept(&routed, &routed.target, &result, &signal).is_none());
        let mut bound = action.clone();
        bound.timeouts.term_grace_command_sha256 = Some("a".repeat(64));
        assert!(accept(&bound, &bound.target, &result, &signal).is_none());
        let mut matching_command = signal.clone();
        matching_command.term_command_sha256 = Some("a".repeat(64));
        assert!(accept(&bound, &bound.target, &result, &matching_command).is_some());
        matching_command.term_command_sha256 = Some("b".repeat(64));
        assert!(accept(&bound, &bound.target, &result, &matching_command).is_none());

        // Old receipts remain readable but lack the binding and observed exit
        // needed for learning, even if their older outcome looked successful.
        let mut legacy = serde_json::to_value(&signal).unwrap();
        for field in ["action_id", "target", "term_exit_observed_ms"] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let legacy: SignalExecutionOutcome = serde_json::from_value(legacy).unwrap();
        assert!(accept(&action, &action.target, &result, &legacy).is_none());
    }

    #[test]
    fn adaptive_patterns_preserve_interpreter_programs_arguments_and_inline_bytes() {
        for (comm, first, other) in [
            (
                "node",
                "node /srv/fast.mjs --watch",
                "node /srv/slow.mjs --watch",
            ),
            (
                "node",
                "node /srv/fast.cjs --watch",
                "node /srv/slow.cjs --watch",
            ),
            ("java", "java -jar /srv/fast.jar", "java -jar /srv/slow.jar"),
            (
                "bash",
                "bash /srv/fast.sh --watch",
                "bash /srv/slow.sh --watch",
            ),
            ("node", "node -e 'cleanup(1)'", "node -e 'cleanup(1000)'"),
            (
                "worker",
                "worker /srv/small-input",
                "worker /srv/large-input",
            ),
        ] {
            let first_id = term_grace_pattern_id(comm, first).unwrap();
            assert_eq!(first_id, term_grace_pattern_id(comm, first).unwrap());
            assert_ne!(first_id, term_grace_pattern_id(comm, other).unwrap());
            assert!(!first_id.contains("/srv/"));
        }
        assert_ne!(
            term_grace_pattern_id("ab", "c"),
            term_grace_pattern_id("a", "bc")
        );
    }

    #[test]
    fn signal_history_persists_merges_deduplicates_and_keeps_commands_private() {
        let directory = tempfile::tempdir().unwrap();
        let mut first = TermGraceStore::load(directory.path()).unwrap();
        let mut concurrent = TermGraceStore::load(directory.path()).unwrap();
        let receipt = observation(1, Some(120), 5_000);
        assert!(first.record(receipt.clone()).unwrap());
        assert!(concurrent.record(receipt.clone()).unwrap());
        first.save().unwrap();
        concurrent.record(observation(2, Some(300), 5_000)).unwrap();
        concurrent.save().unwrap();
        let mut restored = TermGraceStore::load(directory.path()).unwrap();
        assert_eq!(restored.history.observations.len(), 2);
        assert!(!restored.record(receipt.clone()).unwrap());
        let mut conflict = receipt;
        conflict.result = TermGraceResult::Exited { observed_ms: 400 };
        assert!(restored.record(conflict).is_err());
        assert_eq!(restored.history.observations.len(), 2);
        let path = directory.path().join(TERM_GRACE_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("PRIVATE_TERM_TIMING_CANARY"));
        assert!(!text.contains(SESSION));
        assert!(!directory.path().join(DECISIONS_FILE).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn adaptive_grace_keeps_cold_stale_and_unrelated_patterns_neutral() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = TermGraceStore::load(directory.path()).unwrap();
        for index in 0..7 {
            store.record(observation(index, Some(100), 5_000)).unwrap();
        }
        assert!(store
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(100))
            .unwrap()
            .is_none());
        store.record(observation(7, Some(2_000), 5_000)).unwrap();
        let recommendation = store
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(100))
            .unwrap()
            .unwrap();
        assert_eq!(
            recommendation.grace_ms, 2_500,
            "known slow cleanup retains margin"
        );
        assert_eq!(recommendation.successful_exit_quantile_ms, Some(2_000));
        assert_eq!(recommendation.term_successes, 8);
        assert_eq!(recommendation.term_sufficient_posterior_mean, 0.9);
        assert!(store
            .recommend_at(
                "node",
                "node /srv/unrelated.js --worker",
                5_000,
                1_000,
                8,
                at(100)
            )
            .unwrap()
            .is_none());
        assert!(store
            .recommend_at(
                "node",
                COMMAND,
                5_000,
                1_000,
                8,
                at(100) + chrono::Duration::days(31)
            )
            .unwrap()
            .is_none());
        assert!(store
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(-1))
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .recommend_at("node", COMMAND, 500, 1_000, 8, at(100))
                .unwrap()
                .unwrap()
                .grace_ms,
            500
        );
        assert!(store
            .recommend_at("node", COMMAND, 0, 1_000, 8, at(100))
            .is_err());
        assert!(store
            .recommend_at("node", COMMAND, 5_000, 1_000, 1, at(100))
            .is_err());
    }

    #[test]
    fn repeated_full_grace_escalations_shorten_but_mixed_or_censored_evidence_does_not() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = TermGraceStore::load(directory.path()).unwrap();
        for index in 0..8 {
            store.record(observation(index, None, 5_000)).unwrap();
        }
        store.save().unwrap();
        let mut restored = TermGraceStore::load(directory.path()).unwrap();
        let recommendation = restored
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(100))
            .unwrap()
            .unwrap();
        assert_eq!(recommendation.grace_ms, 1_000);
        assert_eq!(
            recommendation.reason,
            TermGraceRecommendationReason::RepeatedEscalation
        );
        assert_eq!(recommendation.term_sufficient_posterior_mean, 0.1);
        assert_eq!(recommendation.successful_exit_quantile_ms, None);
        assert!(restored
            .recommend_at("node", COMMAND, 6_000, 1_000, 8, at(100))
            .unwrap()
            .is_none());
        restored.record(observation(8, Some(2_000), 5_000)).unwrap();
        assert!(restored
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(100))
            .unwrap()
            .is_none());

        let shorter_directory = tempfile::tempdir().unwrap();
        let mut shorter = TermGraceStore::load(shorter_directory.path()).unwrap();
        for index in 0..8 {
            shorter.record(observation(index, None, 1_000)).unwrap();
        }
        assert!(shorter
            .recommend_at("node", COMMAND, 5_000, 1_000, 8, at(100))
            .unwrap()
            .is_none());
    }

    #[test]
    fn retention_watermark_prevents_counting_evicted_receipts_on_replay() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = TermGraceStore::load(directory.path()).unwrap();
        let oldest = observation(0, Some(100), 5_000);
        for index in 0..MAX_TERM_GRACE_OBSERVATIONS {
            let mut receipt = oldest.clone();
            if index != 0 {
                receipt.observation_id = hex::encode(Sha256::digest(index.to_le_bytes()));
                receipt.executed_at = at(index as i64);
            }
            store.record(receipt).unwrap();
        }
        store.save().unwrap();
        let mut newest = oldest.clone();
        newest.observation_id = hex::encode(Sha256::digest(b"newest receipt"));
        newest.executed_at = at(MAX_TERM_GRACE_OBSERVATIONS as i64);
        store.record(newest).unwrap();
        assert_eq!(
            store.history.observations.len(),
            MAX_TERM_GRACE_OBSERVATIONS
        );
        assert!(!store.record(oldest.clone()).unwrap());
        store.save().unwrap();
        let mut restored = TermGraceStore::load(directory.path()).unwrap();
        assert!(!restored.record(oldest).unwrap());
        assert!(restored.history.discarded_through.is_some());
    }

    #[test]
    fn corrupt_signal_history_is_preserved_and_failed_save_keeps_pending_receipts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(TERM_GRACE_FILE);
        let mut store = TermGraceStore::load(directory.path()).unwrap();
        store.record(observation(1, Some(100), 5_000)).unwrap();
        std::fs::write(&path, b"not a signal history").unwrap();
        assert!(TermGraceStore::load(directory.path()).is_err());
        assert!(store.save().is_err());
        assert_eq!(store.pending.len(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), b"not a signal history");
        std::fs::write(
            &path,
            serde_json::to_vec(&TermGraceHistory::default()).unwrap(),
        )
        .unwrap();
        store.save().unwrap();
        assert!(store.pending.is_empty());
        assert_eq!(
            TermGraceStore::load(directory.path())
                .unwrap()
                .history
                .observations
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn signal_history_refuses_symlinks_and_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("history.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&TermGraceHistory::default()).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join(TERM_GRACE_FILE)).unwrap();
        assert!(TermGraceStore::load(directory.path()).is_err());
        let oversized = tempfile::tempdir().unwrap();
        std::fs::File::create(oversized.path().join(TERM_GRACE_FILE))
            .unwrap()
            .set_len(MAX_TERM_GRACE_HISTORY_BYTES + 1)
            .unwrap();
        assert!(TermGraceStore::load(oversized.path()).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global() -> Priors {
        Priors::default()
    }

    fn test_time() -> chrono::DateTime<chrono::Utc> {
        parse_ts(Some("2026-06-01T00:00:00Z")).unwrap()
    }

    fn broad_key() -> String {
        DecisionStore::pattern_keys("node", "node /srv/unseen.js")
            .into_iter()
            .find(|key| key.starts_with("broad|"))
            .unwrap()
    }

    #[test]
    fn empty_and_missing_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        assert!(store.is_empty());
        std::fs::write(dir.path().join(DECISIONS_FILE), "{}\n").unwrap();
        assert!(DecisionStore::load(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn legacy_wrapper_format_is_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(DECISIONS_FILE),
            r#"{"standard|jest|--watch": "kill", "broad|node|": "spare"}"#,
        )
        .unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn malformed_statistics_reject_the_whole_store_at_every_specificity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DECISIONS_FILE);
        let keys = DecisionStore::pattern_keys("node", "node /srv/PRIVATE_PATTERN_CANARY.js");
        assert_eq!(keys.len(), 3);
        let invalid_fields = [
            ("kill_weight", serde_json::json!({"kill_weight": -1.0})),
            ("spare_weight", serde_json::json!({"spare_weight": -1.0})),
            (
                "updated_at",
                serde_json::json!({"updated_at": "not-a-timestamp"}),
            ),
            (
                "combined kill and spare weights",
                serde_json::json!({"kill_weight": f64::MAX, "spare_weight": f64::MAX}),
            ),
            (
                "source_weights.kill",
                serde_json::json!({"source_weights": {"source": {"kill": -1.0, "spare": 0.0}}}),
            ),
            (
                "source_weights.spare",
                serde_json::json!({"source_weights": {"source": {"kill": 0.0, "spare": -1.0}}}),
            ),
            (
                "combined source weights",
                serde_json::json!({"source_weights": {"source": {"kill": f64::MAX, "spare": f64::MAX}}}),
            ),
        ];
        for key in keys {
            for (field, invalid) in &invalid_fields {
                let mut counts = serde_json::json!({"kill": 1, "spare": 1});
                counts
                    .as_object_mut()
                    .unwrap()
                    .extend(invalid.as_object().unwrap().clone());
                let file = serde_json::json!({
                    (key.clone()): counts,
                    "exact|unrelated|safe": {"kill": 0, "spare": 1},
                });
                let bytes = file.to_string();
                std::fs::write(&path, &bytes).unwrap();
                let error = DecisionStore::load(dir.path()).unwrap_err();
                assert!(matches!(&error, DecisionStoreError::InvalidData { .. }));
                assert!(error.to_string().contains(*field), "{key}: {error}");
                assert!(!error.to_string().contains("PRIVATE_PATTERN_CANARY"));
                assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn malformed_sources_are_validated_before_retention_trims_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut sources = serde_json::Map::new();
        for index in 0..MAX_TRACKED_SOURCES {
            sources.insert(
                format!("{index:04}"),
                serde_json::json!({"kill": 1.0, "spare": 0.0}),
            );
        }
        sources.insert(
            "zz-invalid".into(),
            serde_json::json!({"kill": -1.0, "spare": 0.0}),
        );
        std::fs::write(
            dir.path().join(DECISIONS_FILE),
            serde_json::json!({
                (broad_key()): {"kill": 16, "spare": 0, "source_weights": sources},
            })
            .to_string(),
        )
        .unwrap();
        let error = DecisionStore::load(dir.path()).unwrap_err();
        assert!(error.to_string().contains("source_weights.kill"));
    }

    #[test]
    fn large_legacy_counts_remain_visible_at_every_specificity() {
        let cmd = "node /srv/review.js";
        for key in DecisionStore::pattern_keys("node", cmd) {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join(DECISIONS_FILE),
                serde_json::json!({
                    (key.clone()): {
                        "kill": u32::MAX,
                        "spare": 1,
                        "source_weights": {
                            "source-a": {"kill": 1.0, "spare": 0.0},
                            "source-b": {"kill": 1.0, "spare": 0.0},
                        },
                    },
                })
                .to_string(),
            )
            .unwrap();
            let mut store = DecisionStore::load(dir.path()).unwrap();
            let before = store.entries[&key].clone();
            assert_eq!(before.total(), u64::from(u32::MAX) + 1);
            let prior = store
                .learned_prior_at("node", cmd, &global(), test_time())
                .unwrap();
            assert_eq!(prior.pattern_key, key);
            assert_eq!((prior.kill, prior.spare), (u32::MAX, 1));
            assert_eq!(prior.weight, 1.0);
            assert_eq!(prior.effective_sample_count, f64::from(u32::MAX) + 1.0);
            assert_eq!(prior.abandonment_prior, LEARNED_PRIOR_MAX);

            store.record_at("sleep", "sleep 600", Verdict::Spare, test_time());
            store.save().unwrap();
            let loaded = DecisionStore::load(dir.path()).unwrap();
            assert_eq!(loaded.entries[&key], before);
            let prior = loaded
                .learned_prior_at("node", cmd, &global(), test_time())
                .unwrap();
            assert_eq!(prior.pattern_key, key);
            assert_eq!(prior.weight, 1.0);
        }
    }

    #[test]
    fn saturated_counts_allow_larger_weights_and_future_times_do_not_amplify_them() {
        let cmd = "node /srv/review.js";
        let max = f64::from(u32::MAX);
        let now = test_time();
        let future = now + chrono::Duration::days(30);
        for key in DecisionStore::pattern_keys("node", cmd) {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join(DECISIONS_FILE),
                serde_json::json!({
                    (key.clone()): {
                        "kill": u32::MAX,
                        "spare": u32::MAX,
                        "kill_weight": max * 2.0,
                        "spare_weight": max,
                        "updated_at": future.to_rfc3339(),
                        "source_weights": {
                            "source-a": {"kill": max, "spare": 0.0},
                            "source-b": {"kill": max, "spare": 0.0},
                        },
                    },
                })
                .to_string(),
            )
            .unwrap();
            let mut store = DecisionStore::load(dir.path()).unwrap();
            let prior = store.learned_prior_at("node", cmd, &global(), now).unwrap();
            assert_eq!(prior.pattern_key, key);
            assert_eq!(prior.weight, 1.5);
            assert_eq!(prior.effective_sample_count, max * 3.0);
            let global_ab =
                global().classes.abandoned.prior_prob + global().classes.zombie.prior_prob;
            let expected = (max * 2.0 + PRIOR_STRENGTH * global_ab) / (max * 3.0 + PRIOR_STRENGTH);
            assert!((prior.abandonment_prior - expected).abs() < 1e-12);

            store.record_at("node", cmd, Verdict::Spare, now);
            store.save().unwrap();
            let loaded = DecisionStore::load(dir.path()).unwrap();
            let counts = &loaded.entries[&key];
            assert_eq!(counts.total(), u64::from(u32::MAX) * 2);
            assert_eq!(counts.kill_weight, Some(max * 2.0));
            let added_weight = 0.5_f64.powf(30.0 / DECAY_HALF_LIFE_DAYS);
            assert!((counts.spare_weight.unwrap() - (max + added_weight)).abs() < 1e-6);
            assert_eq!(parse_ts(counts.updated_at.as_deref()), Some(future));
        }
    }

    #[test]
    fn failed_save_preserves_corrupt_disk_and_pending_verdicts_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DECISIONS_FILE);
        let cmd = "node /srv/review.js";
        let mut store = DecisionStore::load(dir.path()).unwrap();
        store.record_at("node", cmd, Verdict::Kill, test_time());
        store.save().unwrap();
        let valid = std::fs::read_to_string(&path).unwrap();
        store.record_at("node", cmd, Verdict::Spare, test_time());
        let pending = store.pending.clone();
        let key = DecisionStore::pattern_keys("node", cmd).remove(0);
        let mut corrupt: serde_json::Value = serde_json::from_str(&valid).unwrap();
        corrupt[&key]["spare_weight"] = serde_json::json!(-1.0);
        let corrupt = corrupt.to_string();
        std::fs::write(&path, &corrupt).unwrap();

        let error = store.save().unwrap_err();
        assert!(matches!(error, DecisionStoreError::InvalidData { .. }));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), corrupt);
        assert_eq!(store.pending, pending);

        std::fs::write(&path, valid).unwrap();
        store.save().unwrap();
        assert!(store.pending.is_empty());
        let restored = DecisionStore::load(dir.path()).unwrap();
        let prior = restored
            .learned_prior_at("node", cmd, &global(), test_time())
            .unwrap();
        assert_eq!((prior.kill, prior.spare), (1, 1));
        assert_eq!(prior.effective_sample_count, 2.0);
    }

    #[test]
    fn save_refuses_overflowing_merges_and_nonfinite_weights_before_serializing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DECISIONS_FILE);
        let key = DecisionStore::pattern_keys("sleep", "sleep 600").remove(0);
        let counts = PatternCounts {
            kill: u32::MAX,
            kill_weight: Some(f64::MAX * 0.75),
            ..Default::default()
        };
        let file = serde_json::to_string(&BTreeMap::from([(key.clone(), counts.clone())])).unwrap();
        std::fs::write(&path, &file).unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let before = store.entries[&key].clone();
        store.pending.insert(key.clone(), counts.clone());
        assert!(matches!(
            store.save(),
            Err(DecisionStoreError::InvalidData { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), file);
        assert_eq!(store.entries[&key], before);
        assert_eq!(store.pending[&key], counts);

        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for source_weight in [false, true] {
                let mut store = DecisionStore::load(dir.path()).unwrap();
                let mut pending = PatternCounts {
                    kill: 1,
                    ..Default::default()
                };
                if source_weight {
                    pending.source_weights.insert(
                        "source".into(),
                        SourceWeights {
                            kill: invalid,
                            spare: 0.0,
                        },
                    );
                } else {
                    pending.kill_weight = Some(invalid);
                }
                store.pending.insert(key.clone(), pending);
                assert!(matches!(
                    store.save(),
                    Err(DecisionStoreError::InvalidData { .. })
                ));
                assert_eq!(std::fs::read_to_string(&path).unwrap(), file);
                assert!(!store.pending.is_empty());
            }
        }
    }

    #[test]
    fn record_save_load_roundtrip_and_learned_prior() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let cmd = "node /home/alice/app/node_modules/.bin/jest --watch tests/";
        assert!(store.learned_prior("node", cmd, &global()).is_none());

        store.record("node", cmd, Verdict::Kill);
        store.record("node", cmd, Verdict::Kill);
        store.save().unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();

        let learned = store
            .learned_prior("node", cmd, &global())
            .expect("learned");
        let g = global();
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(learned.abandonment_prior > base, "kills raise the prior");
        assert_eq!((learned.kill, learned.spare), (2, 0));
        assert_eq!(learned.specificity, "exact");
        assert!((learned.effective_sample_count - 2.0).abs() < 1e-3);

        // Overrides are a valid distribution carrying the learned mass.
        let o = DecisionStore::overrides_for(&learned, &g);
        let sum =
            o.useful.unwrap() + o.useful_bad.unwrap() + o.abandoned.unwrap() + o.zombie.unwrap();
        assert!((sum - 1.0).abs() < 1e-9);
        assert!(
            (o.abandoned.unwrap() + o.zombie.unwrap() - learned.abandonment_prior).abs() < 1e-9
        );
    }

    #[test]
    fn concurrent_writers_keep_every_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = "node server.js --port 3000";
        // Two stores loaded before either saves: a plain rewrite would lose one.
        let mut a = DecisionStore::load(dir.path()).unwrap();
        let mut b = DecisionStore::load(dir.path()).unwrap();
        a.record("node", cmd, Verdict::Kill);
        b.record("node", cmd, Verdict::Spare);
        a.save().unwrap();
        b.save().unwrap();

        // Many threads racing load -> record -> save.
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let path = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let mut s = DecisionStore::load(&path).unwrap();
                    s.record("node", cmd, Verdict::Kill);
                    s.save().unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let store = DecisionStore::load(dir.path()).unwrap();
        let learned = store.learned_prior("node", cmd, &global()).unwrap();
        assert_eq!((learned.kill, learned.spare), (17, 1));
        let key = DecisionStore::pattern_keys("node", cmd)
            .into_iter()
            .find(|key| key.starts_with("broad|"))
            .unwrap();
        let source = store.entries[&key].source_weights.values().next().unwrap();
        assert!((source.kill - 17.0).abs() < 1e-3);
        assert!((source.spare - 1.0).abs() < 1e-3);
    }

    #[test]
    fn old_verdicts_decay_toward_the_global_prior() {
        let now = chrono::Utc::now();
        let year_ago = (now - chrono::Duration::days(360)).to_rfc3339();
        assert!((decay_weight(Some(&year_ago), now) - 0.25).abs() < 1e-3);
        assert_eq!(decay_weight(None, now), 1.0);

        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..4 {
            store.record("sleep", "sleep 100", Verdict::Kill);
            store.record("cat", "cat /dev/zero", Verdict::Kill);
        }
        for key in DecisionStore::pattern_keys("cat", "cat /dev/zero") {
            store.entries.get_mut(&key).unwrap().updated_at = Some(year_ago.clone());
        }
        let fresh = store.learned_prior("sleep", "sleep 100", &g).unwrap();
        let stale = store.learned_prior("cat", "cat /dev/zero", &g).unwrap();
        assert!((stale.weight - 0.25).abs() < 1e-3);
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(fresh.abandonment_prior > stale.abandonment_prior);
        assert!(stale.abandonment_prior > base, "decayed, not erased");
    }

    /// Each verdict decays from its own time. Before: a pattern kept one timestamp, so
    /// 50 kills from two years ago plus one spare today counted as 50 fresh kills.
    #[test]
    fn every_verdict_decays_from_its_own_time() {
        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let now = chrono::Utc::now();
        let two_years_ago = now - chrono::Duration::days(730);
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..50 {
            store.record_at("sleep", "sleep 600", Verdict::Kill, two_years_ago);
        }
        store.record_at("sleep", "sleep 600", Verdict::Spare, now);

        let learned = store
            .learned_prior_at("sleep", "sleep 600", &g, now)
            .unwrap();
        assert_eq!((learned.kill, learned.spare), (50, 1));
        // 50 kills at 0.5^(730/180) ~ 0.06 each ~ 3.0, plus one fresh spare.
        let expected_kill_w = 50.0 * 0.5_f64.powf(730.0 / DECAY_HALF_LIFE_DAYS);
        let global_ab = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        let expected = (expected_kill_w + PRIOR_STRENGTH * global_ab)
            / (expected_kill_w + 1.0 + PRIOR_STRENGTH);
        assert!(
            (learned.abandonment_prior - expected).abs() < 1e-6,
            "{} vs {expected}",
            learned.abandonment_prior
        );
        assert!(
            learned.abandonment_prior < 0.7,
            "old kills no longer dominate"
        );

        // Decayed sums survive a save/load round trip and merge with a concurrent writer.
        store.save().unwrap();
        let mut other = DecisionStore::load(dir.path()).unwrap();
        other.record_at("sleep", "sleep 600", Verdict::Spare, now);
        other.save().unwrap();
        let reloaded = DecisionStore::load(dir.path()).unwrap();
        let learned = reloaded
            .learned_prior_at("sleep", "sleep 600", &g, now)
            .unwrap();
        assert_eq!((learned.kill, learned.spare), (50, 2));
        let expected = (expected_kill_w + PRIOR_STRENGTH * global_ab)
            / (expected_kill_w + 2.0 + PRIOR_STRENGTH);
        assert!((learned.abandonment_prior - expected).abs() < 1e-6);
    }

    /// One verdict on `node x.js` must not set the prior for `node y.js` (broad
    /// pattern `node.*`); a second, different node script under the same broad pattern
    /// makes it a habit worth generalizing.
    #[test]
    fn one_script_does_not_speak_for_every_run_of_its_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        store.record("node", "node /home/alice/x.js", Verdict::Kill);
        assert!(store
            .learned_prior("node", "node /home/alice/x.js", &g)
            .is_some());
        assert!(
            store.learned_prior("node", "node /srv/y.js", &g).is_none(),
            "{:?}",
            store.learned_prior("node", "node /srv/y.js", &g)
        );

        store.record("node", "node /home/alice/z.js", Verdict::Kill);
        let learned = store
            .learned_prior("node", "node /srv/y.js", &g)
            .expect("two distinct scripts generalize");
        assert!(
            learned.pattern_key.starts_with("broad|"),
            "{}",
            learned.pattern_key
        );
    }

    #[test]
    fn one_extensionless_or_option_bound_job_cannot_label_another() {
        for (comm, first, second) in [
            ("bash", "bash /srv/backup", "bash /srv/build"),
            ("bash", "bash backup", "bash build"),
            ("sh", "sh -- /srv/backup/run", "sh -- /srv/build/run"),
            ("python3", "python3 /srv/cleanup", "python3 /srv/backup"),
            ("node", "node /srv/cleanup", "node /srv/backup"),
            (
                "bash",
                "bash --rcfile /srv/shared.sh /srv/backup.sh",
                "bash --rcfile /srv/shared.sh /srv/build.sh",
            ),
            (
                "node",
                "node -r /srv/shared.js /srv/backup.js",
                "node -r /srv/shared.js /srv/build.js",
            ),
            (
                "python3",
                "python3 -W ignore /srv/worker.py",
                "python3 -W error /srv/worker.py",
            ),
            (
                "bash",
                "bash /srv/nightly backup",
                "bash /srv/nightly build",
            ),
        ] {
            for verdict in [Verdict::Kill, Verdict::Spare] {
                let mut store = DecisionStore::default();
                store.record_at(comm, first, verdict, test_time());
                let learned = store
                    .learned_prior_at(comm, first, &global(), test_time())
                    .unwrap();
                assert_eq!(learned.specificity, "exact");
                assert_eq!(learned.kill, u32::from(verdict == Verdict::Kill));
                assert_eq!(learned.spare, u32::from(verdict == Verdict::Spare));
                assert!(
                    store
                        .learned_prior_at(comm, second, &global(), test_time())
                        .is_none(),
                    "{verdict:?}: {first} must not label {second}"
                );
            }
        }
    }

    #[test]
    fn corrected_interpreter_keys_roundtrip_without_private_arguments() {
        for verdict in [Verdict::Kill, Verdict::Spare] {
            let directory = tempfile::tempdir().unwrap();
            let mut store = DecisionStore::load(directory.path()).unwrap();
            let first = "bash /srv/PRIVATE_SCRIPT_CANARY --token LEARNING_SECRET_CANARY";
            let second = "bash /srv/unrelated --token LEARNING_SECRET_CANARY";
            store.record_at("bash", first, verdict, test_time());
            store.save().unwrap();
            let saved = std::fs::read_to_string(directory.path().join(DECISIONS_FILE)).unwrap();
            assert!(!saved.contains("PRIVATE_SCRIPT_CANARY"));
            assert!(!saved.contains("LEARNING_SECRET_CANARY"));
            let restored = DecisionStore::load(directory.path()).unwrap();
            let same = restored
                .learned_prior_at("bash", first, &global(), test_time())
                .unwrap();
            assert_eq!(
                (same.kill, same.spare),
                (
                    u32::from(verdict == Verdict::Kill),
                    u32::from(verdict == Verdict::Spare)
                )
            );
            assert!(restored
                .learned_prior_at("bash", second, &global(), test_time())
                .is_none());
        }
    }

    #[test]
    fn legacy_extensionless_source_cannot_supply_a_second_generalization_vote() {
        let mut store = DecisionStore::default();
        for old_key in ["standard|bash|", "broad|bash.*|"] {
            store.entries.insert(
                old_key.to_string(),
                PatternCounts {
                    kill: 1,
                    updated_at: Some(test_time().to_rfc3339()),
                    source_weights: BTreeMap::from([(
                        source_id("standard|bash|"),
                        SourceWeights {
                            kill: 1.0,
                            spare: 0.0,
                        },
                    )]),
                    ..Default::default()
                },
            );
        }
        let first = "bash /srv/backup";
        let second = "bash /srv/build";
        let unseen = "bash /srv/deploy";
        // No old bare standard key may silently label a newly identified job.
        assert!(store
            .learned_prior_at("bash", unseen, &global(), test_time())
            .is_none());
        store.record_at("bash", first, Verdict::Kill, test_time());
        assert!(store
            .learned_prior_at("bash", unseen, &global(), test_time())
            .is_none());
        // Two independent new identities still satisfy the existing broad gate.
        store.record_at("bash", second, Verdict::Kill, test_time());
        let learned = store
            .learned_prior_at("bash", unseen, &global(), test_time())
            .unwrap();
        assert_eq!(learned.specificity, "broad");
        assert_eq!(learned.kill, 2);
        assert!(learned.pattern_key.contains("program-v2:"));
    }

    #[test]
    fn opaque_interpreter_generalization_requires_concordant_distinct_jobs() {
        let mut store = DecisionStore::default();
        for _ in 0..50 {
            store.record_at("bash", "bash /srv/backup", Verdict::Kill, test_time());
        }
        assert!(store
            .learned_prior_at("bash", "bash /srv/unseen", &global(), test_time())
            .is_none());
        store.record_at("bash", "bash /srv/build", Verdict::Spare, test_time());
        assert!(store
            .learned_prior_at("bash", "bash /srv/unseen", &global(), test_time())
            .is_none());
        let spared = store
            .learned_prior_at("bash", "bash /srv/build", &global(), test_time())
            .unwrap();
        assert_eq!((spared.kill, spared.spare), (0, 1));
    }

    #[test]
    fn existing_script_and_module_spares_remain_effective() {
        for (comm, command, legacy_key) in [
            ("node", "node /srv/worker.js", "standard|node|.*worker.js"),
            (
                "python3",
                "python3 -m pytest",
                "standard|python.*|-m pytest",
            ),
            (
                "python3",
                "python3 /srv/worker.py",
                "standard|python.*|.*worker.py",
            ),
        ] {
            let mut store = DecisionStore::default();
            store.entries.insert(
                legacy_key.to_string(),
                PatternCounts {
                    spare: 1,
                    updated_at: Some(test_time().to_rfc3339()),
                    ..Default::default()
                },
            );
            let learned = store
                .learned_prior_at(comm, command, &global(), test_time())
                .unwrap();
            assert_eq!(learned.pattern_key, legacy_key);
            assert_eq!((learned.kill, learned.spare), (0, 1));
            assert!(!DecisionStore::pattern_keys(comm, command)
                .iter()
                .any(|key| key.contains("program-v2:")));
        }
    }

    #[test]
    fn one_inline_job_cannot_train_an_unrelated_program_through_standard_fallback() {
        for (comm, first, second) in [
            (
                "python3",
                "python3 -c print('first')",
                "python3 -c print('second')",
            ),
            (
                "python3",
                "python3 -Ic print('first')",
                "python3 -Ic print('second')",
            ),
            (
                "bash",
                "bash -lc exec /srv/first",
                "bash -lc exec /srv/second",
            ),
            ("node", "node -e doFirst()", "node -e doSecond()"),
            ("node", "node --eval=doFirst()", "node --eval=doSecond()"),
            (
                "node",
                "node -r /srv/first -e run()",
                "node -r /srv/second -e run()",
            ),
            (
                "python3",
                "python3 -c print('a b')",
                "python3 -c print('a  b')",
            ),
        ] {
            let mut store = DecisionStore::default();
            for _ in 0..50 {
                store.record_at(comm, first, Verdict::Kill, test_time());
            }
            let learned = store
                .learned_prior_at(comm, first, &global(), test_time())
                .unwrap();
            assert_eq!(learned.specificity, "exact");
            assert_eq!(learned.kill, 50);
            assert!(
                store
                    .learned_prior_at(comm, second, &global(), test_time())
                    .is_none(),
                "{first} must not label {second}"
            );
        }
    }

    #[test]
    fn inline_generalization_requires_distinct_concordant_jobs() {
        let mut store = DecisionStore::default();
        let first = "python3 -c first_job()";
        let second = "python3 -c second_job()";
        let unseen = "python3 -c unseen_job()";
        store.record_at("python3", first, Verdict::Kill, test_time());
        assert!(store
            .learned_prior_at("python3", unseen, &global(), test_time())
            .is_none());
        store.record_at("python3", second, Verdict::Spare, test_time());
        assert!(store
            .learned_prior_at("python3", unseen, &global(), test_time())
            .is_none());
        // One kill cancels the second source's spare; a second establishes its
        // own material support, rather than reusing the first job's repetitions.
        store.record_at("python3", second, Verdict::Kill, test_time());
        assert!(store
            .learned_prior_at("python3", unseen, &global(), test_time())
            .is_none());
        store.record_at("python3", second, Verdict::Kill, test_time());
        let prior = store
            .learned_prior_at("python3", unseen, &global(), test_time())
            .unwrap();
        assert_eq!(prior.specificity, "broad");
        assert_eq!((prior.kill, prior.spare), (3, 1));
    }

    #[test]
    fn inline_learning_roundtrip_does_not_persist_source_literals_or_use_unsafe_legacy_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(DECISIONS_FILE);
        // An earlier store could have generalized an arbitrary Python program
        // into this bare option. It must not silently regain that influence.
        std::fs::write(&path, r#"{"standard|python.*|-c":{"kill":50,"spare":0}}"#).unwrap();
        let mut store = DecisionStore::load(directory.path()).unwrap();
        let cmdline = "python3 -c send_secret('INLINE_SECRET_CANARY_92731')";
        assert!(store
            .learned_prior_at("python3", cmdline, &global(), test_time())
            .is_none());
        store.record_at("python3", cmdline, Verdict::Spare, test_time());
        store.save().unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(!saved.contains("INLINE_SECRET_CANARY"));
        assert!(!saved.contains("send_secret"));
        let restored = DecisionStore::load(directory.path()).unwrap();
        let prior = restored
            .learned_prior_at("python3", cmdline, &global(), test_time())
            .unwrap();
        assert_eq!(prior.specificity, "exact");
        assert_eq!((prior.kill, prior.spare), (0, 1));
        assert!(restored
            .learned_prior_at("python3", "python3 -c unrelated()", &global(), test_time())
            .is_none());
    }

    #[test]
    fn legacy_inline_source_ids_cannot_supply_a_second_generalization_vote() {
        let mut store = DecisionStore::default();
        let old_key = "broad|python.*|".to_string();
        store.entries.insert(
            old_key,
            PatternCounts {
                kill: 1,
                updated_at: Some(test_time().to_rfc3339()),
                source_weights: BTreeMap::from([(
                    "old-inline-source".to_string(),
                    SourceWeights {
                        kill: 1.0,
                        spare: 0.0,
                    },
                )]),
                ..Default::default()
            },
        );
        store.record_at(
            "python3",
            "python3 -c first_job()",
            Verdict::Kill,
            test_time(),
        );
        assert!(store
            .learned_prior_at("python3", "python3 -c unseen_job()", &global(), test_time())
            .is_none());
    }

    #[test]
    fn conflicting_sources_cannot_generalize_a_heavily_repeated_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let now = test_time();
        for _ in 0..50 {
            store.record_at("node", "node /srv/a.js", Verdict::Kill, now);
        }
        store.record_at("node", "node /srv/b.js", Verdict::Spare, now);
        assert_eq!(store.entries[&broad_key()].source_weights.len(), 2);
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_none());
        // The guard concerns broad transfer; each explicitly labeled script keeps
        // its own verdict, including the minority spare.
        let base = global().classes.abandoned.prior_prob + global().classes.zombie.prior_prob;
        let killed = store
            .learned_prior_at("node", "node /srv/a.js", &global(), now)
            .unwrap();
        let spared = store
            .learned_prior_at("node", "node /srv/b.js", &global(), now)
            .unwrap();
        assert!(killed.abandonment_prior > base);
        assert!(spared.abandonment_prior < base);
        store.save().unwrap();
        let reloaded = DecisionStore::load(dir.path()).unwrap();
        assert!(reloaded
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_none());
    }

    #[test]
    fn broad_prior_reports_specificity_and_effective_sample_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let now = test_time();
        let earlier = now - chrono::Duration::days(90);
        store.record_at("node", "node /srv/a.js", Verdict::Kill, earlier);
        store.record_at("node", "node /srv/b.js", Verdict::Kill, earlier);
        let learned = store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .expect("two agreeing sources still have material support");
        assert_eq!(learned.specificity, "broad");
        assert!((learned.effective_sample_count - 2.0_f64.sqrt()).abs() < 1e-12);
        let explanation = serde_json::to_value(&learned).unwrap();
        assert_eq!(explanation["specificity"], "broad");
        assert_eq!(
            explanation["effective_sample_count"].as_f64(),
            Some(learned.effective_sample_count)
        );
    }

    #[test]
    fn contradictory_updates_revoke_source_agreement() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let now = test_time();
        store.record_at("node", "node /srv/a.js", Verdict::Kill, now);
        store.record_at("node", "node /srv/a.js", Verdict::Kill, now);
        store.record_at("node", "node /srv/b.js", Verdict::Kill, now);
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_some());

        // B first becomes tied, then disagrees with A. Neither state is a second
        // kill-supporting source, although aggregate kills still outnumber spares.
        for _ in 0..2 {
            store.record_at("node", "node /srv/b.js", Verdict::Spare, now);
            assert!(store
                .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
                .is_none());
        }
        store.save().unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_none());
    }

    #[test]
    fn stale_source_ids_cannot_supply_a_second_material_vote() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let earlier = test_time();
        for cmd in ["node /srv/a.js", "node /srv/b.js"] {
            store.record_at("node", cmd, Verdict::Kill, earlier);
        }
        let at_half_life = earlier + chrono::Duration::days(180);
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), at_half_life)
            .is_some());
        let now = at_half_life + chrono::Duration::days(1);
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_none());
        for _ in 0..50 {
            store.record_at("node", "node /srv/a.js", Verdict::Kill, now);
        }
        assert!(
            store
                .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
                .is_none(),
            "fresh A labels must not refresh B's old vote"
        );
        store.record_at("node", "node /srv/b.js", Verdict::Kill, now);
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_some());
    }

    #[test]
    fn concurrent_source_merges_decay_and_reverse_in_either_save_order() {
        let now = test_time();
        let earlier = now - chrono::Duration::days(720);
        let mut outcomes = Vec::new();
        for reverse in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut old = DecisionStore::load(dir.path()).unwrap();
            let mut recent = DecisionStore::load(dir.path()).unwrap();
            for cmd in ["node /srv/a.js", "node /srv/b.js"] {
                old.record_at("node", cmd, Verdict::Kill, earlier);
                recent.record_at("node", cmd, Verdict::Spare, now);
            }
            if reverse {
                recent.save().unwrap();
                old.save().unwrap();
            } else {
                old.save().unwrap();
                recent.save().unwrap();
            }
            let store = DecisionStore::load(dir.path()).unwrap();
            let learned = store
                .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
                .expect("both sources now support spare");
            assert_eq!((learned.kill, learned.spare), (2, 2));
            assert!((learned.effective_sample_count - 2.125).abs() < 1e-12);
            let base = global().classes.abandoned.prior_prob + global().classes.zombie.prior_prob;
            assert!(learned.abandonment_prior < base);
            for source in store.entries[&broad_key()].source_weights.values() {
                assert_eq!(
                    *source,
                    SourceWeights {
                        kill: 0.0625,
                        spare: 1.0
                    }
                );
            }
            outcomes.push(store.entries[&broad_key()].clone());
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    #[test]
    fn legacy_ids_without_directions_do_not_establish_consensus() {
        let dir = tempfile::tempdir().unwrap();
        let now = test_time();
        let file = serde_json::json!({
            (broad_key()): {
                "kill": 50,
                "spare": 1,
                "updated_at": now.to_rfc3339(),
                "sources": ["source-a", "source-b"]
            }
        });
        std::fs::write(dir.path().join(DECISIONS_FILE), file.to_string()).unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        assert!(store
            .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
            .is_none());
        store.record_at("node", "node /srv/a.js", Verdict::Kill, now);
        assert!(
            store
                .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
                .is_none(),
            "one new label cannot promote unknown legacy directions"
        );
        store.record_at("node", "node /srv/b.js", Verdict::Kill, now);
        assert!(
            store
                .learned_prior_at("node", "node /srv/unseen.js", &global(), now)
                .is_some(),
            "two newly observed agreeing sources can generalize"
        );
    }

    #[test]
    fn source_metadata_is_bounded_and_order_independent() {
        let now = test_time();
        let mut outcomes = Vec::new();
        for reverse in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut store = DecisionStore::load(dir.path()).unwrap();
            let mut commands: Vec<_> = (0..64)
                .map(|index| format!("node /srv/task_{index}.js"))
                .collect();
            if reverse {
                commands.reverse();
            }
            for cmd in commands {
                store.record_at("node", &cmd, Verdict::Kill, now);
            }
            store.save().unwrap();
            let store = DecisionStore::load(dir.path()).unwrap();
            let broad = &store.entries[&broad_key()];
            assert_eq!(broad.source_weights.len(), MAX_TRACKED_SOURCES);
            assert_eq!(broad.kill, 64);
            outcomes.push(broad.clone());
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    #[test]
    fn broad_consensus_must_match_actual_prior_movement() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let now = test_time();
        let mut g = global();
        g.classes.abandoned.prior_prob = 0.15;
        g.classes.zombie.prior_prob = 0.10;
        for cmd in ["node /srv/a.js", "node /srv/b.js"] {
            store.record_at("node", cmd, Verdict::Kill, now);
            store.record_at("node", cmd, Verdict::Spare, now);
            store.record_at("node", cmd, Verdict::Spare, now);
        }
        assert!(
            store
                .learned_prior_at("node", "node /srv/unseen.js", &g, now)
                .is_none(),
            "spare consensus must not raise a 25% abandonment prior"
        );

        let mut store = DecisionStore::load(dir.path()).unwrap();
        g.classes.abandoned.prior_prob = 0.88;
        g.classes.zombie.prior_prob = 0.10;
        for cmd in ["node /srv/a.js", "node /srv/b.js"] {
            store.record_at("node", cmd, Verdict::Kill, now);
        }
        assert!(
            store
                .learned_prior_at("node", "node /srv/unseen.js", &g, now)
                .is_none(),
            "the 95% cap must not turn kill agreement into a reduction from 98%"
        );
    }

    /// A file written before decayed weights and sources existed still loads: raw
    /// counts stand in for the weights (exactly the old reading).
    #[test]
    fn store_without_weights_or_sources_loads() {
        let dir = tempfile::tempdir().unwrap();
        let key = DecisionStore::pattern_keys("sleep", "sleep 100")
            .into_iter()
            .next()
            .unwrap();
        let mut file = serde_json::Map::new();
        file.insert(
            key,
            serde_json::json!({ "kill": 3, "spare": 1, "last": "kill" }),
        );
        std::fs::write(
            dir.path().join(DECISIONS_FILE),
            serde_json::Value::Object(file).to_string(),
        )
        .unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        let learned = store
            .learned_prior("sleep", "sleep 100", &global())
            .expect("legacy counts apply");
        assert_eq!((learned.kill, learned.spare), (3, 1));
        assert!((learned.weight - 1.0).abs() < 1e-12);
    }

    #[test]
    fn learned_prior_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..500 {
            store.record("sleep", "sleep 100", Verdict::Kill);
            store.record("vim", "vim notes.txt", Verdict::Spare);
        }
        let g = global();
        let killed = store.learned_prior("sleep", "sleep 100", &g).unwrap();
        let spared = store.learned_prior("vim", "vim notes.txt", &g).unwrap();
        assert_eq!(killed.abandonment_prior, LEARNED_PRIOR_MAX);
        assert_eq!(spared.abandonment_prior, LEARNED_PRIOR_MIN);
    }

    #[test]
    fn spares_lower_the_prior_and_path_details_generalize() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        store.record(
            "python3",
            "python3 -m http.server 8080 --bind 127.0.0.1",
            Verdict::Spare,
        );
        // Different port: the port is normalized away, so the decision applies.
        let learned = store
            .learned_prior(
                "python3",
                "python3 -m http.server 9090 --bind 127.0.0.1",
                &global(),
            )
            .expect("generalizes across ports");
        let g = global();
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(learned.abandonment_prior < base, "spare lowers the prior");
    }
}
