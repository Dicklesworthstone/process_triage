//! Dormant monitoring daemon core loop.
//!
//! Implements the library-side primitives for `ptd` (Plan §3.7):
//!
//! - **Triggers**: EWMA-based baseline tracking with sustained-window rules
//!   and cooldown/backoff to prevent flapping.
//! - **Escalation**: orchestrates scan → infer → plan pipeline, writes inbox
//!   items, respects per-user lock contention.
//! - **Core loop**: tick-based event loop with overhead budgeting.
//!
//! The CLI owns the running event loop. [`service`] provides inspectable,
//! per-user systemd and launchd installation with explicit activation.

pub mod escalation;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod service;
pub mod triggers;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::collect::pressure::{pressure_window_with_elapsed, PressureSnapshot};
use crate::decision::mem_pressure::{
    MemPressureConfig, MemPressureMonitor, MemorySignals, PressureAction, PressureEvaluation,
    PressureMode,
};
use crate::decision::pressure_regime::{
    regime_evidence_available, ProcessCensus, Regime, RegimeKind, Severity,
};
use crate::session::{SessionManifest, SessionMode, SessionState, SessionStore};

/// The incident archive is deliberately small enough to write under pressure.
pub const INCIDENT_MAX_BYTES: usize = 256 * 1024;
const INCIDENT_CHECKPOINT_MAX_BYTES: usize = 1024 * 1024;
const INCIDENT_BEFORE_SAMPLES: usize = 12;
const INCIDENT_AFTER_SAMPLES: usize = 24;
const INCIDENT_PLANNER_ATTEMPTS: usize = 8;
const INCIDENT_PENDING_ARCHIVES: usize = 2;
const INCIDENT_SAMPLE_MAX_BYTES: usize = 16 * 1024;
const INCIDENT_SCHEMA_VERSION: u32 = 1;
const INCIDENT_CHECKPOINT_FILE: &str = "daemon-incidents.json";

/// One pressure observation. Absent sensors remain absent; a missing live clock
/// or invalid reading cannot count toward recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSample {
    pub timestamp: String,
    pub pressure: Option<PressureSnapshot>,
    pub process_census: Option<ProcessCensus>,
    pub memory_mode: Option<PressureMode>,
    pub observed_live: bool,
    pub unavailable_reason: Option<String>,
}

/// A review plan associated with an incident, never evidence of an executed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPlanRef {
    pub session_id: String,
    pub plan_sha256: String,
}

impl IncidentPlanRef {
    pub fn is_valid(&self) -> bool {
        incident_session_id(&self.session_id).is_some()
            && self.plan_sha256.len() == 64
            && self
                .plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPlannerAttempt {
    pub timestamp: String,
    pub status: escalation::EscalationStatus,
    pub reason: String,
    pub session_id: Option<String>,
    pub plan: Option<IncidentPlanRef>,
}

/// A single host pressure episode, coalescing simultaneous critical diagnoses.
/// The session remains `daemon_alert/scanning` until observed recovery, because
/// capturing evidence is ongoing. No action is implied by this lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub schema_version: u32,
    pub session_id: String,
    pub revision: u64,
    pub opened_at: String,
    pub last_observed_at: String,
    pub recovered_at: Option<String>,
    pub causes: Vec<Regime>,
    pub memory_emergency: bool,
    pub before: VecDeque<IncidentSample>,
    pub after: VecDeque<IncidentSample>,
    pub planner_attempts: VecDeque<IncidentPlannerAttempt>,
    pub samples_observed: u64,
    pub samples_dropped: u64,
    pub planner_attempts_dropped: u64,
}

/// Compact links for daemon status and inbox items. The full artifact lives at
/// `sessions/<session_id>/incident.json` and follows normal session retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub session_id: String,
    pub opened_at: String,
    pub last_observed_at: String,
    pub recovered_at: Option<String>,
    pub causes: Vec<RegimeKind>,
    pub memory_emergency: bool,
    pub samples_observed: u64,
    pub samples_dropped: u64,
    pub planner_attempts_dropped: u64,
    pub latest_planner_status: Option<escalation::EscalationStatus>,
    pub latest_plan: Option<IncidentPlanRef>,
}

impl IncidentRecord {
    pub fn summary(&self) -> IncidentSummary {
        IncidentSummary {
            session_id: self.session_id.clone(),
            opened_at: self.opened_at.clone(),
            last_observed_at: self.last_observed_at.clone(),
            recovered_at: self.recovered_at.clone(),
            causes: self.causes.iter().map(|cause| cause.kind).collect(),
            memory_emergency: self.memory_emergency,
            samples_observed: self.samples_observed,
            samples_dropped: self.samples_dropped,
            planner_attempts_dropped: self.planner_attempts_dropped,
            latest_planner_status: self.planner_attempts.back().map(|attempt| attempt.status),
            latest_plan: self
                .planner_attempts
                .iter()
                .rev()
                .find_map(|attempt| attempt.plan.clone()),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != INCIDENT_SCHEMA_VERSION
            || incident_session_id(&self.session_id).is_none()
            || self.before.len() > INCIDENT_BEFORE_SAMPLES
            || self.after.len() > INCIDENT_AFTER_SAMPLES
            || self.planner_attempts.len() > INCIDENT_PLANNER_ATTEMPTS
            || self.causes.len() > 11
            || (self.causes.is_empty() && !self.memory_emergency)
            || self
                .causes
                .iter()
                .any(|cause| cause.explanation.len() > 1024 || cause.severity != Severity::Crit)
            || self.opened_at.len() > 128
            || self.last_observed_at.len() > 128
            || self
                .recovered_at
                .as_ref()
                .is_some_and(|time| time.len() > 128)
            || self.planner_attempts.iter().any(|attempt| {
                attempt.timestamp.len() > 128
                    || attempt.reason.len() > 1024
                    || attempt
                        .session_id
                        .as_ref()
                        .is_some_and(|id| incident_session_id(id).is_none())
                    || attempt.plan.as_ref().is_some_and(|plan| {
                        !plan.is_valid() || attempt.session_id.as_ref() != Some(&plan.session_id)
                    })
            })
        {
            return Err("incident record has an unsupported schema or exceeds its bounds".into());
        }
        for sample in self.before.iter().chain(&self.after) {
            sample.validate()?;
        }
        let unique_causes: std::collections::BTreeSet<_> =
            self.causes.iter().map(|cause| cause.kind).collect();
        if unique_causes.len() != self.causes.len() {
            return Err("incident contains duplicate critical causes".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > INCIDENT_MAX_BYTES
        {
            return Err("incident record exceeds its byte budget".into());
        }
        Ok(())
    }
}

impl IncidentSample {
    fn validate(&self) -> Result<(), String> {
        if self.timestamp.len() > 128
            || self
                .unavailable_reason
                .as_ref()
                .is_some_and(|reason| reason.len() > 1024)
            || self.pressure.as_ref().is_some_and(|snapshot| {
                snapshot.unavailable.len() > 8
                    || snapshot.unavailable.iter().any(|unavailable| {
                        unavailable.source.len() > 128 || unavailable.reason.len() > 512
                    })
            })
        {
            return Err("incident sample exceeds its metadata budget".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > INCIDENT_SAMPLE_MAX_BYTES
        {
            return Err("incident sample exceeds its byte budget".into());
        }
        Ok(())
    }
}

/// Bounded incident state, persisted both in daemon state and a fixed checkpoint.
/// The checkpoint closes the crash window before the normal end-of-tick save.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IncidentTracker {
    generation: u64,
    recent: VecDeque<IncidentSample>,
    active: Option<IncidentRecord>,
    pending_archives: VecDeque<IncidentRecord>,
    last: Option<IncidentSummary>,
    /// If disk errors outlast the bounded retry queue, status exposes lost archives.
    pub discarded_pending_archives: u64,
    pub storage_error: Option<String>,
    captured_pending_oom: bool,
    #[serde(skip)]
    previous: Option<(PressureSnapshot, std::time::Instant)>,
    #[serde(skip)]
    recovery_streak: u32,
}

#[derive(Serialize, Deserialize)]
struct IncidentCheckpoint {
    schema_version: u32,
    generation: u64,
    recent: VecDeque<IncidentSample>,
    active: Option<IncidentRecord>,
    pending_archives: VecDeque<IncidentRecord>,
    last: Option<IncidentSummary>,
    discarded_pending_archives: u64,
    captured_pending_oom: bool,
}

fn incident_session_id(value: &str) -> Option<pt_common::SessionId> {
    value
        .is_ascii()
        .then(|| pt_common::SessionId::parse(value))
        .flatten()
}

fn incident_text(value: &str, max_bytes: usize) -> String {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

impl IncidentTracker {
    pub fn active_summary(&self) -> Option<IncidentSummary> {
        self.active.as_ref().map(IncidentRecord::summary)
    }

    pub fn last_summary(&self) -> Option<IncidentSummary> {
        self.last.clone()
    }

    /// Restart, configuration changes, and missing observation intervals break
    /// continuity, never the incident itself.
    pub fn interrupt_observations(&mut self) {
        self.previous = None;
        self.recovery_streak = 0;
    }

    /// Capture before doing expensive planning, including ticks deferred because
    /// of the daemon's own overhead budget. PressureTriggerState must have been
    /// observed for this tick first.
    pub fn observe(
        &mut self,
        metrics: &TickMetrics,
        pressure: &triggers::PressureTriggerState,
        memory: Option<&PressureEvaluation>,
        recovery_ticks: u32,
    ) {
        let live = metrics.pressure_observed_at.is_some_and(|at| {
            self.previous
                .as_ref()
                .is_none_or(|(_, previous)| at > *previous)
        });
        let window = self.previous.as_ref().and_then(|(before, at)| {
            metrics
                .pressure
                .as_ref()
                .zip(metrics.pressure_observed_at)
                .and_then(|(after, now)| {
                    now.checked_duration_since(*at)
                        .and_then(|elapsed| pressure_window_with_elapsed(before, after, elapsed))
                })
        });
        let mut sample = IncidentSample {
            timestamp: incident_text(&metrics.timestamp, 128),
            pressure: metrics.pressure.clone(),
            process_census: metrics.process_census,
            memory_mode: memory.map(|evaluation| evaluation.mode),
            observed_live: live && metrics.pressure.is_some(),
            unavailable_reason: pressure
                .unavailable_reason
                .as_ref()
                .map(|reason| incident_text(reason, 1024)),
        };
        if let Some(snapshot) = &mut sample.pressure {
            snapshot.unavailable.truncate(8);
            for unavailable in &mut snapshot.unavailable {
                unavailable.source = incident_text(&unavailable.source, 128);
                unavailable.reason = incident_text(&unavailable.reason, 512);
            }
            // JSON's null representation for non-finite numbers cannot be read
            // back as a valid sensor value. Keep such a sample explicitly unknown.
            let valid = serde_json::to_vec(&*snapshot)
                .ok()
                .is_some_and(|bytes| serde_json::from_slice::<PressureSnapshot>(&bytes).is_ok());
            if !valid {
                sample.pressure = None;
                sample.observed_live = false;
                sample.unavailable_reason =
                    Some("pressure snapshot contains non-finite values".into());
            }
        }
        while serde_json::to_vec(&sample).is_ok_and(|bytes| bytes.len() > INCIDENT_SAMPLE_MAX_BYTES)
        {
            let removed = sample
                .pressure
                .as_mut()
                .and_then(|snapshot| snapshot.unavailable.pop());
            if removed.is_none() {
                break;
            }
            sample.unavailable_reason =
                Some("sensor error metadata was truncated to the incident byte budget".into());
        }
        let fresh = sample.observed_live;
        let mut critical = Vec::new();
        if fresh {
            if let Some(assessment) = &pressure.last_assessment {
                for regime in &assessment.regimes {
                    if regime.severity == Severity::Crit
                        && (pressure.active.get(&regime.kind) == Some(&Severity::Crit)
                            || regime.kind == RegimeKind::OomKills)
                    {
                        let mut regime = regime.clone();
                        regime.explanation = incident_text(&regime.explanation, 1024);
                        critical.push(regime);
                    }
                }
            }
        }
        // OOM is an event rather than a sustained regime. A deferred observed
        // kernel kill remains worth capturing even if this tick lost its sensors.
        if !pressure.pending.contains_key(&RegimeKind::OomKills) {
            self.captured_pending_oom = false;
        }
        if let Some(oom) = pressure
            .pending
            .get(&RegimeKind::OomKills)
            .filter(|_| !self.captured_pending_oom)
        {
            let mut oom = oom.clone();
            oom.explanation = incident_text(&oom.explanation, 1024);
            critical.push(oom);
        }
        self.captured_pending_oom |= critical
            .iter()
            .any(|cause| cause.kind == RegimeKind::OomKills);
        let memory_emergency =
            fresh && memory.is_some_and(|evaluation| evaluation.mode == PressureMode::Emergency);
        if self.active.is_none() && (!critical.is_empty() || memory_emergency) {
            self.active = Some(IncidentRecord {
                schema_version: INCIDENT_SCHEMA_VERSION,
                session_id: pt_common::SessionId::new().0,
                revision: 0,
                opened_at: sample.timestamp.clone(),
                last_observed_at: sample.timestamp.clone(),
                recovered_at: None,
                causes: Vec::new(),
                memory_emergency,
                before: self.recent.clone(),
                after: VecDeque::new(),
                planner_attempts: VecDeque::new(),
                samples_observed: 0,
                samples_dropped: 0,
                planner_attempts_dropped: 0,
            });
            self.recovery_streak = 0;
        }
        if let Some(record) = &mut self.active {
            record.memory_emergency |= memory_emergency;
            for cause in critical {
                if let Some(existing) = record
                    .causes
                    .iter_mut()
                    .find(|existing| existing.kind == cause.kind)
                {
                    *existing = cause;
                } else if record.causes.len() < 11 {
                    record.causes.push(cause);
                }
            }
            record.last_observed_at = sample.timestamp.clone();
            record.samples_observed = record.samples_observed.saturating_add(1);
            while record.after.len() >= INCIDENT_AFTER_SAMPLES {
                record.after.pop_front();
                record.samples_dropped = record.samples_dropped.saturating_add(1);
            }
            record.after.push_back(sample.clone());
            record.revision = record.revision.saturating_add(1);

            let healthy = fresh
                && sample.pressure.as_ref().is_some_and(|snapshot| {
                    (record.causes.is_empty()
                        || pressure.last_assessment.as_ref().is_some_and(|assessment| {
                            record.causes.iter().all(|cause| {
                                regime_evidence_available(
                                    cause.kind,
                                    snapshot,
                                    window.as_ref(),
                                    sample.process_census.as_ref(),
                                    true,
                                    false,
                                ) && !assessment.regimes.iter().any(|current| {
                                    current.kind == cause.kind && current.severity > Severity::Ok
                                })
                            })
                        }))
                        && (!record.memory_emergency
                            || (MemorySignals::from_pressure_snapshot(snapshot).is_some()
                                && memory.is_some_and(|evaluation| {
                                    evaluation.mode == PressureMode::Normal
                                })))
                });
            if healthy {
                self.recovery_streak = self.recovery_streak.saturating_add(1);
            } else {
                self.recovery_streak = 0;
            }
            bound_incident_record(record);
            if self.recovery_streak >= recovery_ticks.max(1) {
                let mut closed = self.active.take().expect("active incident was observed");
                closed.recovered_at = Some(sample.timestamp.clone());
                bound_incident_record(&mut closed);
                self.last = Some(closed.summary());
                while self.pending_archives.len() >= INCIDENT_PENDING_ARCHIVES {
                    self.pending_archives.pop_front();
                    self.discarded_pending_archives =
                        self.discarded_pending_archives.saturating_add(1);
                }
                self.pending_archives.push_back(closed);
                self.recovery_streak = 0;
            }
        }
        while self.recent.len() >= INCIDENT_BEFORE_SAMPLES {
            self.recent.pop_front();
        }
        self.recent.push_back(sample);
        // Do not bridge rates or recovery across missing/invalid observations.
        self.previous = if fresh {
            metrics.pressure.clone().zip(metrics.pressure_observed_at)
        } else {
            None
        };
        self.generation = self.generation.saturating_add(1);
    }

    /// Append the real planner outcome, including cooldown, lock, or budget
    /// deferrals. An unrelated tick with no active incident creates no attempt.
    pub fn record_planner(
        &mut self,
        outcome: &escalation::EscalationOutcome,
        plan: Option<IncidentPlanRef>,
    ) {
        let Some(record) = &mut self.active else {
            return;
        };
        let session_id = outcome
            .session_id
            .as_ref()
            .filter(|id| incident_session_id(id).is_some())
            .cloned();
        let plan = plan.filter(|plan| {
            outcome.status != escalation::EscalationStatus::Deferred
                && plan.is_valid()
                && session_id.as_ref() == Some(&plan.session_id)
        });
        while record.planner_attempts.len() >= INCIDENT_PLANNER_ATTEMPTS {
            record.planner_attempts.pop_front();
            record.planner_attempts_dropped = record.planner_attempts_dropped.saturating_add(1);
        }
        record.planner_attempts.push_back(IncidentPlannerAttempt {
            timestamp: record.last_observed_at.clone(),
            status: outcome.status,
            reason: incident_text(&outcome.reason, 1024),
            session_id,
            plan,
        });
        record.revision = record.revision.saturating_add(1);
        bound_incident_record(record);
        self.generation = self.generation.saturating_add(1);
    }

    /// Enrich the latest attempt after the planner callback returns. A plan may
    /// exist even when subsequent inbox delivery failed; its hash does not imply
    /// delivery or execution. Deferred attempts cannot acquire a plan reference.
    pub fn attach_plan_reference(&mut self, plan: IncidentPlanRef) -> bool {
        if !plan.is_valid() {
            return false;
        }
        let Some(record) = &mut self.active else {
            return false;
        };
        let Some(attempt) = record.planner_attempts.back_mut() else {
            return false;
        };
        if attempt.status == escalation::EscalationStatus::Deferred
            || attempt.session_id.as_ref() != Some(&plan.session_id)
        {
            return false;
        }
        attempt.plan = Some(plan);
        record.revision = record.revision.saturating_add(1);
        bound_incident_record(record);
        self.generation = self.generation.saturating_add(1);
        true
    }
}

fn bound_incident_record(record: &mut IncidentRecord) {
    // Unusually verbose sensor metadata is bounded by bytes as well as counts.
    // Retain the latest observation and diagnoses before older context.
    while serde_json::to_vec(&*record).map_or(true, |bytes| bytes.len() > INCIDENT_MAX_BYTES) {
        if record.before.pop_front().is_some() {
            record.samples_dropped = record.samples_dropped.saturating_add(1);
        } else if record.after.len() > 1 {
            record.after.pop_front();
            record.samples_dropped = record.samples_dropped.saturating_add(1);
        } else if record.planner_attempts.len() > 1 {
            record.planner_attempts.pop_front();
            record.planner_attempts_dropped = record.planner_attempts_dropped.saturating_add(1);
        } else {
            break;
        }
    }
}

impl IncidentTracker {
    fn checkpoint(&self) -> IncidentCheckpoint {
        IncidentCheckpoint {
            schema_version: INCIDENT_SCHEMA_VERSION,
            generation: self.generation,
            recent: self.recent.clone(),
            active: self.active.clone(),
            pending_archives: self.pending_archives.clone(),
            last: self.last.clone(),
            discarded_pending_archives: self.discarded_pending_archives,
            captured_pending_oom: self.captured_pending_oom,
        }
    }

    fn restore_checkpoint(&mut self, checkpoint: IncidentCheckpoint) {
        self.generation = checkpoint.generation;
        self.recent = checkpoint.recent;
        self.active = checkpoint.active;
        self.pending_archives = checkpoint.pending_archives;
        self.last = checkpoint.last;
        self.discarded_pending_archives = checkpoint.discarded_pending_archives;
        self.captured_pending_oom = checkpoint.captured_pending_oom;
        self.interrupt_observations();
    }

    /// Restore only the fixed checkpoint and at most three named artifacts. The
    /// checkpoint contains complete records, so a crash at any point between
    /// checkpoint publication, session creation, and artifact publication retains
    /// the original episode even when daemon-state.json predates its first tick.
    pub fn recover_persisted(&mut self, store: &SessionStore) -> Result<(), String> {
        self.interrupt_observations();
        let result = self.recover_incidents(store);
        self.storage_error = result
            .as_ref()
            .err()
            .map(|error| incident_text(error, 1024));
        result
    }

    fn recover_incidents(&mut self, store: &SessionStore) -> Result<(), String> {
        self.checkpoint().validate()?;
        if let Some(checkpoint) = read_daemon_json_bounded::<IncidentCheckpoint>(
            &store.sessions_root().join(INCIDENT_CHECKPOINT_FILE),
            INCIDENT_CHECKPOINT_MAX_BYTES,
        )? {
            checkpoint.validate()?;
            if checkpoint.generation >= self.generation {
                self.restore_checkpoint(checkpoint);
            }
        }
        if let Some(record) = &mut self.active {
            if reconcile_incident_record(store, record)? {
                self.generation = self.generation.saturating_add(1);
            }
            if record.recovered_at.is_some() {
                let record = self.active.take().expect("active record was reconciled");
                self.last = Some(record.summary());
                while self.pending_archives.len() >= INCIDENT_PENDING_ARCHIVES {
                    self.pending_archives.pop_front();
                    self.discarded_pending_archives =
                        self.discarded_pending_archives.saturating_add(1);
                }
                self.pending_archives.push_back(record);
                self.generation = self.generation.saturating_add(1);
            }
        }
        for record in &mut self.pending_archives {
            if reconcile_incident_record(store, record)? {
                self.generation = self.generation.saturating_add(1);
                if self
                    .last
                    .as_ref()
                    .is_some_and(|last| last.session_id == record.session_id)
                {
                    self.last = Some(record.summary());
                }
            }
            if record.recovered_at.is_none() {
                return Err("recovered incident was replaced with an active artifact".into());
            }
        }
        Ok(())
    }

    /// Publish a bounded checkpoint before creating/updating session artifacts.
    /// Failed archives remain queued for retry; errors are also exposed in status.
    /// Completed artifacts are removed from the checkpoint only after publication
    /// and the session's transition to Completed have both succeeded.
    pub fn persist(&mut self, store: &SessionStore) -> Result<(), String> {
        let result = self.persist_incidents(store);
        self.storage_error = result
            .as_ref()
            .err()
            .map(|error| incident_text(error, 1024));
        result
    }

    fn publish_checkpoint(&self, store: &SessionStore) -> Result<(), String> {
        let checkpoint = self.checkpoint();
        checkpoint.validate()?;
        let path = store.sessions_root().join(INCIDENT_CHECKPOINT_FILE);
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| error.to_string())?;
        if let Some(existing) =
            read_daemon_json_bounded::<IncidentCheckpoint>(&path, INCIDENT_CHECKPOINT_MAX_BYTES)?
        {
            existing.validate()?;
            if existing.generation > checkpoint.generation
                || (existing.generation == checkpoint.generation
                    && serde_json::to_vec(&existing).map_err(|error| error.to_string())? != bytes)
            {
                return Err(
                    "a newer or conflicting incident checkpoint must be reconciled before writing"
                        .into(),
                );
            }
        }
        crate::session::write_serialized_json(&path, &bytes).map_err(|error| error.to_string())
    }

    fn persist_incidents(&mut self, store: &SessionStore) -> Result<(), String> {
        self.publish_checkpoint(store)?;
        if let Some(record) = &self.active {
            persist_incident_record(store, record)?;
        }
        let mut drained = false;
        while let Some(record) = self.pending_archives.front() {
            persist_incident_record(store, record)?;
            self.pending_archives.pop_front();
            self.generation = self.generation.saturating_add(1);
            drained = true;
        }
        if drained {
            self.publish_checkpoint(store)?;
        }
        Ok(())
    }
}

impl IncidentCheckpoint {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != INCIDENT_SCHEMA_VERSION
            || self.recent.len() > INCIDENT_BEFORE_SAMPLES
            || self.pending_archives.len() > INCIDENT_PENDING_ARCHIVES
            || self
                .active
                .as_ref()
                .is_some_and(|record| record.recovered_at.is_some())
            || self
                .pending_archives
                .iter()
                .any(|record| record.recovered_at.is_none())
        {
            return Err(
                "incident checkpoint has an unsupported schema or exceeds its bounds".into(),
            );
        }
        for sample in &self.recent {
            sample.validate()?;
        }
        let mut ids = std::collections::BTreeSet::new();
        for record in self.active.iter().chain(&self.pending_archives) {
            record.validate()?;
            if !ids.insert(&record.session_id) {
                return Err("incident checkpoint contains duplicate session IDs".into());
            }
        }
        if let Some(last) = &self.last {
            if incident_session_id(&last.session_id).is_none()
                || last.causes.len() > 11
                || last.opened_at.len() > 128
                || last.last_observed_at.len() > 128
                || last
                    .recovered_at
                    .as_ref()
                    .is_none_or(|time| time.len() > 128)
                || last
                    .latest_plan
                    .as_ref()
                    .is_some_and(|plan| !plan.is_valid())
            {
                return Err("incident checkpoint has an invalid last incident summary".into());
            }
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > INCIDENT_CHECKPOINT_MAX_BYTES
        {
            return Err("incident checkpoint exceeds its byte budget".into());
        }
        Ok(())
    }
}

fn reconcile_incident_record(
    store: &SessionStore,
    record: &mut IncidentRecord,
) -> Result<bool, String> {
    let id = incident_session_id(&record.session_id).ok_or("invalid incident session ID")?;
    let path = store.session_dir(&id).join("incident.json");
    if let Some(saved) = read_daemon_json_bounded::<IncidentRecord>(&path, INCIDENT_MAX_BYTES)? {
        saved.validate()?;
        if saved.session_id != record.session_id {
            return Err("incident artifact belongs to another session".into());
        }
        if saved.revision > record.revision {
            if record.recovered_at.is_some() && saved.recovered_at.is_none() {
                return Err("a recovered incident cannot be reopened by a newer artifact".into());
            }
            *record = saved;
            return Ok(true);
        } else if saved.revision == record.revision
            && serde_json::to_vec(&saved).map_err(|error| error.to_string())?
                != serde_json::to_vec(&*record).map_err(|error| error.to_string())?
        {
            return Err("incident artifact conflicts with the checkpoint revision".into());
        }
    }
    Ok(false)
}

/// Load one named incident for session inspection/export without a directory
/// scan. The identifier, schema, metadata, and serialized size are validated.
pub fn load_incident_record(
    store: &SessionStore,
    session_id: &pt_common::SessionId,
) -> Result<Option<IncidentRecord>, String> {
    let id = incident_session_id(&session_id.0).ok_or("invalid incident session ID")?;
    let record = read_daemon_json_bounded::<IncidentRecord>(
        &store.session_dir(&id).join("incident.json"),
        INCIDENT_MAX_BYTES,
    )?;
    if let Some(record) = &record {
        record.validate()?;
        if record.session_id != id.0 {
            return Err("incident artifact belongs to another session".into());
        }
    }
    Ok(record)
}

fn persist_incident_record(store: &SessionStore, record: &IncidentRecord) -> Result<(), String> {
    record.validate()?;
    let id = incident_session_id(&record.session_id).ok_or("invalid incident session ID")?;
    let dir = store.session_dir(&id);
    let mut manifest =
        match read_daemon_json_bounded::<SessionManifest>(&dir.join("manifest.json"), 32 * 1024)? {
            Some(manifest) => manifest,
            None => {
                let mut manifest = SessionManifest::new(
                    &id,
                    None,
                    SessionMode::DaemonAlert,
                    Some("Critical pressure incident".into()),
                );
                manifest.record_state(SessionState::Scanning);
                // The session's retention guard preserves active DaemonAlert/Scanning
                // records without pretending that the daemon executed an action.
                store.create(&manifest).map_err(|error| error.to_string())?;
                manifest
            }
        };
    if manifest.session_id != record.session_id
        || manifest.mode != SessionMode::DaemonAlert
        || !matches!(
            manifest.state,
            SessionState::Scanning | SessionState::Completed
        )
        || (manifest.state == SessionState::Completed && record.recovered_at.is_none())
        || manifest.state_history.len() > 4
    {
        return Err("incident session manifest has an incompatible identity or lifecycle".into());
    }
    let path = dir.join("incident.json");
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    if let Some(existing) = read_daemon_json_bounded::<IncidentRecord>(&path, INCIDENT_MAX_BYTES)? {
        existing.validate()?;
        if existing.session_id != record.session_id
            || existing.revision > record.revision
            || (existing.revision == record.revision
                && serde_json::to_vec(&existing).map_err(|error| error.to_string())? != bytes)
        {
            return Err(
                "a newer or conflicting incident artifact must be reconciled before writing".into(),
            );
        }
    }
    crate::session::write_serialized_json(&path, &bytes).map_err(|error| error.to_string())?;
    if record.recovered_at.is_some() && manifest.state != SessionState::Completed {
        manifest.record_state(SessionState::Completed);
        crate::session::write_json_pretty(&dir.join("manifest.json"), &manifest)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Descriptor-relative reads complement the session module's atomic no-follow
/// writer. FIFOs/devices, symlink files/directories, and oversized input fail
/// without blocking or allocating an unbounded buffer.
pub fn read_daemon_json_bounded<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    limit: usize,
) -> Result<Option<T>, String> {
    use std::io::Read;
    let io_error = |error: std::io::Error| format!("{}: {error}", path.display());
    let parent = path.parent().ok_or("incident artifact has no parent")?;
    #[cfg(unix)]
    let file = {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let name = std::ffi::CString::new(
            path.file_name()
                .ok_or("incident artifact has no name")?
                .as_bytes(),
        )
        .map_err(|error| error.to_string())?;
        // SAFETY: directory descriptor is live and name is one NUL-terminated
        // final path component. The returned descriptor is uniquely owned.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(io_error(error));
        }
        // SAFETY: ownership of the newly opened descriptor transfers exactly once.
        unsafe { std::fs::File::from_raw_fd(fd) }
    };
    #[cfg(not(unix))]
    let file = {
        match std::fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("daemon artifact parent must be a real directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("incident artifact must be a regular file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        }
        std::fs::File::open(path).map_err(io_error)?
    };
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(format!(
            "{} is not a bounded regular incident artifact",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > limit {
        return Err("incident artifact grew beyond its byte budget".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the daemon core loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Interval between metric collection ticks (seconds).
    pub tick_interval_secs: u64,
    /// Maximum CPU% the daemon may consume (self-limiting).
    pub max_cpu_percent: f64,
    /// Maximum RSS (MB) the daemon may consume.
    pub max_rss_mb: u64,
    /// Trigger configuration.
    pub triggers: triggers::TriggerConfig,
    /// Escalation configuration.
    pub escalation: escalation::EscalationConfig,
    /// Notification escalation ladder configuration.
    #[serde(default)]
    pub notification_ladder: crate::decision::escalation::EscalationConfig,
    /// Notification delivery configuration.
    #[serde(default)]
    pub notifications: DaemonNotificationsConfig,
    /// Memory/PSI pressure response. It generates review plans, never actions.
    #[serde(default)]
    pub memory_pressure: MemPressureConfig,
    /// Reduce the daemon's sampling frequency when its own overhead is too high.
    #[serde(default)]
    pub overhead_backoff: OverheadBackoffConfig,
}

/// Polling backoff after a daemon CPU or RSS budget violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OverheadBackoffConfig {
    /// Maximum backed-off interval. A slower configured base interval takes
    /// precedence, so a budget violation can never make the daemon poll faster.
    pub max_interval_secs: u64,
    /// Consecutive ticks within budget before halving the backed-off interval.
    /// Zero is treated as one tick.
    pub healthy_ticks_before_recovery: u32,
}

impl Default for OverheadBackoffConfig {
    fn default() -> Self {
        Self {
            max_interval_secs: 300,
            healthy_ticks_before_recovery: 3,
        }
    }
}

/// Persisted overhead delay and the current consecutive recovery observations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverheadBackoffState {
    /// Zero means normal polling; otherwise this interval overrides the faster
    /// memory-pressure cadence, subject to the current configuration's bounds.
    pub interval_secs: u64,
    /// Exposed in status. The daemon resets this after restart or a missing
    /// overhead observation, because neither establishes continued recovery.
    pub healthy_ticks: u32,
}

/// Notification delivery settings for the daemon.
///
/// The ladder decides *what* level/channels are appropriate; this config
/// decides which channels are actually delivered in this environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonNotificationsConfig {
    /// Enable notification delivery (inbox items are still written separately).
    pub enabled: bool,
    /// Best-effort desktop notifications (Linux/macOS).
    pub desktop: bool,
    /// Execute a command when a notification is emitted (best-effort).
    #[serde(default)]
    pub notify_cmd: Option<String>,
    /// Extra args for notify_cmd.
    #[serde(default)]
    pub notify_arg: Vec<String>,
}

impl Default for DaemonNotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            desktop: true,
            notify_cmd: None,
            notify_arg: Vec::new(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            tick_interval_secs: 60,
            max_cpu_percent: 2.0,
            max_rss_mb: 64,
            triggers: triggers::TriggerConfig::default(),
            escalation: escalation::EscalationConfig::default(),
            notification_ladder: crate::decision::escalation::EscalationConfig::default(),
            notifications: DaemonNotificationsConfig::default(),
            memory_pressure: MemPressureConfig::default(),
            overhead_backoff: OverheadBackoffConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

/// Instantaneous system metrics collected each tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickMetrics {
    pub timestamp: String,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub swap_used_mb: u64,
    pub process_count: u32,
    /// Observed, unsupervised PID-1 adoptees that retained another job's session
    /// or process group. None means the census is incomplete or unsupported,
    /// never an observed zero. Existing numeric telemetry remains readable.
    #[serde(default)]
    pub orphan_count: Option<u32>,
    /// Complete process-state census from the same visible process-table walk.
    /// Missing, unreadable or over-budget observations stay unknown; they cannot
    /// confirm recovery from a zombie leak or uninterruptible-sleep storm.
    #[serde(default)]
    pub process_census: Option<crate::decision::pressure_regime::ProcessCensus>,
    /// The actual pressure reading, including unavailable sensors. Older callers
    /// without a reading cannot supply CPU capacity or memory-pressure recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure: Option<PressureSnapshot>,
    /// Live monotonic sampling time; deliberately not restored from a saved tick.
    #[serde(skip)]
    pub pressure_observed_at: Option<std::time::Instant>,
}

/// A daemon event for telemetry / audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEvent {
    pub timestamp: String,
    pub event_type: DaemonEventType,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonEventType {
    Started,
    Stopped,
    TickCompleted,
    TriggerFired,
    TriggerCooldown,
    EscalationStarted,
    EscalationCompleted,
    EscalationDeferred,
    EscalationFailed,
    LockContention,
    OverheadBudgetExceeded,
    OverheadBackoffChanged,
    ConfigReloaded,
    LoadEvidenceUnavailable,
    MemoryPressureChanged,
    MemoryPressureUnavailable,
    FreezeRecoveryCompleted,
    FreezeRecoveryDeferred,
    FreezeRecoveryFailed,
    NotificationCommandCompleted,
    NotificationDeliveryFailed,
}

/// Running state of the daemon core loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub started_at: String,
    pub tick_count: u64,
    pub last_tick_at: Option<String>,
    pub last_escalation_at: Option<String>,
    pub escalation_count: u32,
    pub deferred_count: u32,
    /// Recent events for audit.
    pub recent_events: VecDeque<DaemonEvent>,
    /// Retained hysteresis state survives daemon restarts and missing readings.
    #[serde(default)]
    pub memory_pressure: MemPressureMonitor,
    /// Most recent sensor output; missing values remain explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pressure: Option<PressureSnapshot>,
    /// None when this tick could not establish a valid pressure observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_memory_pressure: Option<PressureEvaluation>,
    /// Retain a warning's plan request when lock contention or cooldown defers it.
    #[serde(default)]
    pub memory_pressure_plan_pending: bool,
    /// Persistent self-limiting delay, independent of the host pressure state.
    #[serde(default)]
    pub overhead_backoff: OverheadBackoffState,
    /// Bounded critical-pressure evidence, independent of planner availability.
    #[serde(default)]
    pub incidents: IncidentTracker,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            started_at: Utc::now().to_rfc3339(),
            tick_count: 0,
            last_tick_at: None,
            last_escalation_at: None,
            escalation_count: 0,
            deferred_count: 0,
            recent_events: VecDeque::with_capacity(100),
            memory_pressure: MemPressureMonitor::default(),
            last_pressure: None,
            last_memory_pressure: None,
            memory_pressure_plan_pending: false,
            overhead_backoff: OverheadBackoffState::default(),
            incidents: IncidentTracker::default(),
        }
    }

    /// Record the cheap pressure observation even if the daemon's own overhead
    /// budget prevents it from generating a plan on this tick.
    pub fn observe_memory_pressure(&mut self, config: &DaemonConfig, metrics: &TickMetrics) {
        self.memory_pressure
            .reconfigure(config.memory_pressure.clone());
        self.last_pressure = metrics.pressure.clone();
        let signals = metrics
            .pressure
            .as_ref()
            .and_then(MemorySignals::from_pressure_snapshot);
        let was_available = self.last_memory_pressure.is_some();
        let evaluation = self.memory_pressure.observe(signals.as_ref());
        if let Some(evaluation) = &evaluation {
            if evaluation.mode == PressureMode::Normal {
                self.memory_pressure_plan_pending = false;
            } else if matches!(
                evaluation.action,
                PressureAction::GeneratePlan | PressureAction::UrgentPlan
            ) {
                self.memory_pressure_plan_pending = true;
            }
            if evaluation.transitioned {
                self.record_event(
                    DaemonEventType::MemoryPressureChanged,
                    &evaluation.explanation,
                );
            }
        } else if was_available || self.tick_count <= 1 {
            self.record_event(
                DaemonEventType::MemoryPressureUnavailable,
                "memory-pressure evidence unavailable; retained the previous mode",
            );
        }
        self.last_memory_pressure = evaluation;
    }

    /// Observe the daemon's own budget exactly once per collection tick, before
    /// deciding whether planning is allowed. A breach doubles the delay, up to
    /// the configured cap. Recovery requires consecutive within-budget ticks
    /// and halves the delay one step at a time.
    ///
    /// The first delay is measured from at least the configured base interval:
    /// a host emergency must not make an over-budget daemon poll more often.
    /// Existing state is bounded on every observation so config reloads and
    /// persisted out-of-range intervals cannot bypass the cap.
    /// Pass `false` only after observing that the daemon is within budget; if
    /// overhead evidence is unavailable, interrupt recovery instead.
    pub fn observe_overhead_budget(&mut self, config: &DaemonConfig, budget_exceeded: bool) {
        let base = config.tick_interval_secs.max(1);
        let cap = config.overhead_backoff.max_interval_secs.max(base);
        let recovery_ticks = config.overhead_backoff.healthy_ticks_before_recovery.max(1);
        let previous_interval = self.next_tick_interval_secs(config);
        let previous_backoff = self.overhead_backoff.interval_secs;
        let mut recovered = false;
        if self.overhead_backoff.interval_secs > 0 {
            self.overhead_backoff.interval_secs =
                self.overhead_backoff.interval_secs.clamp(base, cap);
        }
        if self.overhead_backoff.healthy_ticks >= recovery_ticks {
            // A valid streak is always shorter than the threshold: reaching it
            // consumes the streak. Do not trust stale or out-of-range state.
            self.overhead_backoff.healthy_ticks = 0;
        }

        if budget_exceeded {
            self.overhead_backoff.interval_secs = self
                .overhead_backoff
                .interval_secs
                .max(base)
                .saturating_mul(2)
                .min(cap);
            self.overhead_backoff.healthy_ticks = 0;
        } else if self.overhead_backoff.interval_secs > 0 {
            self.overhead_backoff.healthy_ticks =
                self.overhead_backoff.healthy_ticks.saturating_add(1);
            if self.overhead_backoff.healthy_ticks >= recovery_ticks {
                let reduced = self.overhead_backoff.interval_secs / 2;
                self.overhead_backoff.interval_secs = if reduced > base { reduced } else { 0 };
                self.overhead_backoff.healthy_ticks = 0;
                recovered = true;
            }
        } else {
            self.overhead_backoff.healthy_ticks = 0;
        }

        if self.overhead_backoff.interval_secs != previous_backoff {
            let reason = if budget_exceeded {
                "overhead budget exceeded"
            } else if self.overhead_backoff.interval_secs == 0 {
                "within-budget recovery completed"
            } else if recovered {
                "consecutive within-budget observations"
            } else {
                "configured overhead backoff limit"
            };
            self.record_event(
                DaemonEventType::OverheadBackoffChanged,
                &format!(
                    "poll interval {}s -> {}s: {}",
                    previous_interval,
                    self.next_tick_interval_secs(config),
                    reason
                ),
            );
        }
    }

    /// Restart downtime and missing overhead samples break the consecutive
    /// healthy streak without discarding an active self-limiting delay.
    pub fn interrupt_overhead_recovery(&mut self) {
        self.overhead_backoff.healthy_ticks = 0;
    }

    /// Pressure can increase polling cadence only while overhead backoff is
    /// inactive. Every interval is at least one second and bounded arithmetic
    /// prevents extreme configuration or persisted values from overflowing.
    pub fn next_tick_interval_secs(&self, config: &DaemonConfig) -> u64 {
        let base = config.tick_interval_secs.max(1);
        if self.overhead_backoff.interval_secs > 0 {
            return self
                .overhead_backoff
                .interval_secs
                .clamp(base, config.overhead_backoff.max_interval_secs.max(base));
        }
        let requested = self.memory_pressure.scan_interval_secs();
        if requested.is_finite() && requested > 0.0 {
            (requested.ceil() as u64).max(1).min(base)
        } else {
            base
        }
    }

    pub fn record_event(&mut self, event_type: DaemonEventType, detail: &str) {
        let event = DaemonEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            detail: detail.to_string(),
        };
        if self.recent_events.len() >= 100 {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(event);
    }
}

// ---------------------------------------------------------------------------
// Core loop (synchronous, testable)
// ---------------------------------------------------------------------------

/// Outcome of a single daemon tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickOutcome {
    pub tick_number: u64,
    pub triggers_fired: Vec<triggers::FiredTrigger>,
    pub escalation: Option<escalation::EscalationOutcome>,
    pub events: Vec<DaemonEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_pressure: Option<PressureEvaluation>,
    /// Polling interval selected for the next tick, in seconds.
    #[serde(default)]
    pub next_tick_interval_secs: u64,
}

/// Process one daemon tick.
///
/// This is the core testable unit — it takes metrics, evaluates triggers,
/// and decides whether to escalate. The actual metric collection and
/// escalation execution are injected via callbacks for testability.
pub fn process_tick<E>(
    config: &DaemonConfig,
    state: &mut DaemonState,
    trigger_state: &mut triggers::TriggerState,
    metrics: &TickMetrics,
    escalate_fn: &mut E,
) -> TickOutcome
where
    E: FnMut(
        &escalation::EscalationConfig,
        &[triggers::FiredTrigger],
    ) -> escalation::EscalationOutcome,
{
    process_tick_with_incident_observer(
        config,
        state,
        trigger_state,
        metrics,
        &mut |_| {},
        escalate_fn,
    )
}

/// Process a tick with an incident persistence boundary before planner work.
/// The CLI uses the observer to publish captured pressure even if the planner
/// later crashes, times out, or defers. The callback cannot acknowledge an episode.
pub fn process_tick_with_incident_observer<O, E>(
    config: &DaemonConfig,
    state: &mut DaemonState,
    trigger_state: &mut triggers::TriggerState,
    metrics: &TickMetrics,
    before_escalation: &mut O,
    escalate_fn: &mut E,
) -> TickOutcome
where
    O: FnMut(&mut IncidentTracker),
    E: FnMut(
        &escalation::EscalationConfig,
        &[triggers::FiredTrigger],
    ) -> escalation::EscalationOutcome,
{
    state.tick_count += 1;
    let tick_number = state.tick_count;
    state.last_tick_at = Some(metrics.timestamp.clone());

    let mut events = Vec::new();

    // 1) Evaluate triggers.
    let previous_load_error = trigger_state.load_unavailable_reason.clone();
    let mut fired = triggers::evaluate_triggers(&config.triggers, trigger_state, metrics);
    if trigger_state.load_unavailable_reason != previous_load_error {
        if let Some(reason) = &trigger_state.load_unavailable_reason {
            let detail = format!("load trigger unavailable: {reason}; no load escalation");
            state.record_event(DaemonEventType::LoadEvidenceUnavailable, &detail);
            events.push(DaemonEvent {
                timestamp: metrics.timestamp.clone(),
                event_type: DaemonEventType::LoadEvidenceUnavailable,
                detail,
            });
        }
    }
    state.observe_memory_pressure(config, metrics);
    if let Some(evaluation) = &state.last_memory_pressure {
        if evaluation.transitioned {
            events.push(DaemonEvent {
                timestamp: metrics.timestamp.clone(),
                event_type: DaemonEventType::MemoryPressureChanged,
                detail: evaluation.explanation.clone(),
            });
        }
        if state.memory_pressure_plan_pending && evaluation.mode != PressureMode::Normal {
            // The richer observation replaces a same-tick utilization trigger;
            // the existing escalation callback still enforces cooldown and lock.
            fired.retain(|trigger| trigger.kind != triggers::TriggerKind::MemoryPressure);
            fired.push(triggers::FiredTrigger {
                kind: triggers::TriggerKind::MemoryPressure,
                description: evaluation.explanation.clone(),
                current_value: Some(evaluation.utilization),
                ewma_value: Some(trigger_state.memory_ewma),
                threshold: Some(match evaluation.mode {
                    PressureMode::Emergency => config.memory_pressure.emergency_threshold,
                    _ => config.memory_pressure.warning_threshold,
                }),
                sustained_ticks: u32::try_from(state.memory_pressure.sustained_samples())
                    .unwrap_or(u32::MAX),
                provenance_context: Vec::new(),
                memory_pressure: Some(evaluation.clone()),
                pressure_regime: None,
            });
        }
    }

    for t in &fired {
        state.record_event(DaemonEventType::TriggerFired, &t.description);
        events.push(DaemonEvent {
            timestamp: metrics.timestamp.clone(),
            event_type: DaemonEventType::TriggerFired,
            detail: t.description.clone(),
        });
    }

    // Capture the host incident before planning and before successful delivery
    // acknowledges one-shot OOM evidence in the trigger state.
    state.incidents.observe(
        metrics,
        &trigger_state.pressure,
        state.last_memory_pressure.as_ref(),
        config.triggers.pressure_regimes.exit_after_ticks,
    );
    before_escalation(&mut state.incidents);

    // 2) Escalate if any triggers fired.
    let escalation = if !fired.is_empty() {
        let outcome = escalate_fn(&config.escalation, &fired);
        state.incidents.record_planner(&outcome, None);

        match outcome.status {
            escalation::EscalationStatus::Completed => {
                trigger_state.pressure.acknowledge(&fired);
                if fired
                    .iter()
                    .any(|trigger| trigger.memory_pressure.is_some())
                {
                    state.memory_pressure_plan_pending = false;
                }
                state.escalation_count += 1;
                state.last_escalation_at = Some(metrics.timestamp.clone());
                state.record_event(DaemonEventType::EscalationCompleted, "escalation completed");
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationCompleted,
                    detail: "escalation completed".to_string(),
                });
            }
            escalation::EscalationStatus::Deferred => {
                state.deferred_count += 1;
                state.record_event(DaemonEventType::EscalationDeferred, &outcome.reason);
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationDeferred,
                    detail: outcome.reason.clone(),
                });
            }
            escalation::EscalationStatus::Failed => {
                state.record_event(DaemonEventType::EscalationFailed, &outcome.reason);
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationFailed,
                    detail: outcome.reason.clone(),
                });
            }
        }

        Some(outcome)
    } else {
        None
    };

    state.record_event(
        DaemonEventType::TickCompleted,
        &format!("tick {}", tick_number),
    );

    TickOutcome {
        tick_number,
        triggers_fired: fired,
        escalation,
        events,
        memory_pressure: state.last_memory_pressure.clone(),
        next_tick_interval_secs: state.next_tick_interval_secs(config),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metrics(load: f64, mem_used: u64, orphans: u32) -> TickMetrics {
        TickMetrics {
            timestamp: Utc::now().to_rfc3339(),
            load_avg_1: load,
            load_avg_5: load * 0.8,
            memory_used_mb: mem_used,
            memory_total_mb: 8192,
            swap_used_mb: 0,
            process_count: 200,
            orphan_count: Some(orphans),
            process_census: None,
            pressure: None,
            pressure_observed_at: None,
        }
    }

    #[test]
    fn orphan_count_serialization_distinguishes_unknown_from_observed_zero() {
        let mut tick = test_metrics(1.0, 2000, 0);
        let value = serde_json::to_value(&tick).unwrap();
        assert_eq!(value["orphan_count"], serde_json::json!(0));
        let restored: TickMetrics = serde_json::from_value(value).unwrap();
        assert_eq!(restored.orphan_count, Some(0));

        tick.orphan_count = None;
        let mut value = serde_json::to_value(&tick).unwrap();
        assert!(value["orphan_count"].is_null());
        value.as_object_mut().unwrap().remove("orphan_count");
        let absent: TickMetrics = serde_json::from_value(value).unwrap();
        assert_eq!(absent.orphan_count, None);
    }

    #[test]
    fn process_census_serialization_preserves_observed_and_unavailable_evidence() {
        use crate::decision::pressure_regime::ProcessCensus;

        let mut tick = test_metrics(1.0, 2000, 0);
        let mut legacy = serde_json::to_value(&tick).unwrap();
        assert!(legacy["process_census"].is_null());
        legacy.as_object_mut().unwrap().remove("process_census");
        let restored: TickMetrics = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.process_census, None);

        for census in [
            ProcessCensus::default(),
            ProcessCensus {
                zombies: 25,
                dstate: 7,
            },
        ] {
            tick.process_census = Some(census);
            let json = serde_json::to_value(&tick).unwrap();
            assert_eq!(json["process_census"]["zombies"], census.zombies);
            assert_eq!(json["process_census"]["dstate"], census.dstate);
            let restored: TickMetrics = serde_json::from_value(json).unwrap();
            assert_eq!(restored.process_census, Some(census));
            assert!(restored.pressure_observed_at.is_none());
        }
    }

    #[test]
    fn test_tick_no_triggers() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(1.0, 2000, 5);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: String::new(),
                session_id: None,
                provenance_summary: None,
            },
        );

        assert_eq!(outcome.tick_number, 1);
        assert!(outcome.triggers_fired.is_empty());
        assert!(outcome.escalation.is_none());
        assert_eq!(state.tick_count, 1);
    }

    #[test]
    fn test_tick_with_trigger_and_escalation() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = Some(2.0);
        config.triggers.sustained_ticks = 1; // Fire immediately
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(10.0, 2000, 5); // High load
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: "test escalation".to_string(),
                session_id: Some("test-session".to_string()),
                provenance_summary: None,
            },
        );

        assert!(!outcome.triggers_fired.is_empty());
        assert!(outcome.escalation.is_some());
        assert_eq!(state.escalation_count, 1);
    }

    #[test]
    fn test_tick_deferred_escalation() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = Some(2.0);
        config.triggers.sustained_ticks = 1;
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(10.0, 2000, 5);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Deferred,
                reason: "lock held".to_string(),
                session_id: None,
                provenance_summary: None,
            },
        );

        assert!(outcome.escalation.is_some());
        assert_eq!(state.deferred_count, 1);
        assert_eq!(state.escalation_count, 0);
    }

    #[test]
    fn test_tick_failed_escalation_emits_failed_event() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = Some(2.0);
        config.triggers.sustained_ticks = 1;
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(10.0, 2000, 5);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Failed,
                reason: "escalation failed".to_string(),
                session_id: None,
                provenance_summary: None,
            },
        );

        assert!(outcome.escalation.is_some());
        assert_eq!(state.deferred_count, 0);
        assert_eq!(state.escalation_count, 0);
        assert!(outcome
            .events
            .iter()
            .any(|event| event.event_type == DaemonEventType::EscalationFailed));
    }

    #[test]
    fn test_state_event_ring() {
        let mut state = DaemonState::new();
        for i in 0..150 {
            state.record_event(DaemonEventType::TickCompleted, &format!("tick {}", i));
        }
        assert_eq!(state.recent_events.len(), 100);
    }

    #[test]
    fn test_multiple_ticks() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        for _ in 0..5 {
            let metrics = test_metrics(1.0, 2000, 5);
            process_tick(
                &config,
                &mut state,
                &mut trig_state,
                &metrics,
                &mut |_, _| escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: String::new(),
                    session_id: None,
                    provenance_summary: None,
                },
            );
        }
        assert_eq!(state.tick_count, 5);
    }

    #[test]
    fn test_config_serialization() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let restored: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tick_interval_secs, 60);
    }

    #[test]
    fn overhead_backoff_doubles_until_capped() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        assert_eq!(state.next_tick_interval_secs(&config), 60);

        for expected in [120, 240, 300, 300, 300] {
            state.observe_overhead_budget(&config, true);
            assert_eq!(state.next_tick_interval_secs(&config), expected);
            assert_eq!(state.overhead_backoff.healthy_ticks, 0);
        }
        assert_eq!(
            state
                .recent_events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::OverheadBackoffChanged)
                .count(),
            3,
            "a sustained violation at the cap must not emit duplicate delay changes"
        );
    }

    #[test]
    fn overhead_backoff_recovers_gradually_after_consecutive_healthy_ticks() {
        let config = DaemonConfig {
            overhead_backoff: OverheadBackoffConfig {
                max_interval_secs: 480,
                healthy_ticks_before_recovery: 3,
            },
            ..Default::default()
        };
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, true);
        for _ in 0..2 {
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), 240);
        }
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 480);
        assert_eq!(state.overhead_backoff.healthy_ticks, 0);

        for (before, after) in [(480, 240), (240, 120), (120, 60)] {
            for _ in 0..2 {
                state.observe_overhead_budget(&config, false);
                assert_eq!(state.next_tick_interval_secs(&config), before);
            }
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), after);
            assert_eq!(state.overhead_backoff.healthy_ticks, 0);
        }
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.healthy_ticks, 0);
    }

    #[test]
    fn overhead_backoff_survives_restart_without_reusing_recovery_streak() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, false);
        state.observe_overhead_budget(&config, false);
        let saved = serde_json::to_value(&state).unwrap();
        assert_eq!(saved["overhead_backoff"]["healthy_ticks"], 2);

        let mut restored: DaemonState = serde_json::from_value(saved).unwrap();
        assert_eq!(restored.next_tick_interval_secs(&config), 120);
        assert_eq!(restored.overhead_backoff.healthy_ticks, 2);
        restored.interrupt_overhead_recovery();
        assert_eq!(restored.overhead_backoff.healthy_ticks, 0);
        for _ in 0..2 {
            restored.observe_overhead_budget(&config, false);
            assert_eq!(restored.next_tick_interval_secs(&config), 120);
        }
        restored.observe_overhead_budget(&config, false);
        assert_eq!(restored.next_tick_interval_secs(&config), 60);
    }

    #[test]
    fn overhead_backoff_defaults_allow_existing_config_and_state() {
        let mut config = serde_json::to_value(DaemonConfig::default()).unwrap();
        config.as_object_mut().unwrap().remove("overhead_backoff");
        let config: DaemonConfig = serde_json::from_value(config).unwrap();
        assert_eq!(config.overhead_backoff.max_interval_secs, 300);
        assert_eq!(config.overhead_backoff.healthy_ticks_before_recovery, 3);

        let partial: OverheadBackoffConfig =
            serde_json::from_str(r#"{"healthy_ticks_before_recovery":5}"#).unwrap();
        assert_eq!(partial.max_interval_secs, 300);
        assert_eq!(partial.healthy_ticks_before_recovery, 5);

        let mut state = serde_json::to_value(DaemonState::new()).unwrap();
        state.as_object_mut().unwrap().remove("overhead_backoff");
        let state: DaemonState = serde_json::from_value(state).unwrap();
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        assert_eq!(state.next_tick_interval_secs(&config), 60);
    }

    #[test]
    fn overhead_backoff_reconfiguration_bounds_the_existing_delay() {
        let mut config = DaemonConfig::default();
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 240);

        config.tick_interval_secs = 30;
        config.overhead_backoff.max_interval_secs = 90;
        config.overhead_backoff.healthy_ticks_before_recovery = 2;
        assert_eq!(state.next_tick_interval_secs(&config), 90);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.interval_secs, 90);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 45);
        state.observe_overhead_budget(&config, false);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        assert_eq!(state.next_tick_interval_secs(&config), 30);

        config.tick_interval_secs = 180;
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 180);
    }

    #[test]
    fn overhead_backoff_handles_zero_and_extreme_values_without_overflow() {
        let mut config = DaemonConfig {
            tick_interval_secs: 0,
            overhead_backoff: OverheadBackoffConfig {
                max_interval_secs: 0,
                healthy_ticks_before_recovery: 0,
            },
            ..Default::default()
        };
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 1);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 1);
        assert_eq!(state.overhead_backoff.interval_secs, 0);

        config.tick_interval_secs = u64::MAX;
        config.overhead_backoff.max_interval_secs = u64::MAX;
        for _ in 0..3 {
            state.observe_overhead_budget(&config, true);
            assert_eq!(state.next_tick_interval_secs(&config), u64::MAX);
        }

        config = DaemonConfig::default();
        let mut saved = serde_json::to_value(&state).unwrap();
        saved["overhead_backoff"]["healthy_ticks"] = serde_json::json!(u32::MAX);
        let mut restored: DaemonState = serde_json::from_value(saved).unwrap();
        assert_eq!(restored.next_tick_interval_secs(&config), 300);
        restored.observe_overhead_budget(&config, false);
        assert_eq!(restored.overhead_backoff.interval_secs, 300);
        assert_eq!(restored.overhead_backoff.healthy_ticks, 1);
    }

    #[test]
    fn overhead_backoff_overrides_emergency_cadence_without_clearing_pressure() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut metrics = pressure_metrics(40, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &metrics);
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        assert_eq!(state.next_tick_interval_secs(&config), 15);

        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 120);
        for _ in 0..2 {
            advance_reading(&mut metrics);
            state.observe_memory_pressure(&config, &metrics);
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), 120);
        }
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 15);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        assert!(state.memory_pressure_plan_pending);
    }

    fn pressure_metrics(utilization_percent: u64, psi: Option<f64>, at_secs: u64) -> TickMetrics {
        use crate::collect::pressure::{MemInfo, PsiLine, PsiResource};

        let mut metrics = test_metrics(1.0, 8192 * utilization_percent / 100, 0);
        metrics.pressure = Some(PressureSnapshot {
            sampled_at_ms: at_secs * 1000,
            cpus: 4,
            cpu: None,
            memory: psi.map(|avg10| PsiResource {
                some: Some(PsiLine {
                    avg10,
                    avg60: avg10,
                    avg300: avg10,
                    total_us: 10_000,
                }),
                full: None,
            }),
            io: None,
            irq: None,
            load: None,
            meminfo: Some(MemInfo {
                total: Some(1_000_000),
                available: Some(10_000 * (100 - utilization_percent)),
                ..Default::default()
            }),
            vmstat: None,
            file_handles: None,
            unavailable: Vec::new(),
        });
        metrics
    }

    fn advance_reading(metrics: &mut TickMetrics) {
        metrics.pressure.as_mut().unwrap().sampled_at_ms += 60_000;
    }

    fn typed_pressure_metrics(
        started_at: std::time::Instant,
        elapsed_secs: u64,
        cpu: (f64, u64),
        io: (f64, u64),
    ) -> TickMetrics {
        use crate::collect::pressure::{LoadAvg, PsiLine, PsiResource};

        let mut metrics = pressure_metrics(40, Some(0.0), 1000 + elapsed_secs);
        metrics.pressure_observed_at =
            Some(started_at + std::time::Duration::from_secs(elapsed_secs));
        let psi = |(average, total_us)| PsiResource {
            some: Some(PsiLine {
                avg10: average,
                avg60: average,
                avg300: average,
                total_us,
            }),
            full: None,
        };
        let pressure = metrics.pressure.as_mut().unwrap();
        pressure.cpu = Some(psi(cpu));
        pressure.io = Some(psi(io));
        pressure.load = Some(LoadAvg {
            one: 1.0,
            five: 1.0,
            fifteen: 1.0,
            runnable: Some(1),
            total: Some(200),
        });
        metrics
    }

    fn incident_metrics(started: std::time::Instant, tick: u64, critical: bool) -> TickMetrics {
        let mut metrics = typed_pressure_metrics(
            started,
            tick,
            (if critical { 40.0 } else { 0.0 }, 10_000),
            (0.0, 0),
        );
        metrics.timestamp = format!("sample-{tick}");
        metrics
    }

    fn observe_incident(
        tracker: &mut IncidentTracker,
        trigger_state: &mut triggers::TriggerState,
        config: &DaemonConfig,
        metrics: &TickMetrics,
    ) {
        triggers::evaluate_triggers(&config.triggers, trigger_state, metrics);
        tracker.observe(
            metrics,
            &trigger_state.pressure,
            None,
            config.triggers.pressure_regimes.exit_after_ticks,
        );
    }

    #[test]
    fn incident_is_durable_before_planner_and_records_real_deferrals_and_plan() {
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let started = std::time::Instant::now();
        let metrics = incident_metrics(started, 1, true);
        let mut planner_calls = 0;
        process_tick_with_incident_observer(
            &config,
            &mut state,
            &mut triggers,
            &metrics,
            &mut |tracker| tracker.persist(&store).unwrap(),
            &mut |_, _| {
                planner_calls += 1;
                let mut after_crash = IncidentTracker::default();
                after_crash.recover_persisted(&store).unwrap();
                let captured = after_crash.active_summary().unwrap();
                assert_eq!(captured.causes, vec![RegimeKind::CpuContention]);
                let id = incident_session_id(&captured.session_id).unwrap();
                assert!(store.session_dir(&id).join("incident.json").is_file());
                escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Deferred,
                    reason: "global action lock is held".into(),
                    session_id: None,
                    provenance_summary: None,
                }
            },
        );
        assert_eq!(planner_calls, 1);
        for reason in ["escalation cooldown", "daemon overhead budget exceeded"] {
            state.incidents.record_planner(
                &escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Deferred,
                    reason: reason.into(),
                    session_id: None,
                    provenance_summary: None,
                },
                None,
            );
        }
        state.incidents.record_planner(
            &escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Failed,
                reason: "planner timed out".into(),
                session_id: None,
                provenance_summary: None,
            },
            None,
        );
        let plan_session = pt_common::SessionId::new().0;
        state.incidents.record_planner(
            &escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: "review plan durably written".into(),
                session_id: Some(plan_session.clone()),
                provenance_summary: None,
            },
            None,
        );
        assert!(!state.incidents.attach_plan_reference(IncidentPlanRef {
            session_id: "../../victim".into(),
            plan_sha256: "a".repeat(64)
        }));
        assert!(!state.incidents.attach_plan_reference(IncidentPlanRef {
            session_id: plan_session.clone(),
            plan_sha256: "not-a-hash".into()
        }));
        assert!(state.incidents.attach_plan_reference(IncidentPlanRef {
            session_id: plan_session.clone(),
            plan_sha256: "a".repeat(64)
        }));
        state.incidents.persist(&store).unwrap();
        let record = state.incidents.active.as_ref().unwrap();
        assert_eq!(record.planner_attempts.len(), 5);
        assert_eq!(
            record.planner_attempts[0].reason,
            "global action lock is held"
        );
        assert_eq!(record.planner_attempts[1].reason, "escalation cooldown");
        assert_eq!(
            record.planner_attempts[2].reason,
            "daemon overhead budget exceeded"
        );
        assert_eq!(
            record.planner_attempts[3].status,
            escalation::EscalationStatus::Failed
        );
        assert_eq!(
            record.planner_attempts[4].plan.as_ref().unwrap().session_id,
            plan_session
        );
        let manifest: SessionManifest = read_daemon_json_bounded(
            &store
                .session_dir(&incident_session_id(&record.session_id).unwrap())
                .join("manifest.json"),
            32 * 1024,
        )
        .unwrap()
        .unwrap();
        assert_eq!(manifest.mode, SessionMode::DaemonAlert);
        assert_eq!(manifest.state, SessionState::Scanning);
        assert!(!manifest
            .state_history
            .iter()
            .any(|transition| transition.state == SessionState::Executing));
        state.incidents.record_planner(
            &escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Failed,
                reason: "review plan created but durable inbox delivery failed".into(),
                session_id: Some(plan_session.clone()),
                provenance_summary: None,
            },
            None,
        );
        assert!(state.incidents.attach_plan_reference(IncidentPlanRef {
            session_id: plan_session,
            plan_sha256: "b".repeat(64),
        }));
        let summary = state.incidents.active_summary().unwrap();
        assert_eq!(
            summary.latest_planner_status,
            Some(escalation::EscalationStatus::Failed)
        );
        assert_eq!(summary.latest_plan.unwrap().plan_sha256, "b".repeat(64));
        state.incidents.persist(&store).unwrap();
    }

    #[test]
    fn checkpoint_recovers_first_incident_before_session_creation_or_daemon_state_save() {
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(std::time::Instant::now(), 1, true),
        );
        tracker.publish_checkpoint(&store).unwrap();
        let id = incident_session_id(&tracker.active_summary().unwrap().session_id).unwrap();
        assert!(!store.session_dir(&id).exists());
        let mut restarted = IncidentTracker::default();
        restarted.recover_persisted(&store).unwrap();
        assert_eq!(restarted.active_summary().unwrap().session_id, id.0);
        assert_eq!(restarted.active.as_ref().unwrap().after.len(), 1);
        restarted.persist(&store).unwrap();
        assert!(store.session_dir(&id).join("incident.json").is_file());
        assert!(restarted.previous.is_none());
        assert_eq!(restarted.recovery_streak, 0);
    }

    #[test]
    fn incident_recovery_requires_observed_evidence_across_missing_data_and_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        config.triggers.pressure_regimes.exit_after_ticks = 3;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 1, true),
        );
        let id = incident_session_id(&tracker.active_summary().unwrap().session_id).unwrap();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 2, false),
        );
        assert_eq!(tracker.recovery_streak, 1);
        let mut missing = incident_metrics(started, 3, false);
        missing.pressure.as_mut().unwrap().cpu = None;
        observe_incident(&mut tracker, &mut triggers, &config, &missing);
        assert_eq!(tracker.recovery_streak, 0);
        assert!(tracker.active_summary().is_some());
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 4, false),
        );
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 5, false),
        );
        tracker.persist(&store).unwrap();
        let mut restarted: IncidentTracker =
            serde_json::from_slice(&serde_json::to_vec(&tracker).unwrap()).unwrap();
        restarted.recover_persisted(&store).unwrap();
        assert_eq!(restarted.recovery_streak, 0);
        for tick in 6..=7 {
            observe_incident(
                &mut restarted,
                &mut triggers,
                &config,
                &incident_metrics(started, tick, false),
            );
            assert!(restarted.active_summary().is_some());
        }
        observe_incident(
            &mut restarted,
            &mut triggers,
            &config,
            &incident_metrics(started, 8, false),
        );
        assert!(restarted.active_summary().is_none());
        assert_eq!(
            restarted.last_summary().unwrap().recovered_at.as_deref(),
            Some("sample-8")
        );
        restarted.persist(&store).unwrap();
        assert!(restarted.pending_archives.is_empty());
        let archived: IncidentRecord = read_daemon_json_bounded(
            &store.session_dir(&id).join("incident.json"),
            INCIDENT_MAX_BYTES,
        )
        .unwrap()
        .unwrap();
        assert_eq!(archived.recovered_at.as_deref(), Some("sample-8"));
        let manifest: SessionManifest =
            read_daemon_json_bounded(&store.session_dir(&id).join("manifest.json"), 32 * 1024)
                .unwrap()
                .unwrap();
        assert_eq!(manifest.state, SessionState::Completed);
    }

    #[test]
    fn incident_sample_and_planner_history_are_bounded_during_a_long_episode() {
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        for tick in 1..=20 {
            observe_incident(
                &mut tracker,
                &mut triggers,
                &config,
                &incident_metrics(started, tick, false),
            );
        }
        for tick in 21..=120 {
            let mut metrics = incident_metrics(started, tick, true);
            metrics.pressure.as_mut().unwrap().unavailable = (0..20)
                .map(|_| crate::collect::pressure::Unavailable {
                    source: "long sensor name".repeat(100),
                    reason: "\u{1}".repeat(2000),
                })
                .collect();
            observe_incident(&mut tracker, &mut triggers, &config, &metrics);
            tracker.record_planner(
                &escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Deferred,
                    reason: "⏳".repeat(2000),
                    session_id: None,
                    provenance_summary: None,
                },
                None,
            );
        }
        let record = tracker.active.as_ref().unwrap();
        record.validate().unwrap();
        assert!(record.before.len() <= INCIDENT_BEFORE_SAMPLES);
        assert!(record.after.len() <= INCIDENT_AFTER_SAMPLES);
        assert_eq!(record.after.back().unwrap().timestamp, "sample-120");
        assert_eq!(record.samples_observed, 100);
        assert!(record.samples_dropped >= 76);
        assert_eq!(record.planner_attempts.len(), INCIDENT_PLANNER_ATTEMPTS);
        assert_eq!(record.planner_attempts_dropped, 92);
        assert!(serde_json::to_vec(record).unwrap().len() <= INCIDENT_MAX_BYTES);
        tracker.checkpoint().validate().unwrap();
    }

    #[test]
    fn incident_byte_budget_covers_plan_attachment_and_recovery_metadata() {
        fn fill_to(record: &mut IncidentRecord, target: usize, after_count: usize) {
            let mut sample = record.after.back().unwrap().clone();
            sample.pressure.as_mut().unwrap().unavailable = (0..4)
                .map(|_| crate::collect::pressure::Unavailable {
                    source: String::new(),
                    reason: String::new(),
                })
                .collect();
            record.before = std::iter::repeat_n(sample.clone(), INCIDENT_BEFORE_SAMPLES).collect();
            record.after = std::iter::repeat_n(sample, after_count).collect();
            let mut remaining = target - serde_json::to_vec(&*record).unwrap().len();
            for sample in record.before.iter_mut().chain(&mut record.after) {
                for unavailable in &mut sample.pressure.as_mut().unwrap().unavailable {
                    // A control byte occupies six JSON bytes, retaining ample
                    // valid string capacity while filling the encoded budget.
                    let count = (remaining / 6).min(512);
                    unavailable.reason = "\u{1}".repeat(count);
                    remaining -= count * 6;
                }
            }
            assert!(remaining < 6);
            record
                .before
                .front_mut()
                .unwrap()
                .pressure
                .as_mut()
                .unwrap()
                .unavailable[0]
                .source = "x".repeat(remaining);
            assert_eq!(serde_json::to_vec(&*record).unwrap().len(), target);
            record.validate().unwrap();
        }

        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        config.triggers.pressure_regimes.exit_after_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 1, true),
        );
        let plan_session = pt_common::SessionId::new().0;
        tracker.record_planner(
            &escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: "review plan generated".into(),
                session_id: Some(plan_session.clone()),
                provenance_summary: None,
            },
            None,
        );
        fill_to(
            tracker.active.as_mut().unwrap(),
            INCIDENT_MAX_BYTES - 1,
            INCIDENT_AFTER_SAMPLES,
        );
        tracker.persist(&store).unwrap();
        assert!(tracker.attach_plan_reference(IncidentPlanRef {
            session_id: plan_session,
            plan_sha256: "c".repeat(64)
        }));
        tracker.active.as_ref().unwrap().validate().unwrap();
        assert!(tracker.active.as_ref().unwrap().samples_dropped > 0);
        tracker.persist(&store).unwrap();

        let healthy = incident_metrics(started, 2, false);
        let record = tracker.active.as_mut().unwrap();
        record.revision += 1;
        fill_to(record, INCIDENT_MAX_BYTES, INCIDENT_AFTER_SAMPLES - 1);
        let mut next = record.clone();
        next.last_observed_at = healthy.timestamp.clone();
        next.samples_observed += 1;
        next.revision += 1;
        next.after.push_back(IncidentSample {
            timestamp: healthy.timestamp.clone(),
            pressure: healthy.pressure.clone(),
            process_census: healthy.process_census,
            memory_mode: None,
            observed_live: true,
            unavailable_reason: None,
        });
        let observation_growth = serde_json::to_vec(&next).unwrap().len() - INCIDENT_MAX_BYTES;
        fill_to(
            record,
            INCIDENT_MAX_BYTES - observation_growth,
            INCIDENT_AFTER_SAMPLES - 1,
        );
        let dropped_before_recovery = record.samples_dropped;
        tracker.generation += 1;
        tracker.persist(&store).unwrap();
        observe_incident(&mut tracker, &mut triggers, &config, &healthy);
        assert!(tracker.active.is_none());
        let closed = tracker.pending_archives.back().unwrap();
        closed.validate().unwrap();
        assert!(closed.samples_dropped > dropped_before_recovery);
        assert_eq!(closed.recovered_at.as_deref(), Some("sample-2"));
        let id = incident_session_id(&closed.session_id).unwrap();
        tracker.persist(&store).unwrap();
        let saved: IncidentRecord = read_daemon_json_bounded(
            &store.session_dir(&id).join("incident.json"),
            INCIDENT_MAX_BYTES,
        )
        .unwrap()
        .unwrap();
        saved.validate().unwrap();
        assert_eq!(saved.recovered_at.as_deref(), Some("sample-2"));
        assert_eq!(
            saved
                .planner_attempts
                .back()
                .unwrap()
                .plan
                .as_ref()
                .unwrap()
                .plan_sha256,
            "c".repeat(64)
        );
    }

    #[test]
    fn deferred_oom_is_captured_once_and_counter_resets_do_not_prove_recovery() {
        use crate::collect::pressure::VmStat;
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        config.triggers.pressure_regimes.exit_after_ticks = 2;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        for (tick, kills) in [(1, 10), (2, 11), (3, 0)] {
            let mut metrics = incident_metrics(started, tick, false);
            metrics.pressure.as_mut().unwrap().vmstat = Some(VmStat {
                oom_kill: Some(kills),
                ..Default::default()
            });
            observe_incident(&mut tracker, &mut triggers, &config, &metrics);
        }
        assert_eq!(
            tracker.active_summary().unwrap().causes,
            vec![RegimeKind::OomKills]
        );
        assert_eq!(tracker.recovery_streak, 0);
        for tick in 4..=5 {
            let mut metrics = incident_metrics(started, tick, false);
            metrics.pressure.as_mut().unwrap().vmstat = Some(VmStat {
                oom_kill: Some(0),
                ..Default::default()
            });
            observe_incident(&mut tracker, &mut triggers, &config, &metrics);
        }
        assert!(tracker.active_summary().is_none());
        let last_id = tracker.last_summary().unwrap().session_id;
        let mut metrics = incident_metrics(started, 6, false);
        metrics.pressure = None;
        observe_incident(&mut tracker, &mut triggers, &config, &metrics);
        assert!(triggers
            .pressure
            .pending
            .contains_key(&RegimeKind::OomKills));
        assert!(tracker.active_summary().is_none());
        assert_eq!(tracker.last_summary().unwrap().session_id, last_id);
    }

    #[test]
    fn inactive_incident_does_not_collect_planner_outcomes() {
        let mut tracker = IncidentTracker::default();
        tracker.record_planner(
            &escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Deferred,
                reason: "cooldown".into(),
                session_id: None,
                provenance_summary: None,
            },
            None,
        );
        assert!(tracker.active_summary().is_none());
        assert_eq!(tracker.generation, 0);
    }

    #[test]
    fn incident_pending_archives_remain_bounded_and_report_dropped_history() {
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        config.triggers.pressure_regimes.exit_after_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        // Simulate a disk outage spanning many independently recovered episodes.
        for episode in 0..5 {
            observe_incident(
                &mut tracker,
                &mut triggers,
                &config,
                &incident_metrics(started, episode * 2 + 1, true),
            );
            observe_incident(
                &mut tracker,
                &mut triggers,
                &config,
                &incident_metrics(started, episode * 2 + 2, false),
            );
        }
        assert!(tracker.active_summary().is_none());
        assert_eq!(tracker.pending_archives.len(), INCIDENT_PENDING_ARCHIVES);
        assert_eq!(tracker.discarded_pending_archives, 3);
        assert_eq!(
            tracker.last_summary().unwrap().recovered_at.as_deref(),
            Some("sample-10")
        );
        tracker.checkpoint().validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn incident_artifact_failure_preserves_a_restartable_checkpoint() {
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 1, true),
        );
        let id = incident_session_id(&tracker.active_summary().unwrap().session_id).unwrap();
        let mut manifest = SessionManifest::new(
            &id,
            None,
            SessionMode::DaemonAlert,
            Some("Critical pressure incident".into()),
        );
        manifest.record_state(SessionState::Scanning);
        store.create(&manifest).unwrap();
        let victim = temporary.path().join("protected.json");
        std::fs::write(&victim, b"{\"untouched\":true}").unwrap();
        std::os::unix::fs::symlink(&victim, store.session_dir(&id).join("incident.json")).unwrap();
        assert!(tracker.persist(&store).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"{\"untouched\":true}");
        let checkpoint: IncidentCheckpoint = read_daemon_json_bounded(
            &store.sessions_root().join(INCIDENT_CHECKPOINT_FILE),
            INCIDENT_CHECKPOINT_MAX_BYTES,
        )
        .unwrap()
        .unwrap();
        assert_eq!(checkpoint.active.as_ref().unwrap().session_id, id.0);
        assert_eq!(checkpoint.active.as_ref().unwrap().after.len(), 1);
        let mut restarted = IncidentTracker::default();
        // The poisoned archive remains an explicit error, while the valid
        // checkpoint has already restored the episode for inspection/retry.
        assert!(restarted.recover_persisted(&store).is_err());
        assert_eq!(restarted.active_summary().unwrap().session_id, id.0);
        assert!(restarted.storage_error.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn incident_persistence_rejects_symlinks_special_files_and_oversized_checkpoints() {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(&temporary.path().join("linked"));
        std::fs::create_dir_all(store.sessions_root()).unwrap();
        let victim = temporary.path().join("victim.json");
        std::fs::write(&victim, b"{\"untouched\":true}").unwrap();
        symlink(
            &victim,
            store.sessions_root().join(INCIDENT_CHECKPOINT_FILE),
        )
        .unwrap();
        let mut tracker = IncidentTracker::default();
        assert!(tracker.persist(&store).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"{\"untouched\":true}");
        assert!(tracker.storage_error.is_some());

        let store = SessionStore::at_data_dir(&temporary.path().join("oversized"));
        std::fs::create_dir_all(store.sessions_root()).unwrap();
        std::fs::write(
            store.sessions_root().join(INCIDENT_CHECKPOINT_FILE),
            vec![b' '; INCIDENT_CHECKPOINT_MAX_BYTES + 1],
        )
        .unwrap();
        assert!(IncidentTracker::default()
            .recover_persisted(&store)
            .is_err());

        let fifo = temporary.path().join("fifo.json");
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the test owns this temporary pathname and the C string is live.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_daemon_json_bounded::<serde_json::Value>(&fifo, 4096).is_err());
    }

    #[test]
    fn stale_incident_writer_cannot_replace_a_newer_checkpoint() {
        let temporary = tempfile::tempdir().unwrap();
        let store = SessionStore::at_data_dir(temporary.path());
        let mut config = DaemonConfig::default();
        config.triggers.sustained_ticks = 1;
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut tracker = IncidentTracker::default();
        let started = std::time::Instant::now();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 1, true),
        );
        tracker.persist(&store).unwrap();
        let mut stale = tracker.clone();
        observe_incident(
            &mut tracker,
            &mut triggers,
            &config,
            &incident_metrics(started, 2, true),
        );
        tracker.persist(&store).unwrap();
        assert!(stale
            .persist(&store)
            .unwrap_err()
            .contains("newer or conflicting"));
        stale.recover_persisted(&store).unwrap();
        assert_eq!(stale.active.as_ref().unwrap().samples_observed, 2);
        stale.persist(&store).unwrap();
    }

    fn load_metrics(load: f64, cpus: u32) -> TickMetrics {
        use crate::collect::pressure::LoadAvg;

        let mut metrics = pressure_metrics(40, None, 1000);
        let pressure = metrics.pressure.as_mut().unwrap();
        pressure.cpus = cpus;
        pressure.load = Some(LoadAvg {
            one: load,
            five: load,
            fifteen: load,
            runnable: Some(1),
            total: Some(200),
        });
        metrics
    }

    #[test]
    fn observed_load_capacity_controls_the_escalation_callback() {
        for (cpus, expected_escalations) in [(2, 1), (64, 0)] {
            let config = DaemonConfig::default();
            let mut state = DaemonState::new();
            let mut triggers = triggers::TriggerState::new(&config.triggers);
            let mut metrics = load_metrics(10.0, cpus);
            let mut callbacks = 0;
            let mut plan = |config: &escalation::EscalationConfig,
                            fired: &[triggers::FiredTrigger]| {
                callbacks += 1;
                assert!(!config.allow_auto_mitigation);
                assert_eq!(fired.len(), 1);
                assert_eq!(fired[0].kind, triggers::TriggerKind::SustainedLoad);
                assert_eq!(fired[0].current_value, Some(10.0));
                assert_eq!(fired[0].threshold, Some(4.0));
                assert!(fired[0].description.contains("online_cpus=2"));
                escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: fired[0].description.clone(),
                    session_id: Some("load-review-plan".to_string()),
                    provenance_summary: None,
                }
            };

            for tick in 1..=4 {
                let outcome = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
                if tick < 3 {
                    assert!(outcome.escalation.is_none());
                }
                advance_reading(&mut metrics);
            }
            assert_eq!(callbacks, expected_escalations);
            assert_eq!(state.escalation_count, expected_escalations);
        }
    }

    #[test]
    fn unavailable_load_evidence_is_reported_once_per_outage() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let missing = test_metrics(1000.0, 2000, 0);
        let mut plan = |_: &escalation::EscalationConfig, _: &[triggers::FiredTrigger]| {
            panic!("missing CPU capacity must never trigger a load plan")
        };
        for tick in 0..3 {
            let outcome = process_tick(&config, &mut state, &mut triggers, &missing, &mut plan);
            let errors: Vec<_> = outcome
                .events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable)
                .collect();
            assert_eq!(errors.len(), usize::from(tick == 0));
            if let Some(error) = errors.first() {
                assert!(error
                    .detail
                    .contains("CPU capacity observation unavailable"));
            }
        }
        assert_eq!(
            state
                .recent_events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable)
                .count(),
            1
        );

        let observed = load_metrics(3.0, 2);
        process_tick(&config, &mut state, &mut triggers, &observed, &mut plan);
        assert!(triggers.load_unavailable_reason.is_none());
        let failed_again = process_tick(&config, &mut state, &mut triggers, &missing, &mut plan);
        assert!(failed_again
            .events
            .iter()
            .any(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable));
    }

    #[test]
    fn typed_pressure_episodes_share_planning_and_retry_until_delivery_completes() {
        use crate::decision::pressure_regime::{RegimeKind, Severity};

        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let started_at = std::time::Instant::now();
        let mut callbacks = 0;

        for tick in 0..7 {
            // The counters agree with the 40% CPU and 20% I/O stalls in each
            // real one-second monotonic interval, not only the PSI averages.
            let metrics = typed_pressure_metrics(
                started_at,
                tick,
                (40.0, 1_000_000 + tick * 400_000),
                (20.0, 1_000_000 + tick * 200_000),
            );
            let outcome = process_tick(
                &config,
                &mut state,
                &mut triggers,
                &metrics,
                &mut |escalation_config, fired| {
                    assert!(!escalation_config.allow_auto_mitigation);
                    assert_eq!(fired.len(), 2, "both regimes use one planning call");
                    let mut kinds = Vec::new();
                    for trigger in fired {
                        assert_eq!(trigger.kind, triggers::TriggerKind::PressureRegime);
                        assert_eq!(trigger.sustained_ticks, 3);
                        assert!(trigger.current_value.is_none());
                        assert!(trigger.memory_pressure.is_none());
                        let regime = trigger.pressure_regime.as_ref().unwrap();
                        assert_eq!(regime.severity, Severity::Crit);
                        kinds.push(regime.kind);
                    }
                    kinds.sort();
                    assert_eq!(kinds, [RegimeKind::CpuContention, RegimeKind::IoBound]);
                    let status = match callbacks {
                        0 => escalation::EscalationStatus::Deferred,
                        1 => escalation::EscalationStatus::Failed,
                        2 => escalation::EscalationStatus::Completed,
                        _ => panic!("a delivered active episode must not create another plan"),
                    };
                    callbacks += 1;
                    escalation::EscalationOutcome {
                        status,
                        reason: format!("review-plan delivery attempt {callbacks}"),
                        session_id: (status == escalation::EscalationStatus::Completed)
                            .then(|| "typed-pressure-review".to_string()),
                        provenance_summary: None,
                    }
                },
            );

            match tick {
                0 | 1 => {
                    assert!(outcome.triggers_fired.is_empty());
                    assert!(outcome.escalation.is_none());
                    assert!(triggers.pressure.pending.is_empty());
                }
                2 | 3 => {
                    let expected = if tick == 2 {
                        escalation::EscalationStatus::Deferred
                    } else {
                        escalation::EscalationStatus::Failed
                    };
                    assert_eq!(outcome.escalation.as_ref().unwrap().status, expected);
                    assert_eq!(triggers.pressure.pending.len(), 2);
                    assert_eq!(state.escalation_count, 0);
                }
                4 => {
                    assert_eq!(
                        outcome.escalation.as_ref().unwrap().status,
                        escalation::EscalationStatus::Completed
                    );
                    assert!(triggers.pressure.pending.is_empty());
                    assert_eq!(state.escalation_count, 1);
                }
                _ => {
                    assert!(outcome.triggers_fired.is_empty());
                    assert!(outcome.escalation.is_none());
                    assert!(triggers.pressure.pending.is_empty());
                    assert_eq!(triggers.pressure.active.len(), 2);
                }
            }
        }
        assert_eq!(callbacks, 3);
        assert_eq!(state.deferred_count, 1);
        assert_eq!(state.escalation_count, 1);
    }

    #[test]
    fn typed_pressure_requires_fresh_confirmation_and_observed_recovery_between_plans() {
        use crate::decision::pressure_regime::RegimeKind;

        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let started_at = std::time::Instant::now();
        let readings = [
            Some(40),
            Some(40),
            None,
            Some(40),
            Some(40),
            Some(40),
            Some(0),
            Some(0),
            None,
            Some(0),
            Some(0),
            Some(0),
            Some(40),
            Some(40),
            Some(40),
        ];
        let mut cpu_total_us = 1_000_000;
        let mut planned_ticks = Vec::new();
        for (tick, reading) in readings.into_iter().enumerate() {
            cpu_total_us += reading.unwrap_or(0) * 10_000;
            let mut metrics = typed_pressure_metrics(
                started_at,
                tick as u64,
                (reading.unwrap_or(0) as f64, cpu_total_us),
                (0.0, 1_000_000),
            );
            if reading.is_none() {
                metrics.pressure = None;
            }
            let outcome = process_tick(
                &config,
                &mut state,
                &mut triggers,
                &metrics,
                &mut |escalation_config, fired| {
                    assert!(!escalation_config.allow_auto_mitigation);
                    assert_eq!(fired.len(), 1);
                    assert_eq!(fired[0].kind, triggers::TriggerKind::PressureRegime);
                    assert_eq!(
                        fired[0].pressure_regime.as_ref().unwrap().kind,
                        RegimeKind::CpuContention
                    );
                    planned_ticks.push(tick);
                    escalation::EscalationOutcome {
                        status: escalation::EscalationStatus::Completed,
                        reason: "review plan delivered".to_string(),
                        session_id: Some(format!("pressure-episode-{tick}")),
                        provenance_summary: None,
                    }
                },
            );
            assert_eq!(outcome.escalation.is_some(), matches!(tick, 5 | 14));
            assert_eq!(
                triggers
                    .pressure
                    .active
                    .contains_key(&RegimeKind::CpuContention),
                matches!(tick, 5..=10 | 14),
                "missing data must interrupt confirmation and recovery at tick {tick}"
            );
        }
        assert_eq!(planned_ticks, [5, 14]);
        assert_eq!(state.escalation_count, 2);
    }

    #[test]
    fn psi_pressure_reaches_escalation_and_preserves_its_cooldown() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut escalation = escalation::EscalationState::new();
        let mut metrics = pressure_metrics(40, Some(75.0), 1000);
        let mut plan = |config: &escalation::EscalationConfig, fired: &[triggers::FiredTrigger]| {
            assert!(!config.allow_auto_mitigation);
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0].kind, triggers::TriggerKind::MemoryPressure);
            let pressure = fired[0].memory_pressure.as_ref().unwrap();
            assert_eq!(pressure.mode, PressureMode::Emergency);
            assert_eq!(pressure.psi_some10, Some(75.0));
            escalation::decide_escalation(config, &mut escalation, fired, || true)
        };

        let first = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert!(
            first.escalation.is_none(),
            "one PSI spike must not escalate"
        );
        advance_reading(&mut metrics);
        let second = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            second.escalation.unwrap().status,
            escalation::EscalationStatus::Completed
        );
        assert_eq!(second.next_tick_interval_secs, 15);
        advance_reading(&mut metrics);
        let third = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        let deferred = third.escalation.unwrap();
        assert_eq!(deferred.status, escalation::EscalationStatus::Deferred);
        assert!(deferred.reason.contains("Cooldown"));
        assert_eq!(state.escalation_count, 1);
        assert_eq!(state.deferred_count, 1);
    }

    #[test]
    fn pressure_warning_retries_a_deferred_plan_without_requiring_a_new_episode() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut escalation = escalation::EscalationState::new();
        let mut metrics = pressure_metrics(40, Some(25.0), 1000);
        let mut lock_available = false;
        let mut plan = |config: &escalation::EscalationConfig, fired: &[triggers::FiredTrigger]| {
            let outcome =
                escalation::decide_escalation(config, &mut escalation, fired, || lock_available);
            lock_available = true;
            outcome
        };

        process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        advance_reading(&mut metrics);
        let blocked = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            blocked.escalation.unwrap().status,
            escalation::EscalationStatus::Deferred
        );
        assert!(state.memory_pressure_plan_pending);
        assert_eq!(blocked.next_tick_interval_secs, 30);
        advance_reading(&mut metrics);
        let retried = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            retried.escalation.unwrap().status,
            escalation::EscalationStatus::Completed
        );
        assert!(!state.memory_pressure_plan_pending);
        advance_reading(&mut metrics);
        let stable = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert!(stable.escalation.is_none());
    }

    #[test]
    fn daemon_restart_and_missing_sensors_cannot_clear_memory_pressure() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut emergency = pressure_metrics(40, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &emergency);
        advance_reading(&mut emergency);
        state.observe_memory_pressure(&config, &emergency);
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut state: DaemonState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);

        let mut missing = pressure_metrics(40, None, 1120);
        state.observe_memory_pressure(&config, &missing);
        assert!(state.last_memory_pressure.is_none());
        assert_eq!(state.next_tick_interval_secs(&config), 15);
        missing.pressure.as_mut().unwrap().meminfo = None;
        advance_reading(&mut missing);
        state.observe_memory_pressure(&config, &missing);
        assert!(state.last_memory_pressure.is_none());
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);

        let mut normal = pressure_metrics(40, Some(1.0), 1240);
        state.observe_memory_pressure(&config, &normal);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        advance_reading(&mut normal);
        state.observe_memory_pressure(&config, &normal);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Normal);
        assert_eq!(state.next_tick_interval_secs(&config), 60);
        assert!(!state.memory_pressure_plan_pending);
    }

    #[test]
    fn pressure_cadence_never_slows_the_base_or_creates_a_busy_loop() {
        let mut config = DaemonConfig {
            tick_interval_secs: 5,
            ..Default::default()
        };
        let mut state = DaemonState::new();
        let mut metrics = pressure_metrics(97, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &metrics);
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.next_tick_interval_secs(&config), 5);

        config.memory_pressure.emergency_interval_secs = 0.0;
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.next_tick_interval_secs(&config), 5);
        config.tick_interval_secs = 0;
        assert_eq!(state.next_tick_interval_secs(&config), 1);
    }

    #[test]
    fn pressure_plan_keeps_auto_mitigation_disabled() {
        let mut config = DaemonConfig::default();
        config.memory_pressure.transition_count = 1;
        config.memory_pressure.auto_apply = true;
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut triggers,
            &pressure_metrics(40, Some(75.0), 1000),
            &mut |config, _| {
                assert!(!config.allow_auto_mitigation);
                escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: "review plan generated".to_string(),
                    session_id: Some("pressure-plan".to_string()),
                    provenance_summary: None,
                }
            },
        );
        assert_eq!(
            outcome.escalation.unwrap().session_id.as_deref(),
            Some("pressure-plan")
        );
    }
}
