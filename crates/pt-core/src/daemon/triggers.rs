//! Trigger detection with EWMA baselines, sustained-window rules, and cooldown.
//!
//! Each trigger type maintains its own EWMA baseline and a counter tracking
//! how many consecutive ticks the signal has exceeded the threshold. A trigger
//! fires only after the threshold is breached for `sustained_ticks` consecutive
//! ticks, preventing flapping.
//!
//! After firing, a cooldown period suppresses re-firing for `cooldown_ticks`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use crate::collect::pressure::{pressure_window_with_elapsed, PressureSnapshot};
use crate::decision::pressure_regime::{
    assess, psi_evidence_available, regime_evidence_available, PressureAssessment,
    PressureThresholds, Regime, RegimeKind, RegimeTracker, Severity,
};

use super::TickMetrics;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Trigger configuration for the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TriggerConfig {
    /// EWMA decay factor (0..1). Higher = more weight to recent values.
    pub ewma_alpha: f64,
    /// Explicit absolute load-average threshold. When present, this overrides
    /// `load_per_cpu_threshold`, preserving existing daemon configurations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_threshold: Option<f64>,
    /// One-minute load per observed online CPU. Used when no absolute threshold
    /// is configured; requires load and CPU count from the same pressure reading.
    pub load_per_cpu_threshold: f64,
    /// Memory usage fraction threshold (0..1). Trigger at e.g. 0.85 = 85%.
    pub memory_threshold: f64,
    /// Orphan count threshold. Trigger if orphan count sustained above this.
    pub orphan_threshold: u32,
    /// Number of consecutive ticks above threshold before firing.
    pub sustained_ticks: u32,
    /// Number of ticks after firing before the trigger can fire again.
    pub cooldown_ticks: u32,
    /// Observed pressure episodes create review plans through the normal daemon path.
    pub pressure_regimes: PressureRegimeConfig,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.3,
            load_threshold: None,
            load_per_cpu_threshold: 2.0,
            memory_threshold: 0.85,
            orphan_threshold: 20,
            sustained_ticks: 3,
            cooldown_ticks: 10,
            pressure_regimes: PressureRegimeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PressureRegimeConfig {
    pub enabled: bool,
    /// Consecutive observed recovery samples before a new episode can begin.
    pub exit_after_ticks: u32,
    pub minimum_severity: Severity,
    pub thresholds: PressureThresholds,
}

impl Default for PressureRegimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exit_after_ticks: 3,
            minimum_severity: Severity::Warn,
            thresholds: PressureThresholds::default(),
        }
    }
}

impl PressureRegimeConfig {
    fn valid(&self) -> bool {
        let t = &self.thresholds;
        let bands = [
            t.cpu_psi,
            t.io_psi,
            t.memory_psi,
            t.load_ratio,
            t.swap_pages_per_s,
            t.swap_used,
            t.file_handles,
            t.zombies,
            t.dstate_per_cpu,
        ];
        bands.iter().all(|band| {
            band.warn.is_finite()
                && band.crit.is_finite()
                && band.warn >= 0.0
                && band.crit > band.warn
        }) && [t.cpu_psi.crit, t.io_psi.crit, t.memory_psi.crit]
            .iter()
            .all(|value| *value <= 100.0)
            && [t.swap_used.crit, t.file_handles.crit]
                .iter()
                .all(|value| *value <= 1.0)
            && t.cpu_psi_quiet.is_finite()
            && (0.0..=100.0).contains(&t.cpu_psi_quiet)
            && t.memory_used_plentiful.is_finite()
            && t.memory_used_exhausted.is_finite()
            && (0.0..=1.0).contains(&t.memory_used_plentiful)
            && (0.0..=1.0).contains(&t.memory_used_exhausted)
            && t.memory_used_plentiful < t.memory_used_exhausted
    }
}

/// Episode confirmation and delivery are separate: a deferred plan is still due.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureTriggerState {
    tracker: RegimeTracker,
    settings: Option<(u32, PressureRegimeConfig)>,
    pub active: BTreeMap<RegimeKind, Severity>,
    /// Highest successfully delivered severity in each still-active episode.
    announced: BTreeMap<RegimeKind, Severity>,
    pub pending: BTreeMap<RegimeKind, Regime>,
    pub last_assessment: Option<PressureAssessment>,
    pub unavailable_reason: Option<String>,
    // Neither wall clocks nor a serialized Instant can establish a live interval.
    #[serde(skip)]
    previous: Option<(PressureSnapshot, Instant)>,
}

impl Default for PressureTriggerState {
    fn default() -> Self {
        Self {
            tracker: RegimeTracker::new(3, 3),
            settings: None,
            active: BTreeMap::new(),
            announced: BTreeMap::new(),
            pending: BTreeMap::new(),
            last_assessment: None,
            unavailable_reason: None,
            previous: None,
        }
    }
}

impl PressureTriggerState {
    /// Restart, missing observations and policy reload cannot prove continued recovery.
    pub fn interrupt_observations(&mut self) {
        self.previous = None;
        self.last_assessment = None;
        self.active = self
            .tracker
            .update_observed(None, |_| false)
            .into_iter()
            .collect();
    }

    pub fn observe(&mut self, config: &TriggerConfig, metrics: &TickMetrics) -> Vec<Regime> {
        let settings = (config.sustained_ticks.max(1), config.pressure_regimes);
        if self.settings != Some(settings) {
            *self = Self::default();
            self.tracker = RegimeTracker::new(settings.0, settings.1.exit_after_ticks);
            self.settings = Some(settings);
        }
        if !settings.1.enabled {
            return Vec::new();
        }
        if !settings.1.valid() {
            self.interrupt_observations();
            self.unavailable_reason = Some("invalid pressure-regime thresholds".into());
            return Vec::new();
        }
        let Some(snapshot) = metrics.pressure.as_ref() else {
            self.interrupt_observations();
            self.unavailable_reason =
                Some("pressure observation unavailable; active episodes retained".into());
            // A previously observed OOM increment remains an incident even when
            // the next sensor read fails. It is cleared only after delivery.
            return self
                .pending
                .get(&RegimeKind::OomKills)
                .cloned()
                .into_iter()
                .collect();
        };
        let Some(observed_at) = metrics.pressure_observed_at else {
            self.interrupt_observations();
            self.unavailable_reason = Some(
                "live pressure sampling clock unavailable; no sustained regime confirmation".into(),
            );
            return self
                .pending
                .get(&RegimeKind::OomKills)
                .cloned()
                .into_iter()
                .collect();
        };
        if self
            .previous
            .as_ref()
            .is_some_and(|(_, at)| observed_at <= *at)
        {
            self.interrupt_observations();
            self.unavailable_reason =
                Some("pressure observation did not advance monotonically".into());
            return self
                .pending
                .get(&RegimeKind::OomKills)
                .cloned()
                .into_iter()
                .collect();
        }
        self.unavailable_reason = None;
        let window = self.previous.as_ref().and_then(|(before, at)| {
            metrics
                .pressure_observed_at
                .and_then(|now| now.checked_duration_since(*at))
                .and_then(|elapsed| pressure_window_with_elapsed(before, snapshot, elapsed))
        });
        self.previous = Some((snapshot.clone(), observed_at));
        let assessment = assess(snapshot, window.as_ref(), None, &settings.1.thresholds);
        let observed = |kind| {
            // The existing load trigger handles hosts without CPU PSI. An
            // observed PSI episode must never clear through that fallback.
            regime_evidence_available(kind, snapshot, window.as_ref(), None, true, false)
        };
        self.active = self
            .tracker
            .update_observed(Some(&assessment), |kind| {
                kind != RegimeKind::OomKills && observed(kind)
            })
            .into_iter()
            .collect();
        self.announced
            .retain(|kind, _| self.active.contains_key(kind));
        self.pending
            .retain(|kind, _| *kind == RegimeKind::OomKills || self.active.contains_key(kind));
        let minimum = settings.1.minimum_severity.max(Severity::Warn);
        for regime in &assessment.regimes {
            let confirmed =
                regime.kind == RegimeKind::OomKills || self.active.contains_key(&regime.kind);
            if confirmed && observed(regime.kind) {
                if regime.severity >= minimum
                    && self
                        .announced
                        .get(&regime.kind)
                        .is_none_or(|delivered| regime.severity > *delivered)
                {
                    self.pending.insert(regime.kind, regime.clone());
                } else {
                    // Do not deliver a deferred critical upgrade after current
                    // evidence has returned to an already delivered warning.
                    self.pending.remove(&regime.kind);
                }
            }
        }
        let due = self
            .pending
            .values()
            .filter(|regime| {
                regime.kind == RegimeKind::OomKills
                    || (observed(regime.kind)
                        && assessment.regimes.iter().any(|current| {
                            current.kind == regime.kind && current.severity >= minimum
                        }))
            })
            .cloned()
            .collect();
        self.last_assessment = Some(assessment);
        due
    }

    pub fn acknowledge(&mut self, fired: &[FiredTrigger]) {
        for regime in fired
            .iter()
            .filter_map(|trigger| trigger.pressure_regime.as_ref())
        {
            if regime.kind != RegimeKind::OomKills {
                self.announced
                    .entry(regime.kind)
                    .and_modify(|severity| *severity = (*severity).max(regime.severity))
                    .or_insert(regime.severity);
            }
            self.pending.remove(&regime.kind);
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Per-trigger tracking state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerState {
    /// EWMA of load_avg_1.
    pub load_ewma: f64,
    /// Number of valid load readings used by the EWMA. Missing observations do
    /// not initialize it with an invented zero or poison it with NaN.
    #[serde(default)]
    pub load_observed_ticks: u64,
    /// Why this tick could not evaluate the configured load trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_unavailable_reason: Option<String>,
    /// EWMA of memory fraction.
    pub memory_ewma: f64,
    /// EWMA of orphan count.
    pub orphan_ewma: f64,

    /// Consecutive ticks load has exceeded threshold.
    pub load_sustained: u32,
    /// Consecutive ticks memory has exceeded threshold.
    pub memory_sustained: u32,
    /// Consecutive ticks orphan count has exceeded threshold.
    pub orphan_sustained: u32,

    /// Remaining cooldown ticks for each trigger type.
    pub load_cooldown: u32,
    pub memory_cooldown: u32,
    pub orphan_cooldown: u32,

    /// Total number of ticks processed.
    pub total_ticks: u64,
    #[serde(default)]
    pub pressure: PressureTriggerState,
}

impl TriggerState {
    pub fn new(_config: &TriggerConfig) -> Self {
        Self {
            load_ewma: 0.0,
            load_observed_ticks: 0,
            load_unavailable_reason: None,
            memory_ewma: 0.0,
            orphan_ewma: 0.0,
            load_sustained: 0,
            memory_sustained: 0,
            orphan_sustained: 0,
            load_cooldown: 0,
            memory_cooldown: 0,
            orphan_cooldown: 0,
            total_ticks: 0,
            pressure: PressureTriggerState::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Trigger types
// ---------------------------------------------------------------------------

/// The kind of trigger that fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    SustainedLoad,
    MemoryPressure,
    OrphanSpike,
    PressureRegime,
}

/// A trigger that has fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredTrigger {
    pub kind: TriggerKind,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ewma_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    pub sustained_ticks: u32,
    /// Provenance context: top contributing PIDs and their blast-radius risk.
    /// Populated when provenance is enabled; absent otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_context: Vec<TriggerProvenanceHint>,
    /// Validated memory/PSI state behind a pressure-triggered review plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_pressure: Option<crate::decision::mem_pressure::PressureEvaluation>,
    /// Typed diagnosis; scalar trigger fields do not invent a common metric for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_regime: Option<Regime>,
}

/// Provenance hint attached to a daemon trigger.
///
/// Provides minimal provenance context so alert consumers know which
/// processes contributed to the spike and how risky they are to kill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerProvenanceHint {
    /// Process ID of a top contributor.
    pub pid: u32,
    /// Short command name.
    pub comm: String,
    /// Blast-radius risk level (low/medium/high/critical/unknown).
    pub blast_radius_risk: String,
    /// Whether provenance evidence was available for this process.
    pub evidence_available: bool,
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

struct LoadObservation {
    load_avg_1: f64,
    /// Effective threshold in load-average units, matching the reported EWMA.
    threshold: f64,
    /// Present only when the threshold is relative to observed CPU capacity.
    cpus: Option<u32>,
}

fn load_observation(
    config: &TriggerConfig,
    metrics: &TickMetrics,
) -> Result<LoadObservation, &'static str> {
    // The scalar gauges have historical zero fallbacks. When an actual reading
    // exists, use its load value (including its absence), never the scalar.
    let load = match &metrics.pressure {
        Some(pressure) => {
            pressure
                .load
                .ok_or("one-minute load average unavailable in pressure reading")?
                .one
        }
        None if config.load_threshold.is_some() => metrics.load_avg_1,
        None => return Err("load and online CPU capacity observation unavailable"),
    };
    if !load.is_finite() || load < 0.0 {
        return Err("one-minute load average is not finite and nonnegative");
    }

    if let Some(threshold) = config.load_threshold {
        if !threshold.is_finite() {
            return Err("configured absolute load threshold is not finite");
        }
        return Ok(LoadObservation {
            load_avg_1: load,
            threshold,
            cpus: None,
        });
    }

    let cpus = metrics
        .pressure
        .as_ref()
        .filter(|pressure| pressure.cpus > 0)
        .ok_or("online CPU capacity unavailable in pressure reading")?
        .cpus;
    let threshold = config.load_per_cpu_threshold * f64::from(cpus);
    if !threshold.is_finite() || threshold < 0.0 {
        return Err("configured load-per-CPU threshold is not finite and nonnegative");
    }
    Ok(LoadObservation {
        load_avg_1: load,
        threshold,
        cpus: Some(cpus),
    })
}

/// Evaluate all triggers against current metrics. Returns fired triggers.
pub fn evaluate_triggers(
    config: &TriggerConfig,
    state: &mut TriggerState,
    metrics: &TickMetrics,
) -> Vec<FiredTrigger> {
    state.total_ticks = state.total_ticks.saturating_add(1);
    let alpha = sanitize_alpha(config.ewma_alpha);
    let mut fired: Vec<FiredTrigger> = state
        .pressure
        .observe(config, metrics)
        .into_iter()
        .map(|regime| FiredTrigger {
            kind: TriggerKind::PressureRegime,
            description: regime.explanation.clone(),
            current_value: None,
            ewma_value: None,
            threshold: None,
            sustained_ticks: if regime.kind == RegimeKind::OomKills {
                1
            } else {
                config.sustained_ticks.max(1)
            },
            provenance_context: Vec::new(),
            memory_pressure: None,
            pressure_regime: Some(regime),
        })
        .collect();

    // --- Load trigger ---
    let load = match load_observation(config, metrics) {
        Ok(observation) => {
            if state.load_observed_ticks == 0 {
                // Older saved state has no observed-reading counter. Its
                // sustained count may come from the old absolute default and
                // cannot prove a breach of the capacity-aware threshold.
                state.load_sustained = 0;
            }
            state.load_unavailable_reason = None;
            state.load_observed_ticks = state.load_observed_ticks.saturating_add(1);
            state.load_ewma = ewma(
                state.load_ewma,
                observation.load_avg_1,
                alpha,
                state.load_observed_ticks,
            );
            Some(observation)
        }
        Err(reason) => {
            state.load_unavailable_reason = Some(reason.to_string());
            // Unknown readings break the proof of a sustained breach. Retain
            // the last observed EWMA; missing evidence is not observed recovery.
            state.load_sustained = 0;
            None
        }
    };

    if state.load_cooldown > 0 {
        state.load_cooldown -= 1;
        state.load_sustained = 0;
    } else if config.pressure_regimes.enabled
        && config.pressure_regimes.valid()
        && config.load_threshold.is_none()
        && state.pressure.last_assessment.is_some()
        && metrics
            .pressure
            .as_ref()
            .is_some_and(|reading| psi_evidence_available(reading.cpu))
    {
        // PSI distinguishes contention from high load caused by blocked work.
        // Explicit absolute-load settings remain honored as separate operator intent.
        state.load_sustained = 0;
    } else if let Some(load) = load {
        if load.load_avg_1 > load.threshold {
            state.load_sustained = state.load_sustained.saturating_add(1);
            if state.load_sustained >= config.sustained_ticks {
                let description = match load.cpus {
                    Some(cpus) => format!(
                        "load_avg_1={:.2} / online_cpus={cpus} = {:.2} > per_cpu_threshold={:.2} (load threshold={:.2}) for {} ticks",
                        load.load_avg_1,
                        load.load_avg_1 / f64::from(cpus),
                        config.load_per_cpu_threshold,
                        load.threshold,
                        state.load_sustained,
                    ),
                    None => format!(
                        "load_avg_1={:.2} > absolute threshold={:.2} for {} ticks",
                        load.load_avg_1, load.threshold, state.load_sustained,
                    ),
                };
                fired.push(FiredTrigger {
                    kind: TriggerKind::SustainedLoad,
                    description,
                    current_value: Some(load.load_avg_1),
                    ewma_value: Some(state.load_ewma),
                    threshold: Some(load.threshold),
                    sustained_ticks: state.load_sustained,
                    provenance_context: Vec::new(),
                    memory_pressure: None,
                    pressure_regime: None,
                });
                state.load_cooldown = config.cooldown_ticks;
                state.load_sustained = 0;
            }
        } else {
            state.load_sustained = 0;
        }
    }

    // --- Memory trigger ---
    let mem_frac = if metrics.memory_total_mb > 0 {
        metrics.memory_used_mb as f64 / metrics.memory_total_mb as f64
    } else {
        0.0
    };
    state.memory_ewma = ewma(state.memory_ewma, mem_frac, alpha, state.total_ticks);

    if state.memory_cooldown > 0 {
        state.memory_cooldown -= 1;
        state.memory_sustained = 0;
    } else if mem_frac > config.memory_threshold {
        state.memory_sustained += 1;
        if state.memory_sustained >= config.sustained_ticks {
            fired.push(FiredTrigger {
                kind: TriggerKind::MemoryPressure,
                description: format!(
                    "memory={:.1}% > threshold={:.1}% for {} ticks",
                    mem_frac * 100.0,
                    config.memory_threshold * 100.0,
                    state.memory_sustained,
                ),
                current_value: Some(mem_frac),
                ewma_value: Some(state.memory_ewma),
                threshold: Some(config.memory_threshold),
                sustained_ticks: state.memory_sustained,
                provenance_context: Vec::new(),
                memory_pressure: None,
                pressure_regime: None,
            });
            state.memory_cooldown = config.cooldown_ticks;
            state.memory_sustained = 0;
        }
    } else {
        state.memory_sustained = 0;
    }

    // --- Orphan trigger ---
    let orphan_f = metrics.orphan_count as f64;
    state.orphan_ewma = ewma(state.orphan_ewma, orphan_f, alpha, state.total_ticks);

    if state.orphan_cooldown > 0 {
        state.orphan_cooldown -= 1;
        state.orphan_sustained = 0;
    } else if metrics.orphan_count > config.orphan_threshold {
        state.orphan_sustained += 1;
        if state.orphan_sustained >= config.sustained_ticks {
            fired.push(FiredTrigger {
                kind: TriggerKind::OrphanSpike,
                description: format!(
                    "orphans={} > threshold={} for {} ticks",
                    metrics.orphan_count, config.orphan_threshold, state.orphan_sustained,
                ),
                current_value: Some(orphan_f),
                ewma_value: Some(state.orphan_ewma),
                threshold: Some(config.orphan_threshold as f64),
                sustained_ticks: state.orphan_sustained,
                provenance_context: Vec::new(),
                memory_pressure: None,
                pressure_regime: None,
            });
            state.orphan_cooldown = config.cooldown_ticks;
            state.orphan_sustained = 0;
        }
    } else {
        state.orphan_sustained = 0;
    }

    fired
}

/// EWMA update. On the first tick, initialize directly to the value.
fn ewma(prev: f64, value: f64, alpha: f64, tick: u64) -> f64 {
    if tick <= 1 {
        value
    } else {
        alpha * value + (1.0 - alpha) * prev
    }
}

fn sanitize_alpha(alpha: f64) -> f64 {
    if alpha.is_finite() {
        alpha.clamp(0.0, 1.0)
    } else {
        TriggerConfig::default().ewma_alpha
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::pressure::{LoadAvg, PressureSnapshot};
    use chrono::Utc;

    fn pressure(load: f64, cpus: u32) -> PressureSnapshot {
        PressureSnapshot {
            sampled_at_ms: 1_000,
            cpus,
            cpu: None,
            memory: None,
            io: None,
            irq: None,
            load: Some(LoadAvg {
                one: load,
                five: load * 0.8,
                fifteen: load * 0.5,
                runnable: Some(1),
                total: Some(200),
            }),
            meminfo: None,
            vmstat: None,
            file_handles: None,
            unavailable: Vec::new(),
        }
    }

    fn metrics(load: f64, mem_used: u64, mem_total: u64, orphans: u32) -> TickMetrics {
        TickMetrics {
            timestamp: Utc::now().to_rfc3339(),
            load_avg_1: load,
            load_avg_5: load * 0.8,
            memory_used_mb: mem_used,
            memory_total_mb: mem_total,
            swap_used_mb: 0,
            process_count: 200,
            orphan_count: orphans,
            pressure: Some(pressure(load, 2)),
            pressure_observed_at: None,
        }
    }

    fn cfg(sustained: u32, cooldown: u32) -> TriggerConfig {
        TriggerConfig {
            sustained_ticks: sustained,
            cooldown_ticks: cooldown,
            ..Default::default()
        }
    }

    fn cpu_reading(start: Instant, tick: u64, average: f64, total_us: u64) -> TickMetrics {
        use crate::collect::pressure::{PsiLine, PsiResource};
        let mut reading = metrics(1.0, 2000, 8192, 0);
        reading.pressure_observed_at = Some(start + std::time::Duration::from_secs(tick));
        let snapshot = reading.pressure.as_mut().unwrap();
        snapshot.sampled_at_ms = 1_000 + tick * 1_000;
        snapshot.cpu = Some(PsiResource {
            some: Some(PsiLine {
                avg10: average,
                avg60: average,
                avg300: average,
                total_us,
            }),
            full: None,
        });
        reading
    }

    #[test]
    fn pressure_episodes_require_fresh_evidence_and_observed_recovery() {
        let mut config = cfg(3, 0);
        config.pressure_regimes.exit_after_ticks = 2;
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        for tick in 0..2 {
            assert!(evaluate_triggers(
                &config,
                &mut state,
                &cpu_reading(start, tick, 40.0, tick * 400_000)
            )
            .is_empty());
        }
        let mut missing = cpu_reading(start, 2, 0.0, 0);
        missing.pressure = None;
        assert!(evaluate_triggers(&config, &mut state, &missing).is_empty());
        for tick in 3..5 {
            assert!(evaluate_triggers(
                &config,
                &mut state,
                &cpu_reading(start, tick, 40.0, tick * 400_000)
            )
            .is_empty());
        }
        let fired = evaluate_triggers(&config, &mut state, &cpu_reading(start, 5, 40.0, 2_000_000));
        assert_eq!(fired.len(), 1);
        assert_eq!(
            fired[0].pressure_regime.as_ref().unwrap().kind,
            RegimeKind::CpuContention
        );
        assert_eq!(fired[0].current_value, None);
        assert_eq!(fired[0].ewma_value, None);
        state.pressure.acknowledge(&fired);
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 6, 40.0, 2_400_000))
                .is_empty()
        );
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 7, 0.0, 2_400_000))
                .is_empty()
        );
        assert!(state
            .pressure
            .active
            .contains_key(&RegimeKind::CpuContention));
        evaluate_triggers(&config, &mut state, &missing);
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 8, 0.0, 2_400_000))
                .is_empty()
        );
        assert!(
            state
                .pressure
                .active
                .contains_key(&RegimeKind::CpuContention),
            "missing readings break recovery"
        );
        evaluate_triggers(&config, &mut state, &cpu_reading(start, 9, 0.0, 2_400_000));
        assert!(!state
            .pressure
            .active
            .contains_key(&RegimeKind::CpuContention));
        for tick in 10..12 {
            assert!(evaluate_triggers(
                &config,
                &mut state,
                &cpu_reading(start, tick, 40.0, 2_400_000 + (tick - 9) * 400_000)
            )
            .is_empty());
        }
        assert_eq!(
            evaluate_triggers(
                &config,
                &mut state,
                &cpu_reading(start, 12, 40.0, 3_600_000)
            )
            .len(),
            1
        );
    }

    #[test]
    fn pressure_delivery_retries_survive_restart_and_severity_increases() {
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        let warning = evaluate_triggers(&config, &mut state, &cpu_reading(start, 0, 15.0, 0));
        assert_eq!(
            warning[0].pressure_regime.as_ref().unwrap().severity,
            Severity::Warn
        );
        let json = serde_json::to_string(&state).unwrap();
        let mut state: TriggerState = serde_json::from_str(&json).unwrap();
        state.pressure.interrupt_observations();
        let retried = evaluate_triggers(&config, &mut state, &cpu_reading(start, 1, 15.0, 150_000));
        assert_eq!(
            retried.len(),
            1,
            "unacknowledged delivery remains due after restart"
        );
        state.pressure.acknowledge(&retried);
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 2, 15.0, 300_000))
                .is_empty()
        );
        let critical =
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 3, 40.0, 700_000));
        assert_eq!(
            critical[0].pressure_regime.as_ref().unwrap().severity,
            Severity::Crit
        );
        state.pressure.acknowledge(&critical);
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 4, 15.0, 850_000))
                .is_empty(),
            "a delivered critical episode does not repeat when it improves to warning"
        );
    }

    #[test]
    fn deferred_critical_upgrade_must_still_be_observed_at_delivery() {
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        let warning = evaluate_triggers(&config, &mut state, &cpu_reading(start, 0, 15.0, 0));
        state.pressure.acknowledge(&warning);
        let deferred =
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 1, 40.0, 400_000));
        assert_eq!(
            deferred[0].pressure_regime.as_ref().unwrap().severity,
            Severity::Crit
        );
        assert!(
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 2, 15.0, 550_000))
                .is_empty()
        );
        assert!(!state
            .pressure
            .pending
            .contains_key(&RegimeKind::CpuContention));
        let observed_again =
            evaluate_triggers(&config, &mut state, &cpu_reading(start, 3, 40.0, 950_000));
        assert_eq!(
            observed_again[0].pressure_regime.as_ref().unwrap().severity,
            Severity::Crit
        );
    }

    #[test]
    fn io_pressure_with_quiet_cpu_does_not_trigger_default_load_alarm() {
        use crate::collect::pressure::{PsiLine, PsiResource};
        let config = cfg(2, 0);
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        let mut last = None;
        for tick in 0..2 {
            let mut reading = cpu_reading(start, tick, 0.0, 0);
            let snapshot = reading.pressure.as_mut().unwrap();
            snapshot.load.as_mut().unwrap().one = 100.0;
            snapshot.io = Some(PsiResource {
                some: Some(PsiLine {
                    avg10: 20.0,
                    avg60: 20.0,
                    avg300: 20.0,
                    total_us: tick * 200_000,
                }),
                full: None,
            });
            let fired = evaluate_triggers(&config, &mut state, &reading);
            if tick == 0 {
                assert!(fired.is_empty());
            }
            last = Some(fired);
        }
        let fired = last.unwrap();
        assert_eq!(fired.len(), 1);
        assert_eq!(
            fired[0].pressure_regime.as_ref().unwrap().kind,
            RegimeKind::IoBound
        );
        assert!(fired[0].description.contains("waiting on I/O"));
    }

    #[test]
    fn swap_rate_resets_and_missing_counters_do_not_imply_recovery() {
        use crate::collect::pressure::VmStat;
        let mut config = cfg(2, 0);
        config.pressure_regimes.exit_after_ticks = 2;
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        let reading = |tick: u64, pages: Option<u64>| {
            let mut reading = cpu_reading(start, tick, 0.0, 0);
            reading.pressure.as_mut().unwrap().vmstat = Some(VmStat {
                pswpin: pages,
                pswpout: pages,
                ..Default::default()
            });
            reading
        };
        assert!(evaluate_triggers(&config, &mut state, &reading(0, Some(0))).is_empty());
        assert!(evaluate_triggers(&config, &mut state, &reading(1, Some(6_000))).is_empty());
        let fired = evaluate_triggers(&config, &mut state, &reading(2, Some(12_000)));
        assert_eq!(
            fired[0].pressure_regime.as_ref().unwrap().kind,
            RegimeKind::SwapThrash
        );
        state.pressure.acknowledge(&fired);
        for (tick, pages) in [(3, Some(0)), (4, None), (5, Some(0)), (6, Some(0))] {
            assert!(evaluate_triggers(&config, &mut state, &reading(tick, pages)).is_empty());
            assert!(state.pressure.active.contains_key(&RegimeKind::SwapThrash));
        }
        evaluate_triggers(&config, &mut state, &reading(7, Some(0)));
        assert!(!state.pressure.active.contains_key(&RegimeKind::SwapThrash));
    }

    #[test]
    fn oom_counter_increment_is_a_durable_incident_until_delivered() {
        use crate::collect::pressure::VmStat;
        let config = cfg(3, 0);
        let mut state = TriggerState::new(&config);
        let start = Instant::now();
        let reading = |tick: u64, count: u64| {
            let mut reading = cpu_reading(start, tick, 0.0, 0);
            reading.pressure.as_mut().unwrap().vmstat = Some(VmStat {
                oom_kill: Some(count),
                ..Default::default()
            });
            reading
        };
        assert!(evaluate_triggers(&config, &mut state, &reading(0, 10)).is_empty());
        let incident = evaluate_triggers(&config, &mut state, &reading(1, 11));
        assert_eq!(incident.len(), 1);
        assert_eq!(
            incident[0].pressure_regime.as_ref().unwrap().kind,
            RegimeKind::OomKills
        );
        assert_eq!(
            incident[0].pressure_regime.as_ref().unwrap().severity,
            Severity::Crit
        );
        assert_eq!(incident[0].sustained_ticks, 1);
        let mut missing = reading(2, 11);
        missing.pressure = None;
        let retry = evaluate_triggers(&config, &mut state, &missing);
        assert_eq!(
            retry.len(),
            1,
            "a later sensor outage does not erase a known OOM incident"
        );
        state.pressure.acknowledge(&retry);
        assert!(evaluate_triggers(&config, &mut state, &reading(3, 11)).is_empty());
        assert!(evaluate_triggers(&config, &mut state, &reading(4, 11)).is_empty());
        assert!(
            evaluate_triggers(&config, &mut state, &reading(5, 0)).is_empty(),
            "counter reset is not an OOM event"
        );
    }

    #[test]
    fn fd_and_memory_regimes_preserve_their_diagnostic_kind() {
        use crate::collect::pressure::{FileHandles, MemInfo};
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);
        let mut reading = cpu_reading(Instant::now(), 0, 25.0, 0);
        let snapshot = reading.pressure.as_mut().unwrap();
        snapshot.memory = snapshot.cpu.take();
        snapshot.meminfo = Some(MemInfo {
            total: Some(1000),
            available: Some(750),
            ..Default::default()
        });
        snapshot.file_handles = Some(FileHandles {
            allocated: 96,
            max: 100,
        });
        let fired = evaluate_triggers(&config, &mut state, &reading);
        let kinds: Vec<_> = fired
            .iter()
            .filter_map(|trigger| trigger.pressure_regime.as_ref().map(|regime| regime.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![RegimeKind::CacheBloat, RegimeKind::FdExhaustion]
        );
        assert!(!kinds.contains(&RegimeKind::MemoryExhaustion));
    }

    #[test]
    fn invalid_or_replayed_samples_cannot_confirm_pressure() {
        let config = cfg(2, 0);
        let start = Instant::now();
        let mut state = TriggerState::new(&config);
        let reading = cpu_reading(start, 0, 40.0, 0);
        assert!(evaluate_triggers(&config, &mut state, &reading).is_empty());
        assert!(evaluate_triggers(&config, &mut state, &reading).is_empty());
        assert!(state
            .pressure
            .unavailable_reason
            .as_ref()
            .unwrap()
            .contains("monotonically"));
        let mut no_clock: TickMetrics =
            serde_json::from_str(&serde_json::to_string(&reading).unwrap()).unwrap();
        assert!(evaluate_triggers(&config, &mut state, &no_clock).is_empty());
        assert!(state.pressure.active.is_empty());
        // Invalid rich evidence leaves the established load fallback available.
        no_clock
            .pressure
            .as_mut()
            .unwrap()
            .load
            .as_mut()
            .unwrap()
            .one = 100.0;
        let immediate = cfg(1, 0);
        let fired = evaluate_triggers(&immediate, &mut state, &no_clock);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, TriggerKind::SustainedLoad);
        let mut invalid = immediate.clone();
        invalid.pressure_regimes.thresholds.cpu_psi.crit = f64::NAN;
        assert!(evaluate_triggers(&invalid, &mut state, &reading).is_empty());
        assert_eq!(
            state.pressure.unavailable_reason.as_deref(),
            Some("invalid pressure-regime thresholds")
        );
    }

    #[test]
    fn default_load_trigger_scales_to_observed_cpu_capacity() {
        let config = cfg(3, 10);
        let mut small_state = TriggerState::new(&config);
        let mut large_state = TriggerState::new(&config);
        let small = metrics(10.0, 2000, 8192, 0);
        let mut large = small.clone();
        large.pressure.as_mut().unwrap().cpus = 64;

        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut small_state, &small).is_empty());
            assert!(evaluate_triggers(&config, &mut large_state, &large).is_empty());
        }
        let small_fired = evaluate_triggers(&config, &mut small_state, &small);
        assert_eq!(small_fired.len(), 1);
        assert_eq!(small_fired[0].kind, TriggerKind::SustainedLoad);
        assert_eq!(small_fired[0].current_value, Some(10.0));
        assert_eq!(small_fired[0].threshold, Some(4.0));
        assert!(small_fired[0].description.contains("online_cpus=2"));
        assert!(small_fired[0].description.contains("= 5.00 >"));
        assert!(evaluate_triggers(&config, &mut large_state, &large).is_empty());
        assert_eq!(large_state.load_sustained, 0);

        large.pressure.as_mut().unwrap().load.as_mut().unwrap().one = 130.0;
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut large_state, &large).is_empty());
        }
        let large_fired = evaluate_triggers(&config, &mut large_state, &large);
        assert_eq!(large_fired.len(), 1);
        assert_eq!(large_fired[0].current_value, Some(130.0));
        assert_eq!(large_fired[0].threshold, Some(128.0));
        assert!(large_fired[0].description.contains("online_cpus=64"));
    }

    #[test]
    fn configured_absolute_load_threshold_keeps_legacy_semantics() {
        let config: TriggerConfig = serde_json::from_value(serde_json::json!({
            "ewma_alpha": 0.3,
            "load_threshold": 4.0,
            "memory_threshold": 0.85,
            "orphan_threshold": 20,
            "sustained_ticks": 1,
            "cooldown_ticks": 0
        }))
        .unwrap();
        assert_eq!(config.load_threshold, Some(4.0));
        let mut state = TriggerState::new(&config);
        let mut m = metrics(5.0, 2000, 8192, 0);
        m.pressure.as_mut().unwrap().cpus = 64;
        let fired = evaluate_triggers(&config, &mut state, &m);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].threshold, Some(4.0));
        assert!(fired[0].description.contains("absolute threshold=4.00"));

        // An explicit absolute threshold does not require a CPU observation.
        m.pressure = None;
        assert_eq!(evaluate_triggers(&config, &mut state, &m).len(), 1);
        m.load_avg_1 = 4.0;
        assert!(evaluate_triggers(&config, &mut state, &m).is_empty());

        let always = TriggerConfig {
            load_threshold: Some(-1.0),
            ..config
        };
        m.load_avg_1 = 0.0;
        assert_eq!(evaluate_triggers(&always, &mut state, &m).len(), 1);
    }

    #[test]
    fn configured_per_cpu_threshold_uses_each_ticks_capacity() {
        let config: TriggerConfig = serde_json::from_value(serde_json::json!({
            "load_per_cpu_threshold": 1.5,
            "sustained_ticks": 1,
            "cooldown_ticks": 0
        }))
        .unwrap();
        assert_eq!(config.load_threshold, None);
        let mut state = TriggerState::new(&config);
        let at_threshold = metrics(3.0, 2000, 8192, 0);
        assert!(evaluate_triggers(&config, &mut state, &at_threshold).is_empty());
        let mut over = metrics(3.1, 2000, 8192, 0);
        let fired = evaluate_triggers(&config, &mut state, &over);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].threshold, Some(3.0));
        over.pressure.as_mut().unwrap().cpus = 4;
        assert!(evaluate_triggers(&config, &mut state, &over).is_empty());

        // Absolute configuration wins even if a per-CPU threshold is also set.
        let absolute = TriggerConfig {
            load_threshold: Some(100.0),
            ..config
        };
        over.pressure.as_mut().unwrap().cpus = 1;
        assert!(evaluate_triggers(&absolute, &mut state, &over).is_empty());
    }

    #[test]
    fn unknown_or_invalid_observations_never_invent_load_or_capacity() {
        let config = cfg(1, 0);
        let mut cases = vec![None, Some(pressure(100.0, 0))];
        let mut no_load = pressure(100.0, 2);
        no_load.load = None;
        cases.push(Some(no_load));
        for invalid in [f64::NAN, f64::INFINITY, -1.0] {
            cases.push(Some(pressure(invalid, 2)));
        }
        for reading in cases {
            let mut state = TriggerState::new(&config);
            let mut m = metrics(1000.0, 2000, 8192, 0);
            m.pressure = reading;
            assert!(evaluate_triggers(&config, &mut state, &m).is_empty());
            assert!(state.load_unavailable_reason.is_some());
            assert_eq!(state.load_observed_ticks, 0);
            assert_eq!(state.load_sustained, 0);

            // First valid sample initializes the EWMA directly, even after a
            // missing/invalid tick. The stale scalar must not substitute for it.
            m.pressure = Some(pressure(3.0, 2));
            assert!(evaluate_triggers(&config, &mut state, &m).is_empty());
            assert_eq!(state.load_ewma, 3.0);
            assert_eq!(state.load_observed_ticks, 1);
            assert!(state.load_unavailable_reason.is_none());
        }
    }

    #[test]
    fn actual_load_reading_controls_both_relative_and_absolute_triggers() {
        for absolute in [None, Some(4.0)] {
            let config = TriggerConfig {
                load_threshold: absolute,
                ..cfg(1, 0)
            };
            let mut state = TriggerState::new(&config);
            let mut m = metrics(1000.0, 2000, 8192, 0);
            m.pressure = Some(pressure(1.0, 2));
            assert!(evaluate_triggers(&config, &mut state, &m).is_empty());
            assert_eq!(state.load_ewma, 1.0);

            m.load_avg_1 = 0.0;
            m.pressure.as_mut().unwrap().load.as_mut().unwrap().one = 10.0;
            let fired = evaluate_triggers(&config, &mut state, &m);
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0].current_value, Some(10.0));

            m.pressure.as_mut().unwrap().load = None;
            assert!(evaluate_triggers(&config, &mut state, &m).is_empty());
            assert!(state.load_unavailable_reason.is_some());
        }
    }

    #[test]
    fn missing_load_breaks_sustained_evidence_and_preserves_valid_ewma() {
        let config = cfg(3, 2);
        let mut state = TriggerState::new(&config);
        let high = metrics(10.0, 2000, 8192, 0);
        let mut missing = high.clone();
        missing.pressure = None;
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut state, &high).is_empty());
        }
        assert_eq!(state.load_sustained, 2);
        assert!(evaluate_triggers(&config, &mut state, &missing).is_empty());
        assert_eq!(state.load_sustained, 0);
        assert_eq!(state.load_ewma, 10.0);
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut state, &high).is_empty());
        }
        assert_eq!(evaluate_triggers(&config, &mut state, &high).len(), 1);
        assert_eq!(state.load_cooldown, 2);
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut state, &missing).is_empty());
        }
        assert_eq!(state.load_cooldown, 0);
        assert_eq!(state.load_sustained, 0);
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut state, &high).is_empty());
        }
        assert_eq!(evaluate_triggers(&config, &mut state, &high).len(), 1);
    }

    #[test]
    fn legacy_load_state_requires_a_new_sustained_window_and_keeps_cooldown() {
        let config = cfg(3, 2);
        let mut high = metrics(130.0, 2000, 8192, 0);
        high.pressure.as_mut().unwrap().cpus = 64;

        for cooldown in [0, 2] {
            // This is the saved format before load_observed_ticks existed:
            // load 10 breached the old default of 4 on a 64-CPU host, but not
            // the new default of 128. Those two breaches must not carry over.
            let mut state: TriggerState = serde_json::from_value(serde_json::json!({
                "load_ewma": 10.0,
                "memory_ewma": 0.25,
                "orphan_ewma": 0.0,
                "load_sustained": 2,
                "memory_sustained": 0,
                "orphan_sustained": 0,
                "load_cooldown": cooldown,
                "memory_cooldown": 0,
                "orphan_cooldown": 0,
                "total_ticks": 2
            }))
            .unwrap();
            assert_eq!(state.load_observed_ticks, 0);
            assert_eq!(state.load_sustained, 2);

            for remaining in (0..cooldown).rev() {
                assert!(evaluate_triggers(&config, &mut state, &high).is_empty());
                assert_eq!(state.load_cooldown, remaining);
                assert_eq!(state.load_sustained, 0);
            }
            for observed in 1..3 {
                assert!(evaluate_triggers(&config, &mut state, &high).is_empty());
                assert_eq!(state.load_sustained, observed);
            }
            let fired = evaluate_triggers(&config, &mut state, &high);
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0].kind, TriggerKind::SustainedLoad);
            assert_eq!(fired[0].threshold, Some(128.0));
            assert_eq!(fired[0].sustained_ticks, 3);
            assert_eq!(state.load_cooldown, config.cooldown_ticks);
        }

        // New-format state does retain its proven observation sequence.
        let mut current = TriggerState::new(&config);
        for _ in 0..2 {
            assert!(evaluate_triggers(&config, &mut current, &high).is_empty());
        }
        let saved = serde_json::to_string(&current).unwrap();
        let mut restored: TriggerState = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.load_observed_ticks, 2);
        assert_eq!(evaluate_triggers(&config, &mut restored, &high).len(), 1);
    }

    #[test]
    fn invalid_load_configuration_is_visible_without_disabling_other_triggers() {
        let mut configurations = Vec::new();
        for invalid in [f64::NAN, f64::INFINITY, -1.0, f64::MAX] {
            configurations.push(TriggerConfig {
                load_per_cpu_threshold: invalid,
                ..cfg(1, 0)
            });
        }
        configurations.push(TriggerConfig {
            load_threshold: Some(f64::INFINITY),
            ..cfg(1, 0)
        });
        for config in configurations {
            let mut state = TriggerState::new(&config);
            let fired = evaluate_triggers(&config, &mut state, &metrics(100.0, 7373, 8192, 0));
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0].kind, TriggerKind::MemoryPressure);
            assert!(state.load_unavailable_reason.is_some());
        }
    }

    #[test]
    fn test_no_trigger_below_threshold() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);
        let m = metrics(1.0, 4000, 8192, 5);
        let fired = evaluate_triggers(&config, &mut state, &m);
        assert!(fired.is_empty());
    }

    #[test]
    fn test_load_trigger_sustained() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);

        // 2 ticks above threshold — not enough.
        for _ in 0..2 {
            let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
            assert!(fired.is_empty());
        }

        // 3rd tick — fires.
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, TriggerKind::SustainedLoad);
    }

    #[test]
    fn test_load_cooldown() {
        let config = cfg(1, 5); // Fire immediately, 5-tick cooldown.
        let mut state = TriggerState::new(&config);

        // First tick — fires.
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert_eq!(fired.len(), 1);

        // Next 5 ticks — cooldown, no firing.
        for _ in 0..5 {
            let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
            assert!(fired.is_empty());
        }

        // After cooldown — fires again.
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_sustained_reset_on_dip() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);

        // 2 above, then 1 below, then 2 above — should not fire.
        evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        evaluate_triggers(&config, &mut state, &metrics(1.0, 2000, 8192, 5)); // Dip
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert!(fired.is_empty());
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert!(fired.is_empty());

        // 3rd consecutive above threshold — fires.
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 2000, 8192, 5));
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_memory_trigger() {
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);

        // 90% usage > 85% threshold.
        let fired = evaluate_triggers(&config, &mut state, &metrics(1.0, 7373, 8192, 5));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, TriggerKind::MemoryPressure);
    }

    #[test]
    fn test_orphan_trigger() {
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);

        let fired = evaluate_triggers(&config, &mut state, &metrics(1.0, 2000, 8192, 50));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, TriggerKind::OrphanSpike);
    }

    #[test]
    fn test_multiple_triggers_fire() {
        let config = cfg(1, 0);
        let mut state = TriggerState::new(&config);

        // High load + high memory + many orphans.
        let fired = evaluate_triggers(&config, &mut state, &metrics(10.0, 7373, 8192, 50));
        assert_eq!(fired.len(), 3);
        let kinds: Vec<_> = fired.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&TriggerKind::SustainedLoad));
        assert!(kinds.contains(&TriggerKind::MemoryPressure));
        assert!(kinds.contains(&TriggerKind::OrphanSpike));
    }

    #[test]
    fn test_ewma_initialization() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);

        evaluate_triggers(&config, &mut state, &metrics(5.0, 4096, 8192, 10));
        assert!((state.load_ewma - 5.0).abs() < 0.01);
        assert!((state.memory_ewma - 0.5).abs() < 0.01);
        assert!((state.orphan_ewma - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_ewma_smoothing() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);

        evaluate_triggers(&config, &mut state, &metrics(10.0, 4096, 8192, 10));
        evaluate_triggers(&config, &mut state, &metrics(2.0, 4096, 8192, 10));

        // EWMA(10, 2, alpha=0.3) = 0.3*2 + 0.7*10 = 7.6
        assert!((state.load_ewma - 7.6).abs() < 0.01);
    }

    #[test]
    fn test_state_serialization() {
        let config = cfg(3, 10);
        let mut state = TriggerState::new(&config);
        evaluate_triggers(&config, &mut state, &metrics(5.0, 4096, 8192, 10));

        let json = serde_json::to_string(&state).unwrap();
        let restored: TriggerState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_ticks, 1);
        assert!((restored.load_ewma - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_invalid_alpha_is_sanitized() {
        let mut config = cfg(10, 0);
        config.ewma_alpha = 2.0;
        let mut state = TriggerState::new(&config);

        evaluate_triggers(&config, &mut state, &metrics(1.0, 4096, 8192, 10));
        evaluate_triggers(&config, &mut state, &metrics(0.0, 4096, 8192, 10));

        assert!(state.load_ewma >= 0.0);
        assert!(state.load_ewma <= 1.0);
    }
}
