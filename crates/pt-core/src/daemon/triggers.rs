//! Trigger detection with EWMA baselines, sustained-window rules, and cooldown.
//!
//! Each trigger type maintains its own EWMA baseline and a counter tracking
//! how many consecutive ticks the signal has exceeded the threshold. A trigger
//! fires only after the threshold is breached for `sustained_ticks` consecutive
//! ticks, preventing flapping.
//!
//! After firing, a cooldown period suppresses re-firing for `cooldown_ticks`.

use serde::{Deserialize, Serialize};

use super::TickMetrics;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Trigger configuration for the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    /// EWMA decay factor (0..1). Higher = more weight to recent values.
    pub ewma_alpha: f64,
    /// Load average (1-min) threshold. Trigger if sustained above this.
    pub load_threshold: f64,
    /// Memory usage fraction threshold (0..1). Trigger at e.g. 0.85 = 85%.
    pub memory_threshold: f64,
    /// Orphan count threshold. Trigger if orphan count sustained above this.
    pub orphan_threshold: u32,
    /// Number of consecutive ticks above threshold before firing.
    pub sustained_ticks: u32,
    /// Number of ticks after firing before the trigger can fire again.
    pub cooldown_ticks: u32,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.3,
            load_threshold: 4.0,
            memory_threshold: 0.85,
            orphan_threshold: 20,
            sustained_ticks: 3,
            cooldown_ticks: 10,
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
}

impl TriggerState {
    pub fn new(_config: &TriggerConfig) -> Self {
        Self {
            load_ewma: 0.0,
            memory_ewma: 0.0,
            orphan_ewma: 0.0,
            load_sustained: 0,
            memory_sustained: 0,
            orphan_sustained: 0,
            load_cooldown: 0,
            memory_cooldown: 0,
            orphan_cooldown: 0,
            total_ticks: 0,
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
}

/// A trigger that has fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredTrigger {
    pub kind: TriggerKind,
    pub description: String,
    pub current_value: f64,
    pub ewma_value: f64,
    pub threshold: f64,
    pub sustained_ticks: u32,
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate all triggers against current metrics. Returns fired triggers.
pub fn evaluate_triggers(
    config: &TriggerConfig,
    state: &mut TriggerState,
    metrics: &TickMetrics,
) -> Vec<FiredTrigger> {
    state.total_ticks += 1;
    let alpha = sanitize_alpha(config.ewma_alpha);
    let mut fired = Vec::new();

    // --- Load trigger ---
    state.load_ewma = ewma(
        state.load_ewma,
        metrics.load_avg_1,
        alpha,
        state.total_ticks,
    );

    if state.load_cooldown > 0 {
        state.load_cooldown -= 1;
        state.load_sustained = 0;
    } else if metrics.load_avg_1 > config.load_threshold {
        state.load_sustained += 1;
        if state.load_sustained >= config.sustained_ticks {
            fired.push(FiredTrigger {
                kind: TriggerKind::SustainedLoad,
                description: format!(
                    "load_avg_1={:.2} > threshold={:.2} for {} ticks",
                    metrics.load_avg_1, config.load_threshold, state.load_sustained,
                ),
                current_value: metrics.load_avg_1,
                ewma_value: state.load_ewma,
                threshold: config.load_threshold,
                sustained_ticks: state.load_sustained,
            });
            state.load_cooldown = config.cooldown_ticks;
            state.load_sustained = 0;
        }
    } else {
        state.load_sustained = 0;
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
                current_value: mem_frac,
                ewma_value: state.memory_ewma,
                threshold: config.memory_threshold,
                sustained_ticks: state.memory_sustained,
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
                current_value: orphan_f,
                ewma_value: state.orphan_ewma,
                threshold: config.orphan_threshold as f64,
                sustained_ticks: state.orphan_sustained,
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
    use chrono::Utc;

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
        }
    }

    fn cfg(sustained: u32, cooldown: u32) -> TriggerConfig {
        TriggerConfig {
            sustained_ticks: sustained,
            cooldown_ticks: cooldown,
            ..Default::default()
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
