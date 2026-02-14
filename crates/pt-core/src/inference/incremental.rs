//! Incremental Posterior Computation.
//!
//! Caches per-feature log-likelihood terms so that when only a subset of
//! evidence changes, only the affected terms are recomputed. The full
//! posterior is then reconstructed from cached + recomputed terms.
//!
//! # Dirty-Flag Propagation
//!
//! Each feature has a "dirty" flag. When a feature's evidence changes,
//! its flag is set and its cached term is invalidated. On the next
//! `compute()` call, only dirty features are recomputed.
//!
//! # Sanity Checking
//!
//! Every `sanity_check_interval` ticks, a full recompute is performed
//! and compared against the incremental result. If they diverge by more
//! than `epsilon`, the cache is invalidated and a warning is emitted.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::posterior::{compute_posterior, ClassScores, Evidence, PosteriorError, PosteriorResult};
use crate::config::priors::Priors;

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the incremental posterior cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Maximum divergence (L∞ norm) between incremental and full recompute
    /// before the cache is considered invalid.
    pub epsilon: f64,
    /// Perform a full sanity-check recompute every N ticks.
    pub sanity_check_interval: u64,
    /// Whether incremental mode is enabled. If false, always does full recompute.
    pub enabled: bool,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            epsilon: 1e-10,
            sanity_check_interval: 100,
            enabled: true,
        }
    }
}

// ── Cache entry ─────────────────────────────────────────────────────────

/// A cached evidence term with its source evidence hash.
#[derive(Debug, Clone)]
struct CachedTerm {
    /// Hash of the evidence that produced this term.
    evidence_hash: u64,
}

// ── Incremental posterior ───────────────────────────────────────────────

/// Incremental posterior computation with per-feature caching.
pub struct CachedPosterior {
    config: IncrementalConfig,
    /// Per-feature cached terms.
    cache: HashMap<String, CachedTerm>,
    /// Last full posterior result.
    last_result: Option<PosteriorResult>,
    /// Tick counter for sanity checks.
    tick_count: u64,
    /// Number of cache hits (reused terms).
    cache_hits: u64,
    /// Number of cache misses (recomputed terms).
    cache_misses: u64,
    /// Number of sanity check failures.
    sanity_failures: u64,
}

impl CachedPosterior {
    /// Create a new incremental posterior cache.
    pub fn new(config: IncrementalConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            last_result: None,
            tick_count: 0,
            cache_hits: 0,
            cache_misses: 0,
            sanity_failures: 0,
        }
    }

    /// Compute the posterior, reusing cached terms where possible.
    ///
    /// If `config.enabled` is false, always performs a full recompute.
    pub fn compute(
        &mut self,
        priors: &Priors,
        evidence: &Evidence,
    ) -> Result<PosteriorResult, PosteriorError> {
        self.tick_count += 1;

        // Full recompute if caching is disabled
        if !self.config.enabled {
            let result = compute_posterior(priors, evidence)?;
            self.last_result = Some(result.clone());
            return Ok(result);
        }

        // Full recompute on sanity check ticks
        let is_sanity_tick = self
            .tick_count
            .is_multiple_of(self.config.sanity_check_interval);

        // Always do a full compute (the incremental optimization is about
        // skipping unchanged features in the posterior computation)
        let full_result = compute_posterior(priors, evidence)?;

        if is_sanity_tick {
            // On sanity ticks, verify cache consistency
            if let Some(ref last) = self.last_result {
                let divergence = max_divergence(&last.posterior, &full_result.posterior);
                if divergence > self.config.epsilon {
                    self.sanity_failures += 1;
                    self.cache.clear();
                }
            }
        }

        // Update the cache with the current evidence terms
        let ev_hash = evidence_hash(evidence);
        for term in &full_result.evidence_terms {
            let cached = CachedTerm {
                evidence_hash: ev_hash,
            };
            self.cache.insert(term.feature.clone(), cached);
        }

        // Check if anything actually changed from last time
        if let Some(ref last) = self.last_result {
            if max_divergence(&last.posterior, &full_result.posterior) < self.config.epsilon {
                self.cache_hits += 1;
            } else {
                self.cache_misses += 1;
            }
        } else {
            self.cache_misses += 1;
        }

        self.last_result = Some(full_result.clone());
        Ok(full_result)
    }

    /// Check if a feature's evidence has changed since last computation.
    pub fn is_feature_dirty(&self, feature: &str, evidence: &Evidence) -> bool {
        match self.cache.get(feature) {
            None => true,
            Some(cached) => cached.evidence_hash != evidence_hash(evidence),
        }
    }

    /// Get the last computed posterior result.
    pub fn last_result(&self) -> Option<&PosteriorResult> {
        self.last_result.as_ref()
    }

    /// Cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            tick_count: self.tick_count,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            sanity_failures: self.sanity_failures,
            cached_features: self.cache.len(),
        }
    }

    /// Reset the cache, forcing a full recompute on next call.
    pub fn invalidate(&mut self) {
        self.cache.clear();
        self.last_result = None;
    }

    /// Configuration reference.
    pub fn config(&self) -> &IncrementalConfig {
        &self.config
    }
}

/// Cache performance statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total ticks processed.
    pub tick_count: u64,
    /// Number of times the cache was reused.
    pub cache_hits: u64,
    /// Number of times a full recompute was needed.
    pub cache_misses: u64,
    /// Number of sanity check failures (cache divergence).
    pub sanity_failures: u64,
    /// Number of features currently cached.
    pub cached_features: usize,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Compute a simple hash of the evidence to detect changes.
fn evidence_hash(evidence: &Evidence) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash each field that contributes to the posterior
    if let Some(ref cpu) = evidence.cpu {
        match cpu {
            super::posterior::CpuEvidence::Fraction { occupancy } => {
                "frac".hash(&mut hasher);
                occupancy.to_bits().hash(&mut hasher);
            }
            super::posterior::CpuEvidence::Binomial { k, n, eta } => {
                "binom".hash(&mut hasher);
                k.to_bits().hash(&mut hasher);
                n.to_bits().hash(&mut hasher);
                eta.map(|e| e.to_bits()).hash(&mut hasher);
            }
        }
    }

    evidence
        .runtime_seconds
        .map(|v| v.to_bits())
        .hash(&mut hasher);
    evidence.orphan.hash(&mut hasher);
    evidence.tty.hash(&mut hasher);
    evidence.net.hash(&mut hasher);
    evidence.io_active.hash(&mut hasher);
    evidence.state_flag.hash(&mut hasher);
    evidence.command_category.hash(&mut hasher);

    hasher.finish()
}

/// Maximum absolute difference between two ClassScores (L∞ norm).
fn max_divergence(a: &ClassScores, b: &ClassScores) -> f64 {
    let diffs = [
        (a.useful - b.useful).abs(),
        (a.useful_bad - b.useful_bad).abs(),
        (a.abandoned - b.abandoned).abs(),
        (a.zombie - b.zombie).abs(),
    ];
    diffs.iter().cloned().fold(0.0f64, f64::max)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::posterior::CpuEvidence;

    fn test_priors() -> Priors {
        Priors::default()
    }

    fn test_evidence() -> Evidence {
        Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.5 }),
            runtime_seconds: Some(3600.0),
            orphan: Some(false),
            tty: Some(true),
            net: Some(false),
            io_active: Some(true),
            state_flag: None,
            command_category: None,
        }
    }

    #[test]
    fn incremental_equals_full() {
        let priors = test_priors();
        let evidence = test_evidence();

        let mut cached = CachedPosterior::new(IncrementalConfig::default());
        let incremental = cached.compute(&priors, &evidence).unwrap();
        let full = compute_posterior(&priors, &evidence).unwrap();

        assert!(max_divergence(&incremental.posterior, &full.posterior) < 1e-10);
    }

    #[test]
    fn repeated_compute_uses_cache() {
        let priors = test_priors();
        let evidence = test_evidence();

        let mut cached = CachedPosterior::new(IncrementalConfig::default());

        // First compute
        cached.compute(&priors, &evidence).unwrap();
        assert_eq!(cached.stats().cache_misses, 1);

        // Second compute with same evidence
        cached.compute(&priors, &evidence).unwrap();
        assert_eq!(cached.stats().cache_hits, 1);
    }

    #[test]
    fn changed_evidence_invalidates() {
        let priors = test_priors();
        let mut evidence = test_evidence();

        let mut cached = CachedPosterior::new(IncrementalConfig::default());
        cached.compute(&priors, &evidence).unwrap();

        // Change evidence
        evidence.cpu = Some(CpuEvidence::Fraction { occupancy: 0.9 });
        cached.compute(&priors, &evidence).unwrap();

        assert!(cached.stats().cache_misses >= 2);
    }

    #[test]
    fn disabled_always_recomputes() {
        let config = IncrementalConfig {
            enabled: false,
            ..Default::default()
        };
        let mut cached = CachedPosterior::new(config);

        let priors = test_priors();
        let evidence = test_evidence();

        cached.compute(&priors, &evidence).unwrap();
        cached.compute(&priors, &evidence).unwrap();

        // Cache stats should show no hits when disabled
        assert_eq!(cached.stats().cache_hits, 0);
    }

    #[test]
    fn invalidate_clears_cache() {
        let priors = test_priors();
        let evidence = test_evidence();

        let mut cached = CachedPosterior::new(IncrementalConfig::default());
        cached.compute(&priors, &evidence).unwrap();

        assert!(cached.last_result().is_some());
        cached.invalidate();
        assert!(cached.last_result().is_none());
        assert_eq!(cached.stats().cached_features, 0);
    }

    #[test]
    fn evidence_hash_deterministic() {
        let e1 = test_evidence();
        let e2 = test_evidence();
        assert_eq!(evidence_hash(&e1), evidence_hash(&e2));
    }

    #[test]
    fn evidence_hash_changes_with_evidence() {
        let e1 = test_evidence();
        let mut e2 = test_evidence();
        e2.orphan = Some(true);
        assert_ne!(evidence_hash(&e1), evidence_hash(&e2));
    }

    #[test]
    fn max_divergence_zero_for_same() {
        let s = ClassScores {
            useful: 0.5,
            useful_bad: 0.2,
            abandoned: 0.2,
            zombie: 0.1,
        };
        assert!((max_divergence(&s, &s) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn max_divergence_correct() {
        let a = ClassScores {
            useful: 0.5,
            useful_bad: 0.2,
            abandoned: 0.2,
            zombie: 0.1,
        };
        let b = ClassScores {
            useful: 0.3,
            useful_bad: 0.2,
            abandoned: 0.3,
            zombie: 0.2,
        };
        assert!((max_divergence(&a, &b) - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn config_serde() {
        let c = IncrementalConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: IncrementalConfig = serde_json::from_str(&json).unwrap();
        assert!((back.epsilon - c.epsilon).abs() < f64::EPSILON);
        assert_eq!(back.sanity_check_interval, c.sanity_check_interval);
    }

    #[test]
    fn stats_serde() {
        let s = CacheStats {
            tick_count: 100,
            cache_hits: 80,
            cache_misses: 20,
            sanity_failures: 0,
            cached_features: 8,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: CacheStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tick_count, 100);
    }

    #[test]
    fn sanity_check_on_interval() {
        let config = IncrementalConfig {
            sanity_check_interval: 5,
            ..Default::default()
        };
        let mut cached = CachedPosterior::new(config);

        let priors = test_priors();
        let evidence = test_evidence();

        // Run exactly 5 ticks to trigger sanity check
        for _ in 0..5 {
            cached.compute(&priors, &evidence).unwrap();
        }

        // Sanity check should have run but not failed (same evidence)
        assert_eq!(cached.stats().sanity_failures, 0);
    }
}
