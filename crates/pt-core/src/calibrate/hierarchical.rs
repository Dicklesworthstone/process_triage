//! Hierarchical priors with empirical Bayes shrinkage by command category.
//!
//! Implements category-conditioned Beta parameters that shrink toward global
//! class priors. The shrinkage is computed offline from shadow-mode data;
//! runtime inference remains closed-form conjugate.
//!
//! # Model
//!
//! For each feature (e.g., CPU occupancy) and class C:
//! - Global prior: `Beta(α_C, β_C)` from priors.json
//! - Category prior: `Beta(α_{C,g}, β_{C,g})` estimated from category g observations
//! - Shrinkage: `α_{C,g} = λ·α_C + (1-λ)·α̂_{C,g}` where λ depends on category sample size
//!
//! Small categories get strong shrinkage toward the global prior (preventing
//! overconfident posteriors from sparse data). Large categories get weak
//! shrinkage, letting the data speak.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for hierarchical shrinkage fitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalConfig {
    /// Minimum observations per category before fitting category-specific params.
    /// Below this, the global prior is used directly.
    pub min_category_obs: usize,
    /// Base shrinkage strength (pseudo-count weight of the global prior).
    /// Higher = more shrinkage toward global. Typical range: 5-50.
    pub prior_strength: f64,
    /// Features to fit category priors for.
    pub features: Vec<String>,
}

impl Default for HierarchicalConfig {
    fn default() -> Self {
        Self {
            min_category_obs: 10,
            prior_strength: 20.0,
            features: vec![
                "cpu_beta".to_string(),
                "orphan_beta".to_string(),
                "tty_beta".to_string(),
                "net_beta".to_string(),
            ],
        }
    }
}

/// A Beta parameter set for a specific (class, category, feature) triple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryBetaParams {
    /// Fitted alpha (after shrinkage).
    pub alpha: f64,
    /// Fitted beta (after shrinkage).
    pub beta: f64,
    /// Shrinkage weight applied (0 = pure MLE, 1 = pure global prior).
    pub shrinkage_lambda: f64,
    /// Number of observations used for fitting.
    pub n_obs: usize,
    /// Source global alpha before shrinkage.
    pub global_alpha: f64,
    /// Source global beta before shrinkage.
    pub global_beta: f64,
}

impl CategoryBetaParams {
    /// Mean of the fitted Beta distribution.
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }
}

/// Observation counts for a single (class, category, feature) triple.
#[derive(Debug, Clone, Default)]
pub struct FeatureCounts {
    /// Number of times the feature was "true" (success).
    pub successes: u64,
    /// Total observations.
    pub trials: u64,
}

/// Input data for hierarchical fitting: observations grouped by category.
#[derive(Debug, Clone, Default)]
pub struct CategoryObservations {
    /// Keyed by (class_name, category_name, feature_name).
    pub counts: HashMap<(String, String, String), FeatureCounts>,
}

impl CategoryObservations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observation.
    pub fn record(
        &mut self,
        class: &str,
        category: &str,
        feature: &str,
        success: bool,
    ) {
        let key = (class.to_string(), category.to_string(), feature.to_string());
        let entry = self.counts.entry(key).or_default();
        entry.trials += 1;
        if success {
            entry.successes += 1;
        }
    }
}

/// Fitted hierarchical prior parameters for all categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalFit {
    /// Per-(class, category, feature) fitted parameters.
    /// Key format: "class:category:feature"
    pub params: HashMap<String, CategoryBetaParams>,
    /// Configuration used for fitting.
    pub config: HierarchicalConfig,
    /// Categories that used pure global prior (insufficient data).
    pub fallback_categories: Vec<String>,
}

impl HierarchicalFit {
    /// Look up fitted params for a (class, category, feature) triple.
    /// Returns None if no category-specific fit exists (use global prior).
    pub fn get(&self, class: &str, category: &str, feature: &str) -> Option<&CategoryBetaParams> {
        let key = format!("{}:{}:{}", class, category, feature);
        self.params.get(&key)
    }

    /// Get effective alpha/beta for a (class, category, feature),
    /// falling back to global if no category fit exists.
    pub fn effective_params(
        &self,
        class: &str,
        category: &str,
        feature: &str,
        global_alpha: f64,
        global_beta: f64,
    ) -> (f64, f64) {
        match self.get(class, category, feature) {
            Some(p) => (p.alpha, p.beta),
            None => (global_alpha, global_beta),
        }
    }
}

/// Compute shrinkage weight lambda for a category.
///
/// lambda = prior_strength / (prior_strength + n)
///
/// When n is small, lambda → 1 (use global prior).
/// When n is large, lambda → 0 (use category MLE).
fn shrinkage_weight(prior_strength: f64, n: u64) -> f64 {
    prior_strength / (prior_strength + n as f64)
}

/// Fit hierarchical category priors from observation data.
///
/// For each (class, category, feature) with sufficient data:
/// 1. Compute the MLE from observations: α̂ = successes, β̂ = failures
/// 2. Compute shrinkage: λ = prior_strength / (prior_strength + n)
/// 3. Blend: α_fit = λ·α_global + (1-λ)·α̂_scaled
///
/// The MLE is scaled to match the concentration of the global prior,
/// so shrinkage interpolates between global and category-specific priors
/// at the same effective sample size.
pub fn fit_hierarchical(
    observations: &CategoryObservations,
    global_params: &HashMap<(String, String), (f64, f64)>, // (class, feature) → (α, β)
    config: &HierarchicalConfig,
) -> HierarchicalFit {
    let mut params = HashMap::new();
    let mut fallback_categories = Vec::new();

    // Group by (class, feature) to track which categories fall back.
    let mut seen_categories: HashMap<String, bool> = HashMap::new();

    for ((class, category, feature), counts) in &observations.counts {
        if !config.features.contains(feature) {
            continue;
        }

        let global_key = (class.clone(), feature.clone());
        let (global_alpha, global_beta) = match global_params.get(&global_key) {
            Some(p) => *p,
            None => continue,
        };

        if (counts.trials as usize) < config.min_category_obs {
            seen_categories
                .entry(category.clone())
                .and_modify(|_has_fit| {
                    // Keep existing value; only mark fallback if ALL features fall back.
                })
                .or_insert(false);
            continue;
        }

        seen_categories
            .entry(category.clone())
            .and_modify(|has_fit| *has_fit = true)
            .or_insert(true);

        let lambda = shrinkage_weight(config.prior_strength, counts.trials);

        // MLE: scale to match global prior concentration.
        let global_conc = global_alpha + global_beta;
        let mle_rate = counts.successes as f64 / counts.trials as f64;
        let mle_alpha = mle_rate * global_conc;
        let mle_beta = (1.0 - mle_rate) * global_conc;

        // Shrinkage blend.
        let fit_alpha = lambda * global_alpha + (1.0 - lambda) * mle_alpha;
        let fit_beta = lambda * global_beta + (1.0 - lambda) * mle_beta;

        let key = format!("{}:{}:{}", class, category, feature);
        params.insert(
            key,
            CategoryBetaParams {
                alpha: fit_alpha,
                beta: fit_beta,
                shrinkage_lambda: lambda,
                n_obs: counts.trials as usize,
                global_alpha,
                global_beta,
            },
        );
    }

    for (cat, has_fit) in &seen_categories {
        if !has_fit {
            fallback_categories.push(cat.clone());
        }
    }

    fallback_categories.sort();

    HierarchicalFit {
        params,
        config: config.clone(),
        fallback_categories,
    }
}

/// Format a provenance string for explainability ledger.
pub fn format_provenance(
    class: &str,
    category: &str,
    feature: &str,
    fit: &HierarchicalFit,
) -> String {
    match fit.get(class, category, feature) {
        Some(p) => format!(
            "category prior (g={}) with shrinkage λ={:.2} toward global (α={:.1},β={:.1}) → effective (α={:.2},β={:.2}, mean={:.3}, n={})",
            category, p.shrinkage_lambda, p.global_alpha, p.global_beta,
            p.alpha, p.beta, p.mean(), p.n_obs
        ),
        None => format!(
            "global prior (no category-specific fit for g={})",
            category
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_global_params() -> HashMap<(String, String), (f64, f64)> {
        let mut m = HashMap::new();
        m.insert(
            ("abandoned".to_string(), "cpu_beta".to_string()),
            (1.0, 10.0),
        );
        m.insert(
            ("useful".to_string(), "cpu_beta".to_string()),
            (2.0, 5.0),
        );
        m
    }

    #[test]
    fn test_shrinkage_weight() {
        // With prior_strength=20, n=0: lambda=1.0 (pure global)
        assert!((shrinkage_weight(20.0, 0) - 1.0).abs() < 1e-9);

        // With prior_strength=20, n=20: lambda=0.5
        assert!((shrinkage_weight(20.0, 20) - 0.5).abs() < 1e-9);

        // With prior_strength=20, n=180: lambda=0.1
        assert!((shrinkage_weight(20.0, 180) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_fit_with_sufficient_data() {
        let config = HierarchicalConfig {
            min_category_obs: 5,
            prior_strength: 20.0,
            features: vec!["cpu_beta".to_string()],
        };

        let mut obs = CategoryObservations::new();
        // 100 observations of cpu for abandoned/test_runner: 80% zero CPU
        for _ in 0..80 {
            obs.record("abandoned", "test_runner", "cpu_beta", true);
        }
        for _ in 0..20 {
            obs.record("abandoned", "test_runner", "cpu_beta", false);
        }

        let global = make_global_params();
        let fit = fit_hierarchical(&obs, &global, &config);

        let p = fit.get("abandoned", "test_runner", "cpu_beta").unwrap();
        assert_eq!(p.n_obs, 100);

        // lambda = 20/(20+100) = 0.1667
        assert!((p.shrinkage_lambda - 20.0 / 120.0).abs() < 1e-4);

        // MLE rate = 0.8, global conc = 11, so mle_alpha = 8.8, mle_beta = 2.2
        // fit_alpha = 0.1667*1.0 + 0.8333*8.8 ≈ 7.5
        assert!(p.alpha > 5.0); // Much higher than global alpha=1.0
        assert!(p.mean() > 0.5); // Closer to observed 0.8 than global 0.091
    }

    #[test]
    fn test_fit_insufficient_data_fallback() {
        let config = HierarchicalConfig {
            min_category_obs: 50,
            prior_strength: 20.0,
            features: vec!["cpu_beta".to_string()],
        };

        let mut obs = CategoryObservations::new();
        for _ in 0..10 {
            obs.record("abandoned", "rare_tool", "cpu_beta", true);
        }

        let global = make_global_params();
        let fit = fit_hierarchical(&obs, &global, &config);

        // Should fall back to global (only 10 obs < min 50).
        assert!(fit.get("abandoned", "rare_tool", "cpu_beta").is_none());
        assert!(fit.fallback_categories.contains(&"rare_tool".to_string()));
    }

    #[test]
    fn test_effective_params_fallback() {
        let fit = HierarchicalFit {
            params: HashMap::new(),
            config: HierarchicalConfig::default(),
            fallback_categories: vec![],
        };

        // No fit → returns global params.
        let (a, b) = fit.effective_params("abandoned", "unknown", "cpu_beta", 1.0, 10.0);
        assert!((a - 1.0).abs() < 1e-9);
        assert!((b - 10.0).abs() < 1e-9);
    }

    #[test]
    fn test_strong_shrinkage_for_small_n() {
        let config = HierarchicalConfig {
            min_category_obs: 3,
            prior_strength: 100.0, // Very strong shrinkage
            features: vec!["cpu_beta".to_string()],
        };

        let mut obs = CategoryObservations::new();
        // Only 5 observations, all successes (extreme MLE = 1.0)
        for _ in 0..5 {
            obs.record("abandoned", "tiny_cat", "cpu_beta", true);
        }

        let global = make_global_params();
        let fit = fit_hierarchical(&obs, &global, &config);

        let p = fit.get("abandoned", "tiny_cat", "cpu_beta").unwrap();
        // lambda = 100/(100+5) ≈ 0.952 → strong pull toward global
        assert!(p.shrinkage_lambda > 0.9);
        // Mean should be much closer to global mean (0.091) than MLE (1.0)
        assert!(p.mean() < 0.3);
    }

    #[test]
    fn test_provenance_formatting() {
        let config = HierarchicalConfig::default();
        let mut params = HashMap::new();
        params.insert(
            "abandoned:test_runner:cpu_beta".to_string(),
            CategoryBetaParams {
                alpha: 5.0,
                beta: 6.0,
                shrinkage_lambda: 0.3,
                n_obs: 50,
                global_alpha: 1.0,
                global_beta: 10.0,
            },
        );

        let fit = HierarchicalFit {
            params,
            config,
            fallback_categories: vec![],
        };

        let prov = format_provenance("abandoned", "test_runner", "cpu_beta", &fit);
        assert!(prov.contains("g=test_runner"));
        assert!(prov.contains("shrinkage"));
        assert!(prov.contains("n=50"));

        let prov_miss = format_provenance("abandoned", "unknown", "cpu_beta", &fit);
        assert!(prov_miss.contains("global prior"));
    }

    #[test]
    fn test_multiple_classes_and_features() {
        let config = HierarchicalConfig {
            min_category_obs: 5,
            prior_strength: 10.0,
            features: vec!["cpu_beta".to_string()],
        };

        let mut obs = CategoryObservations::new();
        for _ in 0..20 {
            obs.record("abandoned", "test_runner", "cpu_beta", true);
        }
        for _ in 0..20 {
            obs.record("useful", "test_runner", "cpu_beta", false);
        }

        let global = make_global_params();
        let fit = fit_hierarchical(&obs, &global, &config);

        // Both classes should have fits.
        let ab = fit.get("abandoned", "test_runner", "cpu_beta").unwrap();
        let us = fit.get("useful", "test_runner", "cpu_beta").unwrap();

        // Abandoned test runners have high CPU-zero rate.
        assert!(ab.mean() > 0.5);
        // Useful test runners have low CPU-zero rate.
        assert!(us.mean() < 0.2);
    }
}
