//! Dependency-weighted loss scaling for decision making.
//!
//! This module implements loss scaling based on process dependencies (Plan §5.5).
//! The core principle: killing a process with many dependents is costlier than
//! killing an isolated process.
//!
//! # Formula
//!
//! ```text
//! L_kill_scaled = L_kill × (1 + impact_score)
//! ```
//!
//! Where `impact_score` is computed from:
//! - Child process count
//! - Established network connections
//! - Listening ports (server capability)
//! - Open write handles (data-loss risk)
//! - Shared memory segments (IPC dependencies)
//!
//! # Usage
//!
//! ```no_run
//! use pt_core::decision::dependency_loss::{DependencyScaling, DependencyFactors, scale_kill_loss};
//!
//! let factors = DependencyFactors {
//!     child_count: 3,
//!     established_connections: 5,
//!     listen_ports: 1,
//!     open_write_handles: 2,
//!     shared_memory_segments: 0,
//! };
//!
//! let scaling = DependencyScaling::default();
//! let impact = scaling.compute_impact_score(&factors);
//! let scaled_loss = scale_kill_loss(100.0, impact);
//!
//! assert!(scaled_loss > 100.0); // Loss increased due to dependencies
//! ```

use crate::collect::{CriticalFile, CriticalFileCategory, DetectionStrength};
use serde::{Deserialize, Serialize};

// =============================================================================
// Dependency-Based Loss Scaling (Plan §5.5)
// =============================================================================

/// Configuration for dependency-based loss scaling.
///
/// These weights determine how each factor contributes to the impact score.
/// The default weights are from Plan §5.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyScaling {
    /// Weight for child process count (default: 0.1).
    pub child_weight: f64,

    /// Weight for established network connections (default: 0.2).
    pub connection_weight: f64,

    /// Weight for listening ports - server capability (default: 0.5).
    /// Higher weight because listening ports indicate the process serves others.
    pub listen_port_weight: f64,

    /// Weight for open write handles - data-loss risk (default: 0.3).
    pub write_handle_weight: f64,

    /// Weight for shared memory segments - IPC dependencies (default: 0.1).
    pub shared_memory_weight: f64,

    /// Maximum child count for normalization (default: 20).
    pub max_children: usize,

    /// Maximum connections for normalization (default: 50).
    pub max_connections: usize,

    /// Maximum listen ports for normalization (default: 10).
    pub max_listen_ports: usize,

    /// Maximum write handles for normalization (default: 100).
    pub max_write_handles: usize,

    /// Maximum shared memory segments for normalization (default: 20).
    pub max_shared_memory: usize,

    /// Maximum impact score cap (default: 2.0).
    /// Prevents extreme scaling even with many dependencies.
    pub max_impact: f64,
}

impl Default for DependencyScaling {
    fn default() -> Self {
        Self {
            child_weight: 0.1,
            connection_weight: 0.2,
            listen_port_weight: 0.5,
            write_handle_weight: 0.3,
            shared_memory_weight: 0.1,
            max_children: 20,
            max_connections: 50,
            max_listen_ports: 10,
            max_write_handles: 100,
            max_shared_memory: 20,
            max_impact: 2.0,
        }
    }
}

impl DependencyScaling {
    /// Create a new dependency scaling configuration with custom weights.
    pub fn new(
        child_weight: f64,
        connection_weight: f64,
        listen_port_weight: f64,
        write_handle_weight: f64,
        shared_memory_weight: f64,
    ) -> Self {
        Self {
            child_weight,
            connection_weight,
            listen_port_weight,
            write_handle_weight,
            shared_memory_weight,
            ..Default::default()
        }
    }

    /// Compute the impact score from dependency factors.
    ///
    /// Returns a normalized score (typically 0.0-2.0) representing how costly
    /// it would be to kill this process based on its dependencies.
    ///
    /// The score is computed as a weighted sum of normalized factors:
    /// ```text
    /// impact = w_child × (children / max_children) +
    ///          w_conn × (connections / max_connections) +
    ///          w_listen × (listen_ports / max_listen_ports) +
    ///          w_write × (write_handles / max_write_handles) +
    ///          w_shm × (shared_memory / max_shared_memory)
    /// ```
    pub fn compute_impact_score(&self, factors: &DependencyFactors) -> f64 {
        let child_normalized =
            (factors.child_count as f64 / self.max_children as f64).min(1.0);
        let conn_normalized =
            (factors.established_connections as f64 / self.max_connections as f64).min(1.0);
        let listen_normalized =
            (factors.listen_ports as f64 / self.max_listen_ports as f64).min(1.0);
        let write_normalized =
            (factors.open_write_handles as f64 / self.max_write_handles as f64).min(1.0);
        let shm_normalized =
            (factors.shared_memory_segments as f64 / self.max_shared_memory as f64).min(1.0);

        let raw_score = self.child_weight * child_normalized
            + self.connection_weight * conn_normalized
            + self.listen_port_weight * listen_normalized
            + self.write_handle_weight * write_normalized
            + self.shared_memory_weight * shm_normalized;

        // Cap at max_impact to prevent extreme scaling
        raw_score.min(self.max_impact)
    }

    /// Scale the kill loss by the dependency impact.
    ///
    /// Applies the formula: `L_kill_scaled = L_kill × (1 + impact_score)`
    pub fn scale_loss(&self, base_loss: f64, factors: &DependencyFactors) -> f64 {
        let impact = self.compute_impact_score(factors);
        base_loss * (1.0 + impact)
    }
}

/// Dependency factors collected for a process.
///
/// These factors represent external dependencies that would be affected
/// if the process is killed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyFactors {
    /// Number of direct child processes.
    /// Killing this process would orphan these children.
    pub child_count: usize,

    /// Number of established/active network connections.
    /// Killing would abruptly close these connections.
    pub established_connections: usize,

    /// Number of listening ports (TCP + UDP).
    /// Indicates this process is a server for other clients.
    pub listen_ports: usize,

    /// Number of file descriptors open for writing.
    /// Risk of data corruption/loss if killed mid-write.
    pub open_write_handles: usize,

    /// Number of shared memory segments attached.
    /// Other processes may depend on this shared memory.
    pub shared_memory_segments: usize,
}

impl DependencyFactors {
    /// Create a new DependencyFactors instance.
    pub fn new(
        child_count: usize,
        established_connections: usize,
        listen_ports: usize,
        open_write_handles: usize,
        shared_memory_segments: usize,
    ) -> Self {
        Self {
            child_count,
            established_connections,
            listen_ports,
            open_write_handles,
            shared_memory_segments,
        }
    }

    /// Check if the process has any significant dependencies.
    pub fn has_dependencies(&self) -> bool {
        self.child_count > 0
            || self.established_connections > 0
            || self.listen_ports > 0
            || self.open_write_handles > 0
            || self.shared_memory_segments > 0
    }

    /// Create factors from impact components (inference layer).
    ///
    /// This enables reuse of data already collected by the impact scorer.
    #[cfg(feature = "inference-integration")]
    pub fn from_impact_components(components: &crate::inference::impact::ImpactComponents) -> Self {
        Self {
            child_count: components.child_count,
            established_connections: components.established_conns_count,
            listen_ports: components.listen_ports_count,
            open_write_handles: components.open_write_fds_count,
            shared_memory_segments: 0, // Not currently tracked in impact
        }
    }
}

/// Result of dependency scaling computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyScalingResult {
    /// The computed impact score (0.0 - max_impact).
    pub impact_score: f64,

    /// Original kill loss before scaling.
    pub original_kill_loss: f64,

    /// Scaled kill loss after applying dependency factor.
    pub scaled_kill_loss: f64,

    /// The scaling multiplier applied (1 + impact_score).
    pub scale_factor: f64,

    /// Individual factor contributions for explainability.
    pub factors: DependencyFactors,
}

impl DependencyScalingResult {
    /// Create a result showing no scaling (no dependencies).
    pub fn no_scaling(original_loss: f64) -> Self {
        Self {
            impact_score: 0.0,
            original_kill_loss: original_loss,
            scaled_kill_loss: original_loss,
            scale_factor: 1.0,
            factors: DependencyFactors::default(),
        }
    }
}

/// Convenience function to scale a kill loss by dependency impact.
///
/// Uses default scaling weights from Plan §5.5.
pub fn scale_kill_loss(base_loss: f64, impact_score: f64) -> f64 {
    base_loss * (1.0 + impact_score)
}

/// Compute dependency scaling with full result for audit/explainability.
pub fn compute_dependency_scaling(
    original_kill_loss: f64,
    factors: &DependencyFactors,
    config: Option<&DependencyScaling>,
) -> DependencyScalingResult {
    let scaling = config.cloned().unwrap_or_default();
    let impact_score = scaling.compute_impact_score(factors);
    let scale_factor = 1.0 + impact_score;
    let scaled_kill_loss = original_kill_loss * scale_factor;

    DependencyScalingResult {
        impact_score,
        original_kill_loss,
        scaled_kill_loss,
        scale_factor,
        factors: factors.clone(),
    }
}

// =============================================================================
// Critical File Inflation (Plan §11 - Data Loss Safety Gate)
// =============================================================================

/// Configuration for critical file-based loss inflation.
///
/// When a process holds critical files (locks, active writes), we inflate
/// the kill loss to make destructive actions less attractive.
///
/// Different file categories have different inflation levels:
/// - Hard detections (definite locks): very high inflation (effectively blocking)
/// - Soft detections (heuristic matches): moderate inflation (increased caution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalFileInflation {
    /// Base inflation multiplier for hard detections (default: 10.0).
    /// A hard detection multiplies kill loss by this amount.
    pub hard_inflation_base: f64,

    /// Base inflation multiplier for soft detections (default: 2.0).
    /// A soft detection multiplies kill loss by this amount.
    pub soft_inflation_base: f64,

    /// Additional per-file inflation (hard, default: 2.0).
    /// Each additional hard file adds this multiplier.
    pub hard_per_file: f64,

    /// Additional per-file inflation (soft, default: 0.5).
    /// Each additional soft file adds this multiplier.
    pub soft_per_file: f64,

    /// Maximum inflation cap (default: 100.0).
    /// Prevents extreme scaling even with many critical files.
    pub max_inflation: f64,

    /// Category-specific multipliers (applied on top of hard/soft base).
    /// Higher values for more dangerous categories.
    pub sqlite_wal_weight: f64,
    pub git_lock_weight: f64,
    pub git_rebase_weight: f64,
    pub system_package_lock_weight: f64,
    pub node_package_lock_weight: f64,
    pub cargo_lock_weight: f64,
    pub database_write_weight: f64,
    pub app_lock_weight: f64,
    pub open_write_weight: f64,
}

impl Default for CriticalFileInflation {
    fn default() -> Self {
        Self {
            // Hard detections should effectively block kills
            hard_inflation_base: 10.0,
            // Soft detections increase caution significantly
            soft_inflation_base: 2.0,
            // Per-file additives
            hard_per_file: 2.0,
            soft_per_file: 0.5,
            // Maximum cap
            max_inflation: 100.0,
            // Category weights (danger level)
            sqlite_wal_weight: 2.0,       // Very dangerous - active DB write
            git_lock_weight: 1.5,         // Dangerous - repo operation
            git_rebase_weight: 2.0,       // Very dangerous - complex git state
            system_package_lock_weight: 2.5, // Very dangerous - system state
            node_package_lock_weight: 1.5,   // Dangerous - package install
            cargo_lock_weight: 1.5,          // Dangerous - package install
            database_write_weight: 1.5,      // Dangerous - data writes
            app_lock_weight: 1.0,            // Moderate - application locks
            open_write_weight: 0.5,          // Lower - generic writes
        }
    }
}

impl CriticalFileInflation {
    /// Compute inflation factor from a list of critical files.
    ///
    /// Returns a multiplier (>= 1.0) to apply to kill loss.
    ///
    /// Formula:
    /// ```text
    /// inflation = 1.0 + sum(base[strength] * category_weight * per_file_factor)
    /// ```
    pub fn compute_inflation(&self, critical_files: &[CriticalFile]) -> f64 {
        if critical_files.is_empty() {
            return 1.0;
        }

        let mut total_inflation = 0.0;
        let mut hard_count = 0usize;
        let mut soft_count = 0usize;

        for file in critical_files {
            let category_weight = self.category_weight(&file.category);

            match file.strength {
                DetectionStrength::Hard => {
                    let per_file = if hard_count == 0 {
                        self.hard_inflation_base
                    } else {
                        self.hard_per_file
                    };
                    total_inflation += per_file * category_weight;
                    hard_count += 1;
                }
                DetectionStrength::Soft => {
                    let per_file = if soft_count == 0 && hard_count == 0 {
                        self.soft_inflation_base
                    } else {
                        self.soft_per_file
                    };
                    total_inflation += per_file * category_weight;
                    soft_count += 1;
                }
            }
        }

        let inflation = 1.0 + total_inflation;
        inflation.min(self.max_inflation)
    }

    /// Get the category-specific weight multiplier.
    pub fn category_weight(&self, category: &CriticalFileCategory) -> f64 {
        match category {
            CriticalFileCategory::SqliteWal => self.sqlite_wal_weight,
            CriticalFileCategory::GitLock => self.git_lock_weight,
            CriticalFileCategory::GitRebase => self.git_rebase_weight,
            CriticalFileCategory::SystemPackageLock => self.system_package_lock_weight,
            CriticalFileCategory::NodePackageLock => self.node_package_lock_weight,
            CriticalFileCategory::CargoLock => self.cargo_lock_weight,
            CriticalFileCategory::DatabaseWrite => self.database_write_weight,
            CriticalFileCategory::AppLock => self.app_lock_weight,
            CriticalFileCategory::OpenWrite => self.open_write_weight,
        }
    }

    /// Scale the kill loss by critical file inflation.
    pub fn scale_loss(&self, base_loss: f64, critical_files: &[CriticalFile]) -> f64 {
        let inflation = self.compute_inflation(critical_files);
        base_loss * inflation
    }
}

/// Result of critical file inflation computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalFileInflationResult {
    /// The computed inflation factor (>= 1.0).
    pub inflation_factor: f64,

    /// Original kill loss before inflation.
    pub original_kill_loss: f64,

    /// Inflated kill loss after applying critical file factor.
    pub inflated_kill_loss: f64,

    /// Number of hard detections.
    pub hard_count: usize,

    /// Number of soft detections.
    pub soft_count: usize,

    /// Categories detected (for explainability).
    pub categories: Vec<CriticalFileCategory>,

    /// Rule IDs that triggered (for explainability).
    pub rule_ids: Vec<String>,
}

impl CriticalFileInflationResult {
    /// Create a result showing no inflation (no critical files).
    pub fn no_inflation(original_loss: f64) -> Self {
        Self {
            inflation_factor: 1.0,
            original_kill_loss: original_loss,
            inflated_kill_loss: original_loss,
            hard_count: 0,
            soft_count: 0,
            categories: Vec::new(),
            rule_ids: Vec::new(),
        }
    }
}

/// Compute critical file inflation with full result for audit/explainability.
pub fn compute_critical_file_inflation(
    original_kill_loss: f64,
    critical_files: &[CriticalFile],
    config: Option<&CriticalFileInflation>,
) -> CriticalFileInflationResult {
    if critical_files.is_empty() {
        return CriticalFileInflationResult::no_inflation(original_kill_loss);
    }

    let inflation_config = config.cloned().unwrap_or_default();
    let inflation_factor = inflation_config.compute_inflation(critical_files);
    let inflated_kill_loss = original_kill_loss * inflation_factor;

    let hard_count = critical_files
        .iter()
        .filter(|f| matches!(f.strength, DetectionStrength::Hard))
        .count();
    let soft_count = critical_files.len() - hard_count;

    let mut categories: Vec<CriticalFileCategory> = critical_files
        .iter()
        .map(|f| f.category.clone())
        .collect();
    categories.sort_by_key(|c| format!("{:?}", c));
    categories.dedup();

    let mut rule_ids: Vec<String> = critical_files
        .iter()
        .map(|f| f.rule_id.clone())
        .collect();
    rule_ids.sort();
    rule_ids.dedup();

    CriticalFileInflationResult {
        inflation_factor,
        original_kill_loss,
        inflated_kill_loss,
        hard_count,
        soft_count,
        categories,
        rule_ids,
    }
}

/// Convenience function to check if critical files warrant blocking kill actions.
///
/// Returns true if any hard detection is present, which in robot mode should
/// block kill-like actions by default.
pub fn should_block_kill(critical_files: &[CriticalFile]) -> bool {
    critical_files
        .iter()
        .any(|f| matches!(f.strength, DetectionStrength::Hard))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_default_config() {
        let config = DependencyScaling::default();

        // Weights should sum to 1.2 (allowing for some scaling)
        let total = config.child_weight
            + config.connection_weight
            + config.listen_port_weight
            + config.write_handle_weight
            + config.shared_memory_weight;
        assert!(approx_eq(total, 1.2, 0.01), "Total: {}", total);
    }

    #[test]
    fn test_zero_factors_zero_impact() {
        let config = DependencyScaling::default();
        let factors = DependencyFactors::default();

        let impact = config.compute_impact_score(&factors);
        assert_eq!(impact, 0.0);
    }

    #[test]
    fn test_impact_score_formula() {
        let config = DependencyScaling::default();

        // Test with specific values from the plan
        let factors = DependencyFactors {
            child_count: 3,
            established_connections: 5,
            listen_ports: 1,
            open_write_handles: 10,
            shared_memory_segments: 2,
        };

        let impact = config.compute_impact_score(&factors);

        // Manual calculation:
        // child: 0.1 * (3/20) = 0.015
        // conn: 0.2 * (5/50) = 0.02
        // listen: 0.5 * (1/10) = 0.05
        // write: 0.3 * (10/100) = 0.03
        // shm: 0.1 * (2/20) = 0.01
        // Total: 0.125
        let expected = 0.015 + 0.02 + 0.05 + 0.03 + 0.01;
        assert!(approx_eq(impact, expected, 0.001), "Impact: {}", impact);
    }

    #[test]
    fn test_impact_capped_at_max() {
        let config = DependencyScaling::default();

        // Max out all factors
        let factors = DependencyFactors {
            child_count: 100,
            established_connections: 200,
            listen_ports: 50,
            open_write_handles: 500,
            shared_memory_segments: 100,
        };

        let impact = config.compute_impact_score(&factors);
        assert!(impact <= config.max_impact, "Impact {} > max {}", impact, config.max_impact);
    }

    #[test]
    fn test_loss_scaling() {
        let config = DependencyScaling::default();
        let base_loss = 100.0;

        let factors = DependencyFactors {
            child_count: 10,  // 0.1 * 0.5 = 0.05
            established_connections: 25,  // 0.2 * 0.5 = 0.1
            listen_ports: 5,  // 0.5 * 0.5 = 0.25
            open_write_handles: 50,  // 0.3 * 0.5 = 0.15
            shared_memory_segments: 10,  // 0.1 * 0.5 = 0.05
        };

        // Expected impact: 0.05 + 0.1 + 0.25 + 0.15 + 0.05 = 0.6
        let scaled = config.scale_loss(base_loss, &factors);
        let expected = base_loss * (1.0 + 0.6);
        assert!(approx_eq(scaled, expected, 0.01), "Scaled: {}, Expected: {}", scaled, expected);
    }

    #[test]
    fn test_scale_kill_loss_function() {
        let base_loss = 100.0;
        let impact = 0.5;

        let scaled = scale_kill_loss(base_loss, impact);
        assert_eq!(scaled, 150.0);
    }

    #[test]
    fn test_dependency_factors_has_dependencies() {
        assert!(!DependencyFactors::default().has_dependencies());

        assert!(DependencyFactors::new(1, 0, 0, 0, 0).has_dependencies());
        assert!(DependencyFactors::new(0, 1, 0, 0, 0).has_dependencies());
        assert!(DependencyFactors::new(0, 0, 1, 0, 0).has_dependencies());
        assert!(DependencyFactors::new(0, 0, 0, 1, 0).has_dependencies());
        assert!(DependencyFactors::new(0, 0, 0, 0, 1).has_dependencies());
    }

    #[test]
    fn test_compute_dependency_scaling_result() {
        let factors = DependencyFactors {
            child_count: 5,
            established_connections: 10,
            listen_ports: 2,
            open_write_handles: 20,
            shared_memory_segments: 1,
        };

        let result = compute_dependency_scaling(100.0, &factors, None);

        assert!(result.impact_score > 0.0);
        assert_eq!(result.original_kill_loss, 100.0);
        assert!(result.scaled_kill_loss > 100.0);
        assert!(approx_eq(result.scale_factor, 1.0 + result.impact_score, 0.001));
    }

    #[test]
    fn test_no_scaling_result() {
        let result = DependencyScalingResult::no_scaling(100.0);

        assert_eq!(result.impact_score, 0.0);
        assert_eq!(result.original_kill_loss, 100.0);
        assert_eq!(result.scaled_kill_loss, 100.0);
        assert_eq!(result.scale_factor, 1.0);
    }

    #[test]
    fn test_custom_config() {
        // Test with custom weights that heavily penalize listen ports
        let config = DependencyScaling::new(
            0.0,  // child
            0.0,  // conn
            1.0,  // listen (100% weight)
            0.0,  // write
            0.0,  // shm
        );

        let factors = DependencyFactors {
            child_count: 100,  // Should not contribute
            established_connections: 100,  // Should not contribute
            listen_ports: 5,  // 5/10 = 0.5
            open_write_handles: 100,  // Should not contribute
            shared_memory_segments: 100,  // Should not contribute
        };

        let impact = config.compute_impact_score(&factors);
        assert!(approx_eq(impact, 0.5, 0.001), "Impact: {}", impact);
    }

    #[test]
    fn test_normalization_caps() {
        let config = DependencyScaling::default();

        // Values beyond max should be capped at 1.0 in normalization
        let factors = DependencyFactors {
            child_count: 100,  // >> 20, capped to 1.0
            established_connections: 0,
            listen_ports: 0,
            open_write_handles: 0,
            shared_memory_segments: 0,
        };

        // Should be child_weight * 1.0 = 0.1
        let impact = config.compute_impact_score(&factors);
        assert!(approx_eq(impact, 0.1, 0.001));
    }

    #[test]
    fn test_json_serialization() {
        let factors = DependencyFactors {
            child_count: 3,
            established_connections: 5,
            listen_ports: 1,
            open_write_handles: 10,
            shared_memory_segments: 2,
        };

        let json = serde_json::to_string(&factors).unwrap();
        assert!(json.contains("child_count"));
        assert!(json.contains("\"3\"") || json.contains(":3"));

        let parsed: DependencyFactors = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.child_count, 3);
        assert_eq!(parsed.listen_ports, 1);
    }

    #[test]
    fn test_result_json_serialization() {
        let result = compute_dependency_scaling(
            100.0,
            &DependencyFactors::new(3, 5, 1, 10, 2),
            None,
        );

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("impact_score"));
        assert!(json.contains("original_kill_loss"));
        assert!(json.contains("scaled_kill_loss"));
        assert!(json.contains("scale_factor"));
    }

    // =========================================================================
    // Critical File Inflation Tests
    // =========================================================================

    fn make_critical_file(
        category: CriticalFileCategory,
        strength: DetectionStrength,
        rule_id: &str,
    ) -> CriticalFile {
        CriticalFile {
            fd: 42,
            path: "/test/path".to_string(),
            category,
            strength,
            rule_id: rule_id.to_string(),
        }
    }

    #[test]
    fn test_no_critical_files_no_inflation() {
        let config = CriticalFileInflation::default();
        let inflation = config.compute_inflation(&[]);
        assert_eq!(inflation, 1.0);
    }

    #[test]
    fn test_hard_detection_high_inflation() {
        let config = CriticalFileInflation::default();
        let files = vec![make_critical_file(
            CriticalFileCategory::SqliteWal,
            DetectionStrength::Hard,
            "sqlite-wal",
        )];

        let inflation = config.compute_inflation(&files);
        // Expected: 1.0 + (10.0 base * 2.0 sqlite weight) = 21.0
        assert!(approx_eq(inflation, 21.0, 0.01), "Got: {}", inflation);
    }

    #[test]
    fn test_soft_detection_moderate_inflation() {
        let config = CriticalFileInflation::default();
        let files = vec![make_critical_file(
            CriticalFileCategory::DatabaseWrite,
            DetectionStrength::Soft,
            "db-soft",
        )];

        let inflation = config.compute_inflation(&files);
        // Expected: 1.0 + (2.0 soft base * 1.5 db weight) = 4.0
        assert!(approx_eq(inflation, 4.0, 0.01), "Got: {}", inflation);
    }

    #[test]
    fn test_multiple_hard_detections_additive() {
        let config = CriticalFileInflation::default();
        let files = vec![
            make_critical_file(
                CriticalFileCategory::GitLock,
                DetectionStrength::Hard,
                "git-lock",
            ),
            make_critical_file(
                CriticalFileCategory::GitRebase,
                DetectionStrength::Hard,
                "git-rebase",
            ),
        ];

        let inflation = config.compute_inflation(&files);
        // First hard: 10.0 * 1.5 (git-lock) = 15.0
        // Second hard: 2.0 * 2.0 (git-rebase per-file) = 4.0
        // Total: 1.0 + 15.0 + 4.0 = 20.0
        assert!(approx_eq(inflation, 20.0, 0.01), "Got: {}", inflation);
    }

    #[test]
    fn test_inflation_capped_at_max() {
        let config = CriticalFileInflation::default();
        // Create many hard detections
        let files: Vec<_> = (0..50)
            .map(|i| {
                make_critical_file(
                    CriticalFileCategory::SystemPackageLock,
                    DetectionStrength::Hard,
                    &format!("rule-{}", i),
                )
            })
            .collect();

        let inflation = config.compute_inflation(&files);
        assert!(
            inflation <= config.max_inflation,
            "Inflation {} exceeds max {}",
            inflation,
            config.max_inflation
        );
    }

    #[test]
    fn test_compute_critical_file_inflation_result() {
        let files = vec![
            make_critical_file(
                CriticalFileCategory::GitLock,
                DetectionStrength::Hard,
                "git-lock",
            ),
            make_critical_file(
                CriticalFileCategory::OpenWrite,
                DetectionStrength::Soft,
                "open-write",
            ),
        ];

        let result = compute_critical_file_inflation(100.0, &files, None);

        assert!(result.inflation_factor > 1.0);
        assert_eq!(result.original_kill_loss, 100.0);
        assert!(result.inflated_kill_loss > 100.0);
        assert_eq!(result.hard_count, 1);
        assert_eq!(result.soft_count, 1);
        assert_eq!(result.categories.len(), 2);
        assert_eq!(result.rule_ids.len(), 2);
    }

    #[test]
    fn test_should_block_kill_with_hard() {
        let files = vec![make_critical_file(
            CriticalFileCategory::SqliteWal,
            DetectionStrength::Hard,
            "sqlite-wal",
        )];
        assert!(should_block_kill(&files));
    }

    #[test]
    fn test_should_not_block_kill_with_only_soft() {
        let files = vec![make_critical_file(
            CriticalFileCategory::OpenWrite,
            DetectionStrength::Soft,
            "open-write",
        )];
        assert!(!should_block_kill(&files));
    }

    #[test]
    fn test_no_inflation_result() {
        let result = CriticalFileInflationResult::no_inflation(100.0);
        assert_eq!(result.inflation_factor, 1.0);
        assert_eq!(result.inflated_kill_loss, 100.0);
        assert_eq!(result.hard_count, 0);
        assert_eq!(result.soft_count, 0);
    }

    #[test]
    fn test_category_weights() {
        let config = CriticalFileInflation::default();

        // Verify category weights are properly configured
        assert!(config.sqlite_wal_weight > config.open_write_weight);
        assert!(config.system_package_lock_weight > config.app_lock_weight);
        assert!(config.git_rebase_weight >= config.git_lock_weight);
    }
}
