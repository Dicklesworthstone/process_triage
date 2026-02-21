//! Runtime robot mode constraints for `--robot` automation.
//!
//! This module implements Plan §2(BW) / §8.1: fine-grained confidence-bounded
//! automation controls that define a spectrum between full-manual and full-auto.
//!
//! # Architecture
//!
//! ```text
//! Policy.json (defaults) + CLI flags (overrides) → RuntimeRobotConstraints
//!                                                          ↓
//! Candidate → ConstraintChecker → ConstraintCheckResult (allow/block + reasons)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use pt_core::decision::robot_constraints::{RuntimeRobotConstraints, ConstraintChecker};
//!
//! // Build from policy with CLI overrides
//! let constraints = RuntimeRobotConstraints::from_policy(&policy.robot_mode)
//!     .with_min_posterior(Some(0.99))
//!     .with_max_kills(Some(3));
//!
//! // Create checker for a run
//! let mut checker = ConstraintChecker::new(constraints);
//!
//! // Check each candidate
//! for candidate in candidates {
//!     let result = checker.check_candidate(&candidate);
//!     if !result.allowed {
//!         // Show constraint violations
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::config::policy::RobotMode;

/// Runtime constraints for robot mode, merging policy defaults with CLI overrides.
///
/// CLI arguments take precedence over policy.json values. When both are specified,
/// the **more restrictive** value is used for safety (e.g., min of max_kills).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRobotConstraints {
    /// Whether robot mode is enabled.
    pub enabled: bool,

    /// Minimum posterior probability required for action.
    /// Only act when confidence exceeds this threshold.
    pub min_posterior: f64,

    /// Maximum memory (MB) that can be affected per candidate.
    /// Individual process limit.
    pub max_blast_radius_mb: f64,

    /// Maximum total memory (MB) that can be affected per run.
    /// Accumulated across all candidates.
    pub max_total_blast_radius_mb: Option<f64>,

    /// Maximum number of kill actions per run.
    pub max_kills: u32,

    /// Require process to have a known signature match.
    pub require_known_signature: bool,

    /// Require policy snapshot to be attached to session.
    pub require_policy_snapshot: bool,

    /// Categories to allow (if non-empty, only these are allowed).
    pub allow_categories: Vec<String>,

    /// Categories to exclude (these are never allowed).
    pub exclude_categories: Vec<String>,

    /// Require human confirmation for supervised processes.
    pub require_human_for_supervised: bool,

    /// Source of each constraint value for explainability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<ConstraintSources>,
}

/// Tracks where each constraint value came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSources {
    pub min_posterior: ConstraintSource,
    pub max_blast_radius_mb: ConstraintSource,
    pub max_total_blast_radius_mb: ConstraintSource,
    pub max_kills: ConstraintSource,
    pub require_known_signature: ConstraintSource,
    pub require_policy_snapshot: ConstraintSource,
    pub allow_categories: ConstraintSource,
    pub exclude_categories: ConstraintSource,
    pub require_human_for_supervised: ConstraintSource,
}

/// Source of a constraint value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintSource {
    /// Value from policy.json.
    #[default]
    Policy,
    /// Value from CLI flag override.
    CliOverride,
    /// Value from environment variable.
    EnvVar,
    /// Hardcoded default.
    Default,
}

impl RuntimeRobotConstraints {
    /// Create constraints from policy robot_mode configuration.
    pub fn from_policy(robot_mode: &RobotMode) -> Self {
        Self {
            enabled: robot_mode.enabled,
            min_posterior: robot_mode.min_posterior,
            max_blast_radius_mb: robot_mode.max_blast_radius_mb,
            max_total_blast_radius_mb: None, // Not in base policy, must be set via CLI
            max_kills: robot_mode.max_kills,
            require_known_signature: robot_mode.require_known_signature,
            require_policy_snapshot: robot_mode.require_policy_snapshot.unwrap_or(false),
            allow_categories: robot_mode.allow_categories.clone(),
            exclude_categories: robot_mode.exclude_categories.clone(),
            require_human_for_supervised: robot_mode.require_human_for_supervised,
            sources: Some(ConstraintSources::default()),
        }
    }

    /// Create disabled constraints (for non-robot mode).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            min_posterior: 0.0,
            max_blast_radius_mb: f64::MAX,
            max_total_blast_radius_mb: None,
            max_kills: u32::MAX,
            require_known_signature: false,
            require_policy_snapshot: false,
            allow_categories: Vec::new(),
            exclude_categories: Vec::new(),
            require_human_for_supervised: false,
            sources: None,
        }
    }

    /// Override minimum posterior from CLI.
    pub fn with_min_posterior(mut self, value: Option<f64>) -> Self {
        if let Some(v) = value {
            self.min_posterior = v;
            if let Some(ref mut sources) = self.sources {
                sources.min_posterior = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Override max blast radius (per candidate) from CLI.
    pub fn with_max_blast_radius_mb(mut self, value: Option<f64>) -> Self {
        if let Some(v) = value {
            // Use the more restrictive (smaller) value for safety
            self.max_blast_radius_mb = self.max_blast_radius_mb.min(v);
            if let Some(ref mut sources) = self.sources {
                sources.max_blast_radius_mb = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Set max total blast radius (accumulated) from CLI.
    pub fn with_max_total_blast_radius_mb(mut self, value: Option<f64>) -> Self {
        if value.is_some() {
            self.max_total_blast_radius_mb = value;
            if let Some(ref mut sources) = self.sources {
                sources.max_total_blast_radius_mb = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Override max kills from CLI.
    pub fn with_max_kills(mut self, value: Option<u32>) -> Self {
        if let Some(v) = value {
            // Use the more restrictive (smaller) value for safety
            self.max_kills = self.max_kills.min(v);
            if let Some(ref mut sources) = self.sources {
                sources.max_kills = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Override require_known_signature from CLI.
    pub fn with_require_known_signature(mut self, value: Option<bool>) -> Self {
        if let Some(v) = value {
            // For safety, if either policy or CLI requires it, require it
            self.require_known_signature = self.require_known_signature || v;
            if let Some(ref mut sources) = self.sources {
                sources.require_known_signature = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Override require_policy_snapshot from CLI.
    pub fn with_require_policy_snapshot(mut self, value: Option<bool>) -> Self {
        if let Some(v) = value {
            self.require_policy_snapshot = self.require_policy_snapshot || v;
            if let Some(ref mut sources) = self.sources {
                sources.require_policy_snapshot = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Add to exclude categories from CLI.
    pub fn with_exclude_categories(mut self, categories: Vec<String>) -> Self {
        if !categories.is_empty() {
            for cat in categories {
                if !self
                    .exclude_categories
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&cat))
                {
                    self.exclude_categories.push(cat);
                }
            }
            if let Some(ref mut sources) = self.sources {
                sources.exclude_categories = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Set allow categories from CLI (replaces policy if specified).
    pub fn with_allow_categories(mut self, categories: Option<Vec<String>>) -> Self {
        if let Some(cats) = categories {
            self.allow_categories = cats;
            if let Some(ref mut sources) = self.sources {
                sources.allow_categories = ConstraintSource::CliOverride;
            }
        }
        self
    }

    /// Get a summary of active constraints for logging/display.
    pub fn active_constraints_summary(&self) -> Vec<String> {
        let mut summary = Vec::new();

        if !self.enabled {
            summary.push("robot_mode: disabled".to_string());
            return summary;
        }

        summary.push(format!("min_posterior: {:.4}", self.min_posterior));
        summary.push(format!(
            "max_blast_radius_mb: {:.1}",
            self.max_blast_radius_mb
        ));

        if let Some(total) = self.max_total_blast_radius_mb {
            summary.push(format!("max_total_blast_radius_mb: {:.1}", total));
        }

        summary.push(format!("max_kills: {}", self.max_kills));

        if self.require_known_signature {
            summary.push("require_known_signature: true".to_string());
        }

        if self.require_policy_snapshot {
            summary.push("require_policy_snapshot: true".to_string());
        }

        if !self.allow_categories.is_empty() {
            summary.push(format!(
                "allow_categories: [{}]",
                self.allow_categories.join(", ")
            ));
        }

        if !self.exclude_categories.is_empty() {
            summary.push(format!(
                "exclude_categories: [{}]",
                self.exclude_categories.join(", ")
            ));
        }

        if self.require_human_for_supervised {
            summary.push("require_human_for_supervised: true".to_string());
        }

        summary
    }
}

/// Result of checking a candidate against robot constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintCheckResult {
    /// Whether the candidate is allowed.
    pub allowed: bool,

    /// List of constraint violations (empty if allowed).
    pub violations: Vec<ConstraintViolation>,

    /// Warnings that don't block but should be noted.
    pub warnings: Vec<String>,

    /// Metrics about this check.
    pub metrics: ConstraintMetrics,
}

impl ConstraintCheckResult {
    /// Create an allowed result.
    pub fn allowed(metrics: ConstraintMetrics) -> Self {
        Self {
            allowed: true,
            violations: Vec::new(),
            warnings: Vec::new(),
            metrics,
        }
    }

    /// Create a blocked result.
    pub fn blocked(violations: Vec<ConstraintViolation>, metrics: ConstraintMetrics) -> Self {
        Self {
            allowed: false,
            violations,
            warnings: Vec::new(),
            metrics,
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Details about a constraint violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintViolation {
    /// Which constraint was violated.
    pub constraint: ConstraintKind,

    /// Human-readable explanation.
    pub message: String,

    /// The threshold/limit that was exceeded.
    pub threshold: String,

    /// The actual value that violated the constraint.
    pub actual: String,

    /// Source of the constraint.
    pub source: ConstraintSource,

    /// Suggested remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Types of constraints that can be violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    /// Robot mode not enabled.
    RobotModeDisabled,
    /// Posterior below threshold.
    MinPosterior,
    /// Single candidate blast radius exceeded.
    MaxBlastRadius,
    /// Total accumulated blast radius exceeded.
    MaxTotalBlastRadius,
    /// Kill count exceeded.
    MaxKills,
    /// Known signature required but not present.
    RequireKnownSignature,
    /// Policy snapshot required but not attached.
    RequirePolicySnapshot,
    /// Category is in exclude list.
    ExcludedCategory,
    /// Category not in allow list.
    CategoryNotAllowed,
    /// Supervision detected and human confirmation required.
    RequireHumanForSupervised,
}

/// Metrics about a constraint check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintMetrics {
    /// Current kill count in this run.
    pub current_kills: u32,
    /// Remaining kills allowed.
    pub remaining_kills: u32,
    /// Accumulated blast radius (MB) so far.
    pub accumulated_blast_radius_mb: f64,
    /// Remaining blast radius budget (MB).
    pub remaining_blast_radius_mb: Option<f64>,
}

/// Stateful constraint checker for a single run.
///
/// Tracks accumulated state (kills, blast radius) across multiple candidates.
pub struct ConstraintChecker {
    /// The constraints to enforce.
    constraints: RuntimeRobotConstraints,

    /// Number of kills performed this run.
    kill_count: AtomicU32,

    /// Accumulated blast radius in bytes (stored as integer for atomics).
    accumulated_blast_bytes: AtomicU64,
}

impl ConstraintChecker {
    /// Create a new constraint checker.
    pub fn new(constraints: RuntimeRobotConstraints) -> Self {
        Self {
            constraints,
            kill_count: AtomicU32::new(0),
            accumulated_blast_bytes: AtomicU64::new(0),
        }
    }

    /// Get the current constraints.
    pub fn constraints(&self) -> &RuntimeRobotConstraints {
        &self.constraints
    }

    /// Check if a candidate passes all robot constraints.
    ///
    /// This does NOT increment counters - use `record_action()` after successful execution.
    pub fn check_candidate(&self, candidate: &RobotCandidate) -> ConstraintCheckResult {
        let mut violations = Vec::new();

        // Check if robot mode is enabled
        if !self.constraints.enabled {
            violations.push(ConstraintViolation {
                constraint: ConstraintKind::RobotModeDisabled,
                message: "Robot mode is not enabled".to_string(),
                threshold: "enabled: true".to_string(),
                actual: "enabled: false".to_string(),
                source: ConstraintSource::Policy,
                remediation: Some(
                    "Enable robot mode in policy.json or use --robot flag".to_string(),
                ),
            });
            return ConstraintCheckResult::blocked(violations, self.current_metrics());
        }

        // Block supervised processes unless human confirmation is allowed
        if self.constraints.require_human_for_supervised && candidate.is_supervised {
            violations.push(ConstraintViolation {
                constraint: ConstraintKind::RequireHumanForSupervised,
                message: "Process is supervised; requires explicit human confirmation".to_string(),
                threshold: "require_human_for_supervised: true".to_string(),
                actual: "is_supervised: true".to_string(),
                source: self
                    .constraints
                    .sources
                    .as_ref()
                    .map(|s| s.require_human_for_supervised)
                    .unwrap_or_default(),
                remediation: Some(
                    "Run interactively or disable require_human_for_supervised in policy.json"
                        .to_string(),
                ),
            });
        }

        // Check minimum posterior
        if let Some(posterior) = candidate.posterior {
            if posterior < self.constraints.min_posterior {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::MinPosterior,
                    message: format!(
                        "Posterior {:.4} is below minimum threshold {:.4}",
                        posterior, self.constraints.min_posterior
                    ),
                    threshold: format!("{:.4}", self.constraints.min_posterior),
                    actual: format!("{:.4}", posterior),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.min_posterior)
                        .unwrap_or_default(),
                    remediation: Some(
                        "Increase evidence confidence or lower min_posterior threshold".to_string(),
                    ),
                });
            }
        }

        // Check per-candidate blast radius
        if let Some(memory_mb) = candidate.memory_mb {
            if memory_mb > self.constraints.max_blast_radius_mb {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::MaxBlastRadius,
                    message: format!(
                        "Memory usage {:.1}MB exceeds per-candidate limit {:.1}MB",
                        memory_mb, self.constraints.max_blast_radius_mb
                    ),
                    threshold: format!("{:.1}MB", self.constraints.max_blast_radius_mb),
                    actual: format!("{:.1}MB", memory_mb),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.max_blast_radius_mb)
                        .unwrap_or_default(),
                    remediation: Some(
                        "Increase max_blast_radius_mb or handle this process manually".to_string(),
                    ),
                });
            }
        }

        // Check accumulated blast radius
        if let (Some(max_total), Some(memory_mb)) = (
            self.constraints.max_total_blast_radius_mb,
            candidate.memory_mb,
        ) {
            let current_mb =
                self.accumulated_blast_bytes.load(Ordering::Acquire) as f64 / (1024.0 * 1024.0);
            let projected = current_mb + memory_mb;

            if projected > max_total {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::MaxTotalBlastRadius,
                    message: format!(
                        "Would exceed total blast radius limit: {:.1}MB + {:.1}MB = {:.1}MB > {:.1}MB",
                        current_mb, memory_mb, projected, max_total
                    ),
                    threshold: format!("{:.1}MB total", max_total),
                    actual: format!("{:.1}MB projected", projected),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.max_total_blast_radius_mb)
                        .unwrap_or_default(),
                    remediation: Some(
                        "Increase max_total_blast_radius_mb or prioritize smaller processes"
                            .to_string(),
                    ),
                });
            }
        }

        // Check kill count (for kill actions only)
        if candidate.is_kill_action {
            let current = self.kill_count.load(Ordering::Acquire);
            if current >= self.constraints.max_kills {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::MaxKills,
                    message: format!(
                        "Kill count {} has reached limit {}",
                        current, self.constraints.max_kills
                    ),
                    threshold: format!("{} kills", self.constraints.max_kills),
                    actual: format!("{} kills performed", current),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.max_kills)
                        .unwrap_or_default(),
                    remediation: Some(
                        "Increase max_kills or handle remaining processes manually".to_string(),
                    ),
                });
            }
        }

        // Check known signature requirement
        if self.constraints.require_known_signature && !candidate.has_known_signature {
            violations.push(ConstraintViolation {
                constraint: ConstraintKind::RequireKnownSignature,
                message: "Process does not match any known signature".to_string(),
                threshold: "require_known_signature: true".to_string(),
                actual: "no signature match".to_string(),
                source: self
                    .constraints
                    .sources
                    .as_ref()
                    .map(|s| s.require_known_signature)
                    .unwrap_or_default(),
                remediation: Some(
                    "Add a signature for this process pattern or disable require_known_signature"
                        .to_string(),
                ),
            });
        }

        // Check policy snapshot requirement
        if self.constraints.require_policy_snapshot && !candidate.has_policy_snapshot {
            violations.push(ConstraintViolation {
                constraint: ConstraintKind::RequirePolicySnapshot,
                message: "Policy snapshot required but not attached".to_string(),
                threshold: "require_policy_snapshot: true".to_string(),
                actual: "policy_snapshot: missing".to_string(),
                source: self
                    .constraints
                    .sources
                    .as_ref()
                    .map(|s| s.require_policy_snapshot)
                    .unwrap_or_default(),
                remediation: Some(
                    "Attach policy snapshot to session or disable require_policy_snapshot"
                        .to_string(),
                ),
            });
        }

        // Check category exclusions
        if let Some(ref category) = candidate.category {
            let cat_lower = category.to_lowercase();

            // Check exclude list
            if self
                .constraints
                .exclude_categories
                .iter()
                .any(|c| c.to_lowercase() == cat_lower)
            {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::ExcludedCategory,
                    message: format!("Category '{}' is in the exclude list", category),
                    threshold: format!(
                        "exclude_categories: [{}]",
                        self.constraints.exclude_categories.join(", ")
                    ),
                    actual: format!("category: {}", category),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.exclude_categories)
                        .unwrap_or_default(),
                    remediation: Some(format!(
                        "Remove '{}' from exclude_categories or handle this process manually",
                        category
                    )),
                });
            }

            // Check allow list (if non-empty)
            if !self.constraints.allow_categories.is_empty()
                && !self
                    .constraints
                    .allow_categories
                    .iter()
                    .any(|c| c.to_lowercase() == cat_lower)
            {
                violations.push(ConstraintViolation {
                    constraint: ConstraintKind::CategoryNotAllowed,
                    message: format!("Category '{}' is not in the allow list", category),
                    threshold: format!(
                        "allow_categories: [{}]",
                        self.constraints.allow_categories.join(", ")
                    ),
                    actual: format!("category: {}", category),
                    source: self
                        .constraints
                        .sources
                        .as_ref()
                        .map(|s| s.allow_categories)
                        .unwrap_or_default(),
                    remediation: Some(format!(
                        "Add '{}' to allow_categories or handle this process manually",
                        category
                    )),
                });
            }
        }

        let metrics = self.current_metrics();

        if violations.is_empty() {
            ConstraintCheckResult::allowed(metrics)
        } else {
            ConstraintCheckResult::blocked(violations, metrics)
        }
    }

    /// Record that an action was successfully executed.
    ///
    /// Call this AFTER the action succeeds to update counters.
    pub fn record_action(&self, memory_bytes: u64, is_kill: bool) {
        if is_kill {
            self.kill_count.fetch_add(1, Ordering::Release);
        }
        // Use saturating add to prevent u64 wrapping that could bypass blast radius checks
        self.accumulated_blast_bytes
            .fetch_update(Ordering::Release, Ordering::Acquire, |current| {
                Some(current.saturating_add(memory_bytes))
            })
            .unwrap(); // safe: closure always returns Some
    }

    /// Get current metrics.
    pub fn current_metrics(&self) -> ConstraintMetrics {
        let current_kills = self.kill_count.load(Ordering::Acquire);
        let accumulated_bytes = self.accumulated_blast_bytes.load(Ordering::Acquire);
        let accumulated_mb = accumulated_bytes as f64 / (1024.0 * 1024.0);

        ConstraintMetrics {
            current_kills,
            remaining_kills: self.constraints.max_kills.saturating_sub(current_kills),
            accumulated_blast_radius_mb: accumulated_mb,
            remaining_blast_radius_mb: self
                .constraints
                .max_total_blast_radius_mb
                .map(|max| (max - accumulated_mb).max(0.0)),
        }
    }

    /// Reset counters for a new run.
    pub fn reset(&self) {
        self.kill_count.store(0, Ordering::Release);
        self.accumulated_blast_bytes.store(0, Ordering::Release);
    }
}

/// Candidate information needed for constraint checking.
#[derive(Debug, Clone, Default)]
pub struct RobotCandidate {
    /// Posterior probability for the predicted class.
    pub posterior: Option<f64>,

    /// Memory usage in MB.
    pub memory_mb: Option<f64>,

    /// Whether process has a known signature.
    pub has_known_signature: bool,

    /// Process category (e.g., "daemon", "shell").
    pub category: Option<String>,

    /// Whether the proposed action is a kill.
    pub is_kill_action: bool,

    /// Whether policy snapshot is attached (for require_policy_snapshot).
    pub has_policy_snapshot: bool,
    /// Whether process is supervised by an agent/IDE/CI.
    pub is_supervised: bool,
}

impl RobotCandidate {
    /// Create a new candidate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set posterior probability.
    pub fn with_posterior(mut self, posterior: f64) -> Self {
        self.posterior = Some(posterior);
        self
    }

    /// Set memory usage in MB.
    pub fn with_memory_mb(mut self, memory_mb: f64) -> Self {
        self.memory_mb = Some(memory_mb);
        self
    }

    /// Set known signature status.
    pub fn with_known_signature(mut self, has_signature: bool) -> Self {
        self.has_known_signature = has_signature;
        self
    }

    /// Set category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set whether this is a kill action.
    pub fn with_kill_action(mut self, is_kill: bool) -> Self {
        self.is_kill_action = is_kill;
        self
    }

    /// Set policy snapshot status.
    pub fn with_policy_snapshot(mut self, has_snapshot: bool) -> Self {
        self.has_policy_snapshot = has_snapshot;
        self
    }

    /// Set supervision status.
    pub fn with_supervised(mut self, supervised: bool) -> Self {
        self.is_supervised = supervised;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_robot_mode() -> RobotMode {
        RobotMode {
            enabled: true,
            min_posterior: 0.95,
            min_confidence: None,
            max_blast_radius_mb: 1024.0,
            max_kills: 5,
            require_known_signature: false,
            require_policy_snapshot: None,
            allow_categories: Vec::new(),
            exclude_categories: Vec::new(),
            require_human_for_supervised: true,
        }
    }

    #[test]
    fn test_constraints_from_policy() {
        let robot_mode = test_robot_mode();
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);

        assert!(constraints.enabled);
        assert_eq!(constraints.min_posterior, 0.95);
        assert_eq!(constraints.max_blast_radius_mb, 1024.0);
        assert_eq!(constraints.max_kills, 5);
        assert!(!constraints.require_known_signature);
    }

    #[test]
    fn test_cli_override_min_posterior() {
        let robot_mode = test_robot_mode();
        let constraints =
            RuntimeRobotConstraints::from_policy(&robot_mode).with_min_posterior(Some(0.99));

        assert_eq!(constraints.min_posterior, 0.99);
        assert_eq!(
            constraints.sources.as_ref().unwrap().min_posterior,
            ConstraintSource::CliOverride
        );
    }

    #[test]
    fn test_cli_override_max_kills_uses_minimum() {
        let robot_mode = test_robot_mode(); // max_kills = 5

        // CLI specifies lower value - should use it
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode).with_max_kills(Some(3));
        assert_eq!(constraints.max_kills, 3);

        // CLI specifies higher value - should use policy
        let constraints2 =
            RuntimeRobotConstraints::from_policy(&robot_mode).with_max_kills(Some(10));
        assert_eq!(constraints2.max_kills, 5);
    }

    #[test]
    fn test_disabled_constraints() {
        let constraints = RuntimeRobotConstraints::disabled();

        assert!(!constraints.enabled);
        assert_eq!(constraints.max_kills, u32::MAX);
    }

    #[test]
    fn test_checker_allows_valid_candidate() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(500.0)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_checker_blocks_low_posterior() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.80) // Below 0.95 threshold
            .with_memory_mb(500.0)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::MinPosterior));
    }

    #[test]
    fn test_checker_blocks_supervised_candidate() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.99)
            .with_memory_mb(100.0)
            .with_kill_action(true)
            .with_supervised(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::RequireHumanForSupervised));
    }

    #[test]
    fn test_checker_blocks_high_blast_radius() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(2000.0) // Above 1024MB threshold
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::MaxBlastRadius));
    }

    #[test]
    fn test_checker_tracks_kill_count() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode()); // max_kills = 5
        let checker = ConstraintChecker::new(constraints);

        // Record 5 kills
        for _ in 0..5 {
            checker.record_action(100 * 1024 * 1024, true); // 100MB each
        }

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(100.0)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::MaxKills));
    }

    #[test]
    fn test_checker_tracks_accumulated_blast_radius() {
        let mut robot_mode = test_robot_mode();
        robot_mode.max_blast_radius_mb = 1000.0; // Per-candidate

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
            .with_max_total_blast_radius_mb(Some(500.0)); // Total budget

        let checker = ConstraintChecker::new(constraints);

        // Record 300MB
        checker.record_action(300 * 1024 * 1024, false);

        // Try to add another 300MB (would exceed 500MB total)
        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(300.0)
            .with_kill_action(false);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::MaxTotalBlastRadius));
    }

    #[test]
    fn test_checker_blocks_excluded_category() {
        let mut robot_mode = test_robot_mode();
        robot_mode.exclude_categories = vec!["daemon".to_string()];

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(100.0)
            .with_category("daemon")
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::ExcludedCategory));
    }

    #[test]
    fn test_checker_blocks_category_not_in_allow_list() {
        let mut robot_mode = test_robot_mode();
        robot_mode.allow_categories = vec!["test".to_string(), "dev".to_string()];

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(100.0)
            .with_category("daemon") // Not in allow list
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::CategoryNotAllowed));
    }

    #[test]
    fn test_checker_requires_known_signature() {
        let mut robot_mode = test_robot_mode();
        robot_mode.require_known_signature = true;

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(100.0)
            .with_known_signature(false) // No signature
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::RequireKnownSignature));
    }

    #[test]
    fn test_checker_requires_policy_snapshot() {
        let mut robot_mode = test_robot_mode();
        robot_mode.require_policy_snapshot = Some(true);

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.98)
            .with_memory_mb(100.0)
            .with_policy_snapshot(false)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::RequirePolicySnapshot));
    }

    #[test]
    fn test_checker_metrics() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode())
            .with_max_total_blast_radius_mb(Some(1000.0));
        let checker = ConstraintChecker::new(constraints);

        checker.record_action(200 * 1024 * 1024, true); // 200MB kill
        checker.record_action(100 * 1024 * 1024, false); // 100MB non-kill

        let metrics = checker.current_metrics();
        assert_eq!(metrics.current_kills, 1);
        assert_eq!(metrics.remaining_kills, 4);
        assert!((metrics.accumulated_blast_radius_mb - 300.0).abs() < 1.0);
        assert!((metrics.remaining_blast_radius_mb.unwrap() - 700.0).abs() < 1.0);
    }

    #[test]
    fn test_checker_reset() {
        let constraints = RuntimeRobotConstraints::from_policy(&test_robot_mode());
        let checker = ConstraintChecker::new(constraints);

        checker.record_action(100 * 1024 * 1024, true);
        checker.reset();

        let metrics = checker.current_metrics();
        assert_eq!(metrics.current_kills, 0);
        assert_eq!(metrics.accumulated_blast_radius_mb, 0.0);
    }

    #[test]
    fn test_disabled_robot_mode_blocks() {
        let mut robot_mode = test_robot_mode();
        robot_mode.enabled = false;

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
        let checker = ConstraintChecker::new(constraints);

        let candidate = RobotCandidate::new()
            .with_posterior(0.99)
            .with_memory_mb(100.0)
            .with_kill_action(true);

        let result = checker.check_candidate(&candidate);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.constraint == ConstraintKind::RobotModeDisabled));
    }

    #[test]
    fn test_active_constraints_summary() {
        let mut robot_mode = test_robot_mode();
        robot_mode.require_known_signature = true;
        robot_mode.exclude_categories = vec!["daemon".to_string()];

        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
            .with_max_total_blast_radius_mb(Some(2048.0));

        let summary = constraints.active_constraints_summary();

        assert!(summary.iter().any(|s| s.contains("min_posterior")));
        assert!(summary.iter().any(|s| s.contains("max_blast_radius_mb")));
        assert!(summary
            .iter()
            .any(|s| s.contains("max_total_blast_radius_mb")));
        assert!(summary.iter().any(|s| s.contains("max_kills")));
        assert!(summary
            .iter()
            .any(|s| s.contains("require_known_signature")));
        assert!(summary.iter().any(|s| s.contains("exclude_categories")));
    }

    #[test]
    fn test_json_serialization() {
        let constraints =
            RuntimeRobotConstraints::from_policy(&test_robot_mode()).with_min_posterior(Some(0.99));

        let json = serde_json::to_string(&constraints).unwrap();
        assert!(json.contains("min_posterior"));
        assert!(json.contains("0.99"));

        let result = ConstraintCheckResult::blocked(
            vec![ConstraintViolation {
                constraint: ConstraintKind::MinPosterior,
                message: "Too low".to_string(),
                threshold: "0.95".to_string(),
                actual: "0.80".to_string(),
                source: ConstraintSource::Policy,
                remediation: None,
            }],
            ConstraintMetrics::default(),
        );

        let result_json = serde_json::to_string(&result).unwrap();
        assert!(result_json.contains("min_posterior"));
        assert!(result_json.contains("Too low"));
    }
}
