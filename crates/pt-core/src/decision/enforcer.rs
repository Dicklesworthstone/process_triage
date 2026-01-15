//! Policy enforcement engine for Process Triage.
//!
//! The PolicyEnforcer validates actions against policy.json rules. It sits between
//! the decision engine and action execution, blocking actions that violate safety
//! guardrails, rate limits, or robot mode gates.
//!
//! # Architecture
//!
//! ```text
//! Posterior → Decision → PolicyEnforcer → Executor
//!                              ↑
//!                        policy.json
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let enforcer = PolicyEnforcer::new(&policy)?;
//! let result = enforcer.check_action(&candidate, Action::Kill)?;
//! if let Some(violation) = result.violation {
//!     // Action blocked - show user why
//! }
//! ```

use crate::collect::{CriticalFile, DetectionStrength, ProcessState};
use crate::config::policy::{DataLossGates, Guardrails, PatternEntry, Policy, RobotMode};
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

use super::Action;

/// Errors during policy enforcement.
#[derive(Debug, Error)]
pub enum EnforcerError {
    #[error("invalid pattern at {path}: {message}")]
    InvalidPattern { path: String, message: String },

    #[error("policy validation failed: {0}")]
    PolicyInvalid(String),
}

/// Result of a policy check.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyCheckResult {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Violation details if blocked.
    pub violation: Option<PolicyViolation>,
    /// Warnings that don't block but should be noted.
    pub warnings: Vec<String>,
}

impl PolicyCheckResult {
    fn allowed() -> Self {
        Self {
            allowed: true,
            violation: None,
            warnings: Vec::new(),
        }
    }

    fn blocked(violation: PolicyViolation) -> Self {
        Self {
            allowed: false,
            violation: Some(violation),
            warnings: Vec::new(),
        }
    }

    fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Details about why an action was blocked.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyViolation {
    /// Category of violation.
    pub kind: ViolationKind,
    /// Human-readable explanation.
    pub message: String,
    /// Which policy rule triggered this.
    pub rule: String,
    /// Additional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Summary of critical files detected for a process.
#[derive(Debug, Clone, Serialize)]
pub struct CriticalFilesSummary {
    /// Number of hard (definite lock) detections.
    pub hard_count: usize,
    /// Number of soft (heuristic) detections.
    pub soft_count: usize,
    /// Rule IDs that matched.
    pub rules: Vec<String>,
    /// Human-readable remediation hints.
    pub remediation_hints: Vec<String>,
}

/// Categories of policy violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Process matches a protected pattern.
    ProtectedPattern,
    /// Process is in never_kill_pid list.
    ProtectedPid,
    /// Process parent is in never_kill_ppid list.
    ProtectedPpid,
    /// Process user is protected.
    ProtectedUser,
    /// Process group is protected.
    ProtectedGroup,
    /// Process category is protected.
    ProtectedCategory,
    /// Process is too young.
    MinAgeBreach,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Robot mode gate failed.
    RobotModeGate,
    /// Data loss gate triggered.
    DataLossGate,
    /// Force review required.
    ForceReview,
    /// Process state prevents action (zombie/D-state).
    ProcessStateInvalid,
}

/// Information about a process candidate for policy checking.
#[derive(Debug, Clone)]
pub struct ProcessCandidate {
    /// Process ID.
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// Command line (for pattern matching).
    pub cmdline: String,
    /// Process owner username.
    pub user: Option<String>,
    /// Process owner group.
    pub group: Option<String>,
    /// Process category (e.g., "daemon", "shell").
    pub category: Option<String>,
    /// Process age in seconds.
    pub age_seconds: u64,
    /// Posterior probability for the predicted class.
    pub posterior: Option<f64>,
    /// Memory usage in MB (for blast radius).
    pub memory_mb: Option<f64>,
    /// Whether process has known signature.
    pub has_known_signature: bool,
    /// Open write file descriptors.
    pub open_write_fds: Option<u32>,
    /// Whether process has locked files.
    pub has_locked_files: Option<bool>,
    /// Whether process has active TTY.
    pub has_active_tty: Option<bool>,
    /// Seconds since last I/O activity.
    pub seconds_since_io: Option<u64>,
    /// Whether process CWD is deleted.
    pub cwd_deleted: Option<bool>,
    /// Current process state (for zombie/D-state detection).
    pub process_state: Option<ProcessState>,
    /// Kernel wait channel (what D-state process is blocked on).
    pub wchan: Option<String>,
    /// Critical files detected (for data-loss safety gate).
    pub critical_files: Vec<CriticalFile>,
}

/// Compiled pattern for efficient matching.
#[derive(Debug, Clone)]
struct CompiledPattern {
    original: String,
    kind: PatternKind,
    regex: Option<Regex>,
    case_insensitive: bool,
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum PatternKind {
    Regex,
    Glob,
    Literal,
}

impl CompiledPattern {
    fn compile(entry: &PatternEntry, path: &str) -> Result<Self, EnforcerError> {
        let kind = match entry.kind.to_lowercase().as_str() {
            "regex" => PatternKind::Regex,
            "glob" => PatternKind::Glob,
            "literal" => PatternKind::Literal,
            other => {
                return Err(EnforcerError::InvalidPattern {
                    path: path.to_string(),
                    message: format!("unknown pattern kind: {other}"),
                })
            }
        };

        let regex = match kind {
            PatternKind::Regex => {
                let pattern = if entry.case_insensitive {
                    format!("(?i){}", entry.pattern)
                } else {
                    entry.pattern.clone()
                };
                Some(
                    Regex::new(&pattern).map_err(|e| EnforcerError::InvalidPattern {
                        path: path.to_string(),
                        message: e.to_string(),
                    })?,
                )
            }
            PatternKind::Glob => {
                // Convert glob to regex with proper handling of:
                // - ** for recursive matching (any depth)
                // - * for single segment wildcard
                // - ? for single character wildcard
                // - [...] for character classes
                let mut regex_str = String::from("^");
                let pattern = if entry.case_insensitive {
                    entry.pattern.to_lowercase()
                } else {
                    entry.pattern.clone()
                };
                let chars: Vec<char> = pattern.chars().collect();
                let mut i = 0;
                while i < chars.len() {
                    let c = chars[i];
                    match c {
                        '*' => {
                            // Check for ** (recursive match)
                            if i + 1 < chars.len() && chars[i + 1] == '*' {
                                regex_str.push_str(".*");
                                i += 2;
                                continue;
                            }
                            // Single * matches anything except path separator in some contexts,
                            // but for cmdline matching we use .*
                            regex_str.push_str(".*");
                        }
                        '?' => regex_str.push('.'),
                        '[' => {
                            // Character class - find matching ] and pass through
                            let start = i;
                            i += 1;
                            // Handle negation and initial ]
                            if i < chars.len() && (chars[i] == '!' || chars[i] == '^') {
                                i += 1;
                            }
                            if i < chars.len() && chars[i] == ']' {
                                i += 1;
                            }
                            // Find closing ]
                            while i < chars.len() && chars[i] != ']' {
                                i += 1;
                            }
                            if i < chars.len() {
                                // Valid character class - convert ! to ^ for negation
                                let class_content: String = chars[start..=i].iter().collect();
                                let converted = class_content.replace("[!", "[^");
                                regex_str.push_str(&converted);
                            } else {
                                // No closing ] - escape the [
                                regex_str.push_str("\\[");
                                i = start; // Reset to just after [
                            }
                        }
                        '.' | '+' | '(' | ')' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                            regex_str.push('\\');
                            regex_str.push(c);
                        }
                        _ => regex_str.push(c),
                    }
                    i += 1;
                }
                regex_str.push('$');
                let full_pattern = if entry.case_insensitive {
                    format!("(?i){}", regex_str)
                } else {
                    regex_str
                };
                Some(
                    Regex::new(&full_pattern).map_err(|e| EnforcerError::InvalidPattern {
                        path: path.to_string(),
                        message: e.to_string(),
                    })?,
                )
            }
            PatternKind::Literal => None, // Use string matching
        };

        Ok(Self {
            original: entry.pattern.clone(),
            kind,
            regex,
            case_insensitive: entry.case_insensitive,
            notes: entry.notes.clone(),
        })
    }

    fn matches(&self, text: &str) -> bool {
        match self.kind {
            PatternKind::Regex | PatternKind::Glob => self
                .regex
                .as_ref()
                .map(|r| r.is_match(text))
                .unwrap_or(false),
            PatternKind::Literal => {
                if self.case_insensitive {
                    text.to_lowercase().contains(&self.original.to_lowercase())
                } else {
                    text.contains(&self.original)
                }
            }
        }
    }
}

/// Rate limit tracker for kills.
#[derive(Debug)]
struct RateLimiter {
    /// Kills in current run.
    kills_this_run: AtomicU32,
    /// Maximum kills per run.
    max_per_run: u32,
    /// Kills with timestamps (for hourly/daily limits).
    /// In a real implementation, this would need synchronization and persistent storage.
    #[allow(dead_code)]
    hourly_limit: Option<u32>,
    #[allow(dead_code)]
    daily_limit: Option<u32>,
}

impl RateLimiter {
    fn new(guardrails: &Guardrails) -> Self {
        Self {
            kills_this_run: AtomicU32::new(0),
            max_per_run: guardrails.max_kills_per_run,
            hourly_limit: guardrails.max_kills_per_hour,
            daily_limit: guardrails.max_kills_per_day,
        }
    }

    fn check_and_increment(&self, override_limit: Option<u32>) -> Result<(), String> {
        // Use compare_exchange loop to avoid race condition.
        // The previous implementation (fetch_add + conditional fetch_sub) had a TOCTOU bug:
        // two threads could both increment, both see the overflow, and both decrement,
        // resulting in incorrect count and bypassed rate limiting.
        let limit = match override_limit {
            Some(l) => std::cmp::min(l, self.max_per_run),
            None => self.max_per_run,
        };

        loop {
            let current = self.kills_this_run.load(Ordering::Acquire);
            if current >= limit {
                return Err(format!(
                    "rate limit exceeded: {} kills already performed this run (max {})",
                    current, limit
                ));
            }
            // Attempt atomic increment only if value hasn't changed
            match self.kills_this_run.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue, // Value changed, retry
            }
        }
    }

    fn reset_run_counter(&self) {
        self.kills_this_run.store(0, Ordering::SeqCst);
    }

    fn current_run_count(&self) -> u32 {
        self.kills_this_run.load(Ordering::SeqCst)
    }
}

/// Policy enforcement engine.
///
/// Thread-safe, designed for long-running daemon mode with hot-reload support.
pub struct PolicyEnforcer {
    /// Compiled protected patterns.
    protected_patterns: Vec<CompiledPattern>,
    /// Compiled force-review patterns.
    force_review_patterns: Vec<CompiledPattern>,
    /// Protected users (lowercase for case-insensitive matching).
    protected_users: HashSet<String>,
    /// Protected groups (lowercase).
    protected_groups: HashSet<String>,
    /// Protected categories (lowercase).
    protected_categories: HashSet<String>,
    /// Never kill these PIDs.
    never_kill_pid: HashSet<i32>,
    /// Never kill children of these PPIDs.
    never_kill_ppid: HashSet<i32>,
    /// Minimum process age in seconds.
    min_age_seconds: u64,
    /// Whether confirmation is required.
    require_confirmation: bool,
    /// Rate limiter.
    rate_limiter: Arc<RateLimiter>,
    /// Robot mode settings.
    robot_mode: RobotMode,
    /// Data loss gates.
    data_loss_gates: DataLossGates,
    /// Policy snapshot timestamp for hot-reload detection.
    loaded_at: Instant,
}

impl PolicyEnforcer {
    /// Create a new enforcer from a policy.
    pub fn new(policy: &Policy) -> Result<Self, EnforcerError> {
        // Compile protected patterns
        let protected_patterns = policy
            .guardrails
            .protected_patterns
            .iter()
            .enumerate()
            .map(|(i, p)| {
                CompiledPattern::compile(p, &format!("guardrails.protected_patterns[{i}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Compile force-review patterns
        let force_review_patterns = policy
            .guardrails
            .force_review_patterns
            .iter()
            .enumerate()
            .map(|(i, p)| {
                CompiledPattern::compile(p, &format!("guardrails.force_review_patterns[{i}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Build lookup sets (lowercase for case-insensitive matching)
        let protected_users: HashSet<String> = policy
            .guardrails
            .protected_users
            .iter()
            .map(|u| u.to_lowercase())
            .collect();

        let protected_groups: HashSet<String> = policy
            .guardrails
            .protected_groups
            .iter()
            .map(|g| g.to_lowercase())
            .collect();

        let protected_categories: HashSet<String> = policy
            .guardrails
            .protected_categories
            .iter()
            .map(|c| c.to_lowercase())
            .collect();

        let never_kill_pid: HashSet<i32> =
            policy.guardrails.never_kill_pid.iter().copied().collect();
        let never_kill_ppid: HashSet<i32> =
            policy.guardrails.never_kill_ppid.iter().copied().collect();

        Ok(Self {
            protected_patterns,
            force_review_patterns,
            protected_users,
            protected_groups,
            protected_categories,
            never_kill_pid,
            never_kill_ppid,
            min_age_seconds: policy.guardrails.min_process_age_seconds,
            require_confirmation: policy.guardrails.require_confirmation.unwrap_or(true),
            rate_limiter: Arc::new(RateLimiter::new(&policy.guardrails)),
            robot_mode: policy.robot_mode.clone(),
            data_loss_gates: policy.data_loss_gates.clone(),
            loaded_at: Instant::now(),
        })
    }

    /// Check if an action is allowed for a candidate.
    ///
    /// Returns a result indicating whether the action is allowed, and if not,
    /// detailed information about why it was blocked.
    pub fn check_action(
        &self,
        candidate: &ProcessCandidate,
        action: Action,
        robot_mode: bool,
    ) -> PolicyCheckResult {
        let mut warnings = Vec::new();
        // Only enforce most rules for destructive actions
        let is_destructive = matches!(action, Action::Kill | Action::Restart);

        // Check protected PIDs (always, for any action)
        if self.never_kill_pid.contains(&candidate.pid) {
            return PolicyCheckResult::blocked(PolicyViolation {
                kind: ViolationKind::ProtectedPid,
                message: format!("PID {} is in the never_kill_pid list", candidate.pid),
                rule: "guardrails.never_kill_pid".to_string(),
                context: None,
            });
        }

        // Check protected PPIDs
        if self.never_kill_ppid.contains(&candidate.ppid) {
            return PolicyCheckResult::blocked(PolicyViolation {
                kind: ViolationKind::ProtectedPpid,
                message: format!(
                    "PID {} has parent {} which is in never_kill_ppid list",
                    candidate.pid, candidate.ppid
                ),
                rule: "guardrails.never_kill_ppid".to_string(),
                context: None,
            });
        }

        // Check process state constraints (zombie/D-state)
        // These are fundamental constraints: you cannot kill a zombie (already dead)
        // and killing D-state processes usually fails (stuck in kernel I/O)
        if let Some(ref state) = candidate.process_state {
            if let Some(violation) = self.check_process_state_constraints(candidate, state, action)
            {
                return PolicyCheckResult::blocked(violation);
            }
        }

        // Check protected patterns
        for pattern in &self.protected_patterns {
            if pattern.matches(&candidate.cmdline) {
                return PolicyCheckResult::blocked(PolicyViolation {
                    kind: ViolationKind::ProtectedPattern,
                    message: format!("command matches protected pattern: {}", pattern.original),
                    rule: "guardrails.protected_patterns".to_string(),
                    context: pattern.notes.clone(),
                });
            }
        }

        // Check protected user
        if let Some(ref user) = candidate.user {
            if self.protected_users.contains(&user.to_lowercase()) {
                return PolicyCheckResult::blocked(PolicyViolation {
                    kind: ViolationKind::ProtectedUser,
                    message: format!("user '{}' is protected", user),
                    rule: "guardrails.protected_users".to_string(),
                    context: None,
                });
            }
        }

        // Check protected group
        if let Some(ref group) = candidate.group {
            if self.protected_groups.contains(&group.to_lowercase()) {
                return PolicyCheckResult::blocked(PolicyViolation {
                    kind: ViolationKind::ProtectedGroup,
                    message: format!("group '{}' is protected", group),
                    rule: "guardrails.protected_groups".to_string(),
                    context: None,
                });
            }
        }

        // Check protected category
        if let Some(ref category) = candidate.category {
            if self.protected_categories.contains(&category.to_lowercase()) {
                return PolicyCheckResult::blocked(PolicyViolation {
                    kind: ViolationKind::ProtectedCategory,
                    message: format!("category '{}' is protected", category),
                    rule: "guardrails.protected_categories".to_string(),
                    context: None,
                });
            }
        }

        // Check force-review patterns (only blocks in robot mode)
        for pattern in &self.force_review_patterns {
            if pattern.matches(&candidate.cmdline) {
                if robot_mode {
                    return PolicyCheckResult::blocked(PolicyViolation {
                        kind: ViolationKind::ForceReview,
                        message: format!(
                            "command matches force_review pattern (robot mode): {}",
                            pattern.original
                        ),
                        rule: "guardrails.force_review_patterns".to_string(),
                        context: pattern.notes.clone(),
                    });
                }
                // In interactive mode, just warn and continue evaluating other gates
                warnings.push(format!(
                    "matches force_review pattern: {} ({})",
                    pattern.original,
                    pattern.notes.as_deref().unwrap_or("requires manual review")
                ));
                break;
            }
        }

        // Check minimum age (only for destructive actions)
        if is_destructive && candidate.age_seconds < self.min_age_seconds {
            return PolicyCheckResult::blocked(PolicyViolation {
                kind: ViolationKind::MinAgeBreach,
                message: format!(
                    "process age {}s is below minimum {}s",
                    candidate.age_seconds, self.min_age_seconds
                ),
                rule: "guardrails.min_process_age_seconds".to_string(),
                context: None,
            });
        }

        // Check robot mode gates
        if robot_mode {
            if let Some(violation) = self.check_robot_mode_gates(candidate, action) {
                return PolicyCheckResult::blocked(violation);
            }
        }

        // Check data loss gates (only for destructive actions)
        if is_destructive {
            if let Some(violation) = self.check_data_loss_gates(candidate) {
                return PolicyCheckResult::blocked(violation);
            }
        }

        // Check rate limits (only for kills)
        if action == Action::Kill {
            let limit = if robot_mode {
                Some(self.robot_mode.max_kills)
            } else {
                None
            };

            if let Err(msg) = self.rate_limiter.check_and_increment(limit) {
                return PolicyCheckResult::blocked(PolicyViolation {
                    kind: ViolationKind::RateLimitExceeded,
                    message: msg,
                    rule: "guardrails.max_kills_per_run".to_string(),
                    context: None,
                });
            }
        }

        let mut result = PolicyCheckResult::allowed();
        for warning in warnings {
            result = result.with_warning(warning);
        }
        result
    }

    /// Check robot mode specific gates.
    fn check_robot_mode_gates(
        &self,
        candidate: &ProcessCandidate,
        _action: Action,
    ) -> Option<PolicyViolation> {
        // Robot mode must be enabled
        if !self.robot_mode.enabled {
            return Some(PolicyViolation {
                kind: ViolationKind::RobotModeGate,
                message: "robot_mode.enabled is false".to_string(),
                rule: "robot_mode.enabled".to_string(),
                context: None,
            });
        }

        // Check minimum posterior
        if let Some(posterior) = candidate.posterior {
            if posterior < self.robot_mode.min_posterior {
                return Some(PolicyViolation {
                    kind: ViolationKind::RobotModeGate,
                    message: format!(
                        "posterior {:.4} is below robot_mode.min_posterior {:.4}",
                        posterior, self.robot_mode.min_posterior
                    ),
                    rule: "robot_mode.min_posterior".to_string(),
                    context: None,
                });
            }
        }

        // Check blast radius
        if let Some(memory_mb) = candidate.memory_mb {
            if memory_mb > self.robot_mode.max_blast_radius_mb {
                return Some(PolicyViolation {
                    kind: ViolationKind::RobotModeGate,
                    message: format!(
                        "memory usage {:.1}MB exceeds robot_mode.max_blast_radius_mb {:.1}MB",
                        memory_mb, self.robot_mode.max_blast_radius_mb
                    ),
                    rule: "robot_mode.max_blast_radius_mb".to_string(),
                    context: None,
                });
            }
        }

        // Check known signature requirement
        if self.robot_mode.require_known_signature && !candidate.has_known_signature {
            return Some(PolicyViolation {
                kind: ViolationKind::RobotModeGate,
                message:
                    "robot_mode.require_known_signature is true but process has no known signature"
                        .to_string(),
                rule: "robot_mode.require_known_signature".to_string(),
                context: None,
            });
        }

        // Check category exclusions
        if let Some(ref category) = candidate.category {
            let cat_lower = category.to_lowercase();
            if self
                .robot_mode
                .exclude_categories
                .iter()
                .any(|c| c.to_lowercase() == cat_lower)
            {
                return Some(PolicyViolation {
                    kind: ViolationKind::RobotModeGate,
                    message: format!(
                        "category '{}' is in robot_mode.exclude_categories",
                        category
                    ),
                    rule: "robot_mode.exclude_categories".to_string(),
                    context: None,
                });
            }

            // If allow_categories is non-empty, category must be in it
            if !self.robot_mode.allow_categories.is_empty()
                && !self
                    .robot_mode
                    .allow_categories
                    .iter()
                    .any(|c| c.to_lowercase() == cat_lower)
            {
                return Some(PolicyViolation {
                    kind: ViolationKind::RobotModeGate,
                    message: format!(
                        "category '{}' is not in robot_mode.allow_categories",
                        category
                    ),
                    rule: "robot_mode.allow_categories".to_string(),
                    context: None,
                });
            }
        }

        // Check for hard critical files - these always block kill-like actions in robot mode
        // This is a data-loss safety gate: killing processes with active locks/writes is too risky
        // for automation to handle without human review
        if self.has_hard_critical_files(candidate) {
            // Find the first hard critical file for the message
            if let Some(cf) = candidate
                .critical_files
                .iter()
                .find(|cf| cf.strength == DetectionStrength::Hard)
            {
                return Some(PolicyViolation {
                    kind: ViolationKind::RobotModeGate,
                    message: format!(
                        "robot mode blocked: process has hard critical file '{}' (rule: {})",
                        cf.path, cf.rule_id
                    ),
                    rule: "robot_mode.data_loss_gate".to_string(),
                    context: Some(format!(
                        "Detected {:?} lock. Remediation: {}",
                        cf.category,
                        cf.category.remediation_hint()
                    )),
                });
            }
        }

        None
    }

    /// Check data loss prevention gates.
    ///
    /// Returns a violation if any critical file patterns are detected or if generic
    /// data loss conditions are met. Hard detections (definite locks) always block;
    /// soft detections (heuristics) provide warnings with remediation hints.
    fn check_data_loss_gates(&self, candidate: &ProcessCandidate) -> Option<PolicyViolation> {
        // Check critical files first - these provide the most specific information
        // Hard detections block immediately with remediation guidance
        for cf in &candidate.critical_files {
            if cf.strength == DetectionStrength::Hard {
                return Some(PolicyViolation {
                    kind: ViolationKind::DataLossGate,
                    message: format!(
                        "process has critical lock: {} ({})",
                        cf.path,
                        cf.category.remediation_hint()
                    ),
                    rule: format!("data_loss_gates.critical_file.{}", cf.rule_id),
                    context: Some(format!(
                        "Detected {} with rule '{}'. Remediation: {}",
                        format!("{:?}", cf.category).to_lowercase(),
                        cf.rule_id,
                        cf.category.remediation_hint()
                    )),
                });
            }
        }

        // Check open write FDs
        if self.data_loss_gates.block_if_open_write_fds {
            if let Some(fds) = candidate.open_write_fds {
                let max_fds = self.data_loss_gates.max_open_write_fds.unwrap_or(0);
                if fds > max_fds {
                    // If we have soft critical files, include them in the message
                    let soft_files: Vec<_> = candidate
                        .critical_files
                        .iter()
                        .filter(|cf| cf.strength == DetectionStrength::Soft)
                        .collect();

                    let context = if soft_files.is_empty() {
                        "killing may cause data loss".to_string()
                    } else {
                        let hints: Vec<_> = soft_files
                            .iter()
                            .map(|cf| format!("{}: {}", cf.path, cf.category.remediation_hint()))
                            .collect();
                        format!(
                            "killing may cause data loss. Detected files:\n{}",
                            hints.join("\n")
                        )
                    };

                    return Some(PolicyViolation {
                        kind: ViolationKind::DataLossGate,
                        message: format!(
                            "process has {} open write FDs (max allowed: {})",
                            fds, max_fds
                        ),
                        rule: "data_loss_gates.block_if_open_write_fds".to_string(),
                        context: Some(context),
                    });
                }
            }
        }

        // Check locked files
        if self.data_loss_gates.block_if_locked_files && candidate.has_locked_files == Some(true) {
            return Some(PolicyViolation {
                kind: ViolationKind::DataLossGate,
                message: "process has locked files".to_string(),
                rule: "data_loss_gates.block_if_locked_files".to_string(),
                context: Some("killing may corrupt locked files".to_string()),
            });
        }

        // Check active TTY
        if self.data_loss_gates.block_if_active_tty && candidate.has_active_tty == Some(true) {
            return Some(PolicyViolation {
                kind: ViolationKind::DataLossGate,
                message: "process has active TTY".to_string(),
                rule: "data_loss_gates.block_if_active_tty".to_string(),
                context: Some("process may be interactive".to_string()),
            });
        }

        // Check deleted CWD
        if self.data_loss_gates.block_if_deleted_cwd == Some(true)
            && candidate.cwd_deleted == Some(true)
        {
            return Some(PolicyViolation {
                kind: ViolationKind::DataLossGate,
                message: "process CWD is deleted".to_string(),
                rule: "data_loss_gates.block_if_deleted_cwd".to_string(),
                context: Some("process may be orphaned or stale".to_string()),
            });
        }

        // Check recent I/O
        if let Some(threshold) = self.data_loss_gates.block_if_recent_io_seconds {
            if let Some(since_io) = candidate.seconds_since_io {
                if since_io < threshold {
                    return Some(PolicyViolation {
                        kind: ViolationKind::DataLossGate,
                        message: format!(
                            "process had I/O {}s ago (threshold: {}s)",
                            since_io, threshold
                        ),
                        rule: "data_loss_gates.block_if_recent_io_seconds".to_string(),
                        context: Some("process may be actively writing".to_string()),
                    });
                }
            }
        }

        None
    }

    /// Check if any hard critical files are detected for this candidate.
    ///
    /// This is used for robot mode blocking - hard detections always block
    /// kill-like actions in robot mode.
    pub fn has_hard_critical_files(&self, candidate: &ProcessCandidate) -> bool {
        candidate
            .critical_files
            .iter()
            .any(|cf| cf.strength == DetectionStrength::Hard)
    }

    /// Get a summary of critical files for reporting.
    pub fn critical_files_summary(&self, candidate: &ProcessCandidate) -> Option<CriticalFilesSummary> {
        if candidate.critical_files.is_empty() {
            return None;
        }

        let hard_count = candidate
            .critical_files
            .iter()
            .filter(|cf| cf.strength == DetectionStrength::Hard)
            .count();

        let soft_count = candidate
            .critical_files
            .iter()
            .filter(|cf| cf.strength == DetectionStrength::Soft)
            .count();

        let rules: Vec<_> = candidate
            .critical_files
            .iter()
            .map(|cf| cf.rule_id.clone())
            .collect();

        let remediation_hints: Vec<_> = candidate
            .critical_files
            .iter()
            .map(|cf| cf.category.remediation_hint().to_string())
            .collect();

        Some(CriticalFilesSummary {
            hard_count,
            soft_count,
            rules,
            remediation_hints,
        })
    }

    /// Check process state constraints for zombie and D-state processes.
    ///
    /// Zombie processes are already dead and cannot be killed - the parent must reap them.
    /// D-state processes are stuck in uninterruptible kernel I/O and may ignore SIGKILL.
    fn check_process_state_constraints(
        &self,
        candidate: &ProcessCandidate,
        state: &ProcessState,
        action: Action,
    ) -> Option<PolicyViolation> {
        // Only check for destructive signal-based actions
        let is_signal_action = matches!(action, Action::Kill | Action::Pause | Action::Resume);
        if !is_signal_action {
            return None;
        }

        // Zombie processes: cannot be killed, they're already dead
        if state.is_zombie() {
            return Some(PolicyViolation {
                kind: ViolationKind::ProcessStateInvalid,
                message: format!(
                    "PID {} is a zombie (Z state): process is already dead, \
                     only its parent (PPID {}) can reap it",
                    candidate.pid, candidate.ppid
                ),
                rule: "process_state.zombie".to_string(),
                context: Some(
                    "Zombie processes cannot be killed. Consider restarting the parent \
                     process or its supervisor to clean up the zombie."
                        .to_string(),
                ),
            });
        }

        // D-state processes: may not respond to signals
        if state.is_disksleep() && action == Action::Kill {
            let wchan_info = candidate
                .wchan
                .as_ref()
                .map(|w| format!(" (blocked in kernel: {})", w))
                .unwrap_or_default();

            return Some(PolicyViolation {
                kind: ViolationKind::ProcessStateInvalid,
                message: format!(
                    "PID {} is in uninterruptible sleep (D state){}: \
                     kill action is unreliable and may fail",
                    candidate.pid, wchan_info
                ),
                rule: "process_state.disksleep".to_string(),
                context: Some(
                    "D-state processes are blocked in kernel I/O and may ignore SIGKILL. \
                     Consider investigating the underlying I/O issue (check mounts, \
                     disk health, NFS locks) instead of killing."
                        .to_string(),
                ),
            });
        }

        None
    }

    /// Reset rate limit counters (call at start of new run).
    pub fn reset_run_counters(&self) {
        self.rate_limiter.reset_run_counter();
    }

    /// Get current kill count for this run.
    pub fn current_run_kill_count(&self) -> u32 {
        self.rate_limiter.current_run_count()
    }

    /// Check if the enforcer requires confirmation for actions.
    pub fn requires_confirmation(&self) -> bool {
        self.require_confirmation
    }

    /// Get time since policy was loaded.
    pub fn policy_age(&self) -> Duration {
        self.loaded_at.elapsed()
    }

    /// Check if policy should be reloaded (for daemon mode).
    pub fn should_reload(&self, max_age: Duration) -> bool {
        self.policy_age() > max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::Policy;

    fn test_policy() -> Policy {
        Policy::default()
    }

    fn test_candidate() -> ProcessCandidate {
        ProcessCandidate {
            pid: 12345,
            ppid: 1000,
            cmdline: "/usr/bin/test-process --flag".to_string(),
            user: Some("testuser".to_string()),
            group: Some("testgroup".to_string()),
            category: Some("shell".to_string()),
            age_seconds: 7200,
            posterior: Some(0.95),
            memory_mb: Some(100.0),
            has_known_signature: false,
            open_write_fds: Some(0),
            has_locked_files: Some(false),
            has_active_tty: Some(false),
            seconds_since_io: Some(120),
            cwd_deleted: Some(false),
            process_state: None, // Normal processes have no special state
            wchan: None,
            critical_files: Vec::new(),
        }
    }

    #[test]
    fn test_enforcer_creation() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy);
        assert!(enforcer.is_ok());
    }

    #[test]
    fn test_allowed_action() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let candidate = test_candidate();

        let result = enforcer.check_action(&candidate, Action::Keep, false);
        assert!(result.allowed);
        assert!(result.violation.is_none());
    }

    #[test]
    fn test_protected_pid_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.pid = 1; // init process

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProtectedPid
        );
    }

    #[test]
    fn test_protected_ppid_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.ppid = 1; // child of init

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProtectedPpid
        );
    }

    #[test]
    fn test_protected_pattern_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "/usr/bin/sshd -D".to_string();

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProtectedPattern
        );
    }

    #[test]
    fn test_protected_user_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.user = Some("root".to_string());

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProtectedUser
        );
    }

    #[test]
    fn test_min_age_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.age_seconds = 60; // 1 minute, below default 1 hour

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::MinAgeBreach
        );
    }

    #[test]
    fn test_rate_limit() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let candidate = test_candidate();

        // Default max_kills_per_run is 5
        for i in 0..5 {
            let result = enforcer.check_action(&candidate, Action::Kill, false);
            assert!(result.allowed, "kill {} should be allowed", i + 1);
        }

        // 6th kill should be blocked
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::RateLimitExceeded
        );
    }

    #[test]
    fn test_rate_limit_reset() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let candidate = test_candidate();

        // Use up rate limit
        for _ in 0..5 {
            enforcer.check_action(&candidate, Action::Kill, false);
        }

        // Reset
        enforcer.reset_run_counters();

        // Should be allowed again
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_robot_mode_disabled_blocks() {
        let policy = test_policy(); // robot_mode.enabled = false by default
        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let candidate = test_candidate();

        let result = enforcer.check_action(&candidate, Action::Kill, true);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::RobotModeGate
        );
    }

    #[test]
    fn test_robot_mode_posterior_gate() {
        let mut policy = test_policy();
        policy.robot_mode.enabled = true;
        policy.robot_mode.min_posterior = 0.99;

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.posterior = Some(0.95); // Below threshold

        let result = enforcer.check_action(&candidate, Action::Kill, true);
        assert!(!result.allowed);
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("posterior"));
    }

    #[test]
    fn test_robot_mode_blast_radius_gate() {
        let mut policy = test_policy();
        policy.robot_mode.enabled = true;
        policy.robot_mode.min_posterior = 0.90;
        policy.robot_mode.max_blast_radius_mb = 50.0;

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.posterior = Some(0.99);
        candidate.memory_mb = Some(100.0); // Above threshold

        let result = enforcer.check_action(&candidate, Action::Kill, true);
        assert!(!result.allowed);
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("memory"));
    }

    #[test]
    fn test_data_loss_gate_open_fds() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.open_write_fds = Some(5); // Has open write FDs

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::DataLossGate
        );
    }

    #[test]
    fn test_data_loss_gate_locked_files() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.has_locked_files = Some(true);

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("locked"));
    }

    #[test]
    fn test_data_loss_gate_active_tty() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.has_active_tty = Some(true);

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert!(result.violation.as_ref().unwrap().message.contains("TTY"));
    }

    #[test]
    fn test_data_loss_gate_recent_io() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.seconds_since_io = Some(30); // Recent I/O (threshold is 60s)

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert!(result.violation.as_ref().unwrap().message.contains("I/O"));
    }

    #[test]
    fn test_force_review_pattern_warning_in_interactive() {
        let mut policy = test_policy();
        policy.guardrails.force_review_patterns = vec![PatternEntry {
            pattern: "kubectl".to_string(),
            kind: "literal".to_string(),
            case_insensitive: true,
            notes: Some("k8s tool".to_string()),
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "kubectl get pods".to_string();

        // Interactive mode: should be allowed with warning
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed);
        assert!(!result.warnings.is_empty());

        // Robot mode: should be blocked
        let result = enforcer.check_action(&candidate, Action::Kill, true);
        // This will fail first on robot_mode.enabled being false
        assert!(!result.allowed);
    }

    #[test]
    fn test_glob_pattern_matching() {
        let mut policy = test_policy();
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "*.test".to_string(),
            kind: "glob".to_string(),
            case_insensitive: true,
            notes: None,
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "myapp.test".to_string();

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
    }

    #[test]
    fn test_glob_double_star_recursive() {
        // Test that ** matches any path depth (greedy .* in regex)
        let mut policy = test_policy();
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "/usr/**important".to_string(),
            kind: "glob".to_string(),
            case_insensitive: false,
            notes: None,
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "/usr/local/bin/important".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "** should match any characters");

        candidate.cmdline = "/usr/important".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "** should also match zero characters");

        // Test that ** is different from single *
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "test*end".to_string(),
            kind: "glob".to_string(),
            case_insensitive: false,
            notes: None,
        }];
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        candidate.cmdline = "testmiddleend".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "* should match any characters");
    }

    #[test]
    fn test_glob_character_class() {
        // Test that [...] character classes work
        let mut policy = test_policy();
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "process[0-9]".to_string(),
            kind: "glob".to_string(),
            case_insensitive: false,
            notes: None,
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "process5".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "[0-9] should match digits");

        candidate.cmdline = "processX".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed, "[0-9] should not match letters");
    }

    #[test]
    fn test_glob_negated_character_class() {
        // Test that [!...] negated character classes work
        let mut policy = test_policy();
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "proc[!0-9]".to_string(),
            kind: "glob".to_string(),
            case_insensitive: false,
            notes: None,
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "procX".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "[!0-9] should match non-digits");

        candidate.cmdline = "proc5".to_string();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed, "[!0-9] should not match digits");
    }

    #[test]
    fn test_literal_pattern_matching() {
        let mut policy = test_policy();
        policy.guardrails.protected_patterns = vec![PatternEntry {
            pattern: "critical-service".to_string(),
            kind: "literal".to_string(),
            case_insensitive: true,
            notes: None,
        }];

        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.cmdline = "/usr/bin/critical-service --daemon".to_string();

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
    }

    #[test]
    fn test_protected_category_blocked() {
        let policy = test_policy(); // default has "daemon" and "system" protected
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.category = Some("daemon".to_string());

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProtectedCategory
        );
    }

    #[test]
    fn test_keep_action_not_rate_limited() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let candidate = test_candidate();

        // Exhaust rate limit with kills
        for _ in 0..5 {
            enforcer.check_action(&candidate, Action::Kill, false);
        }

        // Keep should still work
        let result = enforcer.check_action(&candidate, Action::Keep, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_policy_age_tracking() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let age = enforcer.policy_age();
        assert!(age.as_millis() < 1000); // Should be very recent

        assert!(!enforcer.should_reload(Duration::from_secs(3600)));
    }

    #[test]
    fn test_rate_limit_robot_mode() {
        let mut policy = test_policy();
        policy.robot_mode.enabled = true;
        policy.robot_mode.max_kills = 3;
        policy.guardrails.max_kills_per_run = 10; // Global is higher

        let enforcer = PolicyEnforcer::new(&policy).unwrap();
        let mut candidate = test_candidate();
        candidate.posterior = Some(0.99); // Pass posterior gate

        // 3 kills allowed
        for i in 0..3 {
            let result = enforcer.check_action(&candidate, Action::Kill, true);
            assert!(result.allowed, "kill {} should be allowed", i + 1);
        }

        // 4th kill blocked by robot limit
        let result = enforcer.check_action(&candidate, Action::Kill, true);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::RateLimitExceeded
        );
    }

    #[test]
    fn test_zombie_process_kill_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::Zombie);

        // Kill action should be blocked for zombie
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProcessStateInvalid
        );
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("zombie"));
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains(&format!("PPID {}", candidate.ppid)));
    }

    #[test]
    fn test_zombie_process_pause_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::Zombie);

        // Pause action should also be blocked for zombie
        let result = enforcer.check_action(&candidate, Action::Pause, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProcessStateInvalid
        );
    }

    #[test]
    fn test_zombie_process_keep_allowed() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::Zombie);

        // Keep action should be allowed even for zombie
        let result = enforcer.check_action(&candidate, Action::Keep, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_disksleep_process_kill_blocked() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::DiskSleep);
        candidate.wchan = Some("nfs_wait".to_string());

        // Kill action should be blocked for D-state
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::ProcessStateInvalid
        );
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("uninterruptible sleep"));
        assert!(result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("nfs_wait"));
    }

    #[test]
    fn test_disksleep_process_pause_allowed() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::DiskSleep);

        // Pause action is technically allowed for D-state (not blocked like Kill)
        // The process might respond to SIGSTOP eventually
        let result = enforcer.check_action(&candidate, Action::Pause, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_disksleep_process_without_wchan() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::DiskSleep);
        candidate.wchan = None; // No wchan info available

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);
        // Should still block but message won't include wchan details
        assert!(!result
            .violation
            .as_ref()
            .unwrap()
            .message
            .contains("blocked in kernel"));
    }

    #[test]
    fn test_normal_running_process_allowed() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::Running);

        // Running process can be killed
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_sleeping_process_allowed() {
        let policy = test_policy();
        let enforcer = PolicyEnforcer::new(&policy).unwrap();

        let mut candidate = test_candidate();
        candidate.process_state = Some(ProcessState::Sleeping);

        // Sleeping process can be killed
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed);
    }
}
