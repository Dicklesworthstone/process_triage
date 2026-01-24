//! Pattern learning from user decisions.
//!
//! This module provides functionality to learn process patterns from user
//! kill/spare decisions. It handles:
//!
//! - **Command normalization**: Converting raw command strings to matchable patterns
//! - **Pattern candidate generation**: Creating patterns at different specificity levels
//! - **Pattern generalization**: Building broader patterns from observed instances
//!
//! # Normalization Strategy
//!
//! Commands are normalized to create patterns that can match similar future processes:
//!
//! ```text
//! Raw:        /usr/bin/node /home/user/project/node_modules/.bin/jest --watch tests/
//! Normalized: node .*/jest --watch .*
//!
//! Raw:        python3 -m pytest /home/user/app/tests/test_api.py -v
//! Normalized: python.* -m pytest .* -v
//! ```
//!
//! # Pattern Specificity Levels
//!
//! Patterns are generated at multiple specificity levels:
//!
//! 1. **Exact**: Preserves most detail (ports, specific args)
//! 2. **Standard**: Generalizes paths, preserves key flags
//! 3. **Broad**: Base command with minimal specifics
//!
//! # Example
//!
//! ```no_run
//! use pt_core::supervision::pattern_learning::{CommandNormalizer, PatternLearner};
//! use pt_core::supervision::PatternLibrary;
//!
//! // Normalize a command
//! let normalizer = CommandNormalizer::new();
//! let candidates = normalizer.generate_candidates(
//!     "node",
//!     "/usr/bin/node /home/user/proj/node_modules/.bin/jest --watch tests/",
//! );
//!
//! // Learn from a user decision
//! let mut library = PatternLibrary::with_default_config().unwrap();
//! library.load().unwrap();
//!
//! let mut learner = PatternLearner::new(&mut library);
//! learner.record_decision(
//!     "node",
//!     "/usr/bin/node /home/user/proj/node_modules/.bin/jest --watch tests/",
//!     true,  // killed
//! ).unwrap();
//! ```

use super::pattern_persistence::{PatternLibrary, PersistenceError};
use super::signature::{SignaturePatterns, SupervisorSignature};
use super::types::SupervisorCategory;
use regex::Regex;
use std::collections::HashMap;
use thiserror::Error;

/// Errors from pattern learning operations.
#[derive(Debug, Error)]
pub enum LearningError {
    #[error("Persistence error: {0}")]
    Persistence(#[from] PersistenceError),

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Pattern compilation failed: {0}")]
    PatternCompilation(String),
}

/// Specificity level for pattern candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecificityLevel {
    /// Preserves most detail (ports, specific args).
    Exact,
    /// Generalizes paths, preserves key flags.
    Standard,
    /// Base command with minimal specifics.
    Broad,
}

impl SpecificityLevel {
    /// Get the priority offset for this specificity level.
    /// Lower values = higher priority. Exact patterns match first.
    pub fn priority_offset(&self) -> u32 {
        match self {
            Self::Exact => 0,
            Self::Standard => 10,
            Self::Broad => 20,
        }
    }
}

/// A pattern candidate at a specific specificity level.
#[derive(Debug, Clone)]
pub struct PatternCandidate {
    /// The specificity level.
    pub level: SpecificityLevel,
    /// Process name pattern (regex).
    pub process_pattern: String,
    /// Argument patterns (regexes).
    pub arg_patterns: Vec<String>,
    /// Human-readable description.
    pub description: String,
}

impl PatternCandidate {
    /// Generate a unique name for this pattern.
    pub fn generate_name(&self, base_name: &str) -> String {
        let suffix = match self.level {
            SpecificityLevel::Exact => "exact",
            SpecificityLevel::Standard => "std",
            SpecificityLevel::Broad => "broad",
        };
        format!("learned_{base_name}_{suffix}")
    }
}

/// Command normalizer for converting raw commands to patterns.
pub struct CommandNormalizer {
    /// Patterns for path stripping.
    path_stripper: Regex,
    /// Patterns for PID/number replacement.
    number_replacer: Regex,
    /// Patterns for port flags (e.g. --port 8080, -p8080).
    port_flag_pattern: Regex,
    /// Patterns for port suffixes (e.g. :8080).
    port_suffix_pattern: Regex,
    /// Patterns for temp path detection.
    temp_path_pattern: Regex,
    /// Patterns for home directory detection.
    home_path_pattern: Regex,
    /// Patterns for UUID detection.
    uuid_pattern: Regex,
    /// Patterns for hash-like strings.
    hash_pattern: Regex,
}

impl Default for CommandNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandNormalizer {
    /// Create a new normalizer with default patterns.
    pub fn new() -> Self {
        Self {
            // Match absolute paths like /usr/bin/node, /home/user/...
            // Use capturing group to preserve boundary (start or whitespace)
            path_stripper: Regex::new(r"(^|\s)/(?:[^/\s]+/)+").unwrap(),
            // Match standalone numbers (PIDs, process IDs)
            number_replacer: Regex::new(r"\b\d{4,}\b").unwrap(),
            // Match port flags in common formats (capture flag prefix)
            port_flag_pattern: Regex::new(r"(--?(?:port|p)\s*[=:]?\s*)\d+").unwrap(),
            // Match port suffixes like :8080
            port_suffix_pattern: Regex::new(r":\d{2,5}\b").unwrap(),
            // Match temp paths
            temp_path_pattern: Regex::new(r"/(?:tmp|var/tmp|var/folders)/[^\s]+").unwrap(),
            // Match home directory paths
            home_path_pattern: Regex::new(r"/(?:home|Users)/[^/\s]+/[^\s]*").unwrap(),
            // Match UUIDs
            uuid_pattern: Regex::new(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            )
            .unwrap(),
            // Match hash-like strings (8+ hex chars)
            hash_pattern: Regex::new(r"\b[0-9a-fA-F]{8,}\b").unwrap(),
        }
    }

    /// Normalize a process name.
    pub fn normalize_process_name(&self, name: &str) -> String {
        // Strip path prefix if present
        let base = if let Some(idx) = name.rfind('/') {
            &name[idx + 1..]
        } else {
            name
        };

        // Handle versioned interpreters (python3.11 -> python.*)
        if let Some(captures) = Regex::new(r"^(python|ruby|perl|node)(\d+(?:\.\d+)*)$")
            .ok()
            .and_then(|re| re.captures(base))
        {
            if let Some(lang) = captures.get(1) {
                return format!("{}.*", lang.as_str());
            }
        }

        base.to_string()
    }

    /// Normalize a command argument at the exact level.
    fn normalize_arg_exact(&self, arg: &str) -> String {
        let mut result = arg.to_string();
        let uuid_placeholder = "__UUID__";

        // Replace UUIDs with pattern
        result = self
            .uuid_pattern
            .replace_all(&result, uuid_placeholder)
            .to_string();

        // Escape regex metacharacters but keep the replacements
        result = regex::escape(&result);
        result = result.replace(uuid_placeholder, "[0-9a-f-]+");

        result
    }

    /// Normalize a command argument at the standard level.
    fn normalize_arg_standard(&self, arg: &str) -> String {
        let mut result = arg.to_string();

        // Strip absolute paths, keep final component
        result = self
            .path_stripper
            .replace_all(&result, "${1}.*")
            .to_string();

        // Replace home paths
        result = self
            .home_path_pattern
            .replace_all(&result, ".*")
            .to_string();

        // Replace temp paths
        result = self
            .temp_path_pattern
            .replace_all(&result, ".*")
            .to_string();

        // Replace port numbers, preserving original form when possible
        result = self
            .port_flag_pattern
            .replace_all(&result, r"${1}\d+")
            .to_string();
        result = self
            .port_suffix_pattern
            .replace_all(&result, r":\d+")
            .to_string();

        // Replace long numbers (PIDs, etc.)
        result = self
            .number_replacer
            .replace_all(&result, r"\d+")
            .to_string();

        // Replace UUIDs
        result = self
            .uuid_pattern
            .replace_all(&result, "[0-9a-f-]+")
            .to_string();

        // Replace hash-like strings
        result = self
            .hash_pattern
            .replace_all(&result, "[0-9a-fA-F]+")
            .to_string();

        result
    }

    /// Normalize a command argument at the broad level.
    fn normalize_arg_broad(&self, arg: &str) -> String {
        // At broad level, we only keep key flags and replace everything else
        let mut result = arg.to_string();

        // Strip all paths
        result = self.path_stripper.replace_all(&result, "${1}").to_string();

        // Replace all paths (including relative)
        result = Regex::new(r"[^\s]+/[^\s]+")
            .unwrap()
            .replace_all(&result, ".*")
            .to_string();

        // Replace all numbers
        result = Regex::new(r"\b\d+\b")
            .unwrap()
            .replace_all(&result, r"\d+")
            .to_string();

        // Collapse multiple wildcards
        result = Regex::new(r"(\.\*)+")
            .unwrap()
            .replace_all(&result, ".*")
            .to_string();

        result.trim().to_string()
    }

    /// Generate pattern candidates at all specificity levels.
    pub fn generate_candidates(&self, process_name: &str, cmdline: &str) -> Vec<PatternCandidate> {
        let normalized_name = self.normalize_process_name(process_name);

        // Parse cmdline into components
        let args: Vec<&str> = cmdline.split_whitespace().collect();

        // Skip the first arg if it's the command itself
        let args_to_process: Vec<&str> = if !args.is_empty() {
            // Check if first arg ends with the process name
            let first = args[0];
            if first.ends_with(process_name) || first.ends_with(&format!("/{}", process_name)) {
                args[1..].to_vec()
            } else {
                args.to_vec()
            }
        } else {
            vec![]
        };

        let mut candidates = Vec::new();

        // Generate exact pattern
        let exact_args: Vec<String> = args_to_process
            .iter()
            .filter(|a| self.is_significant_arg(a))
            .map(|a| self.normalize_arg_exact(a))
            .collect();

        if !exact_args.is_empty() {
            candidates.push(PatternCandidate {
                level: SpecificityLevel::Exact,
                process_pattern: format!("^{}$", regex::escape(&normalized_name)),
                arg_patterns: exact_args.clone(),
                description: format!("Exact match for {} with specific args", normalized_name),
            });
        }

        // Generate standard pattern
        let std_args: Vec<String> = args_to_process
            .iter()
            .filter(|a| self.is_key_arg(a))
            .map(|a| self.normalize_arg_standard(a))
            .collect();

        candidates.push(PatternCandidate {
            level: SpecificityLevel::Standard,
            process_pattern: normalized_name.clone(),
            arg_patterns: std_args,
            description: format!("Standard match for {}", normalized_name),
        });

        // Generate broad pattern
        let broad_args: Vec<String> = args_to_process
            .iter()
            .filter(|a| self.is_primary_flag(a))
            .map(|a| self.normalize_arg_broad(a))
            .filter(|a| !a.is_empty() && a != ".*")
            .collect();

        candidates.push(PatternCandidate {
            level: SpecificityLevel::Broad,
            process_pattern: format!(
                "{}.*",
                normalized_name
                    .split('.')
                    .next()
                    .unwrap_or(&normalized_name)
            ),
            arg_patterns: broad_args,
            description: format!("Broad match for {}-like processes", normalized_name),
        });

        candidates
    }

    /// Check if an argument is significant (worth keeping at exact level).
    fn is_significant_arg(&self, arg: &str) -> bool {
        // Skip empty args
        if arg.is_empty() {
            return false;
        }

        // Skip pure paths that don't contain useful info
        if arg.starts_with('/') && !arg.contains("=") && !arg.starts_with("--") {
            // Keep if it looks like a script/module path
            return arg.ends_with(".py")
                || arg.ends_with(".js")
                || arg.ends_with(".ts")
                || arg.ends_with(".rb")
                || arg.contains("bin/");
        }

        true
    }

    /// Check if an argument is a key flag (worth keeping at standard level).
    fn is_key_arg(&self, arg: &str) -> bool {
        // Flags are key
        if arg.starts_with('-') {
            return true;
        }

        // Module invocations are key
        if arg == "-m" {
            return true;
        }

        // Known important subcommands
        let important_subcommands = [
            "test", "serve", "dev", "build", "watch", "run", "start", "exec", "lint", "check",
            "format", "compile", "bundle",
        ];
        if important_subcommands.contains(&arg.to_lowercase().as_str()) {
            return true;
        }

        false
    }

    /// Check if an argument is a primary flag (worth keeping at broad level).
    fn is_primary_flag(&self, arg: &str) -> bool {
        // Only keep flags that indicate the type of operation
        let primary_flags = [
            "--watch",
            "-w",
            "--hot",
            "--dev",
            "--serve",
            "--test",
            "--build",
            "--verbose",
            "-v",
            "--debug",
            "-m",
        ];

        primary_flags.contains(&arg.to_lowercase().as_str())
            || (arg.starts_with("--") && !arg.contains('='))
    }
}

/// Action type for pattern learning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    /// User killed the process.
    Kill,
    /// User spared the process.
    Spare,
}

/// Pattern learner that integrates with PatternLibrary.
pub struct PatternLearner<'a> {
    library: &'a mut PatternLibrary,
    normalizer: CommandNormalizer,
    /// Track observations for pattern generalization.
    observations: HashMap<String, Vec<PatternObservation>>,
    /// Minimum observations before creating a stable pattern.
    min_observations: usize,
}

/// An observation of a user decision.
#[derive(Debug, Clone)]
pub struct PatternObservation {
    /// The raw command line.
    pub cmdline: String,
    /// The action taken.
    pub action: DecisionAction,
    /// Generated candidates.
    pub candidates: Vec<PatternCandidate>,
}

impl<'a> PatternLearner<'a> {
    /// Create a new pattern learner.
    pub fn new(library: &'a mut PatternLibrary) -> Self {
        Self {
            library,
            normalizer: CommandNormalizer::new(),
            observations: HashMap::new(),
            min_observations: 3,
        }
    }

    /// Set minimum observations before pattern creation.
    pub fn with_min_observations(mut self, min: usize) -> Self {
        self.min_observations = min;
        self
    }

    /// Record a user decision and potentially learn from it.
    pub fn record_decision(
        &mut self,
        process_name: &str,
        cmdline: &str,
        killed: bool,
    ) -> Result<Option<String>, LearningError> {
        let action = if killed {
            DecisionAction::Kill
        } else {
            DecisionAction::Spare
        };

        // Generate candidates
        let candidates = self.normalizer.generate_candidates(process_name, cmdline);

        // Store observation
        let observation = PatternObservation {
            cmdline: cmdline.to_string(),
            action,
            candidates: candidates.clone(),
        };

        self.observations
            .entry(process_name.to_string())
            .or_default()
            .push(observation);

        // Try to find or update a matching pattern
        let pattern_name = self.find_or_create_pattern(process_name, &candidates, action)?;

        // Record match in library stats
        // killed=false (spared) means process is a supervisor (accepted)
        // killed=true means process is not a supervisor (rejected)
        if let Some(ref name) = pattern_name {
            self.library.record_match(name, !killed);
        }

        Ok(pattern_name)
    }

    /// Find an existing pattern or create a new one.
    fn find_or_create_pattern(
        &mut self,
        process_name: &str,
        candidates: &[PatternCandidate],
        action: DecisionAction,
    ) -> Result<Option<String>, LearningError> {
        // First, check if any existing pattern matches
        for candidate in candidates {
            let name = candidate.generate_name(process_name);
            if self.library.get_pattern(&name).is_some() {
                return Ok(Some(name));
            }
        }

        // Check if we have enough observations to create a pattern
        let obs_count = self
            .observations
            .get(process_name)
            .map(|v| v.len())
            .unwrap_or(0);

        if obs_count < self.min_observations {
            // Not enough observations yet
            return Ok(None);
        }

        // Analyze observations to determine best pattern level
        let best_candidate = self.select_best_candidate(process_name, candidates)?;

        if let Some(candidate) = best_candidate {
            let name = self.create_learned_pattern(process_name, &candidate, action)?;
            return Ok(Some(name));
        }

        Ok(None)
    }

    /// Select the best candidate based on observation consistency.
    fn select_best_candidate(
        &self,
        process_name: &str,
        candidates: &[PatternCandidate],
    ) -> Result<Option<PatternCandidate>, LearningError> {
        let observations = match self.observations.get(process_name) {
            Some(obs) => obs,
            None => return Ok(None),
        };

        // Check action consistency - if actions are mixed, prefer broader patterns
        let kill_count = observations
            .iter()
            .filter(|o| o.action == DecisionAction::Kill)
            .count();
        let spare_count = observations.len() - kill_count;

        let action_consistency = if observations.is_empty() {
            0.0
        } else {
            let max_count = kill_count.max(spare_count) as f64;
            max_count / observations.len() as f64
        };

        // If actions are inconsistent (< 80% agreement), use broader patterns
        let preferred_level = if action_consistency < 0.8 {
            SpecificityLevel::Broad
        } else if action_consistency < 0.95 {
            SpecificityLevel::Standard
        } else {
            SpecificityLevel::Exact
        };

        // Find candidate at preferred level or broader
        for candidate in candidates {
            if candidate.level == preferred_level {
                return Ok(Some(candidate.clone()));
            }
        }

        // Fallback to standard
        candidates
            .iter()
            .find(|c| c.level == SpecificityLevel::Standard)
            .cloned()
            .map(Some)
            .ok_or_else(|| LearningError::InvalidCommand("No valid candidates".to_string()))
    }

    /// Create a learned pattern in the library.
    fn create_learned_pattern(
        &mut self,
        process_name: &str,
        candidate: &PatternCandidate,
        action: DecisionAction,
    ) -> Result<String, LearningError> {
        let name = candidate.generate_name(process_name);

        // Determine category based on typical behavior
        let category = self.infer_category(process_name);

        // Set initial confidence based on action consistency
        let obs_count = self
            .observations
            .get(process_name)
            .map(|v| v.len())
            .unwrap_or(0);
        let initial_confidence = 0.5 + (0.1 * (obs_count as f64).min(5.0));

        // Create signature patterns
        let patterns = SignaturePatterns {
            process_names: vec![candidate.process_pattern.clone()],
            arg_patterns: candidate.arg_patterns.clone(),
            ..Default::default()
        };

        // Create the signature
        let signature = SupervisorSignature {
            name: name.clone(),
            category,
            patterns,
            confidence_weight: initial_confidence,
            notes: Some(format!(
                "Learned from {} observations. Action: {:?}. {}",
                obs_count, action, candidate.description
            )),
            builtin: false,
            priors: Default::default(),
            expectations: Default::default(),
            priority: 100 + candidate.level.priority_offset(),
        };

        // Add to library
        self.library.add_learned(signature)?;

        Ok(name)
    }

    /// Infer the supervisor category from process name.
    fn infer_category(&self, process_name: &str) -> SupervisorCategory {
        let name_lower = process_name.to_lowercase();

        // Test runners
        if name_lower.contains("test")
            || name_lower.contains("jest")
            || name_lower.contains("pytest")
            || name_lower.contains("mocha")
            || name_lower.contains("bats")
        {
            return SupervisorCategory::Ci;
        }

        // Dev servers
        if name_lower.contains("vite")
            || name_lower.contains("webpack")
            || name_lower.contains("next")
            || name_lower.contains("serve")
        {
            return SupervisorCategory::Orchestrator;
        }

        // AI agents
        if name_lower.contains("claude")
            || name_lower.contains("codex")
            || name_lower.contains("copilot")
        {
            return SupervisorCategory::Agent;
        }

        // IDEs
        if name_lower.contains("code")
            || name_lower.contains("vim")
            || name_lower.contains("emacs")
            || name_lower.contains("idea")
        {
            return SupervisorCategory::Ide;
        }

        // Default to Other
        SupervisorCategory::Other
    }

    /// Get the current observation count for a process.
    pub fn observation_count(&self, process_name: &str) -> usize {
        self.observations
            .get(process_name)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Clear observations (useful after pattern creation).
    pub fn clear_observations(&mut self, process_name: &str) {
        self.observations.remove(process_name);
    }

    /// Save any pending changes to the library.
    pub fn save(&mut self) -> Result<(), LearningError> {
        self.library.save()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_process_name() {
        let normalizer = CommandNormalizer::new();

        assert_eq!(normalizer.normalize_process_name("node"), "node");
        assert_eq!(normalizer.normalize_process_name("/usr/bin/node"), "node");
        assert_eq!(normalizer.normalize_process_name("python3"), "python.*");
        assert_eq!(normalizer.normalize_process_name("python3.11"), "python.*");
    }

    #[test]
    fn test_generate_candidates_node_jest() {
        let normalizer = CommandNormalizer::new();

        let candidates = normalizer.generate_candidates(
            "node",
            "/usr/bin/node /home/user/project/node_modules/.bin/jest --watch tests/",
        );

        assert!(!candidates.is_empty());

        // Should have candidates at different levels
        let levels: Vec<_> = candidates.iter().map(|c| c.level).collect();
        assert!(levels.contains(&SpecificityLevel::Standard));
        assert!(levels.contains(&SpecificityLevel::Broad));
    }

    #[test]
    fn test_generate_candidates_python_pytest() {
        let normalizer = CommandNormalizer::new();

        let candidates = normalizer.generate_candidates(
            "python3",
            "python3 -m pytest /home/user/app/tests/test_api.py -v",
        );

        assert!(!candidates.is_empty());

        // Standard candidate should include -m pytest
        let std_candidate = candidates
            .iter()
            .find(|c| c.level == SpecificityLevel::Standard)
            .unwrap();

        assert!(std_candidate
            .arg_patterns
            .iter()
            .any(|p| p.contains("-m") || p.contains("pytest")));
    }

    #[test]
    fn test_specificity_priority() {
        assert!(
            SpecificityLevel::Exact.priority_offset()
                < SpecificityLevel::Standard.priority_offset()
        );
        assert!(
            SpecificityLevel::Standard.priority_offset()
                < SpecificityLevel::Broad.priority_offset()
        );
    }
}
