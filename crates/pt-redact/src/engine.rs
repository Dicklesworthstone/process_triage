//! Main redaction engine.
//!
//! The RedactionEngine is the central component that applies the redaction policy
//! to values, using canonicalization, hashing, and secret detection.

use crate::{
    Action, Canonicalizer, FieldClass, KeyManager, KeyMaterial, RedactionPolicy, Result,
    SecretDetector,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of a redaction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedValue {
    /// The redacted output string.
    pub output: String,

    /// The action that was applied.
    pub action_applied: Action,

    /// Whether the value was modified.
    pub was_modified: bool,

    /// For forensic reference: hash of the original value (if hashing was used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
}

impl RedactedValue {
    /// Create a new redacted value.
    pub fn new(output: String, action: Action, was_modified: bool) -> Self {
        Self {
            output,
            action_applied: action,
            was_modified,
            original_hash: None,
        }
    }

    /// Create a value that was allowed through unchanged.
    pub fn allowed(value: String) -> Self {
        Self::new(value, Action::Allow, false)
    }

    /// Create a fully redacted value.
    pub fn redacted() -> Self {
        Self::new("[REDACTED]".to_string(), Action::Redact, true)
    }
}

/// The main redaction engine.
pub struct RedactionEngine {
    /// The redaction policy.
    policy: RedactionPolicy,

    /// Key material for hashing.
    key: KeyMaterial,

    /// Canonicalizer for normalization.
    canonicalizer: Canonicalizer,

    /// Secret detector.
    detector: SecretDetector,
}

impl RedactionEngine {
    /// Create a new redaction engine with the given policy.
    ///
    /// Generates a new random key for hashing.
    pub fn new(policy: RedactionPolicy) -> Result<Self> {
        let key = KeyMaterial::generate("k1")?;
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Ok(Self {
            policy,
            key,
            canonicalizer,
            detector,
        })
    }

    /// Create a redaction engine with an existing key manager.
    pub fn with_key_manager(policy: RedactionPolicy, key_manager: &KeyManager) -> Result<Self> {
        let key = key_manager.active_key()?;
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Ok(Self {
            policy,
            key,
            canonicalizer,
            detector,
        })
    }

    /// Create a redaction engine with explicit key material.
    pub fn with_key(policy: RedactionPolicy, key: KeyMaterial) -> Self {
        let canonicalizer = Canonicalizer::new();
        let detector = SecretDetector::with_entropy_threshold(policy.entropy_threshold);

        Self {
            policy,
            key,
            canonicalizer,
            detector,
        }
    }

    /// Load a redaction engine from config files.
    pub fn load<P: AsRef<Path>>(policy_path: P, key_path: P) -> Result<Self> {
        let policy = RedactionPolicy::load(policy_path)?;
        let key_manager = KeyManager::load(key_path)?;
        Self::with_key_manager(policy, &key_manager)
    }

    /// Apply redaction to a value based on its field class.
    pub fn redact(&self, value: &str, field_class: FieldClass) -> RedactedValue {
        // Get the action for this field class
        let mut action = self.policy.action_for(field_class);

        // If action is detect+action, run detection first
        if action == Action::DetectAction {
            action = self.detect_action(value, field_class);
        }

        self.apply_action(value, action)
    }

    /// Apply redaction with a specific export profile.
    pub fn redact_with_profile(
        &self,
        value: &str,
        field_class: FieldClass,
        profile: crate::ExportProfile,
    ) -> RedactedValue {
        let mut action = self.policy.action_for_profile(field_class, profile);

        if action == Action::DetectAction {
            action = self.detect_action(value, field_class);
        }

        self.apply_action(value, action)
    }

    /// Get the current policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy.schema_version
    }

    /// Get the current key ID.
    pub fn key_id(&self) -> &str {
        &self.key.key_id
    }

    /// An opaque, keyed identifier for artifact addressing. Unlike display
    /// redaction, detected secrets must not collapse distinct inputs into one
    /// placeholder. Use the full digest regardless of display truncation policy.
    pub fn artifact_identifier(&self, path: &str) -> String {
        self.key.hash(&format!("bundle-artifact:{path}"), 32)
    }

    /// Get a reference to the policy.
    pub fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Sanitize structured session data before export. Unknown strings and map
    /// keys are pseudonymized; only validated public schema values are retained.
    /// Environment values are never exported, including with forensic policies.
    pub fn redact_json_for_export(
        &self,
        value: &serde_json::Value,
        profile: crate::ExportProfile,
    ) -> serde_json::Value {
        self.redact_json_field(value, None, profile)
    }

    fn redact_json_field(
        &self,
        value: &serde_json::Value,
        field: Option<&str>,
        profile: crate::ExportProfile,
    ) -> serde_json::Value {
        use serde_json::Value;
        let normalized_field = field.unwrap_or("").to_ascii_lowercase();
        let field = normalized_field.as_str();
        if field == "environment_vars" {
            return match value {
                Value::Object(fields) => Value::Object(
                    fields
                        .keys()
                        .map(|key| {
                            (
                                self.apply_action(key, Action::Hash).output,
                                Value::String("[REDACTED]".to_string()),
                            )
                        })
                        .collect(),
                ),
                _ => Value::String("[REDACTED]".to_string()),
            };
        }
        if matches!(
            field,
            "env"
                | "environ"
                | "environment"
                | "environment_variables"
                | "env_value"
                | "environment_value"
                | "environment_json"
                | "password"
                | "token"
                | "secret"
                | "api_key"
                | "authorization"
                | "credential"
        ) || field.ends_with("_token")
            || field.ends_with("_secret")
            || field.contains("password")
        {
            return Value::String("[REDACTED]".to_string());
        }
        match value {
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| {
                        let exported_key = if is_export_field(key) {
                            key.clone()
                        } else {
                            self.apply_action(key, Action::Hash).output
                        };
                        (
                            exported_key,
                            self.redact_json_field(value, Some(key), profile),
                        )
                    })
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| self.redact_json_field(value, Some(field), profile))
                    .collect(),
            ),
            Value::String(text) => {
                if self.detector.detect(text).is_some() {
                    return Value::String("[REDACTED]".to_string());
                }
                if is_public_export_string(field, text) {
                    return value.clone();
                }
                let class = match field {
                    "cmd" | "comm" | "cmdline" | "command" | "cmd_pattern" | "cmdline_raw"
                    | "command_line" | "argv" | "args" => FieldClass::Cmdline,
                    "hostname" | "host" | "host_id" => FieldClass::Hostname,
                    "username" | "user" | "owner" | "uid" => FieldClass::Username,
                    "path" | "cwd" | "exe" | "executable" | "home" | "artifact_path" => {
                        FieldClass::PathProject
                    }
                    _ => FieldClass::FreeText,
                };
                let redacted = self.redact_with_profile(text, class, profile);
                let output = if profile != crate::ExportProfile::Forensic
                    && !matches!(
                        redacted.action_applied,
                        Action::Hash | Action::NormalizeHash | Action::Redact
                    ) {
                    self.apply_action(text, Action::Hash).output
                } else {
                    redacted.output
                };
                Value::String(output)
            }
            Value::Number(_) if matches!(field, "uid" | "gid" | "euid" | "egid") => {
                if self.policy.action_for_profile(FieldClass::Uid, profile) == Action::Allow {
                    value.clone()
                } else {
                    Value::String(
                        self.redact_with_profile(&value.to_string(), FieldClass::Uid, profile)
                            .output,
                    )
                }
            }
            _ => value.clone(),
        }
    }

    /// Detect what action to apply based on content analysis.
    fn detect_action(&self, value: &str, field_class: FieldClass) -> Action {
        // Skip detection if disabled
        if !self.policy.detection_enabled {
            // Fall back to a safe default
            return Action::Hash;
        }

        // Check for secrets
        if let Some(secret_type) = self.detector.detect(value) {
            return secret_type.recommended_action();
        }

        // Apply field-class-specific defaults
        match field_class {
            FieldClass::CmdlineArg => {
                // Check if it looks like a flag vs value
                if value.starts_with('-') {
                    // Flags are usually safe
                    Action::Allow
                } else if self.detector.is_high_entropy(value) {
                    Action::Redact
                } else {
                    Action::Hash
                }
            }
            FieldClass::FreeText => {
                // Free text: check for secrets, otherwise hash
                Action::Hash
            }
            _ => {
                // Default to the field class's default action
                field_class.default_action()
            }
        }
    }

    /// Apply a specific action to a value.
    fn apply_action(&self, value: &str, action: Action) -> RedactedValue {
        match action {
            Action::Allow => RedactedValue::allowed(value.to_string()),

            Action::Redact => RedactedValue::redacted(),

            Action::Hash => {
                let hash = self.key.hash(value, self.policy.hash_truncation_bytes);
                let mut result = RedactedValue::new(hash.clone(), Action::Hash, true);
                result.original_hash = Some(hash);
                result
            }

            Action::Normalize => {
                let normalized = self.canonicalizer.canonicalize(value);
                RedactedValue::new(normalized, Action::Normalize, true)
            }

            Action::NormalizeHash => {
                let normalized = self.canonicalizer.canonicalize(value);
                let hash = self
                    .key
                    .hash(&normalized, self.policy.hash_truncation_bytes);
                let mut result = RedactedValue::new(hash.clone(), Action::NormalizeHash, true);
                result.original_hash = Some(hash);
                result
            }

            Action::Truncate => {
                let truncated = truncate_value(value, 6);
                RedactedValue::new(truncated, Action::Truncate, true)
            }

            Action::DetectAction => {
                // This should have been resolved before calling apply_action,
                // but fall back to safe hash if we get here
                let hash = self.key.hash(value, self.policy.hash_truncation_bytes);
                RedactedValue::new(hash, Action::Hash, true)
            }
        }
    }

    /// Redact a path value.
    pub fn redact_path(&self, path: &str) -> RedactedValue {
        // Classify the path
        let field_class = classify_path(path);
        self.redact(path, field_class)
    }

    /// Redact an environment variable.
    pub fn redact_env(&self, name: &str, value: &str) -> (RedactedValue, RedactedValue) {
        let name_result = self.redact(name, FieldClass::EnvName);

        // Check if the name suggests a secret
        if let Some(_secret_type) = self.detector.detect_env(name, value) {
            return (name_result, RedactedValue::redacted());
        }

        let value_result = self.redact(value, FieldClass::EnvValue);
        (name_result, value_result)
    }

    /// Redact a command line argument.
    pub fn redact_arg(&self, arg: &str, prev_arg: Option<&str>) -> RedactedValue {
        // Check context-aware detection
        if let Some(secret_type) = self.detector.detect_arg(arg, prev_arg) {
            let action = secret_type.recommended_action();
            return self.apply_action(arg, action);
        }

        self.redact(arg, FieldClass::CmdlineArg)
    }
}

fn is_export_field(key: &str) -> bool {
    static FIELDS: once_cell::sync::Lazy<std::collections::HashSet<&'static str>> =
        once_cell::sync::Lazy::new(|| {
            "schema_version bundle_version pt_version policy_version session_id
            generated_at created_at updated_at started_at ended_at completed_at timestamp
            host_id hostname host os_family os_arch cores memory_total_gb
            payload integrity_sha256 policy_hash priors_hash config_hash
            summary total count total_processes total_system_processes
            protected_filtered record_count records candidate_count candidates
            action_count kill_count review_count spare_count actions outcomes recommendations kills spares
            processes_scanned candidates_found kills_attempted kills_successful deep_scan spares
            total_processes_scanned candidates_evaluated candidates_returned kill_recommendations
            review_recommendations policy_blocked protected_by_rule
            os_version kernel_version arch family memory_bytes duration_ms export_profile timing
            pid ppid uid gid euid egid start_id comm cmd cmdline command command_line command_short
            cmd_short cmd_full target plan_id pre_toggled gates_summary policy_snapshot
            policy_id pgid sid quality pre_checks timeouts order stage blocked routing
            preflight_ms execute_ms verify_ms on_success on_failure details
            blocked_candidates pre_toggled_actions original_zombie_target d_state_diagnostics
            expected_recovery expected_recovery_stddev posterior_odds_abandoned_vs_useful
            sprt_boundary log_odds_threshold numerator denominator has_known_signature category
            wchan io_read_bytes io_write_bytes d_state_duration_ms
            signatures metadata name patterns confidence_weight notes builtin priors expectations priority
            process_names arg_patterns environment_vars working_dir_patterns socket_paths pid_files
            parent_patterns min_matches typical_lifetime_seconds max_normal_lifetime_seconds
            cpu_during_run idle_cpu_normal expected_memory_bytes expects_network expects_disk_io
            signature_age_weight system_state pressure assessment sampled_at_ms cpus psi
            some full avg10 avg60 avg300 one five fifteen runnable meminfo vmstat file_handles
            total_gb available_gb used_gb process_count unavailable source reason load_ratio
            free available buffers cached swap_cached anon shmem slab slab_reclaimable
            slab_unreclaimable dirty writeback swap_total swap_free committed_as commit_limit
            pswpin pswpout pgmajfault pgscan_direct allocstall compact_stall oom_kill allocated max
            worst regimes kind severity sustained explanation cpu_some memory_some io_some
            memory_used_fraction zombies dstate irq
            alpha beta author url check
            cmd_pattern cmdline_raw argv args path cwd exe executable home artifact_path
            user username owner env environ environment environment_variables
            state status mode classification confidence recommendation recommended_action
            action action_id action_type rationale action_rationale score posterior
            posterior_useful posterior_useful_bad posterior_abandoned posterior_zombie
            useful useful_bad abandoned zombie expected_loss loss start_time_unix elapsed_secs
            age_s age_seconds cpu_pct cpu_percent mem_pct mem_mb rss_bytes memory_mb resources cpu memory io
            read_bytes write_bytes read_rate write_rate io_read_rate io_write_rate
            is_orphan is_zombie is_protected has_network has_children child_count
            protected policy policy_blocked blocked_by_gate passed_safety_gates
            evidence evidence_ledger evidence_terms evidence_tags tags features feature
            log_likelihood log_posterior log_odds_abandoned_useful bayes_factors bf log_bf delta_bits
            direction strength top_evidence why_summary evidence_glyphs identity_quality warnings error
            prior runtime orphan tty net io_active queue_saturated state_flag command_category
            blast_radius blast_radius_risk_level blast_radius_total_affected risk_level
            provenance provenance_inference provenance_evidence_completeness provenance_score_terms
            provenance_log_odds_shift uncertainty posterior_entropy_bits abandonment_probability
            intervention_probability reversibility success skipped exit_code duration_ms
            duration_seconds signal reason description scan decision inference event phase case_id artifacts kind
            above_threshold evaluated scanned protected_count recommended_kill recommended_review
            recommended_spare total_candidates total_actions successful failed
            goal goal_progress goal_summary system pressure regime attribution resource_delta"
                .split_whitespace()
                .collect()
        });
    FIELDS.contains(key)
}

fn is_public_export_string(field: &str, value: &str) -> bool {
    if matches!(field, "worst" | "severity") {
        return matches!(value, "ok" | "warn" | "crit");
    }
    if field == "kind" {
        return matches!(
            value,
            "cpu_contention"
                | "io_bound"
                | "memory_exhaustion"
                | "cache_bloat"
                | "swap_thrash"
                | "swap_paradox"
                | "swap_exhaustion"
                | "oom_kills"
                | "fd_exhaustion"
                | "zombie_leak"
                | "dstate_storm"
        );
    }
    if field == "host_id" && value == "unknown" {
        return true;
    }
    if field == "session_id" {
        static SESSION_ID: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
            regex::Regex::new(r"^pt-[0-9]{8}-[0-9]{6}-[a-z2-7]{4}$")
                .expect("static session ID regex")
        });
        return SESSION_ID.is_match(value);
    }
    if matches!(field, "artifact_path" | "path") {
        return matches!(
            value,
            "summary.json"
                | "plan.json"
                | "scan/inventory.json"
                | "scan/provenance.json"
                | "scan/provenance_audit.json"
                | "inference/results.json"
                | "telemetry/audit.parquet"
                | "telemetry/proc_samples.parquet"
                | "logs/events.jsonl"
                | "logs/outcomes.jsonl"
                | "logs/session.jsonl"
                | "signatures/user_signatures.json"
        );
    }
    if matches!(
        field,
        "schema_version" | "bundle_version" | "pt_version" | "policy_version"
    ) {
        static VERSION: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
            regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
                .expect("static public version regex")
        });
        return VERSION.is_match(value);
    }
    if matches!(
        field,
        "integrity_sha256" | "policy_hash" | "priors_hash" | "config_hash"
    ) {
        return value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    if matches!(
        field,
        "generated_at"
            | "created_at"
            | "updated_at"
            | "started_at"
            | "ended_at"
            | "completed_at"
            | "timestamp"
    ) {
        return chrono::DateTime::parse_from_rfc3339(value).is_ok();
    }
    if field == "feature" {
        return matches!(
            value,
            "prior"
                | "cpu"
                | "runtime"
                | "orphan"
                | "tty"
                | "net"
                | "io_active"
                | "queue_saturated"
                | "state_flag"
                | "command_category"
        );
    }
    if matches!(field, "quality" | "identity_quality") {
        return matches!(
            value,
            "Full" | "NoBootId" | "PidOnly" | "full" | "no_boot_id" | "pid_only"
        );
    }
    if matches!(field, "pre_checks" | "check") {
        return matches!(
            value,
            "verify_identity"
                | "check_not_protected"
                | "check_session_safety"
                | "check_data_loss_gate"
                | "check_supervisor"
                | "check_agent_supervision"
                | "verify_process_state"
                | "process_tree"
        );
    }
    if field == "routing" {
        return matches!(
            value,
            "direct"
                | "zombie_to_parent"
                | "zombie_to_supervisor"
                | "zombie_investigate_only"
                | "d_state_low_confidence"
        );
    }
    if field == "direction" {
        return matches!(value, "supports abandoned" | "supports useful" | "neutral");
    }
    if field == "strength" {
        return matches!(
            value,
            "decisive" | "strong" | "substantial" | "moderate" | "weak" | "neutral"
        );
    }
    if field == "category" {
        return matches!(
            value,
            "agent" | "ide" | "ci" | "orchestrator" | "terminal" | "other"
        );
    }
    if matches!(field, "numerator" | "denominator") {
        return matches!(value, "useful" | "useful_bad" | "abandoned" | "zombie");
    }
    if !matches!(
        field,
        "state"
            | "status"
            | "mode"
            | "classification"
            | "confidence"
            | "recommendation"
            | "recommended_action"
            | "action"
            | "action_type"
            | "risk_level"
            | "blast_radius_risk_level"
            | "identity_quality"
            | "reversibility"
            | "os_family"
            | "family"
            | "os_arch"
            | "arch"
            | "export_profile"
    ) {
        return false;
    }
    static VALUES: once_cell::sync::Lazy<std::collections::HashSet<&'static str>> =
        once_cell::sync::Lazy::new(|| {
            "useful useful_bad abandoned zombie kill review spare keep renice pause resume
            freeze unfreeze throttle quarantine unquarantine restart low medium high critical unknown
            very_high veryhigh usefulbad normal very_low report_failure zombie_reaped
            quickscan deep quick interactive robot agent dry_run planned completed applied running
            created scanning executing cancelled archived robot_plan robot_apply daemon_alert scan_only export
            success succeeded failed blocked skipped ok error linux macos darwin x86_64 aarch64
            blocked_by_plan blocked_by_constraints precheck_blocked identity_mismatch identity_check_failed
            already_completed shadow unsupported_platform
            irreversible reversible reversal no_action safe minimal forensic r s d z t i"
                .split_whitespace()
                .collect()
        });
    VALUES.contains(value.to_ascii_lowercase().as_str())
}

/// Truncate a value, keeping prefix and suffix.
fn truncate_value(value: &str, keep_chars: usize) -> String {
    if value.chars().count() <= keep_chars * 2 {
        return value.to_string();
    }

    let prefix: String = value.chars().take(keep_chars).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(keep_chars)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    format!("{}...{}", prefix, suffix)
}

/// Classify a path into a field class.
fn classify_path(path: &str) -> FieldClass {
    // Check for home directory
    if let Ok(home) = std::env::var("HOME") {
        if path.starts_with(&home) {
            return FieldClass::PathHome;
        }
    }

    // Check for temp directories
    if path.starts_with("/tmp") || path.starts_with("/var/tmp") {
        return FieldClass::PathTmp;
    }

    // Check for system paths
    if path.starts_with("/usr")
        || path.starts_with("/etc")
        || path.starts_with("/bin")
        || path.starts_with("/sbin")
        || path.starts_with("/lib")
    {
        return FieldClass::PathSystem;
    }

    // Default to project path
    FieldClass::PathProject
}

/// Canary test strings that should NEVER appear in output.
pub const CANARY_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "password123!@#",
    "super_secret_token",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> RedactionEngine {
        let policy = RedactionPolicy::default();
        let key = KeyMaterial::from_bytes([0u8; 32], "test");
        RedactionEngine::with_key(policy, key)
    }

    #[test]
    fn structured_export_preserves_evidence_without_private_strings() {
        let engine = test_engine();
        let input = serde_json::json!({
            "schema_version": "1.0.0",
            "generated_at": "2026-10-04T20:00:00Z",
            "candidates": [{
                "pid": 1234, "uid": 1000, "score": 87,
                "posterior": {"useful": 0.1, "useful_bad": 0.03, "abandoned": 0.8, "zombie": 0.07},
                "recommended_action": "KILL",
                "cmd": "python /home/private-customer/job.py",
                "hostname": "customer-private-host",
                "cwd": "/home/private-customer/work",
                "environment": {"ACCESS_TOKEN": "super_secret_token"},
                "private-customer-map-key": "AKIAIOSFODNN7EXAMPLE"
            }]
        });
        let output = engine.redact_json_for_export(&input, crate::ExportProfile::Safe);
        let candidate = &output["candidates"][0];
        assert_eq!(candidate["pid"], 1234);
        assert_eq!(candidate["score"], 87);
        assert_eq!(candidate["posterior"]["useful_bad"], 0.03);
        assert_eq!(candidate["recommended_action"], "KILL");
        assert_eq!(output["generated_at"], input["generated_at"]);
        assert_eq!(candidate["environment"], "[REDACTED]");
        assert_eq!(candidate["uid"], 1000);
        let text = output.to_string();
        for canary in [
            "private-customer",
            "customer-private-host",
            "super_secret_token",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(!text.contains(canary), "export leaked {canary}");
        }
    }

    #[test]
    fn forensic_allowlist_never_allows_environment_or_credentials() {
        let mut policy = RedactionPolicy::default();
        let rule = policy.field_rules.get_mut("cmdline").unwrap();
        rule.profile_overrides = Some(
            [("forensic".to_string(), Action::Allow)]
                .into_iter()
                .collect(),
        );
        let engine = RedactionEngine::with_key(policy, KeyMaterial::from_bytes([0; 32], "test"));
        let input = serde_json::json!({
            "cmd": "python private-job.py",
            "environment": {"HOME": "/home/private-user"},
            "args": ["AKIAIOSFODNN7EXAMPLE"]
        });
        let forensic = engine.redact_json_for_export(&input, crate::ExportProfile::Forensic);
        let safe = engine.redact_json_for_export(&input, crate::ExportProfile::Safe);
        assert_eq!(forensic["cmd"], input["cmd"]);
        assert_ne!(safe["cmd"], input["cmd"]);
        assert_eq!(forensic["environment"], "[REDACTED]");
        assert_eq!(forensic["args"][0], "[REDACTED]");
    }

    #[test]
    fn test_redact_allow() {
        let engine = test_engine();
        let result = engine.redact("/usr/bin/python3", FieldClass::PathSystem);

        assert_eq!(result.output, "/usr/bin/python3");
        assert_eq!(result.action_applied, Action::Allow);
        assert!(!result.was_modified);
    }

    #[test]
    fn test_redact_redact() {
        let engine = test_engine();
        let result = engine.redact("secret_value", FieldClass::EnvValue);

        assert_eq!(result.output, "[REDACTED]");
        assert_eq!(result.action_applied, Action::Redact);
        assert!(result.was_modified);
    }

    #[test]
    fn test_redact_hash() {
        let engine = test_engine();
        let result = engine.redact("myhost.example.com", FieldClass::Hostname);

        assert!(result.output.starts_with("[HASH:test:"));
        assert!(result.output.ends_with("]"));
        assert_eq!(result.action_applied, Action::Hash);
        assert!(result.was_modified);
    }

    #[test]
    fn test_hash_stability() {
        let engine = test_engine();

        let result1 = engine.redact("same_value", FieldClass::Hostname);
        let result2 = engine.redact("same_value", FieldClass::Hostname);

        assert_eq!(result1.output, result2.output);
    }

    #[test]
    fn test_different_values_different_hashes() {
        let engine = test_engine();

        let result1 = engine.redact("value1", FieldClass::Hostname);
        let result2 = engine.redact("value2", FieldClass::Hostname);

        assert_ne!(result1.output, result2.output);
    }

    #[test]
    fn test_redact_normalize() {
        let engine = test_engine();
        let result = engine.redact("/tmp/pytest-123/test.log", FieldClass::PathTmp);

        // Should be normalized (contains [TMP] or similar)
        assert!(result.was_modified);
        assert_eq!(result.action_applied, Action::Normalize);
    }

    #[test]
    fn test_truncate() {
        let truncated = truncate_value("abcdefghijklmnopqrstuvwxyz", 6);
        assert_eq!(truncated, "abcdef...uvwxyz");
    }

    #[test]
    fn test_truncate_short_value() {
        let truncated = truncate_value("short", 6);
        assert_eq!(truncated, "short");
    }

    #[test]
    fn test_detect_action_secret() {
        let engine = test_engine();
        let result = engine.redact(
            "--token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            FieldClass::CmdlineArg,
        );

        // Should detect the GitHub token and redact
        assert_eq!(result.output, "[REDACTED]");
    }

    #[test]
    fn test_detect_action_flag() {
        let engine = test_engine();
        let result = engine.redact("--verbose", FieldClass::CmdlineArg);

        // Flags starting with - should be allowed
        assert_eq!(result.output, "--verbose");
        assert_eq!(result.action_applied, Action::Allow);
    }

    #[test]
    fn test_canary_never_leaks() {
        let engine = test_engine();

        for canary in CANARY_SECRETS {
            let result = engine.redact(canary, FieldClass::CmdlineArg);
            assert!(
                !result.output.contains(canary),
                "Canary '{}' leaked in output: {}",
                canary,
                result.output
            );
        }
    }

    #[test]
    fn test_env_redaction() {
        let engine = test_engine();

        // Secret env var should be redacted
        let (_name, value) = engine.redact_env("AWS_SECRET_KEY", "my_secret");
        assert_eq!(value.output, "[REDACTED]");

        // Normal env var still redacted by default policy
        let (_name, value) = engine.redact_env("PATH", "/usr/bin");
        assert_eq!(value.output, "[REDACTED]"); // env_value defaults to redact
    }

    #[test]
    fn test_path_classification() {
        assert_eq!(classify_path("/tmp/test"), FieldClass::PathTmp);
        assert_eq!(classify_path("/usr/bin/test"), FieldClass::PathSystem);
        assert_eq!(classify_path("/var/tmp/test"), FieldClass::PathTmp);
    }

    #[test]
    fn test_arg_context_detection() {
        let engine = test_engine();

        // Argument after --password should be redacted
        let result = engine.redact_arg("secret123", Some("--password"));
        assert_eq!(result.output, "[REDACTED]");

        // Normal argument without sensitive context
        let result = engine.redact_arg("value", Some("--config"));
        // Should be hashed, not redacted
        assert!(result.output.starts_with("[HASH:") || result.output == "value");
    }

    #[test]
    fn test_policy_version() {
        let engine = test_engine();
        assert_eq!(engine.policy_version(), "1.0.0");
    }

    #[test]
    fn test_key_id() {
        let engine = test_engine();
        assert_eq!(engine.key_id(), "test");
    }
}
