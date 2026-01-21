//! Arrow schema definitions for telemetry tables.
//!
//! Tables defined:
//! - `runs`: Session metadata and summary
//! - `proc_samples`: Raw per-process measurements
//! - `proc_features`: Derived features
//! - `proc_inference`: Inference results
//! - `outcomes`: Action outcomes and feedback
//! - `audit`: Audit trail

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

/// Table names for telemetry storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableName {
    Runs,
    ProcSamples,
    ProcFeatures,
    ProcInference,
    Outcomes,
    Audit,
    SignatureMatches,
}

impl TableName {
    /// Get the string name for directory layout.
    pub fn as_str(&self) -> &'static str {
        match self {
            TableName::Runs => "runs",
            TableName::ProcSamples => "proc_samples",
            TableName::ProcFeatures => "proc_features",
            TableName::ProcInference => "proc_inference",
            TableName::Outcomes => "outcomes",
            TableName::Audit => "audit",
            TableName::SignatureMatches => "signature_matches",
        }
    }

    /// Get the default row group size for this table.
    pub fn row_group_size(&self) -> usize {
        match self {
            TableName::Runs => 64 * 1024,              // 64KB
            TableName::ProcSamples => 1024 * 1024,     // 1MB
            TableName::ProcFeatures => 512 * 1024,     // 512KB
            TableName::ProcInference => 512 * 1024,    // 512KB
            TableName::Outcomes => 256 * 1024,         // 256KB
            TableName::Audit => 256 * 1024,            // 256KB
            TableName::SignatureMatches => 256 * 1024, // 256KB
        }
    }

    /// Get the default retention in days for this table.
    pub fn retention_days(&self) -> u32 {
        match self {
            TableName::Runs => 90,
            TableName::ProcSamples => 30,
            TableName::ProcFeatures => 30,
            TableName::ProcInference => 90,
            TableName::Outcomes => 365,
            TableName::Audit => 365,
            TableName::SignatureMatches => 365, // Long retention for calibration analysis
        }
    }
}

impl std::fmt::Display for TableName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Container for all telemetry schemas.
pub struct TelemetrySchema {
    pub runs: Arc<Schema>,
    pub proc_samples: Arc<Schema>,
    pub proc_features: Arc<Schema>,
    pub proc_inference: Arc<Schema>,
    pub outcomes: Arc<Schema>,
    pub audit: Arc<Schema>,
    pub signature_matches: Arc<Schema>,
}

impl TelemetrySchema {
    /// Create all schemas.
    pub fn new() -> Self {
        TelemetrySchema {
            runs: Arc::new(runs_schema()),
            proc_samples: Arc::new(proc_samples_schema()),
            proc_features: Arc::new(proc_features_schema()),
            proc_inference: Arc::new(proc_inference_schema()),
            outcomes: Arc::new(outcomes_schema()),
            audit: Arc::new(audit_schema()),
            signature_matches: Arc::new(signature_matches_schema()),
        }
    }

    /// Get schema by table name.
    pub fn get(&self, table: TableName) -> Arc<Schema> {
        match table {
            TableName::Runs => self.runs.clone(),
            TableName::ProcSamples => self.proc_samples.clone(),
            TableName::ProcFeatures => self.proc_features.clone(),
            TableName::ProcInference => self.proc_inference.clone(),
            TableName::Outcomes => self.outcomes.clone(),
            TableName::Audit => self.audit.clone(),
            TableName::SignatureMatches => self.signature_matches.clone(),
        }
    }
}

impl Default for TelemetrySchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a timestamp field (microseconds UTC).
fn timestamp_field(name: &str, nullable: bool) -> Field {
    Field::new(
        name,
        DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        nullable,
    )
}

/// Helper to create a string field with optional dictionary encoding hint.
fn string_field(name: &str, nullable: bool) -> Field {
    Field::new(name, DataType::Utf8, nullable)
}

/// Schema for `runs` table: Session metadata.
pub fn runs_schema() -> Schema {
    Schema::new(vec![
        // Core identifiers
        string_field("session_id", false),
        string_field("host_id", false),
        string_field("hostname", true),
        string_field("username", true),
        Field::new("uid", DataType::Int32, true),
        // Session info
        string_field("mode", false),
        Field::new("deep_scan", DataType::Boolean, false),
        timestamp_field("started_at", false),
        timestamp_field("ended_at", true),
        Field::new("duration_ms", DataType::Int64, true),
        string_field("state", false),
        // Counts
        Field::new("processes_scanned", DataType::Int32, false),
        Field::new("candidates_found", DataType::Int32, false),
        Field::new("kills_attempted", DataType::Int32, false),
        Field::new("kills_successful", DataType::Int32, false),
        Field::new("spares", DataType::Int32, false),
        // Version info
        string_field("pt_version", false),
        string_field("pt_core_version", false),
        string_field("schema_version", false),
        string_field("capabilities_hash", true),
        string_field("config_snapshot", true),
        // System info
        string_field("os_family", false),
        string_field("os_version", true),
        string_field("kernel_version", true),
        string_field("arch", false),
        Field::new("cores", DataType::Int16, true),
        Field::new("memory_bytes", DataType::Int64, true),
    ])
}

/// Schema for `proc_samples` table: Raw per-process measurements.
pub fn proc_samples_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        string_field("session_id", false),
        timestamp_field("sample_ts", false),
        Field::new("sample_seq", DataType::Int16, false),
        Field::new("pid", DataType::Int32, false),
        Field::new("ppid", DataType::Int32, false),
        Field::new("pgid", DataType::Int32, true),
        Field::new("sid", DataType::Int32, true),
        // User info
        Field::new("uid", DataType::Int32, false),
        Field::new("euid", DataType::Int32, true),
        // Process identity
        Field::new("start_time_boot", DataType::Int64, false),
        string_field("start_id", false),
        Field::new("age_s", DataType::Int64, false),
        // Command info
        string_field("cmd", false),
        string_field("cmdline", true),
        string_field("cmdline_hash", true),
        string_field("exe", true),
        string_field("cwd", true),
        string_field("tty", true),
        string_field("state", false),
        // CPU stats
        Field::new("utime_ticks", DataType::Int64, false),
        Field::new("stime_ticks", DataType::Int64, false),
        Field::new("cutime_ticks", DataType::Int64, true),
        Field::new("cstime_ticks", DataType::Int64, true),
        // Memory stats
        Field::new("rss_bytes", DataType::Int64, false),
        Field::new("vsize_bytes", DataType::Int64, true),
        Field::new("shared_bytes", DataType::Int64, true),
        Field::new("text_bytes", DataType::Int64, true),
        Field::new("data_bytes", DataType::Int64, true),
        // Scheduling
        Field::new("nice", DataType::Int8, true),
        Field::new("priority", DataType::Int16, true),
        Field::new("num_threads", DataType::Int16, true),
        // Percentages
        Field::new("cpu_percent", DataType::Float32, true),
        Field::new("mem_percent", DataType::Float32, true),
        // I/O stats
        Field::new("io_read_bytes", DataType::Int64, true),
        Field::new("io_write_bytes", DataType::Int64, true),
        Field::new("io_read_ops", DataType::Int64, true),
        Field::new("io_write_ops", DataType::Int64, true),
        // Context switches
        Field::new("voluntary_ctxt_switches", DataType::Int64, true),
        Field::new("nonvoluntary_ctxt_switches", DataType::Int64, true),
        // System info
        string_field("wchan", true),
        Field::new("oom_score", DataType::Int16, true),
        Field::new("oom_score_adj", DataType::Int16, true),
        string_field("cgroup_path", true),
        string_field("systemd_unit", true),
        string_field("container_id", true),
        // Namespaces
        Field::new("ns_pid", DataType::Int64, true),
        Field::new("ns_mnt", DataType::Int64, true),
        // Network/FD info
        Field::new("fd_count", DataType::Int16, true),
        Field::new("tcp_listen_count", DataType::Int16, true),
        Field::new("tcp_estab_count", DataType::Int16, true),
        Field::new("child_count", DataType::Int16, true),
    ])
}

/// Schema for `proc_features` table: Derived features.
pub fn proc_features_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        string_field("session_id", false),
        Field::new("pid", DataType::Int32, false),
        string_field("start_id", false),
        timestamp_field("feature_ts", false),
        // Type classification
        string_field("proc_type", false),
        Field::new("proc_type_conf", DataType::Float32, false),
        // Age features
        Field::new("age_s", DataType::Int64, false),
        Field::new("age_ratio", DataType::Float32, false),
        string_field("age_bucket", false),
        // CPU features
        Field::new("cpu_pct_instant", DataType::Float32, false),
        Field::new("cpu_pct_avg", DataType::Float32, true),
        Field::new("cpu_delta_ticks", DataType::Int64, true),
        Field::new("cpu_utilization", DataType::Float32, true),
        Field::new("cpu_stalled", DataType::Boolean, true),
        Field::new("cpu_spinning", DataType::Boolean, true),
        // Memory features
        Field::new("mem_mb", DataType::Float32, false),
        Field::new("mem_pct", DataType::Float32, false),
        Field::new("mem_growth_rate", DataType::Float32, true),
        string_field("mem_bucket", false),
        // I/O features
        Field::new("io_read_rate", DataType::Float32, true),
        Field::new("io_write_rate", DataType::Float32, true),
        Field::new("io_active", DataType::Boolean, true),
        Field::new("io_idle", DataType::Boolean, true),
        // State features
        Field::new("is_orphan", DataType::Boolean, false),
        Field::new("is_zombie", DataType::Boolean, false),
        Field::new("is_stopped", DataType::Boolean, false),
        Field::new("is_sleeping", DataType::Boolean, false),
        Field::new("is_running", DataType::Boolean, false),
        // TTY features
        Field::new("has_tty", DataType::Boolean, false),
        Field::new("tty_active", DataType::Boolean, true),
        Field::new("tty_dead", DataType::Boolean, true),
        // Network features
        Field::new("has_network", DataType::Boolean, true),
        Field::new("is_listener", DataType::Boolean, true),
        // Children features
        Field::new("has_children", DataType::Boolean, false),
        Field::new("children_active", DataType::Boolean, true),
        // Pattern features
        string_field("cmd_pattern", false),
        string_field("cmd_category", false),
        Field::new("is_protected", DataType::Boolean, false),
        // Historical features
        string_field("prior_decision", true),
        Field::new("prior_decision_count", DataType::Int32, true),
    ])
}

/// Schema for `proc_inference` table: Inference results.
pub fn proc_inference_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        string_field("session_id", false),
        Field::new("pid", DataType::Int32, false),
        string_field("start_id", false),
        timestamp_field("inference_ts", false),
        // Posterior probabilities
        Field::new("p_abandoned", DataType::Float32, false),
        Field::new("p_legitimate", DataType::Float32, false),
        Field::new("p_uncertain", DataType::Float32, false),
        // Bayesian factors
        Field::new("log_bayes_factor", DataType::Float32, false),
        string_field("bayes_factor_interpretation", false),
        // Scores and confidence
        Field::new("score", DataType::Float32, false),
        string_field("confidence", false),
        string_field("recommendation", false),
        // Evidence breakdown
        Field::new("evidence_prior", DataType::Float32, false),
        Field::new("evidence_age", DataType::Float32, false),
        Field::new("evidence_cpu", DataType::Float32, false),
        Field::new("evidence_memory", DataType::Float32, false),
        Field::new("evidence_io", DataType::Float32, false),
        Field::new("evidence_state", DataType::Float32, false),
        Field::new("evidence_network", DataType::Float32, false),
        Field::new("evidence_children", DataType::Float32, false),
        Field::new("evidence_history", DataType::Float32, false),
        Field::new("evidence_deep", DataType::Float32, true),
        // Evidence ledger (list of tags stored as JSON array string)
        string_field("evidence_tags_json", false),
        string_field("evidence_ledger_json", true),
        // Safety gates
        Field::new("passed_safety_gates", DataType::Boolean, false),
        string_field("blocked_by_gate", true),
        string_field("safety_gate_details", true),
        // Signature match info (for calibration tracking)
        string_field("signature_id", true),
        string_field("signature_category", true),
        Field::new("signature_match_confidence", DataType::Float32, true),
        Field::new("signature_fast_path_used", DataType::Boolean, true),
    ])
}

/// Schema for `outcomes` table: Action outcomes and feedback.
pub fn outcomes_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        string_field("session_id", false),
        timestamp_field("outcome_ts", false),
        Field::new("pid", DataType::Int32, false),
        string_field("start_id", false),
        // Decision
        string_field("recommendation", false),
        string_field("decision", false),
        string_field("decision_source", false),
        // Action
        string_field("action_type", true),
        Field::new("action_attempted", DataType::Boolean, false),
        Field::new("action_successful", DataType::Boolean, true),
        string_field("signal_sent", true),
        string_field("signal_response", true),
        // Verification
        Field::new("verified_identity", DataType::Boolean, true),
        Field::new("pid_at_action", DataType::Int32, true),
        Field::new("start_id_matched", DataType::Boolean, true),
        // Result
        string_field("process_state_after", true),
        Field::new("memory_freed_bytes", DataType::Int64, true),
        string_field("error_message", true),
        // Feedback
        string_field("user_feedback", true),
        timestamp_field("feedback_ts", true),
        string_field("feedback_note", true),
        // Context
        string_field("cmd", false),
        string_field("cmdline_hash", true),
        Field::new("score", DataType::Float32, false),
        string_field("proc_type", false),
    ])
}

/// Schema for `audit` table: Audit trail.
pub fn audit_schema() -> Schema {
    Schema::new(vec![
        timestamp_field("audit_ts", false),
        string_field("session_id", false),
        string_field("event_type", false),
        string_field("severity", false),
        string_field("actor", false),
        Field::new("target_pid", DataType::Int32, true),
        string_field("target_start_id", true),
        string_field("message", false),
        string_field("details_json", true),
        string_field("host_id", false),
    ])
}

/// Schema for `signature_matches` table: Signature match calibration data.
///
/// This table tracks signature match outcomes for calibration analysis.
/// It enables computing reliability curves, confusion matrices by signature
/// category, and threshold tuning recommendations.
pub fn signature_matches_schema() -> Schema {
    Schema::new(vec![
        // Identifiers
        string_field("session_id", false),
        timestamp_field("match_ts", false),
        Field::new("pid", DataType::Int32, false),
        string_field("start_id", false),
        // Signature info
        string_field("signature_id", false),
        string_field("signature_category", false),
        string_field("signature_name", true),
        // Match details
        Field::new("match_confidence", DataType::Float32, false),
        Field::new("pattern_match_score", DataType::Float32, true),
        Field::new("behavioral_match_score", DataType::Float32, true),
        // Predicted outcome
        Field::new("predicted_prob_abandoned", DataType::Float32, false),
        Field::new("predicted_prob_legitimate", DataType::Float32, false),
        string_field("prediction_class", false), // abandoned, legitimate, uncertain
        Field::new("fast_path_used", DataType::Boolean, false),
        // Thresholds used
        Field::new("high_conf_threshold", DataType::Float32, true),
        Field::new("min_match_threshold", DataType::Float32, true),
        // Process context (redacted)
        string_field("cmd", false),
        string_field("cmdline_hash", true),
        string_field("proc_type", false),
        Field::new("age_s", DataType::Int64, false),
        Field::new("cpu_pct", DataType::Float32, true),
        Field::new("mem_mb", DataType::Float32, true),
        // Actual outcome (filled in later)
        Field::new("actual_abandoned", DataType::Boolean, true),
        string_field("human_decision", true), // kill, spare, none
        timestamp_field("outcome_ts", true),
        string_field("outcome_source", true), // user_confirm, timeout, process_exit, etc.
        // Calibration flags
        Field::new("outcome_available", DataType::Boolean, false),
        Field::new("included_in_calibration", DataType::Boolean, false),
        // Host info
        string_field("host_id", false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runs_schema() {
        let schema = runs_schema();
        assert!(schema.field_with_name("session_id").is_ok());
        assert!(schema.field_with_name("started_at").is_ok());
        assert!(schema.field_with_name("schema_version").is_ok());
    }

    #[test]
    fn test_proc_samples_schema() {
        let schema = proc_samples_schema();
        assert!(schema.field_with_name("session_id").is_ok());
        assert!(schema.field_with_name("pid").is_ok());
        assert!(schema.field_with_name("start_id").is_ok());
        assert!(schema.field_with_name("rss_bytes").is_ok());
    }

    #[test]
    fn test_proc_features_schema() {
        let schema = proc_features_schema();
        assert!(schema.field_with_name("proc_type").is_ok());
        assert!(schema.field_with_name("is_orphan").is_ok());
        assert!(schema.field_with_name("cmd_category").is_ok());
    }

    #[test]
    fn test_proc_inference_schema() {
        let schema = proc_inference_schema();
        assert!(schema.field_with_name("p_abandoned").is_ok());
        assert!(schema.field_with_name("score").is_ok());
        assert!(schema.field_with_name("recommendation").is_ok());
    }

    #[test]
    fn test_outcomes_schema() {
        let schema = outcomes_schema();
        assert!(schema.field_with_name("decision").is_ok());
        assert!(schema.field_with_name("action_successful").is_ok());
        assert!(schema.field_with_name("user_feedback").is_ok());
    }

    #[test]
    fn test_audit_schema() {
        let schema = audit_schema();
        assert!(schema.field_with_name("event_type").is_ok());
        assert!(schema.field_with_name("severity").is_ok());
        assert!(schema.field_with_name("message").is_ok());
    }

    #[test]
    fn test_table_name_display() {
        assert_eq!(TableName::Runs.as_str(), "runs");
        assert_eq!(TableName::ProcSamples.as_str(), "proc_samples");
        assert_eq!(TableName::Audit.as_str(), "audit");
        assert_eq!(TableName::SignatureMatches.as_str(), "signature_matches");
    }

    #[test]
    fn test_telemetry_schema_get() {
        let schemas = TelemetrySchema::new();
        let runs = schemas.get(TableName::Runs);
        assert!(runs.field_with_name("session_id").is_ok());
    }

    #[test]
    fn test_retention_days() {
        assert_eq!(TableName::Runs.retention_days(), 90);
        assert_eq!(TableName::ProcSamples.retention_days(), 30);
        assert_eq!(TableName::Outcomes.retention_days(), 365);
        assert_eq!(TableName::SignatureMatches.retention_days(), 365);
    }

    #[test]
    fn test_signature_matches_schema() {
        let schema = signature_matches_schema();
        assert!(schema.field_with_name("signature_id").is_ok());
        assert!(schema.field_with_name("match_confidence").is_ok());
        assert!(schema.field_with_name("predicted_prob_abandoned").is_ok());
        assert!(schema.field_with_name("actual_abandoned").is_ok());
        assert!(schema.field_with_name("human_decision").is_ok());
        assert!(schema.field_with_name("outcome_available").is_ok());
    }

    #[test]
    fn test_proc_inference_signature_fields() {
        let schema = proc_inference_schema();
        assert!(schema.field_with_name("signature_id").is_ok());
        assert!(schema.field_with_name("signature_category").is_ok());
        assert!(schema.field_with_name("signature_match_confidence").is_ok());
        assert!(schema.field_with_name("signature_fast_path_used").is_ok());
    }
}
