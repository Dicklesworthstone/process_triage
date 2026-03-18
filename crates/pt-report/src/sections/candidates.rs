//! Candidates section data.

use serde::{Deserialize, Serialize};

/// Single candidate row for the table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateRow {
    /// Process ID.
    pub pid: u32,
    /// Process start ID (unique identifier).
    pub start_id: String,
    /// Command name.
    pub cmd: String,
    /// Command pattern (normalized).
    pub cmd_pattern: String,
    /// Process category.
    pub cmd_category: Option<String>,
    /// Process type classification.
    pub proc_type: String,
    /// Process type confidence.
    pub proc_type_conf: f64,

    // Probabilities
    /// Probability of being abandoned.
    pub p_abandoned: f64,
    /// Probability of being legitimate.
    pub p_legitimate: f64,
    /// Uncertainty probability.
    pub p_uncertain: f64,
    /// Overall score (0-1).
    pub score: f64,
    /// Confidence level.
    pub confidence: String,
    /// Recommendation (kill/spare/review).
    pub recommendation: String,

    // Resource usage
    /// Age in seconds.
    pub age_s: u64,
    /// CPU percentage.
    pub cpu_pct: f64,
    /// Memory percentage.
    pub mem_pct: f64,
    /// Memory in MB.
    pub mem_mb: f64,
    /// IO read rate (bytes/s).
    pub io_read_rate: f64,
    /// IO write rate (bytes/s).
    pub io_write_rate: f64,

    // State flags
    /// Is orphan process.
    pub is_orphan: bool,
    /// Is zombie process.
    pub is_zombie: bool,
    /// Has network connections.
    pub has_network: bool,
    /// Has child processes.
    pub has_children: bool,
    /// Is protected from actions.
    pub is_protected: bool,

    // Safety
    /// Passed all safety gates.
    pub passed_safety_gates: bool,
    /// Gate that blocked action.
    pub blocked_by_gate: Option<String>,

    // Evidence tags
    /// Evidence tags for quick reference.
    pub evidence_tags: Vec<String>,

    // Provenance
    /// Provenance narrative headline (one-line summary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_headline: Option<String>,
    /// Blast-radius risk level (low/medium/high/critical).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_risk: Option<String>,
    /// Number of other processes/resources affected if killed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_affected: Option<usize>,
}

impl CandidateRow {
    /// Format age as human-readable string.
    pub fn age_formatted(&self) -> String {
        let age = self.age_s;
        if age >= 86400 {
            format!("{}d", age / 86400)
        } else if age >= 3600 {
            format!("{}h", age / 3600)
        } else if age >= 60 {
            format!("{}m", age / 60)
        } else {
            format!("{}s", age)
        }
    }

    /// Format memory as human-readable string.
    pub fn mem_formatted(&self) -> String {
        if self.mem_mb >= 1024.0 {
            format!("{:.1} GB", self.mem_mb / 1024.0)
        } else if self.mem_mb >= 1.0 {
            format!("{:.0} MB", self.mem_mb)
        } else {
            format!("{:.1} MB", self.mem_mb)
        }
    }

    /// Get CSS class for recommendation badge.
    pub fn recommendation_class(&self) -> &'static str {
        match self.recommendation.as_str() {
            "kill" => "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
            "spare" => "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
            _ => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
        }
    }

    /// Get CSS class for score color.
    pub fn score_class(&self) -> &'static str {
        if self.score >= 0.8 {
            "text-red-600 dark:text-red-400"
        } else if self.score >= 0.5 {
            "text-yellow-600 dark:text-yellow-400"
        } else {
            "text-green-600 dark:text-green-400"
        }
    }
}

/// Candidates section containing all candidate data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatesSection {
    /// All candidate rows.
    pub candidates: Vec<CandidateRow>,
    /// Total candidates (before limit).
    pub total_count: usize,
    /// Whether data was truncated.
    pub truncated: bool,
}

impl CandidatesSection {
    /// Create a new candidates section.
    pub fn new(candidates: Vec<CandidateRow>, total_count: usize) -> Self {
        let truncated = candidates.len() < total_count;
        Self {
            candidates,
            total_count,
            truncated,
        }
    }

    /// Get count of kill recommendations.
    pub fn kill_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.recommendation == "kill")
            .count()
    }

    /// Get count of spare recommendations.
    pub fn spare_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.recommendation == "spare")
            .count()
    }

    /// Get count of review recommendations.
    pub fn review_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.recommendation == "review")
            .count()
    }

    /// Get mean score.
    pub fn mean_score(&self) -> f64 {
        if self.candidates.is_empty() {
            0.0
        } else {
            self.candidates.iter().map(|c| c.score).sum::<f64>() / self.candidates.len() as f64
        }
    }
}
