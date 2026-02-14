//! Evidence source plugin interface.
//!
//! Evidence plugins receive a JSON array of PIDs on stdin and return
//! per-process evidence as JSON on stdout. The evidence is converted into
//! [`EvidenceTerm`] entries and folded into the posterior computation.
//!
//! # Plugin protocol (stdin → stdout)
//!
//! **Input** (JSON on stdin):
//! ```json
//! {"pids": [1234, 5678], "scan_id": "abc-123"}
//! ```
//!
//! **Output** (JSON on stdout):
//! ```json
//! {
//!   "plugin": "prometheus-metrics",
//!   "version": "0.1.0",
//!   "evidence": [
//!     {
//!       "pid": 1234,
//!       "features": {
//!         "request_rate": 0.0,
//!         "error_rate": 0.95
//!       },
//!       "log_likelihoods": {
//!         "useful": -0.5,
//!         "useful_bad": -1.2,
//!         "abandoned": -0.1,
//!         "zombie": -0.3
//!       }
//!     }
//!   ]
//! }
//! ```

use crate::inference::posterior::{ClassScores, EvidenceTerm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors from evidence plugin invocation.
#[derive(Debug, Error)]
pub enum EvidencePluginError {
    #[error("plugin {plugin} returned invalid JSON: {source}")]
    InvalidOutput {
        plugin: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("plugin {plugin} returned no evidence")]
    EmptyOutput { plugin: String },

    #[error("plugin {plugin} failed: {message}")]
    ExecutionFailed { plugin: String, message: String },

    #[error("plugin {plugin} timed out after {timeout_ms}ms")]
    Timeout { plugin: String, timeout_ms: u64 },
}

/// Input sent to an evidence plugin on stdin.
#[derive(Debug, Clone, Serialize)]
pub struct EvidencePluginInput {
    /// PIDs to gather evidence for.
    pub pids: Vec<u32>,
    /// Scan identifier for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
}

/// A single process evidence entry from a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEvidenceEntry {
    /// Process ID this evidence applies to.
    pub pid: u32,
    /// Named features (for audit/display).
    #[serde(default)]
    pub features: HashMap<String, f64>,
    /// Per-class log-likelihoods.
    pub log_likelihoods: PluginLogLikelihoods,
}

/// Per-class log-likelihoods from a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLogLikelihoods {
    pub useful: f64,
    pub useful_bad: f64,
    pub abandoned: f64,
    pub zombie: f64,
}

impl PluginLogLikelihoods {
    /// Convert to ClassScores.
    pub fn to_class_scores(&self) -> ClassScores {
        ClassScores {
            useful: self.useful,
            useful_bad: self.useful_bad,
            abandoned: self.abandoned,
            zombie: self.zombie,
        }
    }
}

/// Full output from an evidence plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePluginOutput {
    /// Plugin name (for verification).
    pub plugin: String,
    /// Plugin version.
    pub version: String,
    /// Per-process evidence entries.
    pub evidence: Vec<PluginEvidenceEntry>,
}

/// Parse raw stdout from an evidence plugin.
pub fn parse_evidence_output(
    plugin_name: &str,
    stdout: &[u8],
) -> Result<EvidencePluginOutput, EvidencePluginError> {
    let output: EvidencePluginOutput =
        serde_json::from_slice(stdout).map_err(|e| EvidencePluginError::InvalidOutput {
            plugin: plugin_name.to_string(),
            source: e,
        })?;

    Ok(output)
}

/// Convert a plugin evidence entry into an EvidenceTerm for the posterior.
///
/// The feature name is prefixed with the plugin name to avoid collisions
/// with built-in evidence terms.
pub fn to_evidence_term(
    plugin_name: &str,
    entry: &PluginEvidenceEntry,
    weight: f64,
) -> EvidenceTerm {
    let raw = entry.log_likelihoods.to_class_scores();

    // Apply weight: scale log-likelihoods toward 0 (neutral).
    // weight=1.0 → full trust, weight=0.0 → ignore (all zeros).
    let scaled = ClassScores {
        useful: raw.useful * weight,
        useful_bad: raw.useful_bad * weight,
        abandoned: raw.abandoned * weight,
        zombie: raw.zombie * weight,
    };

    EvidenceTerm {
        feature: format!("plugin:{}", plugin_name),
        log_likelihood: scaled,
    }
}

/// Look up evidence for a specific PID from plugin output.
pub fn evidence_for_pid(output: &EvidencePluginOutput, pid: u32) -> Option<&PluginEvidenceEntry> {
    output.evidence.iter().find(|e| e.pid == pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_output() {
        let json = r#"{
            "plugin": "test",
            "version": "0.1.0",
            "evidence": [
                {
                    "pid": 1234,
                    "features": {"cpu_custom": 0.5},
                    "log_likelihoods": {
                        "useful": -0.5,
                        "useful_bad": -1.0,
                        "abandoned": -0.1,
                        "zombie": -0.2
                    }
                }
            ]
        }"#;

        let output = parse_evidence_output("test", json.as_bytes()).unwrap();
        assert_eq!(output.plugin, "test");
        assert_eq!(output.evidence.len(), 1);
        assert_eq!(output.evidence[0].pid, 1234);
        assert!((output.evidence[0].log_likelihoods.useful - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_evidence_output("bad", b"not json");
        assert!(matches!(
            result.unwrap_err(),
            EvidencePluginError::InvalidOutput { .. }
        ));
    }

    #[test]
    fn test_to_evidence_term_full_weight() {
        let entry = PluginEvidenceEntry {
            pid: 42,
            features: HashMap::new(),
            log_likelihoods: PluginLogLikelihoods {
                useful: -1.0,
                useful_bad: -2.0,
                abandoned: -0.5,
                zombie: -0.3,
            },
        };

        let term = to_evidence_term("prom", &entry, 1.0);
        assert_eq!(term.feature, "plugin:prom");
        assert!((term.log_likelihood.useful - (-1.0)).abs() < f64::EPSILON);
        assert!((term.log_likelihood.abandoned - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_to_evidence_term_half_weight() {
        let entry = PluginEvidenceEntry {
            pid: 42,
            features: HashMap::new(),
            log_likelihoods: PluginLogLikelihoods {
                useful: -2.0,
                useful_bad: -4.0,
                abandoned: -1.0,
                zombie: -0.6,
            },
        };

        let term = to_evidence_term("half", &entry, 0.5);
        assert!((term.log_likelihood.useful - (-1.0)).abs() < f64::EPSILON);
        assert!((term.log_likelihood.abandoned - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_to_evidence_term_zero_weight() {
        let entry = PluginEvidenceEntry {
            pid: 42,
            features: HashMap::new(),
            log_likelihoods: PluginLogLikelihoods {
                useful: -5.0,
                useful_bad: -5.0,
                abandoned: -5.0,
                zombie: -5.0,
            },
        };

        let term = to_evidence_term("zero", &entry, 0.0);
        assert!((term.log_likelihood.useful).abs() < f64::EPSILON);
        assert!((term.log_likelihood.zombie).abs() < f64::EPSILON);
    }

    #[test]
    fn test_evidence_for_pid() {
        let output = EvidencePluginOutput {
            plugin: "test".to_string(),
            version: "1.0.0".to_string(),
            evidence: vec![
                PluginEvidenceEntry {
                    pid: 100,
                    features: HashMap::new(),
                    log_likelihoods: PluginLogLikelihoods {
                        useful: 0.0,
                        useful_bad: 0.0,
                        abandoned: -1.0,
                        zombie: 0.0,
                    },
                },
                PluginEvidenceEntry {
                    pid: 200,
                    features: HashMap::new(),
                    log_likelihoods: PluginLogLikelihoods {
                        useful: -2.0,
                        useful_bad: 0.0,
                        abandoned: 0.0,
                        zombie: 0.0,
                    },
                },
            ],
        };

        let e100 = evidence_for_pid(&output, 100).unwrap();
        assert!((e100.log_likelihoods.abandoned - (-1.0)).abs() < f64::EPSILON);

        let e200 = evidence_for_pid(&output, 200).unwrap();
        assert!((e200.log_likelihoods.useful - (-2.0)).abs() < f64::EPSILON);

        assert!(evidence_for_pid(&output, 999).is_none());
    }

    #[test]
    fn test_plugin_input_serialization() {
        let input = EvidencePluginInput {
            pids: vec![1, 2, 3],
            scan_id: Some("scan-123".to_string()),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"pids\":[1,2,3]"));
        assert!(json.contains("\"scan_id\":\"scan-123\""));
    }

    #[test]
    fn test_plugin_input_no_scan_id() {
        let input = EvidencePluginInput {
            pids: vec![42],
            scan_id: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("scan_id"));
    }
}
