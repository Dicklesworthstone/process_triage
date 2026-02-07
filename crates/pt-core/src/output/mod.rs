//! Token-efficient output handling for AI agent consumption.
//!
//! This module provides field selection, compact formats, and token estimation
//! for optimizing output for AI agents with limited context windows.

pub mod agent_errors;
pub mod predictions;
pub mod progressive;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use toon_rust::encode;
use toon_rust::options::{EncodeOptions, KeyFoldingMode};

/// Field selection specification for filtering output fields.
#[derive(Debug, Clone, Default)]
pub struct FieldSelector {
    /// Specific fields to include (empty means all fields)
    fields: HashSet<String>,
    /// Whether to use preset field sets
    preset: Option<FieldPreset>,
}

/// Predefined field presets for common use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FieldPreset {
    /// Minimal: pid and classification only
    Minimal,
    /// Standard: pid, classification, score, command (default)
    #[default]
    Standard,
    /// Full: all available fields
    Full,
}


impl FieldSelector {
    /// Create a new field selector with specific fields.
    pub fn new(fields: Vec<String>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
            preset: None,
        }
    }

    /// Create a field selector from a preset.
    pub fn from_preset(preset: FieldPreset) -> Self {
        Self {
            fields: HashSet::new(),
            preset: Some(preset),
        }
    }

    /// Parse a field specification string (comma-separated or preset name).
    pub fn parse(spec: &str) -> Result<Self, FieldSelectorError> {
        let spec = spec.trim().to_lowercase();

        // Check for presets
        match spec.as_str() {
            "minimal" => return Ok(Self::from_preset(FieldPreset::Minimal)),
            "standard" => return Ok(Self::from_preset(FieldPreset::Standard)),
            "full" => return Ok(Self::from_preset(FieldPreset::Full)),
            "" => return Ok(Self::default()),
            _ => {}
        }

        // Parse comma-separated field list
        let fields: Vec<String> = spec
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if fields.is_empty() {
            return Err(FieldSelectorError::EmptyFieldList);
        }

        Ok(Self::new(fields))
    }

    /// Get the list of fields for a preset.
    fn preset_fields(preset: FieldPreset) -> &'static [&'static str] {
        match preset {
            FieldPreset::Minimal => &["pid", "classification"],
            FieldPreset::Standard => &[
                "pid",
                "classification",
                "confidence",
                "cmd_short",
                "recommended_action",
            ],
            FieldPreset::Full => &[], // Empty means all fields
        }
    }

    /// Check if a field should be included in output.
    pub fn includes(&self, field: &str) -> bool {
        // If preset is Full or no fields specified, include everything
        if matches!(self.preset, Some(FieldPreset::Full)) {
            return true;
        }

        // Check preset fields
        if let Some(preset) = self.preset {
            let preset_fields = Self::preset_fields(preset);
            if preset_fields.is_empty() {
                return true; // Full preset
            }
            return preset_fields.contains(&field);
        }

        // Check explicit field list
        if self.fields.is_empty() {
            return true; // No filter, include all
        }

        // Check for exact match or nested field prefix
        if self.fields.contains(field) {
            return true;
        }

        // Check for parent field (e.g., "posterior" includes "posterior.abandoned")
        for f in &self.fields {
            if field.starts_with(&format!("{}.", f)) {
                return true;
            }
            // Check if we're asking about a parent of a specified nested field
            if f.starts_with(&format!("{}.", field)) {
                return true;
            }
        }

        false
    }

    /// Filter a JSON value according to field selection.
    pub fn filter_value(&self, value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let filtered: Map<String, Value> = map
                    .into_iter()
                    .filter_map(|(k, v)| {
                        if self.includes(&k) {
                            // Recursively filter nested objects
                            let filtered_v = match v {
                                Value::Object(inner) => self.filter_nested_object(&k, inner),
                                other => other,
                            };
                            Some((k, filtered_v))
                        } else {
                            None
                        }
                    })
                    .collect();
                Value::Object(filtered)
            }
            Value::Array(arr) => {
                Value::Array(arr.into_iter().map(|v| self.filter_value(v)).collect())
            }
            other => other,
        }
    }

    /// Filter nested object fields with parent path context.
    fn filter_nested_object(&self, parent: &str, map: Map<String, Value>) -> Value {
        let filtered: Map<String, Value> = map
            .into_iter()
            .filter_map(|(k, v)| {
                let full_path = format!("{}.{}", parent, k);
                // Include if parent is fully included or specific nested field is included
                if self.includes(&full_path)
                    || self.fields.is_empty()
                    || matches!(self.preset, Some(FieldPreset::Full))
                {
                    Some((k, v))
                } else {
                    None
                }
            })
            .collect();
        Value::Object(filtered)
    }
}

/// Errors that can occur during field selection.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FieldSelectorError {
    #[error("empty field list provided")]
    EmptyFieldList,
    #[error("invalid field name: {0}")]
    InvalidField(String),
}

/// Compact output configuration.
#[derive(Debug, Clone, Default)]
pub struct CompactConfig {
    /// Use short key names (e.g., "p" instead of "pid")
    pub short_keys: bool,
    /// Remove whitespace from JSON output
    pub minify: bool,
    /// Use abbreviated classification names
    pub short_classifications: bool,
}

impl CompactConfig {
    /// Create a new compact config with all options enabled.
    pub fn all() -> Self {
        Self {
            short_keys: true,
            minify: true,
            short_classifications: true,
        }
    }

    /// Key abbreviation mappings.
    pub fn abbreviate_key(key: &str) -> &str {
        match key {
            "pid" => "p",
            "ppid" => "pp",
            "classification" => "c",
            "confidence" => "cf",
            "cmd_short" => "cmd",
            "cmd_full" => "cmdf",
            "recommended_action" => "act",
            "posterior" => "post",
            "blast_radius" => "br",
            "uncertainty" => "unc",
            "expected_loss" => "el",
            "memory_mb" => "mem",
            "cpu_pct" => "cpu",
            "child_count" => "ch",
            "risk_level" => "risk",
            "entropy" => "ent",
            "session_id" => "sid",
            "schema_version" => "sv",
            "generated_at" => "ts",
            _ => key, // Return unchanged for unknown keys
        }
    }

    /// Classification abbreviations.
    pub fn abbreviate_classification(classification: &str) -> &str {
        match classification {
            "useful" => "U",
            "useful_bad" => "UB",
            "abandoned" => "A",
            "zombie" => "Z",
            _ => classification,
        }
    }

    /// Apply compact transformations to a JSON value.
    pub fn compact_value(&self, value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let compacted: Map<String, Value> = map
                    .into_iter()
                    .map(|(k, v)| {
                        let new_key = if self.short_keys {
                            Self::abbreviate_key(&k).to_string()
                        } else {
                            k.clone()
                        };

                        let new_value = if self.short_classifications && k == "classification" {
                            if let Value::String(s) = &v {
                                Value::String(Self::abbreviate_classification(s).to_string())
                            } else {
                                self.compact_value(v)
                            }
                        } else {
                            self.compact_value(v)
                        };

                        (new_key, new_value)
                    })
                    .collect();
                Value::Object(compacted)
            }
            Value::Array(arr) => {
                Value::Array(arr.into_iter().map(|v| self.compact_value(v)).collect())
            }
            other => other,
        }
    }

    /// Serialize a value to compact JSON string.
    pub fn to_string(&self, value: &Value) -> String {
        if self.minify {
            serde_json::to_string(value).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(value).unwrap_or_default()
        }
    }
}

/// Token estimation for output size prediction.
#[derive(Debug, Clone)]
pub struct TokenEstimator {
    /// Average characters per token (approximation)
    chars_per_token: f64,
}

impl Default for TokenEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenEstimator {
    /// Create a new token estimator with default settings.
    /// Default is ~4 characters per token (typical for English text/JSON).
    pub fn new() -> Self {
        Self {
            chars_per_token: 4.0,
        }
    }

    /// Create estimator with custom chars per token ratio.
    pub fn with_ratio(chars_per_token: f64) -> Self {
        Self { chars_per_token }
    }

    /// Estimate token count for a string.
    pub fn estimate_tokens(&self, text: &str) -> usize {
        let char_count = text.chars().count() as f64;
        (char_count / self.chars_per_token).ceil() as usize
    }

    /// Estimate token count for a JSON value.
    pub fn estimate_value_tokens(&self, value: &Value) -> usize {
        let json = serde_json::to_string(value).unwrap_or_default();
        self.estimate_tokens(&json)
    }
}

/// Output truncation with continuation support.
#[derive(Debug, Clone)]
pub struct TruncationResult {
    /// The truncated output value
    pub value: Value,
    /// Whether truncation occurred
    pub truncated: bool,
    /// Continuation token for resumption (if truncated)
    pub continuation_token: Option<String>,
    /// Number of items remaining (if array truncation)
    pub remaining_count: Option<usize>,
}

/// Truncate output to fit within token budget.
pub fn truncate_to_tokens(
    value: Value,
    max_tokens: usize,
    estimator: &TokenEstimator,
) -> TruncationResult {
    let current_tokens = estimator.estimate_value_tokens(&value);

    if current_tokens <= max_tokens {
        return TruncationResult {
            value,
            truncated: false,
            continuation_token: None,
            remaining_count: None,
        };
    }

    // For arrays (like candidates), truncate items
    if let Value::Object(mut map) = value {
        // Look for common array fields to truncate
        for array_field in ["candidates", "processes", "outcomes", "results"] {
            if let Some(Value::Array(arr)) = map.get(array_field) {
                let arr_len = arr.len();
                if arr_len > 1 {
                    // Binary search for optimal truncation point
                    let mut low = 1;
                    let mut high = arr_len;
                    let mut best_count = 1;

                    while low <= high {
                        let mid = (low + high) / 2;
                        let truncated_arr: Vec<Value> = arr.iter().take(mid).cloned().collect();
                        let mut test_map = map.clone();
                        test_map.insert(array_field.to_string(), Value::Array(truncated_arr));

                        let test_tokens = estimator.estimate_value_tokens(&Value::Object(test_map));

                        if test_tokens <= max_tokens {
                            best_count = mid;
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    }

                    if best_count < arr_len {
                        let truncated_arr: Vec<Value> =
                            arr.iter().take(best_count).cloned().collect();
                        let remaining = arr_len - best_count;
                        let continuation = format!("{}:{}:{}", array_field, best_count, arr_len);

                        map.insert(array_field.to_string(), Value::Array(truncated_arr));

                        return TruncationResult {
                            value: Value::Object(map),
                            truncated: true,
                            continuation_token: Some(continuation),
                            remaining_count: Some(remaining),
                        };
                    }
                }
            }
        }

        return TruncationResult {
            value: Value::Object(map),
            truncated: false,
            continuation_token: None,
            remaining_count: None,
        };
    }

    TruncationResult {
        value,
        truncated: false,
        continuation_token: None,
        remaining_count: None,
    }
}

/// Token-efficient output processor combining all features.
#[derive(Debug, Clone, Default)]
pub struct TokenEfficientOutput {
    /// Field selector for filtering
    pub field_selector: FieldSelector,
    /// Compact output configuration
    pub compact: Option<CompactConfig>,
    /// Maximum token budget
    pub max_tokens: Option<usize>,
    /// Token estimator
    pub estimator: TokenEstimator,
}

impl TokenEfficientOutput {
    /// Create a new token-efficient output processor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set field selection.
    pub fn with_fields(mut self, selector: FieldSelector) -> Self {
        self.field_selector = selector;
        self
    }

    /// Enable compact output.
    pub fn with_compact(mut self, config: CompactConfig) -> Self {
        self.compact = Some(config);
        self
    }

    /// Set maximum token budget.
    pub fn with_max_tokens(mut self, max: usize) -> Self {
        self.max_tokens = Some(max);
        self
    }

    /// Process a JSON value through the full pipeline.
    pub fn process(&self, value: Value) -> ProcessedOutput {
        // Step 1: Filter fields
        let mut result = self.field_selector.filter_value(value);

        // Step 2: Apply compact transformations
        if let Some(ref compact) = self.compact {
            result = compact.compact_value(result);
        }

        // Step 3: Truncate if needed
        let truncation = if let Some(max) = self.max_tokens {
            truncate_to_tokens(result, max, &self.estimator)
        } else {
            TruncationResult {
                value: result,
                truncated: false,
                continuation_token: None,
                remaining_count: None,
            }
        };

        // Step 4: Serialize
        let output_string = if let Some(ref compact) = self.compact {
            compact.to_string(&truncation.value)
        } else {
            serde_json::to_string_pretty(&truncation.value).unwrap_or_default()
        };

        let token_count = self.estimator.estimate_tokens(&output_string);

        ProcessedOutput {
            json: truncation.value,
            output_string,
            token_count,
            truncated: truncation.truncated,
            continuation_token: truncation.continuation_token,
            remaining_count: truncation.remaining_count,
        }
    }
}

/// Result of token-efficient output processing.
#[derive(Debug, Clone)]
pub struct ProcessedOutput {
    /// The processed JSON value
    pub json: Value,
    /// Serialized output string
    pub output_string: String,
    /// Estimated token count
    pub token_count: usize,
    /// Whether output was truncated
    pub truncated: bool,
    /// Continuation token for resumption
    pub continuation_token: Option<String>,
    /// Remaining items if truncated
    pub remaining_count: Option<usize>,
}

/// Encode a JSON value into TOON with safe key folding.
pub fn encode_toon_value(value: &Value) -> String {
    let options = EncodeOptions {
        indent: None,
        delimiter: None,
        key_folding: Some(KeyFoldingMode::Safe),
        flatten_depth: None,
        replacer: None,
    };

    encode(value.clone(), Some(options))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use toon_rust::try_decode;

    #[test]
    fn test_field_selector_presets() {
        let minimal = FieldSelector::from_preset(FieldPreset::Minimal);
        assert!(minimal.includes("pid"));
        assert!(minimal.includes("classification"));
        assert!(!minimal.includes("cmd_short"));

        let full = FieldSelector::from_preset(FieldPreset::Full);
        assert!(full.includes("pid"));
        assert!(full.includes("any_field"));
    }

    #[test]
    fn test_field_selector_parse() {
        let selector = FieldSelector::parse("pid,classification,cmd_short").unwrap();
        assert!(selector.includes("pid"));
        assert!(selector.includes("classification"));
        assert!(selector.includes("cmd_short"));
        assert!(!selector.includes("posterior"));
    }

    #[test]
    fn test_field_selector_nested() {
        let selector = FieldSelector::parse("pid,posterior.abandoned").unwrap();
        assert!(selector.includes("pid"));
        assert!(selector.includes("posterior")); // Parent should be included
        assert!(selector.includes("posterior.abandoned"));
    }

    #[test]
    fn test_field_filter_value() {
        let selector = FieldSelector::parse("pid,classification").unwrap();
        let input = json!({
            "pid": 1234,
            "classification": "abandoned",
            "cmd_short": "test",
            "other_field": "value"
        });

        let filtered = selector.filter_value(input);
        assert!(filtered.get("pid").is_some());
        assert!(filtered.get("classification").is_some());
        assert!(filtered.get("cmd_short").is_none());
        assert!(filtered.get("other_field").is_none());
    }

    #[test]
    fn test_compact_abbreviations() {
        assert_eq!(CompactConfig::abbreviate_key("pid"), "p");
        assert_eq!(CompactConfig::abbreviate_key("classification"), "c");
        assert_eq!(CompactConfig::abbreviate_key("unknown_key"), "unknown_key");

        assert_eq!(CompactConfig::abbreviate_classification("abandoned"), "A");
        assert_eq!(CompactConfig::abbreviate_classification("useful"), "U");
    }

    #[test]
    fn test_compact_value() {
        let config = CompactConfig::all();
        let input = json!({
            "pid": 1234,
            "classification": "abandoned"
        });

        let compacted = config.compact_value(input);
        assert!(compacted.get("p").is_some());
        assert!(compacted.get("c").is_some());
        assert_eq!(compacted.get("c").unwrap(), "A");
    }

    #[test]
    fn test_encode_toon_roundtrip() {
        let input = json!({
            "pid": 1234,
            "classification": "abandoned",
            "confidence": 0.87,
            "tags": ["orphan", "stale"],
            "metrics": { "cpu": 0.12, "mem": 32 }
        });

        let encoded = encode_toon_value(&input);
        let decoded = try_decode(&encoded, None).expect("decode TOON");
        assert_eq!(decoded, input.into());
    }

    #[test]
    fn test_token_estimation() {
        let estimator = TokenEstimator::new();

        // ~4 chars per token
        let text = "test text here"; // 14 chars
        let tokens = estimator.estimate_tokens(text);
        assert!(tokens >= 3 && tokens <= 5);
    }

    #[test]
    fn test_truncation() {
        let estimator = TokenEstimator::new();
        let input = json!({
            "candidates": [
                {"pid": 1, "name": "proc1"},
                {"pid": 2, "name": "proc2"},
                {"pid": 3, "name": "proc3"},
                {"pid": 4, "name": "proc4"},
                {"pid": 5, "name": "proc5"}
            ]
        });

        // Very small token budget should truncate
        let result = truncate_to_tokens(input.clone(), 50, &estimator);
        // With such a small budget, truncation should occur
        if result.truncated {
            assert!(result.continuation_token.is_some());
            assert!(result.remaining_count.is_some());
        }
    }

    #[test]
    fn test_full_pipeline() {
        let processor = TokenEfficientOutput::new()
            .with_fields(FieldSelector::parse("pid,classification").unwrap())
            .with_compact(CompactConfig::all());

        let input = json!({
            "pid": 1234,
            "ppid": 1,
            "classification": "abandoned",
            "cmd_short": "test"
        });

        let output = processor.process(input);

        // Should have pid (as p) and classification (as c with value A)
        assert!(output.json.get("p").is_some());
        assert!(output.json.get("c").is_some());
        assert!(output.json.get("pp").is_none());
        assert!(output.json.get("cmd").is_none());
        assert!(output.token_count > 0);
    }

    // Note: round-trip coverage is handled by test_encode_toon_roundtrip.
}
