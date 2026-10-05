//! Fleet learning transfer: bundle, merge, normalize, diff.
//!
//! Provides a combined transfer workflow that packages priors and signatures
//! into a single bundle, supports weighted merging of Beta-distributed
//! hyperparameters, baseline normalization across different host types, and
//! diff preview before applying changes.

use crate::supervision::pattern_persistence::{
    ConflictResolution, ImportConflict, PersistedSchema,
};
use pt_config::priors::{BetaParams, ClassParams, Priors};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────

/// Current transfer bundle schema version.
pub const TRANSFER_SCHEMA_VERSION: &str = "1.0.0";

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("unsupported schema version: {0} (expected {TRANSFER_SCHEMA_VERSION})")]
    UnsupportedSchemaVersion(String),

    #[error("prior probabilities do not sum to 1.0 (sum = {0:.6})")]
    PriorProbSum(f64),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid weight: {0}")]
    InvalidWeight(String),

    #[error("invalid transfer configuration: {0}")]
    InvalidConfiguration(String),

    #[error("transfer contains detected sensitive content; intact configuration transfer refused")]
    SensitiveContent,
}

/// Non-fatal warning from bundle validation.
#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

// ── Core Types ────────────────────────────────────────────────────────────

/// A combined transfer bundle containing priors, signatures, and baseline stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferBundle {
    pub schema_version: String,
    pub exported_at: String,
    pub source_host_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priors: Option<Priors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<PersistedSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_stats: Option<BaselineStats>,
    pub checksum: String,
}

/// Summary statistics about the source host, used for baseline normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    pub total_processes_seen: u64,
    pub observation_window_hours: f64,
    /// Empirical class frequencies (class name -> fraction).
    /// BTreeMap ensures deterministic serialisation order for stable checksums.
    #[serde(default)]
    pub class_distribution: BTreeMap<String, f64>,
    pub mean_cpu_utilization: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_type: Option<String>,
}

/// Merge strategy for combining priors from two sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MergeStrategy {
    /// Weighted average of pseudo-observations (default).
    #[default]
    Weighted,
    /// Replace local priors entirely with incoming.
    Replace,
    /// Keep local priors, ignore incoming.
    KeepLocal,
}

impl std::str::FromStr for MergeStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "weighted" => Ok(Self::Weighted),
            "replace" => Ok(Self::Replace),
            "keep-local" => Ok(Self::KeepLocal),
            other => Err(format!(
                "unknown merge strategy '{}' (expected: weighted, replace, keep-local)",
                other
            )),
        }
    }
}

// ── Diff Types ────────────────────────────────────────────────────────────

/// Full diff between local state and an incoming transfer bundle.
#[derive(Debug, Clone, Serialize)]
pub struct TransferDiff {
    pub priors_changes: Vec<PriorChange>,
    pub signature_changes: Vec<SignatureChange>,
    pub baseline_adjustments: Vec<BaselineAdjustment>,
}

/// A change to a single class prior.
#[derive(Debug, Clone, Serialize)]
pub struct PriorChange {
    pub class: String,
    pub field: String,
    pub local_value: f64,
    pub incoming_value: f64,
    pub merged_value: Option<f64>,
}

/// A change to a signature.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureChange {
    pub name: String,
    pub change_type: SignatureChangeType,
    pub local_confidence: Option<f64>,
    pub incoming_confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureChangeType {
    Added,
    Removed,
    Updated,
    Unchanged,
}

/// An adjustment due to baseline normalization.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineAdjustment {
    pub class: String,
    pub field: String,
    pub original_value: f64,
    pub adjusted_value: f64,
    pub reason: String,
}

// ── Core Functions ────────────────────────────────────────────────────────

/// Create a transfer bundle from local priors, signatures, and baseline stats.
///
/// The `host_id` is expected to already be HMAC-hashed (or a safe identifier).
pub fn export_bundle(
    priors: Option<&Priors>,
    signatures: Option<&PersistedSchema>,
    baseline: Option<&BaselineStats>,
    host_id: &str,
    profile: Option<&str>,
) -> Result<TransferBundle, TransferError> {
    let exported_at = chrono::Utc::now().to_rfc3339();

    // Build the bundle without checksum first, then compute it.
    let mut bundle = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
        exported_at,
        source_host_id: host_id.to_string(),
        source_host_profile: profile.map(|s| s.to_string()),
        priors: priors.cloned(),
        signatures: signatures.cloned(),
        baseline_stats: baseline.cloned(),
        checksum: String::new(),
    };

    bundle.checksum = compute_bundle_checksum(&bundle)?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// Compute the SHA-256 checksum of the bundle content (excluding the checksum field itself).
pub fn compute_bundle_checksum(bundle: &TransferBundle) -> Result<String, TransferError> {
    // Serialize a copy with empty checksum so the hash is stable.
    let mut for_hash = bundle.clone();
    for_hash.checksum = String::new();
    let mut value = serde_json::to_value(&for_hash)?;
    // Reuse the session checksum's canonical object ordering. Nested matcher
    // HashMaps may be reconstructed with a different order after deserialization.
    crate::session::snapshot_persist::canonicalize_json(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Validate a transfer bundle, returning warnings for non-fatal issues.
pub fn validate_bundle(bundle: &TransferBundle) -> Result<Vec<Warning>, TransferError> {
    // Guard before version/checksum diagnostics, which include supplied fields.
    // Intact operational configuration must not bypass content checks just
    // because it is packaged as opaque bytes. Refuse rather than redact its
    // executable matchers or echo detected values in a diagnostic.
    let content = serde_json::to_value(bundle)?;
    if contains_detected_secret(&content, &pt_redact::SecretDetector::new()) {
        return Err(TransferError::SensitiveContent);
    }
    let mut warnings = Vec::new();

    // 1. Check schema version.
    if bundle.schema_version != TRANSFER_SCHEMA_VERSION {
        // Allow forward-compatible reads for minor bumps, but warn.
        let parts: Vec<&str> = bundle.schema_version.split('.').collect();
        let local_parts: Vec<&str> = TRANSFER_SCHEMA_VERSION.split('.').collect();
        if parts.first() != local_parts.first() {
            return Err(TransferError::UnsupportedSchemaVersion(
                bundle.schema_version.clone(),
            ));
        }
        warnings.push(Warning {
            code: "schema_version_mismatch".to_string(),
            message: format!(
                "bundle schema {} differs from local {}",
                bundle.schema_version, TRANSFER_SCHEMA_VERSION,
            ),
        });
    }

    // 2. Verify checksum.
    let expected = compute_bundle_checksum(bundle)?;
    if bundle.checksum != expected {
        return Err(TransferError::ChecksumMismatch {
            expected,
            actual: bundle.checksum.clone(),
        });
    }

    // 3. Check prior_prob sum.
    if let Some(ref priors) = bundle.priors {
        let sum = priors.classes.useful.prior_prob
            + priors.classes.useful_bad.prior_prob
            + priors.classes.abandoned.prior_prob
            + priors.classes.zombie.prior_prob;
        if (sum - 1.0).abs() > 0.01 {
            return Err(TransferError::PriorProbSum(sum));
        }
        if (sum - 1.0).abs() > 1e-6 {
            warnings.push(Warning {
                code: "prior_prob_drift".to_string(),
                message: format!(
                    "class prior probabilities sum to {:.6}, not exactly 1.0",
                    sum
                ),
            });
        }
        pt_config::validate::validate_priors(priors)
            .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
    }

    if let Some(signatures) = &bundle.signatures {
        signatures
            .validate()
            .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
        for pattern in &signatures.patterns {
            // Inactive patterns can later be activated; validate them as well.
            pattern
                .signature
                .validate_for_activation()
                .map_err(|error| TransferError::InvalidConfiguration(error.to_string()))?;
        }
    }

    if let Some(stats) = &bundle.baseline_stats {
        if !stats.observation_window_hours.is_finite() || stats.observation_window_hours < 0.0 {
            return Err(TransferError::InvalidConfiguration(
                "baseline observation window must be finite and nonnegative".to_string(),
            ));
        }
        if !stats.mean_cpu_utilization.is_finite() || stats.mean_cpu_utilization < 0.0 {
            return Err(TransferError::InvalidConfiguration(
                "baseline CPU mean must be finite and nonnegative".to_string(),
            ));
        }
        if stats
            .class_distribution
            .values()
            .any(|fraction| !fraction.is_finite() || !(0.0..=1.0).contains(fraction))
            || (!stats.class_distribution.is_empty()
                && (stats.class_distribution.values().sum::<f64>() - 1.0).abs() > 1e-6)
        {
            return Err(TransferError::InvalidConfiguration(
                "baseline class fractions must be finite probabilities summing to one".to_string(),
            ));
        }
        if stats.total_processes_seen == 0
            && (stats.mean_cpu_utilization != 0.0 || !stats.class_distribution.is_empty())
        {
            return Err(TransferError::InvalidConfiguration(
                "empty baseline cannot contain a CPU mean or class observations".to_string(),
            ));
        }
    }

    // 4. Check for empty bundle.
    if bundle.priors.is_none() && bundle.signatures.is_none() {
        warnings.push(Warning {
            code: "empty_bundle".to_string(),
            message: "bundle contains neither priors nor signatures".to_string(),
        });
    }

    Ok(warnings)
}

fn contains_detected_secret(
    value: &serde_json::Value,
    detector: &pt_redact::SecretDetector,
) -> bool {
    match value {
        serde_json::Value::String(value) => contains_detected_secret_text(value, detector),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_detected_secret(value, detector)),
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            contains_detected_secret_text(key, detector)
                || contains_detected_secret(value, detector)
        }),
        _ => false,
    }
}

fn contains_detected_secret_text(value: &str, detector: &pt_redact::SecretDetector) -> bool {
    // Explicit credential and argument patterns span the complete text. Entropy
    // describes individual tokens, not an entire prose comment: the shipped
    // command-category explanation exceeds the detector's entropy threshold.
    !pt_redact::detect::find_all_secrets(value).is_empty()
        || value
            .split_whitespace()
            .any(|token| detector.detect(token).is_some())
}

/// Weighted merge of two Beta-distribution parameter sets.
///
/// α_merged = w_l·α_l + w_i·α_i
/// β_merged = w_l·β_l + w_i·β_i
pub fn merge_beta_params(
    local: &BetaParams,
    incoming: &BetaParams,
    local_weight: f64,
    incoming_weight: f64,
) -> Result<BetaParams, TransferError> {
    if local_weight < 0.0 || incoming_weight < 0.0 {
        return Err(TransferError::InvalidWeight(
            "weights must be non-negative".to_string(),
        ));
    }
    let total = local_weight + incoming_weight;
    if total == 0.0 {
        return Err(TransferError::InvalidWeight(
            "total weight must be positive".to_string(),
        ));
    }
    let wl = local_weight / total;
    let wi = incoming_weight / total;
    Ok(BetaParams::new(
        wl * local.alpha + wi * incoming.alpha,
        wl * local.beta + wi * incoming.beta,
    ))
}

/// Merge class parameters with weighted averaging of all Beta-distributed fields.
fn merge_class_params(
    local: &ClassParams,
    incoming: &ClassParams,
    local_weight: f64,
    incoming_weight: f64,
    strategy: MergeStrategy,
) -> Result<ClassParams, TransferError> {
    match strategy {
        MergeStrategy::Replace => Ok(incoming.clone()),
        MergeStrategy::KeepLocal => Ok(local.clone()),
        MergeStrategy::Weighted => {
            let total = local_weight + incoming_weight;
            let wl = if total > 0.0 {
                local_weight / total
            } else {
                0.5
            };
            let wi = 1.0 - wl;

            Ok(ClassParams {
                prior_prob: wl * local.prior_prob + wi * incoming.prior_prob,
                cpu_beta: merge_beta_params(&local.cpu_beta, &incoming.cpu_beta, wl, wi)?,
                runtime_gamma: local.runtime_gamma.clone(),
                orphan_beta: merge_beta_params(&local.orphan_beta, &incoming.orphan_beta, wl, wi)?,
                tty_beta: merge_beta_params(&local.tty_beta, &incoming.tty_beta, wl, wi)?,
                net_beta: merge_beta_params(&local.net_beta, &incoming.net_beta, wl, wi)?,
                io_active_beta: match (&local.io_active_beta, &incoming.io_active_beta) {
                    (Some(l), Some(i)) => Some(merge_beta_params(l, i, wl, wi)?),
                    (Some(l), None) => Some(l.clone()),
                    (None, Some(i)) => Some(i.clone()),
                    (None, None) => None,
                },
                queue_saturation_beta: match (
                    &local.queue_saturation_beta,
                    &incoming.queue_saturation_beta,
                ) {
                    (Some(l), Some(i)) => Some(merge_beta_params(l, i, wl, wi)?),
                    (Some(l), None) => Some(l.clone()),
                    (None, Some(i)) => Some(i.clone()),
                    (None, None) => None,
                },
                hazard_gamma: local.hazard_gamma.clone(),
                competing_hazards: local.competing_hazards.clone(),
            })
        }
    }
}

/// Merge priors from two sources using the given strategy.
///
/// For `Weighted`, uses equal weights (0.5/0.5) unless caller adjusts via
/// baseline normalization beforehand.
pub fn merge_priors(
    local: &Priors,
    incoming: &Priors,
    strategy: MergeStrategy,
) -> Result<Priors, TransferError> {
    merge_priors_weighted(local, incoming, strategy, 0.5, 0.5)
}

/// Merge priors with explicit weights.
pub fn merge_priors_weighted(
    local: &Priors,
    incoming: &Priors,
    strategy: MergeStrategy,
    local_weight: f64,
    incoming_weight: f64,
) -> Result<Priors, TransferError> {
    match strategy {
        MergeStrategy::Replace => Ok(incoming.clone()),
        MergeStrategy::KeepLocal => Ok(local.clone()),
        MergeStrategy::Weighted => {
            let mut merged = local.clone();

            merged.classes.useful = merge_class_params(
                &local.classes.useful,
                &incoming.classes.useful,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.useful_bad = merge_class_params(
                &local.classes.useful_bad,
                &incoming.classes.useful_bad,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.abandoned = merge_class_params(
                &local.classes.abandoned,
                &incoming.classes.abandoned,
                local_weight,
                incoming_weight,
                strategy,
            )?;
            merged.classes.zombie = merge_class_params(
                &local.classes.zombie,
                &incoming.classes.zombie,
                local_weight,
                incoming_weight,
                strategy,
            )?;

            // Renormalize prior_probs to sum to 1.0
            let sum = merged.classes.useful.prior_prob
                + merged.classes.useful_bad.prior_prob
                + merged.classes.abandoned.prior_prob
                + merged.classes.zombie.prior_prob;
            if sum > 0.0 {
                merged.classes.useful.prior_prob /= sum;
                merged.classes.useful_bad.prior_prob /= sum;
                merged.classes.abandoned.prior_prob /= sum;
                merged.classes.zombie.prior_prob /= sum;
            }

            merged.updated_at = Some(chrono::Utc::now().to_rfc3339());

            Ok(merged)
        }
    }
}

/// Adjust priors based on baseline differences between source and target hosts.
///
/// Scales Beta pseudo-observation counts by the ratio of total processes seen,
/// so priors from a high-traffic server are down-weighted when applied to a
/// workstation (and vice versa).
pub fn normalize_baseline(
    priors: &mut Priors,
    source_stats: &BaselineStats,
    target_stats: &BaselineStats,
) {
    if source_stats.total_processes_seen == 0 || target_stats.total_processes_seen == 0 {
        return;
    }

    // Scale factor: ratio of observation counts (clamped to [0.1, 10.0]).
    let raw_ratio =
        target_stats.total_processes_seen as f64 / source_stats.total_processes_seen as f64;
    let scale = raw_ratio.clamp(0.1, 10.0);

    fn scale_beta(bp: &mut BetaParams, factor: f64) {
        bp.alpha = (bp.alpha * factor).max(0.01);
        bp.beta = (bp.beta * factor).max(0.01);
    }

    for class in [
        &mut priors.classes.useful,
        &mut priors.classes.useful_bad,
        &mut priors.classes.abandoned,
        &mut priors.classes.zombie,
    ] {
        scale_beta(&mut class.cpu_beta, scale);
        scale_beta(&mut class.orphan_beta, scale);
        scale_beta(&mut class.tty_beta, scale);
        scale_beta(&mut class.net_beta, scale);
        if let Some(ref mut io) = class.io_active_beta {
            scale_beta(io, scale);
        }
    }
}

/// Compare local and incoming fields, optionally including the actual merged priors.
/// Comparison-only callers leave merged values unknown instead of predicting a strategy.
pub fn compute_diff(
    local_priors: Option<&Priors>,
    local_signatures: Option<&PersistedSchema>,
    incoming: &TransferBundle,
    merged_priors: Option<&Priors>,
) -> TransferDiff {
    let mut priors_changes = Vec::new();
    let mut signature_changes = Vec::new();
    let baseline_adjustments = Vec::new();

    // ── Priors diff ───────────────────────────────────────────────────
    if let (Some(lp), Some(ip)) = (local_priors, &incoming.priors) {
        diff_class(
            "useful",
            &lp.classes.useful,
            &ip.classes.useful,
            merged_priors.map(|priors| &priors.classes.useful),
            &mut priors_changes,
        );
        diff_class(
            "useful_bad",
            &lp.classes.useful_bad,
            &ip.classes.useful_bad,
            merged_priors.map(|priors| &priors.classes.useful_bad),
            &mut priors_changes,
        );
        diff_class(
            "abandoned",
            &lp.classes.abandoned,
            &ip.classes.abandoned,
            merged_priors.map(|priors| &priors.classes.abandoned),
            &mut priors_changes,
        );
        diff_class(
            "zombie",
            &lp.classes.zombie,
            &ip.classes.zombie,
            merged_priors.map(|priors| &priors.classes.zombie),
            &mut priors_changes,
        );
    }

    // ── Signature diff ────────────────────────────────────────────────
    if let Some(incoming_sigs) = &incoming.signatures {
        let local_names: HashMap<&str, f64> = local_signatures
            .map(|ls| {
                ls.patterns
                    .iter()
                    .map(|p| (p.signature.name.as_str(), p.signature.confidence_weight))
                    .collect()
            })
            .unwrap_or_default();

        let incoming_names: HashMap<&str, f64> = incoming_sigs
            .patterns
            .iter()
            .map(|p| (p.signature.name.as_str(), p.signature.confidence_weight))
            .collect();

        // Added or updated in incoming.
        for (name, &inc_conf) in &incoming_names {
            if let Some(&loc_conf) = local_names.get(name) {
                let change_type = if (loc_conf - inc_conf).abs() < 1e-9 {
                    SignatureChangeType::Unchanged
                } else {
                    SignatureChangeType::Updated
                };
                signature_changes.push(SignatureChange {
                    name: name.to_string(),
                    change_type,
                    local_confidence: Some(loc_conf),
                    incoming_confidence: Some(inc_conf),
                });
            } else {
                signature_changes.push(SignatureChange {
                    name: name.to_string(),
                    change_type: SignatureChangeType::Added,
                    local_confidence: None,
                    incoming_confidence: Some(inc_conf),
                });
            }
        }

        // Removed (in local but not in incoming).
        for (name, &loc_conf) in &local_names {
            if !incoming_names.contains_key(name) {
                signature_changes.push(SignatureChange {
                    name: name.to_string(),
                    change_type: SignatureChangeType::Removed,
                    local_confidence: Some(loc_conf),
                    incoming_confidence: None,
                });
            }
        }
    }

    TransferDiff {
        priors_changes,
        signature_changes,
        baseline_adjustments,
    }
}

/// Helper: diff a single class's key numeric fields.
fn diff_class(
    class: &str,
    local: &ClassParams,
    incoming: &ClassParams,
    merged: Option<&ClassParams>,
    changes: &mut Vec<PriorChange>,
) {
    let merged_values = merged.map(|params| {
        [
            params.prior_prob,
            params.cpu_beta.alpha,
            params.cpu_beta.beta,
            params.orphan_beta.alpha,
            params.orphan_beta.beta,
            params.tty_beta.alpha,
            params.tty_beta.beta,
            params.net_beta.alpha,
            params.net_beta.beta,
        ]
    });
    let fields: Vec<(&str, f64, f64)> = vec![
        ("prior_prob", local.prior_prob, incoming.prior_prob),
        (
            "cpu_beta.alpha",
            local.cpu_beta.alpha,
            incoming.cpu_beta.alpha,
        ),
        ("cpu_beta.beta", local.cpu_beta.beta, incoming.cpu_beta.beta),
        (
            "orphan_beta.alpha",
            local.orphan_beta.alpha,
            incoming.orphan_beta.alpha,
        ),
        (
            "orphan_beta.beta",
            local.orphan_beta.beta,
            incoming.orphan_beta.beta,
        ),
        (
            "tty_beta.alpha",
            local.tty_beta.alpha,
            incoming.tty_beta.alpha,
        ),
        ("tty_beta.beta", local.tty_beta.beta, incoming.tty_beta.beta),
        (
            "net_beta.alpha",
            local.net_beta.alpha,
            incoming.net_beta.alpha,
        ),
        ("net_beta.beta", local.net_beta.beta, incoming.net_beta.beta),
    ];
    for (index, (field, lv, iv)) in fields.into_iter().enumerate() {
        if (lv - iv).abs() > 1e-9 {
            changes.push(PriorChange {
                class: class.to_string(),
                field: field.to_string(),
                local_value: lv,
                incoming_value: iv,
                merged_value: merged_values.map(|values| values[index]),
            });
        }
    }
}

/// Resolve signature conflicts during import, returning summary of changes.
pub fn resolve_signature_conflicts(
    local: &PersistedSchema,
    incoming: &PersistedSchema,
    resolution: ConflictResolution,
) -> (PersistedSchema, Vec<ImportConflict>) {
    let mut result_patterns = local.patterns.clone();
    let mut conflicts = Vec::new();

    let local_names: HashMap<&str, usize> = local
        .patterns
        .iter()
        .enumerate()
        .map(|(i, p)| (p.signature.name.as_str(), i))
        .collect();

    for incoming_pattern in &incoming.patterns {
        let name = &incoming_pattern.signature.name;
        if let Some(&idx) = local_names.get(name.as_str()) {
            let existing = &local.patterns[idx];
            let existing_conf = existing.signature.confidence_weight;
            let imported_conf = incoming_pattern.signature.confidence_weight;

            let conflict = ImportConflict {
                name: name.clone(),
                resolution,
                existing_confidence: Some(existing_conf),
                imported_confidence: Some(imported_conf),
            };

            match resolution {
                ConflictResolution::KeepExisting => {}
                ConflictResolution::ReplaceWithImported => {
                    result_patterns[idx] = incoming_pattern.clone();
                }
                ConflictResolution::KeepHigherConfidence => {
                    if imported_conf > existing_conf {
                        result_patterns[idx] = incoming_pattern.clone();
                    }
                }
                ConflictResolution::Merge => {
                    if imported_conf > existing_conf {
                        result_patterns[idx] = incoming_pattern.clone();
                    }
                }
            }
            conflicts.push(conflict);
        } else {
            // New pattern, always add.
            result_patterns.push(incoming_pattern.clone());
        }
    }

    let schema = PersistedSchema {
        schema_version: local.schema_version,
        patterns: result_patterns,
        metadata: local.metadata.clone(),
    };

    (schema, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_priors() -> Priors {
        Priors::default()
    }

    fn minimal_baseline() -> BaselineStats {
        BaselineStats {
            total_processes_seen: 5000,
            observation_window_hours: 72.0,
            class_distribution: {
                let mut m = BTreeMap::new();
                m.insert("useful".to_string(), 0.7);
                m.insert("useful_bad".to_string(), 0.1);
                m.insert("abandoned".to_string(), 0.15);
                m.insert("zombie".to_string(), 0.05);
                m
            },
            mean_cpu_utilization: 45.0,
            host_type: Some("server".to_string()),
        }
    }

    #[test]
    fn export_bundle_roundtrip_json() {
        let priors = minimal_priors();
        let baseline = minimal_baseline();
        let bundle = export_bundle(
            Some(&priors),
            None,
            Some(&baseline),
            "host-abc",
            Some("server"),
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let reloaded: TransferBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.schema_version, TRANSFER_SCHEMA_VERSION);
        assert_eq!(reloaded.source_host_id, "host-abc");
        assert_eq!(reloaded.source_host_profile.as_deref(), Some("server"));
        assert!(reloaded.priors.is_some());
        assert!(reloaded.signatures.is_none());
        assert!(reloaded.baseline_stats.is_some());
        assert!(!reloaded.checksum.is_empty());
    }

    #[test]
    fn validate_bundle_ok() {
        let priors = minimal_priors();
        let bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        let warnings = validate_bundle(&bundle).unwrap();
        // No warnings for a clean bundle
        assert!(
            warnings
                .iter()
                .all(|w| w.code != "empty_bundle" || bundle.priors.is_some()),
            "unexpected warnings: {:?}",
            warnings,
        );
    }

    #[test]
    fn baseline_statistics_refuse_nonfinite_negative_and_inconsistent_values() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut baseline = minimal_baseline();
            baseline.observation_window_hours = invalid;
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
            baseline = minimal_baseline();
            baseline.mean_cpu_utilization = invalid;
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
            baseline = minimal_baseline();
            baseline
                .class_distribution
                .insert("useful".to_string(), invalid);
            assert!(matches!(
                export_bundle(None, None, Some(&baseline), "host-owned", None),
                Err(TransferError::InvalidConfiguration(_))
            ));
        }
        let mut baseline = minimal_baseline();
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 1.1)]);
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 0.5)]);
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution = BTreeMap::from([("useful".to_string(), 1.0)]);
        export_bundle(None, None, Some(&baseline), "host-owned", None).unwrap();
        baseline.total_processes_seen = 0;
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.class_distribution.clear();
        assert!(export_bundle(None, None, Some(&baseline), "host-owned", None).is_err());
        baseline.mean_cpu_utilization = 0.0;
        baseline.observation_window_hours = 0.0;
        export_bundle(None, None, Some(&baseline), "host-owned", None).unwrap();
    }

    #[test]
    fn validate_bundle_checksum_mismatch() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.checksum = "bad".to_string();
        let err = validate_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn validate_bundle_bad_schema_version() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.schema_version = "99.0.0".to_string();
        // Recompute checksum to avoid checksum error.
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        let err = validate_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("unsupported schema version"));
    }

    #[test]
    fn validate_bundle_prior_prob_sum_error() {
        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        bundle.priors.as_mut().unwrap().classes.useful.prior_prob = 0.9;
        // Deliberately build a checksummed but invalid incoming configuration.
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        assert!(matches!(
            validate_bundle(&bundle),
            Err(TransferError::PriorProbSum(_))
        ));
    }

    #[test]
    fn checksum_survives_independent_matcher_map_order_and_rejects_tampering() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;

        let mut signature = SupervisorSignature::new("transfer-owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["^transfer-owned$"]);
        let entries = [
            ("MODE", "^test$"),
            ("RUNNER", "^owned$"),
            ("WORKSPACE", "^fixture$"),
        ];
        signature.patterns.environment_vars = entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        let schema = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(signature, PatternSource::Custom)],
            metadata: None,
        };
        let bundle = export_bundle(None, Some(&schema), None, "host-owned", None).unwrap();
        let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
        for _ in 0..4 {
            let mut independent: TransferBundle = serde_json::from_slice(&bytes).unwrap();
            validate_bundle(&independent).expect("unchanged incoming checksum must validate");
            assert_eq!(independent.checksum, bundle.checksum);
            let matcher = &mut independent.signatures.as_mut().unwrap().patterns[0]
                .signature
                .patterns
                .environment_vars;
            *matcher = entries
                .iter()
                .rev()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            assert_eq!(
                compute_bundle_checksum(&independent).unwrap(),
                bundle.checksum
            );
            validate_bundle(&independent).unwrap();
            independent.signatures.as_mut().unwrap().patterns[0]
                .signature
                .patterns
                .environment_vars
                .insert("MODE".to_string(), "^changed$".to_string());
            assert!(matches!(
                validate_bundle(&independent),
                Err(TransferError::ChecksumMismatch { .. })
            ));
        }
    }

    #[test]
    fn checksummed_invalid_priors_and_inactive_redacted_matchers_are_refused() {
        use crate::supervision::pattern_persistence::{
            PatternLifecycle, PatternSource, PersistedPattern,
        };
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;

        let priors = minimal_priors();
        let mut bundle = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        bundle
            .priors
            .as_mut()
            .unwrap()
            .classes
            .useful
            .cpu_beta
            .alpha = -1.0;
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        assert!(matches!(
            validate_bundle(&bundle),
            Err(TransferError::InvalidConfiguration(_))
        ));

        let signature = SupervisorSignature::new("redacted-owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["[HASH:k1:abcd]"]);
        let mut pattern = PersistedPattern::new(signature, PatternSource::Custom);
        pattern.lifecycle = PatternLifecycle::Removed;
        bundle.priors = None;
        bundle.signatures = Some(PersistedSchema {
            schema_version: 2,
            patterns: vec![pattern],
            metadata: None,
        });
        bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
        let error = validate_bundle(&bundle).unwrap_err();
        assert!(matches!(error, TransferError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("redacted matcher"));
    }

    #[test]
    fn intact_transfer_refuses_detected_credentials_in_values_and_keys() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::SupervisorSignature;
        use crate::supervision::SupervisorCategory;
        let canary = "AKIAIOSFODNN7EXAMPLE";
        let mut priors = minimal_priors();
        let clean = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        for field in ["schema_version", "checksum"] {
            let mut poisoned = clean.clone();
            if field == "schema_version" {
                poisoned.schema_version = canary.to_string();
            } else {
                poisoned.checksum = canary.to_string();
            }
            let error = validate_bundle(&poisoned).unwrap_err();
            assert!(matches!(error, TransferError::SensitiveContent));
            assert!(!error.to_string().contains(canary));
        }
        priors.classes.useful.cpu_beta.comment = Some(canary.to_string());
        let error = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap_err();
        assert!(matches!(error, TransferError::SensitiveContent));
        assert!(!error.to_string().contains(canary));
        let mut signature = SupervisorSignature::new("owned", SupervisorCategory::Other)
            .with_process_patterns(vec!["^owned$"]);
        signature
            .patterns
            .environment_vars
            .insert(canary.to_string(), ".*".to_string());
        let schema = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(signature, PatternSource::Custom)],
            metadata: None,
        };
        let error = export_bundle(None, Some(&schema), None, "host-owned", None).unwrap_err();
        assert!(matches!(error, TransferError::SensitiveContent));
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn intact_transfer_preserves_shipped_prose_but_refuses_embedded_secret_tokens() {
        let mut priors: Priors = serde_json::from_str(include_str!(
            "../../../pt-config/src/schemas/priors.default.json"
        ))
        .unwrap();
        let comment = priors.command_categories.as_ref().unwrap().comment.clone();
        let bundle = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap();
        assert_eq!(
            bundle.priors.unwrap().command_categories.unwrap().comment,
            comment
        );
        for text in [
            "ordinary note AKIAIOSFODNN7EXAMPLE more text",
            "ordinary note aB3$cD4@eF5#gH6!iJ7%kL8 more text",
            "ordinary note --password short-value more text",
        ] {
            priors.classes.useful.cpu_beta.comment = Some(text.to_string());
            let error = export_bundle(Some(&priors), None, None, "host-owned", None).unwrap_err();
            assert!(matches!(error, TransferError::SensitiveContent));
            assert!(!error.to_string().contains(text));
        }
    }

    #[test]
    fn merge_beta_equal_weights() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let m = merge_beta_params(&a, &b, 0.5, 0.5).unwrap();
        assert!((m.alpha - 5.0).abs() < 1e-9);
        assert!((m.beta - 5.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_zero_local_weight() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(10.0, 10.0);
        let m = merge_beta_params(&a, &b, 0.0, 1.0).unwrap();
        assert!((m.alpha - 10.0).abs() < 1e-9);
        assert!((m.beta - 10.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_zero_incoming_weight() {
        let a = BetaParams::new(3.0, 7.0);
        let b = BetaParams::new(10.0, 10.0);
        let m = merge_beta_params(&a, &b, 1.0, 0.0).unwrap();
        assert!((m.alpha - 3.0).abs() < 1e-9);
        assert!((m.beta - 7.0).abs() < 1e-9);
    }

    #[test]
    fn merge_beta_both_zero_weight_errors() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let err = merge_beta_params(&a, &b, 0.0, 0.0).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn merge_beta_negative_weight_errors() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(8.0, 2.0);
        let err = merge_beta_params(&a, &b, -1.0, 1.0).unwrap_err();
        assert!(err.to_string().contains("non-negative"));
    }

    #[test]
    fn merge_beta_asymmetric_weights() {
        let a = BetaParams::new(2.0, 8.0);
        let b = BetaParams::new(10.0, 2.0);
        // w_l=0.75, w_i=0.25 (after normalization)
        let m = merge_beta_params(&a, &b, 3.0, 1.0).unwrap();
        let expected_alpha = 0.75 * 2.0 + 0.25 * 10.0; // 4.0
        let expected_beta = 0.75 * 8.0 + 0.25 * 2.0; // 6.5
        assert!((m.alpha - expected_alpha).abs() < 1e-9);
        assert!((m.beta - expected_beta).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_replace() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let result = merge_priors(&local, &incoming, MergeStrategy::Replace).unwrap();
        assert!((result.classes.useful.prior_prob - 0.99).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_keep_local() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let result = merge_priors(&local, &incoming, MergeStrategy::KeepLocal).unwrap();
        assert!((result.classes.useful.prior_prob - local.classes.useful.prior_prob).abs() < 1e-9);
    }

    #[test]
    fn merge_priors_weighted_sums_to_one() {
        let local = minimal_priors();
        let incoming = minimal_priors();
        let result = merge_priors(&local, &incoming, MergeStrategy::Weighted).unwrap();
        let sum = result.classes.useful.prior_prob
            + result.classes.useful_bad.prior_prob
            + result.classes.abandoned.prior_prob
            + result.classes.zombie.prior_prob;
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn normalize_baseline_scales_beta_params() {
        let mut priors = minimal_priors();
        let original_alpha = priors.classes.useful.cpu_beta.alpha;

        let source = BaselineStats {
            total_processes_seen: 1000,
            observation_window_hours: 24.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 80.0,
            host_type: Some("server".to_string()),
        };
        let target = BaselineStats {
            total_processes_seen: 2000,
            observation_window_hours: 24.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 30.0,
            host_type: Some("workstation".to_string()),
        };

        normalize_baseline(&mut priors, &source, &target);
        // Scale = 2000/1000 = 2.0, so alpha should double.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original_alpha * 2.0).abs() < 1e-9,
            "expected alpha={}, got alpha={}",
            original_alpha * 2.0,
            priors.classes.useful.cpu_beta.alpha,
        );
    }

    #[test]
    fn normalize_baseline_identity_transform() {
        let original = minimal_priors();
        let mut priors = original.clone();
        let stats = minimal_baseline();
        normalize_baseline(&mut priors, &stats, &stats);
        // Same source and target: scale = 1.0, no change.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
                < 1e-9
        );
    }

    #[test]
    fn normalize_baseline_zero_source_noop() {
        let original = minimal_priors();
        let mut priors = original.clone();
        let source = BaselineStats {
            total_processes_seen: 0,
            observation_window_hours: 0.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 0.0,
            host_type: None,
        };
        let target = minimal_baseline();
        normalize_baseline(&mut priors, &source, &target);
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
                < 1e-9
        );
    }

    #[test]
    fn normalize_baseline_clamps_extreme_ratio() {
        let mut priors = minimal_priors();
        let source = BaselineStats {
            total_processes_seen: 1,
            observation_window_hours: 1.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 1.0,
            host_type: None,
        };
        let target = BaselineStats {
            total_processes_seen: 1_000_000,
            observation_window_hours: 1000.0,
            class_distribution: BTreeMap::new(),
            mean_cpu_utilization: 90.0,
            host_type: None,
        };
        let original_alpha = priors.classes.useful.cpu_beta.alpha;
        normalize_baseline(&mut priors, &source, &target);
        // Clamped to 10.0x.
        assert!(
            (priors.classes.useful.cpu_beta.alpha - original_alpha * 10.0).abs() < 1e-9,
            "expected alpha={}, got alpha={}",
            original_alpha * 10.0,
            priors.classes.useful.cpu_beta.alpha,
        );
    }

    #[test]
    fn compute_diff_no_changes() {
        let priors = minimal_priors();
        let bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
        let diff = compute_diff(Some(&priors), None, &bundle, None);
        assert!(diff.priors_changes.is_empty());
    }

    #[test]
    fn compute_diff_detects_prior_change() {
        let local = minimal_priors();
        let mut incoming = minimal_priors();
        incoming.classes.useful.prior_prob = 0.99;
        incoming.classes.useful_bad.prior_prob = 0.005;
        incoming.classes.abandoned.prior_prob = 0.004;
        incoming.classes.zombie.prior_prob = 0.001;
        let bundle = export_bundle(Some(&incoming), None, None, "h2", None).unwrap();
        let diff = compute_diff(Some(&local), None, &bundle, None);
        assert!(
            !diff.priors_changes.is_empty(),
            "expected prior changes, got none"
        );
        let useful_change = diff
            .priors_changes
            .iter()
            .find(|c| c.class == "useful" && c.field == "prior_prob");
        assert!(useful_change.is_some());
    }

    #[test]
    fn compute_diff_reports_raw_and_actual_merged_values_for_each_strategy() {
        let mut local = minimal_priors();
        local.classes.useful.cpu_beta.alpha = 2.0;
        let mut incoming = minimal_priors();
        incoming.classes.useful.cpu_beta.alpha = 6.0;
        let bundle = export_bundle(Some(&incoming), None, None, "host-owned", None).unwrap();
        for (strategy, expected) in [
            (MergeStrategy::Weighted, 4.0),
            (MergeStrategy::Replace, 6.0),
            (MergeStrategy::KeepLocal, 2.0),
        ] {
            let merged = merge_priors(&local, &incoming, strategy).unwrap();
            let diff = compute_diff(Some(&local), None, &bundle, Some(&merged));
            let change = diff
                .priors_changes
                .iter()
                .find(|change| change.class == "useful" && change.field == "cpu_beta.alpha")
                .expect("actual changed field reported");
            assert_eq!(change.local_value, 2.0);
            assert_eq!(change.incoming_value, 6.0);
            assert_eq!(change.merged_value, Some(expected));
        }
        let comparison = compute_diff(Some(&local), None, &bundle, None);
        assert!(comparison
            .priors_changes
            .iter()
            .all(|change| change.merged_value.is_none()));
    }

    #[test]
    fn compute_diff_detects_signature_added() {
        use crate::supervision::pattern_persistence::{PatternSource, PersistedPattern};
        use crate::supervision::signature::{SignaturePatterns, SupervisorSignature};
        use crate::supervision::SupervisorCategory;

        let sig = SupervisorSignature {
            name: "new_sig".to_string(),
            category: SupervisorCategory::Other,
            patterns: SignaturePatterns {
                process_names: vec!["^test$".to_string()],
                ..Default::default()
            },
            confidence_weight: 0.8,
            notes: None,
            builtin: false,
            priors: Default::default(),
            expectations: Default::default(),
            priority: 100,
        };
        let incoming_sigs = PersistedSchema {
            schema_version: 2,
            patterns: vec![PersistedPattern::new(sig, PatternSource::Custom)],
            metadata: None,
        };
        let bundle = export_bundle(None, Some(&incoming_sigs), None, "h3", None).unwrap();
        let local_sigs = PersistedSchema::new();
        let diff = compute_diff(None, Some(&local_sigs), &bundle, None);
        assert_eq!(diff.signature_changes.len(), 1);
        assert!(matches!(
            diff.signature_changes[0].change_type,
            SignatureChangeType::Added
        ));
    }

    #[test]
    fn merge_strategy_from_str() {
        assert_eq!(
            "weighted".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Weighted
        );
        assert_eq!(
            "replace".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Replace
        );
        assert_eq!(
            "keep-local".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::KeepLocal
        );
        assert!("invalid".parse::<MergeStrategy>().is_err());
    }

    #[test]
    fn deterministic_checksum() {
        // Same input should produce same checksum every time.
        // We need stable exported_at to test this, so construct directly.
        let priors = minimal_priors();
        let mut b1 = TransferBundle {
            schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            source_host_id: "host1".to_string(),
            source_host_profile: None,
            priors: Some(priors.clone()),
            signatures: None,
            baseline_stats: None,
            checksum: String::new(),
        };
        b1.checksum = compute_bundle_checksum(&b1).unwrap();

        let mut b2 = TransferBundle {
            schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            source_host_id: "host1".to_string(),
            source_host_profile: None,
            priors: Some(priors),
            signatures: None,
            baseline_stats: None,
            checksum: String::new(),
        };
        b2.checksum = compute_bundle_checksum(&b2).unwrap();

        assert_eq!(b1.checksum, b2.checksum);
    }

    #[test]
    fn empty_bundle_warning() {
        let bundle = export_bundle(None, None, None, "h1", None).unwrap();
        let warnings = validate_bundle(&bundle).unwrap();
        assert!(warnings.iter().any(|w| w.code == "empty_bundle"));
    }

    #[test]
    fn baseline_stats_serde_roundtrip() {
        let stats = minimal_baseline();
        let json = serde_json::to_string(&stats).unwrap();
        let back: BaselineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_processes_seen, 5000);
        assert_eq!(back.host_type.as_deref(), Some("server"));
    }

    #[test]
    fn transfer_diff_empty_when_no_data() {
        let bundle = export_bundle(None, None, None, "h1", None).unwrap();
        let diff = compute_diff(None, None, &bundle, None);
        assert!(diff.priors_changes.is_empty());
        assert!(diff.signature_changes.is_empty());
        assert!(diff.baseline_adjustments.is_empty());
    }
}
