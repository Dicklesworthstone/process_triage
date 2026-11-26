//! Private, independently loadable model versions from an offline prior refit.

use super::evaluation::{configuration_fingerprint, PriorRefitReport, ReplayEvaluationError};
use crate::config::{load_config, ConfigOptions, Policy};
use crate::scoring::Scorer;
use crate::supervision::pattern_persistence::{DisabledPatterns, PersistedSchema};
use crate::supervision::signature::{SignatureDatabase, SignatureSchema};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Paths are returned only after both configurations reload with the evaluated
/// fingerprints and the completion report has been durably written.
#[derive(Debug, Clone, Serialize)]
pub struct PriorRefitArtifact {
    pub directory: PathBuf,
    pub candidate_config: PathBuf,
    pub incumbent_config: PathBuf,
    pub report: PathBuf,
}

fn private_directory(path: &Path) -> Result<(), ReplayEvaluationError> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), ReplayEvaluationError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ReplayEvaluationError> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn verify_saved_configuration(path: &Path, expected: &str) -> Result<(), ReplayEvaluationError> {
    let config = load_config(&ConfigOptions {
        config_dir: Some(path.to_path_buf()),
        ..Default::default()
    })
    .map_err(|error| {
        ReplayEvaluationError::InvalidEvaluation(format!(
            "saved refit configuration {} could not be loaded: {error}",
            path.display()
        ))
    })?;
    let scorer =
        Scorer::try_from_config(&config).map_err(ReplayEvaluationError::InvalidEvaluation)?;
    if configuration_fingerprint(&scorer, &config.policy)? != expected {
        return Err(ReplayEvaluationError::InvalidEvaluation(format!(
            "saved refit configuration {} differs from the evaluated model; no completion report was published",
            path.display()
        )));
    }
    Ok(())
}

/// Save a new version, never overwrite or activate a configuration. All model
/// bytes come from the evaluated in-memory inputs, not a second read of mutable
/// source files. Rejected and unchanged candidates remain inspectable.
///
/// report.json is written last, after both saved models have been verified.
/// An interrupted save retains its private partial directory for inspection;
/// callers must not treat a missing or incomplete report as a completed version.
/// Loading the version with another engine version can change bundled models;
/// the report records the engine and exact evaluated model fingerprints.
pub fn save_prior_refit_artifact(
    directory: impl AsRef<Path>,
    report: &PriorRefitReport,
    incumbent: &Scorer,
    policy: &Policy,
) -> Result<PriorRefitArtifact, ReplayEvaluationError> {
    let directory = directory.as_ref();
    if configuration_fingerprint(incumbent, policy)? != report.incumbent_configuration_sha256 {
        return Err(ReplayEvaluationError::InvalidEvaluation(
            "refit artifact inputs differ from the evaluated incumbent".to_string(),
        ));
    }
    let mut candidate = incumbent.clone();
    candidate.priors = report.candidate_priors.clone();
    if configuration_fingerprint(&candidate, policy)? != report.candidate_configuration_sha256 {
        return Err(ReplayEvaluationError::InvalidEvaluation(
            "refit artifact inputs differ from the evaluated candidate".to_string(),
        ));
    }

    // Disk overlays deliberately cannot acquire bundled-only supervision
    // semantics. Keep active bundled signatures bundled, export custom winners,
    // and explicitly suppress every bundled name absent from the frozen model.
    let bundled = SignatureDatabase::with_defaults();
    let active_names: HashSet<&str> = incumbent
        .signatures
        .signatures()
        .iter()
        .map(|signature| signature.name.as_str())
        .collect();
    let mut signatures = SignatureSchema::new();
    for signature in incumbent.signatures.signatures() {
        if signature.builtin {
            if !bundled
                .signatures()
                .iter()
                .any(|built_in| built_in == signature)
            {
                return Err(ReplayEvaluationError::InvalidEvaluation(format!(
                    "cannot persist changed bundled signature '{}' as a user override",
                    signature.name
                )));
            }
        } else {
            signatures.add(signature.clone());
        }
    }
    let mut disabled = DisabledPatterns::default();
    for signature in bundled.signatures() {
        if !active_names.contains(signature.name.as_str()) {
            disabled.disabled.insert(signature.name.clone());
        }
    }
    let mut bundled_snapshot = SignatureSchema::new();
    bundled_snapshot.signatures = incumbent
        .signatures
        .signatures()
        .iter()
        .filter(|signature| signature.builtin)
        .cloned()
        .collect();

    // Serialize and validate all inputs before creating the new version. Explicit
    // empty pattern layers also prevent legacy fallback from adding other inputs.
    let common_files = [
        ("policy.json", serde_json::to_vec_pretty(policy)?),
        ("signatures.json", serde_json::to_vec_pretty(&signatures)?),
        (
            "decisions.json",
            serde_json::to_vec_pretty(&incumbent.decisions.evaluation_snapshot()?)?,
        ),
        (
            "patterns/disabled.json",
            serde_json::to_vec_pretty(&disabled)?,
        ),
        (
            "patterns/learned.json",
            serde_json::to_vec_pretty(&PersistedSchema::new())?,
        ),
        (
            "patterns/custom.json",
            serde_json::to_vec_pretty(&PersistedSchema::new())?,
        ),
    ];
    let incumbent_priors = serde_json::to_vec_pretty(&incumbent.priors)?;
    let candidate_priors = serde_json::to_vec_pretty(&candidate.priors)?;
    let bundled_bytes = serde_json::to_vec_pretty(&bundled_snapshot)?;
    let report_bytes = serde_json::to_vec_pretty(report)?;
    let artifact = PriorRefitArtifact {
        directory: directory.to_path_buf(),
        candidate_config: directory.join("candidate"),
        incumbent_config: directory.join("incumbent"),
        report: directory.join("report.json"),
    };

    // Exclusive creation refuses existing directories and symlinks. A new
    // version name is required for every fit, including a repeated rejected fit.
    private_directory(directory)?;
    for (path, priors) in [
        (&artifact.incumbent_config, &incumbent_priors),
        (&artifact.candidate_config, &candidate_priors),
    ] {
        private_directory(path)?;
        private_directory(&path.join("patterns"))?;
        for (name, bytes) in &common_files {
            write_new_private(&path.join(name), bytes)?;
        }
        write_new_private(&path.join("priors.json"), priors)?;
        sync_directory(&path.join("patterns"))?;
        sync_directory(path)?;
    }
    write_new_private(&directory.join("bundled-signatures.json"), &bundled_bytes)?;
    verify_saved_configuration(
        &artifact.incumbent_config,
        &report.incumbent_configuration_sha256,
    )?;
    verify_saved_configuration(
        &artifact.candidate_config,
        &report.candidate_configuration_sha256,
    )?;
    write_new_private(&artifact.report, &report_bytes)?;
    sync_directory(directory)?;
    let parent = directory
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_directory(parent)?;
    Ok(artifact)
}
