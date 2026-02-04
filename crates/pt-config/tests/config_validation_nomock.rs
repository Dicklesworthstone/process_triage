//! No-mock configuration validation + resolution tests.
//!
//! Covers:
//! - Priors and policy validation against real JSON fixtures
//! - Resolution order (CLI > env > config dir > XDG)
//! - Preset determinism
//!
//! See: bd-m3zh

use pt_config::preset::{get_preset, list_presets, PresetName};
use pt_config::resolve::{resolve_config, ConfigSource};
use pt_config::validate::{validate_policy, validate_priors, ValidationError};
use pt_config::{Policy, Priors};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_priors_fixture(name: &str) -> Priors {
    let path = fixtures_dir().join(name);
    Priors::from_file(&path).expect("read priors fixture")
}

fn load_policy_fixture(name: &str) -> Policy {
    let path = fixtures_dir().join(name);
    Policy::from_file(&path).expect("read policy fixture")
}

struct EnvGuard {
    keys: Vec<String>,
    saved: Vec<Option<String>>,
}

impl EnvGuard {
    fn new(keys: &[&str]) -> Self {
        let mut saved = Vec::with_capacity(keys.len());
        for key in keys {
            saved.push(env::var(key).ok());
        }
        Self {
            keys: keys.iter().map(|k| k.to_string()).collect(),
            saved,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (idx, key) in self.keys.iter().enumerate() {
            match self.saved.get(idx).and_then(|v| v.as_ref()) {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }
    }
}

fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned");
    f()
}

fn write_fixture(src_name: &str, dest: &Path) {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).expect("create fixture parent");
    }
    fs::copy(fixtures_dir().join(src_name), dest).expect("copy fixture");
}

fn write_config_dir(dir: &Path) {
    fs::create_dir_all(dir).expect("create config dir");
    write_fixture("valid_priors.json", &dir.join("priors.json"));
    write_fixture("valid_policy.json", &dir.join("policy.json"));
}

#[test]
fn test_validate_priors_fixture_ok() {
    let priors = load_priors_fixture("valid_priors.json");
    validate_priors(&priors).expect("valid priors should pass validation");
    assert!(priors.priors_sum_to_one(0.01));
}

#[test]
fn test_validate_priors_rejects_bad_sum() {
    let priors = load_priors_fixture("invalid_priors_bad_sum.json");
    let err = validate_priors(&priors).expect_err("bad sum should fail validation");
    assert!(matches!(err, ValidationError::SemanticError(_)));
}

#[test]
fn test_validate_priors_rejects_bad_beta() {
    let priors = load_priors_fixture("invalid_priors_bad_beta.json");
    let err = validate_priors(&priors).expect_err("bad beta should fail validation");
    assert!(matches!(err, ValidationError::InvalidValue { .. }));
}

#[test]
fn test_validate_policy_fixture_ok() {
    let policy = load_policy_fixture("valid_policy.json");
    validate_policy(&policy).expect("valid policy should pass validation");
}

#[test]
fn test_validate_policy_rejects_missing_pid1() {
    let policy = load_policy_fixture("invalid_policy_missing_pid1.json");
    let err = validate_policy(&policy).expect_err("missing PID 1 should fail validation");
    assert!(matches!(err, ValidationError::SemanticError(_)));
}

#[test]
fn test_validate_policy_rejects_bad_alpha() {
    let policy = load_policy_fixture("invalid_policy_bad_alpha.json");
    let err = validate_policy(&policy).expect_err("bad alpha should fail validation");
    assert!(matches!(err, ValidationError::InvalidValue { .. }));
}

#[test]
fn test_resolve_config_cli_over_env() {
    with_env_lock(|| {
        let _guard = EnvGuard::new(&[
            "PROCESS_TRIAGE_PRIORS",
            "PROCESS_TRIAGE_POLICY",
            "PROCESS_TRIAGE_CONFIG_DIR",
            "XDG_CONFIG_HOME",
        ]);

        let temp = TempDir::new().expect("temp dir");
        let cli_dir = temp.path().join("cli");
        let env_dir = temp.path().join("env");
        write_config_dir(&cli_dir);
        write_config_dir(&env_dir);

        env::set_var(
            "PROCESS_TRIAGE_PRIORS",
            env_dir.join("priors.json").display().to_string(),
        );
        env::set_var(
            "PROCESS_TRIAGE_POLICY",
            env_dir.join("policy.json").display().to_string(),
        );
        env::set_var(
            "PROCESS_TRIAGE_CONFIG_DIR",
            env_dir.display().to_string(),
        );

        let cli_priors = cli_dir.join("priors.json");
        let cli_policy = cli_dir.join("policy.json");
        let paths = resolve_config(Some(&cli_priors), Some(&cli_policy));

        assert_eq!(paths.priors_source, ConfigSource::CliArgument);
        assert_eq!(paths.policy_source, ConfigSource::CliArgument);
        assert_eq!(paths.priors.unwrap(), cli_priors);
        assert_eq!(paths.policy.unwrap(), cli_policy);
    });
}

#[test]
fn test_resolve_config_env_over_config_dir() {
    with_env_lock(|| {
        let _guard = EnvGuard::new(&[
            "PROCESS_TRIAGE_PRIORS",
            "PROCESS_TRIAGE_POLICY",
            "PROCESS_TRIAGE_CONFIG_DIR",
            "XDG_CONFIG_HOME",
        ]);

        let temp = TempDir::new().expect("temp dir");
        let env_dir = temp.path().join("env");
        let config_dir = temp.path().join("config_dir");
        write_config_dir(&env_dir);
        write_config_dir(&config_dir);

        env::set_var(
            "PROCESS_TRIAGE_PRIORS",
            env_dir.join("priors.json").display().to_string(),
        );
        env::set_var(
            "PROCESS_TRIAGE_POLICY",
            env_dir.join("policy.json").display().to_string(),
        );
        env::set_var(
            "PROCESS_TRIAGE_CONFIG_DIR",
            config_dir.display().to_string(),
        );

        let paths = resolve_config(None, None);
        assert_eq!(paths.priors_source, ConfigSource::Environment);
        assert_eq!(paths.policy_source, ConfigSource::Environment);
        assert_eq!(paths.priors.unwrap(), env_dir.join("priors.json"));
        assert_eq!(paths.policy.unwrap(), env_dir.join("policy.json"));
    });
}

#[test]
fn test_resolve_config_xdg_fallback() {
    with_env_lock(|| {
        let _guard = EnvGuard::new(&[
            "PROCESS_TRIAGE_PRIORS",
            "PROCESS_TRIAGE_POLICY",
            "PROCESS_TRIAGE_CONFIG_DIR",
            "XDG_CONFIG_HOME",
        ]);

        let temp = TempDir::new().expect("temp dir");
        let xdg_dir = temp.path().join("xdg");
        let app_dir = xdg_dir.join("process-triage");
        write_config_dir(&app_dir);

        env::set_var("XDG_CONFIG_HOME", xdg_dir.display().to_string());

        let paths = resolve_config(None, None);
        assert_eq!(paths.priors_source, ConfigSource::XdgConfig);
        assert_eq!(paths.policy_source, ConfigSource::XdgConfig);
        assert_eq!(paths.priors.unwrap(), app_dir.join("priors.json"));
        assert_eq!(paths.policy.unwrap(), app_dir.join("policy.json"));
    });
}

#[test]
fn test_presets_are_deterministic() {
    let first = get_preset(PresetName::Ci);
    let second = get_preset(PresetName::Ci);
    let first_json = serde_json::to_string(&first).expect("serialize preset");
    let second_json = serde_json::to_string(&second).expect("serialize preset");
    assert_eq!(first_json, second_json);

    let presets = list_presets();
    assert!(presets
        .iter()
        .any(|p| p.name == PresetName::Ci.as_str()));
}
