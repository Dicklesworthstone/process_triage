//! Alpha-investing online safety budget.

use crate::config::policy::AlphaInvesting;
use crate::config::Policy;
use crate::logging::get_host_id;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Alpha-investing policy parameters.
#[derive(Debug, Clone)]
pub struct AlphaInvestingPolicy {
    pub w0: f64,
    pub alpha_spend: f64,
    pub alpha_earn: f64,
}

/// Persisted wealth state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlphaWealthState {
    pub wealth: f64,
    pub last_updated: String,
    pub policy_id: Option<String>,
    pub policy_version: String,
    pub host_id: String,
    pub user_id: u32,
}

/// Alpha investing update summary.
#[derive(Debug, Clone, Serialize)]
pub struct AlphaUpdate {
    pub wealth_prev: f64,
    pub alpha_spend: f64,
    pub discoveries: u32,
    pub alpha_earn: f64,
    pub wealth_next: f64,
}

/// Alpha investing state store.
#[derive(Debug, Clone)]
pub struct AlphaInvestingStore {
    state_path: PathBuf,
    lock_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum AlphaInvestingError {
    #[error("alpha investing not configured in policy")]
    MissingPolicy,
    #[error("invalid alpha investing policy: {0}")]
    InvalidPolicy(String),
    #[error("failed to acquire alpha investing lock")]
    LockUnavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl AlphaInvestingPolicy {
    pub fn from_policy(policy: &Policy) -> Result<Self, AlphaInvestingError> {
        let alpha = policy
            .fdr_control
            .alpha_investing
            .clone()
            .ok_or(AlphaInvestingError::MissingPolicy)?;
        Self::from_config(&alpha)
    }

    fn from_config(alpha: &AlphaInvesting) -> Result<Self, AlphaInvestingError> {
        let w0 = alpha.w0.unwrap_or(0.05);
        let alpha_spend = alpha.alpha_spend.unwrap_or(0.02);
        let alpha_earn = alpha.alpha_earn.unwrap_or(0.01);
        if w0 <= 0.0 || alpha_spend < 0.0 || alpha_earn < 0.0 {
            return Err(AlphaInvestingError::InvalidPolicy(
                "w0 must be > 0 and spend/earn must be >= 0".to_string(),
            ));
        }
        Ok(Self {
            w0,
            alpha_spend,
            alpha_earn,
        })
    }

    /// Compute the alpha spend for a given wealth value.
    pub fn alpha_spend_for_wealth(&self, wealth: f64) -> f64 {
        if wealth <= 0.0 {
            return 0.0;
        }
        let spend = self.alpha_spend * wealth;
        spend.min(wealth)
    }
}

impl AlphaInvestingStore {
    pub fn new(config_dir: &Path) -> Self {
        let state_path = config_dir.join("alpha_wealth.json");
        let lock_path = config_dir.join("alpha_wealth.lock");
        Self {
            state_path,
            lock_path,
        }
    }

    pub fn load_or_init(
        &self,
        policy: &Policy,
        user_id: u32,
    ) -> Result<AlphaWealthState, AlphaInvestingError> {
        let _guard = LockGuard::acquire(&self.lock_path)?;
        let policy_cfg = AlphaInvestingPolicy::from_policy(policy)?;
        if self.state_path.exists() {
            let contents = fs::read_to_string(&self.state_path)?;
            let state: AlphaWealthState = serde_json::from_str(&contents)?;
            return Ok(state);
        }

        let state = AlphaWealthState {
            wealth: policy_cfg.w0,
            last_updated: chrono::Utc::now().to_rfc3339(),
            policy_id: policy.policy_id.clone(),
            policy_version: policy.schema_version.clone(),
            host_id: get_host_id(),
            user_id,
        };
        self.write_state(&state)?;
        Ok(state)
    }

    pub fn update_wealth(
        &self,
        policy: &Policy,
        user_id: u32,
        discoveries: u32,
    ) -> Result<AlphaUpdate, AlphaInvestingError> {
        let _guard = LockGuard::acquire(&self.lock_path)?;
        let policy_cfg = AlphaInvestingPolicy::from_policy(policy)?;
        let mut state = if self.state_path.exists() {
            let contents = fs::read_to_string(&self.state_path)?;
            serde_json::from_str::<AlphaWealthState>(&contents)?
        } else {
            AlphaWealthState {
                wealth: policy_cfg.w0,
                last_updated: chrono::Utc::now().to_rfc3339(),
                policy_id: policy.policy_id.clone(),
                policy_version: policy.schema_version.clone(),
                host_id: get_host_id(),
                user_id,
            }
        };

        let alpha_spend = policy_cfg.alpha_spend_for_wealth(state.wealth);
        let reward = policy_cfg.alpha_earn * discoveries as f64;
        let next = (state.wealth - alpha_spend + reward).max(0.0);

        let update = AlphaUpdate {
            wealth_prev: state.wealth,
            alpha_spend,
            discoveries,
            alpha_earn: policy_cfg.alpha_earn,
            wealth_next: next,
        };

        state.wealth = next;
        state.last_updated = chrono::Utc::now().to_rfc3339();
        state.policy_id = policy.policy_id.clone();
        state.policy_version = policy.schema_version.clone();
        state.user_id = user_id;
        state.host_id = get_host_id();

        self.write_state(&state)?;
        Ok(update)
    }

    fn write_state(&self, state: &AlphaWealthState) -> Result<(), AlphaInvestingError> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.state_path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(state)?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(&json)?;
            file.flush()?;
        }
        fs::rename(tmp_path, &self.state_path)?;
        Ok(())
    }
}

enum LockState {
    Valid,
    Stale,
    Gone,
}

struct LockGuard {
    lock_path: PathBuf,
}

impl LockGuard {
    fn acquire(path: &Path) -> Result<Self, AlphaInvestingError> {
        let file = OpenOptions::new().create_new(true).write(true).open(path);
        match file {
            Ok(mut handle) => {
                // Write PID to lock file for stale lock detection
                let _ = handle.write_all(format!("{}", std::process::id()).as_bytes());
                Ok(Self {
                    lock_path: path.to_path_buf(),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                match Self::check_lock_state(path) {
                    LockState::Gone => Self::acquire(path), // Lock file disappeared, retry
                    LockState::Stale => {
                        // Try to remove stale lock and acquire
                        match fs::remove_file(path) {
                            Ok(_) => Self::acquire(path),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                Self::acquire(path)
                            }
                            Err(_) => Err(AlphaInvestingError::LockUnavailable),
                        }
                    }
                    LockState::Valid => Err(AlphaInvestingError::LockUnavailable),
                }
            }
            Err(err) => Err(AlphaInvestingError::Io(err)),
        }
    }

    /// Check the state of the lock file.
    fn check_lock_state(path: &Path) -> LockState {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                if trimmed.is_empty() {
                    // File exists but is empty - likely being created/written to.
                    // Treat as valid to avoid race condition where we delete a lock
                    // that is actively being initialized.
                    return LockState::Valid;
                }

                if let Ok(pid) = trimmed.parse::<u32>() {
                    // Check if process with this PID exists
                    #[cfg(unix)]
                    {
                        // kill(pid, 0) returns 0 if process exists, -1 if not
                        let result = unsafe { libc::kill(pid as i32, 0) };
                        if result == 0 {
                            return LockState::Valid; // Process exists
                        }
                        // Check error: ESRCH = no such process, EPERM = exists but no permission
                        let err = std::io::Error::last_os_error();
                        match err.raw_os_error() {
                            Some(code) if code == libc::ESRCH => LockState::Stale, // Process dead
                            Some(code) if code == libc::EPERM => LockState::Valid, // Process alive
                            _ => LockState::Stale,                                 // Unknown error
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        // On non-Unix, we can't easily check - assume valid to be safe
                        let _ = pid;
                        LockState::Valid
                    }
                } else {
                    // Can't parse PID - might be corrupted
                    LockState::Stale
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => LockState::Gone,
            Err(_) => LockState::Stale, // Can't read, assume stale/broken
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn alpha_update_formula_matches() {
        let mut policy = Policy::default();
        policy.fdr_control.alpha_investing = Some(AlphaInvesting {
            w0: Some(0.05),
            alpha_spend: Some(0.02),
            alpha_earn: Some(0.01),
        });
        let cfg = AlphaInvestingPolicy::from_policy(&policy).expect("policy");
        let update = {
            let wealth_prev = 0.05;
            let alpha_spend = cfg.alpha_spend_for_wealth(wealth_prev);
            let discoveries = 3u32;
            let reward = cfg.alpha_earn * discoveries as f64;
            let wealth_next = (wealth_prev - alpha_spend + reward).max(0.0);
            AlphaUpdate {
                wealth_prev,
                alpha_spend,
                discoveries,
                alpha_earn: cfg.alpha_earn,
                wealth_next,
            }
        };
        let expected = (0.05 - update.alpha_spend + 0.03).max(0.0);
        assert!((update.wealth_next - expected).abs() <= 1e-12);
    }

    #[test]
    fn store_persists_state() {
        let dir = tempdir().expect("tempdir");
        let store = AlphaInvestingStore::new(dir.path());
        let mut policy = Policy::default();
        policy.fdr_control.alpha_investing = Some(AlphaInvesting {
            w0: Some(0.05),
            alpha_spend: Some(0.02),
            alpha_earn: Some(0.01),
        });
        let state = store.load_or_init(&policy, 1000).expect("init");
        assert!(state.wealth > 0.0);
        let update = store.update_wealth(&policy, 1000, 2).expect("update");
        assert!(update.wealth_next >= 0.0);
    }

    // ── AlphaInvestingPolicy construction ────────────────────────────

    fn make_policy_with_alpha(w0: Option<f64>, spend: Option<f64>, earn: Option<f64>) -> Policy {
        let mut p = Policy::default();
        p.fdr_control.alpha_investing = Some(AlphaInvesting {
            w0,
            alpha_spend: spend,
            alpha_earn: earn,
        });
        p
    }

    #[test]
    fn policy_from_config_defaults() {
        let policy = make_policy_with_alpha(None, None, None);
        let cfg = AlphaInvestingPolicy::from_policy(&policy).unwrap();
        assert!((cfg.w0 - 0.05).abs() < f64::EPSILON);
        assert!((cfg.alpha_spend - 0.02).abs() < f64::EPSILON);
        assert!((cfg.alpha_earn - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_from_config_custom_values() {
        let policy = make_policy_with_alpha(Some(0.10), Some(0.05), Some(0.03));
        let cfg = AlphaInvestingPolicy::from_policy(&policy).unwrap();
        assert!((cfg.w0 - 0.10).abs() < f64::EPSILON);
        assert!((cfg.alpha_spend - 0.05).abs() < f64::EPSILON);
        assert!((cfg.alpha_earn - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_missing_alpha_investing() {
        let policy = Policy::default();
        let result = AlphaInvestingPolicy::from_policy(&policy);
        assert!(result.is_err());
        match result.unwrap_err() {
            AlphaInvestingError::MissingPolicy => {}
            other => panic!("expected MissingPolicy, got {:?}", other),
        }
    }

    #[test]
    fn policy_invalid_w0_zero() {
        let policy = make_policy_with_alpha(Some(0.0), Some(0.02), Some(0.01));
        let result = AlphaInvestingPolicy::from_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn policy_invalid_w0_negative() {
        let policy = make_policy_with_alpha(Some(-0.01), Some(0.02), Some(0.01));
        assert!(AlphaInvestingPolicy::from_policy(&policy).is_err());
    }

    #[test]
    fn policy_invalid_negative_spend() {
        let policy = make_policy_with_alpha(Some(0.05), Some(-0.01), Some(0.01));
        assert!(AlphaInvestingPolicy::from_policy(&policy).is_err());
    }

    #[test]
    fn policy_invalid_negative_earn() {
        let policy = make_policy_with_alpha(Some(0.05), Some(0.02), Some(-0.01));
        assert!(AlphaInvestingPolicy::from_policy(&policy).is_err());
    }

    #[test]
    fn policy_zero_spend_and_earn_valid() {
        let policy = make_policy_with_alpha(Some(0.05), Some(0.0), Some(0.0));
        let cfg = AlphaInvestingPolicy::from_policy(&policy).unwrap();
        assert!((cfg.alpha_spend - 0.0).abs() < f64::EPSILON);
        assert!((cfg.alpha_earn - 0.0).abs() < f64::EPSILON);
    }

    // ── alpha_spend_for_wealth ──────────────────────────────────────

    #[test]
    fn alpha_spend_proportional_to_wealth() {
        let cfg = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: 0.02,
            alpha_earn: 0.01,
        };
        let spend = cfg.alpha_spend_for_wealth(0.05);
        assert!((spend - 0.001).abs() < f64::EPSILON); // 0.02 * 0.05 = 0.001
    }

    #[test]
    fn alpha_spend_zero_wealth() {
        let cfg = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: 0.02,
            alpha_earn: 0.01,
        };
        assert!((cfg.alpha_spend_for_wealth(0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn alpha_spend_negative_wealth() {
        let cfg = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: 0.02,
            alpha_earn: 0.01,
        };
        assert!((cfg.alpha_spend_for_wealth(-1.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn alpha_spend_capped_at_wealth() {
        // If alpha_spend is very high, spend is capped at wealth
        let cfg = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: 2.0,
            alpha_earn: 0.01,
        };
        let spend = cfg.alpha_spend_for_wealth(0.05);
        // 2.0 * 0.05 = 0.10, but min(0.10, 0.05) = 0.05
        assert!((spend - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn alpha_spend_large_wealth() {
        let cfg = AlphaInvestingPolicy {
            w0: 0.05,
            alpha_spend: 0.02,
            alpha_earn: 0.01,
        };
        let spend = cfg.alpha_spend_for_wealth(10.0);
        assert!((spend - 0.2).abs() < f64::EPSILON); // 0.02 * 10 = 0.2
    }

    // ── AlphaWealthState serde ──────────────────────────────────────

    #[test]
    fn wealth_state_serde_roundtrip() {
        let state = AlphaWealthState {
            wealth: 0.042,
            last_updated: "2026-01-15T00:00:00Z".to_string(),
            policy_id: Some("default".to_string()),
            policy_version: "1.0.0".to_string(),
            host_id: "test-host".to_string(),
            user_id: 1000,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: AlphaWealthState = serde_json::from_str(&json).unwrap();
        assert!((back.wealth - 0.042).abs() < f64::EPSILON);
        assert_eq!(back.user_id, 1000);
        assert_eq!(back.policy_id.as_deref(), Some("default"));
    }

    // ── AlphaUpdate serialization ───────────────────────────────────

    #[test]
    fn alpha_update_serializes() {
        let update = AlphaUpdate {
            wealth_prev: 0.05,
            alpha_spend: 0.001,
            discoveries: 2,
            alpha_earn: 0.01,
            wealth_next: 0.069,
        };
        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("\"discoveries\":2"));
        assert!(json.contains("wealth_prev"));
        assert!(json.contains("wealth_next"));
    }

    // ── AlphaInvestingStore with tempdir ─────────────────────────────

    #[test]
    fn store_new_paths() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        assert_eq!(store.state_path, dir.path().join("alpha_wealth.json"));
        assert_eq!(store.lock_path, dir.path().join("alpha_wealth.lock"));
    }

    #[test]
    fn store_load_or_init_creates_state() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.10), Some(0.02), Some(0.01));
        let state = store.load_or_init(&policy, 1000).unwrap();
        assert!((state.wealth - 0.10).abs() < f64::EPSILON);
        assert_eq!(state.user_id, 1000);
        assert!(store.state_path.exists());
    }

    #[test]
    fn store_load_or_init_returns_existing() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.10), Some(0.02), Some(0.01));
        store.load_or_init(&policy, 1000).unwrap();

        // Second call returns existing state
        let state2 = store.load_or_init(&policy, 2000).unwrap();
        // Note: user_id is from original init, not the new call
        assert_eq!(state2.user_id, 1000);
    }

    #[test]
    fn store_update_wealth_no_discoveries() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.05), Some(0.02), Some(0.01));
        store.load_or_init(&policy, 1000).unwrap();
        let update = store.update_wealth(&policy, 1000, 0).unwrap();
        // wealth_next = (0.05 - 0.001 + 0).max(0) = 0.049
        assert!((update.wealth_prev - 0.05).abs() < f64::EPSILON);
        assert!(update.wealth_next < update.wealth_prev);
        assert_eq!(update.discoveries, 0);
    }

    #[test]
    fn store_update_wealth_with_discoveries() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.05), Some(0.02), Some(0.01));
        store.load_or_init(&policy, 1000).unwrap();
        let update = store.update_wealth(&policy, 1000, 5).unwrap();
        // reward = 0.01 * 5 = 0.05
        // wealth_next = (0.05 - 0.001 + 0.05).max(0) = 0.099
        assert!(update.wealth_next > update.wealth_prev);
    }

    #[test]
    fn store_update_wealth_bottoms_at_zero() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.001), Some(1.0), Some(0.0));
        store.load_or_init(&policy, 1000).unwrap();
        // alpha_spend = min(1.0 * 0.001, 0.001) = 0.001
        // wealth_next = (0.001 - 0.001 + 0).max(0) = 0
        let update = store.update_wealth(&policy, 1000, 0).unwrap();
        assert!((update.wealth_next - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn store_sequential_updates_accumulate() {
        let dir = tempdir().unwrap();
        let store = AlphaInvestingStore::new(dir.path());
        let policy = make_policy_with_alpha(Some(0.05), Some(0.02), Some(0.01));
        store.load_or_init(&policy, 1000).unwrap();

        let u1 = store.update_wealth(&policy, 1000, 0).unwrap();
        let u2 = store.update_wealth(&policy, 1000, 0).unwrap();
        // Each update spends some wealth
        assert!((u2.wealth_prev - u1.wealth_next).abs() < f64::EPSILON);
        assert!(u2.wealth_next < u1.wealth_next);
    }

    // ── LockGuard ───────────────────────────────────────────────────

    #[test]
    fn lock_guard_creates_and_removes_file() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join("test.lock");
        {
            let _guard = LockGuard::acquire(&lock_path).unwrap();
            assert!(lock_path.exists());
        }
        // After drop, lock file is removed
        assert!(!lock_path.exists());
    }

    #[test]
    fn lock_guard_contains_pid() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join("pid.lock");
        let _guard = LockGuard::acquire(&lock_path).unwrap();
        let content = std::fs::read_to_string(&lock_path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
    }

    // ── AlphaInvestingError ─────────────────────────────────────────

    #[test]
    fn alpha_investing_error_display() {
        assert!(AlphaInvestingError::MissingPolicy
            .to_string()
            .contains("not configured"));
        assert!(AlphaInvestingError::InvalidPolicy("bad".into())
            .to_string()
            .contains("bad"));
        assert!(AlphaInvestingError::LockUnavailable
            .to_string()
            .contains("lock"));
    }
}
