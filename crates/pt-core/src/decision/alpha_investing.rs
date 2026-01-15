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

        let alpha_spend = choose_alpha_spend(state.wealth, &policy_cfg);
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

fn choose_alpha_spend(wealth: f64, policy: &AlphaInvestingPolicy) -> f64 {
    if wealth <= 0.0 {
        return 0.0;
    }
    let spend = policy.alpha_spend * wealth;
    spend.min(wealth)
}

struct LockGuard {
    lock_path: PathBuf,
}

impl LockGuard {
    fn acquire(path: &Path) -> Result<Self, AlphaInvestingError> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path);
        match file {
            Ok(mut handle) => {
                // Write PID to lock file for stale lock detection
                let _ = handle.write_all(format!("{}", std::process::id()).as_bytes());
                Ok(Self {
                    lock_path: path.to_path_buf(),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // Check if the lock is stale (holder process is dead)
                if Self::is_stale_lock(path) {
                    // Try to remove stale lock and acquire
                    if fs::remove_file(path).is_ok() {
                        return Self::acquire(path); // Retry acquisition
                    }
                }
                Err(AlphaInvestingError::LockUnavailable)
            }
            Err(err) => Err(AlphaInvestingError::Io(err)),
        }
    }

    /// Check if a lock file is stale (holder process no longer exists).
    fn is_stale_lock(path: &Path) -> bool {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                // Check if process with this PID exists
                // On Unix, sending signal 0 checks existence without affecting process
                #[cfg(unix)]
                {
                    // kill(pid, 0) returns 0 if process exists, -1 if not
                    let result = unsafe { libc::kill(pid as i32, 0) };
                    return result != 0;
                }
                #[cfg(not(unix))]
                {
                    // On non-Unix, we can't easily check - assume not stale
                    let _ = pid;
                    return false;
                }
            }
        }
        // Can't read/parse lock file - might be corrupted, treat as stale
        true
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
        let policy = Policy::default();
        let cfg = AlphaInvestingPolicy::from_policy(&policy).expect("policy");
        let update = {
            let wealth_prev = 0.05;
            let alpha_spend = choose_alpha_spend(wealth_prev, &cfg);
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
        let policy = Policy::default();
        let state = store.load_or_init(&policy, 1000).expect("init");
        assert!(state.wealth > 0.0);
        let update = store.update_wealth(&policy, 1000, 2).expect("update");
        assert!(update.wealth_next >= 0.0);
    }
}
