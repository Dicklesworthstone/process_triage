//! Learned kill/spare decisions per command pattern ("pt learns from your decisions").
//!
//! Human verdicts (an explicit `pt-core agent label`, or an action a human
//! confirmed in the TUI) are counted per normalized command pattern at three
//! specificity levels (exact / standard / broad, via [`CommandNormalizer`]). When a
//! process matching a pattern is evaluated again, the counts become a Beta-Binomial
//! posterior for "this kind of process is abandoned", which replaces the class
//! prior for that process through the existing user-override path.
//!
//! Robot/agent-applied actions are deliberately NOT recorded: learning from the
//! model's own decisions would reinforce its own mistakes.
//!
//! Storage: `<config_dir>/decisions.json`, the file the `pt history` / `pt clear`
//! wrapper commands read and reset.

use crate::config::priors::Priors;
use crate::inference::prior_override::UserPriorOverrides;
use crate::supervision::pattern_learning::{CommandNormalizer, SpecificityLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// File name of the decision store inside the config directory.
pub const DECISIONS_FILE: &str = "decisions.json";

/// Pseudo-observations given to the global prior when combining it with counts.
/// With 2, one human "kill" moves P(abandoned) from a global 0.25 to 0.5.
pub const PRIOR_STRENGTH: f64 = 2.0;

/// Bounds on a learned P(abandoned): no amount of labeling makes a pattern certain,
/// so live evidence (CPU, TTY, children, state) can still overturn the prior.
pub const LEARNED_PRIOR_MIN: f64 = 0.02;
pub const LEARNED_PRIOR_MAX: f64 = 0.95;

/// Each verdict loses half its weight for every this many days since it was given, so
/// habits that changed long ago fade back toward the global prior.
pub const DECAY_HALF_LIFE_DAYS: f64 = 180.0;

/// A broad pattern (the program name plus a few primary flags, so it also covers
/// unrelated runs of the same interpreter) only sets the prior once verdicts for at
/// least this many distinct specific patterns were counted under it: one kill of
/// `node x.js` says nothing about `node y.js`.
pub const MIN_SOURCES_FOR_GENERALIZATION: usize = 2;

/// Distinct source patterns remembered per key (enough to apply the rule above).
const MAX_TRACKED_SOURCES: usize = 16;

fn parse_ts(ts: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Decay factor from `since` to `now` (1.0 if `since` is unknown or in the future).
fn decay_weight(since: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> f64 {
    let Some(ts) = parse_ts(since) else {
        return 1.0;
    };
    let age_days = (now - ts).num_seconds().max(0) as f64 / 86_400.0;
    0.5_f64.powf(age_days / DECAY_HALF_LIFE_DAYS)
}

/// Stable short id of a pattern key (FNV-1a 64), used to count distinct sources.
fn source_id(key: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A human verdict about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Kill,
    Spare,
}

/// Counts for one pattern key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PatternCounts {
    pub kill: u32,
    pub spare: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Decayed kill / spare weights as of `updated_at`: every verdict decays from the
    /// time it was given (exponential decay is memoryless, so these sums are exact).
    /// Absent in files written before they existed; the raw counts stand in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_weight: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spare_weight: Option<f64>,
    /// Ids of the distinct most-specific patterns whose verdicts were counted here
    /// (capped at `MAX_TRACKED_SOURCES`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

impl PatternCounts {
    fn total(&self) -> u32 {
        self.kill + self.spare
    }

    /// Decayed (kill, spare) weights at `now`.
    fn weights_at(&self, now: chrono::DateTime<chrono::Utc>) -> (f64, f64) {
        let decay = decay_weight(self.updated_at.as_deref(), now);
        (
            self.kill_weight.unwrap_or(f64::from(self.kill)) * decay,
            self.spare_weight.unwrap_or(f64::from(self.spare)) * decay,
        )
    }
}

/// On-disk entry: current format (counts) or the legacy wrapper format ("kill"/"spare").
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredEntry {
    Counts(PatternCounts),
    Legacy(Verdict),
}

/// Errors reading or writing the decision store.
#[derive(Debug, thiserror::Error)]
pub enum DecisionStoreError {
    #[error("decision store I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("decision store at {path} is not a JSON object: {message}")]
    Parse { path: PathBuf, message: String },
}

/// What the learned prior was derived from (for explanations / plan JSON).
#[derive(Debug, Clone, Serialize)]
pub struct LearnedPrior {
    pub pattern_key: String,
    pub kill: u32,
    pub spare: u32,
    /// Effective weight per verdict after age decay (1.0 = all labeled just now).
    pub weight: f64,
    /// Posterior mean P(abandoned or zombie) after combining with the global prior.
    pub abandonment_prior: f64,
}

/// Learned decisions keyed by `"<level>|<normalized name>|<normalized args>"`.
#[derive(Debug, Clone, Default)]
pub struct DecisionStore {
    path: PathBuf,
    entries: BTreeMap<String, PatternCounts>,
    /// Verdicts recorded since the last save, merged into the on-disk file on save.
    pending: BTreeMap<String, PatternCounts>,
}

fn read_entries(path: &Path) -> Result<BTreeMap<String, PatternCounts>, DecisionStoreError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(DecisionStoreError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let raw: BTreeMap<String, StoredEntry> =
        serde_json::from_str(&text).map_err(|e| DecisionStoreError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| {
            let counts = match v {
                StoredEntry::Counts(c) => c,
                StoredEntry::Legacy(Verdict::Kill) => PatternCounts {
                    kill: 1,
                    last: Some(Verdict::Kill),
                    ..Default::default()
                },
                StoredEntry::Legacy(Verdict::Spare) => PatternCounts {
                    spare: 1,
                    last: Some(Verdict::Spare),
                    ..Default::default()
                },
            };
            (k, counts)
        })
        .collect())
}

/// Add `delta`'s verdicts to `into`: both weight sums are decayed to the later of the
/// two timestamps and added there; `last` is the verdict of the later one.
fn add_counts(into: &mut PatternCounts, delta: &PatternCounts) {
    let into_ts = parse_ts(into.updated_at.as_deref());
    let delta_ts = parse_ts(delta.updated_at.as_deref());
    let at = into_ts.max(delta_ts);
    let (ik, is) = at.map_or_else(
        || {
            (
                into.kill_weight.unwrap_or(f64::from(into.kill)),
                into.spare_weight.unwrap_or(f64::from(into.spare)),
            )
        },
        |t| into.weights_at(t),
    );
    let (dk, ds) = at.map_or_else(
        || {
            (
                delta.kill_weight.unwrap_or(f64::from(delta.kill)),
                delta.spare_weight.unwrap_or(f64::from(delta.spare)),
            )
        },
        |t| delta.weights_at(t),
    );
    into.kill = into.kill.saturating_add(delta.kill);
    into.spare = into.spare.saturating_add(delta.spare);
    into.kill_weight = Some(ik + dk);
    into.spare_weight = Some(is + ds);
    if delta.last.is_some() && delta_ts >= into_ts {
        into.last = delta.last;
    }
    if let Some(t) = at {
        into.updated_at = Some(t.to_rfc3339());
    }
    for source in &delta.sources {
        if into.sources.len() < MAX_TRACKED_SOURCES && !into.sources.contains(source) {
            into.sources.push(source.clone());
        }
    }
}

/// Exclusive advisory lock on `<store>.lock`, held until dropped.
struct StoreLock(#[allow(dead_code)] std::fs::File);

impl StoreLock {
    fn acquire(store_path: &Path) -> Result<Self, DecisionStoreError> {
        let lock_path = store_path.with_extension("json.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|source| DecisionStoreError::Io {
                path: lock_path.clone(),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: flock on a file descriptor we own; blocks until the lock is free.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(DecisionStoreError::Io {
                    path: lock_path,
                    source: std::io::Error::last_os_error(),
                });
            }
        }
        // The lock is released when the file descriptor is closed.
        Ok(Self(file))
    }
}

impl DecisionStore {
    /// Load the store from `<config_dir>/decisions.json` (missing file = empty).
    pub fn load(config_dir: &Path) -> Result<Self, DecisionStoreError> {
        let path = config_dir.join(DECISIONS_FILE);
        let entries = read_entries(&path)?;
        Ok(Self {
            path,
            entries,
            pending: BTreeMap::new(),
        })
    }

    /// Merge verdicts recorded since the last save into the file: under an exclusive
    /// lock, re-read it (other writers may have added decisions), add ours, and
    /// replace it atomically. Concurrent writers never lose each other's verdicts.
    pub fn save(&mut self) -> Result<(), DecisionStoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|source| DecisionStoreError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        }
        let _lock = StoreLock::acquire(&self.path)?;
        let mut merged = read_entries(&self.path)?;
        for (key, delta) in &self.pending {
            add_counts(merged.entry(key.clone()).or_default(), delta);
        }
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        let text = serde_json::to_string_pretty(&merged).expect("counts serialize");
        std::fs::write(&tmp, format!("{text}\n")).map_err(|source| DecisionStoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|source| DecisionStoreError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.entries = merged;
        self.pending.clear();
        Ok(())
    }

    /// Number of distinct pattern keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no decisions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Pattern keys for a process, most specific first.
    pub fn pattern_keys(comm: &str, cmdline: &str) -> Vec<String> {
        let normalizer = CommandNormalizer::new();
        let mut candidates = normalizer.generate_candidates(comm, cmdline);
        candidates.sort_by_key(|c| c.level.priority_offset());
        candidates
            .into_iter()
            .map(|c| {
                let level = match c.level {
                    SpecificityLevel::Exact => "exact",
                    SpecificityLevel::Standard => "standard",
                    SpecificityLevel::Broad => "broad",
                };
                format!("{level}|{}|{}", c.process_pattern, c.arg_patterns.join(" "))
            })
            .collect()
    }

    /// Record a human verdict for a process at every specificity level.
    pub fn record(&mut self, comm: &str, cmdline: &str, verdict: Verdict) {
        self.record_at(comm, cmdline, verdict, chrono::Utc::now());
    }

    fn record_at(
        &mut self,
        comm: &str,
        cmdline: &str,
        verdict: Verdict,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        let keys = Self::pattern_keys(comm, cmdline);
        let Some(most_specific) = keys.first() else {
            return;
        };
        let delta = PatternCounts {
            kill: u32::from(verdict == Verdict::Kill),
            spare: u32::from(verdict == Verdict::Spare),
            last: Some(verdict),
            updated_at: Some(at.to_rfc3339()),
            kill_weight: None,
            spare_weight: None,
            sources: vec![source_id(most_specific)],
        };
        for key in keys {
            add_counts(self.entries.entry(key.clone()).or_default(), &delta);
            add_counts(self.pending.entry(key).or_default(), &delta);
        }
    }

    /// Learned prior for a process: decayed counts of the most specific pattern with
    /// decisions that may speak for it, combined with the global prior (Beta-Binomial
    /// posterior mean). Exact and standard patterns always may; a broad one only after
    /// verdicts for `MIN_SOURCES_FOR_GENERALIZATION` distinct specific patterns were
    /// counted under it.
    pub fn learned_prior(
        &self,
        comm: &str,
        cmdline: &str,
        global: &Priors,
    ) -> Option<LearnedPrior> {
        self.learned_prior_at(comm, cmdline, global, chrono::Utc::now())
    }

    fn learned_prior_at(
        &self,
        comm: &str,
        cmdline: &str,
        global: &Priors,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<LearnedPrior> {
        let g = &global.classes;
        let global_ab = (g.abandoned.prior_prob + g.zombie.prior_prob).clamp(1e-6, 1.0 - 1e-6);
        Self::pattern_keys(comm, cmdline)
            .into_iter()
            .find_map(|key| {
                self.entries
                    .get(&key)
                    .filter(|c| c.total() > 0)
                    .filter(|c| {
                        !key.starts_with("broad|")
                            || c.sources.len() >= MIN_SOURCES_FOR_GENERALIZATION
                    })
                    .map(|c| (key, c))
            })
            .map(|(key, c)| {
                let (kill_w, spare_w) = c.weights_at(now);
                let p = (kill_w + PRIOR_STRENGTH * global_ab)
                    / (kill_w + spare_w + PRIOR_STRENGTH);
                let p = p.clamp(LEARNED_PRIOR_MIN, LEARNED_PRIOR_MAX);
                LearnedPrior {
                    pattern_key: key,
                    kill: c.kill,
                    spare: c.spare,
                    weight: (kill_w + spare_w) / f64::from(c.total()),
                    abandonment_prior: p,
                }
            })
    }

    /// Class-prior overrides implementing a learned prior: the abandoned+zombie mass
    /// becomes `abandonment_prior`, split in the global ratio; the rest keeps the
    /// global useful : useful_bad ratio.
    pub fn overrides_for(learned: &LearnedPrior, global: &Priors) -> UserPriorOverrides {
        let g = &global.classes;
        let p = learned.abandonment_prior.clamp(1e-6, 1.0 - 1e-6);
        let ab_mass = (g.abandoned.prior_prob + g.zombie.prior_prob).max(1e-12);
        let ok_mass = (g.useful.prior_prob + g.useful_bad.prior_prob).max(1e-12);
        UserPriorOverrides {
            abandoned: Some(p * g.abandoned.prior_prob / ab_mass),
            zombie: Some(p * g.zombie.prior_prob / ab_mass),
            useful: Some((1.0 - p) * g.useful.prior_prob / ok_mass),
            useful_bad: Some((1.0 - p) * g.useful_bad.prior_prob / ok_mass),
        }
    }

    /// `global` with its class priors replaced by the learned prior for this process,
    /// or `None` when no human decision matches its command pattern.
    pub fn priors_for(&self, comm: &str, cmdline: &str, global: &Priors) -> Option<Priors> {
        let learned = self.learned_prior(comm, cmdline, global)?;
        let o = Self::overrides_for(&learned, global);
        let mut priors = global.clone();
        let c = &mut priors.classes;
        (c.useful.prior_prob, c.useful_bad.prior_prob) = (o.useful?, o.useful_bad?);
        (c.abandoned.prior_prob, c.zombie.prior_prob) = (o.abandoned?, o.zombie?);
        Some(priors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global() -> Priors {
        Priors::default()
    }

    #[test]
    fn empty_and_missing_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        assert!(store.is_empty());
        std::fs::write(dir.path().join(DECISIONS_FILE), "{}\n").unwrap();
        assert!(DecisionStore::load(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn legacy_wrapper_format_is_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(DECISIONS_FILE),
            r#"{"standard|jest|--watch": "kill", "broad|node|": "spare"}"#,
        )
        .unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn record_save_load_roundtrip_and_learned_prior() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        let cmd = "node /home/alice/app/node_modules/.bin/jest --watch tests/";
        assert!(store.learned_prior("node", cmd, &global()).is_none());

        store.record("node", cmd, Verdict::Kill);
        store.record("node", cmd, Verdict::Kill);
        store.save().unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();

        let learned = store
            .learned_prior("node", cmd, &global())
            .expect("learned");
        let g = global();
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(learned.abandonment_prior > base, "kills raise the prior");
        assert_eq!((learned.kill, learned.spare), (2, 0));

        // Overrides are a valid distribution carrying the learned mass.
        let o = DecisionStore::overrides_for(&learned, &g);
        let sum =
            o.useful.unwrap() + o.useful_bad.unwrap() + o.abandoned.unwrap() + o.zombie.unwrap();
        assert!((sum - 1.0).abs() < 1e-9);
        assert!(
            (o.abandoned.unwrap() + o.zombie.unwrap() - learned.abandonment_prior).abs() < 1e-9
        );
    }

    #[test]
    fn concurrent_writers_keep_every_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = "node server.js --port 3000";
        // Two stores loaded before either saves: a plain rewrite would lose one.
        let mut a = DecisionStore::load(dir.path()).unwrap();
        let mut b = DecisionStore::load(dir.path()).unwrap();
        a.record("node", cmd, Verdict::Kill);
        b.record("node", cmd, Verdict::Spare);
        a.save().unwrap();
        b.save().unwrap();

        // Many threads racing load -> record -> save.
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let path = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let mut s = DecisionStore::load(&path).unwrap();
                    s.record("node", cmd, Verdict::Kill);
                    s.save().unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let store = DecisionStore::load(dir.path()).unwrap();
        let learned = store.learned_prior("node", cmd, &global()).unwrap();
        assert_eq!((learned.kill, learned.spare), (17, 1));
    }

    #[test]
    fn old_verdicts_decay_toward_the_global_prior() {
        let now = chrono::Utc::now();
        let year_ago = (now - chrono::Duration::days(360)).to_rfc3339();
        assert!((decay_weight(Some(&year_ago), now) - 0.25).abs() < 1e-3);
        assert_eq!(decay_weight(None, now), 1.0);

        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..4 {
            store.record("sleep", "sleep 100", Verdict::Kill);
            store.record("cat", "cat /dev/zero", Verdict::Kill);
        }
        for key in DecisionStore::pattern_keys("cat", "cat /dev/zero") {
            store.entries.get_mut(&key).unwrap().updated_at = Some(year_ago.clone());
        }
        let fresh = store.learned_prior("sleep", "sleep 100", &g).unwrap();
        let stale = store.learned_prior("cat", "cat /dev/zero", &g).unwrap();
        assert!((stale.weight - 0.25).abs() < 1e-3);
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(fresh.abandonment_prior > stale.abandonment_prior);
        assert!(stale.abandonment_prior > base, "decayed, not erased");
    }

    /// Each verdict decays from its own time. Before: a pattern kept one timestamp, so
    /// 50 kills from two years ago plus one spare today counted as 50 fresh kills.
    #[test]
    fn every_verdict_decays_from_its_own_time() {
        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let now = chrono::Utc::now();
        let two_years_ago = now - chrono::Duration::days(730);
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..50 {
            store.record_at("sleep", "sleep 600", Verdict::Kill, two_years_ago);
        }
        store.record_at("sleep", "sleep 600", Verdict::Spare, now);

        let learned = store.learned_prior_at("sleep", "sleep 600", &g, now).unwrap();
        assert_eq!((learned.kill, learned.spare), (50, 1));
        // 50 kills at 0.5^(730/180) ~ 0.06 each ~ 3.0, plus one fresh spare.
        let expected_kill_w = 50.0 * 0.5_f64.powf(730.0 / DECAY_HALF_LIFE_DAYS);
        let global_ab = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        let expected = (expected_kill_w + PRIOR_STRENGTH * global_ab)
            / (expected_kill_w + 1.0 + PRIOR_STRENGTH);
        assert!(
            (learned.abandonment_prior - expected).abs() < 1e-6,
            "{} vs {expected}",
            learned.abandonment_prior
        );
        assert!(learned.abandonment_prior < 0.7, "old kills no longer dominate");

        // Decayed sums survive a save/load round trip and merge with a concurrent writer.
        store.save().unwrap();
        let mut other = DecisionStore::load(dir.path()).unwrap();
        other.record_at("sleep", "sleep 600", Verdict::Spare, now);
        other.save().unwrap();
        let reloaded = DecisionStore::load(dir.path()).unwrap();
        let learned = reloaded
            .learned_prior_at("sleep", "sleep 600", &g, now)
            .unwrap();
        assert_eq!((learned.kill, learned.spare), (50, 2));
        let expected = (expected_kill_w + PRIOR_STRENGTH * global_ab)
            / (expected_kill_w + 2.0 + PRIOR_STRENGTH);
        assert!((learned.abandonment_prior - expected).abs() < 1e-6);
    }

    /// One verdict on `node x.js` must not set the prior for `node y.js` (broad
    /// pattern `node.*`); a second, different node script under the same broad pattern
    /// makes it a habit worth generalizing.
    #[test]
    fn one_script_does_not_speak_for_every_run_of_its_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let g = global();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        store.record("node", "node /home/alice/x.js", Verdict::Kill);
        assert!(store
            .learned_prior("node", "node /home/alice/x.js", &g)
            .is_some());
        assert!(
            store.learned_prior("node", "node /srv/y.js", &g).is_none(),
            "{:?}",
            store.learned_prior("node", "node /srv/y.js", &g)
        );

        store.record("node", "node /home/alice/z.js", Verdict::Kill);
        let learned = store
            .learned_prior("node", "node /srv/y.js", &g)
            .expect("two distinct scripts generalize");
        assert!(learned.pattern_key.starts_with("broad|"), "{}", learned.pattern_key);
    }

    /// A file written before decayed weights and sources existed still loads: raw
    /// counts stand in for the weights (exactly the old reading).
    #[test]
    fn store_without_weights_or_sources_loads() {
        let dir = tempfile::tempdir().unwrap();
        let key = DecisionStore::pattern_keys("sleep", "sleep 100")
            .into_iter()
            .next()
            .unwrap();
        let mut file = serde_json::Map::new();
        file.insert(
            key,
            serde_json::json!({ "kill": 3, "spare": 1, "last": "kill" }),
        );
        std::fs::write(
            dir.path().join(DECISIONS_FILE),
            serde_json::Value::Object(file).to_string(),
        )
        .unwrap();
        let store = DecisionStore::load(dir.path()).unwrap();
        let learned = store
            .learned_prior("sleep", "sleep 100", &global())
            .expect("legacy counts apply");
        assert_eq!((learned.kill, learned.spare), (3, 1));
        assert!((learned.weight - 1.0).abs() < 1e-12);
    }

    #[test]
    fn learned_prior_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        for _ in 0..500 {
            store.record("sleep", "sleep 100", Verdict::Kill);
            store.record("vim", "vim notes.txt", Verdict::Spare);
        }
        let g = global();
        let killed = store.learned_prior("sleep", "sleep 100", &g).unwrap();
        let spared = store.learned_prior("vim", "vim notes.txt", &g).unwrap();
        assert_eq!(killed.abandonment_prior, LEARNED_PRIOR_MAX);
        assert_eq!(spared.abandonment_prior, LEARNED_PRIOR_MIN);
    }

    #[test]
    fn spares_lower_the_prior_and_path_details_generalize() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DecisionStore::load(dir.path()).unwrap();
        store.record(
            "python3",
            "python3 -m http.server 8080 --bind 127.0.0.1",
            Verdict::Spare,
        );
        // Different port: the port is normalized away, so the decision applies.
        let learned = store
            .learned_prior(
                "python3",
                "python3 -m http.server 9090 --bind 127.0.0.1",
                &global(),
            )
            .expect("generalizes across ports");
        let g = global();
        let base = g.classes.abandoned.prior_prob + g.classes.zombie.prior_prob;
        assert!(learned.abandonment_prior < base, "spare lowers the prior");
    }
}
