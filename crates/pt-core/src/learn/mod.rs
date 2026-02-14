//! Interactive tutorial catalog and progress tracking for `pt learn`.
//!
//! This module intentionally keeps a conservative fallback path:
//! when verification budgets are exceeded or progress state is corrupt,
//! it falls back to static tutorial guidance without blocking users.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LEARN_SCHEMA_VERSION: &str = "1.0.0";
pub const PROGRESS_FILE_NAME: &str = "learn_progress.json";

static VERIFY_01: &[&[&str]] = &[
    &["--version"],
    &["scan", "--help"],
    &["robot", "plan", "--help"],
];
static VERIFY_02: &[&[&str]] = &[&["robot", "explain", "--help"], &["scan", "--help"]];
static VERIFY_03: &[&[&str]] = &[&["scan", "--help"], &["run", "--help"]];
static VERIFY_04: &[&[&str]] = &[&["robot", "plan", "--help"], &["robot", "apply", "--help"]];
static VERIFY_05: &[&[&str]] = &[
    &["agent", "plan", "--help"],
    &["agent", "explain", "--help"],
];
static VERIFY_06: &[&[&str]] = &[&["shadow", "--help"], &["telemetry", "status", "--help"]];
static VERIFY_07: &[&[&str]] = &[&["deep-scan", "--help"], &["scan", "--deep", "--help"]];

#[derive(Debug, Clone, Serialize)]
pub struct Tutorial {
    pub id: &'static str,
    pub slug: &'static str,
    pub title: &'static str,
    pub goal: &'static str,
    pub doc_path: &'static str,
    pub commands: &'static [&'static str],
    pub hints: &'static [&'static str],
    #[serde(skip_serializing)]
    pub verify_args: &'static [&'static [&'static str]],
}

static TUTORIALS: &[Tutorial] = &[
    Tutorial {
        id: "01",
        slug: "first-run",
        title: "First Run",
        goal: "Understand safe scan/report behavior with no destructive actions.",
        doc_path: "docs/tutorials/01-first-run.md",
        commands: &["pt --version", "pt scan", "pt robot plan --format json"],
        hints: &[
            "Start with scan and plan-only commands before any apply step.",
            "Use robot explain to understand evidence on a single PID.",
        ],
        verify_args: VERIFY_01,
    },
    Tutorial {
        id: "02",
        slug: "stuck-test-runner",
        title: "Stuck Test Runner",
        goal: "Triage long-running tests safely and inspect decision evidence.",
        doc_path: "docs/tutorials/02-stuck-test-runner.md",
        commands: &["pt scan", "pt robot explain --pid <pid> --format json"],
        hints: &[
            "Prefer explain and plan before any apply command.",
            "Check command ancestry when deciding if a test process is abandoned.",
        ],
        verify_args: VERIFY_02,
    },
    Tutorial {
        id: "03",
        slug: "port-conflict",
        title: "Port Conflict",
        goal: "Resolve port collisions by ranking and reviewing suspicious processes.",
        doc_path: "docs/tutorials/03-port-conflict.md",
        commands: &["pt scan", "pt run --inline"],
        hints: &[
            "Use summary and genealogy views to inspect port-holding process trees.",
            "Avoid force-killing unknown parent processes; inspect first.",
        ],
        verify_args: VERIFY_03,
    },
    Tutorial {
        id: "04",
        slug: "agent-workflow",
        title: "Agent Workflow",
        goal: "Run plan/explain/apply flows in automation-friendly stages.",
        doc_path: "docs/tutorials/04-agent-workflow.md",
        commands: &[
            "pt robot plan --format json",
            "pt robot explain --pid <pid> --format json",
            "pt robot apply --pids <pid> --yes --format json",
        ],
        hints: &[
            "Persist plan output before apply to keep a full audit trail.",
            "Prefer dry-run in CI when introducing new policy thresholds.",
        ],
        verify_args: VERIFY_04,
    },
    Tutorial {
        id: "05",
        slug: "fleet-workflow",
        title: "Fleet Workflow",
        goal: "Coordinate multi-host planning with explicit review and artifacts.",
        doc_path: "docs/tutorials/05-fleet-workflow.md",
        commands: &[
            "pt agent fleet plan --hosts <hosts> --format json",
            "pt agent fleet apply --fleet-session <session> --format json",
        ],
        hints: &[
            "Use fleet report/status commands to inspect host-level outcomes.",
            "Keep apply operations gated by policy and explicit operator intent.",
        ],
        verify_args: VERIFY_05,
    },
    Tutorial {
        id: "06",
        slug: "shadow-calibration",
        title: "Shadow Calibration",
        goal: "Use shadow mode to calibrate decisions without executing actions.",
        doc_path: "docs/tutorials/README.md",
        commands: &["pt --shadow run", "pt shadow status"],
        hints: &[
            "Shadow mode should never execute destructive actions.",
            "Compare shadow telemetry before changing thresholds.",
        ],
        verify_args: VERIFY_06,
    },
    Tutorial {
        id: "07",
        slug: "deep-scan-evidence",
        title: "Deep Scan Evidence",
        goal: "Collect richer evidence using deep scan pathways with clear limits.",
        doc_path: "docs/tutorials/README.md",
        commands: &["pt deep-scan", "pt scan --deep"],
        hints: &[
            "Use deep scan selectively because it is more expensive.",
            "Fallback to quick scan when privileged probes are unavailable.",
        ],
        verify_args: VERIFY_07,
    },
];

pub fn tutorials() -> &'static [Tutorial] {
    TUTORIALS
}

pub fn find_tutorial(query: &str) -> Option<&'static Tutorial> {
    let q = query.trim().to_lowercase();
    TUTORIALS.iter().find(|t| {
        t.id == q
            || t.slug == q
            || format!("{}-{}", t.id, t.slug) == q
            || format!("tutorial-{}", t.id) == q
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnProgress {
    pub schema_version: String,
    pub completed: BTreeMap<String, String>,
}

impl Default for LearnProgress {
    fn default() -> Self {
        Self {
            schema_version: LEARN_SCHEMA_VERSION.to_string(),
            completed: BTreeMap::new(),
        }
    }
}

impl LearnProgress {
    pub fn is_completed(&self, tutorial: &Tutorial) -> bool {
        self.completed.contains_key(tutorial.id)
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    pub fn completion_ratio(&self, total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }
        self.completed_count() as f64 / total as f64
    }
}

#[derive(Debug, Error)]
pub enum LearnError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Progress file corrupted at {path}: {source}")]
    CorruptProgress {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub fn progress_path(config_dir: &Path) -> PathBuf {
    config_dir.join(PROGRESS_FILE_NAME)
}

pub fn load_progress(config_dir: &Path) -> Result<LearnProgress, LearnError> {
    let path = progress_path(config_dir);
    if !path.exists() {
        return Ok(LearnProgress::default());
    }
    let raw = std::fs::read_to_string(&path).map_err(|source| LearnError::Io {
        path: path.clone(),
        source,
    })?;
    let progress = serde_json::from_str::<LearnProgress>(&raw).map_err(|source| {
        LearnError::CorruptProgress {
            path: path.clone(),
            source,
        }
    })?;
    Ok(progress)
}

pub fn save_progress(config_dir: &Path, progress: &LearnProgress) -> Result<PathBuf, LearnError> {
    std::fs::create_dir_all(config_dir).map_err(|source| LearnError::Io {
        path: config_dir.to_path_buf(),
        source,
    })?;
    let path = progress_path(config_dir);
    let serialized = serde_json::to_string_pretty(progress).expect("progress serialization");
    std::fs::write(&path, serialized).map_err(|source| LearnError::Io {
        path: path.clone(),
        source,
    })?;
    tracing::debug!(
        target: "learn.progress_save",
        total_complete = progress.completed.len(),
        total_exercises = TUTORIALS.len(),
        path = %path.display(),
        "Saved learn progress"
    );
    Ok(path)
}

pub fn mark_completed(progress: &mut LearnProgress, tutorial: &Tutorial) {
    progress
        .completed
        .insert(tutorial.id.to_string(), Utc::now().to_rfc3339());
}

pub fn clear_progress(progress: &mut LearnProgress) {
    progress.completed.clear();
    progress.schema_version = LEARN_SCHEMA_VERSION.to_string();
}

pub fn next_tutorial<'a>(
    progress: &LearnProgress,
    catalog: &'a [Tutorial],
) -> Option<&'a Tutorial> {
    catalog.iter().find(|t| !progress.is_completed(t))
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyCheck {
    pub command: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub tutorial_id: String,
    pub tutorial_slug: String,
    pub status: String,
    pub fallback_active: bool,
    pub fallback_reason: Option<String>,
    pub total_duration_ms: u64,
    pub checks: Vec<VerifyCheck>,
}

fn command_label(args: &[&str]) -> String {
    let mut parts = vec!["pt-core".to_string()];
    parts.extend(args.iter().map(|s| (*s).to_string()));
    parts.join(" ")
}

fn run_check_with_budget(binary: &Path, args: &[&str], budget: Duration) -> VerifyCheck {
    let started = Instant::now();
    let command = command_label(args);
    let mut child = match Command::new(binary)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return VerifyCheck {
                command,
                status: "error".to_string(),
                exit_code: None,
                duration_ms: started.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            };
        }
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return VerifyCheck {
                    command,
                    status: if status.success() { "ok" } else { "failed" }.to_string(),
                    exit_code: status.code(),
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: None,
                };
            }
            Ok(None) => {
                if started.elapsed() > budget {
                    let _ = child.kill();
                    let _ = child.wait();
                    return VerifyCheck {
                        command,
                        status: "timeout".to_string(),
                        exit_code: None,
                        duration_ms: started.elapsed().as_millis() as u64,
                        error: Some(format!(
                            "verification exceeded {} ms budget",
                            budget.as_millis()
                        )),
                    };
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return VerifyCheck {
                    command,
                    status: "error".to_string(),
                    exit_code: None,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                };
            }
        }
    }
}

pub fn verify_tutorial(
    binary: &Path,
    tutorial: &Tutorial,
    per_check_budget: Duration,
    total_budget: Duration,
) -> VerifyResult {
    let overall_started = Instant::now();
    let mut checks = Vec::new();
    let mut fallback_active = false;
    let mut fallback_reason = None;
    let mut all_ok = true;

    for args in tutorial.verify_args {
        let elapsed = overall_started.elapsed();
        if elapsed >= total_budget {
            fallback_active = true;
            all_ok = false;
            fallback_reason = Some("total verification budget exhausted".to_string());
            checks.push(VerifyCheck {
                command: command_label(args),
                status: "budget_exhausted".to_string(),
                exit_code: None,
                duration_ms: elapsed.as_millis() as u64,
                error: Some("falling back to static tutorial guidance".to_string()),
            });
            break;
        }

        let remaining = total_budget.saturating_sub(elapsed);
        let budget = per_check_budget.min(remaining);
        let check = run_check_with_budget(binary, args, budget);
        if check.status != "ok" {
            all_ok = false;
            if check.status == "timeout" {
                fallback_active = true;
                fallback_reason = Some("per-check verification budget exhausted".to_string());
            }
        }
        checks.push(check);
    }

    VerifyResult {
        tutorial_id: tutorial.id.to_string(),
        tutorial_slug: tutorial.slug.to_string(),
        status: if all_ok { "ok" } else { "degraded" }.to_string(),
        fallback_active,
        fallback_reason,
        total_duration_ms: overall_started.elapsed().as_millis() as u64,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tutorial_lookup_supports_id_and_slug() {
        assert_eq!(find_tutorial("01").map(|t| t.slug), Some("first-run"));
        assert_eq!(find_tutorial("first-run").map(|t| t.id), Some("01"));
        assert_eq!(
            find_tutorial("tutorial-03").map(|t| t.slug),
            Some("port-conflict")
        );
    }

    #[test]
    fn progress_default_is_empty() {
        let p = LearnProgress::default();
        assert_eq!(p.completed_count(), 0);
        assert_eq!(p.schema_version, LEARN_SCHEMA_VERSION);
    }

    #[test]
    fn mark_and_clear_progress() {
        let mut p = LearnProgress::default();
        let t = find_tutorial("02").expect("tutorial");
        mark_completed(&mut p, t);
        assert!(p.is_completed(t));
        clear_progress(&mut p);
        assert!(!p.is_completed(t));
    }

    #[test]
    fn next_tutorial_skips_completed() {
        let mut p = LearnProgress::default();
        let first = &tutorials()[0];
        mark_completed(&mut p, first);
        let next = next_tutorial(&p, tutorials()).expect("next tutorial");
        assert_ne!(next.id, first.id);
    }

    #[test]
    fn verify_uses_fallback_for_zero_budget() {
        let tutorial = find_tutorial("01").expect("tutorial");
        let result = verify_tutorial(
            Path::new("/bin/echo"),
            tutorial,
            Duration::from_millis(1),
            Duration::from_millis(0),
        );
        assert_eq!(result.status, "degraded");
        assert!(result.fallback_active);
    }
}
