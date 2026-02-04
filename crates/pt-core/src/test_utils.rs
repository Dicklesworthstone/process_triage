//! Test utilities for pt-core.
//!
//! This module provides test infrastructure including:
//! - Test logging with structured JSONL output
//! - Fixture loading helpers
//! - Common assertions
//! - Tempdir management

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ============================================================================
// Macros (must be defined first for use in this module)
// ============================================================================

/// Assert that a Result is Ok and return the value.
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    };
    ($expr:expr, $msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("{}: {:?}", $msg, e),
        }
    };
}

/// Assert that a Result is Err.
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?}", val),
            Err(_) => {}
        }
    };
    ($expr:expr, $msg:expr) => {
        match $expr {
            Ok(val) => panic!("{}: got Ok({:?})", $msg, val),
            Err(_) => {}
        }
    };
}

/// Assert that two floating point numbers are approximately equal.
#[macro_export]
macro_rules! assert_approx_eq {
    ($a:expr, $b:expr) => {
        $crate::assert_approx_eq!($a, $b, 1e-6_f64)
    };
    ($a:expr, $b:expr, $epsilon:expr) => {{
        let a: f64 = $a;
        let b: f64 = $b;
        let eps: f64 = $epsilon;
        let diff = (a - b).abs();
        if diff > eps {
            panic!(
                "assertion failed: `(left ~= right)` (left: `{}`, right: `{}`, diff: `{}`, epsilon: `{}`)",
                a, b, diff, eps
            );
        }
    }};
}

// ============================================================================
// Fixtures
// ============================================================================

/// Fixture directory relative to crate root.
pub const FIXTURES_DIR: &str = "../../test/fixtures/pt-core";

/// Get the path to a test fixture file.
///
/// # Example
/// ```ignore
/// let priors_path = fixture_path("priors.json");
/// ```
pub fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join(FIXTURES_DIR).join(name)
}

/// Load a fixture file as a string.
pub fn load_fixture(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(fixture_path(name))
}

/// Load a fixture file and parse as JSON.
pub fn load_fixture_json<T: serde::de::DeserializeOwned>(name: &str) -> Result<T, String> {
    let content =
        load_fixture(name).map_err(|e| format!("Failed to read fixture {}: {}", name, e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse fixture {}: {}", name, e))
}

// ============================================================================
// Test Timer
// ============================================================================

/// Test timer for measuring duration of operations.
pub struct TestTimer {
    name: String,
    start: Instant,
}

impl TestTimer {
    /// Start a new timer with the given name.
    pub fn new(name: &str) -> Self {
        let timer = Self {
            name: name.to_string(),
            start: Instant::now(),
        };
        eprintln!("[TIMER] {} started", name);
        timer
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }
}

impl Drop for TestTimer {
    fn drop(&mut self) {
        eprintln!("[TIMER] {} completed in {}ms", self.name, self.elapsed_ms());
    }
}

// ============================================================================
// Tempdir Helper
// ============================================================================

/// Create a temporary directory that is automatically cleaned up.
///
/// Uses the `tempfile` crate's TempDir.
#[cfg(feature = "test-tempdir")]
pub fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp dir")
}

// ============================================================================
// Process Harness (no-mock integration tests)
// ============================================================================

/// Lightweight process harness for spawning real processes in tests.
#[derive(Debug, Default)]
pub struct ProcessHarness;

impl ProcessHarness {
    /// Return true if the current platform supports spawning test processes.
    pub fn is_available() -> bool {
        #[cfg(unix)]
        {
            if !Path::new("/proc").exists() {
                return false;
            }
            std::process::Command::new("sh")
                .arg("-c")
                .arg("true")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Spawn a shell command and return a handle.
    pub fn spawn_shell(&self, cmd: &str) -> std::io::Result<ProcessHandle> {
        #[cfg(unix)]
        {
            ProcessHandle::spawn("sh", &["-c", cmd])
        }
        #[cfg(not(unix))]
        {
            let _ = cmd;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "shell spawn not supported on this platform",
            ))
        }
    }

    /// Spawn a sleep process for the given duration (seconds).
    pub fn spawn_sleep(&self, seconds: u64) -> std::io::Result<ProcessHandle> {
        #[cfg(unix)]
        {
            ProcessHandle::spawn("sleep", &[&seconds.max(1).to_string()])
        }
        #[cfg(not(unix))]
        {
            // Fallback for non-unix (not really supported but keep signature)
            self.spawn_shell(&format!("sleep {}", seconds.max(1)))
        }
    }

    /// Spawn a CPU-busy process.
    pub fn spawn_busy(&self) -> std::io::Result<ProcessHandle> {
        self.spawn_shell("while :; do :; done")
    }

    /// Spawn a process for TOCTOU testing (killable target).
    pub fn spawn_toctou_target(&self, seconds: u64) -> std::io::Result<ProcessHandle> {
        self.spawn_sleep(seconds)
    }

    /// Spawn a process group with a parent and child processes.
    ///
    /// Returns the parent process handle. The parent spawns a child worker.
    /// Both processes run in a NEW process group (separate from the test runner).
    /// This is important for testing SIGSTOP/SIGCONT on process groups without
    /// affecting the test runner itself.
    pub fn spawn_process_group(&self) -> std::io::Result<ProcessHandle> {
        #[cfg(unix)]
        {
            // Spawn in a new session/process group to isolate from test runner
            ProcessHandle::spawn_with_options(
                "sh",
                &["-c", "sleep 120 & child_pid=$!; sleep 120; wait $child_pid"],
                true, // new_pgrp = true
            )
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "process group spawn not supported on this platform",
            ))
        }
    }

    /// Spawn a CPU-busy process group (parent + child worker).
    /// Spawns in a new process group to isolate from test runner.
    pub fn spawn_busy_group(&self) -> std::io::Result<ProcessHandle> {
        #[cfg(unix)]
        {
            ProcessHandle::spawn_with_options(
                "sh",
                &[
                    "-c",
                    "(while :; do :; done) & child_pid=$!; while :; do :; done",
                ],
                true, // new_pgrp = true
            )
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "process group spawn not supported on this platform",
            ))
        }
    }
}

/// Handle to a spawned process for test control.
pub struct ProcessHandle {
    pid: u32,
    child: std::sync::Mutex<std::process::Child>,
}

impl ProcessHandle {
    fn spawn(program: &str, args: &[&str]) -> std::io::Result<Self> {
        Self::spawn_with_options(program, args, false)
    }

    /// Spawn a process, optionally in its own process group (new session).
    #[cfg(unix)]
    fn spawn_with_options(program: &str, args: &[&str], new_pgrp: bool) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;

        let mut cmd = std::process::Command::new(program);
        cmd.args(args);

        if new_pgrp {
            // Create the process in its own process group
            // SAFETY: setsid() is safe to call in a child process pre-exec
            unsafe {
                cmd.pre_exec(|| {
                    // Create a new session and process group
                    libc::setsid();
                    Ok(())
                });
            }
        }

        let child = cmd.spawn()?;
        let pid = child.id();
        Ok(Self {
            pid,
            child: std::sync::Mutex::new(child),
        })
    }

    #[cfg(not(unix))]
    fn spawn_with_options(program: &str, args: &[&str], _new_pgrp: bool) -> std::io::Result<Self> {
        let child = std::process::Command::new(program).args(args).spawn()?;
        let pid = child.id();
        Ok(Self {
            pid,
            child: std::sync::Mutex::new(child),
        })
    }

    /// Return the PID for this process.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Return the process group ID (PGID) for this process.
    #[cfg(target_os = "linux")]
    pub fn pgid(&self) -> Option<u32> {
        let stat_path = format!("/proc/{}/stat", self.pid);
        let stat = std::fs::read_to_string(stat_path).ok()?;
        // Format: pid (comm) state ppid pgrp session ...
        let comm_end = stat.rfind(')')?;
        let after_comm = stat.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // Field 2 (0-indexed after comm) is pgrp
        fields.get(2)?.parse().ok()
    }

    /// Get the process state character (R, S, T, Z, etc).
    #[cfg(target_os = "linux")]
    pub fn state(&self) -> Option<char> {
        let stat_path = format!("/proc/{}/stat", self.pid);
        let stat = std::fs::read_to_string(stat_path).ok()?;
        let comm_end = stat.rfind(')')?;
        let after_comm = stat.get(comm_end + 2..)?;
        after_comm.chars().next()
    }

    /// Check if the process is stopped (state T or t).
    #[cfg(target_os = "linux")]
    pub fn is_stopped(&self) -> bool {
        matches!(self.state(), Some('T') | Some('t'))
    }

    /// Get all PIDs in this process's group (including self).
    #[cfg(target_os = "linux")]
    pub fn group_pids(&self) -> Vec<u32> {
        let target_pgid = match self.pgid() {
            Some(pg) => pg,
            None => return vec![self.pid],
        };

        let mut pids = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        // Read this process's PGID
                        let stat_path = format!("/proc/{}/stat", pid);
                        if let Ok(stat) = std::fs::read_to_string(stat_path) {
                            if let Some(comm_end) = stat.rfind(')') {
                                if let Some(after_comm) = stat.get(comm_end + 2..) {
                                    let fields: Vec<&str> = after_comm.split_whitespace().collect();
                                    if let Some(pgid_str) = fields.get(2) {
                                        if let Ok(pgid) = pgid_str.parse::<u32>() {
                                            if pgid == target_pgid {
                                                pids.push(pid);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        pids
    }

    /// Check if the process is still running.
    pub fn is_running(&self) -> bool {
        let Ok(mut child) = self.child.lock() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Capture a /proc snapshot for this process.
    pub fn snapshot(&self) -> std::io::Result<ProcSnapshot> {
        ProcSnapshot::capture(self.pid)
    }

    /// Request the process to exit.
    pub fn trigger_exit(&self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }

    /// Wait for the process to exit, returning true if it exited before timeout.
    pub fn wait_for_exit(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        loop {
            if !self.is_running() {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Snapshot of /proc data for a PID, used for TOCTOU checks.
#[derive(Debug, Clone)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub start_time_ticks: Option<u64>,
    pub stat: Option<String>,
    pub comm: Option<String>,
    pub status: std::collections::HashMap<String, String>,
}

impl ProcSnapshot {
    /// Capture a snapshot of /proc data for a PID.
    pub fn capture(pid: u32) -> std::io::Result<Self> {
        let stat_path = format!("/proc/{pid}/stat");
        let stat = std::fs::read_to_string(&stat_path)?;
        let start_time_ticks = parse_start_time_ticks(&stat);

        let comm_path = format!("/proc/{pid}/comm");
        let comm = std::fs::read_to_string(&comm_path)
            .ok()
            .map(|s| s.trim().to_string());

        let status_path = format!("/proc/{pid}/status");
        let status_content = std::fs::read_to_string(&status_path).unwrap_or_default();
        let status = parse_status(&status_content);

        Ok(Self {
            pid,
            start_time_ticks,
            stat: Some(stat),
            comm,
            status,
        })
    }

    /// Check if the process is still running with the same start time.
    pub fn is_still_running(&self) -> bool {
        let stat_path = format!("/proc/{}/stat", self.pid);
        let stat = match std::fs::read_to_string(&stat_path) {
            Ok(stat) => stat,
            Err(_) => return false,
        };
        let current = parse_start_time_ticks(&stat);
        match (self.start_time_ticks, current) {
            (Some(prev), Some(now)) => prev == now,
            _ => true,
        }
    }
}

fn parse_start_time_ticks(stat: &str) -> Option<u64> {
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    fields[19].parse().ok()
}

fn parse_status(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

// ============================================================================
// Process State Helpers
// ============================================================================

/// Get the process state character for any PID.
#[cfg(target_os = "linux")]
pub fn get_process_state(pid: u32) -> Option<char> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(stat_path).ok()?;
    let comm_end = stat.rfind(')')?;
    let after_comm = stat.get(comm_end + 2..)?;
    after_comm.chars().next()
}

/// Check if a process is stopped (state T or t).
#[cfg(target_os = "linux")]
pub fn is_process_stopped(pid: u32) -> bool {
    matches!(get_process_state(pid), Some('T') | Some('t'))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_path() {
        let path = fixture_path("priors.json");
        assert!(path.to_string_lossy().contains("fixtures"));
        assert!(path.to_string_lossy().ends_with("priors.json"));
    }

    #[test]
    fn test_load_fixture() {
        let content = load_fixture("priors.json").expect("Should load priors.json");
        assert!(content.contains("schema_version"));
        assert!(content.contains("useful"));
    }

    #[test]
    fn test_load_fixture_missing() {
        let result = load_fixture("nonexistent.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_timer() {
        let _timer = TestTimer::new("test_operation");
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Timer will log on drop
    }

    #[test]
    fn test_log_macro() {
        crate::test_log!("Test message: {}", 42);
        crate::test_log!("Another message");
    }

    #[test]
    fn test_assert_ok_macro() {
        let result: Result<i32, &str> = Ok(42);
        let val = assert_ok!(result);
        assert_eq!(val, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Ok")]
    fn test_assert_ok_fails() {
        let result: Result<i32, &str> = Err("error");
        let _ = assert_ok!(result);
    }

    #[test]
    fn test_assert_err_macro() {
        let result: Result<i32, &str> = Err("error");
        assert_err!(result);
    }

    #[test]
    fn test_assert_approx_eq() {
        assert_approx_eq!(1.0_f64, 1.0_f64);
        assert_approx_eq!(1.0_f64, 1.0000001_f64);
        assert_approx_eq!(0.1_f64 + 0.2_f64, 0.3_f64, 1e-10_f64);
    }
}
