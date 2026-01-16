//! Tool runner with timeout, output cap, and budget controls.
//!
//! This module provides safe execution of external tools (ps, lsof, perf, etc.)
//! with robust safety controls:
//!
//! - Per-command timeout with SIGTERM → SIGKILL escalation
//! - Output size caps to prevent memory exhaustion
//! - Parallel execution with concurrency limits
//! - Cumulative budget tracking for overhead management
//! - nice/ionice to limit system impact
//! - Command path validation to prevent injection
//!
//! # Example
//!
//! ```ignore
//! use pt_core::collect::tool_runner::{ToolRunner, ToolConfig};
//! use std::time::Duration;
//!
//! let runner = ToolRunner::new(ToolConfig::default());
//! let output = runner.run_tool("ps", &["-ef"], None)?;
//! println!("Output: {}", String::from_utf8_lossy(&output.stdout));
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

/// Default timeout per command in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum output size in bytes (10MB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Default maximum parallel executions.
pub const DEFAULT_MAX_PARALLEL: usize = 4;

/// Default budget in milliseconds (5 seconds).
pub const DEFAULT_BUDGET_MS: u64 = 5000;

/// Grace period between SIGTERM and SIGKILL in milliseconds.
const SIGTERM_GRACE_MS: u64 = 500;

/// Errors that can occur during tool execution.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("command not found: {0}")]
    CommandNotFound(String),

    #[error("command failed to spawn: {0}")]
    SpawnFailed(String),

    #[error("command timed out after {0:?}")]
    Timeout(Duration),

    #[error("output exceeded limit of {limit} bytes (truncated to {actual})")]
    OutputTruncated { limit: usize, actual: usize },

    #[error("budget exhausted: used {used_ms}ms of {budget_ms}ms")]
    BudgetExhausted { used_ms: u64, budget_ms: u64 },

    #[error("command exited with non-zero status: {code}")]
    NonZeroExit { code: i32 },

    #[error("command killed by signal: {signal}")]
    KilledBySignal { signal: i32 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid command path: {0}")]
    InvalidPath(String),

    #[error("command not in allowlist: {0}")]
    NotAllowed(String),
}

/// Output from a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Command that was executed.
    pub command: String,

    /// Arguments passed to the command.
    pub args: Vec<String>,

    /// Standard output (may be truncated).
    pub stdout: Vec<u8>,

    /// Standard error (may be truncated).
    pub stderr: Vec<u8>,

    /// Exit code (if available).
    pub exit_code: Option<i32>,

    /// Whether output was truncated.
    pub truncated: bool,

    /// Execution duration.
    pub duration: Duration,

    /// Whether the command timed out.
    pub timed_out: bool,
}

impl ToolOutput {
    /// Get stdout as string (lossy UTF-8 conversion).
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Get stderr as string (lossy UTF-8 conversion).
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    /// Check if the command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Configuration for the tool runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Default timeout per command.
    #[serde(with = "humantime_serde")]
    pub default_timeout: Duration,

    /// Maximum output size per command in bytes.
    pub max_output_bytes: usize,

    /// Maximum parallel executions.
    pub max_parallel: usize,

    /// Total time budget in milliseconds.
    pub budget_ms: u64,

    /// Use nice to lower priority.
    pub use_nice: bool,

    /// Nice value (0-19, higher = lower priority).
    pub nice_value: i32,

    /// Use ionice to lower I/O priority (Linux only).
    #[cfg(target_os = "linux")]
    pub use_ionice: bool,

    /// ionice class (2 = best-effort, 3 = idle).
    #[cfg(target_os = "linux")]
    pub ionice_class: i32,

    /// Allowed commands (empty = all allowed).
    pub allowed_commands: HashSet<String>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_parallel: DEFAULT_MAX_PARALLEL,
            budget_ms: DEFAULT_BUDGET_MS,
            use_nice: true,
            nice_value: 10,
            #[cfg(target_os = "linux")]
            use_ionice: true,
            #[cfg(target_os = "linux")]
            ionice_class: 3, // idle class
            allowed_commands: HashSet::new(),
        }
    }
}

/// Specification for a tool to run.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// Command to execute.
    pub command: String,

    /// Arguments to pass.
    pub args: Vec<String>,

    /// Override timeout (None = use default).
    pub timeout: Option<Duration>,

    /// Override max output (None = use default).
    pub max_output: Option<usize>,
}

impl ToolSpec {
    /// Create a new tool specification.
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            command: command.into(),
            args,
            timeout: None,
            max_output: None,
        }
    }

    /// Set custom timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set custom max output.
    pub fn with_max_output(mut self, max_output: usize) -> Self {
        self.max_output = Some(max_output);
        self
    }
}

/// Tool runner with shared budget tracking.
#[derive(Debug)]
pub struct ToolRunner {
    config: ToolConfig,
    /// Cumulative time used in milliseconds.
    used_ms: Arc<AtomicU64>,
}

impl ToolRunner {
    /// Create a new tool runner with the given configuration.
    pub fn new(config: ToolConfig) -> Self {
        Self {
            config,
            used_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a tool runner with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ToolConfig::default())
    }

    /// Get the current budget usage in milliseconds.
    pub fn used_budget_ms(&self) -> u64 {
        self.used_ms.load(Ordering::SeqCst)
    }

    /// Get the remaining budget in milliseconds.
    pub fn remaining_budget_ms(&self) -> u64 {
        let used = self.used_ms.load(Ordering::SeqCst);
        self.config.budget_ms.saturating_sub(used)
    }

    /// Check if budget is exhausted.
    pub fn budget_exhausted(&self) -> bool {
        self.remaining_budget_ms() == 0
    }

    /// Reset the budget counter.
    pub fn reset_budget(&self) {
        self.used_ms.store(0, Ordering::SeqCst);
    }

    /// Run a single tool with the given command and arguments.
    ///
    /// # Arguments
    /// * `cmd` - Command to execute
    /// * `args` - Arguments to pass
    /// * `timeout` - Override timeout (None = use default)
    ///
    /// # Returns
    /// * `ToolOutput` on success
    /// * `ToolError` on failure
    #[instrument(skip(self), fields(cmd = %cmd))]
    pub fn run_tool(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<ToolOutput, ToolError> {
        let spec = ToolSpec {
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            timeout,
            max_output: None,
        };
        self.run(&spec)
    }

    /// Run a tool from a specification.
    #[instrument(skip(self), fields(cmd = %spec.command))]
    pub fn run(&self, spec: &ToolSpec) -> Result<ToolOutput, ToolError> {
        // Check budget before running
        if self.budget_exhausted() {
            let used = self.used_ms.load(Ordering::SeqCst);
            warn!(
                used_ms = used,
                budget_ms = self.config.budget_ms,
                "budget exhausted"
            );
            return Err(ToolError::BudgetExhausted {
                used_ms: used,
                budget_ms: self.config.budget_ms,
            });
        }

        // Validate command
        self.validate_command(&spec.command)?;

        let timeout = spec.timeout.unwrap_or(self.config.default_timeout);
        let max_output = spec.max_output.unwrap_or(self.config.max_output_bytes);

        debug!(
            command = %spec.command,
            args = ?spec.args,
            timeout_ms = timeout.as_millis(),
            max_output,
            "running tool"
        );

        let start = Instant::now();

        // Build command
        let mut command = self.build_command(&spec.command, &spec.args)?;

        // Spawn process
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!(command = %spec.command, error = %e, "failed to spawn");
                ToolError::SpawnFailed(e.to_string())
            })?;

        // Execute with timeout and output capture
        let result = self.execute_with_timeout(&mut child, timeout, max_output);

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;

        // Update budget
        self.used_ms.fetch_add(duration_ms, Ordering::SeqCst);

        info!(
            command = %spec.command,
            duration_ms,
            success = result.is_ok(),
            "tool execution complete"
        );

        match result {
            Ok((stdout, stderr, exit_code, truncated, timed_out)) => Ok(ToolOutput {
                command: spec.command.clone(),
                args: spec.args.clone(),
                stdout,
                stderr,
                exit_code,
                truncated,
                duration,
                timed_out,
            }),
            Err(e) => {
                // Even on error, we want to return what we captured
                warn!(command = %spec.command, error = %e, "tool execution failed");
                Err(e)
            }
        }
    }

    /// Run multiple tools in parallel with concurrency limit.
    ///
    /// # Arguments
    /// * `specs` - Tool specifications to run
    ///
    /// # Returns
    /// * Vector of results in the same order as input specs
    #[instrument(skip(self, specs), fields(count = specs.len()))]
    pub fn run_parallel(&self, specs: &[ToolSpec]) -> Vec<Result<ToolOutput, ToolError>> {
        if specs.is_empty() {
            return Vec::new();
        }

        let max_parallel = self.config.max_parallel;
        info!(
            count = specs.len(),
            max_parallel, "running tools in parallel"
        );

        // Use scoped threads to run in parallel with limited concurrency
        let results: Vec<_> = specs
            .chunks(max_parallel)
            .flat_map(|chunk| {
                thread::scope(|s| {
                    let handles: Vec<_> = chunk
                        .iter()
                        .map(|spec| s.spawn(|| self.run(spec)))
                        .collect();

                    handles
                        .into_iter()
                        .map(|h| h.join().unwrap_or_else(|_| {
                            error!("tool execution thread panicked");
                            Err(ToolError::SpawnFailed("thread panicked".to_string()))
                        }))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        results
    }

    /// Validate that a command is allowed and safe to execute.
    fn validate_command(&self, cmd: &str) -> Result<(), ToolError> {
        // Check allowlist if configured
        if !self.config.allowed_commands.is_empty() {
            let basename = Path::new(cmd)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(cmd);

            if !self.config.allowed_commands.contains(cmd)
                && !self.config.allowed_commands.contains(basename)
            {
                return Err(ToolError::NotAllowed(cmd.to_string()));
            }
        }

        // Reject commands with shell metacharacters
        if cmd.contains(['|', '&', ';', '$', '`', '\n', '\r']) {
            return Err(ToolError::InvalidPath(format!(
                "command contains shell metacharacters: {}",
                cmd
            )));
        }

        // Verify command exists if it's an absolute path
        if cmd.starts_with('/') && !Path::new(cmd).exists() {
            return Err(ToolError::CommandNotFound(cmd.to_string()));
        }

        Ok(())
    }

    /// Build the command with nice/ionice wrappers if configured.
    fn build_command(&self, cmd: &str, args: &[String]) -> Result<Command, ToolError> {
        let mut command;

        #[cfg(unix)]
        if self.config.use_nice {
            command = Command::new("nice");
            command.arg("-n").arg(self.config.nice_value.to_string());

            #[cfg(target_os = "linux")]
            if self.config.use_ionice {
                command.arg("ionice");
                command.arg("-c").arg(self.config.ionice_class.to_string());
            }

            command.arg(cmd);
        } else {
            command = Command::new(cmd);
        }

        #[cfg(not(unix))]
        {
            command = Command::new(cmd);
        }

        command.args(args);

        // Clear environment variables that could affect behavior
        command.env_clear();

        // Set minimal safe environment
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        command.env("LC_ALL", "C");
        command.env("LANG", "C");

        Ok(command)
    }

    /// Execute a child process with timeout and output capture.
    #[allow(clippy::type_complexity)]
    fn execute_with_timeout(
        &self,
        child: &mut Child,
        timeout: Duration,
        max_output: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, Option<i32>, bool, bool), ToolError> {
        let deadline = Instant::now() + timeout;
        let mut stdout_buf = Vec::with_capacity(max_output.min(65536));
        let mut stderr_buf = Vec::with_capacity(max_output.min(65536));
        let mut truncated = false;
        let mut timed_out = false;

        // Take ownership of stdout/stderr
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();

        // Read output in chunks with timeout checks
        let chunk_size = 8192;
        let mut chunk = vec![0u8; chunk_size];

        loop {
            if Instant::now() >= deadline {
                timed_out = true;
                warn!("command timed out, sending SIGTERM");
                self.kill_with_grace(child);
                break;
            }

            let mut did_read = false;

            // Try to read stdout
            if let Some(ref mut out) = stdout {
                if let Ok(n) = try_read_nonblocking(out, &mut chunk) {
                    if n > 0 {
                        did_read = true;
                        let space = max_output.saturating_sub(stdout_buf.len());
                        if space > 0 {
                            let to_copy = n.min(space);
                            stdout_buf.extend_from_slice(&chunk[..to_copy]);
                            if n > space {
                                truncated = true;
                            }
                        } else {
                            truncated = true;
                        }
                    }
                }
            }

            // Try to read stderr
            if let Some(ref mut err) = stderr {
                if let Ok(n) = try_read_nonblocking(err, &mut chunk) {
                    if n > 0 {
                        did_read = true;
                        let space = max_output.saturating_sub(stderr_buf.len());
                        if space > 0 {
                            let to_copy = n.min(space);
                            stderr_buf.extend_from_slice(&chunk[..to_copy]);
                            if n > space {
                                truncated = true;
                            }
                        } else {
                            truncated = true;
                        }
                    }
                }
            }

            // Check if process has exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited, drain remaining output
                    if let Some(ref mut out) = stdout {
                        let _ =
                            Self::drain_to_limit(out, &mut stdout_buf, max_output, &mut truncated);
                    }
                    if let Some(ref mut err) = stderr {
                        let _ =
                            Self::drain_to_limit(err, &mut stderr_buf, max_output, &mut truncated);
                    }

                    let exit_code = status.code();
                    trace!(exit_code = ?exit_code, "process exited");
                    return Ok((stdout_buf, stderr_buf, exit_code, truncated, timed_out));
                }
                Ok(None) => {
                    // Still running
                    if !did_read {
                        // Avoid busy-waiting
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(e) => {
                    error!(error = %e, "failed to wait for child");
                    return Err(ToolError::Io(e));
                }
            }
        }

        // Timed out - wait for kill to complete
        let status = child.wait().ok();
        let exit_code = status.and_then(|s| s.code());

        Ok((stdout_buf, stderr_buf, exit_code, truncated, timed_out))
    }

    /// Drain remaining data from a stream up to the limit.
    ///
    /// Uses non-blocking reads to avoid hanging on grandchild processes
    /// that may still hold the pipe open after the direct child exits.
    #[cfg(unix)]
    fn drain_to_limit<R: Read + std::os::unix::io::AsRawFd>(
        stream: &mut R,
        buf: &mut Vec<u8>,
        max: usize,
        truncated: &mut bool,
    ) -> std::io::Result<()> {
        let mut chunk = vec![0u8; 8192];
        // Use non-blocking reads to drain what's immediately available.
        // This prevents hanging when a grandchild process still holds the pipe open.
        loop {
            match try_read_nonblocking(stream, &mut chunk) {
                Ok(0) => break, // No more data available
                Ok(n) => {
                    let space = max.saturating_sub(buf.len());
                    if space > 0 {
                        let to_copy = n.min(space);
                        buf.extend_from_slice(&chunk[..to_copy]);
                        if n > space {
                            *truncated = true;
                        }
                    } else {
                        *truncated = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Drain remaining data from a stream up to the limit.
    #[cfg(not(unix))]
    fn drain_to_limit(
        stream: &mut impl Read,
        buf: &mut Vec<u8>,
        max: usize,
        truncated: &mut bool,
    ) -> std::io::Result<()> {
        let mut chunk = vec![0u8; 8192];
        loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            let space = max.saturating_sub(buf.len());
            if space > 0 {
                let to_copy = n.min(space);
                buf.extend_from_slice(&chunk[..to_copy]);
                if n > space {
                    *truncated = true;
                }
            } else {
                *truncated = true;
            }
        }
        Ok(())
    }

    /// Kill a process with SIGTERM, then SIGKILL after grace period.
    #[cfg(unix)]
    fn kill_with_grace(&self, child: &mut Child) {
        let pid = child.id() as i32;

        // Send SIGTERM
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        debug!(pid, "sent SIGTERM");

        // Wait for grace period
        thread::sleep(Duration::from_millis(SIGTERM_GRACE_MS));

        // Check if still running
        match child.try_wait() {
            Ok(Some(_)) => {
                trace!(pid, "process exited after SIGTERM");
            }
            Ok(None) => {
                // Still running, escalate to SIGKILL
                warn!(pid, "process did not exit after SIGTERM, sending SIGKILL");
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let _ = child.wait();
            }
            Err(e) => {
                error!(pid, error = %e, "failed to check process status");
            }
        }
    }

    #[cfg(not(unix))]
    fn kill_with_grace(&self, child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Try to read from a stream without blocking.
///
/// On Unix, this uses fcntl to set O_NONBLOCK on the file descriptor,
/// performs a read, then restores the original flags.
/// Returns Ok(0) if no data is available (EAGAIN/EWOULDBLOCK).
#[cfg(unix)]
fn try_read_nonblocking<R: Read + std::os::unix::io::AsRawFd>(
    stream: &mut R,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let fd = stream.as_raw_fd();

    // Get current flags
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Set non-blocking if not already set
    let was_nonblocking = (flags & libc::O_NONBLOCK) != 0;
    if !was_nonblocking {
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Attempt read
    let result = stream.read(buf);

    // Restore blocking mode if we changed it
    if !was_nonblocking {
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags);
        }
    }

    // Convert EAGAIN/EWOULDBLOCK to Ok(0)
    match result {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(e),
    }
}

/// Non-blocking read fallback for non-Unix platforms.
/// Falls back to blocking read.
#[cfg(not(unix))]
fn try_read_nonblocking<R: Read>(stream: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    stream.read(buf)
}

/// Builder for creating a tool runner with custom configuration.
#[derive(Debug, Default)]
pub struct ToolRunnerBuilder {
    config: ToolConfig,
}

impl ToolRunnerBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.default_timeout = timeout;
        self
    }

    /// Set the maximum output size.
    pub fn max_output(mut self, max_bytes: usize) -> Self {
        self.config.max_output_bytes = max_bytes;
        self
    }

    /// Set the maximum parallel executions.
    pub fn max_parallel(mut self, max: usize) -> Self {
        self.config.max_parallel = max;
        self
    }

    /// Set the total time budget in milliseconds.
    pub fn budget_ms(mut self, budget: u64) -> Self {
        self.config.budget_ms = budget;
        self
    }

    /// Enable or disable nice.
    pub fn use_nice(mut self, enable: bool) -> Self {
        self.config.use_nice = enable;
        self
    }

    /// Set the nice value.
    pub fn nice_value(mut self, value: i32) -> Self {
        self.config.nice_value = value;
        self
    }

    /// Add allowed commands (restrict to only these).
    pub fn allow_commands<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for cmd in commands {
            self.config.allowed_commands.insert(cmd.into());
        }
        self
    }

    /// Build the tool runner.
    pub fn build(self) -> ToolRunner {
        ToolRunner::new(self.config)
    }
}

/// Convenience function to run a single tool with default settings.
pub fn run_tool(
    cmd: &str,
    args: &[&str],
    timeout: Option<Duration>,
    max_output: Option<usize>,
) -> Result<ToolOutput, ToolError> {
    let mut config = ToolConfig::default();
    if let Some(t) = timeout {
        config.default_timeout = t;
    }
    if let Some(m) = max_output {
        config.max_output_bytes = m;
    }
    let runner = ToolRunner::new(config);
    runner.run_tool(cmd, args, None)
}

/// Convenience function to run multiple tools in parallel.
pub fn run_tools_parallel(
    specs: &[ToolSpec],
    max_parallel: Option<usize>,
) -> Vec<Result<ToolOutput, ToolError>> {
    let mut config = ToolConfig::default();
    if let Some(m) = max_parallel {
        config.max_parallel = m;
    }
    let runner = ToolRunner::new(config);
    runner.run_parallel(specs)
}

// Custom serde module for Duration using humantime format
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ms = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runner() -> ToolRunner {
        ToolRunnerBuilder::new()
            .use_nice(false)
            .budget_ms(60000) // 60s budget for tests
            .build()
    }

    #[test]
    fn test_run_echo() {
        let runner = test_runner();
        let result = runner.run_tool("echo", &["hello", "world"], None);

        assert!(result.is_ok(), "echo failed: {:?}", result);
        let output = result.unwrap();
        assert!(output.success());
        assert_eq!(output.stdout_str().trim(), "hello world");
        assert!(!output.truncated);
        assert!(!output.timed_out);
    }

    #[test]
    fn test_run_with_stderr() {
        let runner = test_runner();
        // Use sh to echo to stderr
        let result = runner.run_tool("sh", &["-c", "echo error >&2"], None);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.success());
        assert!(output.stderr_str().contains("error"));
    }

    #[test]
    fn test_nonzero_exit() {
        let runner = test_runner();
        let result = runner.run_tool("sh", &["-c", "exit 42"], None);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(!output.success());
        assert_eq!(output.exit_code, Some(42));
    }

    #[test]
    fn test_command_not_found() {
        let runner = test_runner();
        let result = runner.run_tool("/nonexistent/command/that/does/not/exist", &[], None);

        assert!(result.is_err());
        matches!(result.unwrap_err(), ToolError::CommandNotFound(_));
    }

    #[test]
    fn test_invalid_path_shell_metachar() {
        let runner = test_runner();
        let result = runner.run_tool("echo; rm -rf /", &[], None);

        assert!(result.is_err());
        match result.unwrap_err() {
            ToolError::InvalidPath(_) => {}
            e => panic!("expected InvalidPath, got {:?}", e),
        }
    }

    #[test]
    fn test_timeout() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .timeout(Duration::from_millis(100))
            .budget_ms(60000)
            .build();

        let result = runner.run_tool("sleep", &["10"], None);

        assert!(result.is_ok(), "result: {:?}", result);
        let output = result.unwrap();
        assert!(
            output.timed_out,
            "Expected timed_out=true, got: {:?}",
            output
        );
        // Process should have been killed
        assert!(output.duration < Duration::from_secs(2));
    }

    #[test]
    fn test_output_truncation() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .max_output(100)
            .budget_ms(60000)
            .build();

        // Generate lots of output
        let result = runner.run_tool("sh", &["-c", "yes | head -n 1000"], None);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.truncated);
        assert!(output.stdout.len() <= 100);
    }

    #[test]
    fn test_budget_tracking() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .budget_ms(60000)
            .build();

        assert_eq!(runner.used_budget_ms(), 0);

        let _ = runner.run_tool("echo", &["test"], None);

        assert!(runner.used_budget_ms() > 0);
        assert!(runner.remaining_budget_ms() < 60000);

        runner.reset_budget();
        assert_eq!(runner.used_budget_ms(), 0);
    }

    #[test]
    fn test_budget_exhaustion() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .budget_ms(1) // Very small budget
            .build();

        // First run should succeed but exhaust budget
        let _ = runner.run_tool("echo", &["test"], None);

        // Second run should fail
        let result = runner.run_tool("echo", &["test2"], None);
        match result {
            Err(ToolError::BudgetExhausted { .. }) => {}
            other => panic!("expected BudgetExhausted, got {:?}", other),
        }
    }

    #[test]
    fn test_allowlist() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .allow_commands(vec!["echo"])
            .budget_ms(60000)
            .build();

        // Allowed command
        let result = runner.run_tool("echo", &["allowed"], None);
        assert!(result.is_ok());

        // Not allowed
        let result = runner.run_tool("cat", &["/etc/passwd"], None);
        match result {
            Err(ToolError::NotAllowed(_)) => {}
            other => panic!("expected NotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn test_parallel_execution() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .max_parallel(2)
            .budget_ms(60000)
            .build();

        let specs = vec![
            ToolSpec::new("echo", vec!["one".to_string()]),
            ToolSpec::new("echo", vec!["two".to_string()]),
            ToolSpec::new("echo", vec!["three".to_string()]),
        ];

        let results = runner.run_parallel(&specs);

        assert_eq!(results.len(), 3);
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok(), "spec {} failed: {:?}", i, result);
        }

        // Check outputs are correct
        assert_eq!(results[0].as_ref().unwrap().stdout_str().trim(), "one");
        assert_eq!(results[1].as_ref().unwrap().stdout_str().trim(), "two");
        assert_eq!(results[2].as_ref().unwrap().stdout_str().trim(), "three");
    }

    #[test]
    fn test_tool_spec_builder() {
        let spec = ToolSpec::new("ps", vec!["-ef".to_string()])
            .with_timeout(Duration::from_secs(5))
            .with_max_output(1024);

        assert_eq!(spec.command, "ps");
        assert_eq!(spec.args, vec!["-ef"]);
        assert_eq!(spec.timeout, Some(Duration::from_secs(5)));
        assert_eq!(spec.max_output, Some(1024));
    }

    #[test]
    fn test_config_defaults() {
        let config = ToolConfig::default();

        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert_eq!(config.max_output_bytes, 10 * 1024 * 1024);
        assert_eq!(config.max_parallel, 4);
        assert_eq!(config.budget_ms, 5000);
        assert!(config.use_nice);
        assert!(config.allowed_commands.is_empty());
    }

    #[test]
    fn test_convenience_functions() {
        // Test run_tool convenience function
        let result = run_tool("echo", &["convenience"], None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().stdout_str().trim(), "convenience");

        // Test run_tools_parallel convenience function
        let specs = vec![
            ToolSpec::new("echo", vec!["a".to_string()]),
            ToolSpec::new("echo", vec!["b".to_string()]),
        ];
        let results = run_tools_parallel(&specs, Some(2));
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }
}
