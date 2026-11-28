//! Tool runner with timeout, output cap, and budget controls.
//!
//! This module provides safe execution of external tools (ps, lsof, perf, etc.)
//! with robust safety controls:
//!
//! - Per-command deadline covering all pipes and child termination
//! - Output size caps to prevent memory exhaustion
//! - Parallel execution with concurrency limits
//! - Cumulative budget tracking for overhead management
//! - nice/ionice to limit system impact
//! - Command path validation to prevent injection
//! - Linux owned helpers receive a death signal if their spawning thread exits
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
use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
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

/// Hook delivery must not suspend monitoring. All notifications in one scan or
/// daemon tick share a budget, while each command also has its own deadline.
pub const NOTIFICATION_TIMEOUT_SECS: u64 = 2;
pub const NOTIFICATION_TICK_BUDGET_MS: u64 = 5_000;
pub const NOTIFICATION_MAX_OUTPUT_BYTES: usize = 16 * 1024;

/// Reuse this runner for every notification in a single monitoring iteration.
pub fn notification_runner() -> ToolRunner {
    ToolRunner::new(ToolConfig {
        default_timeout: Duration::from_secs(NOTIFICATION_TIMEOUT_SECS),
        max_output_bytes: NOTIFICATION_MAX_OUTPUT_BYTES,
        budget_ms: NOTIFICATION_TICK_BUDGET_MS,
        use_nice: false,
        ..ToolConfig::default()
    })
}

/// Run a literal notification command with bounded execution and pipe capture.
/// Successful exit is a command receipt, not proof of delivery to a person.
/// Never return child output: hooks may print credentials or terminal escapes.
pub fn run_notification(runner: &ToolRunner, spec: &ToolSpec) -> Result<(), String> {
    let mut bounded = spec.clone();
    // Linux keeps the owned group leader unreaped until collection completes,
    // so deadline cleanup can also cancel hook children without a PID-reuse race.
    #[cfg(target_os = "linux")]
    {
        bounded.isolate_process_group = true;
    }
    bounded.timeout = Some(
        bounded
            .timeout
            .unwrap_or(Duration::from_secs(NOTIFICATION_TIMEOUT_SECS))
            .min(Duration::from_secs(NOTIFICATION_TIMEOUT_SECS)),
    );
    bounded.max_output = Some(
        bounded
            .max_output
            .unwrap_or(NOTIFICATION_MAX_OUTPUT_BYTES)
            .min(NOTIFICATION_MAX_OUTPUT_BYTES),
    );
    let output = runner
        .run(&bounded)
        .map_err(|error| format!("notification command could not complete: {error}"))?;
    if output.timed_out {
        return Err("notification command timed out; delivery is unconfirmed".into());
    }
    if output.truncated {
        return Err(
            "notification command exceeded its output limit; delivery is unconfirmed".into(),
        );
    }
    if output.exit_code != Some(0) {
        return Err(format!(
            "notification command exited with {:?}; delivery is unconfirmed",
            output.exit_code
        ));
    }
    Ok(())
}

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
    NonZeroExit {
        code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },

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
        self.exit_code == Some(0) && !self.timed_out && !self.truncated
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

    /// Optional data to write to stdin.
    pub stdin: Option<Vec<u8>>,

    /// Optional working directory.
    pub working_dir: Option<std::path::PathBuf>,

    /// Override timeout (None = use default).
    pub timeout: Option<Duration>,

    /// Override max output (None = use default).
    pub max_output: Option<usize>,

    /// Explicit environment additions after clearing inherited variables.
    /// Callers must select only the variables their command requires.
    pub env: BTreeMap<String, String>,

    /// Own a separate process group and cancel its descendants on completion.
    /// Supported on Linux and macOS, where WNOWAIT pins the leader's identity.
    pub isolate_process_group: bool,
}

impl ToolSpec {
    /// Create a new tool specification.
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            command: command.into(),
            args,
            stdin: None,
            working_dir: None,
            timeout: None,
            max_output: None,
            env: BTreeMap::new(),
            isolate_process_group: false,
        }
    }

    /// Set stdin data.
    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = Some(stdin);
        self
    }

    /// Set working directory.
    pub fn with_working_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
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

    /// Add one literal environment value without inheriting the parent environment.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Isolate a trusted worker and its subprocesses for deadline cancellation.
    pub fn with_process_group(mut self) -> Self {
        self.isolate_process_group = true;
        self
    }
}

/// Tool runner with shared budget tracking.
#[derive(Debug)]
pub struct ToolRunner {
    config: ToolConfig,
    /// Cumulative time used in milliseconds.
    used_ms: Arc<AtomicU64>,
    budget_refusals: AtomicU64,
}

impl Drop for ToolRunner {
    fn drop(&mut self) {
        self.report_budget_refusals();
    }
}

type StdoutHandler<'a> = &'a mut dyn FnMut(&[u8]) -> std::io::Result<()>;

/// Retain ownership until collection finishes, including every error path.
/// A timeout must not turn a D-state child into a blocking `wait()` in the caller.
struct ToolChildGuard(Option<Child>, bool);

impl Drop for ToolChildGuard {
    fn drop(&mut self) {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = self.1;
        if let Some(child) = self.0.take() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if self.1 {
                terminate_owned_group(&child);
            }
            terminate_owned_child(child);
        }
    }
}

/// Observe exit without reaping: the leader's PID must remain pinned until its
/// process group has been cancelled, even if descendants retain output pipes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn peek_child_exit(child: &Child) -> std::io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;

    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let status = unsafe { info.si_status() };
    let raw = match info.si_code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_DUMPED => status | 0x80,
        _ => status,
    };
    Ok(Some(std::process::ExitStatus::from_raw(raw)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_owned_group(child: &Child) {
    let pid = child.id();
    // WNOWAIT establishes parenthood without releasing the numeric identity.
    // Never signal a group after an ECHILD result or a failed setpgid invariant.
    if pid <= 1 || peek_child_exit(child).is_err() {
        warn!(pid, "cannot establish worker group ownership for cleanup");
        return;
    }
    let observed_group = unsafe { libc::getpgid(pid as libc::pid_t) };
    if observed_group != pid as libc::pid_t {
        // Darwin getpgid uses proc_find, which excludes exited processes, while
        // waitid(WNOWAIT) retains the owned zombie until we reap it. Recheck
        // that ownership after ESRCH: its reserved PID still prevents an
        // unrelated process from creating a replacement group with this ID.
        // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exit.c
        // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c
        #[cfg(target_os = "macos")]
        let owned_exited_leader = observed_group == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            && matches!(peek_child_exit(child), Ok(Some(_)));
        #[cfg(not(target_os = "macos"))]
        let owned_exited_leader = false;
        if !owned_exited_leader {
            warn!(pid, "worker is no longer its owned process group leader");
            return;
        }
    }
    if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            warn!(pid, %error, "cannot terminate worker process group");
        }
    }
}

/// Cancel only an unreaped child whose ownership can still be established.
/// Reaping can wait for uninterruptible kernel I/O, so it runs off the collection
/// path. Successful commands do not create a reaper thread.
pub fn terminate_owned_child(mut child: Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(error) => {
            // ECHILD no longer proves that the numeric PID belongs to us.
            warn!(pid = child.id(), %error, "cannot establish tool ownership for cleanup");
            return;
        }
    }
    let pid = child.id();
    // The unreaped child pins its PID, even if it exits before this call.
    if let Err(error) = child.kill() {
        warn!(pid, %error, "cannot terminate failed tool");
    }
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if let Err(error) = thread::Builder::new()
        .name("pt-tool-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        })
    {
        warn!(pid, %error, "cannot start tool reaper; cleanup remains unverified");
    }
}

/// Supervise a trusted worker with its original arguments, environment and stdio.
/// Unlike captured probe output, foreground planner output is streamed directly
/// to the operator. The same ownership guard cancels the group before reaping.
pub fn run_owned_worker(
    command: &mut Command,
    timeout: Duration,
    should_cancel: impl Fn() -> bool,
) -> std::io::Result<std::process::ExitStatus> {
    let started = Instant::now();
    let check_deadline = || {
        if should_cancel() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "worker cancelled",
            ))
        } else if started.elapsed() >= timeout {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("worker timed out after {timeout:?}"),
            ))
        } else {
            Ok(())
        }
    };
    check_deadline()?;
    configure_owned_worker(command, true)?;
    let mut guard = ToolChildGuard(Some(command.spawn()?), true);
    let child = guard.0.as_mut().expect("owned worker");
    loop {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let result = peek_child_exit(child);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = child.try_wait();
        match result {
            Ok(Some(status)) => return Ok(status),
            Err(error) if error.kind() != std::io::ErrorKind::Interrupted => return Err(error),
            _ => {}
        }
        check_deadline()?;
        thread::sleep(Duration::from_millis(20).min(timeout.saturating_sub(started.elapsed())));
    }
}

impl ToolRunner {
    /// Create a new tool runner with the given configuration.
    pub fn new(config: ToolConfig) -> Self {
        Self {
            config,
            used_ms: Arc::new(AtomicU64::new(0)),
            budget_refusals: AtomicU64::new(0),
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
        self.report_budget_refusals();
        self.used_ms.store(0, Ordering::SeqCst);
    }

    fn report_budget_refusals(&self) {
        let refused = self.budget_refusals.swap(0, Ordering::Relaxed);
        if refused != 0 {
            warn!(
                refused_probes = refused,
                used_ms = self.used_budget_ms(),
                budget_ms = self.config.budget_ms,
                "probe budget exhausted"
            );
        }
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
            stdin: None,
            working_dir: None,
            env: BTreeMap::new(),
            isolate_process_group: false,
        };
        self.run(&spec)
    }

    /// Run a tool from a specification.
    #[instrument(skip(self, spec), fields(cmd = %spec.command))]
    pub fn run(&self, spec: &ToolSpec) -> Result<ToolOutput, ToolError> {
        self.run_with_stdout_handler(spec, None)
    }

    /// Consume stdout while the original deadline and output cap are active.
    /// A handler error cancels the owned tool just like a pipe error.
    pub(super) fn run_with_stdout_handler(
        &self,
        spec: &ToolSpec,
        stdout_handler: Option<StdoutHandler<'_>>,
    ) -> Result<ToolOutput, ToolError> {
        let start = Instant::now();
        // Validate command
        self.validate_command(&spec.command)?;

        let requested_timeout = spec.timeout.unwrap_or(self.config.default_timeout);
        let max_output = spec.max_output.unwrap_or(self.config.max_output_bytes);

        // Reserve budget to prevent parallel overcommitment
        let mut allocated_ms;
        let mut current = self.used_ms.load(Ordering::SeqCst);

        loop {
            if current >= self.config.budget_ms {
                self.budget_refusals.fetch_add(1, Ordering::Relaxed);
                return Err(ToolError::BudgetExhausted {
                    used_ms: current,
                    budget_ms: self.config.budget_ms,
                });
            }

            let remaining = self.config.budget_ms - current;
            let requested_ms = requested_timeout.as_millis() as u64;
            allocated_ms = std::cmp::min(requested_ms, remaining);

            match self.used_ms.compare_exchange_weak(
                current,
                current + allocated_ms,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(updated) => current = updated,
            }
        }

        let timeout = Duration::from_millis(allocated_ms);

        debug!(
            command = %spec.command,
            // Arguments may contain private command text or credentials. Human
            // logging does not run the JSONL field redactor.
            argument_count = spec.args.len(),
            timeout_ms = timeout.as_millis(),
            max_output,
            "running tool"
        );

        // Build command
        let mut command = match self.build_command(spec) {
            Ok(mut cmd) => {
                if let Some(ref dir) = spec.working_dir {
                    cmd.current_dir(dir);
                }
                if spec.stdin.is_some() {
                    cmd.stdin(Stdio::piped());
                } else {
                    cmd.stdin(Stdio::null());
                }
                cmd
            }
            Err(e) => {
                // Refund budget if build fails
                self.used_ms.fetch_sub(allocated_ms, Ordering::SeqCst);
                return Err(e);
            }
        };

        if start.elapsed() >= timeout {
            // Preparation consumed the reservation even though no tool started.
            // Refunding here makes repeated pre-spawn timeouts free forever.
            let charged_ms = charged_budget_ms(start.elapsed());
            self.used_ms
                .fetch_add(charged_ms.saturating_sub(allocated_ms), Ordering::SeqCst);
            return Err(ToolError::Timeout(timeout));
        }

        // Spawn process
        let child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                // Refund budget if spawn fails
                self.used_ms.fetch_sub(allocated_ms, Ordering::SeqCst);
                error!(command = %spec.command, error = %e, "failed to spawn");
                return Err(ToolError::SpawnFailed(e.to_string()));
            }
        };

        let mut child = ToolChildGuard(Some(child), spec.isolate_process_group);
        // Stdin, both output pipes, and child exit share the original deadline.
        // Never leave a detached writer blocked on a child that stopped reading.
        let result = self.execute_with_timeout(
            child.0.as_mut().expect("owned tool child"),
            start,
            timeout,
            max_output,
            spec.stdin.as_deref(),
            spec.isolate_process_group,
            stdout_handler,
        );
        // Cancel/reap before charging elapsed time, without waiting for a child
        // stuck in kernel I/O. This also runs after setup or pipe-read failures.
        drop(child);

        let duration = start.elapsed();
        // Charge whole milliseconds, rounded up, and at least 1 ms per run. Truncating
        // made every sub-millisecond run free, so a budget never ran out for fast
        // tools (and a 1 ms budget survived an `echo` on a fast host: GH #21).
        let charged_ms = charged_budget_ms(duration);

        // Adjust budget: we reserved allocated_ms and charge charged_ms, so move
        // used_ms by the difference (refund or extra charge).
        if charged_ms < allocated_ms {
            self.used_ms
                .fetch_sub(allocated_ms - charged_ms, Ordering::SeqCst);
        } else {
            self.used_ms
                .fetch_add(charged_ms - allocated_ms, Ordering::SeqCst);
        }

        info!(
            command = %spec.command,
            duration_ms = duration.as_millis() as u64,
            charged_ms,
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
                        .map(|h| {
                            h.join().unwrap_or_else(|_| {
                                error!("tool execution thread panicked");
                                Err(ToolError::SpawnFailed("thread panicked".to_string()))
                            })
                        })
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
    fn build_command(&self, spec: &ToolSpec) -> Result<Command, ToolError> {
        let cmd = &spec.command;
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

        command.args(&spec.args);

        // Clear environment variables that could affect behavior
        command.env_clear();

        // Set minimal safe environment
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        command.env("LC_ALL", "C");
        command.env("LANG", "C");
        command.envs(&spec.env);

        configure_owned_worker(&mut command, spec.isolate_process_group)?;
        Ok(command)
    }
}

fn configure_owned_worker(
    command: &mut Command,
    isolate_process_group: bool,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        // A scanner can itself run under a deadline in another process.
        // Killing that scanner also removes its timeout/reaper threads, so
        // its owned helpers need kernel-enforced cancellation as well.
        // This covers this direct child across ordinary execs, including
        // nice/ionice wrappers. Linux clears the setting in forked children
        // and on credential-changing execs; it is not a process-tree kill.
        // SAFETY: getpid only reads the current process identity.
        let parent_pid = unsafe { libc::getpid() };
        // SAFETY: after fork, use only allocation-free libc operations and
        // raw OS errors. Checking getppid after prctl closes the race where
        // the parent died before the death signal was installed.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
    }

    if isolate_process_group {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "owned worker process groups require Linux or macOS WNOWAIT",
        ));
    }

    Ok(())
}

impl ToolRunner {
    /// Read/write each nonblocking pipe once per iteration. EOF and process exit
    /// are separate conditions: descendants can retain output pipes after the
    /// tool exits, and a tool can close its pipes before becoming stuck.
    #[cfg(unix)]
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn execute_with_timeout(
        &self,
        child: &mut Child,
        started: Instant,
        timeout: Duration,
        max_output: usize,
        input: Option<&[u8]>,
        isolate_process_group: bool,
        mut stdout_handler: Option<StdoutHandler<'_>>,
    ) -> Result<(Vec<u8>, Vec<u8>, Option<i32>, bool, bool), ToolError> {
        use std::os::fd::AsRawFd;

        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let mut stdin = child.stdin.take();
        if let Some(pipe) = &stdout {
            set_nonblocking(pipe.as_raw_fd())?;
        }
        if let Some(pipe) = &stderr {
            set_nonblocking(pipe.as_raw_fd())?;
        }
        if let Some(pipe) = &stdin {
            set_nonblocking(pipe.as_raw_fd())?;
        }
        let input = input.unwrap_or_default();
        let mut written = 0;
        let mut stdout_buf = Vec::with_capacity(max_output.min(65536));
        let mut stderr_buf = Vec::with_capacity(max_output.min(65536));
        let mut truncated = false;
        let mut status = None;
        let mut chunk = [0_u8; 8192];

        loop {
            if started.elapsed() >= timeout {
                return Ok((
                    stdout_buf,
                    stderr_buf,
                    status.and_then(|status: std::process::ExitStatus| status.code()),
                    truncated,
                    true,
                ));
            }
            let mut progressed = false;
            if written == input.len() {
                stdin = None;
            }
            if let Some(pipe) = stdin.as_mut() {
                let end = (written + chunk.len()).min(input.len());
                match pipe.write(&input[written..end]) {
                    Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
                    Ok(count) => {
                        written += count;
                        progressed = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => stdin = None,
                    Err(error) if retry_pipe_io(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let stdout_start = stdout_buf.len();
            progressed |= read_tool_pipe(
                &mut stdout,
                &mut stdout_buf,
                &mut chunk,
                max_output,
                &mut truncated,
            )?;
            if stdout_buf.len() > stdout_start {
                if let Some(handler) = stdout_handler.as_mut() {
                    handler(&stdout_buf[stdout_start..])?;
                }
            }
            progressed |= read_tool_pipe(
                &mut stderr,
                &mut stderr_buf,
                &mut chunk,
                max_output,
                &mut truncated,
            )?;
            if status.is_none() {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    status = if isolate_process_group {
                        peek_child_exit(child)?
                    } else {
                        child.try_wait()?
                    };
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    let _ = isolate_process_group;
                    status = child.try_wait()?;
                }
            }
            if truncated || (status.is_some() && stdout.is_none() && stderr.is_none()) {
                let exit_code = status.and_then(|status| status.code());
                trace!(?exit_code, truncated, "tool collection complete");
                return Ok((stdout_buf, stderr_buf, exit_code, truncated, false));
            }
            if !progressed {
                thread::sleep(
                    Duration::from_millis(5).min(timeout.saturating_sub(started.elapsed())),
                );
            }
        }
    }

    #[cfg(not(unix))]
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn execute_with_timeout(
        &self,
        _child: &mut Child,
        _started: Instant,
        _timeout: Duration,
        _max_output: usize,
        _input: Option<&[u8]>,
        _isolate_process_group: bool,
        _stdout_handler: Option<StdoutHandler<'_>>,
    ) -> Result<(Vec<u8>, Vec<u8>, Option<i32>, bool, bool), ToolError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bounded tool collection requires Unix pipes",
        )
        .into())
    }
}

/// Budget charged for a run that took `duration`: whole milliseconds, rounded up,
/// never less than 1 ms (a run is never free).
fn charged_budget_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros().div_ceil(1000))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Set non-blocking mode on a file descriptor.
#[cfg(unix)]
fn set_nonblocking(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn retry_pipe_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

#[cfg(unix)]
fn read_tool_pipe<R: Read>(
    pipe: &mut Option<R>,
    output: &mut Vec<u8>,
    chunk: &mut [u8],
    max_output: usize,
    truncated: &mut bool,
) -> std::io::Result<bool> {
    let Some(stream) = pipe.as_mut() else {
        return Ok(false);
    };
    match stream.read(chunk) {
        Ok(0) => {
            *pipe = None;
            Ok(true)
        }
        Ok(count) => {
            let retained = count.min(max_output.saturating_sub(output.len()));
            output.extend_from_slice(&chunk[..retained]);
            *truncated |= retained != count;
            Ok(true)
        }
        Err(error) if retry_pipe_io(&error) => Ok(false),
        Err(error) => Err(error),
    }
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
        // A standalone call's budget is its own timeout. (The default 5 s budget
        // silently capped every call: a 300 s ssh was SIGTERMed after 5 s.)
        config.budget_ms = config
            .budget_ms
            .max(u64::try_from(t.as_millis()).unwrap_or(u64::MAX));
    }
    if let Some(m) = max_output {
        config.max_output_bytes = m;
    }
    let runner = ToolRunner::new(config);
    runner.run_tool(cmd, args, None)
}

/// Run `ssh` with `ToolRunner` bounds while retaining only standard OpenSSH
/// client environment variables (HOME, SSH_AUTH_SOCK, etc.) after `env_clear`.
pub fn run_ssh_tool(
    args: &[&str],
    timeout: Option<Duration>,
    max_output: Option<usize>,
) -> Result<ToolOutput, ToolError> {
    let mut config = ToolConfig::default();
    if let Some(t) = timeout {
        config.default_timeout = t;
        config.budget_ms = config
            .budget_ms
            .max(u64::try_from(t.as_millis()).unwrap_or(u64::MAX));
    }
    if let Some(m) = max_output {
        config.max_output_bytes = m;
    }
    let mut spec = ToolSpec::new("ssh", args.iter().map(|s| (*s).to_string()).collect());
    for key in [
        "HOME",
        "USER",
        "LOGNAME",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "KRB5CCNAME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            spec = spec.with_env(key, value);
        }
    }
    let runner = ToolRunner::new(config);
    runner.run(&spec)
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
    fn explicit_environment_preserves_literal_values_without_broad_inheritance() {
        let runner = test_runner();
        let default_spec = ToolSpec::new("systemctl", vec!["--user".into()]);
        let default_command = runner.build_command(&default_spec).unwrap();
        assert!(default_command
            .get_envs()
            .all(|(key, _)| { matches!(key.to_str(), Some("PATH" | "LC_ALL" | "LANG")) }));

        let spec = default_spec
            .with_env("XDG_RUNTIME_DIR", "/run/user/1000")
            .with_env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/bus $literal%name",
            )
            .with_env("HOME", "/home/user with spaces");
        let command = runner.build_command(&spec).unwrap();
        for (key, value) in &spec.env {
            let actual = command
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(key))
                .and_then(|(_, value)| value);
            assert_eq!(actual, Some(std::ffi::OsStr::new(value)));
        }
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [std::ffi::OsStr::new("--user")]
        );
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
        // Process should have been killed (allow extra slack for busy CI)
        assert!(output.duration < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn pre_spawn_timeout_consumes_budget_without_starting_the_command() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("started");
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .budget_ms(1)
            .build();
        let spec = ToolSpec::new(
            "sh",
            vec![
                "-c".into(),
                "printf started > \"$1\"".into(),
                "deadline-fixture".into(),
                marker.to_string_lossy().into_owned(),
            ],
        )
        .with_timeout(Duration::ZERO);

        assert!(matches!(runner.run(&spec), Err(ToolError::Timeout(_))));
        assert!(!marker.exists(), "an expired deadline must prevent launch");
        assert!(runner.used_budget_ms() >= 1);
        assert_eq!(runner.remaining_budget_ms(), 0);
        assert!(
            matches!(runner.run(&spec), Err(ToolError::BudgetExhausted { .. })),
            "repeated preparation timeouts must not bypass cumulative budgeting"
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn deadline_covers_closed_pipes_and_blocked_stdin() {
        let runner = test_runner();
        for spec in [
            ToolSpec::new(
                "sh",
                vec!["-c".into(), "exec 1>&- 2>&-; exec sleep 30".into()],
            ),
            ToolSpec::new("sleep", vec!["30".into()]).with_stdin(vec![b'x'; 1024 * 1024]),
        ] {
            let started = Instant::now();
            let output = runner
                .run(&spec.with_timeout(Duration::from_millis(100)))
                .expect("bounded collection");
            assert!(output.timed_out, "{output:?}");
            assert!(!output.success(), "incomplete capture is not success");
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    /// Subprocess fixture: keep a real nested ToolRunner alive until its owner
    /// is terminated by the outer runner's deadline.
    #[cfg(target_os = "linux")]
    #[test]
    fn nested_runner_parent_death_worker() {
        let Some(marker) = std::env::var_os("PT_TOOL_PARENT_DEATH_MARKER") else {
            return;
        };
        let marker = marker.to_str().expect("fixture marker is UTF-8");
        let output = test_runner()
            .run_tool(
                "sh",
                &[
                    "-c",
                    "printf '%s\\n' \"$$\" > \"$1\"; exec sleep 30",
                    "pt-tool-parent-death",
                    marker,
                ],
                Some(Duration::from_secs(30)),
            )
            .expect("nested owned helper starts");
        panic!("outer deadline must terminate this worker first: {output:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminating_a_runner_also_terminates_its_owned_helper() {
        let root = tempfile::tempdir()
            .expect("parent-death fixture directory")
            .keep();
        let marker = root.join("helper.pid");
        let executable = std::env::current_exe().expect("current test executable");
        let worker_test = format!(
            "{}::nested_runner_parent_death_worker",
            module_path!().split_once("::").unwrap().1
        );
        let spec = ToolSpec::new(
            executable.to_str().expect("test executable is UTF-8"),
            vec!["--exact".into(), worker_test, "--nocapture".into()],
        )
        .with_env(
            "PT_TOOL_PARENT_DEATH_MARKER",
            marker.to_str().expect("fixture marker is UTF-8"),
        );
        let runner = test_runner();
        let mut worker = ToolChildGuard(
            Some(
                runner
                    .build_command(&spec)
                    .expect("build owned worker")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("start owned worker"),
            ),
            false,
        );

        let started = Instant::now();
        let helper_pid: u32 = loop {
            if let Ok(contents) = std::fs::read_to_string(&marker) {
                if let Ok(pid) = contents.trim().parse() {
                    break pid;
                }
            }
            assert!(
                worker.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "nested worker must stay alive until the deadline"
            );
            assert!(started.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(5));
        };
        let helper_state = || {
            std::fs::read_to_string(format!("/proc/{helper_pid}/stat"))
                .ok()
                .and_then(|contents| super::super::proc_parsers::parse_proc_stat_content(&contents))
        };
        let before = helper_state().expect("nested helper is alive");
        assert_eq!(before.ppid, worker.0.as_ref().unwrap().id());
        assert_ne!(before.state, 'Z');

        // Start the short outer deadline after readiness; slow test-executable
        // startup must not turn this into a spurious helper-startup failure.
        let (_, _, _, _, timed_out) = runner
            .execute_with_timeout(
                worker.0.as_mut().unwrap(),
                Instant::now(),
                Duration::from_millis(100),
                4096,
                None,
                false,
                None,
            )
            .expect("bounded outer worker");
        assert!(timed_out);
        drop(worker);

        let stopped = Instant::now();
        loop {
            match helper_state() {
                None => break,
                Some(after) if after.starttime != before.starttime || after.state == 'Z' => break,
                Some(_) => {}
            }
            assert!(
                stopped.elapsed() < Duration::from_secs(2),
                "nested helper must stop when its timeout owner dies"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn large_stdin_and_stdout_share_deadline_without_deadlock() {
        let data = vec![b'x'; 512 * 1024];
        let output = test_runner()
            .run(
                &ToolSpec::new("cat", vec![])
                    .with_stdin(data.clone())
                    .with_timeout(Duration::from_secs(10)),
            )
            .expect("cat run");
        assert!(output.success(), "{output:?}");
        assert_eq!(output.stdout, data);
    }

    #[cfg(unix)]
    #[test]
    fn exited_tool_with_inherited_pipes_is_incomplete_and_leaves_holder_alive() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().expect("output pair");
        let holder_writer = writer.try_clone().expect("holder output");
        let mut holder = ToolChildGuard(
            Some(
                Command::new("sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(OwnedFd::from(holder_writer)))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("owned output holder"),
            ),
            false,
        );
        let mut tool = ToolChildGuard(
            Some(
                Command::new("sh")
                    .args(["-c", "exit 0"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(OwnedFd::from(writer)))
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("owned exiting tool"),
            ),
            false,
        );
        let child = tool.0.as_mut().unwrap();
        child.stdout = Some(std::process::ChildStdout::from(OwnedFd::from(reader)));
        let fixture_start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("tool status") {
                assert!(status.success());
                break;
            }
            assert!(fixture_start.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(5));
        }
        let started = Instant::now();
        let (_, _, code, truncated, timed_out) = test_runner()
            .execute_with_timeout(
                child,
                started,
                Duration::from_millis(100),
                1024,
                None,
                false,
                None,
            )
            .expect("bounded inherited output");
        assert_eq!(code, Some(0));
        assert!(timed_out);
        assert!(!truncated);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(tool);
        assert!(holder.0.as_mut().unwrap().try_wait().unwrap().is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn owned_worker_group_cancels_descendants_after_its_leader_exits() {
        let mut unrelated = ToolChildGuard(
            Some(Command::new("sleep").arg("30").spawn().unwrap()),
            false,
        );
        // Both a descendant retaining the pipes and one closing them must die.
        // A successful leader exit must not release its PID before group cleanup.
        for (script, expect_timeout) in [
            ("sleep 30 & printf '%s\\n' \"$!\"; exit 0", true),
            (
                "sleep 30 >/dev/null 2>&1 & printf '%s\\n' \"$!\"; exit 0",
                false,
            ),
        ] {
            let output = test_runner()
                .run(
                    &ToolSpec::new("sh", vec!["-c".into(), script.into()])
                        .with_process_group()
                        .with_timeout(Duration::from_millis(750)),
                )
                .unwrap();
            assert_eq!(output.timed_out, expect_timeout, "{output:?}");
            assert_eq!(
                output.exit_code,
                Some(0),
                "leader exit was observed without reaping"
            );
            let descendant: u32 = output.stdout_str().trim().parse().unwrap();
            let cleanup_start = Instant::now();
            loop {
                #[cfg(target_os = "linux")]
                let state = std::fs::read_to_string(format!("/proc/{descendant}/stat"))
                    .ok()
                    .and_then(|stat| {
                        stat.rsplit_once(") ")
                            .and_then(|(_, rest)| rest.chars().next())
                    });
                #[cfg(target_os = "macos")]
                let state =
                    crate::collect::macos::read_session_stat(descendant).map(|stat| stat.state);
                if matches!(state, None | Some('Z') | Some('X')) {
                    break;
                }
                assert!(
                    cleanup_start.elapsed() < Duration::from_secs(3),
                    "worker descendant {descendant} survived cancellation in state {state:?}"
                );
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                unrelated.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "group cancellation must leave the caller's other children alive"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn foreground_worker_preserves_stdio_and_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let stdout = dir.path().join("stdout");
        let stderr = dir.path().join("stderr");
        for expected in [0, 1, 21] {
            let mut command = Command::new("sh");
            command
                .args(["-c", "echo out; echo err >&2; exit \"$1\"", "worker"])
                .arg(expected.to_string())
                .stdout(std::fs::File::create(&stdout).unwrap())
                .stderr(std::fs::File::create(&stderr).unwrap());
            let status = run_owned_worker(&mut command, Duration::from_secs(5), || false).unwrap();
            assert_eq!(status.code(), Some(expected));
            assert_eq!(std::fs::read(&stdout).unwrap(), b"out\n");
            assert_eq!(std::fs::read(&stderr).unwrap(), b"err\n");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn foreground_worker_deadline_and_cancellation_stop_owned_descendants() {
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("descendant");
            let mut command = Command::new("sh");
            command
                .args(["-c", "sleep 60 & echo $! > \"$1\"; wait", "worker"])
                .arg(&marker);
            let timeout = Duration::from_secs(if cancel { 30 } else { 1 });
            let started = Instant::now();
            let error = run_owned_worker(&mut command, timeout, || cancel && marker.exists())
                .expect_err("worker must be interrupted");
            assert_eq!(
                error.kind(),
                if cancel {
                    std::io::ErrorKind::Interrupted
                } else {
                    std::io::ErrorKind::TimedOut
                }
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            let pid = std::fs::read_to_string(marker)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            loop {
                #[cfg(target_os = "linux")]
                let stat = crate::collect::proc_parsers::read_required_proc_stat(pid).ok();
                #[cfg(target_os = "macos")]
                let stat = crate::collect::macos::read_session_stat(pid);
                if stat.is_none_or(|stat| matches!(stat.state, 'Z' | 'X' | 'x')) {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "living worker descendant {pid}"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn streaming_stdout_handler_cancels_a_worker_on_protocol_failure() {
        let mut observed = Vec::new();
        let mut handler = |bytes: &[u8]| {
            observed.extend_from_slice(bytes);
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid worker protocol",
            ))
        };
        let started = Instant::now();
        let error = test_runner()
            .run_with_stdout_handler(
                &ToolSpec::new(
                    "sh",
                    vec!["-c".into(), "printf 'bad-message\\n'; exec sleep 30".into()],
                )
                .with_process_group()
                .with_timeout(Duration::from_secs(10)),
                Some(&mut handler),
            )
            .unwrap_err();
        assert!(
            matches!(error, ToolError::Io(ref error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
        assert_eq!(observed, b"bad-message\n");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_output_is_an_error_not_eof() {
        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        let error = read_tool_pipe(
            &mut Some(FailedReader),
            &mut Vec::new(),
            &mut [0; 8],
            8,
            &mut false,
        )
        .expect_err("read failures cannot establish complete output");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn complete_exit_status_does_not_hide_capture_failure() {
        let mut output = ToolOutput {
            command: "fixture".into(),
            args: vec![],
            stdout: vec![],
            stderr: vec![],
            exit_code: Some(0),
            truncated: false,
            duration: Duration::ZERO,
            timed_out: false,
        };
        assert!(output.success());
        output.timed_out = true;
        assert!(!output.success());
        output.timed_out = false;
        output.truncated = true;
        assert!(!output.success());
    }

    /// Regression: the free `run_tool` capped every call at the default 5 s budget,
    /// whatever timeout the caller asked for (fleet ssh plans died with 255).
    #[test]
    fn run_tool_honors_timeouts_longer_than_default_budget() {
        let output =
            run_tool("sleep", &["6"], Some(Duration::from_secs(20)), None).expect("sleep runs");
        assert!(!output.timed_out, "{output:?}");
        assert_eq!(output.exit_code, Some(0), "{output:?}");
        assert!(output.duration >= Duration::from_secs(6));
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
    fn charged_budget_rounds_up_to_whole_milliseconds() {
        assert_eq!(charged_budget_ms(Duration::ZERO), 1);
        assert_eq!(charged_budget_ms(Duration::from_micros(1)), 1);
        assert_eq!(charged_budget_ms(Duration::from_micros(1000)), 1);
        assert_eq!(charged_budget_ms(Duration::from_micros(1001)), 2);
        assert_eq!(charged_budget_ms(Duration::from_millis(250)), 250);
    }

    #[test]
    fn test_budget_exhaustion() {
        let runner = ToolRunnerBuilder::new()
            .use_nice(false)
            .budget_ms(1) // Very small budget
            .build();

        // Every run is charged at least 1 ms, so the first run uses up the budget
        // however fast the host is.
        let _ = runner.run_tool("echo", &["test"], None);
        assert!(runner.budget_exhausted());

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
        // Use short timeout to fit within default 5000ms budget (2 * 1000ms < 5000ms)
        let specs = vec![
            ToolSpec::new("echo", vec!["a".to_string()]).with_timeout(Duration::from_millis(1000)),
            ToolSpec::new("echo", vec!["b".to_string()]).with_timeout(Duration::from_millis(1000)),
        ];
        let results = run_tools_parallel(&specs, Some(2));
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }
}
