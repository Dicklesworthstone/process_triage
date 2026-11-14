//! Signal-based action execution.
//!
//! Implements the actual signal delivery for pause/resume/kill actions with:
//! - TOCTOU safety via identity revalidation
//! - Staged escalation (SIGTERM → SIGKILL)
//! - Process group awareness
//! - Outcome verification

use super::executor::{ActionError, ActionRunner};
#[cfg(target_os = "linux")]
use super::reversal::{PreparedReversal, ReversalJournal, ReversalStatus};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::Serialize;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{path::PathBuf, sync::Arc};

/// One observation of the recorded incarnation. Missing or replaced processes
/// can prove exit, but never successful pause/resume of the current occupant.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalObservation {
    Gone,
    Replaced,
    Present(char),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum SignalExpectation {
    Exited,
    Stopped,
    Resumed,
    Reaped,
}

#[cfg(unix)]
impl SignalExpectation {
    fn satisfied(self, observation: SignalObservation) -> Result<bool, ActionError> {
        match observation {
            SignalObservation::Gone => match self {
                Self::Exited | Self::Reaped => Ok(true),
                Self::Stopped | Self::Resumed => Err(ActionError::ProcessNotFound),
            },
            SignalObservation::Replaced => match self {
                Self::Exited | Self::Reaped => Ok(true),
                Self::Stopped | Self::Resumed => Err(ActionError::IdentityMismatch),
            },
            SignalObservation::Present(state) => {
                let dead = matches!(state, 'Z' | 'X' | 'x');
                if !matches!(
                    state,
                    'R' | 'S' | 'D' | 'Z' | 'T' | 't' | 'X' | 'x' | 'K' | 'W' | 'P' | 'I'
                ) {
                    return Err(ActionError::Failed(
                        "cannot verify an unknown process state".to_string(),
                    ));
                }
                match self {
                    Self::Exited => Ok(dead),
                    // A zombie is still present until it disappears or a new
                    // birth takes its PID. An unreadable or live process is not
                    // evidence that the recorded zombie was reaped.
                    Self::Reaped if dead => Ok(false),
                    Self::Reaped => Err(ActionError::Failed(
                        "recorded zombie is still present with a live state".to_string(),
                    )),
                    Self::Stopped | Self::Resumed if dead => Err(ActionError::ProcessNotFound),
                    Self::Stopped | Self::Resumed if state == 't' => Err(ActionError::Failed(
                        "tracing stop belongs to the debugger, not a verified job-control transition"
                            .to_string(),
                    )),
                    Self::Stopped => Ok(state == 'T'),
                    Self::Resumed => Ok(state != 'T'),
                }
            }
        }
    }
}

/// Read failures remain unknown unless the kernel independently confirms that
/// this positive PID no longer exists. In particular, EPERM is not exit.
#[cfg(unix)]
fn signal_observation_unavailable(
    pid: u32,
    reason: impl std::fmt::Display,
) -> Result<SignalObservation, ActionError> {
    let target = signal_syscall_target(pid, false)?;
    // SAFETY: signal zero only checks this validated positive PID's existence.
    if unsafe { libc::kill(target, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return Ok(SignalObservation::Gone);
    }
    Err(ActionError::Failed(format!(
        "process {pid} observation unavailable: {reason}"
    )))
}

/// Observe birth, owner and state together, with identity reads bracketing the
/// other fields. Group/session facts in the plan remain binding when supplied.
#[cfg(unix)]
fn observe_signal_target(
    target: &pt_common::ProcessIdentity,
) -> Result<SignalObservation, ActionError> {
    signal_syscall_target(target.pid.0, false)?;
    ensure_action_pid_namespace()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (expected_boot, expected_start, expected_pid) = parse_start_id(&target.start_id.0);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let expected_start = expected_start
        .filter(|_| target.can_safely_revalidate())
        .filter(|_| expected_pid.is_none_or(|pid| pid == target.pid.0))
        .filter(|_| {
            target.quality != pt_common::IdentityQuality::Full
                || (expected_pid.is_some()
                    && (!cfg!(target_os = "linux") || expected_boot.is_some()))
        })
        .ok_or(ActionError::IdentityMismatch)?;

    #[cfg(target_os = "linux")]
    {
        use crate::collect::proc_parsers::read_required_proc_stat;

        let identity = LiveIdentityProvider::new();
        if identity.boot_id == "unknown" || identity.boot_id.is_empty() {
            return Err(ActionError::Failed(
                "cannot verify signal outcome without the current boot identity".to_string(),
            ));
        }
        if expected_boot.is_some_and(|boot| boot != identity.boot_id) {
            return Err(ActionError::IdentityMismatch);
        }
        let before = match read_required_proc_stat(target.pid.0) {
            Ok(stat) => stat,
            Err(error) => return signal_observation_unavailable(target.pid.0, error),
        };
        if before.starttime != expected_start {
            return Ok(SignalObservation::Replaced);
        }
        let Some(uid) = identity.read_uid(target.pid.0) else {
            return signal_observation_unavailable(target.pid.0, "cannot read process owner");
        };
        let after = match read_required_proc_stat(target.pid.0) {
            Ok(stat) => stat,
            Err(error) => return signal_observation_unavailable(target.pid.0, error),
        };
        if after.starttime != expected_start {
            return Ok(SignalObservation::Replaced);
        }
        if uid != target.uid
            || target.pgid.is_some_and(|pgid| {
                u32::try_from(before.pgrp) != Ok(pgid) || u32::try_from(after.pgrp) != Ok(pgid)
            })
            || target.sid.is_some_and(|sid| {
                u32::try_from(before.session) != Ok(sid) || u32::try_from(after.session) != Ok(sid)
            })
        {
            return Err(ActionError::IdentityMismatch);
        }
        Ok(SignalObservation::Present(after.state))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = expected_boot;
        let Some(before) = crate::collect::macos::read_bsd_info(target.pid.0) else {
            return signal_observation_unavailable(target.pid.0, "cannot read native identity");
        };
        if before.start_us != expected_start {
            return Ok(SignalObservation::Replaced);
        }
        let Some(stat) = crate::collect::macos::read_session_stat(target.pid.0) else {
            return signal_observation_unavailable(target.pid.0, "cannot read native state");
        };
        let Some(after) = crate::collect::macos::read_bsd_info(target.pid.0) else {
            return signal_observation_unavailable(target.pid.0, "cannot recheck native identity");
        };
        if after.start_us != expected_start || stat.starttime != expected_start {
            return Ok(SignalObservation::Replaced);
        }
        if before.uid != target.uid
            || after.uid != target.uid
            || target
                .pgid
                .is_some_and(|pgid| u32::try_from(stat.pgrp) != Ok(pgid))
            || target
                .sid
                .is_some_and(|sid| u32::try_from(stat.session) != Ok(sid))
        {
            return Err(ActionError::IdentityMismatch);
        }
        Ok(SignalObservation::Present(stat.state))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = target;
        Err(ActionError::Failed(
            "identity-bound signal observations are unsupported on this platform".to_string(),
        ))
    }
}

/// Read a known state only for the complete recorded live incarnation. Undo
/// callers decide which observed states they may safely restore.
#[cfg(target_os = "linux")]
pub(crate) fn signal_state(target: &pt_common::ProcessIdentity) -> Result<char, ActionError> {
    match observe_signal_target(target)? {
        SignalObservation::Present(state) => Ok(state),
        SignalObservation::Gone => Err(ActionError::ProcessNotFound),
        SignalObservation::Replaced => Err(ActionError::IdentityMismatch),
    }
}

/// Undo may release only a verified job-control stop, through an fd pinned to
/// that process. A numeric-PID fallback cannot provide this restoration promise.
#[cfg(target_os = "linux")]
pub(crate) fn send_bound_signal(
    target: &pt_common::ProcessIdentity,
    signal: i32,
) -> Result<(), ActionError> {
    if signal != libc::SIGCONT || target.quality != pt_common::IdentityQuality::Full {
        return Err(ActionError::Failed(
            "pause restoration requires SIGCONT and the full original identity".to_string(),
        ));
    }
    ensure_action_pid_namespace()?;
    let pidfd = PidFd::open(target.pid.0)?.ok_or_else(|| {
        ActionError::Failed("pause restoration requires kernel pidfd support".to_string())
    })?;
    if signal_state(target)? != 'T' {
        return Err(ActionError::Failed(
            "pause restoration requires the original process to remain job-control stopped"
                .to_string(),
        ));
    }
    pidfd.send(signal)
}

#[cfg(unix)]
fn wait_for_signal_observation(
    timeout: Duration,
    poll_interval: Duration,
    expected: SignalExpectation,
    mut observe: impl FnMut() -> Result<SignalObservation, ActionError>,
) -> Result<(), ActionError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let observation = observe()?;
        if start.elapsed() >= timeout {
            return Err(ActionError::Timeout);
        }
        if expected.satisfied(observation)? {
            return Ok(());
        }
        thread::sleep(poll_interval.min(timeout.saturating_sub(start.elapsed())));
    }
    Err(ActionError::Timeout)
}

/// Procfs identities and numeric-PID syscalls must refer to the same namespace.
/// A container can inherit an ancestor namespace's procfs mount: in that case
/// even a matching start time in `/proc/PID` does not identify `kill(PID)` or
/// `pidfd_open(PID)` in the caller's namespace. Do not cache this check; a mount
/// namespace or its procfs mount can change while the process is running.
pub(super) fn ensure_action_pid_namespace() -> Result<(), ActionError> {
    #[cfg(target_os = "linux")]
    {
        let proc_self = std::fs::read_link("/proc/self").map_err(|error| {
            ActionError::Failed(format!(
                "cannot establish action PID namespace from /proc/self: {error}"
            ))
        })?;
        let status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
            ActionError::Failed(format!(
                "cannot establish action PID namespace from /proc/self/status: {error}"
            ))
        })?;
        validate_procfs_pid_namespace(std::process::id(), &proc_self, &status)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_procfs_pid_namespace(
    caller_pid: u32,
    proc_self: &std::path::Path,
    status: &str,
) -> Result<(), ActionError> {
    let observed = proc_self
        .to_str()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            ActionError::Failed(
                "cannot establish action PID namespace: invalid /proc/self link".into(),
            )
        })?;
    if observed != caller_pid {
        return Err(ActionError::Failed(format!(
            "refusing action: procfs PID namespace differs from the caller (/proc/self={observed}, caller={caller_pid})"
        )));
    }
    // Numeric PIDs can coincide across nested namespaces after PID wraparound.
    // NSpid starts in the procfs mount's namespace and lists each nested PID;
    // only a single observed PID proves the mount uses the caller's namespace.
    let mut namespace_lines = status
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:"));
    let mut pids = namespace_lines
        .next()
        .ok_or_else(|| {
            ActionError::Failed("cannot establish action PID namespace: NSpid is missing".into())
        })?
        .split_whitespace();
    if namespace_lines.next().is_some()
        || pids.next().and_then(|pid| pid.parse::<u32>().ok()) != Some(caller_pid)
        || pids.next().is_some()
    {
        return Err(ActionError::Failed(
            "refusing action: procfs PID namespace is ambiguous or differs from the caller (NSpid)"
                .into(),
        ));
    }
    Ok(())
}

/// Convert a resolved process/group ID without admitting kill(2)'s special
/// broadcast targets. PID 0 targets the caller's group, and negating PGID 1
/// produces -1 (all signalable processes), not a process-group-only operation.
/// PID 1 itself is protected infrastructure and is never an action target.
#[cfg(any(unix, test))]
fn signal_syscall_target(target_id: u32, use_group: bool) -> Result<i32, ActionError> {
    if target_id <= 1 {
        return Err(ActionError::Failed(format!(
            "refusing signal to protected {} {}",
            if use_group { "process group" } else { "PID" },
            target_id
        )));
    }
    let target = i32::try_from(target_id)
        .map_err(|_| ActionError::Failed(format!("PID {target_id} exceeds i32 range")))?;
    Ok(if use_group { -target } else { target })
}

/// A job-control stopped target cannot handle a pending SIGTERM until resumed.
/// Tracing stops belong to the debugger, and one process's state cannot justify
/// resuming every member of its process group. Linux distinguishes these stops
/// as `T` and `t`; other collectors do not yet provide that distinction.
#[cfg(any(unix, test))]
fn should_resume_after_sigterm(state: Option<char>, use_group: bool) -> bool {
    cfg!(target_os = "linux") && !use_group && state == Some('T')
}

/// Observed disposition of SIGTERM. Unavailable or inconsistent kernel evidence
/// stays unknown and never shortens the approved graceful-shutdown interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalDisposition {
    Unknown,
    Default,
    Caught,
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalEscalationReason {
    SigtermIgnored,
    GraceExpired,
}

/// Delivery evidence and monotonic timings from one attempted kill. These facts
/// describe the signal sequence, not proof that the target has exited; final
/// effect verification remains separate. Failed attempts retain their evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SignalExecutionOutcome {
    pub sigterm_disposition: SignalDisposition,
    pub sigterm_recheck: Option<SignalDisposition>,
    pub configured_grace_ms: u64,
    /// Elapsed after successful TERM delivery until execution returned, including
    /// any resume, disposition recheck and escalation overhead. Not an exit time.
    pub observed_grace_ms: Option<u64>,
    pub sigterm_delivered: bool,
    pub sigcont_delivered: bool,
    pub sigkill_delivered: bool,
    /// Why escalation was selected. A final identity/deadline check can still
    /// prevent delivery; sigkill_delivered records whether the syscall succeeded.
    pub escalation_reason: Option<SignalEscalationReason>,
    pub execution_elapsed_ms: u64,
}

#[cfg(target_os = "linux")]
fn sigterm_disposition_from_status(status: &str) -> SignalDisposition {
    let mut ignored = None;
    let mut caught = None;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let field = match name {
            "SigIgn" => &mut ignored,
            "SigCgt" => &mut caught,
            _ => continue,
        };
        let value = value.trim();
        if field.is_some()
            || value.is_empty()
            || value.len() > 16
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return SignalDisposition::Unknown;
        }
        *field = u64::from_str_radix(value, 16).ok();
    }
    let (Some(ignored), Some(caught)) = (ignored, caught) else {
        return SignalDisposition::Unknown;
    };
    let term_bit = 1_u64 << (libc::SIGTERM - 1);
    match (ignored & term_bit != 0, caught & term_bit != 0) {
        (true, false) => SignalDisposition::Ignored,
        (false, true) => SignalDisposition::Caught,
        (false, false) => SignalDisposition::Default,
        (true, true) => SignalDisposition::Unknown,
    }
}

/// A group leader's disposition says nothing about its other members. Requiring
/// two complete observations also preserves grace if a target changes handlers
/// or the second observation becomes unavailable after TERM.
fn may_skip_term_grace(
    use_group: bool,
    before: SignalDisposition,
    after: SignalDisposition,
) -> bool {
    cfg!(target_os = "linux")
        && !use_group
        && before == SignalDisposition::Ignored
        && after == SignalDisposition::Ignored
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A phase budget from the approved plan. Elapsed time is measured monotonically;
/// using a duration instead of adding to Instant also accepts large saved budgets
/// without overflowing the platform's clock representation.
struct SignalDeadline {
    started: Instant,
    budget: Duration,
}

impl SignalDeadline {
    fn new(timeout_ms: u64) -> Self {
        Self {
            started: Instant::now(),
            budget: Duration::from_millis(timeout_ms),
        }
    }

    fn remaining(&self) -> Result<Duration, ActionError> {
        self.budget
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ActionError::Timeout)
    }
}

/// Signal action runner configuration.
#[derive(Debug, Clone)]
pub struct SignalConfig {
    /// Grace period after SIGTERM before escalating to SIGKILL.
    pub term_grace_ms: u64,
    /// Polling interval when waiting for process to exit.
    pub poll_interval_ms: u64,
    /// Maximum time to wait for process state change after signal. A saved
    /// action's verify_ms may impose a shorter observation budget.
    pub verify_timeout_ms: u64,
    /// Whether to send signals to process groups (negative PID).
    pub use_process_groups: bool,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            term_grace_ms: crate::config::policy::DEFAULT_TERM_GRACE_MS,
            poll_interval_ms: 100,
            verify_timeout_ms: 10_000,
            use_process_groups: false,
        }
    }
}

/// Signal-based action runner.
#[derive(Debug)]
pub struct SignalActionRunner {
    config: SignalConfig,
    /// How the last signal was delivered: "pidfd", "kill" or "kill_group".
    last_path: std::sync::Mutex<Option<&'static str>>,
    /// A successful SIGTERM/SIGKILL delivery, even if later verification fails.
    kill_signal_delivered: std::sync::atomic::AtomicBool,
    last_outcome: std::sync::Mutex<Option<SignalExecutionOutcome>>,
    #[cfg(target_os = "linux")]
    reversal_journal: Option<Arc<ReversalJournal>>,
    #[cfg(target_os = "linux")]
    reversal_ownership_root: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    applied_pause: std::sync::Mutex<Option<AppliedPause>>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct AppliedPause {
    action_id: String,
    target: pt_common::ProcessIdentity,
    receipt: PreparedReversal,
}

impl SignalActionRunner {
    pub fn new(config: SignalConfig) -> Self {
        Self {
            config,
            last_path: std::sync::Mutex::new(None),
            kill_signal_delivered: std::sync::atomic::AtomicBool::new(false),
            last_outcome: std::sync::Mutex::new(None),
            #[cfg(target_os = "linux")]
            reversal_journal: None,
            #[cfg(target_os = "linux")]
            reversal_ownership_root: None,
            #[cfg(target_os = "linux")]
            applied_pause: std::sync::Mutex::new(None),
        }
    }

    /// Record the original job-control state durably before sending SIGSTOP.
    #[cfg(target_os = "linux")]
    pub fn with_reversal_journal(mut self, journal: Arc<ReversalJournal>) -> Self {
        self.reversal_journal = Some(journal);
        self
    }

    /// Prevent an unjournaled action from superseding another session's stop.
    #[cfg(target_os = "linux")]
    pub fn with_reversal_ownership_guard(mut self, sessions_root: PathBuf) -> Self {
        self.reversal_ownership_root = Some(sessions_root);
        self
    }

    #[cfg(target_os = "linux")]
    fn ensure_signal_stop_unowned(
        &self,
        target: &pt_common::ProcessIdentity,
    ) -> Result<(), ActionError> {
        if let Some(journal) = &self.reversal_journal {
            journal.ensure_signal_stop_unowned(target)
        } else if let Some(sessions_root) = &self.reversal_ownership_root {
            super::reversal::ensure_signal_stop_unowned(sessions_root, target)
        } else {
            Ok(())
        }
    }

    fn note_path(&self, path: &'static str) {
        *self.last_path.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    /// How the most recent signal was delivered ("pidfd", "kill", "kill_group"),
    /// clearing it; `None` if no signal was sent since the last call.
    pub fn take_signal_path(&self) -> Option<&'static str> {
        self.last_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// Consume actual destructive-signal delivery evidence for budget accounting.
    pub fn take_kill_signal_delivered(&self) -> bool {
        self.kill_signal_delivered
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// Consume the most recent kill attempt's signal evidence. Non-kill action
    /// execution clears it, so it cannot be attributed to the next action.
    pub fn take_signal_outcome(&self) -> Option<SignalExecutionOutcome> {
        self.last_outcome
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    #[cfg(unix)]
    fn note_delivered_signal(&self, signal: i32) {
        if matches!(signal, libc::SIGTERM | libc::SIGKILL) {
            self.kill_signal_delivered
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SignalConfig::default())
    }

    fn resolve_group_target(&self, pid: u32, pgid: Option<u32>) -> (u32, bool) {
        let pgid = pgid.filter(|pgid| *pgid > 0);
        let use_group = self.config.use_process_groups && pgid.is_some();
        let target = if use_group { pgid.unwrap() } else { pid };
        (target, use_group)
    }

    /// Send a signal to a process (or process group when `use_group` is true).
    ///
    /// `target_id` is the resolved target: either the PID itself or the PGID,
    /// as returned by [`resolve_group_target`].
    #[cfg(unix)]
    fn send_signal(&self, target_id: u32, signal: i32, use_group: bool) -> Result<(), ActionError> {
        let target_pid = signal_syscall_target(target_id, use_group)?;
        ensure_action_pid_namespace()?;
        self.note_path(if use_group { "kill_group" } else { "kill" });

        let result = unsafe { libc::kill(target_pid, signal) };
        if result == 0 {
            self.note_delivered_signal(signal);
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            Some(libc::EINVAL) => Err(ActionError::Failed("invalid signal".to_string())),
            _ => Err(ActionError::Failed(err.to_string())),
        }
    }

    /// Open a pidfd pinned to the planned process (Linux >= 5.3), if available.
    ///
    /// `Ok(None)` means pidfds are unsupported here (fall back to `kill(2)`).
    #[cfg(target_os = "linux")]
    fn pinned_pidfd(&self, action: &PlanAction) -> Result<Option<PidFd>, ActionError> {
        ensure_action_pid_namespace()?;
        let pid = action.target.pid.0;
        let Some(fd) = PidFd::open(pid)? else {
            return Ok(None);
        };
        // Opening the descriptor pins an incarnation, not its mutable owner,
        // process group or session. Check every recorded identity field after
        // the open, so a changed context cannot inherit the approved action.
        // If the PID is reused after this check, the pinned descriptor still
        // cannot signal the replacement.
        self.check_identity_now(action)?;
        self.note_path("pidfd");
        Ok(Some(fd))
    }

    /// Check if a process exists.
    #[cfg(unix)]
    fn process_exists(&self, pid: u32) -> bool {
        let result = unsafe { libc::kill(pid as i32, 0) };
        if result == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        // EPERM means process exists but we can't signal it
        err.raw_os_error() == Some(libc::EPERM)
    }

    /// Get process state.
    #[cfg(target_os = "linux")]
    fn get_process_state(&self, pid: u32) -> Option<char> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        // Format: pid (comm) state ...
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        after_comm.chars().next()
    }

    #[cfg(target_os = "macos")]
    fn get_process_state(&self, pid: u32) -> Option<char> {
        crate::collect::read_process_snapshot(pid).map(|info| info.state)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn get_process_state(&self, _pid: u32) -> Option<char> {
        None
    }

    /// Wait for a process to reach a target state or exit.
    fn wait_for_state_change(
        &self,
        pid: u32,
        expect_exit: bool,
        expect_stopped: Option<bool>,
        timeout: Duration,
    ) -> Result<(), ActionError> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms.max(1));

        while start.elapsed() < timeout {
            if expect_exit {
                if !self.process_exists(pid) {
                    return Ok(());
                }
                // A zombie counts as "exited" (we terminated it, even if the parent
                // hasn't reaped it yet).
                if let Some('Z') = self.get_process_state(pid) {
                    return Ok(());
                }
            }

            if let Some(stopped) = expect_stopped {
                if let Some(state) = self.get_process_state(pid) {
                    let expected = if stopped {
                        SignalExpectation::Stopped
                    } else {
                        SignalExpectation::Resumed
                    };
                    if expected.satisfied(SignalObservation::Present(state))? {
                        return Ok(());
                    }
                }
            }

            // A coarse polling interval must not extend the approved deadline.
            thread::sleep(poll_interval.min(timeout.saturating_sub(start.elapsed())));
        }

        Err(ActionError::Timeout)
    }

    /// Follow the process incarnation from the approved plan through every
    /// observation. A replacement must never supply a successful stop/resume
    /// result or keep a completed termination waiting on the replacement.
    #[cfg(unix)]
    fn wait_for_planned_state(
        &self,
        target: &pt_common::ProcessIdentity,
        expected: SignalExpectation,
        timeout: Duration,
    ) -> Result<(), ActionError> {
        wait_for_signal_observation(
            timeout,
            Duration::from_millis(self.config.poll_interval_ms.max(1)),
            expected,
            || observe_signal_target(target),
        )
    }

    /// Observe the full configured TERM grace period when the plan permits it.
    /// A shorter execution budget is a timeout, never permission to escalate to
    /// KILL early. `false` means the full grace expired with time left to escalate.
    #[cfg(unix)]
    fn wait_for_term_grace(
        &self,
        action: &PlanAction,
        deadline: &SignalDeadline,
        term_grace_ms: u64,
    ) -> Result<bool, ActionError> {
        let remaining = deadline.remaining()?;
        let grace = Duration::from_millis(term_grace_ms);
        match self.wait_for_planned_state(
            &action.target,
            SignalExpectation::Exited,
            grace.min(remaining),
        ) {
            Ok(()) => Ok(true),
            Err(ActionError::Timeout) => {
                if remaining <= grace {
                    return Err(ActionError::Timeout);
                }
                deadline.remaining()?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Bind the signal masks to the complete recorded incarnation before and
    /// after the status read. The masks are advisory only: unavailable evidence
    /// keeps the ordinary grace path, and delivery still revalidates identity.
    fn observed_sigterm_disposition(&self, action: &PlanAction) -> SignalDisposition {
        #[cfg(target_os = "linux")]
        {
            if action.target.quality != pt_common::IdentityQuality::Full
                || self.check_identity_now(action).is_err()
            {
                return SignalDisposition::Unknown;
            }
            let disposition =
                std::fs::read_to_string(format!("/proc/{}/status", action.target.pid.0))
                    .map(|status| sigterm_disposition_from_status(&status))
                    .unwrap_or(SignalDisposition::Unknown);
            if self.check_identity_now(action).is_err() {
                return SignalDisposition::Unknown;
            }
            disposition
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = action;
            SignalDisposition::Unknown
        }
    }

    /// TERM is always delivered first. Only an individually identified target
    /// observed to ignore it both before and after delivery can bypass waiting.
    /// A caught, default, changed, or unavailable disposition gets the full grace.
    #[cfg(unix)]
    fn wait_for_term_or_escalation(
        &self,
        action: &PlanAction,
        deadline: &SignalDeadline,
        use_group: bool,
        outcome: &mut SignalExecutionOutcome,
    ) -> Result<bool, ActionError> {
        if !use_group && outcome.sigterm_disposition == SignalDisposition::Ignored {
            if !self.original_target_still_present(action)? {
                return Ok(true);
            }
            deadline.remaining()?;
            let recheck = self.observed_sigterm_disposition(action);
            outcome.sigterm_recheck = Some(recheck);
            if may_skip_term_grace(use_group, outcome.sigterm_disposition, recheck) {
                deadline.remaining()?;
                outcome.escalation_reason = Some(SignalEscalationReason::SigtermIgnored);
                return Ok(false);
            }
        }
        if self.wait_for_term_grace(action, deadline, outcome.configured_grace_ms)? {
            Ok(true)
        } else {
            outcome.escalation_reason = Some(SignalEscalationReason::GraceExpired);
            Ok(false)
        }
    }

    fn verification_timeout(&self, action: &PlanAction) -> Duration {
        Duration::from_millis(self.config.verify_timeout_ms.min(action.timeouts.verify_ms))
    }

    /// Execute a pause action (SIGSTOP).
    #[cfg(unix)]
    fn execute_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        #[cfg(target_os = "linux")]
        {
            if use_group
                && (self.reversal_journal.is_some() || self.reversal_ownership_root.is_some())
            {
                return Err(ActionError::Failed(
                    "single-process stop ownership cannot authorize a process-group pause"
                        .to_string(),
                ));
            }
            if self.reversal_journal.is_some() {
                return self.execute_journaled_pause(action, &deadline);
            }
            self.ensure_signal_stop_unowned(&action.target)?;
        }

        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                return pidfd.send(libc::SIGSTOP);
            }
        }
        // Bind a fallback signal to every recorded identity field, including
        // the leader's current group/session when group signaling is requested.
        self.check_identity_now(action)?;
        deadline.remaining()?;
        self.send_signal(target, libc::SIGSTOP, use_group)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn execute_journaled_pause(
        &self,
        action: &PlanAction,
        deadline: &SignalDeadline,
    ) -> Result<(), ActionError> {
        if self.verification_timeout(action).is_zero() {
            return Err(ActionError::Failed(
                "durable pause requires a nonzero verification budget for recovery".to_string(),
            ));
        }
        let mut applied = self
            .applied_pause
            .lock()
            .map_err(|_| ActionError::Failed("pause execution record unavailable".to_string()))?;
        *applied = None;
        let journal = self.reversal_journal.as_ref().ok_or_else(|| {
            ActionError::Failed("pause requires its configured undo journal".to_string())
        })?;
        deadline.remaining()?;
        ensure_action_pid_namespace()?;
        let pidfd = PidFd::open(action.target.pid.0)?.ok_or_else(|| {
            ActionError::Failed("durable pause requires kernel pidfd support".to_string())
        })?;
        let state = signal_state(&action.target)?;
        let was_stopped = match state {
            'T' => true,
            'R' | 'S' | 'D' | 'I' => false,
            _ => {
                return Err(ActionError::Failed(
                    "durable pause requires a live process outside a debugger tracing stop"
                        .to_string(),
                ))
            }
        };
        let receipt = journal.prepare_signal_stop(action, was_stopped)?;
        self.apply_prepared_pause(action, deadline, &pidfd, was_stopped, &receipt)?;
        *applied = Some(AppliedPause {
            action_id: action.action_id.clone(),
            target: action.target.clone(),
            receipt,
        });
        Ok(())
    }

    /// A refusal before the first signal attempt owns no process stop. Keep it
    /// distinct from an attempted delivery whose effect may need recovery.
    #[cfg(target_os = "linux")]
    fn apply_prepared_pause(
        &self,
        action: &PlanAction,
        deadline: &SignalDeadline,
        pidfd: &PidFd,
        was_stopped: bool,
        receipt: &PreparedReversal,
    ) -> Result<(), ActionError> {
        let ready = (|| {
            deadline.remaining()?;
            let state = signal_state(&action.target)?;
            if !matches!(state, 'R' | 'S' | 'D' | 'I' | 'T') || (state == 'T') != was_stopped {
                return Err(ActionError::Failed(
                    "job-control state changed after pause receipt preparation".to_string(),
                ));
            }
            deadline.remaining()?;
            Ok(())
        })();
        if let Err(error) = ready {
            return receipt.abort_signal_stop(error);
        }
        let execution = (|| {
            if !was_stopped {
                // From this point even a syscall error remains an attempted
                // actuation; do not release its conservative recovery receipt.
                pidfd.send(libc::SIGSTOP)?;
                self.note_path("pidfd");
            }
            Ok(())
        })();
        receipt.finish(execution, ReversalStatus::Applied)
    }

    /// Re-check the recorded incarnation and its owner/group/session immediately
    /// before delivery. A matching start tick alone does not bind those fields.
    #[cfg(unix)]
    fn check_identity_now(&self, action: &PlanAction) -> Result<(), ActionError> {
        match observe_signal_target(&action.target)? {
            SignalObservation::Present(_) => Ok(()),
            SignalObservation::Replaced => Err(ActionError::IdentityMismatch),
            SignalObservation::Gone => Err(ActionError::ProcessNotFound),
        }
    }

    /// Once TERM was delivered, disappearance/replacement means the original
    /// target exited. Changed ownership or job-control context is still an error
    /// and must not authorize a follow-up CONT or KILL, even through a pidfd.
    #[cfg(unix)]
    fn original_target_still_present(&self, action: &PlanAction) -> Result<bool, ActionError> {
        match observe_signal_target(&action.target)? {
            SignalObservation::Present(_) => Ok(true),
            SignalObservation::Gone | SignalObservation::Replaced => Ok(false),
        }
    }

    /// Execute a kill action (SIGTERM → SIGKILL).
    #[cfg(unix)]
    fn execute_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        // Read the reviewed value from the immutable plan, never a later policy
        // configuration. Legacy library callers may still supply runner defaults.
        let term_grace_ms = action
            .timeouts
            .term_grace_ms
            .unwrap_or(self.config.term_grace_ms);
        crate::config::policy::validate_term_grace_ms(term_grace_ms)
            .map_err(|reason| ActionError::Failed(reason.to_string()))?;
        let started = Instant::now();
        let mut term_started = None;
        let mut outcome = SignalExecutionOutcome {
            sigterm_disposition: SignalDisposition::Unknown,
            sigterm_recheck: None,
            configured_grace_ms: term_grace_ms,
            observed_grace_ms: None,
            sigterm_delivered: false,
            sigcont_delivered: false,
            sigkill_delivered: false,
            escalation_reason: None,
            execution_elapsed_ms: 0,
        };
        let result = self.execute_kill_observed(action, &mut outcome, &mut term_started);
        outcome.observed_grace_ms = term_started.map(elapsed_millis);
        outcome.execution_elapsed_ms = elapsed_millis(started);
        *self
            .last_outcome
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(outcome);
        result
    }

    #[cfg(unix)]
    fn execute_kill_observed(
        &self,
        action: &PlanAction,
        outcome: &mut SignalExecutionOutcome,
        term_started: &mut Option<Instant>,
    ) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);
        if !use_group {
            outcome.sigterm_disposition = self.observed_sigterm_disposition(action);
        }
        let resume_stopped = should_resume_after_sigterm(self.get_process_state(pid), use_group);

        // Linux: TERM, any CONT needed for graceful shutdown, and KILL all go
        // through one pidfd pinned to the verified process. Never resume a
        // replacement process if the target exits between these signals.
        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                pidfd.send(libc::SIGTERM)?;
                *term_started = Some(Instant::now());
                outcome.sigterm_delivered = true;
                self.note_delivered_signal(libc::SIGTERM);
                if resume_stopped {
                    if !self.original_target_still_present(action)? {
                        return Ok(());
                    }
                    deadline.remaining()?;
                    match pidfd.send(libc::SIGCONT) {
                        Ok(()) => outcome.sigcont_delivered = true,
                        Err(ActionError::ProcessNotFound) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                return if self.wait_for_term_or_escalation(action, &deadline, use_group, outcome)? {
                    Ok(())
                } else {
                    if !self.original_target_still_present(action)? {
                        return Ok(());
                    }
                    deadline.remaining()?;
                    match pidfd.send(libc::SIGKILL) {
                        Ok(()) => {
                            outcome.sigkill_delivered = true;
                            self.note_delivered_signal(libc::SIGKILL);
                            Ok(())
                        }
                        // Exited between the grace timeout and SIGKILL: done.
                        Err(ActionError::ProcessNotFound) => Ok(()),
                        other => other,
                    }
                };
            }
        }

        self.check_identity_now(action)?;

        // Stage 1: SIGTERM
        deadline.remaining()?;
        self.send_signal(target, libc::SIGTERM, use_group)?;
        *term_started = Some(Instant::now());
        outcome.sigterm_delivered = true;

        if resume_stopped {
            // Without a pidfd, revalidate immediately before the additional
            // signal just as for TERM and KILL. CONT always targets this one
            // process, never an unverified group or a tracing-stop subject.
            if !self.original_target_still_present(action)? {
                return Ok(());
            }
            deadline.remaining()?;
            match self.send_signal(pid, libc::SIGCONT, false) {
                Ok(()) => outcome.sigcont_delivered = true,
                Err(ActionError::ProcessNotFound) => return Ok(()),
                Err(error) => return Err(error),
            }
        }

        // Wait for graceful termination
        if self.wait_for_term_or_escalation(action, &deadline, use_group, outcome)? {
            return Ok(());
        }

        // Revalidate all recorded identity fields after the grace period.
        // A new occupant or an exited original needs no further signal.
        if self.original_target_still_present(action)? {
            deadline.remaining()?;
            self.send_signal(target, libc::SIGKILL, use_group)?;
            outcome.sigkill_delivered = true;
        }

        Ok(())
    }

    /// Zombie routed to its parent (`ActionRouting::ZombieToParent`): ask the parent
    /// to reap with SIGCHLD. Harmless (the default disposition is ignore); the zombie
    /// itself is never signaled and the parent is never killed or restarted here.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn nudge_parent_to_reap(&self, action: &PlanAction) -> Result<(), ActionError> {
        let _ = self.take_signal_outcome();
        action
            .validate_signal_timing()
            .map_err(|reason| ActionError::Failed(reason.to_string()))?;
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        #[cfg(target_os = "linux")]
        if let Some(pidfd) = self.pinned_pidfd(action)? {
            deadline.remaining()?;
            return pidfd.send(libc::SIGCHLD);
        }
        self.check_identity_now(action)?;
        deadline.remaining()?;
        self.send_signal(action.target.pid.0, libc::SIGCHLD, false)
    }

    /// The routed zombie is gone (reaped), or a different process now holds its pid.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn verify_zombie_reaped(&self, action: &PlanAction) -> Result<(), ActionError> {
        let Some(zombie) = action.original_zombie_target.as_ref() else {
            return Err(ActionError::Failed(
                "cannot verify reaping without the original zombie identity".to_string(),
            ));
        };
        let pid = zombie.pid.0;
        match self.wait_for_planned_state(
            zombie,
            SignalExpectation::Reaped,
            self.verification_timeout(action),
        ) {
            Ok(()) => Ok(()),
            Err(ActionError::Timeout) => Err(ActionError::Failed(format!(
                "zombie {pid} persists: parent {} did not reap it on SIGCHLD; \
                 restart or stop the parent to clear it",
                action.target.pid.0
            ))),
            Err(error) => Err(error),
        }
    }

    /// Verify a pause action succeeded.
    #[cfg(unix)]
    fn verify_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        #[cfg(target_os = "linux")]
        if self.reversal_journal.is_some() {
            let applied = self.applied_pause.lock().map_err(|_| {
                ActionError::Failed("pause execution record unavailable".to_string())
            })?;
            let record = applied.as_ref().ok_or_else(|| {
                ActionError::Failed(
                    "cannot verify a pause without its execution receipt".to_string(),
                )
            })?;
            if record.action_id != action.action_id || record.target != action.target {
                return Err(ActionError::IdentityMismatch);
            }
            return record.receipt.finish(
                self.wait_for_planned_state(
                    &action.target,
                    SignalExpectation::Stopped,
                    self.verification_timeout(action),
                ),
                ReversalStatus::Verified,
            );
        }
        self.wait_for_planned_state(
            &action.target,
            SignalExpectation::Stopped,
            self.verification_timeout(action),
        )
    }

    /// Verify a kill action succeeded.
    #[cfg(unix)]
    fn verify_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.wait_for_planned_state(
            &action.target,
            SignalExpectation::Exited,
            self.verification_timeout(action),
        )
    }

    /// Execute a resume action (SIGCONT) - raw version.
    #[cfg(unix)]
    pub fn resume(&self, pid: u32, use_group: bool, pgid: Option<u32>) -> Result<(), ActionError> {
        let pgid = pgid.filter(|pgid| *pgid > 0);
        let use_group = use_group && pgid.is_some();
        let target = if use_group { pgid.unwrap() } else { pid };
        self.send_signal(target, libc::SIGCONT, use_group)
    }

    /// Verify a resume action succeeded - raw version.
    pub fn verify_resume_raw(&self, pid: u32) -> Result<(), ActionError> {
        let timeout = Duration::from_millis(self.config.verify_timeout_ms);
        // Process should not be stopped anymore
        self.wait_for_state_change(pid, false, Some(false), timeout)
    }

    /// Execute a resume action (SIGCONT) from PlanAction.
    #[cfg(unix)]
    fn execute_resume(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        #[cfg(target_os = "linux")]
        {
            if use_group
                && (self.reversal_journal.is_some() || self.reversal_ownership_root.is_some())
            {
                return Err(ActionError::Failed(
                    "single-process stop ownership cannot authorize a process-group resume"
                        .to_string(),
                ));
            }
            self.ensure_signal_stop_unowned(&action.target)?;
        }

        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                return pidfd.send(libc::SIGCONT);
            }
        }
        self.check_identity_now(action)?;
        deadline.remaining()?;
        self.send_signal(target, libc::SIGCONT, use_group)?;
        Ok(())
    }

    /// Verify a resume action succeeded.
    #[cfg(unix)]
    fn verify_resume(&self, action: &PlanAction) -> Result<(), ActionError> {
        // Process should not be stopped anymore
        self.wait_for_planned_state(
            &action.target,
            SignalExpectation::Resumed,
            self.verification_timeout(action),
        )
    }
}

#[cfg(unix)]
impl ActionRunner for SignalActionRunner {
    fn revalidate(
        &self,
        action: &PlanAction,
        provider: &dyn super::executor::IdentityProvider,
    ) -> Result<bool, ActionError> {
        provider.revalidate(&action.target)
    }

    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        let _ = self.take_signal_outcome();
        action
            .validate_signal_timing()
            .map_err(|reason| ActionError::Failed(reason.to_string()))?;
        match action.action {
            Action::Pause => self.execute_pause(action),
            Action::Resume => self.execute_resume(action),
            Action::Kill => self.execute_kill(action),
            Action::Keep => Ok(()),
            Action::Throttle => {
                // Throttle requires cgroup operations, not signals
                Err(ActionError::Failed(
                    "throttle requires cgroup support".to_string(),
                ))
            }
            Action::CapMemory => Err(ActionError::Failed(
                "memory cap requires a planned cgroup-v2 memory.high operation".to_string(),
            )),
            Action::Restart => {
                // Restart requires supervisor awareness
                Err(ActionError::Failed(
                    "restart requires supervisor support".to_string(),
                ))
            }
            Action::Renice => {
                // Renice requires setpriority operations, not signals
                Err(ActionError::Failed(
                    "renice requires setpriority support".to_string(),
                ))
            }
            Action::Freeze | Action::Unfreeze => {
                // Freeze/Unfreeze require cgroup v2 freezer operations
                Err(ActionError::Failed(
                    "freeze/unfreeze requires cgroup v2 freezer support".to_string(),
                ))
            }
            Action::Quarantine | Action::Unquarantine => {
                // Quarantine requires cgroup cpuset operations
                Err(ActionError::Failed(
                    "quarantine requires cgroup cpuset support".to_string(),
                ))
            }
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Pause => self.verify_pause(action),
            Action::Resume => self.verify_resume(action),
            Action::Kill => self.verify_kill(action),
            Action::Keep => Ok(()),
            Action::Throttle
            | Action::CapMemory
            | Action::Restart
            | Action::Renice
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(not(unix))]
impl ActionRunner for SignalActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "signals not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "signals not supported on this platform".to_string(),
        ))
    }
}

/// Live identity provider that validates against /proc.
#[cfg(target_os = "linux")]
pub struct LiveIdentityProvider {
    boot_id: &'static str,
}

#[cfg(target_os = "linux")]
impl LiveIdentityProvider {
    pub fn new() -> Self {
        use std::sync::OnceLock;
        static BOOT_ID: OnceLock<String> = OnceLock::new();
        let boot_id = BOOT_ID.get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
        Self { boot_id }
    }

    /// Read start_id from /proc/[pid]/stat.
    fn read_start_id(&self, pid: u32) -> Option<String> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(&stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // Field 19 (0-indexed from after comm) is starttime
        let starttime = fields.get(19)?.parse::<u64>().ok()?;

        Some(format!("{}:{starttime}:{pid}", self.boot_id))
    }

    /// Read uid from /proc/[pid]/status.
    fn read_uid(&self, pid: u32) -> Option<u32> {
        let status_path = format!("/proc/{pid}/status");
        let content_bytes = std::fs::read(&status_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Real UID is the first value after "Uid:"
                return parts.get(1)?.parse().ok();
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
impl Default for LiveIdentityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl super::executor::IdentityProvider for LiveIdentityProvider {
    fn revalidate(&self, target: &pt_common::ProcessIdentity) -> Result<bool, ActionError> {
        ensure_action_pid_namespace()?;
        let pid = target.pid.0;

        // Check if process exists
        let stat_path = format!("/proc/{pid}/stat");
        if !std::path::Path::new(&stat_path).exists() {
            return Ok(false); // Process gone
        }

        // Validate start_id
        if let Some(current_start_id) = self.read_start_id(pid) {
            // start_id format might differ; check starttime portion
            if !ids_match(&target.start_id.0, &current_start_id) {
                return Ok(false); // PID was reused
            }
        } else {
            return Ok(false); // Can't read identity
        }

        // Bracket ownership and job-control facts with birth observations, just
        // as the delivery boundary does. A PID can keep its start time while
        // changing UID, process group or session after the plan was approved.
        match observe_signal_target(target) {
            Ok(SignalObservation::Present(_)) => Ok(true),
            Ok(SignalObservation::Gone | SignalObservation::Replaced)
            | Err(ActionError::IdentityMismatch) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Live identity provider for macOS: exact start time (microseconds) and uid from
/// `proc_pidinfo`, the same source the scan records in start ids.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct LiveIdentityProvider;

#[cfg(target_os = "macos")]
impl LiveIdentityProvider {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl super::executor::IdentityProvider for LiveIdentityProvider {
    fn revalidate(&self, target: &pt_common::ProcessIdentity) -> Result<bool, ActionError> {
        match observe_signal_target(target) {
            Ok(SignalObservation::Present(_)) => Ok(true),
            Ok(SignalObservation::Gone | SignalObservation::Replaced)
            | Err(ActionError::IdentityMismatch) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// A pidfd (Linux >= 5.3): a file descriptor pinned to one specific process.
/// Signals sent through it can never reach a process that later reuses the PID.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PidFd(libc::c_int);

#[cfg(target_os = "linux")]
impl PidFd {
    /// `Ok(None)` when the kernel lacks pidfd support.
    fn open(pid: u32) -> Result<Option<Self>, ActionError> {
        let target = signal_syscall_target(pid, false)?;
        // SAFETY: plain syscall with integer arguments; the returned fd is owned below.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target as libc::pid_t, 0) };
        if fd >= 0 {
            return Ok(Some(PidFd(fd as libc::c_int)));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::ENOSYS) => Ok(None),
            _ => Err(ActionError::Failed(format!("pidfd_open({pid}): {err}"))),
        }
    }

    fn send(&self, signal: i32) -> Result<(), ActionError> {
        // SAFETY: valid owned fd; null siginfo is allowed; flags must be 0.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            _ => Err(ActionError::Failed(format!("pidfd_send_signal: {err}"))),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: we own this fd and close it exactly once.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Values of a `boot_id:start_ticks:pid` start id that are known (not placeholders).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn parse_start_id(id: &str) -> (Option<&str>, Option<u64>, Option<u32>) {
    let parts: Vec<&str> = id.split(':').collect();
    let known = |s: &str| !s.is_empty() && !matches!(s, "unknown" | "synthetic");
    match parts.as_slice() {
        [ticks] => (None, ticks.parse().ok(), None),
        [boot, ticks, pid] => (
            Some(*boot).filter(|b| known(b)),
            ticks.parse().ok(),
            pid.parse().ok(),
        ),
        _ => (None, None, None),
    }
}

/// Check whether a plan's start_id identifies the same process as the live one.
///
/// Both boot ids (when known), pids (when present) and start ticks must agree
/// exactly. Plans record exact /proc start ticks on Linux, so the old +-150-tick
/// tolerance (for ps-estimated ids) only widened the PID-reuse window, and the old
/// check ignored the boot id entirely.
#[cfg(any(target_os = "linux", test))]
fn ids_match(expected: &str, current: &str) -> bool {
    if expected == current {
        return true;
    }
    let (e_boot, e_ticks, e_pid) = parse_start_id(expected);
    let (c_boot, c_ticks, c_pid) = parse_start_id(current);
    if let (Some(a), Some(b)) = (e_boot, c_boot) {
        if a != b {
            return false;
        }
    }
    if let (Some(a), Some(b)) = (e_pid, c_pid) {
        if a != b {
            return false;
        }
    }
    matches!((e_ticks, c_ticks), (Some(a), Some(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn sigterm_disposition_requires_complete_consistent_kernel_masks() {
        assert_eq!(
            sigterm_disposition_from_status(
                "Name:\tworker\nSigIgn:\t0000000000004000\nSigCgt:\t0000000000000000\n"
            ),
            SignalDisposition::Ignored
        );
        assert_eq!(
            sigterm_disposition_from_status(
                "SigIgn:\t0000000000000000\nSigCgt:\t0000000000004000\n"
            ),
            SignalDisposition::Caught
        );
        assert_eq!(
            sigterm_disposition_from_status(
                "SigIgn:\t0000000000000001\nSigCgt:\t0000000180000000\n"
            ),
            SignalDisposition::Default,
            "unrelated ignored/caught signals cannot shorten TERM grace"
        );
        for malformed in [
            "",
            "SigIgn:\t0000000000004000\n",
            "SigCgt:\t0000000000000000\n",
            "SigIgn:\t4000\nSigCgt:\t4000\n",
            "SigIgn:\t4000\nSigCgt:\t\n",
            "SigIgn:\t4000\nSigCgt:\tnot-hex\n",
            "SigIgn:\t4000\nSigCgt:\t+0\n",
            "SigIgn:\t0x4000\nSigCgt:\t0\n",
            "SigIgn:\t10000000000004000\nSigCgt:\t0\n",
            "SigIgn:\t4000\nSigIgn:\t4000\nSigCgt:\t0\n",
            "SigIgn:\t4000\nSigCgt:\t0\nSigCgt:\t0\n",
        ] {
            assert_eq!(
                sigterm_disposition_from_status(malformed),
                SignalDisposition::Unknown,
                "malformed or incomplete status: {malformed:?}"
            );
        }
    }

    #[test]
    fn skipped_term_grace_requires_two_ignored_reads_and_an_individual_target() {
        for before in [
            SignalDisposition::Unknown,
            SignalDisposition::Default,
            SignalDisposition::Caught,
            SignalDisposition::Ignored,
        ] {
            for after in [
                SignalDisposition::Unknown,
                SignalDisposition::Default,
                SignalDisposition::Caught,
                SignalDisposition::Ignored,
            ] {
                assert!(
                    !may_skip_term_grace(true, before, after),
                    "leader-only evidence must never shorten group grace"
                );
                let expected = cfg!(target_os = "linux")
                    && before == SignalDisposition::Ignored
                    && after == SignalDisposition::Ignored;
                assert_eq!(may_skip_term_grace(false, before, after), expected);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn signal_outcome_observations_preserve_exit_and_job_control_semantics() {
        for missing in [SignalObservation::Gone, SignalObservation::Replaced] {
            assert!(SignalExpectation::Exited.satisfied(missing).unwrap());
            assert!(SignalExpectation::Reaped.satisfied(missing).unwrap());
            assert!(SignalExpectation::Stopped.satisfied(missing).is_err());
            assert!(SignalExpectation::Resumed.satisfied(missing).is_err());
        }
        for state in ['Z', 'X', 'x'] {
            let observation = SignalObservation::Present(state);
            assert!(SignalExpectation::Exited.satisfied(observation).unwrap());
            assert!(!SignalExpectation::Reaped.satisfied(observation).unwrap());
            assert!(SignalExpectation::Stopped.satisfied(observation).is_err());
            assert!(SignalExpectation::Resumed.satisfied(observation).is_err());
        }
        for state in ['R', 'S', 'D', 'I', 'W', 'K', 'P'] {
            let observation = SignalObservation::Present(state);
            assert!(!SignalExpectation::Exited.satisfied(observation).unwrap());
            assert!(!SignalExpectation::Stopped.satisfied(observation).unwrap());
            assert!(SignalExpectation::Resumed.satisfied(observation).unwrap());
            assert!(SignalExpectation::Reaped.satisfied(observation).is_err());
        }
        assert!(SignalExpectation::Stopped
            .satisfied(SignalObservation::Present('T'))
            .unwrap());
        assert!(!SignalExpectation::Resumed
            .satisfied(SignalObservation::Present('T'))
            .unwrap());
        for state in ['t', '?'] {
            assert!(SignalExpectation::Stopped
                .satisfied(SignalObservation::Present(state))
                .is_err());
            assert!(SignalExpectation::Resumed
                .satisfied(SignalObservation::Present(state))
                .is_err());
        }
        assert!(SignalExpectation::Exited
            .satisfied(SignalObservation::Present('?'))
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_signal_observations_never_become_completed_effects() {
        for expected in [
            SignalExpectation::Exited,
            SignalExpectation::Stopped,
            SignalExpectation::Resumed,
            SignalExpectation::Reaped,
        ] {
            let mut reads = 0;
            let result = wait_for_signal_observation(
                Duration::from_secs(1),
                Duration::from_millis(1),
                expected,
                || {
                    reads += 1;
                    Err(ActionError::PermissionDenied)
                },
            );
            assert!(matches!(result, Err(ActionError::PermissionDenied)));
            assert_eq!(reads, 1);
        }
        let mut reads = 0;
        let result = wait_for_signal_observation(
            Duration::ZERO,
            Duration::from_millis(1),
            SignalExpectation::Exited,
            || {
                reads += 1;
                Ok(SignalObservation::Gone)
            },
        );
        assert!(matches!(result, Err(ActionError::Timeout)));
        assert_eq!(reads, 0, "a zero approved window certifies nothing");
    }

    #[test]
    fn signal_syscall_target_rejects_broadcast_and_init_values() {
        for use_group in [false, true] {
            for invalid in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
                assert!(
                    signal_syscall_target(invalid, use_group).is_err(),
                    "target={invalid}, group={use_group}"
                );
            }
        }

        // A child may have inherited init's process group. Even an explicit
        // group-signaling configuration must not turn that PGID into kill(-1).
        let runner = SignalActionRunner::new(SignalConfig {
            use_process_groups: true,
            ..Default::default()
        });
        let (target, use_group) = runner.resolve_group_target(42, Some(1));
        assert!(use_group);
        assert!(signal_syscall_target(target, use_group).is_err());
    }

    #[test]
    fn signal_syscall_target_preserves_valid_process_and_group_ranges() {
        for id in [2, 3, 42, 65_535, i32::MAX as u32] {
            let process = signal_syscall_target(id, false).unwrap();
            let group = signal_syscall_target(id, true).unwrap();
            assert_eq!(process, id as i32);
            assert_eq!(group, -(id as i32));
            assert!(process >= 2);
            assert!(group <= -2);
        }
    }

    #[test]
    fn graceful_kill_does_not_resume_tracing_stops_or_groups() {
        assert_eq!(
            should_resume_after_sigterm(Some('T'), false),
            cfg!(target_os = "linux")
        );
        assert!(!should_resume_after_sigterm(Some('T'), true));
        for state in [None, Some('t'), Some('R'), Some('S'), Some('Z')] {
            assert!(!should_resume_after_sigterm(state, false), "{state:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn action_namespace_validation_rejects_ancestor_procfs_and_unknown_links() {
        use std::path::Path;

        let status = "Name:\tpt-core\nNSpid:\t42\n";
        assert!(validate_procfs_pid_namespace(42, Path::new("42"), status).is_ok());
        let mismatch = validate_procfs_pid_namespace(42, Path::new("9876"), status).unwrap_err();
        assert!(mismatch.to_string().contains("PID namespace differs"));
        for invalid in ["", "0", "-1", "+42", "42/task/42", "/proc/42", "4294967296"] {
            assert!(
                validate_procfs_pid_namespace(42, Path::new(invalid), status).is_err(),
                "{invalid}"
            );
        }
        assert!(validate_procfs_pid_namespace(0, Path::new("42"), status).is_err());
        for status in [
            "",
            "NSpid:\n",
            "NSpid:\t42 42\n",
            "NSpid:\t42 5\n",
            "NSpid:\twrong\n",
            "NSpid:\t42\nNSpid:\t42\n",
        ] {
            assert!(
                validate_procfs_pid_namespace(42, Path::new("42"), status).is_err(),
                "{status}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_identity_namespace_refusal_precedes_missing_target_lookup() {
        use super::super::executor::IdentityProvider;
        use pt_common::{ProcessIdentity, StartId};

        // No action is executed and this PID cannot be allocated by Linux. The
        // test runs in both ordinary and ancestor-procfs containers: mismatched
        // procfs must be an explicit namespace error, not a "process gone" result.
        let target = ProcessIdentity::new(u32::MAX, StartId::from_linux("test", 1, u32::MAX), 0);
        let result = LiveIdentityProvider::new().revalidate(&target);
        let proc_pid: u32 = std::fs::read_link("/proc/self")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let namespace_pids: Vec<_> = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .unwrap()
            .split_whitespace()
            .collect();
        if proc_pid == std::process::id() && namespace_pids.len() == 1 {
            assert!(matches!(result, Ok(false)));
        } else {
            let error =
                result.expect_err("namespace mismatch must refuse before reading target identity");
            assert!(error.to_string().contains("PID namespace"), "{error}");
        }
    }

    #[test]
    fn signal_config_defaults() {
        let config = SignalConfig::default();
        assert_eq!(config.term_grace_ms, 5_000);
        assert_eq!(config.poll_interval_ms, 100);
        assert_eq!(config.verify_timeout_ms, 10_000);
        assert!(!config.use_process_groups);
    }

    #[test]
    fn ids_match_direct() {
        assert!(ids_match("abc:123:456", "abc:123:456"));
    }

    #[test]
    fn ids_match_requires_same_boot_and_pid() {
        // Same ticks after a reboot, or on another pid, is a different process.
        assert!(!ids_match("abc:123:456", "def:123:456"));
        assert!(!ids_match("abc:123:456", "abc:123:789"));
        // Unknown/synthetic boot ids do not veto a match.
        assert!(ids_match("unknown:123:456", "abc:123:456"));
    }

    #[test]
    fn ids_match_different() {
        assert!(!ids_match("abc:123:456", "abc:999:456"));
    }

    #[test]
    fn ids_match_is_exact_on_ticks() {
        // Start ticks come from /proc: any difference means a different process.
        assert!(!ids_match("abc:10000:456", "abc:10001:456"));
        assert!(!ids_match("abc:10000:456", "abc:10150:456"));
        assert!(ids_match("abc:10000:456", "abc:10000:456"));
    }

    /// pidfd-pinned signaling: open a pidfd for a live child, send it a signal and
    /// check the kernel delivered it; after the child is reaped, the same pidfd must
    /// report ESRCH instead of reaching whatever reuses the pid.
    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_signals_only_the_pinned_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let Some(fd) = PidFd::open(pid).expect("pidfd_open") else {
            let _ = child.kill();
            let _ = child.wait();
            return; // kernel without pidfd support
        };
        fd.send(libc::SIGTERM).expect("signal via pidfd");
        let status = child.wait().expect("wait child");
        assert!(!status.success(), "child should have died from SIGTERM");
        assert!(matches!(
            fd.send(libc::SIGTERM),
            Err(ActionError::ProcessNotFound)
        ));
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::process::Command;

        #[test]
        fn runner_can_be_created() {
            let runner = SignalActionRunner::with_defaults();
            assert_eq!(runner.config.term_grace_ms, 5_000);
        }

        #[test]
        fn process_exists_for_self() {
            let runner = SignalActionRunner::with_defaults();
            let pid = std::process::id();
            assert!(runner.process_exists(pid));
        }

        #[test]
        fn process_not_exists_for_invalid() {
            let runner = SignalActionRunner::with_defaults();
            // Very high PID unlikely to exist
            assert!(!runner.process_exists(999_999_999));
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn get_process_state_for_self() {
            let runner = SignalActionRunner::with_defaults();
            let pid = std::process::id();
            let state = runner.get_process_state(pid);
            assert!(state.is_some());
            // Running process should be in R (running) or S (sleeping) state
            let s = state.unwrap();
            assert!(s == 'R' || s == 'S' || s == 'D');
        }

        #[test]
        fn can_pause_and_resume_child() {
            // Spawn a sleep process
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("failed to spawn sleep");

            let pid = child.id();
            let runner = SignalActionRunner::with_defaults();

            // Pause it
            let pause_result = runner.send_signal(pid, libc::SIGSTOP, false);
            assert!(pause_result.is_ok(), "pause failed: {:?}", pause_result);

            // Verify stopped (on Linux)
            #[cfg(target_os = "linux")]
            {
                std::thread::sleep(Duration::from_millis(100));
                let state = runner.get_process_state(pid);
                assert_eq!(state, Some('T'), "expected stopped state");
            }

            // Resume it
            let resume_result = runner.resume(pid, false, None);
            assert!(resume_result.is_ok(), "resume failed: {:?}", resume_result);

            // Kill and cleanup
            let _ = child.kill();
            let _ = child.wait();
        }

        #[test]
        fn can_kill_child() {
            // Spawn a sleep process
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("failed to spawn sleep");

            let pid = child.id();
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100, // Short grace for test
                poll_interval_ms: 10,
                verify_timeout_ms: 1_000,
                use_process_groups: false,
            });

            // Kill it (SIGTERM)
            let kill_result = runner.send_signal(pid, libc::SIGTERM, false);
            assert!(kill_result.is_ok(), "kill failed: {:?}", kill_result);

            // Wait for exit
            let status = child.wait().expect("wait failed");
            assert!(!status.success() || status.code().is_none());
        }

        #[test]
        fn delivered_kill_is_retained_after_verification_timeout() {
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn owned sleep");
            let pid = child.id();
            let runner = SignalActionRunner::new(SignalConfig {
                verify_timeout_ms: 0,
                ..SignalConfig::default()
            });
            assert!(!runner.take_kill_signal_delivered());
            runner.send_signal(pid, libc::SIGTERM, false).unwrap();
            // A zero observation window deliberately cannot certify the effect.
            let observation = runner.wait_for_state_change(pid, true, None, Duration::ZERO);
            assert!(matches!(observation, Err(ActionError::Timeout)));
            child.wait().expect("reap signaled child");
            assert!(runner.take_kill_signal_delivered());
            assert!(!runner.take_kill_signal_delivered());
            // No delivery is credited when the syscall itself refuses a target.
            assert!(runner.send_signal(u32::MAX, libc::SIGTERM, false).is_err());
            assert!(!runner.take_kill_signal_delivered());
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::action::executor::IdentityProvider;
        use crate::plan::ActionRouting;
        use std::os::unix::process::{CommandExt, ExitStatusExt};

        struct OwnedSignalChild(std::process::Child);

        impl Drop for OwnedSignalChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        /// The shell stops itself only after installing its handler. Its open
        /// stdin pipe keeps `read` blocked after CONT without any descendant
        /// process or busy loop, including when TERM is deliberately ignored.
        fn stopped_term_child(
            marker: &std::path::Path,
            ignore_term: bool,
            own_group: bool,
        ) -> (OwnedSignalChild, PlanAction) {
            let script = if ignore_term {
                "trap '' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || exit; done"
            } else {
                "trap 'printf \"term handled\\n\" > \"$1\"; exit 0' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || exit; done"
            };
            stopped_signal_child(script, marker, own_group)
        }

        fn stopped_signal_child(
            script: &str,
            marker: &std::path::Path,
            own_group: bool,
        ) -> (OwnedSignalChild, PlanAction) {
            let mut command = std::process::Command::new("sh");
            command
                .arg("-c")
                .arg(script)
                .arg("pt-signal-test")
                .arg(marker)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if own_group {
                // Any group-directed test signal must stay within this owned
                // child's group, never the test runner's inherited group.
                command.process_group(0);
            }
            let child = OwnedSignalChild(command.spawn().expect("spawn owned TERM handler"));
            let pid = child.0.id();
            SignalActionRunner::with_defaults()
                .wait_for_state_change(pid, false, Some(true), Duration::from_secs(5))
                .expect("child installed TERM handler and stopped");
            let provider = LiveIdentityProvider::new();
            let target = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(provider.read_start_id(pid).expect("child start ID")),
                uid: provider.read_uid(pid).expect("child UID"),
                pgid: own_group.then_some(pid),
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };
            let action = serde_json::from_value(serde_json::json!({
                "action_id": "owned-signal-test",
                "target": target,
                "action": "kill",
                "order": 0,
                "stage": 0,
                "timeouts": crate::plan::ActionTimeouts::default(),
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
            }))
            .expect("valid kill PlanAction");
            (child, action)
        }

        #[test]
        fn planned_signal_verification_requires_the_recorded_identity() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            action.action = Action::Pause;
            action.timeouts.verify_ms = 100;
            let stat = crate::collect::proc_parsers::read_required_proc_stat(child.0.id())
                .expect("owned child identity");
            action.target.pgid = Some(stat.pgrp as u32);
            action.target.sid = Some(stat.session as u32);
            let runner = SignalActionRunner::with_defaults();
            runner.verify(&action).expect("original child is stopped");

            for changed in ["birth", "boot", "pid", "uid", "pgid", "sid"] {
                let mut stale = action.clone();
                match changed {
                    "birth" => {
                        let (boot, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            boot.unwrap(),
                            ticks.unwrap() + 1,
                            pid.unwrap(),
                        );
                    }
                    "boot" => {
                        let (_, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            "different-boot",
                            ticks.unwrap(),
                            pid.unwrap(),
                        );
                    }
                    "pid" => {
                        let (boot, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            boot.unwrap(),
                            ticks.unwrap(),
                            pid.unwrap() + 1,
                        );
                    }
                    "uid" => stale.target.uid ^= 1,
                    "pgid" => stale.target.pgid = Some(stat.pgrp as u32 + 1),
                    "sid" => stale.target.sid = Some(stat.session as u32 + 1),
                    _ => unreachable!(),
                }
                assert!(
                    runner.verify(&stale).is_err(),
                    "{changed}: a matching numeric PID/state cannot verify another identity"
                );
            }
            assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
            assert!(!marker.exists());
        }

        #[test]
        fn planned_signal_delivery_refuses_stale_owner_group_session_and_quality() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_term_child(&marker, false, true);
            let stat = crate::collect::proc_parsers::read_required_proc_stat(child.0.id())
                .expect("owned child identity");
            action.target.pgid = Some(stat.pgrp as u32);
            action.target.sid = Some(stat.session as u32);
            let runner = SignalActionRunner::with_defaults();
            let provider = LiveIdentityProvider::new();
            assert!(provider.revalidate(&action.target).unwrap());

            for changed in [
                "birth",
                "boot",
                "pid",
                "uid",
                "pgid",
                "sid",
                "pid_only",
                "missing_boot",
                "missing_pid",
            ] {
                let mut stale = action.clone();
                match changed {
                    "birth" => {
                        let (boot, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            boot.unwrap(),
                            ticks.unwrap() + 1,
                            pid.unwrap(),
                        );
                    }
                    "boot" => {
                        let (_, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            "different-boot",
                            ticks.unwrap(),
                            pid.unwrap(),
                        );
                    }
                    "pid" => {
                        let (boot, ticks, pid) = parse_start_id(&stale.target.start_id.0);
                        stale.target.start_id = pt_common::StartId::from_linux(
                            boot.unwrap(),
                            ticks.unwrap(),
                            pid.unwrap() + 1,
                        );
                    }
                    "uid" => stale.target.uid ^= 1,
                    "pgid" => stale.target.pgid = Some(stat.pgrp as u32 + 1),
                    "sid" => stale.target.sid = Some(stat.session as u32 + 1),
                    "pid_only" => stale.target.quality = pt_common::IdentityQuality::PidOnly,
                    "missing_boot" => {
                        stale.target.start_id =
                            pt_common::StartId::from_linux("unknown", stat.starttime, child.0.id());
                    }
                    "missing_pid" => {
                        stale.target.start_id = pt_common::StartId(stat.starttime.to_string());
                    }
                    _ => unreachable!(),
                }
                assert!(
                    !provider.revalidate(&stale.target).unwrap(),
                    "{changed}: executor identity revalidation must refuse"
                );
                // The fallback path and later TERM escalation use the same full
                // observation. A different birth proves exit; mutable identity
                // drift must remain an error rather than permission to escalate.
                assert!(runner.check_identity_now(&stale).is_err(), "{changed}");
                if changed == "birth" {
                    assert!(!runner.original_target_still_present(&stale).unwrap());
                } else {
                    assert!(runner.original_target_still_present(&stale).is_err());
                }
                // Process groups are disabled here: even a regression must only
                // ever signal the owned child, never the deliberately stale PGID.
                for kind in [Action::Pause, Action::Kill, Action::Resume] {
                    stale.action = kind;
                    assert!(
                        runner.execute(&stale).is_err(),
                        "{changed}: {kind:?} must refuse before signal delivery"
                    );
                    assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                    assert!(!runner.take_kill_signal_delivered());
                    assert!(!marker.exists());
                }
            }

            // Optional unknown fields retain their documented weaker identity
            // contract; Full quality, in contrast, cannot omit boot or PID.
            let mut partial = action.target.clone();
            partial.quality = pt_common::IdentityQuality::NoBootId;
            partial.start_id =
                pt_common::StartId::from_linux("unknown", stat.starttime, child.0.id());
            partial.pgid = None;
            partial.sid = None;
            assert!(provider.revalidate(&partial).unwrap());

            action.action = Action::Resume;
            runner
                .execute(&action)
                .expect("resume unchanged owned child");
            runner.verify(&action).expect("verify owned child resumed");
            action.action = Action::Pause;
            runner
                .execute(&action)
                .expect("pause unchanged owned child");
            runner.verify(&action).expect("verify owned child paused");
            action.action = Action::Kill;
            runner
                .execute(&action)
                .expect("terminate unchanged owned child");
            runner.verify(&action).expect("verify owned child exited");
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            assert!(runner.take_kill_signal_delivered());
        }

        #[test]
        fn planned_group_delivery_requires_the_recorded_leader_context() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, true);
            let stat = crate::collect::proc_parsers::read_required_proc_stat(child.0.id())
                .expect("owned child identity");
            action.target.sid = Some(stat.session as u32 + 1);
            let runner = SignalActionRunner::new(SignalConfig {
                use_process_groups: true,
                ..SignalConfig::default()
            });
            // The child has its own group and that PGID is never altered. Even
            // unfixed code can only affect this test's owned process group.
            assert_eq!(action.target.pgid, Some(child.0.id()));
            for kind in [Action::Pause, Action::Kill, Action::Resume] {
                action.action = kind;
                assert!(matches!(
                    runner.execute(&action),
                    Err(ActionError::IdentityMismatch)
                ));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                assert!(!runner.take_kill_signal_delivered());
                assert!(!marker.exists());
            }
        }

        #[test]
        fn kill_verification_recognizes_a_replaced_incarnation() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            action.timeouts.verify_ms = 100;
            let (boot, ticks, pid) = parse_start_id(&action.target.start_id.0);
            action.target.start_id =
                pt_common::StartId::from_linux(boot.unwrap(), ticks.unwrap() + 1, pid.unwrap());
            let runner = SignalActionRunner::with_defaults();
            runner
                .verify(&action)
                .expect("a different birth proves the original target is gone");
            // Verification never signals the unrelated current occupant.
            assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
            assert!(!marker.exists());
        }

        #[test]
        fn planned_resume_requires_the_original_live_process() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_term_child(&marker, false, false);
            action.action = Action::Resume;
            let runner = SignalActionRunner::with_defaults();
            runner.execute(&action).expect("resume owned child");
            runner.verify(&action).expect("owned child resumed");
            let mut wrong_owner = action.clone();
            wrong_owner.target.uid ^= 1;
            assert!(matches!(
                runner.verify(&wrong_owner),
                Err(ActionError::IdentityMismatch)
            ));
            let mut wrong_birth = action.clone();
            let (boot, ticks, pid) = parse_start_id(&wrong_birth.target.start_id.0);
            wrong_birth.target.start_id =
                pt_common::StartId::from_linux(boot.unwrap(), ticks.unwrap() + 1, pid.unwrap());
            assert!(matches!(
                runner.verify(&wrong_birth),
                Err(ActionError::IdentityMismatch)
            ));
            assert!(signal_observation_unavailable(child.0.id(), "unreadable state").is_err());
            child.0.kill().expect("kill owned target");
            child.0.wait().expect("reap owned target");
            assert!(matches!(
                runner.verify(&action),
                Err(ActionError::ProcessNotFound)
            ));
            assert!(!runner.take_kill_signal_delivered());
        }

        #[test]
        fn bound_resume_requires_the_original_full_identity_and_a_job_control_stop() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            let mut wrong_owner = action.target.clone();
            wrong_owner.uid ^= 1;
            let mut wrong_birth = action.target.clone();
            let (boot, ticks, pid) = parse_start_id(&wrong_birth.start_id.0);
            wrong_birth.start_id =
                pt_common::StartId::from_linux(boot.unwrap(), ticks.unwrap() + 1, pid.unwrap());
            let mut weak_identity = action.target.clone();
            weak_identity.quality = pt_common::IdentityQuality::NoBootId;
            for stale in [&wrong_owner, &wrong_birth, &weak_identity] {
                assert!(send_bound_signal(stale, libc::SIGCONT).is_err());
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            }
            assert!(send_bound_signal(&action.target, libc::SIGTERM).is_err());
            assert_eq!(signal_state(&action.target).unwrap(), 'T');
            send_bound_signal(&action.target, libc::SIGCONT)
                .expect("resume the pinned owned child");
            runner
                .wait_for_planned_state(
                    &action.target,
                    SignalExpectation::Resumed,
                    Duration::from_secs(1),
                )
                .expect("the original child resumed");
            assert!(send_bound_signal(&action.target, libc::SIGCONT).is_err());
            assert!(!marker.exists());
            assert!(!runner.take_kill_signal_delivered());
        }

        #[test]
        fn journaled_pause_refuses_zero_verification_budget_before_stopping_a_running_child() {
            for (saved_verify_ms, runner_verify_ms) in [(0, 1_000), (1_000, 0)] {
                let dir = tempfile::tempdir().expect("pause session directory");
                let marker = dir.path().join("term-handled");
                let (child, mut action) = stopped_term_child(&marker, false, false);
                let setup = SignalActionRunner::with_defaults();
                setup
                    .resume(child.0.id(), false, None)
                    .expect("resume owned child before pause attempt");
                setup
                    .wait_for_planned_state(
                        &action.target,
                        SignalExpectation::Resumed,
                        Duration::from_secs(5),
                    )
                    .expect("original child is running");
                action.action = Action::Pause;
                action.timeouts.verify_ms = saved_verify_ms;
                let sessions_root = dir.path().join("sessions");
                let session_id = "pt-zero-pause-budget";
                let action_directory = sessions_root.join(session_id).join("action");
                std::fs::create_dir_all(&action_directory).unwrap();
                let journal = Arc::new(
                    ReversalJournal::new(
                        action_directory,
                        session_id,
                        "a".repeat(64),
                        &sessions_root,
                    )
                    .unwrap(),
                );
                let runner = SignalActionRunner::new(SignalConfig {
                    verify_timeout_ms: runner_verify_ms,
                    ..SignalConfig::default()
                })
                .with_reversal_journal(Arc::clone(&journal));

                let error = runner
                    .execute(&action)
                    .expect_err("pause must retain an observation budget for recovery");
                assert!(error.to_string().contains("nonzero verification budget"));
                assert!(journal.inspect(&action).unwrap().is_empty());
                assert!(!journal.directory().exists());
                journal
                    .ensure_signal_stop_unowned(&action.target)
                    .expect("refused pause must not claim stop ownership");
                assert!(matches!(
                    signal_state(&action.target),
                    Ok('R' | 'S' | 'D' | 'I')
                ));
                assert!(runner.take_signal_path().is_none());
                assert!(!runner.take_kill_signal_delivered());
                assert!(!marker.exists());
            }
        }

        #[test]
        fn prepared_pause_aborts_unsent_stops_without_claiming_an_external_stop() {
            for externally_stopped in [false, true] {
                let dir = tempfile::tempdir().expect("pause session directory");
                let marker = dir.path().join("term-handled");
                let (child, mut action) = stopped_term_child(&marker, false, false);
                let setup = SignalActionRunner::with_defaults();
                setup
                    .resume(child.0.id(), false, None)
                    .expect("resume owned child before receipt preparation");
                setup
                    .wait_for_planned_state(
                        &action.target,
                        SignalExpectation::Resumed,
                        Duration::from_secs(5),
                    )
                    .expect("original child is running");
                action.action = Action::Pause;
                let sessions_root = dir.path().join("sessions");
                let session_id = "pt-unsent-pause";
                let action_directory = sessions_root.join(session_id).join("action");
                std::fs::create_dir_all(&action_directory).unwrap();
                let journal = Arc::new(
                    ReversalJournal::new(
                        action_directory,
                        session_id,
                        "a".repeat(64),
                        &sessions_root,
                    )
                    .unwrap(),
                );
                let runner =
                    SignalActionRunner::with_defaults().with_reversal_journal(Arc::clone(&journal));
                let pidfd = PidFd::open(child.0.id())
                    .unwrap()
                    .expect("kernel pidfd support");
                let receipt = journal.prepare_signal_stop(&action, false).unwrap();
                if externally_stopped {
                    setup
                        .send_signal(child.0.id(), libc::SIGSTOP, false)
                        .expect("external stop after receipt preparation");
                    setup
                        .wait_for_planned_state(
                            &action.target,
                            SignalExpectation::Stopped,
                            Duration::from_secs(5),
                        )
                        .expect("external stop completed");
                }
                let deadline = SignalDeadline::new(if externally_stopped { 5_000 } else { 0 });
                let error = runner
                    .apply_prepared_pause(&action, &deadline, &pidfd, false, &receipt)
                    .expect_err("pre-delivery refusal must abort an unsent pause");
                if externally_stopped {
                    assert!(error.to_string().contains("job-control state changed"));
                } else {
                    let timeout_detail = ActionError::Timeout.to_string();
                    assert!(error.to_string().contains(timeout_detail.as_str()));
                }

                let records = journal.inspect(&action).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].status, ReversalStatus::NotApplied);
                assert!(records[0].restorations.is_empty());
                assert!(journal.observe_restoration(&action).unwrap().is_none());
                journal
                    .ensure_signal_stop_unowned(&action.target)
                    .expect("an unsent pause must not retain stop ownership");
                assert!(journal.restore(&action, None).is_err());
                let state = signal_state(&action.target).unwrap();
                if externally_stopped {
                    assert_eq!(state, 'T', "undo cannot release somebody else's stop");
                } else {
                    assert!(matches!(state, 'R' | 'S' | 'D' | 'I'));
                }
                assert!(runner.take_signal_path().is_none());
                assert!(!runner.take_kill_signal_delivered());
                assert!(!marker.exists());
            }
        }

        #[test]
        fn term_grace_finishes_on_reuse_without_signalling_the_current_occupant() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let (boot, ticks, pid) = parse_start_id(&action.target.start_id.0);
            action.target.start_id =
                pt_common::StartId::from_linux(boot.unwrap(), ticks.unwrap() + 1, pid.unwrap());
            let runner = SignalActionRunner::with_defaults();
            assert!(runner
                .wait_for_term_grace(
                    &action,
                    &SignalDeadline::new(100),
                    runner.config.term_grace_ms,
                )
                .unwrap());
            assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
            assert!(!marker.exists());
        }

        #[test]
        fn zombie_reaping_verification_does_not_credit_a_live_same_birth() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            action.action = Action::Restart;
            action.routing = crate::plan::ActionRouting::ZombieToParent;
            action.original_zombie_target = Some(action.target.clone());
            action.timeouts.verify_ms = 100;
            let runner = SignalActionRunner::with_defaults();
            assert!(
                runner.verify_zombie_reaped(&action).is_err(),
                "a readable live target with the recorded birth was not reaped"
            );
            assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
        }

        #[test]
        fn stopped_kill_runs_sigterm_handler_before_escalation() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();

            runner.execute(&action).expect("terminate stopped child");
            runner.verify(&action).expect("child exited");
            let status = child.0.wait().expect("reap owned child");
            assert!(
                status.success(),
                "TERM handler should exit cleanly: {status}"
            );
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            assert!(runner.take_kill_signal_delivered());
            let outcome = runner.take_signal_outcome().expect("delivery evidence");
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Caught);
            assert!(outcome.sigterm_delivered);
            assert!(outcome.sigcont_delivered);
            assert!(!outcome.sigkill_delivered);
            assert!(outcome.escalation_reason.is_none());
            assert!(outcome.observed_grace_ms.is_some());
            assert!(
                runner.take_signal_outcome().is_none(),
                "consumed exactly once"
            );
        }

        #[test]
        fn stopped_kill_skips_futile_grace_only_after_delivering_ignored_sigterm() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, true, false);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 10,
                ..SignalConfig::default()
            });

            let started = Instant::now();
            runner
                .execute(&action)
                .expect("terminate TERM-ignoring child");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "explicit SIGTERM ignore must not wait the normal five-second grace"
            );
            runner
                .verify(&action)
                .expect("child exited after escalation");
            let status = child.0.wait().expect("reap owned child");
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert!(!marker.exists());
            assert!(runner.take_kill_signal_delivered());
            let outcome = runner.take_signal_outcome().expect("delivery evidence");
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Ignored);
            assert_eq!(outcome.sigterm_recheck, Some(SignalDisposition::Ignored));
            assert!(outcome.sigterm_delivered, "TERM always precedes escalation");
            assert!(outcome.sigkill_delivered);
            assert_eq!(
                outcome.escalation_reason,
                Some(SignalEscalationReason::SigtermIgnored)
            );
            assert_eq!(outcome.configured_grace_ms, 5_000);
            assert!(outcome.observed_grace_ms.unwrap() < outcome.configured_grace_ms);
            let json = serde_json::to_value(outcome).unwrap();
            assert_eq!(json["escalation_reason"], "sigterm_ignored");
        }

        #[test]
        fn caught_sigterm_retains_grace_for_a_slow_cleanup_handler() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_signal_child(
                "trap 'sleep 2; printf \"term handled\\n\" > \"$1\"; exit 0' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                &marker,
                false,
            );
            let runner = SignalActionRunner::with_defaults();
            runner.execute(&action).expect("allow slow TERM cleanup");
            runner.verify(&action).expect("cleanup finished");
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            let outcome = runner.take_signal_outcome().expect("delivery evidence");
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Caught);
            assert!(outcome.sigterm_delivered);
            assert!(!outcome.sigkill_delivered);
            assert!(outcome.escalation_reason.is_none());
            assert!(outcome.observed_grace_ms.unwrap() >= 2_000);
        }

        #[test]
        fn approved_grace_overrides_later_runner_config_for_slow_cleanup() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_signal_child(
                "trap 'sleep 2; printf \"term handled\\n\" > \"$1\"; exit 0' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                &marker,
                false,
            );
            action.timeouts.term_grace_ms = Some(12_500);
            action.timeouts.execute_ms = 17_500;
            let saved = serde_json::to_string(&action).unwrap();
            let approved: PlanAction = serde_json::from_str(&saved).unwrap();
            // Even an explicitly shorter later runner configuration cannot
            // replace the cleanup allowance saved with the approved action.
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 25,
                poll_interval_ms: 10,
                ..SignalConfig::default()
            });
            runner.execute(&approved).expect("honor approved cleanup");
            runner.verify(&approved).expect("cleanup finished");
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            let outcome = runner.take_signal_outcome().unwrap();
            assert_eq!(outcome.configured_grace_ms, 12_500);
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Caught);
            assert!(outcome.sigterm_delivered);
            assert!(!outcome.sigkill_delivered);
            assert!(outcome.escalation_reason.is_none());
            assert!(outcome.observed_grace_ms.unwrap() >= 2_000);
        }

        #[test]
        fn approved_short_grace_escalates_a_caught_nonexiting_handler() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_signal_child(
                "trap ':' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                &marker,
                false,
            );
            action.timeouts.term_grace_ms = Some(100);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 10,
                ..SignalConfig::default()
            });
            let started = Instant::now();
            runner.execute(&action).expect("use approved shorter grace");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the saved 100ms allowance must replace the five-second default"
            );
            runner.verify(&action).expect("verify escalated exit");
            assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
            let outcome = runner.take_signal_outcome().unwrap();
            assert_eq!(outcome.configured_grace_ms, 100);
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Caught);
            assert!(outcome.sigterm_delivered);
            assert!(outcome.sigkill_delivered);
            assert_eq!(
                outcome.escalation_reason,
                Some(SignalEscalationReason::GraceExpired)
            );
            assert!(outcome.observed_grace_ms.unwrap() >= 100);
        }

        #[test]
        fn approved_grace_exceeding_execution_budget_never_sends_early_kill() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_signal_child(
                "trap ':' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                &marker,
                false,
            );
            action.timeouts.term_grace_ms = Some(5_000);
            action.timeouts.execute_ms = 30;
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 1,
                poll_interval_ms: 5_000,
                ..SignalConfig::default()
            });
            let started = Instant::now();
            assert!(matches!(runner.execute(&action), Err(ActionError::Timeout)));
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(child.0.try_wait().unwrap().is_none(), "no early SIGKILL");
            let outcome = runner.take_signal_outcome().unwrap();
            assert_eq!(outcome.configured_grace_ms, 5_000);
            assert!(outcome.sigterm_delivered);
            assert!(!outcome.sigkill_delivered);
            assert!(outcome.escalation_reason.is_none());
        }

        #[test]
        fn malformed_approved_grace_is_rejected_before_any_signal() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            for (kind, grace_ms) in [
                (Action::Kill, 0),
                (Action::Kill, 300_001),
                (Action::Kill, u64::MAX),
                (Action::Pause, 5_000),
                (Action::Resume, 5_000),
            ] {
                action.action = kind;
                action.timeouts.term_grace_ms = Some(grace_ms);
                assert!(matches!(runner.execute(&action), Err(ActionError::Failed(_))));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                assert!(!runner.take_kill_signal_delivered());
                assert!(runner.take_signal_path().is_none());
                assert!(runner.take_signal_outcome().is_none());
                assert!(!marker.exists());
            }
            action.action = Action::Kill;
            action.timeouts.term_grace_ms = Some(5_000);
            for routing in [
                ActionRouting::Supervisor,
                ActionRouting::ZombieToParent,
                ActionRouting::ZombieToSupervisor,
                ActionRouting::ZombieInvestigateOnly,
            ] {
                action.routing = routing;
                assert!(matches!(runner.execute(&action), Err(ActionError::Failed(_))));
                assert!(matches!(
                    runner.nudge_parent_to_reap(&action),
                    Err(ActionError::Failed(_))
                ));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                assert!(!runner.take_kill_signal_delivered());
                assert!(runner.take_signal_path().is_none());
                assert!(runner.take_signal_outcome().is_none());
                assert!(!marker.exists());
            }
            action.routing = ActionRouting::Direct;
            action.original_zombie_target = Some(action.target.clone());
            assert!(matches!(runner.execute(&action), Err(ActionError::Failed(_))));
            assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            assert!(runner.take_signal_outcome().is_none());
        }

        #[test]
        fn changed_sigterm_handler_preserves_grace_after_an_ignored_delivery() {
            use std::io::Write;

            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_signal_child(
                "trap '' TERM\nkill -STOP \"$$\"\nread -r line\ntrap ':' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                &marker,
                false,
            );
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100,
                poll_interval_ms: 5,
                ..SignalConfig::default()
            });
            let before = runner.observed_sigterm_disposition(&action);
            assert_eq!(before, SignalDisposition::Ignored);
            runner
                .send_signal(child.0.id(), libc::SIGTERM, false)
                .unwrap();
            runner
                .send_signal(child.0.id(), libc::SIGCONT, false)
                .unwrap();
            child
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"install handler\n")
                .unwrap();
            let ready = Instant::now();
            loop {
                if runner.observed_sigterm_disposition(&action) == SignalDisposition::Caught
                    && runner.get_process_state(child.0.id()) == Some('T')
                {
                    break;
                }
                assert!(ready.elapsed() < Duration::from_secs(5), "handler changed");
                thread::sleep(Duration::from_millis(5));
            }

            let mut outcome = SignalExecutionOutcome {
                sigterm_disposition: before,
                sigterm_recheck: None,
                configured_grace_ms: 100,
                observed_grace_ms: None,
                sigterm_delivered: true,
                sigcont_delivered: true,
                sigkill_delivered: false,
                escalation_reason: None,
                execution_elapsed_ms: 0,
            };
            let started = Instant::now();
            assert!(!runner
                .wait_for_term_or_escalation(
                    &action,
                    &SignalDeadline::new(2_000),
                    false,
                    &mut outcome,
                )
                .unwrap());
            assert!(started.elapsed() >= Duration::from_millis(100));
            assert_eq!(outcome.sigterm_recheck, Some(SignalDisposition::Caught));
            assert_eq!(
                outcome.escalation_reason,
                Some(SignalEscalationReason::GraceExpired)
            );
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(
                !outcome.sigkill_delivered,
                "waiting never sends SIGKILL itself"
            );
        }

        #[test]
        fn sigterm_disposition_cannot_be_borrowed_from_another_incarnation() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (_child, mut action) = stopped_term_child(&marker, true, false);
            let runner = SignalActionRunner::with_defaults();
            assert_eq!(
                runner.observed_sigterm_disposition(&action),
                SignalDisposition::Ignored
            );
            for quality in [
                pt_common::IdentityQuality::NoBootId,
                pt_common::IdentityQuality::PidOnly,
            ] {
                let mut weaker = action.clone();
                weaker.target.quality = quality;
                assert_eq!(
                    runner.observed_sigterm_disposition(&weaker),
                    SignalDisposition::Unknown,
                    "weaker saved identities must retain ordinary TERM grace"
                );
            }
            action.target.uid ^= 1;
            assert_eq!(
                runner.observed_sigterm_disposition(&action),
                SignalDisposition::Unknown
            );
            assert!(matches!(
                runner.execute(&action),
                Err(ActionError::IdentityMismatch)
            ));
            let outcome = runner.take_signal_outcome().unwrap();
            assert!(!outcome.sigterm_delivered);
            assert!(!outcome.sigkill_delivered);
            assert!(outcome.observed_grace_ms.is_none());
        }

        #[test]
        fn exhausted_plan_execution_budget_sends_no_signals() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            action.timeouts.execute_ms = 0;

            for kind in [Action::Kill, Action::Pause, Action::Resume] {
                action.action = kind;
                assert!(matches!(runner.execute(&action), Err(ActionError::Timeout)));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                assert!(!runner.take_kill_signal_delivered());
                assert!(runner.take_signal_path().is_none());
                if kind == Action::Kill {
                    let outcome = runner.take_signal_outcome().unwrap();
                    assert!(!outcome.sigterm_delivered);
                    assert!(!outcome.sigkill_delivered);
                    assert!(outcome.observed_grace_ms.is_none());
                } else {
                    assert!(runner.take_signal_outcome().is_none());
                }
            }
            assert!(matches!(
                runner.nudge_parent_to_reap(&action),
                Err(ActionError::Timeout)
            ));
            assert!(!marker.exists());
        }

        #[test]
        fn short_plan_budget_never_accelerates_sigkill() {
            for own_group in [false, true] {
                let dir = tempfile::tempdir().expect("marker directory");
                let marker = dir.path().join("term-handled");
                let (mut child, mut action) = if own_group {
                    stopped_term_child(&marker, true, true)
                } else {
                    // A handler that chooses not to exit is caught, not SIG_IGN;
                    // it retains the configured grace even under a short budget.
                    stopped_signal_child(
                        "trap ':' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || :; done",
                        &marker,
                        false,
                    )
                };
                let runner = SignalActionRunner::new(SignalConfig {
                    term_grace_ms: 5_000,
                    poll_interval_ms: 5_000,
                    use_process_groups: own_group,
                    ..SignalConfig::default()
                });
                action.timeouts.execute_ms = 30;

                let started = Instant::now();
                assert!(matches!(runner.execute(&action), Err(ActionError::Timeout)));
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "polling must be bounded by the saved execution budget"
                );
                assert!(child.0.try_wait().unwrap().is_none(), "no early SIGKILL");
                assert_eq!(
                    runner.get_process_state(child.0.id()) == Some('T'),
                    own_group,
                    "only the individually verified process may be resumed"
                );
                assert!(runner.take_kill_signal_delivered(), "TERM still counts");
                assert!(!marker.exists());
                let outcome = runner.take_signal_outcome().unwrap();
                assert!(outcome.sigterm_delivered);
                assert!(!outcome.sigkill_delivered);
                assert!(outcome.escalation_reason.is_none());
                assert!(outcome.observed_grace_ms.is_some());
            }
        }

        #[test]
        fn short_plan_budget_still_allows_graceful_exit() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 1,
                ..SignalConfig::default()
            });
            action.timeouts.execute_ms = 1_000;

            runner
                .execute(&action)
                .expect("TERM handler exits in budget");
            runner.verify(&action).expect("observe graceful exit");
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            assert!(runner.take_kill_signal_delivered());
        }

        #[test]
        fn verification_honors_plan_budget_and_caps_polling() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 5_000,
                ..SignalConfig::default()
            });
            action.timeouts.verify_ms = 25;

            for kind in [Action::Kill, Action::Resume] {
                action.action = kind;
                let started = Instant::now();
                assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
                assert!(started.elapsed() < Duration::from_secs(2));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            }
            action.action = Action::Pause;
            runner
                .verify(&action)
                .expect("observe already stopped child");
            action.timeouts.verify_ms = 0;
            assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
            assert!(!runner.take_kill_signal_delivered());
        }

        #[test]
        fn verification_retains_stricter_runner_budget() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (_child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                verify_timeout_ms: 25,
                poll_interval_ms: 5_000,
                ..SignalConfig::default()
            });
            action.timeouts.verify_ms = u64::MAX;

            let started = Instant::now();
            assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
            assert!(started.elapsed() < Duration::from_secs(2));
        }

        #[test]
        fn stopped_kill_does_not_resume_an_unverified_process_group() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, false, true);
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100,
                poll_interval_ms: 10,
                use_process_groups: true,
                ..SignalConfig::default()
            });

            runner.execute(&action).expect("terminate owned group");
            runner.verify(&action).expect("group leader exited");
            assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
            assert!(
                !marker.exists(),
                "a leader's state must not authorize group CONT"
            );
            let outcome = runner.take_signal_outcome().unwrap();
            assert_eq!(outcome.sigterm_disposition, SignalDisposition::Unknown);
            assert_eq!(outcome.sigterm_recheck, None);
            assert_eq!(
                outcome.escalation_reason,
                Some(SignalEscalationReason::GraceExpired)
            );
            assert!(outcome.observed_grace_ms.unwrap() >= 100);
            assert!(outcome.sigkill_delivered);
        }

        #[test]
        fn stopped_kill_does_not_signal_a_changed_identity() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            let pid = child.0.id();
            let other_start = crate::collect::proc_parsers::read_required_proc_stat(pid)
                .unwrap()
                .starttime
                + 1;
            action.target.start_id = pt_common::StartId(format!("unknown:{other_start}:{pid}"));

            assert!(matches!(
                runner.execute(&action),
                Err(ActionError::IdentityMismatch)
            ));
            assert_eq!(runner.get_process_state(pid), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
            assert!(!marker.exists());
        }

        #[test]
        fn live_identity_provider_validates_self() {
            let provider = LiveIdentityProvider::new();
            let pid = std::process::id();

            // Get our start_id
            let start_id = provider.read_start_id(pid).expect("read start_id");
            let uid = provider.read_uid(pid).expect("read uid");

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(start_id),
                uid,
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(valid, "self should validate");
        }

        #[test]
        fn live_identity_provider_rejects_wrong_uid() {
            let provider = LiveIdentityProvider::new();
            let pid = std::process::id();

            let start_id = provider.read_start_id(pid).expect("read start_id");
            let uid = provider.read_uid(pid).expect("read uid");

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(start_id),
                uid: uid + 1, // Wrong UID
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(!valid, "wrong uid should not validate");
        }

        #[test]
        fn live_identity_provider_rejects_nonexistent() {
            let provider = LiveIdentityProvider::new();

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(999_999_999),
                start_id: pt_common::StartId("fake".to_string()),
                uid: 1000,
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(!valid, "nonexistent should not validate");
        }

        #[test]
        fn test_zombie_detection() {
            use std::process::Command;

            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.wait();
                }
            }
            // Spawn a process that exits immediately
            // It will become a zombie because we hold the handle and don't wait() yet
            let mut child = OwnedChild(Command::new("true").spawn().expect("failed to spawn true"));

            let pid = child.0.id();
            let runner = SignalActionRunner::with_defaults();

            // Observe this owned child's actual exit without reaping it. Fixture
            // startup is not a signal-runner latency measurement; the original
            // 500 ms effect-verification deadline below remains unchanged.
            // SAFETY: siginfo_t is a C integer/union record with a valid zero
            // representation. waitid fills its child-status fields on success.
            let mut exit_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            loop {
                // SAFETY: pid is our still-unreaped direct child. WNOWAIT leaves
                // the exited child available for the real /proc and runner checks.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid,
                        &mut exit_info,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    let _ = child.0.wait();
                    panic!("observe owned child exit without reaping: {error}");
                }
            }
            // SAFETY: successful WEXITED waitid initialized child-status fields.
            assert_eq!(unsafe { exit_info.si_pid() }, pid as libc::pid_t);
            assert_eq!(exit_info.si_code, libc::CLD_EXITED);
            // SAFETY: CLD_EXITED makes si_status the child's actual exit status.
            assert_eq!(unsafe { exit_info.si_status() }, 0);
            assert_eq!(runner.get_process_state(pid), Some('Z'));
            assert!(runner.process_exists(pid), "owned zombie still exists");

            // Verify wait_for_state_change considers it exited
            // Without the fix, this would timeout because process_exists() is true for zombies
            let result = runner.wait_for_state_change(
                pid,
                true, // expect_exit
                None,
                Duration::from_millis(500),
            );

            assert!(result.is_ok(), "Zombie should be considered exited");

            // Cleanup
            assert!(child.0.wait().expect("reap the owned zombie").success());
        }
    }
}
