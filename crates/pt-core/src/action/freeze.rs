//! Cgroup v2 freeze/unfreeze action execution.
//!
//! Implements process freezing using cgroup v2 freezer with:
//! - TOCTOU safety via identity revalidation
//! - Bounded verification of completed transitions via cgroup.events
//! - Support for same-cgroup blast radius control
//!
//! The cgroup freezer is more robust than SIGSTOP because:
//! - Works at cgroup level (entire process tree)
//! - No userspace signal handler required
//! - Cleaner state management via cgroup.events

use super::executor::{ActionError, ActionRunner};
#[cfg(target_os = "linux")]
use super::reversal::{PreparedReversal, ReversalJournal, ReversalStatus, ReversalValue};
#[cfg(all(target_os = "linux", test))]
use crate::collect::cgroup::collect_cgroup_details;
#[cfg(target_os = "linux")]
use crate::decision::Action;
use crate::plan::PlanAction;
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use tracing::{debug, trace};

/// The requested freezer state and the kernel's completed effective state.
///
/// `cgroup.freeze` is only a request. In particular, a thaw request does not
/// thaw a cgroup while an ancestor remains frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FreezerState {
    pub(crate) requested: bool,
    pub(crate) frozen: bool,
}

/// Read both freezer facts without changing the cgroup. Missing or malformed
/// acknowledgement data is an error, never evidence that an action completed.
pub(crate) fn read_freezer_state(directory: &Path) -> Result<FreezerState, ActionError> {
    let request_path = directory.join("cgroup.freeze");
    read_freezer_state_with(
        || {
            let request = fs::read_to_string(&request_path).map_err(|error| {
                ActionError::Failed(format!("cannot read {}: {error}", request_path.display()))
            })?;
            parse_freezer_bit(request.trim(), "cgroup.freeze")
        },
        || read_frozen_event(&directory.join("cgroup.events")),
    )
}

/// The request and acknowledgement are separate files. A concurrent request
/// change must not fabricate agreement between states observed at different times.
fn read_freezer_state_with(
    mut read_request: impl FnMut() -> Result<bool, ActionError>,
    read_frozen: impl FnOnce() -> Result<bool, ActionError>,
) -> Result<FreezerState, ActionError> {
    let requested = read_request()?;
    let frozen = read_frozen()?;
    if read_request()? != requested {
        return Err(ActionError::Failed(
            "freezer request changed during observation".to_string(),
        ));
    }
    Ok(FreezerState { requested, frozen })
}

fn parse_freezer_bit(value: &str, source: &str) -> Result<bool, ActionError> {
    match value {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(ActionError::Failed(format!(
            "unexpected {source} value: {value:?}"
        ))),
    }
}

/// Read the completed state, refusing missing, ambiguous, or malformed evidence.
fn parse_frozen_event(content: &str) -> Result<bool, ActionError> {
    let mut frozen = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("frozen") {
            continue;
        }
        let state = match (fields.next(), fields.next()) {
            (Some("0"), None) => false,
            (Some("1"), None) => true,
            _ => {
                return Err(ActionError::Failed(
                    "malformed frozen field in cgroup.events".to_string(),
                ));
            }
        };
        if frozen.replace(state).is_some() {
            return Err(ActionError::Failed(
                "duplicate frozen field in cgroup.events".to_string(),
            ));
        }
    }
    frozen.ok_or_else(|| ActionError::Failed("missing frozen field in cgroup.events".to_string()))
}

fn read_frozen_event(events_path: &Path) -> Result<bool, ActionError> {
    let content = fs::read_to_string(events_path).map_err(|error| {
        ActionError::Failed(format!("cannot read {}: {error}", events_path.display()))
    })?;
    parse_frozen_event(&content)
}

/// Observe immediately, then poll without sleeping beyond the remaining budget.
/// A zero timeout permits one observation but never waits for a transition.
pub(crate) fn wait_for_frozen_state(
    expected: bool,
    timeout: Duration,
    mut observe: impl FnMut() -> Result<FreezerState, ActionError>,
) -> Result<(), ActionError> {
    let started = Instant::now();
    loop {
        let state = observe()?;
        if state.requested == expected && state.frozen == expected {
            return Ok(());
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ActionError::Timeout);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
        if started.elapsed() >= timeout {
            return Err(ActionError::Timeout);
        }
    }
}

/// Freeze action runner configuration.
#[derive(Debug, Clone)]
pub struct FreezeConfig {
    /// Whether to verify cgroup v2 availability before executing.
    pub verify_capability: bool,
    /// Maximum time in milliseconds to wait for a completed freezer transition.
    /// The action's verification timeout may impose a shorter deadline.
    pub propagation_timeout_ms: u64,
}

impl Default for FreezeConfig {
    fn default() -> Self {
        Self {
            verify_capability: true,
            propagation_timeout_ms: 100,
        }
    }
}

/// Freeze action runner using cgroup v2 freezer.
#[derive(Debug)]
pub struct FreezeActionRunner {
    config: FreezeConfig,
    /// Verification belongs to the exact action and cgroup used by execution,
    /// including changes that occur before verification starts.
    #[cfg(target_os = "linux")]
    applied: Mutex<Option<AppliedFreeze>>,
    #[cfg(target_os = "linux")]
    reversal_journal: Option<Arc<ReversalJournal>>,
    #[cfg(target_os = "linux")]
    reversal_ownership_root: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct AppliedFreeze {
    action_id: String,
    identity: pt_common::ProcessIdentity,
    frozen: bool,
    scope: FreezerScope,
    reversal: Option<PreparedReversal>,
}

#[cfg(target_os = "linux")]
impl AppliedFreeze {
    fn check_action(&self, action: &PlanAction, frozen: bool) -> Result<(), ActionError> {
        let expected_action = if self.frozen {
            Action::Freeze
        } else {
            Action::Unfreeze
        };
        if self.action_id != action.action_id
            || self.identity != action.target
            || self.frozen != frozen
            || action.action != expected_action
        {
            return Err(ActionError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Hold the original cgroup directory open so a removed/recreated pathname
/// cannot masquerade as the cgroup that received the freezer request.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct FreezerScope {
    cgroup_path: String,
    directory: PathBuf,
    handle: fs::File,
}

#[cfg(target_os = "linux")]
impl FreezerScope {
    fn open(cgroup_path: String, directory: PathBuf) -> Result<Self, ActionError> {
        let handle = fs::File::open(&directory).map_err(|error| {
            ActionError::Failed(format!(
                "cannot open cgroup {}: {error}",
                directory.display()
            ))
        })?;
        let scope = Self {
            cgroup_path,
            directory,
            handle,
        };
        scope.check_current_path(&scope.cgroup_path)?;
        Ok(scope)
    }

    fn pinned_directory(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
    }

    fn check_current_path(&self, current_path: &str) -> Result<(), ActionError> {
        use std::os::unix::fs::MetadataExt;
        if current_path != self.cgroup_path {
            return Err(ActionError::Failed(
                "target cgroup changed since freezer execution".to_string(),
            ));
        }
        let original = self.handle.metadata().map_err(|error| {
            ActionError::Failed(format!("cannot inspect pinned freezer cgroup: {error}"))
        })?;
        let current = fs::symlink_metadata(&self.directory).map_err(|error| {
            ActionError::Failed(format!(
                "cannot inspect freezer cgroup {}: {error}",
                self.directory.display()
            ))
        })?;
        if !original.is_dir()
            || !current.is_dir()
            || original.dev() != current.dev()
            || original.ino() != current.ino()
        {
            return Err(ActionError::Failed(
                "freezer cgroup directory changed since execution".to_string(),
            ));
        }
        Ok(())
    }

    fn observe(
        &self,
        mut current_path: impl FnMut() -> Result<String, ActionError>,
    ) -> Result<FreezerState, ActionError> {
        self.check_current_path(&current_path()?)?;
        let state = read_freezer_state(&self.pinned_directory());
        self.check_current_path(&current_path()?)?;
        state
    }
}

impl FreezeActionRunner {
    pub fn new(config: FreezeConfig) -> Self {
        Self {
            config,
            #[cfg(target_os = "linux")]
            applied: Mutex::new(None),
            #[cfg(target_os = "linux")]
            reversal_journal: None,
            #[cfg(target_os = "linux")]
            reversal_ownership_root: None,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(FreezeConfig::default())
    }

    /// Record exact previous requests durably at the actual controller writer.
    #[cfg(target_os = "linux")]
    pub fn with_reversal_journal(mut self, journal: Arc<ReversalJournal>) -> Self {
        self.reversal_journal = Some(journal);
        self
    }

    /// Protect existing durable owners without promising undo for this caller.
    #[cfg(target_os = "linux")]
    pub fn with_reversal_ownership_guard(mut self, sessions_root: PathBuf) -> Self {
        self.reversal_ownership_root = Some(sessions_root);
        self
    }

    /// Write freeze state to cgroup.freeze.
    ///
    /// `frozen=true` freezes the cgroup, `frozen=false` unfreezes it.
    #[cfg(target_os = "linux")]
    fn write_freeze_state(&self, freeze_path: &Path, frozen: bool) -> Result<(), ActionError> {
        let value = if frozen { "1" } else { "0" };

        trace!(path = %freeze_path.display(), value = value, "writing freeze state");

        fs::write(freeze_path, value).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => ActionError::PermissionDenied,
            _ => ActionError::Failed(format!("cannot write {}: {}", freeze_path.display(), e)),
        })
    }

    /// Execute a freeze action.
    #[cfg(target_os = "linux")]
    fn execute_freeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.execute_frozen_state(action, true)
    }

    /// Execute an unfreeze action.
    #[cfg(target_os = "linux")]
    fn execute_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.execute_frozen_state(action, false)
    }

    #[cfg(target_os = "linux")]
    fn execute_frozen_state(&self, action: &PlanAction, frozen: bool) -> Result<(), ActionError> {
        let mut applied = self.applied.lock().map_err(|_| {
            ActionError::Failed("freezer execution record is unavailable".to_string())
        })?;
        // A failed attempt must not leave an earlier success available to verify.
        *applied = None;
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        let directory = PathBuf::from(format!("/sys/fs/cgroup{checked_path}"));
        let scope = FreezerScope::open(checked_path, directory)?;
        scope.check_current_path(&super::dispatch::ensure_cgroup_target(&action.target)?)?;
        debug!(pid, frozen, "executing freezer request");

        if self.reversal_journal.is_none() {
            if let Some(sessions_root) = &self.reversal_ownership_root {
                super::reversal::ensure_control_unowned(
                    sessions_root,
                    &scope.cgroup_path,
                    &scope.handle,
                    ReversalValue::Freeze { requested: frozen },
                )?;
            }
        }

        let before = self
            .reversal_journal
            .as_ref()
            .map(|_| scope.observe(|| super::dispatch::ensure_cgroup_target(&action.target)))
            .transpose()?;
        let reversal = match (&self.reversal_journal, before) {
            (Some(journal), Some(before)) => Some(
                journal.prepare(
                    action,
                    &scope.cgroup_path,
                    &scope.handle,
                    ReversalValue::Freeze {
                        requested: before.requested,
                    },
                    ReversalValue::Freeze { requested: frozen },
                    self.config
                        .propagation_timeout_ms
                        .min(action.timeouts.verify_ms),
                )?,
            ),
            _ => None,
        };
        let execution = (|| {
            scope.check_current_path(&super::dispatch::ensure_cgroup_target(&action.target)?)?;
            if let Some(before) = before {
                if read_freezer_state(&scope.pinned_directory())?.requested != before.requested {
                    return Err(ActionError::Failed(
                        "freezer request changed before the journaled write".to_string(),
                    ));
                }
            }
            // Write through the pinned directory, never a replacement at its old path.
            self.write_freeze_state(&scope.pinned_directory().join("cgroup.freeze"), frozen)?;
            scope.check_current_path(&super::dispatch::ensure_cgroup_target(&action.target)?)
        })();
        match &reversal {
            Some(receipt) => receipt.finish(execution, ReversalStatus::Applied)?,
            None => execution?,
        }
        *applied = Some(AppliedFreeze {
            action_id: action.action_id.clone(),
            identity: action.target.clone(),
            frozen,
            scope,
            reversal,
        });
        Ok(())
    }

    /// Verify a freeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_freeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.verify_frozen_state(action, true)
    }

    /// Verify an unfreeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.verify_frozen_state(action, false)
    }

    #[cfg(target_os = "linux")]
    fn verify_frozen_state(&self, action: &PlanAction, frozen: bool) -> Result<(), ActionError> {
        let applied = self.applied.lock().map_err(|_| {
            ActionError::Failed("freezer execution record is unavailable".to_string())
        })?;
        let record = applied.as_ref().ok_or_else(|| {
            ActionError::Failed(
                "cannot verify freezer state without an executed request".to_string(),
            )
        })?;
        record.check_action(action, frozen)?;
        let pid = action.target.pid.0;
        let timeout = Duration::from_millis(
            self.config
                .propagation_timeout_ms
                .min(action.timeouts.verify_ms),
        );

        // cgroup.freeze records the request. Only cgroup.events reports that
        // freezing has completed, or that an ancestor no longer keeps it frozen.
        // Every sample rechecks the complete guard and the executed cgroup,
        // including the final sample that can establish a completed transition.
        let verification = (|| {
            record
                .scope
                .check_current_path(&super::dispatch::ensure_cgroup_target(&action.target)?)?;
            wait_for_frozen_state(frozen, timeout, || {
                record
                    .scope
                    .observe(|| super::dispatch::ensure_cgroup_target(&action.target))
            })
        })();
        match &record.reversal {
            Some(receipt) => receipt.finish(verification, ReversalStatus::Verified)?,
            None => verification?,
        }

        debug!(pid, frozen, "freezer transition verified");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl ActionRunner for FreezeActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Freeze => self.execute_freeze(action),
            Action::Unfreeze => self.execute_unfreeze(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Renice
            | Action::Quarantine
            | Action::Unquarantine => Err(ActionError::Failed(format!(
                "{:?} requires signal/setpriority support, not cgroup freeze",
                action.action
            ))),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Freeze => self.verify_freeze(action),
            Action::Unfreeze => self.verify_unfreeze(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Renice
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl ActionRunner for FreezeActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup freeze not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup freeze not supported on this platform".to_string(),
        ))
    }
}

/// Check if cgroup v2 freeze is available for a process.
///
/// Reports the same identity, isolation, access and acknowledgement facts used
/// by planning. Execution still rechecks them before a transition.
#[cfg(target_os = "linux")]
pub fn is_freeze_available(pid: u32) -> bool {
    let Some(identity) = super::dispatch::read_cgroup_identity(pid) else {
        return false;
    };
    super::dispatch::cgroup_action_feasibility(&identity).is_allowed(Action::Freeze)
}

#[cfg(not(target_os = "linux"))]
pub fn is_freeze_available(_pid: u32) -> bool {
    false
}

/// Read the same request/acknowledgement pair used by verification, without
/// requesting a transition. Unwritable or unverifiable freezers are infeasible.
#[cfg(target_os = "linux")]
pub(super) fn check_freeze_capability(directory: &Path) -> Result<(), ActionError> {
    super::dispatch::check_controller_access(&directory.join("cgroup.freeze"))?;
    read_freezer_state(directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_config_defaults() {
        let config = FreezeConfig::default();
        assert!(config.verify_capability);
        assert_eq!(config.propagation_timeout_ms, 100);
    }

    #[test]
    fn runner_can_be_created() {
        let runner = FreezeActionRunner::with_defaults();
        assert!(runner.config.verify_capability);
    }

    #[test]
    fn frozen_event_accepts_completed_states_and_other_fields() {
        assert!(parse_frozen_event("populated 1\nfrozen 1\n").unwrap());
        assert!(!parse_frozen_event("frozen\t0\npopulated 1\nfuture_event 2\n").unwrap());
    }

    #[test]
    fn frozen_event_rejects_missing_malformed_and_duplicate_fields() {
        for content in [
            "",
            "populated 1\n",
            "frozen\n",
            "frozen 2\n",
            "frozen true\n",
            "frozen 01\n",
            "frozen 1 extra\n",
            "frozen 0\nfrozen 1\n",
            "frozen 1\nfrozen 1\n",
        ] {
            assert!(
                matches!(parse_frozen_event(content), Err(ActionError::Failed(_))),
                "invalid freezer evidence accepted: {content:?}"
            );
        }
    }

    #[test]
    fn freezer_request_does_not_prove_transition_completion() {
        let dir = tempfile::tempdir().unwrap();
        let freeze_path = dir.path().join("cgroup.freeze");
        let events_path = dir.path().join("cgroup.events");
        for (request, events, expected) in [
            ("1\n", "populated 1\nfrozen 0\n", true),
            ("0\n", "populated 1\nfrozen 1\n", false),
        ] {
            // A completed write only records intent. In particular an ancestor
            // may keep the target frozen after its own freeze request is cleared.
            fs::write(&freeze_path, request).unwrap();
            fs::write(&events_path, events).unwrap();
            assert_eq!(
                read_freezer_state(dir.path()).unwrap(),
                FreezerState {
                    requested: expected,
                    frozen: !expected,
                }
            );
            assert!(matches!(
                wait_for_frozen_state(expected, Duration::ZERO, || {
                    read_freezer_state(dir.path())
                }),
                Err(ActionError::Timeout)
            ));
        }
    }

    #[test]
    fn freezer_completion_is_observed_without_a_fixed_delay() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        for frozen in [true, false] {
            fs::write(
                dir.path().join("cgroup.freeze"),
                u8::from(frozen).to_string(),
            )
            .unwrap();
            fs::write(
                &events_path,
                format!("populated 1\nfrozen {}\n", u8::from(frozen)),
            )
            .unwrap();
            assert!(wait_for_frozen_state(frozen, Duration::ZERO, || {
                read_freezer_state(dir.path())
            })
            .is_ok());
        }
    }

    #[test]
    fn freezer_completion_polls_until_each_transition() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        let transition_delay = Duration::from_millis(20);
        for frozen in [true, false] {
            fs::write(
                dir.path().join("cgroup.freeze"),
                u8::from(frozen).to_string(),
            )
            .unwrap();
            fs::write(
                &events_path,
                format!("populated 1\nfrozen {}\n", u8::from(!frozen)),
            )
            .unwrap();
            let pending_path = dir.path().join("completed.events");
            fs::write(
                &pending_path,
                format!("populated 1\nfrozen {}\n", u8::from(frozen)),
            )
            .unwrap();
            let destination = events_path.clone();
            let started = Instant::now();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(transition_delay);
                // Replace the complete fixture atomically; readers must never
                // accept a truncated frozen field as evidence of completion.
                fs::rename(pending_path, destination).unwrap();
            });
            let result = wait_for_frozen_state(frozen, Duration::from_secs(2), || {
                read_freezer_state(dir.path())
            });
            let elapsed = started.elapsed();
            writer.join().unwrap();
            assert!(result.is_ok(), "transition not observed: {result:?}");
            assert!(
                elapsed >= transition_delay,
                "returned before the transition"
            );
        }
    }

    #[test]
    fn freezer_completion_times_out_while_still_pending() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        fs::write(dir.path().join("cgroup.freeze"), "1\n").unwrap();
        fs::write(&events_path, "populated 1\nfrozen 0\n").unwrap();
        let timeout = Duration::from_millis(5);
        let started = Instant::now();
        assert!(matches!(
            wait_for_frozen_state(true, timeout, || read_freezer_state(dir.path())),
            Err(ActionError::Timeout)
        ));
        assert!(started.elapsed() >= timeout);
    }

    #[test]
    fn freezer_completion_fails_closed_on_unavailable_or_invalid_events() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        for path in [events_path.as_path(), dir.path()] {
            assert!(matches!(
                wait_for_frozen_state(false, Duration::ZERO, || {
                    read_frozen_event(path).map(|frozen| FreezerState {
                        requested: false,
                        frozen,
                    })
                }),
                Err(ActionError::Failed(_))
            ));
        }
        fs::write(dir.path().join("cgroup.freeze"), "0\n").unwrap();
        for content in ["populated 1\n", "frozen 0 extra\n", "frozen 1\nfrozen 0\n"] {
            fs::write(&events_path, content).unwrap();
            assert!(matches!(
                wait_for_frozen_state(false, Duration::ZERO, || read_freezer_state(dir.path())),
                Err(ActionError::Failed(_))
            ));
        }
    }

    #[test]
    fn freezer_read_refuses_missing_or_malformed_evidence() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_freezer_state(directory.path()).is_err());
        fs::write(directory.path().join("cgroup.freeze"), "1\n").unwrap();
        assert!(read_freezer_state(directory.path()).is_err());
        fs::write(directory.path().join("cgroup.events"), "populated 1\n").unwrap();
        assert!(read_freezer_state(directory.path()).is_err());
        fs::write(directory.path().join("cgroup.events"), "frozen 1\n").unwrap();
        fs::write(directory.path().join("cgroup.freeze"), "yes\n").unwrap();
        assert!(read_freezer_state(directory.path()).is_err());
    }

    #[test]
    fn freezer_read_rejects_a_request_change_around_the_acknowledgement() {
        for requested in [false, true] {
            let mut request_reads = 0;
            let result = read_freezer_state_with(
                || {
                    request_reads += 1;
                    Ok(if request_reads == 1 {
                        requested
                    } else {
                        !requested
                    })
                },
                || Ok(requested),
            );
            assert!(
                matches!(result, Err(ActionError::Failed(_))),
                "an old request and a later matching acknowledgement cannot prove completion"
            );
            assert_eq!(request_reads, 2);

            // A stable request can legitimately have either acknowledgement:
            // the caller decides whether the transition is still pending.
            for frozen in [false, true] {
                assert_eq!(
                    read_freezer_state_with(|| Ok(requested), || Ok(frozen)).unwrap(),
                    FreezerState { requested, frozen },
                );
            }
        }
    }

    #[test]
    fn zero_timeout_observes_once_and_requires_completed_transition() {
        for expected in [false, true] {
            for state in [
                FreezerState {
                    requested: expected,
                    frozen: expected,
                },
                FreezerState {
                    requested: expected,
                    frozen: !expected,
                },
                FreezerState {
                    requested: !expected,
                    frozen: expected,
                },
            ] {
                let mut observations = 0;
                let result = wait_for_frozen_state(expected, Duration::ZERO, || {
                    observations += 1;
                    Ok(state)
                });
                assert_eq!(observations, 1);
                if state.requested == expected && state.frozen == expected {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(ActionError::Timeout)));
                }
            }
        }
    }

    #[test]
    fn freezer_poll_propagates_identity_failure_during_transition() {
        let mut observations = 0;
        let result = wait_for_frozen_state(true, Duration::from_secs(2), || {
            observations += 1;
            if observations == 1 {
                Ok(FreezerState {
                    requested: true,
                    frozen: false,
                })
            } else {
                Err(ActionError::IdentityMismatch)
            }
        });
        assert_eq!(observations, 2);
        assert!(matches!(result, Err(ActionError::IdentityMismatch)));
    }

    #[test]
    fn freezer_poll_never_observes_again_after_its_deadline() {
        let mut observations = 0;
        let result = wait_for_frozen_state(true, Duration::from_millis(5), || {
            observations += 1;
            Ok(FreezerState {
                requested: true,
                frozen: observations > 1,
            })
        });
        assert!(matches!(result, Err(ActionError::Timeout)));
        assert_eq!(observations, 1);
    }

    #[test]
    fn completed_freezer_transition_does_not_wait_out_timeout() {
        let mut observations = 0;
        wait_for_frozen_state(false, Duration::from_secs(60), || {
            observations += 1;
            Ok(FreezerState {
                requested: false,
                frozen: false,
            })
        })
        .unwrap();
        assert_eq!(observations, 1);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        fn freezer_action(frozen: bool) -> PlanAction {
            PlanAction {
                action_id: "test-freezer-request".to_string(),
                target: pt_common::ProcessIdentity::new(
                    123,
                    pt_common::StartId("test-boot:456:123".to_string()),
                    1000,
                ),
                action: if frozen {
                    Action::Freeze
                } else {
                    Action::Unfreeze
                },
                order: 0,
                stage: 0,
                timeouts: Default::default(),
                pre_checks: vec![],
                rationale: crate::plan::ActionRationale {
                    expected_loss: None,
                    expected_recovery: None,
                    expected_recovery_stddev: None,
                    posterior_odds_abandoned_vs_useful: None,
                    sprt_boundary: None,
                    posterior: None,
                    memory_mb: None,
                    has_known_signature: None,
                    category: None,
                },
                on_success: vec![],
                on_failure: vec![],
                blocked: false,
                routing: Default::default(),
                confidence: Default::default(),
                original_zombie_target: None,
                d_state_diagnostics: None,
                supervisor_restart: None,
            }
        }

        fn completed_freezer_files(directory: &Path, frozen: bool) {
            fs::create_dir_all(directory).unwrap();
            fs::write(
                directory.join("cgroup.freeze"),
                u8::from(frozen).to_string(),
            )
            .unwrap();
            fs::write(
                directory.join("cgroup.events"),
                format!("populated 1\nfrozen {}\n", u8::from(frozen)),
            )
            .unwrap();
        }

        #[test]
        fn freezer_verification_requires_matching_execution() {
            for frozen in [false, true] {
                let runner = FreezeActionRunner::with_defaults();
                let action = freezer_action(frozen);
                assert!(runner
                    .verify(&action)
                    .unwrap_err()
                    .to_string()
                    .contains("without an executed request"));
                let directory = tempfile::tempdir().unwrap();
                *runner.applied.lock().unwrap() = Some(AppliedFreeze {
                    action_id: action.action_id.clone(),
                    identity: action.target.clone(),
                    frozen,
                    reversal: None,
                    scope: FreezerScope::open(
                        "/executed".to_string(),
                        directory.path().to_path_buf(),
                    )
                    .unwrap(),
                });
                runner
                    .applied
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .check_action(&action, frozen)
                    .unwrap();
                for field in [
                    "action_id",
                    "action_kind",
                    "birth",
                    "pid",
                    "uid",
                    "pgid",
                    "sid",
                    "quality",
                ] {
                    let mut changed = action.clone();
                    match field {
                        "action_id" => changed.action_id.push_str("-different"),
                        "action_kind" => {
                            changed.action = if frozen {
                                Action::Unfreeze
                            } else {
                                Action::Freeze
                            }
                        }
                        "birth" => changed.target.start_id.0.push_str("-different"),
                        "pid" => changed.target.pid.0 += 1,
                        "uid" => changed.target.uid += 1,
                        "pgid" => changed.target.pgid = Some(234),
                        "sid" => changed.target.sid = Some(345),
                        "quality" => changed.target.quality = pt_common::IdentityQuality::PidOnly,
                        _ => unreachable!(),
                    }
                    assert!(
                        matches!(runner.verify(&changed), Err(ActionError::IdentityMismatch)),
                        "accepted mismatched {field} for frozen={frozen}"
                    );
                }

                // No cgroup is mutated: protected PID 1 is refused before a write.
                // Its failed attempt must also invalidate the previous receipt.
                let mut protected = action.clone();
                protected.target.pid.0 = 1;
                assert!(runner.execute(&protected).is_err());
                assert!(runner.applied.lock().unwrap().is_none());
                assert!(runner
                    .verify(&action)
                    .unwrap_err()
                    .to_string()
                    .contains("without an executed request"));
            }
        }

        #[test]
        fn pinned_freezer_scope_observes_both_completed_states() {
            let directory = tempfile::tempdir().unwrap();
            let scope = FreezerScope::open("/executed".to_string(), directory.path().to_path_buf())
                .unwrap();
            for frozen in [true, false] {
                completed_freezer_files(directory.path(), frozen);
                fs::write(
                    directory.path().join("cgroup.freeze"),
                    u8::from(!frozen).to_string(),
                )
                .unwrap();
                fs::write(
                    scope.pinned_directory().join("cgroup.freeze"),
                    u8::from(frozen).to_string(),
                )
                .unwrap();
                assert_eq!(
                    fs::read_to_string(directory.path().join("cgroup.freeze")).unwrap(),
                    u8::from(frozen).to_string()
                );
                wait_for_frozen_state(frozen, Duration::ZERO, || {
                    scope.observe(|| Ok("/executed".to_string()))
                })
                .unwrap();
            }
        }

        #[test]
        fn freezer_scope_rejects_migration_before_or_during_verification() {
            for frozen in [true, false] {
                let directory = tempfile::tempdir().unwrap();
                let original = directory.path().join("executed");
                let replacement = directory.path().join("other");
                completed_freezer_files(&original, frozen);
                completed_freezer_files(&replacement, frozen);
                let scope = FreezerScope::open("/executed".to_string(), original).unwrap();
                // Both groups already show the requested state. Verification must
                // still refuse a different group, even before its first sample.
                assert!(matches!(
                    scope.observe(|| Ok("/other".to_string())),
                    Err(ActionError::Failed(reason)) if reason.contains("target cgroup changed")
                ));
                let mut observations = 0;
                let result = scope.observe(|| {
                    observations += 1;
                    Ok(if observations == 1 {
                        "/executed"
                    } else {
                        "/other"
                    }
                    .to_string())
                });
                assert_eq!(observations, 2);
                assert!(matches!(
                    result,
                    Err(ActionError::Failed(reason)) if reason.contains("target cgroup changed")
                ));
                assert!(matches!(
                    scope.observe(|| Err(ActionError::IdentityMismatch)),
                    Err(ActionError::IdentityMismatch)
                ));
            }
        }

        #[test]
        fn freezer_scope_rejects_directory_replacement_at_the_same_path() {
            for replace_during_observation in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let original = directory.path().join("executed");
                let retained = directory.path().join("previous");
                completed_freezer_files(&original, true);
                let scope = FreezerScope::open("/executed".to_string(), original.clone()).unwrap();
                let replace = || {
                    fs::rename(&original, &retained).unwrap();
                    completed_freezer_files(&original, true);
                };
                if !replace_during_observation {
                    replace();
                }
                let mut observations = 0;
                let result = scope.observe(|| {
                    observations += 1;
                    if replace_during_observation && observations == 2 {
                        replace();
                    }
                    Ok("/executed".to_string())
                });
                assert!(matches!(
                    result,
                    Err(ActionError::Failed(reason)) if reason.contains("directory changed")
                ));

                // The retained descriptor also pins writes: changing the former
                // cgroup path cannot redirect a request to the replacement.
                fs::write(scope.pinned_directory().join("cgroup.freeze"), "0").unwrap();
                assert_eq!(
                    fs::read_to_string(retained.join("cgroup.freeze")).unwrap(),
                    "0"
                );
                assert_eq!(
                    fs::read_to_string(original.join("cgroup.freeze")).unwrap(),
                    "1"
                );
            }
        }

        #[test]
        fn check_freeze_availability_for_self() {
            let pid = std::process::id();
            // This will be true on modern Linux with cgroup v2
            let available = is_freeze_available(pid);
            crate::test_log!(
                INFO,
                "freeze availability check",
                pid = pid,
                available = available
            );
            // Don't assert - availability depends on system configuration
        }

        #[test]
        fn read_frozen_event_for_self() {
            let pid = std::process::id();
            if let Some(path) = collect_cgroup_details(pid).and_then(|details| details.unified_path)
            {
                let events_path = format!("/sys/fs/cgroup{path}/cgroup.events");
                match read_frozen_event(Path::new(&events_path)) {
                    Ok(frozen) => {
                        crate::test_log!(INFO, "freeze state read", pid = pid, frozen = frozen);
                        // Our test process should not be frozen
                        assert!(!frozen, "test process should not be frozen");
                    }
                    Err(e) => {
                        crate::test_log!(
                            INFO,
                            "cannot read completed freezer state",
                            error = e.to_string().as_str()
                        );
                    }
                }
            }
        }
    }
}
