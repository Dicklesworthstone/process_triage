//! Immutable planning-time resource forecasts and their observed associations.
//!
//! A forecast belongs to the saved action and process incarnation. Apply and
//! verify must not replace it with current measurements, RSS, or a newer model.
//! Host changes remain observations, never proof of per-action causal recovery.

use super::relief::{ResourceActionBinding, ResourceDelta};
use crate::collect::disk::DiskMountIdentity;
use crate::collect::pressure::HostCpuWindow;
use crate::decision::Action;
use crate::plan::{Plan, PlanAction};
use chrono::DateTime;
use pt_common::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const RESOURCE_PREDICTION_SCHEMA_VERSION: u32 = 1;
const MEMORY_BASIS: &str = "private_clean_plus_private_dirty";
const CPU_BASIS: &str = "process_tick_delta_divided_by_host_total_tick_delta";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateMemoryPrediction {
    pub basis: String,
    pub bytes: u64,
    pub private_clean_bytes: u64,
    pub private_dirty_bytes: u64,
    pub private_hugetlb_bytes: Option<u64>,
    pub observed_at_unix_ms: i64,
}

impl PrivateMemoryPrediction {
    pub fn new(
        private_clean_bytes: u64,
        private_dirty_bytes: u64,
        private_hugetlb_bytes: Option<u64>,
        observed_at_unix_ms: i64,
    ) -> Result<Self, String> {
        let bytes = private_clean_bytes
            .checked_add(private_dirty_bytes)
            .ok_or("private-memory prediction overflows bytes")?;
        let prediction = Self {
            basis: MEMORY_BASIS.into(),
            bytes,
            private_clean_bytes,
            private_dirty_bytes,
            private_hugetlb_bytes,
            observed_at_unix_ms,
        };
        prediction.validate()?;
        Ok(prediction)
    }

    fn validate(&self) -> Result<(), String> {
        if self.basis != MEMORY_BASIS
            || self
                .private_clean_bytes
                .checked_add(self.private_dirty_bytes)
                != Some(self.bytes)
            || self.observed_at_unix_ms < 0
        {
            return Err(
                "invalid private-memory prediction basis, counters, or observation time".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostCpuPrediction {
    pub basis: String,
    /// Fraction of the measured whole-host capacity, not percent of one CPU.
    pub host_fraction: f64,
    pub process_ticks: u64,
    pub host_total_ticks: u64,
    pub host_busy_ticks: u64,
    pub logical_cpus: u32,
    pub process_window_seconds: f64,
    pub host_window_seconds: f64,
    pub observed_at_unix_ms: i64,
}

impl HostCpuPrediction {
    pub fn from_window(
        process_ticks: u64,
        process_window_seconds: f64,
        host: &HostCpuWindow,
        observed_at_unix_ms: i64,
    ) -> Result<Self, String> {
        let host_fraction = host
            .process_percent(process_ticks)
            .ok_or("host CPU prediction requires valid measured counters")?
            / 100.0;
        let prediction = Self {
            basis: CPU_BASIS.into(),
            host_fraction,
            process_ticks,
            host_total_ticks: host.total_ticks,
            host_busy_ticks: host.busy_ticks,
            logical_cpus: host.logical_cpus,
            process_window_seconds,
            host_window_seconds: host.window_seconds,
            observed_at_unix_ms,
        };
        prediction.validate()?;
        Ok(prediction)
    }

    fn validate(&self) -> Result<(), String> {
        let host = HostCpuWindow {
            total_ticks: self.host_total_ticks,
            busy_ticks: self.host_busy_ticks,
            logical_cpus: self.logical_cpus,
            window_seconds: self.host_window_seconds,
        };
        let expected = host
            .process_percent(self.process_ticks)
            .map(|value| value / 100.0);
        if self.basis != CPU_BASIS
            || self.observed_at_unix_ms < 0
            || !self.host_fraction.is_finite()
            || !(0.0..=1.0).contains(&self.host_fraction)
            || expected.is_none_or(|expected| (expected - self.host_fraction).abs() > 1e-12)
            || !self.process_window_seconds.is_finite()
            || self.process_window_seconds <= 0.0
            || self.process_window_seconds > self.host_window_seconds
        {
            return Err("invalid measured host CPU prediction or enclosing window".into());
        }
        Ok(())
    }

    fn same_host_window(&self, other: &Self) -> bool {
        self.host_total_ticks == other.host_total_ticks
            && self.host_busy_ticks == other.host_busy_ticks
            && self.logical_cpus == other.logical_cpus
            && self.host_window_seconds == other.host_window_seconds
            && self.observed_at_unix_ms == other.observed_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescriptorPrediction {
    pub count: u64,
    pub observed_at_unix_ms: i64,
}

/// Planning-time allocation held exclusively by this action's process on one
/// observed filesystem. Apparent file lengths and shared holders contribute
/// nothing. Apply retains this forecast; fresh readings measure progress only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskRecoveryPrediction {
    pub mount: DiskMountIdentity,
    pub allocated_bytes: u64,
    pub observed_at_unix_ms: i64,
}

impl DiskRecoveryPrediction {
    pub fn new(
        mount: DiskMountIdentity,
        allocated_bytes: u64,
        observed_at_unix_ms: i64,
    ) -> Result<Self, String> {
        let prediction = Self {
            mount,
            allocated_bytes,
            observed_at_unix_ms,
        };
        prediction.validate()?;
        Ok(prediction)
    }

    fn validate(&self) -> Result<(), String> {
        self.mount.validate()?;
        if self.observed_at_unix_ms < 0 {
            return Err("disk prediction observation time precedes the epoch".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionResourcePrediction {
    pub action_id: String,
    pub action: Action,
    pub target: ProcessIdentity,
    pub memory: Option<PrivateMemoryPrediction>,
    pub cpu: Option<HostCpuPrediction>,
    pub file_descriptors: Option<FileDescriptorPrediction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskRecoveryPrediction>,
    #[serde(default)]
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourcePredictionSnapshot {
    pub schema_version: u32,
    pub session_id: String,
    pub plan_id: String,
    /// Time this immutable forecast was assembled, after its source readings.
    pub generated_at: String,
    pub actions: Vec<ActionResourcePrediction>,
}

#[derive(Debug, Clone)]
pub struct ValidatedResourcePredictions {
    snapshot: ResourcePredictionSnapshot,
    by_action: HashMap<String, usize>,
}

impl ResourcePredictionSnapshot {
    pub fn validate(&self, plan: &Plan) -> Result<ValidatedResourcePredictions, String> {
        if self.schema_version != RESOURCE_PREDICTION_SCHEMA_VERSION
            || self.session_id != plan.session_id
            || self.plan_id != plan.plan_id
            || self.session_id.is_empty()
            || self.plan_id.is_empty()
            || self.actions.len() > plan.actions.len()
        {
            return Err("resource predictions do not bind the saved plan and schema".into());
        }
        let generated = DateTime::parse_from_rfc3339(&self.generated_at)
            .map_err(|_| "resource prediction creation time is invalid")?
            .timestamp_millis();
        if generated < 0 {
            return Err("resource prediction creation time precedes the epoch".into());
        }
        let mut plan_by_id = HashMap::new();
        for action in &plan.actions {
            if action.action_id.is_empty()
                || plan_by_id
                    .insert(action.action_id.as_str(), action)
                    .is_some()
            {
                return Err("saved plan contains empty or duplicate action IDs".into());
            }
        }
        let mut by_action = HashMap::new();
        for (index, prediction) in self.actions.iter().enumerate() {
            if by_action
                .insert(prediction.action_id.clone(), index)
                .is_some()
            {
                return Err("resource predictions repeat an action ID".into());
            }
            let action = plan_by_id
                .get(prediction.action_id.as_str())
                .ok_or("resource prediction names an action outside the saved plan")?;
            if action.blocked
                || prediction.action != action.action
                || prediction.target != action.target
                || !prediction.target.can_safely_revalidate()
                || prediction.action == Action::Keep
            {
                return Err(
                    "resource prediction does not match an executable saved action identity".into(),
                );
            }
            if prediction.action != Action::Kill
                && (prediction.memory.is_some()
                    || prediction.cpu.is_some()
                    || prediction.file_descriptors.is_some()
                    || prediction.disk.is_some())
            {
                return Err(
                    "this prediction schema supports recovery forecasts only for Kill".into(),
                );
            }
            if let Some(memory) = &prediction.memory {
                memory.validate()?;
            }
            if let Some(cpu) = &prediction.cpu {
                cpu.validate()?;
            }
            if let Some(disk) = &prediction.disk {
                disk.validate()?;
                let start_id = &prediction.target.start_id.0;
                if pt_common::StartId::parse(start_id).is_none()
                    || start_id.split(':').next() != Some(disk.mount.boot_id.as_str())
                    || start_id
                        .rsplit(':')
                        .next()
                        .and_then(|pid| pid.parse::<u32>().ok())
                        != Some(prediction.target.pid.0)
                {
                    return Err(
                        "disk prediction filesystem does not bind the target's boot and identity"
                            .into(),
                    );
                }
            }
            for observed in [
                prediction
                    .memory
                    .as_ref()
                    .map(|value| value.observed_at_unix_ms),
                prediction
                    .cpu
                    .as_ref()
                    .map(|value| value.observed_at_unix_ms),
                prediction
                    .file_descriptors
                    .as_ref()
                    .map(|value| value.observed_at_unix_ms),
                prediction
                    .disk
                    .as_ref()
                    .map(|value| value.observed_at_unix_ms),
            ]
            .into_iter()
            .flatten()
            {
                if observed < 0 || observed > generated {
                    return Err(
                        "resource prediction observation is outside its creation-time boundary"
                            .into(),
                    );
                }
            }
        }
        Ok(ValidatedResourcePredictions {
            snapshot: self.clone(),
            by_action,
        })
    }
}

impl ValidatedResourcePredictions {
    pub fn snapshot(&self) -> &ResourcePredictionSnapshot {
        &self.snapshot
    }

    pub fn for_action(&self, action: &PlanAction) -> Option<&ActionResourcePrediction> {
        let prediction = self
            .snapshot
            .actions
            .get(*self.by_action.get(&action.action_id)?)?;
        (!action.blocked
            && prediction.action == action.action
            && prediction.target == action.target)
            .then_some(prediction)
    }

    fn for_execution(&self, action: &ResourceActionBinding) -> Option<&ActionResourcePrediction> {
        let prediction = self
            .snapshot
            .actions
            .get(*self.by_action.get(&action.action_id)?)?;
        (prediction.action == action.action && prediction.target == action.target)
            .then_some(prediction)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePredictionComparison {
    pub unit: String,
    pub predicted: Option<f64>,
    /// Useful known Kill forecasts remain visible without claiming completeness.
    pub known_subtotal: Option<f64>,
    pub known_targets: usize,
    /// Positive means improvement: more available memory or lower host CPU.
    pub observed: Option<f64>,
    pub observed_minus_predicted: Option<f64>,
    pub comparable: bool,
    /// Whether the original prediction covers all successful actions.
    pub complete: bool,
    pub missing_action_ids: Vec<String>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResourcePredictionComparison {
    pub scope: String,
    pub attribution: String,
    pub prediction_generated_at: String,
    pub successful_action_ids: Vec<String>,
    pub unique_targets: usize,
    pub memory: ResourcePredictionComparison,
    pub cpu: ResourcePredictionComparison,
    pub file_descriptors: ResourcePredictionComparison,
    pub limitations: Vec<String>,
}

fn comparison(
    unit: &str,
    predicted: Option<f64>,
    known_subtotal: Option<f64>,
    known_targets: usize,
    observed: Option<f64>,
    missing_action_ids: Vec<String>,
    unavailable: Vec<String>,
) -> ResourcePredictionComparison {
    let observed = observed.filter(|value| value.is_finite());
    ResourcePredictionComparison {
        unit: unit.into(),
        predicted,
        known_subtotal,
        known_targets,
        observed,
        observed_minus_predicted: predicted
            .zip(observed)
            .map(|(predicted, observed)| observed - predicted),
        comparable: predicted.is_some() && observed.is_some(),
        complete: predicted.is_some(),
        missing_action_ids,
        unavailable,
    }
}

type TargetActions<'a> = BTreeMap<(u32, String, u32), Vec<&'a ResourceActionBinding>>;

fn target_kills<'a>(actions: &'a [&'a ResourceActionBinding]) -> Vec<&'a ResourceActionBinding> {
    actions
        .iter()
        .copied()
        .filter(|action| action.action == Action::Kill)
        .collect()
}

struct CountPrediction {
    total: Option<u64>,
    known_subtotal: Option<u64>,
    known_targets: usize,
    missing: Vec<String>,
    errors: Vec<String>,
}

/// Require complete, consistent predictions for every successful action. The
/// known Kill subtotal counts an incarnation once, even when an unknown earlier
/// stage prevents treating that subtotal as a complete run forecast.
fn sum_counts(
    targets: &TargetActions<'_>,
    predictions: &ValidatedResourcePredictions,
    pick: fn(&ActionResourcePrediction) -> Option<u64>,
) -> CountPrediction {
    let mut known_subtotal = Some(0_u64);
    let mut known_targets = 0;
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    for actions in targets.values() {
        missing.extend(
            actions
                .iter()
                .filter(|action| action.action != Action::Kill)
                .map(|action| action.action_id.clone()),
        );
        let kills = target_kills(actions);
        let mut amount = None;
        let mut complete = !kills.is_empty();
        for action in &kills {
            match predictions.for_execution(action).and_then(pick) {
                Some(value) if amount.is_none_or(|previous| previous == value) => {
                    amount = Some(value)
                }
                _ => complete = false,
            }
        }
        if !complete {
            missing.extend(kills.iter().map(|action| action.action_id.clone()));
        } else if let Some(amount) = amount {
            known_targets += 1;
            if let Some(previous) = known_subtotal {
                known_subtotal = previous.checked_add(amount);
                if known_subtotal.is_none() {
                    errors.push("prediction count total overflowed".into());
                }
            }
        }
    }
    CountPrediction {
        total: missing.is_empty().then_some(known_subtotal).flatten(),
        known_subtotal,
        known_targets,
        missing,
        errors,
    }
}

pub(crate) fn compare_run_predictions(
    predictions: &ValidatedResourcePredictions,
    actions: &[ResourceActionBinding],
    delta: &ResourceDelta,
) -> RunResourcePredictionComparison {
    let mut targets = TargetActions::new();
    let successful_action_ids = actions
        .iter()
        .filter(|action| action.status == "success")
        .map(|action| {
            targets
                .entry((
                    action.target.pid.0,
                    action.target.start_id.0.clone(),
                    action.target.uid,
                ))
                .or_default()
                .push(action);
            action.action_id.clone()
        })
        .collect();
    let memory = sum_counts(&targets, predictions, |prediction| {
        prediction.memory.as_ref().map(|value| value.bytes)
    });
    let mut fds = sum_counts(&targets, predictions, |prediction| {
        prediction
            .file_descriptors
            .as_ref()
            .map(|value| value.count)
    });
    fds.errors.push("host allocated file handles are not process descriptor counts; no comparable descriptor delta was recorded in this resource window".into());

    let mut cpu_known_subtotal = Some(0.0_f64);
    let mut cpu_ticks_subtotal = Some(0_u64);
    let mut cpu_known_targets = 0;
    let mut cpu_missing = Vec::new();
    let mut cpu_errors = Vec::new();
    let mut host_window: Option<&HostCpuPrediction> = None;
    for actions in targets.values() {
        cpu_missing.extend(
            actions
                .iter()
                .filter(|action| action.action != Action::Kill)
                .map(|action| action.action_id.clone()),
        );
        let kills = target_kills(actions);
        let mut cpu: Option<&HostCpuPrediction> = None;
        let mut complete = !kills.is_empty();
        for action in kills {
            match predictions
                .for_execution(action)
                .and_then(|prediction| prediction.cpu.as_ref())
            {
                Some(value) if cpu.is_none_or(|previous| previous == value) => cpu = Some(value),
                _ => complete = false,
            }
        }
        if let Some(cpu) = cpu.filter(|_| complete) {
            if host_window.is_some_and(|window| !window.same_host_window(cpu)) {
                complete = false;
                cpu_known_subtotal = None;
                cpu_errors.push(
                    "successful targets have different planning-time host CPU windows".into(),
                );
            } else {
                host_window = Some(cpu);
                cpu_known_targets += 1;
                cpu_known_subtotal = cpu_known_subtotal.map(|total| total + cpu.host_fraction);
                cpu_ticks_subtotal =
                    cpu_ticks_subtotal.and_then(|total| total.checked_add(cpu.process_ticks));
            }
        } else {
            complete = false;
        }
        if !complete {
            cpu_missing.extend(
                actions
                    .iter()
                    .filter(|action| action.action == Action::Kill)
                    .map(|action| action.action_id.clone()),
            );
        }
    }
    if cpu_known_subtotal.is_some_and(|total| !total.is_finite() || total > 1.0) {
        cpu_known_subtotal = None;
        cpu_errors.push("predicted CPU relief exceeds whole-host capacity".into());
    }
    if host_window
        .is_some_and(|window| cpu_ticks_subtotal.is_none_or(|ticks| ticks > window.host_busy_ticks))
    {
        cpu_known_subtotal = None;
        cpu_errors.push(
            "unique target CPU ticks exceed the enclosing host busy_ticks or overflow".into(),
        );
    }
    let cpu_total = cpu_missing
        .is_empty()
        .then_some(cpu_known_subtotal)
        .flatten();
    let mut cpu_comparison = comparison(
        "fraction_of_host_capacity",
        cpu_total,
        cpu_known_subtotal,
        cpu_known_targets,
        delta.cpu.busy_percent.delta.map(|value| -value / 100.0),
        cpu_missing,
        cpu_errors,
    );
    if host_window.is_some_and(|window| delta.observed_logical_cpus != Some(window.logical_cpus)) {
        cpu_comparison.comparable = false;
        cpu_comparison.observed_minus_predicted = None;
        cpu_comparison.unavailable.push("planning and execution CPU capacities differ or the common observed capacity is unknown; host fractions cannot be compared".into());
    }
    RunResourcePredictionComparison {
        scope: "successful_bound_execution_targets".into(),
        attribution: "observed_host_association_not_per_action_causal_relief".into(),
        prediction_generated_at: predictions.snapshot.generated_at.clone(),
        successful_action_ids, unique_targets: targets.len(),
        memory: comparison("bytes", memory.total.map(|value| value as f64),
            memory.known_subtotal.map(|value| value as f64), memory.known_targets,
            delta.available_memory_bytes.delta, memory.missing, memory.errors),
        cpu: cpu_comparison,
        file_descriptors: comparison("descriptor_count", fds.total.map(|value| value as f64),
            fds.known_subtotal.map(|value| value as f64), fds.known_targets,
            None, fds.missing, fds.errors),
        limitations: vec![
            "Forecasts are the original saved-plan observations; they were not resampled or recalculated with a later model.".into(),
            "Only successful bound executions contribute. Failed, blocked, shadow and dry-run actions cannot supply recovery credit.".into(),
            "An unknown successful action or stage keeps the full forecast unknown; known Kill subtotals remain partial forecasts, never measured recovery.".into(),
            "The host delta can include other workloads, caches and partial failed-action effects; residuals are associations, not per-action efficacy or causal training labels.".into(),
            "Private huge-TLB pages, shared memory and swap do not contribute to the private-resident memory forecast.".into(),
            "No per-action port-release forecast is inferred from descriptor or socket counts.".into(),
        ],
    }
}

/// Preserve valid host observations when prediction evidence is absent or
/// corrupt, but never substitute a later forecast for the one saved at apply.
pub(crate) fn attach_prediction_comparison(
    delta: &mut ResourceDelta,
    stored: Option<&ResourcePredictionSnapshot>,
    expected: Option<&ValidatedResourcePredictions>,
    plan: &Plan,
    actions: &[ResourceActionBinding],
) {
    delta.prediction_comparison = None;
    let reason = match (stored, expected) {
        (Some(stored), Some(expected)) if stored == expected.snapshot() => {
            match stored.validate(plan) {
                Ok(validated)
                    if DateTime::parse_from_rfc3339(&stored.generated_at)
                        .ok()
                        .is_some_and(|generated| {
                            actions.iter().all(|action| generated <= action.executed_at)
                        }) =>
                {
                    delta.prediction_comparison =
                        Some(compare_run_predictions(&validated, actions, delta));
                    return;
                }
                Ok(_) => {
                    "planning-time predictions were created after a bound action execution".into()
                }
                Err(error) => error,
            }
        }
        (Some(_), Some(_)) => {
            "saved resource predictions differ from the original canonical plan".into()
        }
        (None, _) => {
            "this apply artifact has no original planning-time resource predictions".into()
        }
        (Some(_), None) => {
            "the canonical plan has no validated resource prediction snapshot".into()
        }
    };
    delta
        .unavailable
        .push(crate::collect::pressure::Unavailable {
            source: "resource_predictions".into(),
            reason,
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::relief::{compare_resource_windows, ResourceObservationWindow};
    use crate::verify::ExecutionClock;
    use chrono::Utc;
    use pt_common::StartId;

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";

    fn disk_mount() -> DiskMountIdentity {
        DiskMountIdentity {
            boot_id: BOOT.into(),
            mount_namespace_device: 1,
            mount_namespace_inode: 2,
            mount_id: 3,
            device_major: 8,
            device_minor: 1,
            filesystem_type: "ext4".into(),
            mount_root_sha256: "1".repeat(64),
            mount_source_sha256: "2".repeat(64),
            mount_options_sha256: "3".repeat(64),
        }
    }

    fn fixture() -> (Plan, ResourcePredictionSnapshot, Vec<ResourceActionBinding>) {
        let actions: Vec<_> = [42_u32, 43]
            .into_iter()
            .map(|pid| {
                serde_json::json!({
                    "action_id": format!("kill-{pid}"),
                    "target": ProcessIdentity::new(pid, StartId::from_linux(BOOT, 10, pid), 1000),
                    "action": "kill", "order": 0, "stage": 1,
                    "timeouts": crate::plan::ActionTimeouts::default(), "pre_checks": [],
                    "rationale": {}, "on_success": [], "on_failure": [], "blocked": false,
                })
            })
            .collect();
        let plan: Plan = serde_json::from_value(serde_json::json!({
            "plan_id": "forecast-plan", "session_id": "forecast-session",
            "generated_at": "1970-01-01T00:00:00Z", "policy_version": "test", "pre_toggled": [],
            "gates_summary": {"total_candidates": 2, "blocked_candidates": 0, "pre_toggled_actions": 0},
            "actions": actions,
        })).unwrap();
        let host = HostCpuWindow {
            total_ticks: 1000,
            busy_ticks: 800,
            logical_cpus: 8,
            window_seconds: 2.0,
        };
        let predictions = plan
            .actions
            .iter()
            .enumerate()
            .map(|(index, action)| {
                let amount = (index as u64 + 1) * 10;
                ActionResourcePrediction {
                    action_id: action.action_id.clone(),
                    action: action.action,
                    target: action.target.clone(),
                    memory: Some(
                        PrivateMemoryPrediction::new(amount / 2, amount / 2, Some(1000), 1000)
                            .unwrap(),
                    ),
                    cpu: Some(
                        HostCpuPrediction::from_window(amount * 10, 1.0, &host, 1000).unwrap(),
                    ),
                    file_descriptors: Some(FileDescriptorPrediction {
                        count: amount,
                        observed_at_unix_ms: 1000,
                    }),
                    disk: None,
                    unavailable: Vec::new(),
                }
            })
            .collect();
        let snapshot = ResourcePredictionSnapshot {
            schema_version: RESOURCE_PREDICTION_SCHEMA_VERSION,
            session_id: plan.session_id.clone(),
            plan_id: plan.plan_id.clone(),
            generated_at: "1970-01-01T00:00:02Z".into(),
            actions: predictions,
        };
        let executions = plan
            .actions
            .iter()
            .map(|action| ResourceActionBinding {
                action_id: action.action_id.clone(),
                action: action.action,
                target: action.target.clone(),
                status: "success".into(),
                executed_at: DateTime::<Utc>::from_timestamp_millis(3000).unwrap(),
                execution_clock: ExecutionClock {
                    boot_id: BOOT.into(),
                    ticks: 300,
                },
            })
            .collect();
        (plan, snapshot, executions)
    }

    fn observed_delta(memory: f64, cpu_percent: f64) -> ResourceDelta {
        let window = ResourceObservationWindow {
            requested_duration_ms: 0,
            sample_interval_ms: 1000,
            samples: Vec::new(),
        };
        let mut delta = compare_resource_windows(&window, &window);
        delta.comparable = true;
        delta.cpu_capacity_comparable = true;
        delta.observed_logical_cpus = Some(8);
        delta.available_memory_bytes.delta = Some(memory);
        delta.cpu.busy_percent.delta = Some(cpu_percent);
        delta
    }

    #[test]
    fn private_counters_preserve_original_bytes_and_never_credit_hugetlb() {
        let prediction = PrivateMemoryPrediction::new(512, 1024, Some(u64::MAX), 1).unwrap();
        assert_eq!(prediction.bytes, 1536);
        assert_eq!(prediction.private_hugetlb_bytes, Some(u64::MAX));
        assert!(PrivateMemoryPrediction::new(u64::MAX, 1, None, 1).is_err());
        assert!(PrivateMemoryPrediction::new(0, 0, None, -1).is_err());
        let mut invalid = prediction;
        invalid.bytes = 2000;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn cpu_forecast_requires_ticks_inside_a_real_enclosing_host_window() {
        let host = HostCpuWindow {
            total_ticks: 800,
            busy_ticks: 600,
            logical_cpus: 8,
            window_seconds: 2.0,
        };
        let prediction = HostCpuPrediction::from_window(200, 1.0, &host, 1000).unwrap();
        assert_eq!(prediction.host_fraction, 0.25);
        assert_eq!(prediction.process_ticks, 200);
        for seconds in [0.0, -1.0, f64::NAN, f64::INFINITY, 2.1] {
            assert!(HostCpuPrediction::from_window(200, seconds, &host, 1000).is_err());
        }
        assert!(HostCpuPrediction::from_window(601, 1.0, &host, 1000).is_err());
        let mut invalid = prediction;
        invalid.host_fraction = 0.5;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn snapshot_roundtrip_requires_exact_saved_action_and_observation_binding() {
        let (plan, snapshot, _) = fixture();
        let restored: ResourcePredictionSnapshot =
            serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let valid = restored.validate(&plan).unwrap();
        assert_eq!(
            valid
                .for_action(&plan.actions[0])
                .unwrap()
                .memory
                .as_ref()
                .unwrap()
                .bytes,
            10
        );
        for case in 0..11 {
            let mut changed = snapshot.clone();
            match case {
                0 => changed.schema_version += 1,
                1 => changed.plan_id.push_str("-other"),
                2 => changed.session_id.push_str("-other"),
                3 => changed.actions[0].target.uid += 1,
                4 => changed.actions[0].target.start_id.0.push_str("-reused"),
                5 => changed.actions[0].target.pgid = Some(999),
                6 => changed.actions[0].action = Action::Pause,
                7 => changed.actions[1].action_id = changed.actions[0].action_id.clone(),
                8 => {
                    changed.actions[0]
                        .memory
                        .as_mut()
                        .unwrap()
                        .observed_at_unix_ms = 2001
                }
                9 => {
                    changed.actions[0]
                        .file_descriptors
                        .as_mut()
                        .unwrap()
                        .observed_at_unix_ms = -1
                }
                10 => changed.actions[0].memory.as_mut().unwrap().basis = "rss".into(),
                _ => unreachable!(),
            }
            assert!(changed.validate(&plan).is_err(), "case {case}");
        }
        let mut blocked = plan.clone();
        blocked.actions[0].blocked = true;
        assert!(snapshot.validate(&blocked).is_err());
    }

    #[test]
    fn disk_forecast_roundtrips_only_for_its_saved_kill_and_filesystem() {
        let (mut plan, mut snapshot, _) = fixture();
        snapshot.actions[0].disk =
            Some(DiskRecoveryPrediction::new(disk_mount(), 50_000_000, 1000).unwrap());
        let restored: ResourcePredictionSnapshot =
            serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let valid = restored.validate(&plan).unwrap();
        assert_eq!(
            valid.for_action(&plan.actions[0]).unwrap().disk,
            snapshot.actions[0].disk
        );

        let mut replacement = plan.actions[0].clone();
        replacement.target.start_id = StartId::from_linux(BOOT, 11, replacement.target.pid.0);
        assert!(valid.for_action(&replacement).is_none());

        // Isolate the new forecast from other recovery metrics: even a pause
        // with no memory/CPU/FD forecast may not promise released disk space.
        plan.actions[0].action = Action::Pause;
        snapshot.actions[0].action = Action::Pause;
        snapshot.actions[0].memory = None;
        snapshot.actions[0].cpu = None;
        snapshot.actions[0].file_descriptors = None;
        assert!(snapshot.validate(&plan).is_err());
    }

    #[test]
    fn disk_forecast_rejects_weak_scope_wrong_boot_and_late_observations() {
        let (plan, mut snapshot, _) = fixture();
        snapshot.actions[0].disk =
            Some(DiskRecoveryPrediction::new(disk_mount(), 0, 1000).unwrap());
        assert!(
            snapshot.validate(&plan).is_ok(),
            "measured zero allocation is valid"
        );
        for case in [
            "boot",
            "namespace",
            "mount",
            "digest",
            "negative_time",
            "late_time",
        ] {
            let mut changed = snapshot.clone();
            let disk = changed.actions[0].disk.as_mut().unwrap();
            match case {
                "boot" => disk.mount.boot_id = "22222222-2222-4222-8222-222222222222".into(),
                "namespace" => disk.mount.mount_namespace_inode = 0,
                "mount" => disk.mount.mount_id = 0,
                "digest" => disk.mount.mount_root_sha256.clear(),
                "negative_time" => disk.observed_at_unix_ms = -1,
                "late_time" => disk.observed_at_unix_ms = 2001,
                _ => unreachable!(),
            }
            assert!(changed.validate(&plan).is_err(), "{case}");
        }
    }

    #[test]
    fn older_resource_forecasts_preserve_their_serialized_representation() {
        let (plan, snapshot, _) = fixture();
        let older = serde_json::to_value(&snapshot).unwrap();
        for action in older["actions"].as_array().unwrap() {
            assert!(action.get("disk").is_none());
        }
        let restored: ResourcePredictionSnapshot = serde_json::from_value(older.clone()).unwrap();
        assert!(restored.actions.iter().all(|action| action.disk.is_none()));
        assert!(restored.validate(&plan).is_ok());
        assert_eq!(serde_json::to_value(restored).unwrap(), older);
    }

    #[test]
    fn successful_kill_subtotals_are_unique_but_unknown_pause_stages_remain_incomplete() {
        let (mut plan, mut snapshot, mut executions) = fixture();
        for (id, kind) in [
            ("kill-42-repeat", Action::Kill),
            ("pause-42", Action::Pause),
        ] {
            let mut action = plan.actions[0].clone();
            action.action_id = id.into();
            action.action = kind;
            let mut prediction = snapshot.actions[0].clone();
            prediction.action_id = id.into();
            prediction.action = kind;
            if kind == Action::Pause {
                prediction.memory = None;
                prediction.cpu = None;
                prediction.file_descriptors = None;
            }
            let mut execution = executions[0].clone();
            execution.action_id = id.into();
            execution.action = kind;
            plan.actions.push(action);
            snapshot.actions.push(prediction);
            executions.push(execution);
        }
        let valid = snapshot.validate(&plan).unwrap();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        assert_eq!(report.unique_targets, 2);
        assert_eq!(report.successful_action_ids.len(), 4);
        assert_eq!(report.memory.predicted, None);
        assert_eq!(report.memory.known_subtotal, Some(30.0));
        assert_eq!(report.memory.known_targets, 2);
        assert_eq!(report.memory.missing_action_ids, ["pause-42"]);
        assert!((report.cpu.known_subtotal.unwrap() - 0.3).abs() < 1e-12);
        assert_eq!(report.cpu.predicted, None);
        assert_eq!(report.file_descriptors.known_subtotal, Some(30.0));
        assert_eq!(report.file_descriptors.predicted, None);
        assert_eq!(report.file_descriptors.observed, None);
        assert_eq!(report.memory.observed_minus_predicted, None);
        executions[1].status = "failed".into();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        assert_eq!(report.unique_targets, 1);
        assert_eq!(report.memory.known_subtotal, Some(10.0));
        assert_eq!(report.memory.predicted, None);
        executions[3].status = "failed".into();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        assert_eq!(report.memory.predicted, Some(10.0));
    }

    #[test]
    fn missing_one_prediction_is_unknown_instead_of_a_partial_total() {
        let (plan, mut snapshot, executions) = fixture();
        snapshot.actions[1].memory = None;
        snapshot.actions[1].cpu = None;
        snapshot.actions[1].file_descriptors = None;
        let valid = snapshot.validate(&plan).unwrap();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        for metric in [&report.memory, &report.cpu, &report.file_descriptors] {
            assert!(!metric.complete);
            assert_eq!(metric.predicted, None);
            assert_eq!(metric.observed_minus_predicted, None);
            assert_eq!(metric.missing_action_ids, ["kill-43"]);
        }
        assert_eq!(report.memory.observed, Some(25.0));
        assert_eq!(report.cpu.observed, Some(0.2));
        assert_eq!(report.memory.known_subtotal, Some(10.0));
        assert_eq!(report.memory.known_targets, 1);
    }

    #[test]
    fn checked_count_and_incompatible_cpu_windows_cannot_invent_complete_totals() {
        let (plan, mut snapshot, executions) = fixture();
        snapshot.actions[0].memory =
            Some(PrivateMemoryPrediction::new(u64::MAX, 0, None, 1000).unwrap());
        snapshot.actions[0].file_descriptors.as_mut().unwrap().count = u64::MAX;
        snapshot.actions[1]
            .cpu
            .as_mut()
            .unwrap()
            .observed_at_unix_ms = 1001;
        let valid = snapshot.validate(&plan).unwrap();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        for metric in [&report.memory, &report.cpu, &report.file_descriptors] {
            assert_eq!(metric.predicted, None);
            assert!(!metric.complete);
            assert!(!metric.unavailable.is_empty());
        }
    }

    #[test]
    fn combined_unique_cpu_predictions_cannot_exceed_observed_host_busy_ticks() {
        let (plan, mut snapshot, executions) = fixture();
        let host = HostCpuWindow {
            total_ticks: 1000,
            busy_ticks: 800,
            logical_cpus: 8,
            window_seconds: 2.0,
        };
        for prediction in &mut snapshot.actions {
            prediction.cpu = Some(HostCpuPrediction::from_window(500, 1.0, &host, 1000).unwrap());
        }
        let valid = snapshot.validate(&plan).unwrap();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        assert_eq!(report.cpu.predicted, None);
        assert_eq!(report.cpu.known_subtotal, None);
        assert!(!report.cpu.complete);
        assert!(report
            .cpu
            .unavailable
            .iter()
            .any(|reason| reason.contains("busy_ticks")));
    }

    #[test]
    fn changed_execution_cpu_capacity_preserves_evidence_but_refuses_a_residual() {
        let (plan, snapshot, executions) = fixture();
        let valid = snapshot.validate(&plan).unwrap();
        for capacity in [None, Some(4), Some(16)] {
            let mut delta = observed_delta(25.0, -20.0);
            delta.observed_logical_cpus = capacity;
            let report = compare_run_predictions(&valid, &executions, &delta);
            assert!((report.cpu.predicted.unwrap() - 0.3).abs() < 1e-12);
            assert_eq!(report.cpu.known_subtotal, report.cpu.predicted);
            assert_eq!(report.cpu.observed, Some(0.2));
            assert!(report.cpu.complete);
            assert!(!report.cpu.comparable);
            assert_eq!(report.cpu.observed_minus_predicted, None);
            assert!(report
                .cpu
                .unavailable
                .iter()
                .any(|reason| reason.contains("capacities")));
            assert!(report.memory.comparable);
        }
    }

    #[test]
    fn non_kill_only_success_is_unknown_and_no_success_is_explicit_zero() {
        let (mut plan, mut snapshot, mut executions) = fixture();
        plan.actions.truncate(1);
        snapshot.actions.truncate(1);
        executions.truncate(1);
        plan.actions[0].action = Action::Pause;
        snapshot.actions[0].action = Action::Pause;
        assert!(
            snapshot.validate(&plan).is_err(),
            "a pause cannot claim a kill footprint"
        );
        snapshot.actions[0].memory = None;
        snapshot.actions[0].cpu = None;
        snapshot.actions[0].file_descriptors = None;
        executions[0].action = Action::Pause;
        let valid = snapshot.validate(&plan).unwrap();
        let report = compare_run_predictions(&valid, &executions, &observed_delta(25.0, -20.0));
        assert!(!report.memory.complete);
        assert!(!report.cpu.complete);
        assert!(!report.file_descriptors.complete);
        assert_eq!(report.memory.predicted, None);
        executions[0].status = "failed".into();
        for actions in [executions.as_slice(), &[]] {
            let report = compare_run_predictions(&valid, actions, &observed_delta(25.0, -20.0));
            assert!(report.successful_action_ids.is_empty());
            assert_eq!(report.unique_targets, 0);
            for metric in [&report.memory, &report.cpu, &report.file_descriptors] {
                assert!(metric.complete);
                assert_eq!(metric.predicted, Some(0.0));
            }
            assert!(report.attribution.contains("not_per_action_causal"));
        }
    }

    #[test]
    fn observed_worsening_is_preserved_and_changed_prediction_cannot_replace_original() {
        let (plan, snapshot, executions) = fixture();
        let valid = snapshot.validate(&plan).unwrap();
        let mut delta = observed_delta(-50.0, 20.0);
        attach_prediction_comparison(
            &mut delta,
            Some(&snapshot),
            Some(&valid),
            &plan,
            &executions,
        );
        let report = delta.prediction_comparison.as_ref().unwrap();
        assert_eq!(report.memory.observed, Some(-50.0));
        assert_eq!(report.memory.observed_minus_predicted, Some(-80.0));
        assert_eq!(report.cpu.observed, Some(-0.2));
        let mut edited = snapshot.clone();
        edited.actions[0].memory = Some(PrivateMemoryPrediction::new(5, 500, None, 1000).unwrap());
        attach_prediction_comparison(&mut delta, Some(&edited), Some(&valid), &plan, &executions);
        assert!(delta.prediction_comparison.is_none());
        assert_eq!(delta.available_memory_bytes.delta, Some(-50.0));
        assert!(delta
            .unavailable
            .iter()
            .any(|missing| missing.reason.contains("differ")));
        attach_prediction_comparison(&mut delta, None, Some(&valid), &plan, &executions);
        assert!(delta.prediction_comparison.is_none());
        let mut future = snapshot;
        future.generated_at = "1970-01-01T00:00:04Z".into();
        let future_valid = future.validate(&plan).unwrap();
        attach_prediction_comparison(
            &mut delta,
            Some(&future),
            Some(&future_valid),
            &plan,
            &executions,
        );
        assert!(delta.prediction_comparison.is_none());
        assert!(delta
            .unavailable
            .iter()
            .any(|missing| missing.reason.contains("after a bound")));
    }
}
