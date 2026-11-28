//! An aggregate of the verifier's saved, identity-bound action observations.

use super::{BundleError, Result};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

/// Portable verification evidence. Only the session binding, observation time
/// and counts can reach an archive, including under the minimal profile.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationSummary {
    session_id: String,
    completed_at: DateTime<FixedOffset>,
    outcomes: BTreeMap<Outcome, u32>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    ConfirmedDead,
    ConfirmedStopped,
    ConfirmedEffect,
    ConfirmedRestored,
    RestorationUnverified,
    ExecutionUncertain,
    EffectNotObserved,
    StillRunning,
    Respawned,
    PidReused,
    Unsupported,
    #[serde(other)]
    Other,
}

fn invalid(message: &str) -> BundleError {
    BundleError::CorruptedManifest(format!("recorded verification: {message}"))
}

fn identity_text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|id| !id.is_empty() && *id != "[REDACTED]")
}

impl VerificationSummary {
    /// Bind observations to the source plan before any identities are removed
    /// or pseudonymized. A legacy record without an identity yields no summary.
    pub fn from_artifacts(session: &str, plan: &Value, saved: &Value) -> Result<Option<Self>> {
        let (Some(plan_session), Some(saved_session), Some(actions)) = (
            plan["session_id"].as_str(),
            saved["session_id"].as_str(),
            plan["actions"].as_array(),
        ) else {
            return Ok(None);
        };
        if plan_session != session || saved_session != session {
            return Err(invalid("session ID mismatch"));
        }
        let window = &saved["verification"];
        let time = |key: &str| {
            window[key]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .ok_or_else(|| invalid("invalid observation time"))
        };
        let completed_at = time("completed_at")?;
        if completed_at < time("requested_at")? {
            return Err(invalid("observation window is reversed"));
        }
        let rows = saved["action_outcomes"]
            .as_array()
            .ok_or_else(|| invalid("missing action outcomes"))?;
        let mut planned = BTreeMap::new();
        for action in actions {
            let Some(id) = identity_text(&action["action_id"]) else {
                return Ok(None);
            };
            if planned.insert(id, action).is_some() {
                return Err(invalid("ambiguous action ID in plan"));
            }
        }

        let mut seen = HashSet::new();
        let mut outcomes = BTreeMap::<Outcome, u32>::new();
        for row in rows {
            let Some(id) = identity_text(&row["action_id"]) else {
                return Ok(None);
            };
            let action = planned
                .get(id)
                .ok_or_else(|| invalid("action absent from plan"))?;
            let target = &action["target"];
            let observed = &row["target"];
            let (Some(birth), Some(observed_birth), Some(kind), Some(observed_kind)) = (
                identity_text(&target["start_id"]),
                identity_text(&observed["start_id"]),
                identity_text(&action["action"]),
                identity_text(&row["action"]),
            ) else {
                return Ok(None);
            };
            if target["pid"].is_null() || observed["pid"].is_null() || target["uid"].is_null() {
                return Ok(None);
            }
            let id_number = |record: &Value, field: &str| {
                record[field]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| invalid("missing or invalid numeric target identity"))
            };
            let pid = id_number(target, "pid")?;
            if !seen.insert(id)
                || pid == 0
                || pid != id_number(observed, "pid")?
                || id_number(target, "uid")? != id_number(observed, "uid")?
                || birth != observed_birth
                || !kind.eq_ignore_ascii_case(observed_kind)
            {
                return Err(invalid("ambiguous or mismatched action target"));
            }
            if row["outcome"].as_str().is_none_or(str::is_empty) {
                return Err(invalid("missing observed outcome"));
            }
            let outcome = serde_json::from_value(row["outcome"].clone())?;
            let count = outcomes.entry(outcome).or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| invalid("too many outcomes"))?;
        }
        Ok(Some(Self {
            session_id: session.into(),
            completed_at,
            outcomes,
        }))
    }

    pub(super) fn bind_export_session(&mut self, exported_session: &str) {
        self.session_id = exported_session.to_owned();
    }

    /// Recheck the archive's session binding and expose only aggregate facts.
    pub fn report_value(&self, session: &str) -> Result<Value> {
        if self.session_id != session {
            return Err(invalid("exported summary belongs to another session"));
        }
        let count: u64 = self.outcomes.values().map(|n| u64::from(*n)).sum();
        Ok(
            json!({"completed_at": self.completed_at.to_rfc3339(), "count": count, "outcomes": self.outcomes}),
        )
    }
}
