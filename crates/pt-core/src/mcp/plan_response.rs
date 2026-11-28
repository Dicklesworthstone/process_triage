//! Bounded, read-only views of a validated canonical planner document.

use super::response_budget::{escaped_len, result_size};
use super::scan_response::{DEFAULT_BYTES, MIN_BYTES};
use serde_json::{json, Value};

pub(super) const MAX_PLAN_BYTES: usize = 8 * 1024 * 1024;
pub(super) const PLAN_FIELDS: &[&str] = &[
    "responsible_units",
    "agent_activity",
    "goal_summary",
    "goal_progress",
    "differential",
    "resource_predictions",
    "evidence_ledger",
    "pressure_decision",
    "predictions",
];
const ROW_FIELDS: &[&str] = &["evidence_ledger", "pressure_decision", "predictions"];

pub(super) struct PlanOutput {
    full: bool,
    budget: usize,
    fields: Vec<&'static str>,
}

impl PlanOutput {
    pub(super) fn parse(params: &Value) -> Result<Self, String> {
        let full = match params.get("detail").map(Value::as_str) {
            None | Some(Some("brief")) => false,
            Some(Some("full")) => true,
            _ => return Err("detail must be brief or full".into()),
        };
        let budget = match params.get("max_response_bytes") {
            None => DEFAULT_BYTES,
            Some(v) => v.as_u64().and_then(|n| usize::try_from(n).ok())
                .filter(|n| (MIN_BYTES..=MAX_PLAN_BYTES).contains(n))
                .ok_or_else(|| format!("max_response_bytes must be an integer between {MIN_BYTES} and {MAX_PLAN_BYTES}"))?,
        };
        let mut fields = Vec::new();
        if let Some(value) = params.get("fields") {
            if full {
                return Err("fields can only be selected with brief detail".into());
            }
            let names = value
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or("fields must be a nonempty array of unique plan field names")?;
            for value in names {
                let name = PLAN_FIELDS
                    .iter()
                    .copied()
                    .find(|n| Some(*n) == value.as_str())
                    .ok_or("unknown plan field")?;
                if fields.contains(&name) {
                    return Err(format!("duplicate plan field: {name}"));
                }
                fields.push(name);
            }
        }
        for (enabled, name) in [
            (params.get("goal").is_some(), "goal_summary"),
            (params.get("goal").is_some(), "goal_progress"),
            (
                params.get("since").is_some() || params.get("since_time").is_some(),
                "differential",
            ),
            (params["include_predictions"] == true, "predictions"),
            (
                params["include_predictions"] == true,
                "resource_predictions",
            ),
        ] {
            if enabled && !fields.contains(&name) {
                fields.push(name);
            }
        }
        Ok(Self {
            full,
            budget,
            fields,
        })
    }

    pub(super) fn render(&self, plan: &Value, original: String) -> Result<String, String> {
        let required = result_size(&original);
        if self.full && required <= self.budget {
            return Ok(original);
        }
        let candidates = plan["candidates"]
            .as_array()
            .ok_or("missing plan candidates")?;
        let summary = &plan["summary"];
        let skipped = summary["decision_skipped"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut view = json!({
            "view": if self.full { "reference" } else { "brief" },
            "session_id": plan["session_id"], "plan_id": plan["plan_id"],
            "generated_at": plan["generated_at"], "artifact": "decision/plan.json",
            "summary": {
                "total_processes_scanned": summary["total_processes_scanned"],
                "candidates_returned": candidates.len(),
                "decision_complete": summary["decision_complete"].as_bool().unwrap_or(true),
                "decision_skipped_count": skipped.len(),
                "decision_skipped": [],
            },
            "response": {
                "max_bytes": self.budget, "full_response_bytes": required,
                "candidate_rows_omitted": candidates.len(), "decision_skipped_omitted": skipped.len(),
            },
            "truncated": false,
        });
        if self.full {
            view["reason"] = json!("full_plan_exceeds_response_budget");
            view["truncated"] = json!(true);
        } else {
            for name in [
                "above_threshold",
                "kill_recommendations",
                "review_recommendations",
                "policy_blocked",
                "goal_achievable",
                "goal_selected_count",
            ] {
                if let Some(value) = summary.get(name) {
                    view["summary"][name] = value.clone();
                }
            }
            view["candidates"] = json!([]);
            view["response"]["requested_fields"] = json!(self.fields);
            // Reserve names for a worst-case omission report while packing rows.
            view["response"]["elided_fields"] = json!(self.fields);
            view["response"]["unavailable_fields"] = json!(self.fields);
        }
        let mut used = result_size(&view.to_string());
        let mut skipped_rows = Vec::new();
        // Keep failure visibility even when ranked candidates fill the budget.
        let failure_budget = if self.full || candidates.is_empty() {
            self.budget
        } else {
            used + self.budget.saturating_sub(used) / 3
        };
        for skipped in skipped {
            let mut row = select(skipped, &["pid", "uid", "start_id", "stage"]);
            preview(&mut row, skipped, "reason");
            if !push_row(row, &mut skipped_rows, &mut used, failure_budget) {
                break;
            }
        }
        view["response"]["decision_skipped_omitted"] = json!(skipped.len() - skipped_rows.len());
        view["summary"]["decision_skipped"] = Value::Array(skipped_rows);
        if !self.full {
            let mut rows = Vec::new();
            for candidate in candidates {
                let mut row = select(
                    candidate,
                    &[
                        "pid",
                        "uid",
                        "start_id",
                        "score",
                        "classification",
                        "recommended_action",
                        "action_target",
                        "plan_action_ids",
                        "policy_blocked",
                        "goal_selected",
                    ],
                );
                preview(&mut row, candidate, "command_short");
                preview(&mut row, candidate, "action_rationale");
                if !push_row(row, &mut rows, &mut used, self.budget) {
                    break;
                }
            }
            let omitted = candidates.len() - rows.len();
            view["response"]["candidate_rows_omitted"] = json!(omitted);
            let mut elided = Vec::new();
            let mut unavailable = Vec::new();
            for &name in &self.fields {
                if ROW_FIELDS.contains(&name) {
                    // A selected column is complete for every returned row, or
                    // explicitly elided for all of them.
                    if !candidates[..rows.len()]
                        .iter()
                        .any(|c| c.get(name).is_some())
                    {
                        unavailable.push(name);
                        continue;
                    }
                    let extra: usize = candidates[..rows.len()]
                        .iter()
                        .filter_map(|c| c.get(name))
                        .map(|v| field_cost(name, v))
                        .sum();
                    if used + extra > self.budget {
                        elided.push(name);
                    } else {
                        used += extra;
                        for (row, candidate) in rows.iter_mut().zip(candidates) {
                            if let Some(value) = candidate.get(name) {
                                row[name] = value.clone();
                            }
                        }
                    }
                } else if let Some(value) = plan.get(name) {
                    let extra = field_cost(name, value);
                    if used + extra > self.budget {
                        elided.push(name);
                    } else {
                        used += extra;
                        view[name] = value.clone();
                    }
                } else {
                    unavailable.push(name);
                }
            }
            view["response"]["elided_fields"] = json!(elided);
            view["response"]["unavailable_fields"] = json!(unavailable);
            view["truncated"] = json!(
                omitted > 0
                    || !elided.is_empty()
                    || view["response"]["decision_skipped_omitted"] != 0
            );
            view["candidates"] = Value::Array(rows);
        }
        let text = view.to_string();
        if result_size(&text) > self.budget {
            return Err("plan reference metadata exceeds the MCP response byte budget".into());
        }
        Ok(text)
    }
}

fn select(source: &Value, names: &[&str]) -> Value {
    Value::Object(
        names
            .iter()
            .filter_map(|&name| {
                source
                    .get(name)
                    .map(|value| (name.to_owned(), value.clone()))
            })
            .collect(),
    )
}

fn preview(row: &mut Value, source: &Value, key: &str) {
    if let Some(text) = source[key].as_str() {
        let mut end = text.len().min(256);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        row[key] = json!(&text[..end]);
        if end < text.len() {
            row[format!("{key}_truncated")] = json!(true);
        }
    }
}

fn push_row(row: Value, rows: &mut Vec<Value>, used: &mut usize, budget: usize) -> bool {
    let extra = escaped_len(&row.to_string()) + usize::from(!rows.is_empty());
    if *used + extra > budget {
        return false;
    }
    *used += extra;
    rows.push(row);
    true
}

fn field_cost(name: &str, value: &Value) -> usize {
    // One comma, two escaped quotes, a colon, plus the key and encoded value.
    6 + name.len() + escaped_len(&value.to_string())
}

/// Older canonical documents carry no decision-coverage marker and retain
/// their original clean/plan-ready statuses. A partial child must supply the
/// complete inventory of decisions it could not make.
pub(super) fn check_worker_coverage(
    document: &Value,
    candidate_count: usize,
    exit: Option<i32>,
) -> bool {
    let Ok(skipped) = crate::session::snapshot_persist::recorded_plan_decision_skips(document)
    else {
        return false;
    };
    let expected_exit = if skipped.is_empty() {
        i32::from(candidate_count != 0)
    } else {
        3
    };
    exit == Some(expected_exit)
        && document["summary"]["total_processes_scanned"]
            .as_u64()
            .is_some_and(|total| total >= (candidate_count + skipped.len()) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::{JsonRpcResponse, ToolContent};

    fn wire(text: String) -> usize {
        let content = ToolContent {
            content_type: "text".into(),
            text,
        };
        serde_json::to_vec(&JsonRpcResponse::success(
            Some(json!(1)),
            json!({"content":[content],"isError":false}),
        ))
        .unwrap()
        .len()
    }

    fn plan(n: usize, skipped: usize) -> Value {
        let evidence = "\"\n\\".repeat(4000);
        let why = "🦀".repeat(300);
        json!({
            "command":"agent plan", "plan_id":"plan-test", "session_id":"test-session",
            "generated_at":"time", "actions":[{"action_id":"real-action"}],
            "responsible_units": evidence, "agent_activity": {"live":true},
            "summary": {"total_processes_scanned":n+skipped, "candidates_returned":n,
                "decision_complete":skipped == 0, "decision_skipped_count":skipped,
                "decision_skipped":(0..skipped).map(|i| json!({"pid":i+n+1,"uid":1,"start_id":format!("boot:{i}:{}", i+n+1),
                    "stage":"inference","reason":why})).collect::<Vec<_>>()
            },
            "candidates":(0..n).map(|i| json!({"pid":i+1,"uid":1,"start_id":format!("boot:{i}:{}", i+1),"score":88,
                "command_short":"worker", "recommended_action":"review","action_rationale":why,
                "predictions":{"observations":1},"evidence_ledger":evidence})).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn review_preserves_partial_coverage_identity_and_reports_exact_budget_omissions() {
        let doc = plan(64, 30);
        let output = PlanOutput::parse(&json!({"max_response_bytes":4096,
            "fields":["evidence_ledger","responsible_units","agent_activity"],"include_predictions":true})).unwrap();
        let text = output.render(&doc, doc.to_string()).unwrap();
        let view: Value = serde_json::from_str(&text).unwrap();
        assert!(wire(text) <= 4096);
        assert_eq!(view["view"], "brief");
        assert!(view.get("actions").is_none());
        assert_eq!(view["artifact"], "decision/plan.json");
        assert_eq!(view["summary"]["decision_complete"], false);
        assert_eq!(view["summary"]["decision_skipped_count"], 30);
        let failures = view["summary"]["decision_skipped"].as_array().unwrap();
        let candidates = view["candidates"].as_array().unwrap();
        assert!(!failures.is_empty() && !candidates.is_empty());
        assert_eq!(
            view["response"]["decision_skipped_omitted"],
            30 - failures.len()
        );
        assert_eq!(
            view["response"]["candidate_rows_omitted"],
            64 - candidates.len()
        );
        assert_eq!(view["truncated"], true);
        assert_eq!(failures[0]["reason_truncated"], true);
        assert_eq!(failures[0]["reason"].as_str().unwrap().len(), 256);
        assert_eq!(candidates[0]["pid"], 1);
        assert_eq!(candidates[0]["start_id"], "boot:0:1");
        assert_eq!(candidates[0]["action_rationale_truncated"], true);
        assert!(candidates
            .iter()
            .all(|row| row.get("evidence_ledger").is_none()));
        let omitted = view["response"]["elided_fields"].as_array().unwrap();
        assert!(
            omitted.contains(&json!("evidence_ledger"))
                && omitted.contains(&json!("responsible_units"))
        );
    }

    #[test]
    fn full_is_byte_exact_or_an_explicit_non_executable_reference() {
        let doc = plan(1, 1);
        let original = format!("\n{}\r\n", serde_json::to_string_pretty(&doc).unwrap());
        let exact = result_size(&original);
        let render = |budget| {
            PlanOutput::parse(&json!({"detail":"full","max_response_bytes":budget}))
                .unwrap()
                .render(&doc, original.clone())
                .unwrap()
        };
        assert_eq!(render(exact), original);
        let text = render(exact - 1);
        assert!(wire(text.clone()) <= exact - 1);
        let reference: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(reference["view"], "reference");
        assert_eq!(reference["reason"], "full_plan_exceeds_response_budget");
        assert_eq!(reference["summary"]["decision_complete"], false);
        assert_eq!(reference["response"]["full_response_bytes"], exact);
        assert!(reference.get("actions").is_none() && reference.get("candidates").is_none());
        let options = PlanOutput::parse(
            &json!({"fields":["evidence_ledger","agent_activity"],"max_response_bytes":8388608}),
        )
        .unwrap();
        let brief: Value = serde_json::from_str(&options.render(&doc, original).unwrap()).unwrap();
        assert_eq!(brief["agent_activity"], doc["agent_activity"]);
        assert_eq!(
            brief["candidates"][0]["evidence_ledger"],
            doc["candidates"][0]["evidence_ledger"]
        );
        assert_eq!(brief["response"]["elided_fields"], json!([]));
        assert!(brief.get("responsible_units").is_none());
    }

    #[test]
    fn partial_exit_requires_consistent_coverage_even_when_no_candidates_survive() {
        for n in [0, 1] {
            let mut doc = plan(n, 1);
            let clean = Some(i32::from(n > 0));
            let legacy = json!({"summary":{"total_processes_scanned":n}, "candidates":doc["candidates"]});
            assert!(check_worker_coverage(&legacy, n, clean));
            assert!(!check_worker_coverage(&legacy, n, Some(3)));
            assert!(check_worker_coverage(&doc, n, Some(3)));
            assert!(!check_worker_coverage(&doc, n, clean));
            let text = PlanOutput::parse(&json!({}))
                .unwrap()
                .render(&doc, doc.to_string())
                .unwrap();
            let brief: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(brief["summary"]["decision_complete"], false);
            assert_eq!(brief["candidates"].as_array().unwrap().len(), n);
            for (path, value) in [
                ("/summary/decision_skipped_count", json!(2)),
                ("/summary/total_processes_scanned", json!(n)),
                ("/summary/decision_skipped/0/reason", Value::Null),
                ("/summary/decision_skipped/0/reason", json!(" ")),
                ("/summary/decision_skipped/0/stage", json!(" ")),
                ("/summary/decision_skipped/0/start_id", json!("boot:22:99")),
            ] {
                let mut invalid = doc.clone();
                *invalid.pointer_mut(path).unwrap() = value;
                assert!(!check_worker_coverage(&invalid, n, Some(3)), "{path}");
            }
            let skipped_pid = (n + 1).to_string();
            doc["summary"]["protected_by_pid"] = json!({skipped_pid: "protected"});
            assert!(!check_worker_coverage(&doc, n, Some(3)));
            if n > 0 {
                let mut overlap = plan(n, 1);
                overlap["summary"]["decision_skipped"][0]["pid"] = json!(1);
                overlap["summary"]["decision_skipped"][0]["start_id"] = json!("boot:0:1");
                assert!(!check_worker_coverage(&overlap, n, Some(3)));
            }
            let complete = plan(n, 0);
            assert!(check_worker_coverage(&complete, n, clean));
            assert!(!check_worker_coverage(&complete, n, Some(3)));

        }
    }

    #[test]
    fn selectors_reject_unknown_ambiguous_and_out_of_range_requests() {
        for params in [
            json!({"detail":true}),
            json!({"detail":"minimal"}),
            json!({"fields":[]}),
            json!({"fields":["typo"]}),
            json!({"fields":["agent_activity","agent_activity"]}),
            json!({"fields":[false]}),
            json!({"detail":"full","fields":["pressure_decision"]}),
            json!({"max_response_bytes":4095}),
            json!({"max_response_bytes":MAX_PLAN_BYTES+1}),
            json!({"max_response_bytes":5.5}),
        ] {
            assert!(PlanOutput::parse(&params).is_err(), "{params}");
        }
    }
}
