//! Read durable coordinator receipts without connecting to any fleet host.
use super::apply::{ApplyBindingReceipt, HostApplyStatus};
use pt_common::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

#[derive(Debug, Deserialize)]
struct IntentHost {
    host: String,
    request: Option<Request>,
}

#[derive(Debug, Deserialize)]
struct Request {
    host: String,
    binding: ApplyBindingReceipt,
    targets: Vec<ProcessIdentity>,
    actions: Vec<serde::de::IgnoredAny>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Observation {
    host: String,
    binding: Option<ApplyBindingReceipt>,
    selected_targets: Vec<ProcessIdentity>,
    status: HostApplyStatus,
    attempted: bool,
    successful_actions: usize,
    kill_signals_delivered: usize,
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Intent {
        attempt_id: String,
        fleet_session_id: String,
        created_at: String,
        hosts: Vec<IntentHost>,
    },
    HostResult { attempt_id: String, result: Observation },
    Finished { attempt_id: String, report: FinalReport },
}

#[derive(Deserialize)]
struct FinalReport {
    hosts: Vec<Observation>,
    persistence_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HostStatus {
    pub host: String,
    pub remote_session_id: Option<String>,
    pub status: HostApplyStatus,
    pub attempted: Option<bool>,
    pub successful_actions: Option<usize>,
    pub kill_signals_delivered: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AttemptStatus {
    pub attempt_id: String,
    pub created_at: Option<String>,
    pub finished: bool,
    pub hosts: Vec<HostStatus>,
    pub receipt_error: Option<String>,
}

fn record_matches(request: Option<&Request>, result: &Observation) -> bool {
    let actions = request.map_or(0, |r| r.actions.len());
    result.binding.as_ref() == request.map(|r| &r.binding)
        && result.selected_targets.as_slice() == request.map_or(&[][..], |r| r.targets.as_slice())
        && result.successful_actions <= actions
        && result.kill_signals_delivered <= actions
        && (result.attempted || (result.successful_actions == 0 && result.kill_signals_delivered == 0))
        && match result.status {
            HostApplyStatus::Preview => false,
            HostApplyStatus::Applied => result.attempted && actions > 0 && result.successful_actions == actions,
            HostApplyStatus::Partial | HostApplyStatus::Unknown => result.attempted,
            HostApplyStatus::NotStarted => !result.attempted,
            HostApplyStatus::NoActions => result.successful_actions == 0 && result.kill_signals_delivered == 0,
            HostApplyStatus::Blocked => result.successful_actions == 0 && result.kill_signals_delivered == 0,
        }
}

fn read_attempt(path: &Path, attempt_id: &str, session: &str) -> AttemptStatus {
    let mut attempt = AttemptStatus {
        attempt_id: attempt_id.into(),
        created_at: None,
        finished: false,
        hosts: Vec::new(),
        receipt_error: None,
    };
    let mut expected = BTreeMap::new();
    let mut seen = BTreeMap::new();
    let read = (|| -> Result<(), String> {
        // Never follow a link or block opening a FIFO in the session directory.
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("receipt is not a regular file".into());
        }
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        loop {
            line.clear();
            // Full intents and terminal reports contain the original action lists.
            const MAX_LINE: u64 = 64 * 1024 * 1024;
            let n = reader
                .by_ref()
                .take(MAX_LINE + 1)
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if n as u64 > MAX_LINE || line.last() != Some(&b'\n') {
                return Err("incomplete or oversized receipt record".into());
            }
            if attempt.finished { return Err("unexpected record after finished report".into()); }
            match serde_json::from_slice::<Event>(&line).map_err(|e| format!("invalid receipt record: {e}"))? {
                Event::Intent { attempt_id: id, fleet_session_id, created_at, hosts }
                    if id == attempt_id && fleet_session_id == session && attempt.created_at.is_none() => {
                    let mut names = BTreeMap::new();
                    for h in hosts {
                        if h.host.is_empty() || h.request.as_ref().is_some_and(|r| r.host != h.host)
                            || names.insert(h.host, h.request).is_some() {
                            return Err("duplicate or mismatched host in execution intent".into());
                        }
                    }
                    expected = names;
                    attempt.created_at = Some(created_at);
                }
                Event::HostResult { attempt_id: id, result } if id == attempt_id && attempt.created_at.is_some() => {
                    if !expected.get(&result.host).is_some_and(|r| record_matches(r.as_ref(), &result))
                        || seen.contains_key(&result.host)
                    {
                        seen.remove(&result.host);
                        return Err("duplicate or unbound host result".into());
                    }
                    seen.insert(result.host.clone(), result);
                }
                Event::Finished { attempt_id: id, report } if id == attempt_id && attempt.created_at.is_some() => {
                    let mut terminal = BTreeMap::new();
                    for result in report.hosts {
                        if !expected.get(&result.host).is_some_and(|r| record_matches(r.as_ref(), &result))
                            || seen.get(&result.host).is_some_and(|earlier| earlier != &result)
                            || terminal.contains_key(&result.host) {
                            seen.remove(&result.host);
                            return Err("inconsistent final host report".into());
                        }
                        terminal.insert(result.host.clone(), result);
                    }
                    if terminal.len() != expected.len() { return Err("final report omitted an intended host".into()); }
                    seen = terminal;
                    attempt.finished = true;
                    attempt.receipt_error = report.persistence_error;
                }
                _ => return Err("mismatched execution attempt, fleet session, or record order".into()),
            }
        }
        if attempt.created_at.is_none() { return Err("missing execution intent".into()); }
        Ok(())
    })();
    if let Err(error) = read {
        attempt.finished = false;
        attempt.receipt_error = Some(error);
    }
    for (host, request) in expected {
        let result = seen.get(&host);
        attempt.hosts.push(HostStatus {
            remote_session_id: request.map(|r| r.binding.session_id),
            status: result.map_or(HostApplyStatus::Unknown, |r| r.status),
            attempted: result.map(|r| r.attempted),
            successful_actions: result.map(|r| r.successful_actions),
            kill_signals_delivered: result.map(|r| r.kill_signals_delivered),
            host,
        });
    }
    attempt
}

pub fn apply_history(dir: &Path, session: &str) -> io::Result<Vec<AttemptStatus>> {
    let mut attempts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str()
            .and_then(|s| s.strip_prefix("fleet-apply-"))
            .and_then(|s| s.strip_suffix(".jsonl"))
        else {
            continue;
        };
        attempts.push(read_attempt(&entry.path(), id, session));
    }
    attempts.sort_by(|a, b| {
        a.created_at.cmp(&b.created_at).then_with(|| a.attempt_id.cmp(&b.attempt_id))
    });
    Ok(attempts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::Write;

    fn target() -> ProcessIdentity {
        ProcessIdentity::new(42, pt_common::StartId::from_linux("boot", 180, 42), 1000)
    }

    fn request(host: &str) -> Value {
        json!({"host":host, "binding":{"host_id":host, "session_id": "remote", "plan_sha256": "digest"},
            "targets":[target()], "actions":[{"action": "kill"}]})
    }

    fn intent() -> Value {
        let hosts = ["a", "b"].map(|h| json!({"host":h, "request":request(h)}));
        json!({"event": "intent", "attempt_id": "one", "fleet_session_id": "session", "created_at": "2026-11-26T00:00:00Z",
            "hosts":hosts})
    }

    fn observation(host: &str, status: &str, successes: usize, signals: usize) -> Value {
        json!({"host":host, "binding":request(host)["binding"], "selected_targets":[target()],
            "status":status, "attempted":true, "successful_actions":successes, "kill_signals_delivered":signals})
    }

    fn result(o: &Value) -> Value {
        json!({"event": "host_result", "attempt_id": "one", "result":o})
    }

    fn replay(events: &[Value], suffix: &[u8]) -> AttemptStatus {
        let dir = tempfile::tempdir().unwrap();
        let mut f = fs::File::create(dir.path().join("fleet-apply-one.jsonl")).unwrap();
        for e in events { writeln!(f, "{e}").unwrap(); }
        f.write_all(suffix).unwrap();
        apply_history(dir.path(), "session").unwrap().pop().unwrap()
    }

    #[test]
    fn interrupted_dispatch_keeps_acknowledged_host_and_leaves_other_counts_unknown() {
        let host = observation("a", "partial", 0, 1);
        for tail in [&[][..], &b"{\"event\": "[..]] {
            let status = replay(&[intent(),result(&host)], tail);
            assert!(!status.finished);
            assert_eq!(status.receipt_error.is_some(), !tail.is_empty());
            assert_eq!(status.hosts[0].status, HostApplyStatus::Partial);
            assert_eq!(status.hosts[0].kill_signals_delivered, Some(1));
            assert_eq!(status.hosts[1].status, HostApplyStatus::Unknown);
            assert_eq!(status.hosts[1].attempted, None);
            assert_eq!(status.hosts[1].successful_actions, None);
        }
    }

    #[test]
    fn final_report_can_recover_lost_host_rows_and_remote_no_actions() {
        let hosts = [observation("a", "applied", 1, 1),observation("b", "no_actions", 0, 0)];
        let end = json!({"event": "finished", "attempt_id": "one", "report":{"hosts":hosts, "persistence_error": "write failed"}});
        let status = replay(&[intent(), result(&hosts[0]),end], &[]);
        assert!(status.finished);
        assert_eq!(status.receipt_error.as_deref(), Some("write failed"));
        assert_eq!(status.hosts[1].attempted, Some(true));
        assert_eq!(status.hosts[1].status, HostApplyStatus::NoActions);
    }

    #[test]
    fn wrong_session_binding_and_conflicting_results_do_not_confirm_work() {
        let good = observation("a", "applied", 1, 1);
        let mut wrong = good.clone();
        wrong["binding"]["plan_sha256"] = json!("other");
        for events in [vec![intent(),result(&wrong)], vec![intent(),result(&good),result(&wrong)]] {
            let status = replay(&events, &[]);
            assert!(status.receipt_error.is_some());
            assert_eq!(status.hosts[0].status, HostApplyStatus::Unknown);
        }
        let mut foreign = intent();
        foreign["fleet_session_id"] = json!("another");
        let status = replay(&[foreign], &[]);
        assert!(status.hosts.is_empty());
        assert!(status.receipt_error.is_some());
    }
}
