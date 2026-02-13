#![cfg(all(feature = "daemon", unix))]

//! E2E tests for dormant daemon behavior (feature-gated behind `daemon`).
//!
//! These tests exercise the CLI daemon loop end-to-end (spawn process, write
//! config, observe state/inbox artifacts), without requiring any UI.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn write_daemon_json_config(config_dir: &Path, content: &str) {
    fs::create_dir_all(config_dir).expect("create config dir");
    fs::write(config_dir.join("daemon.json"), content).expect("write daemon.json");
}

fn write_config_file(config_dir: &Path, name: &str, content: &str) {
    fs::create_dir_all(config_dir).expect("create config dir");
    fs::write(config_dir.join(name), content).expect("write config file");
}

fn daemon_pid_path(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon").join("daemon.pid")
}

fn daemon_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon").join("state.json")
}

fn inbox_items_path(data_dir: &Path) -> PathBuf {
    data_dir.join("inbox").join("items.jsonl")
}

fn acquire_global_lock(data_dir: &Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;

    let path = data_dir.join(".pt-lock");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open lock file");

    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "expected to acquire global lock at {:?}", path);
    file
}

fn start_daemon_foreground(config_dir: &Path, data_dir: &Path) -> Child {
    let exe = assert_cmd::cargo::cargo_bin!("pt-core");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--format",
        "json",
        "--config",
        config_dir.to_string_lossy().as_ref(),
        "daemon",
        "start",
        "--foreground",
    ]);

    cmd.env("PROCESS_TRIAGE_DATA", data_dir);
    cmd.env("PROCESS_TRIAGE_CONFIG", config_dir);
    // The daemon loop uses the global lock directly; make sure we do not skip it.
    cmd.env_remove("PT_SKIP_GLOBAL_LOCK");

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd.spawn().expect("spawn daemon")
}

fn send_signal(child: &Child, signal: i32) {
    let pid = child.id() as i32;
    let rc = unsafe { libc::kill(pid, signal) };
    assert_eq!(
        rc,
        0,
        "failed to send signal {} to pid {}: {}",
        signal,
        pid,
        std::io::Error::last_os_error()
    );
}

fn send_sigterm(child: &Child) {
    send_signal(child, libc::SIGTERM);
}

fn wait_for<F: FnMut() -> bool>(timeout: Duration, mut f: F) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {:?}", timeout);
}

fn read_jsonl_items(path: &Path) -> Vec<Value> {
    let content = fs::read_to_string(path).expect("read jsonl");
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("valid JSONL line"))
        .collect()
}

#[test]
fn daemon_lock_contention_writes_inbox_item_and_cleans_pid() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 1,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": -1.0,
    "memory_threshold": 2.0,
    "orphan_threshold": 999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let _lock = acquire_global_lock(data_dir.path());
    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let inbox_path = inbox_items_path(data_dir.path());
    wait_for(Duration::from_secs(10), || {
        inbox_path.exists()
            && read_jsonl_items(&inbox_path).iter().any(|v| {
                v.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t == "lock_contention")
                    .unwrap_or(false)
            })
    });

    send_sigterm(&child);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().unwrap().is_some()
    });

    // Ensure the daemon cleaned up its own pid file.
    assert!(
        !daemon_pid_path(data_dir.path()).exists(),
        "daemon pid file should be removed on clean shutdown"
    );
}

#[test]
fn daemon_trigger_cooldown_prevents_repeated_lock_contention_spam() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 1,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": -1.0,
    "memory_threshold": 2.0,
    "orphan_threshold": 999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 100
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let _lock = acquire_global_lock(data_dir.path());
    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let inbox_path = inbox_items_path(data_dir.path());
    wait_for(Duration::from_secs(10), || inbox_path.exists());
    std::thread::sleep(Duration::from_secs(3)); // allow multiple ticks

    send_sigterm(&child);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().unwrap().is_some()
    });

    let items = read_jsonl_items(&inbox_path);
    let lock_items = items
        .iter()
        .filter(|v| v.get("type").and_then(|t| t.as_str()) == Some("lock_contention"))
        .count();
    assert_eq!(
        lock_items, 1,
        "cooldown should prevent repeated lock contention entries across ticks"
    );
}

#[test]
fn daemon_signal_storm_remains_alive_during_storm() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 5,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": -1.0,
    "memory_threshold": 2.0,
    "orphan_threshold": 999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());
    std::thread::sleep(Duration::from_millis(250));

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should still be running shortly after startup"
    );

    for _ in 0..250 {
        send_signal(&child, libc::SIGUSR1);
    }
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should remain alive after SIGUSR1 storm"
    );

    // Use SIGKILL for deterministic teardown in this chaos test; the purpose here
    // is to ensure the daemon stays alive while under the signal burst.
    send_signal(&child, libc::SIGKILL);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().expect("query child status").is_some()
    });
    let _ = child.wait().expect("wait for daemon exit status");
}

#[test]
fn daemon_sigint_stops_and_cleans_pid_file() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 30,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": 9999.0,
    "memory_threshold": 9999.0,
    "orphan_threshold": 9999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let pid_path = daemon_pid_path(data_dir.path());
    wait_for(Duration::from_secs(10), || pid_path.exists());
    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should be alive before SIGINT"
    );

    send_signal(&child, libc::SIGINT);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().expect("query child status").is_some()
    });

    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGINT");
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after SIGINT shutdown"
    );
}

#[test]
fn daemon_sigterm_stops_and_cleans_pid_file() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 30,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": 9999.0,
    "memory_threshold": 9999.0,
    "orphan_threshold": 9999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let pid_path = daemon_pid_path(data_dir.path());
    wait_for(Duration::from_secs(10), || pid_path.exists());
    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should be alive before SIGTERM"
    );

    send_sigterm(&child);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().expect("query child status").is_some()
    });

    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGTERM");
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after SIGTERM shutdown"
    );
}

#[test]
fn daemon_sighup_reloads_config_without_exiting() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 1,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": 9999.0,
    "memory_threshold": 9999.0,
    "orphan_threshold": 9999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());
    let pid_path = daemon_pid_path(data_dir.path());
    let state_path = daemon_state_path(data_dir.path());
    wait_for(Duration::from_secs(10), || {
        pid_path.exists() && state_path.exists()
    });

    send_signal(&child, libc::SIGHUP);
    wait_for(Duration::from_secs(10), || {
        let content = fs::read_to_string(&state_path).expect("read state.json");
        let json: Value = serde_json::from_str(&content).expect("valid state json");
        let events = json
            .get("daemon")
            .and_then(|d| d.get("recent_events"))
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        events.iter().any(|ev| {
            ev.get("event_type")
                .and_then(|t| t.as_str())
                .map(|t| t == "config_reloaded")
                .unwrap_or(false)
        })
    });

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should stay running after SIGHUP config reload"
    );

    send_sigterm(&child);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().expect("query child status").is_some()
    });
    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGTERM");
}

#[test]
fn daemon_restart_after_sigkill_recovers_cleanly() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 30,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": 9999.0,
    "memory_threshold": 9999.0,
    "orphan_threshold": 9999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let pid_path = daemon_pid_path(data_dir.path());

    let mut first = start_daemon_foreground(config_dir.path(), data_dir.path());
    wait_for(Duration::from_secs(10), || pid_path.exists());
    let first_pid: u32 = fs::read_to_string(&pid_path)
        .expect("read first daemon pid file")
        .trim()
        .parse()
        .expect("parse first daemon pid");
    assert!(
        first
            .try_wait()
            .expect("query first child status")
            .is_none(),
        "first daemon should be alive before SIGKILL"
    );

    send_signal(&first, libc::SIGKILL);
    wait_for(Duration::from_secs(10), || {
        first
            .try_wait()
            .expect("query first child status")
            .is_some()
    });
    let _ = first.wait().expect("wait for first daemon exit status");

    let mut second = start_daemon_foreground(config_dir.path(), data_dir.path());
    wait_for(Duration::from_secs(10), || {
        if !pid_path.exists() {
            return false;
        }
        let pid = fs::read_to_string(&pid_path)
            .expect("read second daemon pid file")
            .trim()
            .parse::<u32>()
            .expect("parse second daemon pid");
        pid != first_pid
    });
    assert!(
        second
            .try_wait()
            .expect("query second child status")
            .is_none(),
        "second daemon should be alive after SIGKILL recovery restart"
    );

    send_sigterm(&second);
    wait_for(Duration::from_secs(10), || {
        second
            .try_wait()
            .expect("query second child status")
            .is_some()
    });
    let status = second.wait().expect("wait for second daemon exit status");
    assert!(
        status.success(),
        "second daemon should exit cleanly after SIGTERM"
    );
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after clean second shutdown"
    );
}

#[test]
fn daemon_overhead_budget_exceeded_is_persisted_and_skips_inbox_writes() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 1,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 0,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": -1.0,
    "memory_threshold": 2.0,
    "orphan_threshold": 999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 10
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let state_path = daemon_state_path(data_dir.path());
    wait_for(Duration::from_secs(10), || state_path.exists());

    wait_for(Duration::from_secs(10), || {
        let content = fs::read_to_string(&state_path).expect("read state.json");
        let json: Value = serde_json::from_str(&content).expect("valid state json");
        let events = json
            .get("daemon")
            .and_then(|d| d.get("recent_events"))
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        events.iter().any(|ev| {
            ev.get("event_type")
                .and_then(|t| t.as_str())
                .map(|t| t == "overhead_budget_exceeded")
                .unwrap_or(false)
        })
    });

    send_sigterm(&child);
    wait_for(Duration::from_secs(10), || {
        child.try_wait().unwrap().is_some()
    });

    // When budget is exceeded we skip escalation; inbox should remain absent.
    assert!(
        !inbox_items_path(data_dir.path()).exists(),
        "no inbox items should be written when overhead budget is exceeded"
    );
}

#[test]
fn daemon_escalation_writes_dormant_inbox_item_and_session_log() {
    let data_dir = TempDir::new().expect("temp data dir");
    let config_dir = TempDir::new().expect("temp config dir");

    // Ensure daemon escalation can successfully run `pt-core agent plan` by
    // providing a minimal config set (policy + priors).
    write_config_file(
        config_dir.path(),
        "priors.json",
        r#"{
  "schema_version": "1.0.0",
  "description": "E2E daemon priors fixture",
  "classes": {
    "useful": {
      "prior_prob": 0.70,
      "cpu_beta": { "alpha": 5.0, "beta": 3.0 },
      "orphan_beta": { "alpha": 1.0, "beta": 20.0 },
      "tty_beta": { "alpha": 5.0, "beta": 3.0 },
      "net_beta": { "alpha": 4.0, "beta": 4.0 }
    },
    "useful_bad": {
      "prior_prob": 0.10,
      "cpu_beta": { "alpha": 7.0, "beta": 2.0 },
      "orphan_beta": { "alpha": 2.0, "beta": 8.0 },
      "tty_beta": { "alpha": 4.0, "beta": 4.0 },
      "net_beta": { "alpha": 3.0, "beta": 5.0 }
    },
    "abandoned": {
      "prior_prob": 0.15,
      "cpu_beta": { "alpha": 1.0, "beta": 8.0 },
      "orphan_beta": { "alpha": 6.0, "beta": 2.0 },
      "tty_beta": { "alpha": 1.0, "beta": 8.0 },
      "net_beta": { "alpha": 1.0, "beta": 6.0 }
    },
    "zombie": {
      "prior_prob": 0.05,
      "cpu_beta": { "alpha": 1.0, "beta": 100.0 },
      "orphan_beta": { "alpha": 10.0, "beta": 1.0 },
      "tty_beta": { "alpha": 1.0, "beta": 20.0 },
      "net_beta": { "alpha": 1.0, "beta": 50.0 }
    }
  }
}"#,
    );

    write_config_file(
        config_dir.path(),
        "policy.json",
        r#"{
  "schema_version": "1.0.0",
  "policy_id": "fixture-valid",
  "description": "E2E daemon policy fixture",
  "loss_matrix": {
    "useful": { "keep": 0, "kill": 100 },
    "useful_bad": { "keep": 10, "kill": 20 },
    "abandoned": { "keep": 30, "kill": 1 },
    "zombie": { "keep": 50, "kill": 1 }
  },
  "guardrails": {
    "protected_patterns": [
      { "pattern": ".*", "kind": "regex", "case_insensitive": true, "notes": "protect all for fast E2E" }
    ],
    "never_kill_ppid": [1],
    "max_kills_per_run": 5,
    "min_process_age_seconds": 0
  },
  "robot_mode": {
    "enabled": false,
    "min_posterior": 0.99,
    "max_blast_radius_mb": 4096,
    "max_kills": 5,
    "require_known_signature": false
  },
  "fdr_control": {
    "enabled": true,
    "method": "bh",
    "alpha": 0.05
  },
  "data_loss_gates": {
    "block_if_open_write_fds": true,
    "block_if_locked_files": true,
    "block_if_active_tty": true
  }
}"#,
    );

    write_daemon_json_config(
        config_dir.path(),
        r#"{
  "tick_interval_secs": 1,
  "max_cpu_percent": 1000.0,
  "max_rss_mb": 4096,
  "triggers": {
    "ewma_alpha": 0.3,
    "load_threshold": -1.0,
    "memory_threshold": 2.0,
    "orphan_threshold": 999999,
    "sustained_ticks": 1,
    "cooldown_ticks": 100
  },
  "escalation": {
    "min_interval_secs": 0,
    "allow_auto_mitigation": false,
    "max_deep_scan_targets": 1
  },
  "notifications": {
    "enabled": false,
    "desktop": false,
    "notify_cmd": null,
    "notify_arg": []
  }
}"#,
    );

    let mut child = start_daemon_foreground(config_dir.path(), data_dir.path());

    let inbox_path = inbox_items_path(data_dir.path());
    wait_for(Duration::from_secs(30), || {
        inbox_path.exists()
            && read_jsonl_items(&inbox_path).iter().any(|v| {
                v.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t == "dormant_escalation")
                    .unwrap_or(false)
            })
    });

    // Resolve the session id from the inbox item and ensure the session JSONL log was created.
    let items = read_jsonl_items(&inbox_path);
    let session_id = items
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("dormant_escalation"))
        .and_then(|v| v.get("session_id").and_then(|s| s.as_str()))
        .expect("dormant_escalation item should include session_id")
        .to_string();

    let session_log = data_dir
        .path()
        .join("sessions")
        .join(&session_id)
        .join("logs")
        .join("session.jsonl");

    wait_for(Duration::from_secs(30), || session_log.exists());

    // Spot-check that the session log contains at least one valid JSONL entry.
    let first_line = fs::read_to_string(&session_log)
        .expect("read session.jsonl")
        .lines()
        .next()
        .expect("session.jsonl should not be empty")
        .to_string();
    let v: Value = serde_json::from_str(&first_line).expect("valid JSONL line");
    assert!(
        v.get("event").is_some() && v.get("timestamp").is_some(),
        "expected progress event fields in session.jsonl"
    );

    send_sigterm(&child);
    wait_for(Duration::from_secs(30), || {
        child.try_wait().unwrap().is_some()
    });
}
