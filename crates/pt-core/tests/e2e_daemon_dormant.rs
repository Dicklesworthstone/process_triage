#![cfg(all(feature = "daemon", unix))]

//! E2E tests for dormant daemon behavior (feature-gated behind `daemon`).
//!
//! These tests exercise the CLI daemon loop end-to-end (spawn process, write
//! config, observe state/inbox artifacts), without requiring any UI.

use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::os::unix::process::ExitStatusExt;
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

fn acquire_daemon_pid_lock(data_dir: &Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;

    let path = data_dir.join("daemon").join("daemon.pid.lock");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create daemon pid lock dir");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open daemon pid lock file");

    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "expected to acquire daemon pid lock at {:?}", path);
    file
}

fn read_diagnostic(path: &Path) -> Value {
    match fs::read_to_string(path) {
        Ok(content) => json!({ "path": path, "contents": content }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            json!({ "path": path, "missing": true })
        }
        Err(error) => json!({
            "path": path, "read_error": error.to_string(),
            "error_kind": format!("{:?}", error.kind()), "os_error": error.raw_os_error()
        }),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observed_priority(pid: u32) -> Value {
    // SAFETY: this observes priority only. Thread-local errno distinguishes a
    // legitimate nice -1 from an observation error.
    unsafe {
        #[cfg(target_os = "linux")]
        let errno = libc::__errno_location();
        #[cfg(target_os = "macos")]
        let errno = libc::__error();
        *errno = 0;
        let nice = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
        if *errno != 0 {
            json!({ "error": std::io::Error::last_os_error().to_string(), "os_error": *errno })
        } else {
            json!({ "nice": nice })
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn observed_priority(_pid: u32) -> Value {
    json!({ "unsupported": true })
}

fn observed_process(pid: u32) -> Value {
    #[cfg(target_os = "linux")]
    {
        let stat = read_diagnostic(Path::new(&format!("/proc/{pid}/stat")));
        let status = read_diagnostic(Path::new(&format!("/proc/{pid}/status")));
        let parsed_stat = match stat.get("contents").and_then(Value::as_str) {
            Some(content) => match pt_core::collect::parse_proc_stat_content(content) {
                Some(parsed) => json!({ "record": parsed }),
                None => json!({ "parse_error": "invalid proc stat" }),
            },
            None => json!({ "unavailable": true }),
        };
        let parsed_status = match status.get("contents").and_then(Value::as_str) {
            Some(content) => {
                match pt_core::collect::proc_parsers::parse_proc_status_content(content) {
                    Some(parsed) => json!({ "record": parsed }),
                    None => json!({ "parse_error": "invalid proc status" }),
                }
            }
            None => json!({ "unavailable": true }),
        };
        json!({
            "pid": pid, "priority": observed_priority(pid),
            "stat": stat, "status": status, "parsed_stat": parsed_stat,
            "parsed_status": parsed_status,
            "boot_id": read_diagnostic(Path::new("/proc/sys/kernel/random/boot_id"))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        json!({ "pid": pid, "priority": observed_priority(pid), "identity_probe_unsupported": true })
    }
}

fn fixture_artifact_dir(data_dir: &Path) -> PathBuf {
    let path = data_dir
        .join("daemon-fixture-logs")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&path).expect("create retained daemon artifact directory");
    path
}

struct OwnedDaemon {
    child: Child,
    data_dir: PathBuf,
    config_dir: PathBuf,
    artifact_dir: PathBuf,
}

impl OwnedDaemon {
    fn record_observation(&mut self, phase: &str, elapsed: Duration) -> Value {
        let child_status = match self.child.try_wait() {
            Ok(Some(status)) => {
                json!({ "running": false, "code": status.code(), "signal": status.signal() })
            }
            Ok(None) => json!({ "running": true }),
            Err(error) => {
                json!({ "status_error": error.to_string(), "os_error": error.raw_os_error() })
            }
        };
        let state = read_diagnostic(&daemon_state_path(&self.data_dir));
        let parsed_state = match state.get("contents").and_then(Value::as_str) {
            Some(content) => match serde_json::from_str::<Value>(content) {
                Ok(value) => json!({ "value": value }),
                Err(error) => json!({ "parse_error": error.to_string() }),
            },
            None => json!({ "unavailable": true }),
        };
        let process = if child_status.get("running").and_then(Value::as_bool) == Some(true) {
            observed_process(self.child.id())
        } else {
            json!({ "pid": self.child.id(), "unavailable_reason": "owned child exited or status unknown" })
        };
        let observation = json!({
            "phase": phase, "elapsed_ms": elapsed.as_millis(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "child": child_status, "process": process,
            "data_dir": self.data_dir, "config_dir": self.config_dir,
            "pid_file": read_diagnostic(&daemon_pid_path(&self.data_dir)),
            "state": state, "parsed_state": parsed_state,
            "inbox": read_diagnostic(&inbox_items_path(&self.data_dir)),
            "config": read_diagnostic(&self.config_dir.join("daemon.json")),
            "stdout": read_diagnostic(&self.artifact_dir.join("stdout.json")),
            "stderr": read_diagnostic(&self.artifact_dir.join("stderr.jsonl")),
            "artifact_dir": self.artifact_dir
        });
        let line = serde_json::to_string(&observation).expect("serialize daemon observation");
        eprintln!("{line}");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.artifact_dir.join("observations.jsonl"))
            .expect("open retained daemon observations");
        writeln!(file, "{line}").expect("write retained daemon observation");
        file.flush().expect("flush retained daemon observation");
        observation
    }
}

impl Deref for OwnedDaemon {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for OwnedDaemon {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        // An unreaped direct child keeps its PID bound to the original owned
        // incarnation. A cached exit status means no further signal is allowed.
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.child.kill() {
                    eprintln!(
                        "owned daemon {} cleanup kill failed: {error}",
                        self.child.id()
                    );
                }
                if let Err(error) = self.child.wait() {
                    eprintln!(
                        "owned daemon {} cleanup wait failed: {error}",
                        self.child.id()
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "owned daemon {} cleanup status unknown; no signal sent: {error}",
                    self.child.id()
                );
            }
        }
    }
}

fn start_daemon_foreground(config_dir: &Path, data_dir: &Path) -> OwnedDaemon {
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

    let artifact_dir = fixture_artifact_dir(data_dir);
    let stdout = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(artifact_dir.join("stdout.json"))
        .expect("create retained daemon stdout");
    let stderr = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(artifact_dir.join("stderr.jsonl"))
        .expect("create retained daemon stderr");
    cmd.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
    let invocation = json!({
        "executable": cmd.get_program().to_string_lossy(),
        "argv": cmd.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "config_dir": config_dir, "data_dir": data_dir,
        "overrides": { "PROCESS_TRIAGE_DATA": data_dir, "PROCESS_TRIAGE_CONFIG": config_dir,
            "PT_SKIP_GLOBAL_LOCK": null },
        "caller_pid": std::process::id(),
        // SAFETY: geteuid only observes the test's current owner.
        "caller_uid": unsafe { libc::geteuid() },
        "caller_thread_priority": observed_priority(0)
    });
    fs::write(
        artifact_dir.join("invocation.json"),
        serde_json::to_vec_pretty(&invocation).expect("serialize daemon invocation"),
    )
    .expect("write retained daemon invocation");
    let mut daemon = OwnedDaemon {
        child: cmd.spawn().expect("spawn daemon"),
        data_dir: data_dir.to_path_buf(),
        config_dir: config_dir.to_path_buf(),
        artifact_dir,
    };
    daemon.record_observation("spawned", Duration::ZERO);
    daemon
}

fn run_daemon_cli(
    config_dir: &Path,
    data_dir: &Path,
    daemon_args: &[&str],
) -> std::process::Output {
    let exe = assert_cmd::cargo::cargo_bin!("pt-core");
    let mut cmd = Command::new(exe);
    cmd.arg("--format")
        .arg("json")
        .arg("--config")
        .arg(config_dir)
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.args(daemon_args);
    let artifact_dir = fixture_artifact_dir(data_dir);
    let argv = cmd
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let started = Instant::now();
    let output = cmd.output().expect("run pt-core daemon command");
    fs::write(artifact_dir.join("stdout.json"), &output.stdout).expect("retain daemon CLI stdout");
    fs::write(artifact_dir.join("stderr.jsonl"), &output.stderr).expect("retain daemon CLI stderr");
    let record = json!({
        "executable": exe, "argv": argv, "data_dir": data_dir, "config_dir": config_dir,
        "caller_uid": unsafe { libc::geteuid() }, "caller_thread_priority": observed_priority(0),
        "elapsed_ms": started.elapsed().as_millis(), "exit": output.status.code(),
        "signal": output.status.signal(), "artifact_dir": artifact_dir,
        "pid_file": read_diagnostic(&daemon_pid_path(data_dir)),
        "state": read_diagnostic(&daemon_state_path(data_dir))
    });
    fs::write(
        artifact_dir.join("invocation.json"),
        serde_json::to_vec_pretty(&record).expect("serialize daemon CLI invocation"),
    )
    .expect("retain daemon CLI invocation");
    eprintln!("{record}");
    output
}

fn send_signal(child: &mut OwnedDaemon, signal: i32) {
    assert!(
        child
            .try_wait()
            .expect("check owned child before signal")
            .is_none(),
        "refusing signal to an already reaped daemon child"
    );
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

fn send_sigterm(child: &mut OwnedDaemon) {
    send_signal(child, libc::SIGTERM);
}

fn wait_for<F: FnMut(&mut OwnedDaemon) -> bool>(
    child: &mut OwnedDaemon,
    timeout: Duration,
    phase: &str,
    mut f: F,
) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if f(child) && start.elapsed() < timeout {
            child.record_observation(phase, start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let observation = child.record_observation(phase, start.elapsed());
    panic!("daemon phase {phase} timed out after {timeout:?}: {observation}");
}

fn read_jsonl_items(path: &Path) -> Vec<Value> {
    let content = fs::read_to_string(path).expect("read jsonl");
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("valid JSONL line"))
        .collect()
}

fn state_has_event(state_path: &Path, event_type: &str) -> bool {
    let content = match fs::read_to_string(state_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(error) => panic!(
            "failed to read daemon state {}: {error}",
            state_path.display()
        ),
    };
    let json = serde_json::from_str::<Value>(&content).unwrap_or_else(|error| {
        panic!(
            "invalid daemon state {}: {error}; contents={content}",
            state_path.display()
        )
    });
    let events = json
        .get("daemon")
        .and_then(|d| d.get("recent_events"))
        .and_then(|e| e.as_array())
        .expect("recorded daemon state must contain recent_events");
    events.iter().any(|ev| {
        ev.get("event_type")
            .and_then(|t| t.as_str())
            .map(|t| t == event_type)
            .unwrap_or(false)
    })
}

#[test]
fn daemon_start_fails_when_pid_lock_is_held() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let _pid_lock = acquire_daemon_pid_lock(&data_dir);
    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "pid_lock_refusal",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let status = child.wait().expect("wait for daemon exit status");
    // ExitCode::LockError == 14.
    assert_eq!(
        status.code(),
        Some(14),
        "daemon should exit with lock contention when daemon pid lock is held"
    );
    assert!(
        !daemon_pid_path(&data_dir).exists(),
        "daemon pid file should not be written when pid lock acquisition fails"
    );
}

#[test]
fn daemon_background_start_reports_lock_error_when_pid_lock_is_held() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let _pid_lock = acquire_daemon_pid_lock(&data_dir);
    let output = run_daemon_cli(&config_dir, &data_dir, &["daemon", "start"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // ExitCode::LockError == 14.
    assert_eq!(
        output.status.code(),
        Some(14),
        "background daemon start should surface lock contention (stdout={stdout:?}, stderr={stderr:?})"
    );
    assert!(
        !daemon_pid_path(&data_dir).exists(),
        "background start should not leave daemon pid file when pid lock is held"
    );
}

#[test]
fn daemon_starts_with_defaults_when_daemon_json_is_missing() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    let pid_path = daemon_pid_path(&data_dir);
    let state_path = daemon_state_path(&data_dir);

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "default_config_started",
        |_| pid_path.exists() && state_path.exists(),
    );

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should stay alive when daemon.json is missing (default config path)"
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "default_config_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );

    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGTERM");
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after clean shutdown"
    );
}

#[test]
fn daemon_recovers_from_corrupt_state_file() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let state_path = daemon_state_path(&data_dir);
    fs::create_dir_all(
        state_path
            .parent()
            .expect("state path should have daemon parent dir"),
    )
    .expect("create daemon state dir");
    fs::write(&state_path, "{ this is not valid json }").expect("write corrupt state");

    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    let pid_path = daemon_pid_path(&data_dir);

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "corrupt_state_started",
        |_| pid_path.exists(),
    );
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "corrupt_state_replaced",
        |_| {
            let content = match fs::read_to_string(&state_path) {
                Ok(content) => content,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
                Err(error) => panic!("failed to read corrupt-state recovery input: {error}"),
            };
            serde_json::from_str::<Value>(&content).is_ok()
        },
    );

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should remain alive after recovering from corrupt state file"
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "corrupt_state_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let status = child.wait().expect("wait for daemon exit status");
    assert!(
        status.success(),
        "daemon should exit cleanly after corrupt-state recovery test"
    );
}

#[test]
fn daemon_lock_contention_writes_inbox_item_and_cleans_pid() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let _lock = acquire_global_lock(&data_dir);
    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let inbox_path = inbox_items_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "lock_contention_inbox",
        |_| {
            inbox_path.exists()
                && read_jsonl_items(&inbox_path).iter().any(|v| {
                    v.get("type")
                        .and_then(|t| t.as_str())
                        .map(|t| t == "lock_contention")
                        .unwrap_or(false)
                })
        },
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "lock_contention_stopped",
        |child| child.try_wait().unwrap().is_some(),
    );

    // Ensure the daemon cleaned up its own pid file.
    assert!(
        !daemon_pid_path(&data_dir).exists(),
        "daemon pid file should be removed on clean shutdown"
    );
}

#[test]
fn daemon_trigger_cooldown_prevents_repeated_lock_contention_spam() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let _lock = acquire_global_lock(&data_dir);
    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let inbox_path = inbox_items_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "cooldown_inbox_created",
        |_| inbox_path.exists(),
    );
    std::thread::sleep(Duration::from_secs(3)); // allow multiple ticks

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "cooldown_stopped",
        |child| child.try_wait().unwrap().is_some(),
    );

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
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    std::thread::sleep(Duration::from_millis(250));

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should still be running shortly after startup"
    );

    for _ in 0..250 {
        send_signal(&mut child, libc::SIGUSR1);
    }
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should remain alive after SIGUSR1 storm"
    );

    // Use SIGKILL for deterministic teardown in this chaos test; the purpose here
    // is to ensure the daemon stays alive while under the signal burst.
    send_signal(&mut child, libc::SIGKILL);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "signal_storm_killed",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let _ = child.wait().expect("wait for daemon exit status");
}

#[test]
fn daemon_sigint_stops_and_cleans_pid_file() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let pid_path = daemon_pid_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "sigint_started",
        |_| pid_path.exists(),
    );
    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should be alive before SIGINT"
    );

    send_signal(&mut child, libc::SIGINT);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "sigint_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );

    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGINT");
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after SIGINT shutdown"
    );
}

#[test]
fn daemon_sigterm_stops_and_cleans_pid_file() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let pid_path = daemon_pid_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "sigterm_started",
        |_| pid_path.exists(),
    );
    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should be alive before SIGTERM"
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "sigterm_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );

    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGTERM");
    assert!(
        !pid_path.exists(),
        "daemon pid file should be removed after SIGTERM shutdown"
    );
}

#[test]
fn daemon_sighup_reloads_config_without_exiting() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    let pid_path = daemon_pid_path(&data_dir);
    let state_path = daemon_state_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "reload_started",
        |_| pid_path.exists() && state_path.exists(),
    );

    send_signal(&mut child, libc::SIGHUP);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "reload_event_observed",
        |child| {
            child
                .try_wait()
                .expect("query child status after SIGHUP")
                .is_none()
                && state_has_event(&state_path, "config_reloaded")
        },
    );

    assert!(
        child.try_wait().expect("query child status").is_none(),
        "daemon should stay running after SIGHUP config reload"
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "reload_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let status = child.wait().expect("wait for daemon exit status");
    assert!(status.success(), "daemon should exit cleanly after SIGTERM");
}

#[test]
fn daemon_sighup_with_deleted_config_keeps_running() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let daemon_config_path = config_dir.join("daemon.json");
    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    let pid_path = daemon_pid_path(&data_dir);
    let state_path = daemon_state_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "missing_reload_started",
        |_| pid_path.exists() && state_path.exists(),
    );

    let retained_config = config_dir.join(format!("daemon.retained-{}.json", uuid::Uuid::new_v4()));
    assert!(!retained_config.exists());
    fs::rename(&daemon_config_path, &retained_config).expect("retain daemon.json at a fresh path");
    assert!(
        !daemon_config_path.exists(),
        "the original daemon config path must be absent"
    );
    assert!(retained_config.is_file());
    send_signal(&mut child, libc::SIGHUP);

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "missing_reload_event_observed",
        |child| {
            child.try_wait().expect("query child status").is_none()
                && state_has_event(&state_path, "config_reloaded")
        },
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "missing_reload_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let status = child.wait().expect("wait for daemon exit status");
    assert!(
        status.success(),
        "daemon should remain healthy when config is deleted before SIGHUP reload"
    );
}

#[test]
fn daemon_sighup_with_invalid_config_keeps_running() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let daemon_config_path = config_dir.join("daemon.json");
    let mut child = start_daemon_foreground(&config_dir, &data_dir);
    let pid_path = daemon_pid_path(&data_dir);
    let state_path = daemon_state_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "invalid_reload_started",
        |_| pid_path.exists() && state_path.exists(),
    );

    fs::write(&daemon_config_path, "{ invalid json").expect("write invalid daemon.json");
    send_signal(&mut child, libc::SIGHUP);

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "invalid_reload_event_observed",
        |child| {
            child.try_wait().expect("query child status").is_none()
                && state_has_event(&state_path, "config_reloaded")
        },
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "invalid_reload_stopped",
        |child| child.try_wait().expect("query child status").is_some(),
    );
    let status = child.wait().expect("wait for daemon exit status");
    assert!(
        status.success(),
        "daemon should remain healthy when config is invalid during SIGHUP reload"
    );
}

#[test]
fn daemon_restart_after_sigkill_recovers_cleanly() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let pid_path = daemon_pid_path(&data_dir);

    let mut first = start_daemon_foreground(&config_dir, &data_dir);
    wait_for(
        &mut first,
        Duration::from_secs(10),
        "restart_first_started",
        |_| pid_path.exists(),
    );
    let first_pid: u32 = fs::read_to_string(&pid_path)
        .expect("read first daemon pid file")
        .trim()
        .parse()
        .expect("parse first daemon pid");
    assert_eq!(
        first_pid,
        first.id(),
        "PID file must identify the owned first daemon"
    );
    assert!(
        first
            .try_wait()
            .expect("query first child status")
            .is_none(),
        "first daemon should be alive before SIGKILL"
    );

    send_signal(&mut first, libc::SIGKILL);
    wait_for(
        &mut first,
        Duration::from_secs(10),
        "restart_first_killed",
        |child| {
            child
                .try_wait()
                .expect("query first child status")
                .is_some()
        },
    );
    let first_status = first.wait().expect("wait for first daemon exit status");
    assert_eq!(first_status.signal(), Some(libc::SIGKILL));

    let mut second = start_daemon_foreground(&config_dir, &data_dir);
    wait_for(
        &mut second,
        Duration::from_secs(10),
        "restart_second_pid_bound",
        |child| {
            if !pid_path.exists() {
                return false;
            }
            let pid = fs::read_to_string(&pid_path)
                .expect("read second daemon pid file")
                .trim()
                .parse::<u32>()
                .expect("parse second daemon pid");
            pid != first_pid && pid == child.id()
        },
    );
    assert!(
        second
            .try_wait()
            .expect("query second child status")
            .is_none(),
        "second daemon should be alive after SIGKILL recovery restart"
    );

    send_sigterm(&mut second);
    wait_for(
        &mut second,
        Duration::from_secs(10),
        "restart_second_stopped",
        |child| {
            child
                .try_wait()
                .expect("query second child status")
                .is_some()
        },
    );
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
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    write_daemon_json_config(
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let state_path = daemon_state_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "budget_state_created",
        |_| state_path.exists(),
    );

    wait_for(
        &mut child,
        Duration::from_secs(10),
        "budget_exceeded_observed",
        |_| state_has_event(&state_path, "overhead_budget_exceeded"),
    );

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(10),
        "budget_stopped",
        |child| child.try_wait().unwrap().is_some(),
    );

    // When budget is exceeded we skip escalation; inbox should remain absent.
    assert!(
        !inbox_items_path(&data_dir).exists(),
        "no inbox items should be written when overhead budget is exceeded"
    );
}

#[test]
fn daemon_escalation_writes_dormant_inbox_item_and_session_log() {
    let data_dir = TempDir::new().expect("temp data dir").keep();
    let config_dir = TempDir::new().expect("temp config dir").keep();

    // Ensure daemon escalation can successfully run `pt-core agent plan` by
    // providing a minimal config set (policy + priors).
    write_config_file(
        &config_dir,
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
        &config_dir,
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
        &config_dir,
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

    let mut child = start_daemon_foreground(&config_dir, &data_dir);

    let inbox_path = inbox_items_path(&data_dir);
    wait_for(
        &mut child,
        Duration::from_secs(30),
        "escalation_inbox_item",
        |_| {
            inbox_path.exists()
                && read_jsonl_items(&inbox_path).iter().any(|v| {
                    v.get("type")
                        .and_then(|t| t.as_str())
                        .map(|t| t == "dormant_escalation")
                        .unwrap_or(false)
                })
        },
    );

    // Resolve the session id from the inbox item and ensure the session JSONL log was created.
    let items = read_jsonl_items(&inbox_path);
    let session_id = items
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("dormant_escalation"))
        .and_then(|v| v.get("session_id").and_then(|s| s.as_str()))
        .expect("dormant_escalation item should include session_id")
        .to_string();

    let session_log = data_dir
        .join("sessions")
        .join(&session_id)
        .join("logs")
        .join("session.jsonl");

    wait_for(
        &mut child,
        Duration::from_secs(30),
        "escalation_session_log",
        |_| session_log.exists(),
    );

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

    send_sigterm(&mut child);
    wait_for(
        &mut child,
        Duration::from_secs(30),
        "escalation_stopped",
        |child| child.try_wait().unwrap().is_some(),
    );
}
