//! The TUI owns terminal rendering. Collector diagnostics belong in its session.

use pt_core::collect::tool_runner::{ToolConfig, ToolError, ToolRunner};
use std::io::{BufRead, Seek};
use tracing_subscriber::layer::SubscriberExt;

#[test]
fn budget_refusals_emit_one_count_per_window() {
    let mut log = tempfile::tempfile().unwrap();
    let subscriber = tracing_subscriber::registry()
        .with(pt_core::logging::JsonlLayer::new(log.try_clone().unwrap()));
    tracing::subscriber::with_default(subscriber, || {
        let runner = ToolRunner::new(ToolConfig {
            budget_ms: 0,
            ..Default::default()
        });
        for n in [5, 7] {
            for _ in 0..n {
                assert!(matches!(
                    runner.run_tool("ps", &[], None),
                    Err(ToolError::BudgetExhausted { .. })
                ));
            }
            if n == 5 {
                runner.reset_budget();
            }
        }
    });
    log.rewind().unwrap();
    let counts: Vec<_> = std::io::BufReader::new(log)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(&line.unwrap()).unwrap())
        .filter(|event| event["message"] == "probe budget exhausted")
        .map(|event| event["fields"]["refused_probes"].as_u64().unwrap())
        .collect();
    assert_eq!(counts, [5, 7]);
}

#[cfg(all(unix, feature = "ui"))]
#[test]
fn interactive_scan_keeps_structured_logs_off_its_terminal() {
    use std::process::Command;

    let root = tempfile::tempdir().unwrap();
    // forkpty gives the child a controlling terminal. Start with all three
    // standard streams attached, as for an ordinary interactive invocation.
    let script = r#"
import errno, fcntl, os, pty, select, signal, struct, sys, termios, time
pid, terminal = pty.fork()
if pid == 0:
    fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack('HHHH', 45, 160, 0, 0))
    os.execv(sys.argv[1], [sys.argv[1], '--dry-run', 'run', '--window-ms', '0', '--deep', '--probe-budget-ms', '0'])
deadline = time.monotonic() + 45
screen = bytearray()
exited = False
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([terminal], [], [], 0.2)
        if ready:
            try:
                part = os.read(terminal, 65536)
                if not part: break
                screen.extend(part)
            except OSError as error:
                if error.errno == errno.EIO: break
                raise
        if b'\x1b[' in screen:
            os.write(terminal, b'q')
    else:
        raise AssertionError('TUI deadline elapsed: ' + repr(screen[-512:]))
    _, status = os.waitpid(pid, 0)
    exited = True
    assert os.waitstatus_to_exitcode(status) == 0, repr(screen[-2048:])
    assert b'\x1b[' in screen, repr(screen)
    assert b'"level":' not in screen and b'"event":"pt_core' not in screen, repr(screen[-2048:])
finally:
    if not exited:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
    os.close(terminal)
"#;
    let data = root.path().join("data");
    let config = root.path().join("config");
    std::fs::create_dir(&config).unwrap();
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(assert_cmd::cargo::cargo_bin!("pt-core"))
        .env("TERM", "xterm-256color")
        .env("PROCESS_TRIAGE_CONFIG", &config)
        .env_remove("PT_CONFIG_DIR")
        .env("PROCESS_TRIAGE_DATA", &data)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .env("RUST_LOG", "pt_core=info")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sessions = std::fs::read_dir(data.join("sessions")).unwrap();
    let log = sessions
        .flatten()
        .find_map(|entry| std::fs::read_to_string(entry.path().join("logs/tui.jsonl")).ok())
        .expect("interactive session log");
    assert!(
        log.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|row| {
                row["event"]
                    .as_str()
                    .is_some_and(|target| target.starts_with("pt_core"))
            })
        }),
        "{log}"
    );
}
