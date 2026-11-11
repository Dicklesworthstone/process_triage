//! Live-system integration tests for /proc collectors.
//!
//! These tests are Linux-only and do not use mocks. They validate that
//! collectors can parse live `/proc` data for the current process.

#![cfg(target_os = "linux")]

use pt_common::ResourceKind;
use pt_core::collect::{
    collect_local_resource_evidence, parse_cgroup, parse_environ, parse_fd, parse_io, parse_sched,
    parse_schedstat, parse_statm, parse_wchan,
};
use std::fs;
use std::fs::OpenOptions;

mod support;
use support::live_harness::LiveHarness;

fn skip_if_proc_unavailable() -> bool {
    if !std::path::Path::new("/proc").exists() {
        eprintln!("skipping: /proc not available on this system");
        return true;
    }
    false
}

#[test]
fn live_parse_io_schedstat_statm() {
    if skip_if_proc_unavailable() {
        return;
    }
    let harness = LiveHarness::new().expect("harness init");
    let pid = harness.pid();

    let io = parse_io(pid).expect("parse_io should succeed");
    let schedstat = parse_schedstat(pid).expect("parse_schedstat should succeed");
    let statm = parse_statm(pid).expect("parse_statm should succeed");

    let _ = io;
    let _ = schedstat;
    assert!(statm.size > 0);
}

#[test]
fn live_parse_sched_and_wchan() {
    if skip_if_proc_unavailable() {
        return;
    }
    let harness = LiveHarness::new().expect("harness init");
    let pid = harness.pid();

    let sched = parse_sched(pid).expect("parse_sched should succeed");
    let _ = sched;

    let _wchan = parse_wchan(pid);
}

#[test]
fn live_parse_environ_for_self() {
    if skip_if_proc_unavailable() {
        return;
    }
    let harness = LiveHarness::new().expect("harness init");
    let pid = harness.pid();

    let env = parse_environ(pid).expect("parse_environ should succeed");
    assert!(env.contains_key("PATH") || env.contains_key("HOME"));
}

#[test]
fn live_parse_fd_includes_open_files() {
    if skip_if_proc_unavailable() {
        return;
    }
    let mut harness = LiveHarness::new().expect("harness init");

    let _rw_path = harness.open_rw_file().expect("open_rw_file");
    let _ro_path = harness.open_ro_file().expect("open_ro_file");

    #[cfg(unix)]
    {
        harness.open_pipe().expect("open_pipe");
    }

    let pid = harness.pid();
    let fd = parse_fd(pid).expect("parse_fd should succeed");
    assert!(fd.count >= 2);
    assert!(fd.files >= 1);

    let has_rw = fd.open_files.iter().any(|f| f.mode.write);
    assert!(has_rw, "expected at least one writable fd");
}

#[test]
fn live_parse_cgroup_self() {
    if skip_if_proc_unavailable() {
        return;
    }
    let harness = LiveHarness::new().expect("harness init");
    let pid = harness.pid();

    let cgroup = parse_cgroup(pid).expect("parse_cgroup should succeed");
    assert!(cgroup.unified.is_some() || !cgroup.v1_paths.is_empty());
}

#[test]
fn live_collect_local_resource_evidence_for_self() {
    if skip_if_proc_unavailable() {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let pidfile = dir.path().join("collector.pid");
    let lockfile = dir.path().join("collector.lock");
    let pid = std::process::id();

    fs::write(&pidfile, format!("{pid}\n")).expect("write pidfile");
    fs::write(&lockfile, "locked\n").expect("write lockfile");

    let _pid_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pidfile)
        .expect("open pidfile");
    let _lock_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lockfile)
        .expect("open lockfile");

    let fd = parse_fd(pid).expect("parse_fd should succeed");
    let evidence = collect_local_resource_evidence(pid, Some(&fd));

    assert!(evidence
        .iter()
        .any(|entry| entry.kind == ResourceKind::Pidfile
            && entry.state == pt_common::ResourceState::Active
            && matches!(entry.details, pt_common::ResourceDetails::Pidfile { recorded_pid: Some(recorded), .. } if recorded == pid)));
    assert!(evidence
        .iter()
        .any(|entry| entry.kind == ResourceKind::Lockfile));
}

#[test]
fn live_fifo_pidfile_probe_is_bounded_without_losing_ipc_evidence() {
    use std::ffi::CString;
    use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            // The fixture owns this exact sleeping child, whose FIFO is held
            // as a descriptor and is never read by the child itself.
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let directory = tempfile::tempdir().expect("owned FIFO directory");
    let path = directory.path().join("worker.pid");
    let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the fixture owns this new path and supplies a valid C string.
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
    let fifo = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .expect("open owned FIFO without waiting for a peer");
    let mut holder = OwnedChild(
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::from(fifo))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owned descriptor holder"),
    );
    let pid = holder.0.id();
    let descriptors = parse_fd(pid).expect("owned child descriptors");
    let started = Instant::now();
    let evidence = collect_local_resource_evidence(pid, Some(&descriptors));
    assert!(started.elapsed() < Duration::from_secs(2));
    let pidfile = evidence
        .iter()
        .find(|entry| entry.kind == ResourceKind::Pidfile)
        .expect("pidfile marker remains visible");
    assert_eq!(pidfile.state, pt_common::ResourceState::Partial);
    assert!(matches!(
        pidfile.details,
        pt_common::ResourceDetails::Pidfile {
            recorded_pid: None,
            ..
        }
    ));

    let started = Instant::now();
    let ipc = pt_core::collect::collect_fd_ipc_resources_with_diagnostics(pid);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(ipc.unavailable.is_empty(), "{:?}", ipc.unavailable);
    assert!(ipc.resources.iter().any(|entry| {
        entry.kind == ResourceKind::NamedPipe
            && entry.state == pt_common::ResourceState::Active
            && entry.owner_pid == pid
            && entry.key == path.to_string_lossy()
    }));
    assert!(holder.0.try_wait().unwrap().is_none());
}

#[test]
fn live_tool_deadline_covers_closed_output_and_blocked_input() {
    use pt_core::collect::tool_runner::{ToolRunnerBuilder, ToolSpec};
    use std::time::{Duration, Instant};

    let runner = ToolRunnerBuilder::new()
        .use_nice(false)
        .budget_ms(30_000)
        .build();
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
            .expect("bounded tool observation");
        assert!(output.timed_out);
        assert!(!output.success());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    // Bidirectional pipes must make progress while input exceeds pipe capacity.
    let input = vec![b'x'; 512 * 1024];
    let output = runner
        .run(
            &ToolSpec::new("cat", vec![])
                .with_stdin(input.clone())
                .with_timeout(Duration::from_secs(10)),
        )
        .expect("bounded large stdin/stdout roundtrip");
    assert!(output.success(), "{output:?}");
    assert_eq!(output.stdout, input);
}
