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
        .any(|entry| entry.kind == ResourceKind::Pidfile));
    assert!(evidence
        .iter()
        .any(|entry| entry.kind == ResourceKind::Lockfile));
}
