//! A consumer that closes stdout early (`| head`, `| tail`, an early-exiting
//! `jq`, an agent runner truncating a log) must end `pt-core` quietly.
//!
//! Before GH #11 the Rust runtime's ignored `SIGPIPE` turned the first write
//! after the close into a `println!` panic, which the release profile's
//! `panic = "abort"` escalated to `SIGABRT` and a core dump.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// `completions zsh` writes several hundred kilobytes of deterministic output
/// without touching the process table, so the binary cannot finish before the
/// reader goes away, and the write that follows the close must hit `EPIPE`.
#[test]
fn closed_stdout_pipe_ends_process_without_abort() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pt-core"))
        .args(["completions", "zsh"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pt-core");

    // Consume one byte so the child has definitely started writing, then
    // close our end of the pipe while it still has output to produce.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut first = [0u8; 1];
    let read = stdout.read(&mut first).expect("read first byte");
    assert_eq!(read, 1, "completions must produce output");
    drop(stdout);

    let output = child.wait_with_output().expect("wait for pt-core");
    let status = output.status;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(
        status.signal(),
        Some(libc::SIGABRT),
        "pt-core aborted on a closed stdout pipe; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "pt-core must not panic on a closed stdout pipe; stderr: {stderr}"
    );
    assert!(
        status.success() || status.signal() == Some(libc::SIGPIPE),
        "expected a clean exit or termination by SIGPIPE, got {status:?}; stderr: {stderr}"
    );
}
