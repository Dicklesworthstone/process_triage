//! Wait-free prober using io_uring for non-blocking /proc inspection.
//!
//! This module implements Plan §3.7 / bd-g0q5.6: a prober that uses io_uring
//! to submit multiple /proc read requests asynchronously, ensuring that
//! the triage agent never blocks even when target processes are in D-state.

use io_uring::{opcode, types, IoUring};
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;
use tracing::error;

/// Result of a single probe operation.
#[derive(Debug)]
pub struct ProbeResult {
    /// The path that was probed.
    pub path: PathBuf,
    /// The data read from the file.
    pub data: Vec<u8>,
    /// Whether the probe timed out.
    pub timed_out: bool,
    /// Error if the probe failed (other than timeout).
    pub error: Option<io::Error>,
}

/// Configuration for the wait-free prober.
#[derive(Debug, Clone)]
pub struct ProberConfig {
    /// Maximum number of concurrent probes in flight.
    pub ring_entries: u32,
    /// Default timeout for a single probe.
    pub probe_timeout: Duration,
    /// Whether to use O_DIRECT where available.
    pub use_direct_io: bool,
}

impl Default for ProberConfig {
    fn default() -> Self {
        Self {
            ring_entries: 512,
            probe_timeout: Duration::from_millis(100),
            use_direct_io: false,
        }
    }
}

/// A wait-free prober that manages an io_uring instance.
pub struct Prober {
    ring: IoUring,
    config: ProberConfig,
    /// Batch generation, encoded in the high 32 bits of every `user_data`, so that
    /// late completions from an earlier (timed-out) batch are never attributed to
    /// the current one.
    generation: u32,
    /// Set when a failed submit left entries queued in a ring that could not be
    /// replaced: that ring must never be submitted again.
    poisoned: bool,
    /// Test hook: make the next batch's submit fail.
    #[cfg(test)]
    fail_next_submit: bool,
}

struct ProbeState {
    path: PathBuf,
    _file: File,
    buffer: Vec<u8>,
    completed: bool,
    failed: bool,
}

/// Low-32-bit `user_data` tags for the non-read entries of a batch.
const TAG_TIMEOUT: u64 = 0xFFFF_FFFF;
const TAG_CANCEL: u64 = 0xFFFF_FFFE;

impl Prober {
    /// Create a new prober with the given configuration.
    ///
    /// Falls back to returning an error if io_uring is not supported.
    pub fn new(config: ProberConfig) -> io::Result<Self> {
        let ring = IoUring::new(config.ring_entries)?;
        Ok(Self {
            ring,
            config,
            generation: 0,
            poisoned: false,
            #[cfg(test)]
            fail_next_submit: false,
        })
    }

    /// Replace the ring, discarding any entries queued but never submitted. If a new
    /// ring cannot be created, poison the prober so the old queue is never submitted.
    fn replace_ring(&mut self) {
        match IoUring::new(self.config.ring_entries) {
            Ok(ring) => self.ring = ring,
            Err(e) => {
                error!(error = %e, "io_uring: cannot replace ring after failed submit; disabling prober");
                self.poisoned = true;
            }
        }
    }

    /// Submit probe requests and wait for completion or timeout.
    ///
    /// Paths are processed in chunks that fit the submission ring together with
    /// the batch's timeout entry. (Pushing more reads than the ring holds used to
    /// drop the excess reads, and the timeout entry with them, so a batch could
    /// block forever on a D-state process.)
    pub fn probe_batch(&mut self, paths: &[PathBuf]) -> Vec<ProbeResult> {
        let chunk = self.config.ring_entries.saturating_sub(2).max(1) as usize;
        let mut results = Vec::with_capacity(paths.len());
        for part in paths.chunks(chunk) {
            results.extend(self.probe_chunk(part));
        }
        results
    }

    /// Probe at most `ring_entries - 2` paths.
    ///
    /// Memory-safety contract: a read's buffer and file are only released after its
    /// completion has been reaped. Reads still in flight after the timeout (and after
    /// a cancellation attempt) are leaked on purpose: the kernel may still write into
    /// them, and a leak is safe where a free is not.
    fn probe_chunk(&mut self, paths: &[PathBuf]) -> Vec<ProbeResult> {
        let mut results = Vec::with_capacity(paths.len());
        if paths.is_empty() {
            return results;
        }
        if self.poisoned {
            return paths
                .iter()
                .map(|path| ProbeResult {
                    path: path.clone(),
                    data: Vec::new(),
                    timed_out: false,
                    error: Some(io::Error::other(
                        "io_uring prober disabled after a failed submit",
                    )),
                })
                .collect();
        }
        self.generation = self.generation.wrapping_add(1);
        let generation_bits = u64::from(self.generation) << 32;
        let tag = move |low: u64| generation_bits | low;

        let mut states: Vec<ProbeState> = Vec::with_capacity(paths.len());

        for path in paths {
            match File::open(path) {
                Ok(file) => {
                    states.push(ProbeState {
                        path: path.clone(),
                        _file: file,
                        buffer: vec![0u8; 4096],
                        completed: false,
                        failed: false,
                    });
                }
                Err(e) => {
                    results.push(ProbeResult {
                        path: path.clone(),
                        data: Vec::new(),
                        timed_out: false,
                        error: Some(e),
                    });
                }
            }
        }

        if states.is_empty() {
            return results;
        }

        // The timespec must stay alive until the kernel has consumed the timeout SQE
        // (at submit); it previously lived in an inner block that ended before submit.
        let ts = types::Timespec::new()
            .sec(self.config.probe_timeout.as_secs())
            .nsec(self.config.probe_timeout.subsec_nanos());

        // Submit reads plus one timeout. `probe_batch` sized the chunk so all fit.
        let mut submitted = vec![false; states.len()];
        let mut submitted_count = 0usize;
        {
            let mut sq = self.ring.submission();
            for (idx, state) in states.iter_mut().enumerate() {
                let fd = state._file.as_raw_fd();
                let read_e = opcode::Read::new(
                    types::Fd(fd),
                    state.buffer.as_mut_ptr(),
                    state.buffer.len() as u32,
                )
                .build()
                .user_data(tag(idx as u64));

                // SAFETY: the buffer and file live in `states`, which outlives the
                // read (released only after its CQE is reaped, else leaked below).
                if unsafe { sq.push(&read_e) }.is_err() {
                    break;
                }
                submitted[idx] = true;
                submitted_count += 1;
            }

            // Completes after `submitted_count` completions (normal case) or when
            // the probe timeout expires (-ETIME), whichever comes first.
            let timeout_e = opcode::Timeout::new(&ts)
                .count(submitted_count as u32)
                .build()
                .user_data(tag(TAG_TIMEOUT));
            // SAFETY: `ts` outlives the submit below.
            if unsafe { sq.push(&timeout_e) }.is_err() {
                // Cannot happen with chunking; without a timeout we must not wait.
                drop(sq);
                error!("io_uring: no room for timeout entry; skipping blocking wait");
            }
        }

        #[cfg(test)]
        let forced_failure = std::mem::take(&mut self.fail_next_submit);
        #[cfg(not(test))]
        let forced_failure = false;
        let submit_result = if forced_failure {
            Err(io::Error::other("injected submit failure"))
        } else {
            self.ring.submit().map(|_| ())
        };
        if let Err(e) = submit_result {
            error!(error = %e, "Failed to submit io_uring requests");
            // io_uring_enter consumed nothing, but the pushed entries are still queued
            // in this ring and would reach the kernel on its next submit, pointing at
            // this batch's buffers and at `ts` on this stack frame. Discard them by
            // replacing the ring (a dropped ring never submits its queue); only then
            // is releasing everything normally safe.
            self.replace_ring();
            submitted_count = 0;
            submitted.iter_mut().for_each(|s| *s = false);
        }

        let mut completed_count = 0usize;
        let mut timed_out = false;
        let mut timeout_reaped = submitted_count == 0;

        while completed_count < submitted_count && !timed_out {
            if let Err(e) = self.ring.submit_and_wait(1) {
                error!(error = %e, "io_uring wait failed");
                break;
            }
            for cqe in self.ring.completion() {
                let user_data = cqe.user_data();
                if user_data & 0xFFFF_FFFF_0000_0000 != generation_bits {
                    continue; // late completion from an earlier batch
                }
                let low = user_data & 0xFFFF_FFFF;
                if low == TAG_TIMEOUT {
                    timeout_reaped = true;
                    if cqe.result() == -libc::ETIME {
                        timed_out = true;
                    }
                    continue;
                }
                if low == TAG_CANCEL {
                    continue;
                }
                let idx = low as usize;
                if idx < states.len() && !states[idx].completed {
                    let res = cqe.result();
                    if res >= 0 {
                        states[idx].buffer.truncate(res as usize);
                    } else {
                        states[idx].failed = true;
                        results.push(ProbeResult {
                            path: states[idx].path.clone(),
                            data: Vec::new(),
                            timed_out: false,
                            error: Some(io::Error::from_raw_os_error(-res)),
                        });
                    }
                    states[idx].completed = true;
                    completed_count += 1;
                }
            }
        }

        // Timed out with reads still in flight: ask the kernel to cancel them, then
        // reap whatever completes without blocking. Anything still in flight after
        // that is leaked below instead of freed.
        let in_flight: Vec<usize> = (0..states.len())
            .filter(|&i| submitted[i] && !states[i].completed)
            .collect();
        if !in_flight.is_empty() {
            {
                let mut sq = self.ring.submission();
                for &idx in &in_flight {
                    let cancel = opcode::AsyncCancel::new(tag(idx as u64))
                        .build()
                        .user_data(tag(TAG_CANCEL));
                    // SAFETY: AsyncCancel references no user memory.
                    if unsafe { sq.push(&cancel) }.is_err() {
                        break;
                    }
                }
            }
            let _ = self.ring.submit();
            for cqe in self.ring.completion() {
                let user_data = cqe.user_data();
                if user_data & 0xFFFF_FFFF_0000_0000 != generation_bits {
                    continue;
                }
                let idx = (user_data & 0xFFFF_FFFF) as usize;
                if idx < states.len() && submitted[idx] && !states[idx].completed {
                    // Completed or cancelled: the kernel is done with the buffer.
                    // Report it as timed out either way (the deadline passed).
                    states[idx].completed = true;
                    states[idx].failed = true;
                    results.push(ProbeResult {
                        path: states[idx].path.clone(),
                        data: Vec::new(),
                        timed_out: true,
                        error: None,
                    });
                }
            }
        }
        // An unreaped timeout entry is harmless: it references `ts` only at submit
        // time and its late CQE is filtered by generation.
        let _ = timeout_reaped;

        // Finalize results
        for (idx, state) in states.into_iter().enumerate() {
            if submitted[idx] && !state.completed {
                // Still owned by the kernel: leak buffer + fd (memory-safe) and report
                // the probe as timed out (likely a D-state process).
                results.push(ProbeResult {
                    path: state.path.clone(),
                    data: Vec::new(),
                    timed_out: true,
                    error: None,
                });
                std::mem::forget(state);
                continue;
            }
            if state.completed {
                if state.failed {
                    continue;
                }
                results.push(ProbeResult {
                    path: state.path,
                    data: state.buffer,
                    timed_out: false,
                    error: None,
                });
            } else {
                results.push(ProbeResult {
                    path: state.path,
                    data: Vec::new(),
                    timed_out: true,
                    error: None,
                });
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prober_new() {
        let config = ProberConfig::default();
        let prober = Prober::new(config);
        if cfg!(target_os = "linux") {
            assert!(prober.is_ok());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_probe_batch_success() {
        let mut prober = Prober::new(ProberConfig::default()).unwrap();
        let paths = vec![
            PathBuf::from("/proc/self/stat"),
            PathBuf::from("/proc/self/status"),
        ];

        let results = prober.probe_batch(&paths);
        assert_eq!(results.len(), 2);
        for res in results {
            assert!(!res.timed_out);
            assert!(
                res.error.is_none(),
                "Error probing {:?}: {:?}",
                res.path,
                res.error
            );
            assert!(!res.data.is_empty());
        }
    }

    /// Regression: more paths than ring entries used to silently drop the excess
    /// reads (and the timeout entry), reporting them as timed out.
    #[test]
    #[cfg(target_os = "linux")]
    fn batch_larger_than_ring_returns_every_result() {
        let config = ProberConfig {
            ring_entries: 8,
            probe_timeout: Duration::from_secs(5),
            ..ProberConfig::default()
        };
        let mut prober = Prober::new(config).unwrap();
        let paths: Vec<PathBuf> = (0..50)
            .map(|i| {
                if i % 2 == 0 {
                    PathBuf::from("/proc/self/stat")
                } else {
                    PathBuf::from("/proc/self/status")
                }
            })
            .collect();
        let results = prober.probe_batch(&paths);
        assert_eq!(results.len(), 50);
        for res in &results {
            assert!(!res.timed_out, "{:?} timed out", res.path);
            assert!(res.error.is_none(), "{:?}: {:?}", res.path, res.error);
            assert!(!res.data.is_empty());
        }
    }

    /// A batch following a timed-out batch must not receive its stale completions.
    #[test]
    #[cfg(target_os = "linux")]
    fn batches_after_a_timeout_are_not_corrupted() {
        let mut prober = Prober::new(ProberConfig {
            probe_timeout: Duration::from_nanos(1),
            ..ProberConfig::default()
        })
        .unwrap();
        let _ = prober.probe_batch(&[PathBuf::from("/proc/self/status")]);
        prober.config.probe_timeout = Duration::from_secs(5);
        let results = prober.probe_batch(&[
            PathBuf::from("/proc/self/stat"),
            PathBuf::from("/proc/self/status"),
        ]);
        assert_eq!(results.len(), 2);
        for res in results {
            assert!(!res.timed_out);
            assert!(res.error.is_none());
            assert!(!res.data.is_empty());
        }
    }

    /// After a failed submit no entry of that batch may stay queued (it would reach
    /// the kernel on the next submit pointing at freed buffers and a dead stack
    /// frame), and the prober keeps working.
    #[test]
    #[cfg(target_os = "linux")]
    fn failed_submit_leaves_nothing_queued() {
        let mut prober = Prober::new(ProberConfig::default()).unwrap();
        prober.fail_next_submit = true;
        let failed = prober.probe_batch(&[
            PathBuf::from("/proc/self/stat"),
            PathBuf::from("/proc/self/status"),
        ]);
        assert_eq!(failed.len(), 2);
        assert!(failed.iter().all(|r| r.data.is_empty()));
        assert!(
            prober.ring.submission().is_empty(),
            "stale entries of the failed batch are still queued"
        );

        let results = prober.probe_batch(&[PathBuf::from("/proc/self/stat")]);
        assert_eq!(results.len(), 1);
        assert!(results[0].error.is_none() && !results[0].data.is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_probe_batch_not_found() {
        let mut prober = Prober::new(ProberConfig::default()).unwrap();
        let paths = vec![
            PathBuf::from("/proc/9999999/stat"), // Non-existent PID
        ];

        let results = prober.probe_batch(&paths);
        assert_eq!(results.len(), 1);
        let res = &results[0];
        assert!(res.error.is_some());
        assert_eq!(res.error.as_ref().unwrap().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_probe_batch_timeout() {
        let config = ProberConfig {
            probe_timeout: Duration::from_nanos(1), // Impossible timeout
            ..ProberConfig::default()
        };

        let mut prober = Prober::new(config).unwrap();
        let paths = vec![PathBuf::from("/proc/self/stat")];

        let results = prober.probe_batch(&paths);
        for res in results {
            if res.timed_out {
                assert!(res.data.is_empty());
                assert!(res.error.is_none());
            }
        }
    }
}
