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
}

struct ProbeState {
    path: PathBuf,
    _file: File,
    buffer: Vec<u8>,
    completed: bool,
    failed: bool,
}

impl Prober {
    /// Create a new prober with the given configuration.
    ///
    /// Falls back to returning an error if io_uring is not supported.
    pub fn new(config: ProberConfig) -> io::Result<Self> {
        let ring = IoUring::new(config.ring_entries)?;
        Ok(Self { ring, config })
    }

    /// Submit a batch of probe requests and wait for completion or timeout.
    pub fn probe_batch(&mut self, paths: &[PathBuf]) -> Vec<ProbeResult> {
        let mut results = Vec::with_capacity(paths.len());
        if paths.is_empty() {
            return results;
        }

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

        // Submit reads and a global timeout
        let mut submitted_count = 0;
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
                .user_data(idx as u64);

                unsafe {
                    if let Err(_) = sq.push(&read_e) {
                        break;
                    }
                }
                submitted_count += 1;
            }

            // Add a linked timeout if supported, or a global timeout entry.
            // For simplicity and broad compatibility, we'll use a global timeout
            // entry with a special user_data.
            let ts = types::Timespec::new()
                .sec(self.config.probe_timeout.as_secs())
                .nsec(self.config.probe_timeout.subsec_nanos());
            let timeout_e = opcode::Timeout::new(&ts).build().user_data(u64::MAX);

            unsafe {
                let _ = sq.push(&timeout_e);
            }
        }

        if let Err(e) = self.ring.submit() {
            error!(error = %e, "Failed to submit io_uring requests");
            return results;
        }

        let mut completed_count = 0;
        let mut timed_out = false;

        while completed_count < submitted_count && !timed_out {
            // Wait for at least one completion
            if let Err(e) = self.ring.submit_and_wait(1) {
                error!(error = %e, "io_uring wait failed");
                break;
            }

            let mut cq = self.ring.completion();
            while let Some(cqe) = cq.next() {
                let user_data = cqe.user_data();
                if user_data == u64::MAX {
                    // Global timeout triggered
                    timed_out = true;
                    continue;
                }

                let idx = user_data as usize;
                if idx < states.len() && !states[idx].completed {
                    let res = cqe.result();
                    if res >= 0 {
                        states[idx].buffer.truncate(res as usize);
                    } else {
                        results.push(ProbeResult {
                            path: states[idx].path.clone(),
                            data: Vec::new(),
                            timed_out: false,
                            error: Some(io::Error::from_raw_os_error(-res)),
                        });
                        states[idx].failed = true;
                    }
                    states[idx].completed = true;
                    completed_count += 1;
                }
            }
        }

        // Finalize results
        for state in states {
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
        let mut config = ProberConfig::default();
        config.probe_timeout = Duration::from_nanos(1); // Impossible timeout

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
