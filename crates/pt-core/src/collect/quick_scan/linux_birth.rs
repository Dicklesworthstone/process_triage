//! Bind Linux ps rows to processes that existed before the collector started.

use crate::collect::proc_parsers::{parse_required_proc_stat_content, read_required_proc_stat};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd;

pub(super) struct LinuxBirthFence {
    // Lower bound on boottime, in the same USER_HZ units as /proc/PID/stat.
    cutoff: Option<u64>,
    pinned: HashMap<u32, File>,
}

fn cutoff_ticks(uptime: &str, hz: u64) -> Option<u64> {
    // Linux exports uptime truncated to hundredths of a second. Keep arithmetic
    // integral: rounding upward at a tick boundary would admit a later birth.
    let (seconds, fraction) = uptime.split_whitespace().next()?.split_once('.')?;
    if hz == 0 || fraction.len() != 2 || !fraction.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let hundredths = seconds
        .parse::<u64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(fraction.parse().ok()?)?;
    hundredths.checked_mul(hz)?.checked_div(100)
}

impl LinuxBirthFence {
    pub(super) fn capture(pids: &[u32], hz: Option<u64>) -> Self {
        let cutoff =
            hz.and_then(|hz| cutoff_ticks(&std::fs::read_to_string("/proc/uptime").ok()?, hz));
        Self::with_cutoff(pids, cutoff)
    }

    fn with_cutoff(pids: &[u32], cutoff: Option<u64>) -> Self {
        const MAX_PINS: usize = 64;
        let mut pinned = HashMap::new();
        for &pid in pids {
            if pinned.len() == MAX_PINS {
                break;
            }
            if pinned.contains_key(&pid)
                || cutoff.is_some_and(|cutoff| {
                    read_required_proc_stat(pid).is_ok_and(|stat| stat.starttime < cutoff)
                })
            {
                continue;
            }
            // An open procfs PID directory remains tied to the original task.
            // A later lookup underneath it cannot resolve to a reused PID.
            if let Ok(dir) = File::open(format!("/proc/{pid}")) {
                pinned.insert(pid, dir);
            }
        }
        Self { cutoff, pinned }
    }

    pub(super) fn accepts(&self, pid: u32, birth: u64) -> bool {
        if self.cutoff.is_some_and(|cutoff| birth < cutoff) {
            return true;
        }
        // Same-tick births cannot establish ordering. A targeted pre-ps pin
        // can establish continuity even then. Open stat afresh; never reuse a
        // previously read seq_file buffer after the process exited.
        self.pinned.get(&pid).is_some_and(|dir| {
            let path = format!("/proc/self/fd/{}/stat", dir.as_raw_fd());
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| parse_required_proc_stat_content(pid, &text).ok())
                .is_some_and(|stat| stat.starttime == birth)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn birth_tick_must_strictly_precede_the_scan() {
        assert_eq!(cutoff_ticks("10.99 123.45", 100), Some(1099));
        assert_eq!(cutoff_ticks("10.99 123.45", 128), Some(1406));
        for input in ["10.1", "10.000", "10.9x", "NaN", "18446744073709551615.99"] {
            assert_eq!(cutoff_ticks(input, 100), None);
        }
        let fence = LinuxBirthFence::with_cutoff(&[], Some(100));
        assert!(fence.accepts(42, 99));
        assert!(!fence.accepts(42, 100));
        assert!(!fence.accepts(42, 101));
        assert!(!LinuxBirthFence::with_cutoff(&[], None).accepts(42, 99));
    }

    #[test]
    fn full_scan_cannot_bind_a_process_created_after_the_fence() {
        let fence = LinuxBirthFence::capture(&[], super::super::clock_ticks_per_second());
        assert!(fence.cutoff.is_some());
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let pid = child.id();
        let birth = read_required_proc_stat(pid).unwrap().starttime;
        let accepted = fence.accepts(pid, birth);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!accepted);
    }

    #[test]
    fn targeted_pin_accepts_original_birth_and_expires_with_disposable_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let pid = child.id();
        let birth = read_required_proc_stat(pid).unwrap().starttime;
        let fence = LinuxBirthFence::with_cutoff(&[pid], Some(birth));
        let original = fence.accepts(pid, birth);
        let other_birth = fence.accepts(pid, birth + 1);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(original);
        assert!(!other_birth);
        assert!(!fence.accepts(pid, birth));
    }
}
