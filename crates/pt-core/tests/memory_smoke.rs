use pt_core::session::diff::{compute_diff, DiffConfig};
use pt_core::session::snapshot_persist::{PersistedInference, PersistedProcess};
use std::hint::black_box;

#[cfg(target_os = "linux")]
fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        // Example: "VmRSS:\t   12345 kB"
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb_str = rest.trim().split_whitespace().next()?;
            return kb_str.parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn rss_kb() -> Option<u64> {
    None
}

fn make_process(pid: u32, start_id: String, elapsed_secs: u64) -> PersistedProcess {
    PersistedProcess {
        pid,
        ppid: 1,
        uid: 1000,
        start_id,
        comm: "proc".to_string(),
        cmd: "proc --synthetic".to_string(),
        state: "S".to_string(),
        start_time_unix: 1_700_000_000,
        elapsed_secs,
        identity_quality: "full".to_string(),
    }
}

fn make_inference(proc: &PersistedProcess, classification: &str, score: u32) -> PersistedInference {
    PersistedInference {
        pid: proc.pid,
        start_id: proc.start_id.clone(),
        classification: classification.to_string(),
        posterior_useful: 0.01,
        posterior_useful_bad: 0.02,
        posterior_abandoned: 0.90,
        posterior_zombie: 0.07,
        confidence: "high".to_string(),
        recommended_action: "kill".to_string(),
        score,
    }
}

#[test]
fn memory_rss_sanity_diff_10k() {
    let Some(before_kb) = rss_kb() else {
        // Best-effort: Linux-only in CI.
        return;
    };

    // Baseline: 10k processes.
    let mut old_procs = Vec::with_capacity(10_000);
    let mut old_infs = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 3600 + (i as u64));
        let class = if i % 2 == 0 { "abandoned" } else { "useful" };
        let score = 20 + (i % 80);
        old_infs.push(make_inference(&p, class, score));
        old_procs.push(p);
    }

    // Current: keep 9.5k baseline processes (drop first 500), add 500 new.
    let mut new_procs = Vec::with_capacity(10_000);
    let mut new_infs = Vec::with_capacity(10_000);
    for i in 500..10_000u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 3600 + (i as u64) + 5);
        let class = if i % 2 == 0 { "abandoned" } else { "useful" };
        let score = 20 + (i % 80);
        new_infs.push(make_inference(&p, class, score));
        new_procs.push(p);
    }
    for i in 10_000..10_500u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 120);
        new_infs.push(make_inference(&p, "abandoned", 60));
        new_procs.push(p);
    }

    let after_alloc_kb = rss_kb().unwrap_or(before_kb);

    let config = DiffConfig::default();
    let diff = compute_diff(
        "pt-baseline",
        "pt-current",
        &old_procs,
        &old_infs,
        &new_procs,
        &new_infs,
        &config,
    );
    black_box(diff.summary.total_old);

    let after_diff_kb = rss_kb().unwrap_or(after_alloc_kb);
    let peak_kb = before_kb.max(after_alloc_kb).max(after_diff_kb);

    // Very generous budget: goal is to catch catastrophic regressions.
    let budget_kb: u64 = 800 * 1024; // 800 MB
    assert!(
        peak_kb <= budget_kb,
        "RSS too high for synthetic diff workload: peak={}kB budget={}kB (before={}kB after_alloc={}kB after_diff={}kB)",
        peak_kb,
        budget_kb,
        before_kb,
        after_alloc_kb,
        after_diff_kb
    );
}
