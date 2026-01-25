//! Tests for zombie detection behavior in inference defaults.

use pt_core::config::priors::Priors;
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence};

#[test]
fn zombie_state_flag_drives_zombie_posterior() {
    let priors = Priors::default();

    let state_flags = priors
        .state_flags
        .as_ref()
        .expect("default priors must include state_flags");
    assert_eq!(
        state_flags.flag_names,
        vec![
            "Running",
            "Sleeping",
            "DiskSleep",
            "Zombie",
            "Stopped",
            "Idle",
            "Dead",
        ],
        "state_flags must align with ProcessState mapping"
    );

    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.0 }),
        runtime_seconds: Some(3600.0),
        orphan: Some(false),
        tty: Some(false),
        net: Some(false),
        io_active: Some(false),
        state_flag: Some(3), // Z state
        command_category: None,
    };

    let result = compute_posterior(&priors, &evidence).expect("posterior computation failed");
    let posterior = result.posterior;

    let max = posterior
        .useful
        .max(posterior.useful_bad)
        .max(posterior.abandoned)
        .max(posterior.zombie);

    assert!(
        (posterior.zombie - max).abs() < 1e-9,
        "zombie posterior should be the max class (got {posterior:?})"
    );
    assert!(
        posterior.zombie > 0.8,
        "zombie posterior should be high, got {:.3}",
        posterior.zombie
    );
}
