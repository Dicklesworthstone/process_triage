//! Criterion benchmarks for provenance operations (bd-ppcl.13).
//!
//! Measures the cost of:
//! - Shared resource graph construction from evidence
//! - Blast-radius estimation per candidate
//! - CandidateProvenanceOutput serialization
//! - ProvenanceNarrative rendering at each verbosity level
//!
//! These benchmarks establish baseline performance budgets for the
//! provenance subsystem so regressions are caught before they reach
//! production scan paths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_common::{
    CandidateBlastRadiusOutput, CandidateProvenanceOutput, LockMechanism, NarrativeVerbosity,
    ProvenanceFeatureContribution, ProvenanceNarrative, ProvenanceRedactionState,
    ProvenanceScoreImpact, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails,
    ResourceKind, ResourceState,
};
use pt_core::collect::shared_resource_graph::SharedResourceGraph;
use pt_core::decision::blast_radius_estimator::{estimate_blast_radius, BlastRadiusEstimatorConfig};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock_evidence(pid: u32, path: &str) -> RawResourceEvidence {
    RawResourceEvidence {
        kind: ResourceKind::Lockfile,
        key: path.to_string(),
        owner_pid: pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state: ResourceState::Active,
        details: ResourceDetails::Lockfile {
            path: path.to_string(),
            mechanism: LockMechanism::Existence,
        },
        observed_at: "2026-03-18T00:00:00Z".to_string(),
    }
}

fn build_evidence_set(n_processes: usize, n_shared_locks: usize) -> Vec<(u32, Vec<RawResourceEvidence>)> {
    let mut evidence = Vec::with_capacity(n_processes);
    for i in 0..n_processes {
        let pid = 1000 + i as u32;
        let mut resources = Vec::new();
        // Each process has a private lock
        resources.push(lock_evidence(pid, &format!("/tmp/proc_{}.lock", pid)));
        // Plus some shared locks
        for j in 0..n_shared_locks {
            resources.push(lock_evidence(pid, &format!("/tmp/shared_{}.lock", j)));
        }
        evidence.push((pid, resources));
    }
    evidence
}

fn sample_provenance_output(n_terms: usize) -> CandidateProvenanceOutput {
    let features: Vec<ProvenanceFeatureContribution> = (0..n_terms)
        .map(|i| ProvenanceFeatureContribution {
            feature: format!("provenance_feature_{}", i),
            abandoned_ll: 0.5 + (i as f64 * 0.1),
            useful_ll: -(0.3 + (i as f64 * 0.05)),
            direction: "toward_abandon".to_string(),
        })
        .collect();

    CandidateProvenanceOutput {
        enabled: true,
        evidence_completeness: 0.85,
        confidence_penalty_steps: 1,
        confidence_notes: vec![
            "resource provenance has 2 unresolved edge(s)".to_string(),
        ],
        score_terms: features.iter().map(|f| f.feature.clone()).collect(),
        blast_radius: CandidateBlastRadiusOutput {
            risk_score: 0.35,
            risk_level: "medium".to_string(),
            confidence: 0.72,
            summary: "Process shares 2 lockfiles with 4 peers".to_string(),
            total_affected: 4,
        },
        redaction_state: ProvenanceRedactionState::None,
        score_impact: Some(ProvenanceScoreImpact {
            log_odds_shift: features.iter().map(|f| f.abandoned_ll - f.useful_ll).sum(),
            feature_contributions: features,
        }),
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_resource_graph_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance_resource_graph");

    for &(n_procs, n_shared) in &[(10, 2), (50, 5), (200, 10)] {
        let evidence = build_evidence_set(n_procs, n_shared);
        group.bench_with_input(
            BenchmarkId::new("from_evidence", format!("{}proc_{}shared", n_procs, n_shared)),
            &evidence,
            |b, ev| {
                b.iter(|| {
                    let graph = SharedResourceGraph::from_evidence(black_box(ev));
                    black_box(graph.resources.len());
                });
            },
        );
    }

    group.finish();
}

fn bench_blast_radius_estimation(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance_blast_radius");
    let config = BlastRadiusEstimatorConfig::default();

    for &(n_procs, n_shared) in &[(10, 2), (50, 5), (200, 10)] {
        let evidence = build_evidence_set(n_procs, n_shared);
        let graph = SharedResourceGraph::from_evidence(&evidence);
        let child_pids: Vec<u32> = (2000..2003).collect();

        group.bench_with_input(
            BenchmarkId::new("estimate", format!("{}proc_{}shared", n_procs, n_shared)),
            &(&graph, &child_pids),
            |b, (graph, children)| {
                b.iter(|| {
                    let estimate = estimate_blast_radius(
                        black_box(1000),
                        black_box(graph),
                        None,
                        black_box(children),
                        0.85,
                        &config,
                    );
                    black_box(estimate.risk_score);
                });
            },
        );
    }

    group.finish();
}

fn bench_output_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance_serialization");

    for &n_terms in &[0, 3, 10] {
        let output = sample_provenance_output(n_terms);
        group.bench_with_input(
            BenchmarkId::new("to_json", format!("{}_terms", n_terms)),
            &output,
            |b, output| {
                b.iter(|| {
                    let json = serde_json::to_value(black_box(output)).unwrap();
                    black_box(json);
                });
            },
        );
    }

    group.finish();
}

fn bench_narrative_rendering(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance_narrative");
    let output = sample_provenance_output(5);
    let narrative = ProvenanceNarrative::from_output(&output);

    for verbosity in &[
        NarrativeVerbosity::Compact,
        NarrativeVerbosity::Standard,
        NarrativeVerbosity::Full,
    ] {
        group.bench_with_input(
            BenchmarkId::new(
                "render",
                match verbosity {
                    NarrativeVerbosity::Compact => "compact",
                    NarrativeVerbosity::Standard => "standard",
                    NarrativeVerbosity::Full => "full",
                },
            ),
            verbosity,
            |b, &verbosity| {
                b.iter(|| {
                    let rendered = narrative.render(black_box(verbosity));
                    black_box(rendered.len());
                });
            },
        );
    }

    // Also bench the full from_output + render pipeline
    group.bench_function("from_output_and_render_standard", |b| {
        b.iter(|| {
            let narrative = ProvenanceNarrative::from_output(black_box(&output));
            let rendered = narrative.render(NarrativeVerbosity::Standard);
            black_box(rendered.len());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_resource_graph_construction,
    bench_blast_radius_estimation,
    bench_output_serialization,
    bench_narrative_rendering,
);
criterion_main!(benches);
