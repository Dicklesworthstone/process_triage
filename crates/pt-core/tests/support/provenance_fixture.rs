//! Shared provenance fixture helpers for pt-core integration tests.

use pt_common::ProvenanceGraphSnapshot;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

pub fn provenance_fixture_path(name: &str) -> PathBuf {
    repo_root()
        .join("test")
        .join("fixtures")
        .join("pt-core")
        .join(name)
}

pub fn provenance_log_fixture_path(name: &str) -> PathBuf {
    repo_root()
        .join("test")
        .join("fixtures")
        .join("pt-core")
        .join("logs")
        .join(name)
}

pub fn load_provenance_graph_fixture(name: &str) -> ProvenanceGraphSnapshot {
    let path = provenance_fixture_path(name);
    let contents = fs::read_to_string(&path).expect("read provenance graph fixture");
    serde_json::from_str(&contents).expect("parse provenance graph fixture")
}

pub fn load_provenance_trace_fixture(name: &str) -> Vec<Value> {
    let path = provenance_log_fixture_path(name);
    let contents = fs::read_to_string(&path).expect("read provenance log fixture");

    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("parse provenance log event"))
        .collect()
}
