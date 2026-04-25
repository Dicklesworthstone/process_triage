//! Shared test helpers for pt-core integration tests.
//!
//! Each test binary only includes the helpers it actually references, so the
//! dead-code lint fires on the unused pieces per binary even though every
//! helper is used by at least one test. Silence the noise at the module level.

#![allow(dead_code)]

pub mod live_harness;
pub mod provenance_fixture;
