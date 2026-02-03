# No-Mock Policy (Core Modules)

## Goal
Keep core modules deterministic and grounded in real system behavior by **disallowing mocking frameworks** inside the core implementation paths.

## Scope (Restricted Paths)
The policy applies to the following directories:
- `crates/pt-core/src/collect`
- `crates/pt-core/src/inference`
- `crates/pt-core/src/decision`
- `crates/pt-core/src/plan`
- `crates/pt-core/src/action`
- `crates/pt-core/src/session`
- `crates/pt-core/src/supervision`

## Denylist (Mock Frameworks)
The following crates/usages are **not allowed** in restricted paths:
- `mockall`
- `mockito`
- `wiremock`
- `httmock`
- `httpmock`
- `faux`
- `mockall_double`

## Allowlist (Explicit Exceptions)
These paths are **out of scope** for the no-mock policy check:
- `crates/pt-core/tests`
- `test/`
- `crates/pt-core/src/mock_process.rs`
- `crates/pt-core/src/test_utils.rs`

If a new exception is needed:
1. Add it to `ALLOWLIST_PATHS` in `scripts/check_no_mocks.sh`.
2. Document the reason here in this file.

## Local Check
```bash
scripts/check_no_mocks.sh
```

## CI Gate
The CI workflow runs the script and fails the build if denylisted mocks appear in restricted paths.

## Rationale
Core modules should reflect real system conditions. Mock frameworks can mask incorrect assumptions and reduce confidence in safety-critical behavior.
