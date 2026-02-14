#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
}

@test "pt-core command enum and dispatch include learn workflow" {
    run bash -lc "cd '$REPO_ROOT' && rg -n 'Commands::Learn|Learn\\(LearnArgs\\)' crates/pt-core/src/main.rs"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "learn command exposes conservative verification budgets and fallback" {
    run bash -lc "cd '$REPO_ROOT' && rg -n 'verify_budget_ms|total_budget_ms|fallback' crates/pt-core/src/main.rs crates/pt-core/src/learn/mod.rs docs/tutorials/README.md"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "docs mention pt learn onboarding entrypoint" {
    run bash -lc "cd '$REPO_ROOT' && rg -n '^- `pt learn`|pt learn verify' docs/tutorials/README.md"
    [ "$status" -eq 0 ]
}

@test "scenario policy configs validate with pt-core" {
    run bash -lc "cd '$REPO_ROOT' && cargo run -q -p pt-core --bin pt-core -- config validate examples/configs/developer.json --format summary"
    [ "$status" -eq 0 ]

    run bash -lc "cd '$REPO_ROOT' && cargo run -q -p pt-core --bin pt-core -- config validate examples/configs/server.json --format summary"
    [ "$status" -eq 0 ]

    run bash -lc "cd '$REPO_ROOT' && cargo run -q -p pt-core --bin pt-core -- config validate examples/configs/ci.json --format summary"
    [ "$status" -eq 0 ]
}

@test "fleet discovery and inventory examples are well-formed JSON with expected keys" {
    run bash -lc "cd '$REPO_ROOT' && jq -e '.providers | length > 0' examples/configs/fleet.json >/dev/null"
    [ "$status" -eq 0 ]

    run bash -lc "cd '$REPO_ROOT' && jq -e '.hosts | length > 0' examples/configs/fleet.inventory.json >/dev/null"
    [ "$status" -eq 0 ]
}

@test "README links tutorial, architecture, adr, and demo references" {
    run bash -lc "cd '$REPO_ROOT' && rg -n 'docs/tutorials/README.md|docs/architecture/README.md|docs/adr/|docs/demos/README.md' README.md"
    [ "$status" -eq 0 ]
}
