#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
}

@test "tutorial index references existing markdown files" {
    local readme="${REPO_ROOT}/docs/tutorials/README.md"
    [[ -f "$readme" ]]

    run bash -lc "cd '$REPO_ROOT' && rg -o --no-filename '[0-9]{2}-[a-z0-9-]+\\.md' docs/tutorials/README.md"
    [ "$status" -eq 0 ]
    [ -n "$output" ]

    while IFS= read -r rel; do
        [[ -f "${REPO_ROOT}/docs/tutorials/${rel}" ]]
    done <<< "$output"
}

@test "tutorial markdown files include pt command examples" {
    run bash -lc "cd '$REPO_ROOT' && rg -n --glob '*.md' '(^|\\s)pt(\\s|$)' docs/tutorials/"
    [ "$status" -eq 0 ]
}

@test "learn catalog defines seven tutorial exercises" {
    local learn_mod="${REPO_ROOT}/crates/pt-core/src/learn/mod.rs"
    [[ -f "$learn_mod" ]]

    run bash -lc "cd '$REPO_ROOT' && rg -n 'id: \"0[1-7]\"' crates/pt-core/src/learn/mod.rs | wc -l"
    [ "$status" -eq 0 ]
    [ "${output//[[:space:]]/}" = "7" ]
}

@test "adr directory contains five core decisions" {
    run bash -lc "cd '$REPO_ROOT' && find docs/adr -maxdepth 1 -type f -name 'ADR-*.md' | wc -l"
    [ "$status" -eq 0 ]
    [ "${output//[[:space:]]/}" -ge 5 ]

    run bash -lc "cd '$REPO_ROOT' && rg -n '## Context|## Decision|## Consequences' docs/adr/ADR-00[1-5]-*.md"
    [ "$status" -eq 0 ]
}

@test "architecture docs include mermaid flow diagram source" {
    [[ -f "${REPO_ROOT}/docs/architecture/README.md" ]]
    [[ -f "${REPO_ROOT}/docs/architecture/flow.mmd" ]]

    run bash -lc "cd '$REPO_ROOT' && rg -n 'mermaid|flowchart' docs/architecture/README.md docs/architecture/flow.mmd"
    [ "$status" -eq 0 ]
}

@test "demo documentation tracks three executable scripts" {
    [[ -x "${REPO_ROOT}/docs/demos/basic-scan.sh" ]]
    [[ -x "${REPO_ROOT}/docs/demos/plan-review-apply.sh" ]]
    [[ -x "${REPO_ROOT}/docs/demos/robot-mode.sh" ]]

    run bash -lc "cd '$REPO_ROOT' && rg -n 'basic-scan.sh|plan-review-apply.sh|robot-mode.sh' docs/demos/README.md"
    [ "$status" -eq 0 ]
}
