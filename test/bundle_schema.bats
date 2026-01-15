#!/usr/bin/env bats

setup() {
    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    export PROJECT_ROOT
}

@test "bundle manifest schema is valid JSON" {
    run python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["PROJECT_ROOT"])
with open(root / "specs" / "schemas" / "bundle-manifest.schema.json", "r", encoding="utf-8") as f:
    schema = json.load(f)
assert schema.get("$schema")
assert schema.get("$id")
assert schema.get("title")
PY
    [ "$status" -eq 0 ]
}
