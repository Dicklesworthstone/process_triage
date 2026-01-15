#!/usr/bin/env bats

setup() {
    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    export PROJECT_ROOT
}

@test "policy schema is valid JSON" {
    run python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["PROJECT_ROOT"])
with open(root / "specs" / "schemas" / "policy.schema.json", "r", encoding="utf-8") as f:
    schema = json.load(f)
assert schema.get("schema_version") is None
assert schema.get("$schema")
assert schema.get("$id")
PY
    [ "$status" -eq 0 ]
}

@test "policy default has required keys and sane loss rows" {
    run python3 - <<'PY'
import json
import os
import sys
from pathlib import Path
root = Path(os.environ["PROJECT_ROOT"])
with open(root / "specs" / "schemas" / "policy.default.json", "r", encoding="utf-8") as f:
    policy = json.load(f)

required = ["schema_version", "loss_matrix", "guardrails", "robot_mode", "fdr_control", "data_loss_gates"]
missing = [k for k in required if k not in policy]
if missing:
    print("missing keys:", ",".join(missing))
    sys.exit(1)

classes = ["useful", "useful_bad", "abandoned", "zombie"]
for cls in classes:
    row = policy["loss_matrix"].get(cls)
    if row is None:
        print("missing loss row:", cls)
        sys.exit(1)
    for k in ("keep", "kill"):
        if k not in row:
            print("missing action", k, "for", cls)
            sys.exit(1)
    for action, value in row.items():
        if not isinstance(value, (int, float)) or value < 0:
            print("invalid loss value", action, value, "for", cls)
            sys.exit(1)
PY
    [ "$status" -eq 0 ]
}
