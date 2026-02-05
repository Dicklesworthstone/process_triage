#!/usr/bin/env bats

setup() {
    TEST_DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" && pwd )"
    PROJECT_ROOT="$(dirname "$TEST_DIR")"
    export PROJECT_ROOT
}

@test "Fixture manifest schema is valid JSON" {
    run python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["PROJECT_ROOT"])
with open(root / "specs" / "schemas" / "fixture-manifest.schema.json", "r", encoding="utf-8") as f:
    schema = json.load(f)
assert schema.get("$schema")
assert schema.get("$id")
assert schema.get("title")
PY
    [ "$status" -eq 0 ]
}

@test "Fixture manifest validator accepts fixtures" {
    local manifests=(
        "$PROJECT_ROOT/test/fixtures/config/fixture_manifest.json"
        "$PROJECT_ROOT/test/fixtures/pt-core/fixture_manifest.json"
        "$PROJECT_ROOT/test/fixtures/manifest_examples/fixture_manifest.json"
        "$PROJECT_ROOT/test/fixtures/capabilities/fixture_manifest.json"
        "$PROJECT_ROOT/test/fixtures/output/fixture_manifest.json"
    )

    for manifest in "${manifests[@]}"; do
        run "$PROJECT_ROOT/scripts/validate_fixture_manifest.py" "$manifest"
        [ "$status" -eq 0 ]
    done
}

@test "Fixture manifest validator rejects checksum mismatch" {
    run python3 - <<'PY'
import os
from pathlib import Path
from shutil import copytree
from tempfile import mkdtemp
root = Path(os.environ["PROJECT_ROOT"])
source_dir = root / "test" / "fixtures" / "config"
workspace = Path(mkdtemp(prefix="fixture_manifest_badhash_"))
copytree(source_dir, workspace, dirs_exist_ok=True)
fixture_file = workspace / "valid_policy.json"
fixture_file.write_text("tampered\n", encoding="utf-8")
print(workspace / "fixture_manifest.json")
PY
    [ "$status" -eq 0 ]
    manifest_path="$output"
    run "$PROJECT_ROOT/scripts/validate_fixture_manifest.py" "$manifest_path"
    [ "$status" -ne 0 ]
}

@test "Fixture manifest validator enforces redaction" {
    run python3 - <<'PY'
import json
import hashlib
import os
from pathlib import Path
from shutil import copytree
from tempfile import mkdtemp
root = Path(os.environ["PROJECT_ROOT"])
source_dir = root / "test" / "fixtures" / "pt-core"
workspace = Path(mkdtemp(prefix="fixture_manifest_redact_"))
copytree(source_dir, workspace, dirs_exist_ok=True)
manifest_path = workspace / "fixture_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest.setdefault("source", {})["paths"] = ["/home/alice/secret"]
clone = dict(manifest)
clone.pop("manifest_sha256", None)
canonical = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(manifest_path)
PY
    [ "$status" -eq 0 ]
    manifest_path="$output"
    run "$PROJECT_ROOT/scripts/validate_fixture_manifest.py" "$manifest_path"
    [ "$status" -ne 0 ]
}
