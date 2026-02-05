#!/usr/bin/env python3
"""Validate fixture manifests (schema, files, checksums, redaction)."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

SCHEMA_RELATIVE = Path("specs/schemas/fixture-manifest.schema.json")
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
REDACTION_PROFILES = {"minimal", "safe", "forensic", "custom"}

HOME_RE = re.compile(r"/(Users|home)/[^/]+")
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_HOST_RE = re.compile(r"https?://([^/\s]+)")
USER_HOST_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)")
HOST_FLAG_RE = re.compile(r"(?P<prefix>--host(?:name)?(?:=|\s+))(?P<host>[^\s]+)")


def is_redacted_host(host: str) -> bool:
    base = host.strip()
    if ":" in base:
        base = base.split(":", 1)[0]
    return base in {"<HOST>", "<IP>", "localhost", "127.0.0.1"}


def load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise SystemExit(f"manifest not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}")


def canonical_manifest_bytes(manifest: Dict[str, Any]) -> bytes:
    clone = deepcopy(manifest)
    clone.pop("manifest_sha256", None)
    canonical = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_schema_with_jsonschema(
    manifest: Dict[str, Any], schema_path: Path, errors: List[str]
) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return

    try:
        schema = load_json(schema_path)
        jsonschema.Draft202012Validator(schema).validate(manifest)
    except jsonschema.ValidationError as exc:
        errors.append(f"schema validation failed: {exc.message}")
    except Exception as exc:  # pragma: no cover - unexpected
        errors.append(f"schema validation error: {exc}")


def parse_rfc3339(value: str) -> bool:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def validate_version(version: str, errors: List[str]) -> None:
    match = VERSION_RE.match(version)
    if not match:
        errors.append(f"schema_version not semver: {version}")
        return
    major = int(match.group(1))
    if major != 1:
        errors.append(f"unsupported schema_version major: {version}")


def check_redaction(value: str, label: str, errors: List[str]) -> None:
    if HOME_RE.search(value):
        errors.append(f"{label} contains unredacted home path")
    if UUID_RE.search(value):
        errors.append(f"{label} contains unredacted UUID")
    if HEX_RE.search(value):
        errors.append(f"{label} contains unredacted hex id")
    if IPV4_RE.search(value):
        errors.append(f"{label} contains unredacted IP address")
    for match in URL_HOST_RE.finditer(value):
        if not is_redacted_host(match.group(1)):
            errors.append(f"{label} contains unredacted hostname in URL")
    for match in USER_HOST_RE.finditer(value):
        if not is_redacted_host(match.group(1)):
            errors.append(f"{label} contains unredacted user@host")
    for match in HOST_FLAG_RE.finditer(value):
        if not is_redacted_host(match.group("host")):
            errors.append(f"{label} contains unredacted --host value")


def validate_source(source: Dict[str, Any], errors: List[str]) -> None:
    origin = source.get("origin")
    if not isinstance(origin, str) or not origin:
        errors.append("source.origin must be string")

    for key in ("command", "paths"):
        value = source.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            errors.append(f"source.{key} must be list")
            continue
        for idx, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(f"source.{key}[{idx}] must be string")
                continue
            check_redaction(item, f"source.{key}[{idx}]", errors)

    notes = source.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("source.notes must be string")


def validate_tool_versions(tool_versions: Dict[str, Any], errors: List[str]) -> None:
    for key, value in tool_versions.items():
        if not isinstance(key, str) or not key:
            errors.append("tool_versions keys must be strings")
            continue
        if not isinstance(value, str) or not value:
            errors.append(f"tool_versions.{key} must be string")


def validate_artifact_entry(
    entry: Dict[str, Any], base_dir: Path, errors: List[str]
) -> None:
    path_value = entry.get("path")
    if not isinstance(path_value, str) or not path_value:
        errors.append("artifact entry missing path")
        return

    path = Path(path_value)
    if not path.is_absolute():
        path = base_dir / path

    if not path.exists():
        errors.append(f"artifact file missing: {path}")
        return

    expected_hash = entry.get("sha256")
    expected_bytes = entry.get("bytes")

    actual_bytes = path.stat().st_size
    actual_hash = sha256_file(path)

    if not isinstance(expected_bytes, int):
        errors.append(f"artifact bytes missing for {path_value}")
    elif expected_bytes != actual_bytes:
        errors.append(
            f"artifact bytes mismatch for {path_value}: expected {expected_bytes}, got {actual_bytes}"
        )

    if not isinstance(expected_hash, str) or not SHA256_RE.match(expected_hash):
        errors.append(f"artifact sha256 invalid for {path_value}")
    elif expected_hash != actual_hash:
        errors.append(
            f"artifact sha256 mismatch for {path_value}: expected {expected_hash}, got {actual_hash}"
        )

    redaction_profile = entry.get("redaction_profile")
    if redaction_profile not in REDACTION_PROFILES:
        errors.append(f"artifact redaction_profile invalid for {path_value}")


def validate_manifest(manifest: Dict[str, Any], manifest_path: Path, schema_path: Path) -> List[str]:
    errors: List[str] = []

    validate_schema_with_jsonschema(manifest, schema_path, errors)

    for field in [
        "schema_version",
        "fixture_id",
        "domain",
        "capture_time",
        "source",
        "tool_versions",
        "redaction_profile",
        "artifacts",
        "manifest_sha256",
    ]:
        if field not in manifest:
            errors.append(f"missing required field: {field}")

    schema_version = manifest.get("schema_version")
    if isinstance(schema_version, str):
        validate_version(schema_version, errors)
    else:
        errors.append("schema_version must be string")

    if not isinstance(manifest.get("fixture_id"), str):
        errors.append("fixture_id must be string")
    if not isinstance(manifest.get("domain"), str):
        errors.append("domain must be string")

    capture_time = manifest.get("capture_time")
    if isinstance(capture_time, str):
        if not parse_rfc3339(capture_time):
            errors.append("capture_time must be RFC3339 timestamp")
    else:
        errors.append("capture_time must be string")

    source = manifest.get("source")
    if isinstance(source, dict):
        validate_source(source, errors)
    else:
        errors.append("source must be object")

    tool_versions = manifest.get("tool_versions")
    if isinstance(tool_versions, dict):
        validate_tool_versions(tool_versions, errors)
    else:
        errors.append("tool_versions must be object")

    redaction_profile = manifest.get("redaction_profile")
    if redaction_profile not in REDACTION_PROFILES:
        errors.append("redaction_profile must be one of minimal/safe/forensic/custom")

    artifacts = manifest.get("artifacts")
    if isinstance(artifacts, list) and artifacts:
        base_dir = manifest_path.parent
        for entry in artifacts:
            if not isinstance(entry, dict):
                errors.append("artifact entry must be object")
                continue
            validate_artifact_entry(entry, base_dir, errors)
    else:
        errors.append("artifacts must be non-empty list")

    manifest_sha = manifest.get("manifest_sha256")
    if isinstance(manifest_sha, str) and SHA256_RE.match(manifest_sha):
        computed = sha256_bytes(canonical_manifest_bytes(manifest))
        if manifest_sha != computed:
            errors.append("manifest_sha256 mismatch")
    else:
        errors.append("manifest_sha256 must be sha256 hex")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate fixture manifest files.")
    parser.add_argument("manifest", type=Path, help="Path to fixture manifest JSON")
    args = parser.parse_args()

    manifest_path = args.manifest
    root = Path(__file__).resolve().parents[1]
    schema_path = root / SCHEMA_RELATIVE

    manifest = load_json(manifest_path)
    errors = validate_manifest(manifest, manifest_path, schema_path)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
