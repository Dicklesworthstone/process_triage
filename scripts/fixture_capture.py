#!/usr/bin/env python3
"""Capture deterministic fixture manifests with redaction and checksums."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

HOME_RE = re.compile(r"/(Users|home)/[^/]+")
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_HOST_RE = re.compile(r"(https?://)([^/\s]+)")
USER_HOST_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+)")
HOST_FLAG_RE = re.compile(r"(?P<prefix>--host(?:name)?(?:=|\s+))(?P<host>[^\s]+)")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest_bytes(manifest: Dict[str, Any]) -> bytes:
    clone = dict(manifest)
    clone.pop("manifest_sha256", None)
    canonical = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def redact_path(value: str) -> str:
    return HOME_RE.sub("/home/USER", value)


def redact_id(value: str) -> str:
    value = UUID_RE.sub("<UUID>", value)
    value = HEX_RE.sub("<HEX>", value)
    return value


def redact_cmdline(value: str) -> str:
    value = redact_path(value)
    value = redact_id(value)
    value = redact_hostname(value)
    return value


def redact_hostname(value: str) -> str:
    value = URL_HOST_RE.sub(lambda match: f"{match.group(1)}<HOST>", value)
    value = USER_HOST_RE.sub(lambda match: f"{match.group(1)}@<HOST>", value)
    value = HOST_FLAG_RE.sub(lambda match: f"{match.group('prefix')}<HOST>", value)
    value = IPV4_RE.sub("<IP>", value)
    return value


def redact_values(values: Iterable[str]) -> List[str]:
    return [redact_cmdline(value) for value in values]


def parse_tool_versions(entries: Optional[List[str]]) -> Dict[str, str]:
    tool_versions: Dict[str, str] = {"fixture_capture": SCRIPT_VERSION}
    if not entries:
        return tool_versions
    for entry in entries:
        if "=" not in entry:
            raise SystemExit(f"tool version must be key=value, got: {entry}")
        key, value = entry.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise SystemExit(f"tool version must be key=value, got: {entry}")
        tool_versions[key] = value
    return tool_versions


def should_exclude(rel_path: str, excludes: Iterable[str]) -> bool:
    for pattern in excludes:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
    return False


def infer_kind(rel_path: str) -> str:
    name = Path(rel_path).name.lower()
    if name.endswith(".jsonl"):
        return "log"
    if "policy" in name:
        return "policy"
    if "priors" in name:
        return "priors"
    if name.endswith("manifest.json"):
        return "manifest"
    if name.endswith(".json"):
        return "config"
    return "other"


def gather_artifacts(
    fixture_dir: Path,
    excludes: List[str],
    manifest_path: Path,
    log_path: Optional[Path],
    redaction_profile: str,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(fixture_dir.rglob("*")):
        if path.is_dir():
            continue
        if path == manifest_path:
            continue
        if log_path and path == log_path:
            continue
        rel_path = path.relative_to(fixture_dir).as_posix()
        if should_exclude(rel_path, excludes):
            continue
        entries.append(
            {
                "path": rel_path,
                "kind": infer_kind(rel_path),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "redaction_profile": redaction_profile,
            }
        )
    return entries


def write_log(
    log_path: Path,
    event: str,
    fixture_id: str,
    duration_ms: int,
    artifacts: List[Dict[str, Any]],
    host_id: Optional[str],
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "fixture_id": fixture_id,
        "duration_ms": duration_ms,
        "artifacts": [
            {"path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]}
            for item in artifacts
        ],
    }
    if host_id:
        payload["host_id"] = host_id
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")


def build_manifest(
    fixture_dir: Path,
    fixture_id: str,
    domain: str,
    description: Optional[str],
    capture_time: str,
    origin: str,
    command: Optional[List[str]],
    source_paths: Optional[List[str]],
    tool_versions: Dict[str, str],
    redaction_profile: str,
    artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": fixture_id,
        "domain": domain,
        "capture_time": capture_time,
        "source": {
            "origin": origin,
        },
        "tool_versions": tool_versions,
        "redaction_profile": redaction_profile,
        "artifacts": artifacts,
    }

    if description:
        manifest["description"] = description

    if command:
        manifest["source"]["command"] = redact_values(command)

    if source_paths:
        manifest["source"]["paths"] = redact_values(source_paths)

    manifest["manifest_sha256"] = hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture deterministic fixture manifests.")
    parser.add_argument("fixture_dir", type=Path, help="Fixture directory")
    parser.add_argument("--fixture-id", required=True, help="Unique fixture identifier")
    parser.add_argument("--domain", required=True, help="Fixture domain")
    parser.add_argument("--description", default="", help="Fixture description")
    parser.add_argument("--origin", default="manual", help="Source origin")
    parser.add_argument("--command", action="append", help="Source command (repeatable)")
    parser.add_argument("--source-path", action="append", help="Source path (repeatable)")
    parser.add_argument("--tool-version", action="append", help="Tool version key=value")
    parser.add_argument(
        "--redaction-profile",
        default="safe",
        choices=["minimal", "safe", "forensic", "custom"],
    )
    parser.add_argument(
        "--capture-time",
        default=None,
        help="RFC3339 timestamp (default: now UTC)",
    )
    parser.add_argument(
        "--output",
        default="fixture_manifest.json",
        help="Manifest output path (relative to fixture dir if not absolute)",
    )
    parser.add_argument(
        "--log",
        default="logs/fixture_capture.jsonl",
        help="JSONL log path (relative to fixture dir if not absolute)",
    )
    parser.add_argument(
        "--event",
        default="fixture_capture",
        help="Log event name",
    )
    parser.add_argument(
        "--host-id",
        default=None,
        help="Optional host identifier for log correlation",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob to exclude (repeatable, relative to fixture dir)",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Disable JSONL logging",
    )

    args = parser.parse_args()

    fixture_dir = args.fixture_dir.resolve()
    if not fixture_dir.exists():
        raise SystemExit(f"fixture_dir not found: {fixture_dir}")

    capture_time = args.capture_time
    if capture_time is None:
        capture_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    tool_versions = parse_tool_versions(args.tool_version)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = fixture_dir / output_path

    log_path: Optional[Path] = None
    if not args.no_log:
        log_path = Path(args.log)
        if not log_path.is_absolute():
            log_path = fixture_dir / log_path

    start = time.time()
    artifacts = gather_artifacts(
        fixture_dir,
        excludes=args.exclude,
        manifest_path=output_path,
        log_path=log_path,
        redaction_profile=args.redaction_profile,
    )

    manifest = build_manifest(
        fixture_dir=fixture_dir,
        fixture_id=args.fixture_id,
        domain=args.domain,
        description=args.description or None,
        capture_time=capture_time,
        origin=args.origin,
        command=args.command,
        source_paths=args.source_path,
        tool_versions=tool_versions,
        redaction_profile=args.redaction_profile,
        artifacts=artifacts,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    duration_ms = int((time.time() - start) * 1000)
    if log_path is not None:
        write_log(log_path, args.event, args.fixture_id, duration_ms, artifacts, args.host_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
