#!/usr/bin/env python3
"""Verify fixture redaction by scanning for sensitive patterns."""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List

HOME_RE = re.compile(r"/(Users|home)/[^/]+")
WIN_HOME_RE = re.compile(r"[A-Za-z]:\\\\Users\\\\[^\\\\]+")
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RE = re.compile(r"\b(?:[A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,}\b")
SENSITIVE_ENV_RE = re.compile(
    r"\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|"
    r"SLACK_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|AZURE_API_KEY|"
    r"PASSWORD|PASSWD|SECRET|TOKEN)\b\s*[:=]",
    re.IGNORECASE,
)
SAFE_HEX_FIELD_RE = re.compile(r'"(?:sha256|manifest_sha256)"\s*:\s*"[0-9a-f]{32,}"', re.IGNORECASE)

FILE_EXTENSION_ALLOWLIST = {
    ".json",
    ".jsonl",
    ".toml",
    ".yaml",
    ".yml",
    ".log",
    ".txt",
    ".md",
    ".rs",
    ".sh",
    ".py",
    ".csv",
    ".tsv",
    ".lock",
    ".sock",
    ".ptb",
    ".html",
    ".htm",
    ".gz",
    ".tar",
    ".zip",
}
HOST_ALLOWLIST = {"localhost", "example.com", "example.org", "example.net"}


def should_exclude(rel_path: str, excludes: Iterable[str]) -> bool:
    for pattern in excludes:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
    return False


def scrub_safe_fields(text: str) -> str:
    return SAFE_HEX_FIELD_RE.sub('"sha256":"<HEX>"', text)


def is_allowed_hostname(value: str) -> bool:
    if value in HOST_ALLOWLIST:
        return True
    if value.startswith("<HOST>") or value.startswith("<IP>"):
        return True
    suffix = "." + value.split(".")[-1].lower()
    if suffix in FILE_EXTENSION_ALLOWLIST:
        return True
    return False


def is_placeholder_home(value: str) -> bool:
    return value.startswith("/home/USER") or value.startswith("/Users/USER") or value.startswith("C:\\Users\\USER")


def collect_matches(pattern: re.Pattern[str], text: str, limit: int) -> List[str]:
    return [match.group(0) for match in pattern.finditer(text)][:limit]


def scan_text(text: str, max_matches: int) -> Dict[str, List[str]]:
    text = scrub_safe_fields(text)
    findings: Dict[str, List[str]] = {}

    home_hits = [match for match in collect_matches(HOME_RE, text, max_matches) if not is_placeholder_home(match)]
    if home_hits:
        findings["home_path"] = home_hits

    win_home_hits = [
        match for match in collect_matches(WIN_HOME_RE, text, max_matches) if not is_placeholder_home(match)
    ]
    if win_home_hits:
        findings["windows_home_path"] = win_home_hits

    uuid_hits = collect_matches(UUID_RE, text, max_matches)
    if uuid_hits:
        findings["uuid"] = uuid_hits

    hex_hits = collect_matches(HEX_RE, text, max_matches)
    if hex_hits:
        findings["hex_id"] = hex_hits

    ip_hits = collect_matches(IPV4_RE, text, max_matches)
    if ip_hits:
        findings["ip_address"] = ip_hits

    host_hits: List[str] = []
    for match in HOSTNAME_RE.finditer(text):
        token = match.group(0)
        if is_allowed_hostname(token):
            continue
        host_hits.append(token)
        if len(host_hits) >= max_matches:
            break
    if host_hits:
        findings["hostname"] = host_hits

    env_hits = collect_matches(SENSITIVE_ENV_RE, text, max_matches)
    if env_hits:
        findings["env_var"] = env_hits

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify fixture redaction patterns.")
    parser.add_argument("fixture_dir", type=Path, help="Fixture directory to scan")
    parser.add_argument("--exclude", action="append", default=["fixture_manifest.json"], help="Glob to exclude")
    parser.add_argument("--report", default="-", help="Report path or '-' for stdout")
    parser.add_argument("--max-matches", type=int, default=3, help="Max matches per pattern per file")
    args = parser.parse_args()

    fixture_dir = args.fixture_dir.resolve()
    if not fixture_dir.exists():
        raise SystemExit(f"fixture_dir not found: {fixture_dir}")

    issues: List[Dict[str, object]] = []
    scanned_files = 0

    for path in sorted(fixture_dir.rglob("*")):
        if path.is_dir():
            continue
        rel_path = path.relative_to(fixture_dir).as_posix()
        if should_exclude(rel_path, args.exclude):
            continue
        scanned_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        findings = scan_text(text, args.max_matches)
        for kind, matches in findings.items():
            issues.append({"path": rel_path, "kind": kind, "matches": matches})

    report = {
        "schema_version": "1.0.0",
        "fixture_dir": fixture_dir.as_posix(),
        "scanned_files": scanned_files,
        "issue_count": len(issues),
        "issues": issues,
    }

    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report == "-":
        print(payload)
    else:
        report_path = Path(args.report)
        if not report_path.is_absolute():
            report_path = fixture_dir / report_path
        report_path.write_text(payload + "\n", encoding="utf-8")

    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
