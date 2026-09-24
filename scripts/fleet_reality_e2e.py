#!/usr/bin/env python3
"""Live, read-only fleet reality e2e for `pt-core agent plan`.

Runs the REAL shipped planning pipeline on real hosts over SSH, applies the label
rules in test/fixtures/fleet/labels.json and enforces their gates:

  * must_not_act: live infrastructure (agent CLIs, terminal multiplexers, SSH
    ControlMasters, session daemons, db/web workers, interactive shells, pt itself)
    is never recommended for any action other than keep/review;
  * no candidate younger than the effective minimum age;
  * no impossible process age (older than the host's uptime);
  * plan wall time within budget.

Read-only by construction: only `agent plan` runs (never apply), under `nice -n 19`,
with an isolated PROCESS_TRIAGE_DATA directory and PROCESS_TRIAGE_RETENTION=off so
the session-retention GC can never touch a host's real session history.

Fleet data (command lines are private) is written only under the gitignored
target/test-logs/e2e/fleet/<run_id>/, with an E2E artifact manifest
(docs/E2E_ARTIFACT_MANIFEST.md) validated by scripts/validate_e2e_manifest.py.

Usage:
  scripts/fleet_reality_e2e.py --hosts trj,hz3,vmi1149989 [--binary PATH] [--tag TAG]
  scripts/fleet_reality_e2e.py --hosts ... --use-installed      # test the installed pt-core

Exit status: 0 = all gates PASS, 1 = at least one gate FAIL, 2 = harness error.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import pathlib
import platform
import re
import shlex
import subprocess
import sys
import time
import uuid

REPO = pathlib.Path(__file__).resolve().parent.parent
LABELS = REPO / "test" / "fixtures" / "fleet" / "labels.json"
ACTIVE_ACTIONS = {"kill", "restart", "pause", "renice", "throttle", "freeze", "quarantine"}

REMOTE_SCRIPT = r"""
set -u
BIN="$1"; DATA="$2"
export PROCESS_TRIAGE_DATA="$DATA" PROCESS_TRIAGE_RETENTION=off
mkdir -p "$DATA"
UPTIME=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo 0)
T0=$(date +%s%N)
nice -n 19 timeout 900 "$BIN" agent plan --format json --max-candidates 5000 \
  >"$DATA/.plan.json" 2>"$DATA/.plan.err"
RC=$?
T1=$(date +%s%N)
echo "@@META rc=$RC ms=$(( (T1 - T0) / 1000000 )) uptime=$UPTIME version=$("$BIN" --version 2>/dev/null)"
echo "@@PLAN"; cat "$DATA/.plan.json"
echo "@@ERR"; tail -c 4000 "$DATA/.plan.err"
"""


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def log_event(log_path: pathlib.Path, run_id: str, **fields) -> None:
    fields = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "run_id": run_id, **fields}
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(fields, sort_keys=True) + "\n")


def run_host(host: str, binary: str | None, tag: str, use_installed: bool, timeout: int) -> dict:
    """Stage the binary (unless --use-installed) and run the read-only plan on one host."""
    started = time.monotonic()
    commands = []
    if use_installed:
        remote_bin = "$HOME/.local/bin/pt-core"
    else:
        remote_dir = f".cache/pt-e2e/{tag}"
        remote_bin = f"$HOME/{remote_dir}/pt-core"
        for argv in (
            ["ssh", "-o", "BatchMode=yes", host, f"mkdir -p ~/{remote_dir}"],
            ["scp", "-q", binary, f"{host}:{remote_dir}/pt-core"],
        ):
            t = time.monotonic()
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            commands.append({"argv": argv, "exit_code": r.returncode,
                             "duration_ms": int((time.monotonic() - t) * 1000)})
            if r.returncode != 0:
                return {"host": host, "error": f"staging failed: {r.stderr.strip()[:300]}",
                        "commands": commands}
    data_dir = f"$HOME/.cache/pt-e2e/{tag}/data"
    argv = ["ssh", "-o", "BatchMode=yes", host,
            f"bash -s -- {remote_bin} {data_dir}"]
    t = time.monotonic()
    try:
        r = subprocess.run(argv, input=REMOTE_SCRIPT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        commands.append({"argv": argv, "exit_code": -1, "duration_ms": timeout * 1000})
        return {"host": host, "error": "ssh timeout", "commands": commands}
    commands.append({"argv": argv, "exit_code": r.returncode,
                     "duration_ms": int((time.monotonic() - t) * 1000)})
    out = r.stdout
    meta_m = re.search(r"@@META rc=(-?\d+) ms=(\d+) uptime=([\d.]+) version=(.*)", out)
    if not meta_m or "@@PLAN" not in out:
        return {"host": host, "error": f"no plan output: {r.stderr.strip()[:300]}", "commands": commands}
    plan_text = out.split("@@PLAN", 1)[1].split("@@ERR", 1)[0].strip()
    err_text = out.split("@@ERR", 1)[1] if "@@ERR" in out else ""
    try:
        plan = json.loads(plan_text)
    except json.JSONDecodeError as exc:
        return {"host": host, "error": f"plan JSON invalid: {exc}", "commands": commands,
                "stderr": err_text}
    return {
        "host": host,
        "plan_rc": int(meta_m.group(1)),
        "plan_ms": int(meta_m.group(2)),
        "uptime_s": float(meta_m.group(3)),
        "version": meta_m.group(4).strip(),
        "plan": plan,
        "plan_text": plan_text,
        "stderr": err_text,
        "commands": commands,
        "wall_ms": int((time.monotonic() - started) * 1000),
    }


def evaluate(result: dict, labels: dict) -> dict:
    """Apply label rules and gates to one host's plan."""
    must = {k: re.compile(v) for k, v in labels["must_not_act"].items() if not k.startswith("_")}
    surf = {k: re.compile(v) for k, v in labels["should_surface"].items() if not k.startswith("_")}
    gates = labels["gates"]
    plan = result["plan"]
    cands = plan.get("candidates", [])
    min_age = (plan.get("args") or {}).get("effective_min_age")
    violations, young, impossible = [], [], []
    surfaced = {k: 0 for k in surf}
    present = {k: 0 for k in surf}
    for c in cands:
        cmd = c.get("command") or ""
        action = c.get("recommended_action")
        age = c.get("age_seconds") or 0
        if action in ACTIVE_ACTIONS:
            for cls, rx in must.items():
                if rx.search(cmd):
                    violations.append({"class": cls, "pid": c.get("pid"), "action": action,
                                       "score": c.get("score"), "command": cmd[:160]})
                    break
        if min_age is not None and age < min_age:
            young.append({"pid": c.get("pid"), "age_seconds": age})
        if age > result["uptime_s"] + 60:
            impossible.append({"pid": c.get("pid"), "age_seconds": age})
        for cls, rx in surf.items():
            if rx.search(cmd):
                present[cls] += 1
                if (c.get("score") or 0) >= 50:
                    surfaced[cls] += 1
    actions: dict[str, int] = {}
    for c in cands:
        actions[c.get("recommended_action")] = actions.get(c.get("recommended_action"), 0) + 1
    checks = {
        "must_not_act_violations": (len(violations), gates["must_not_act_violations_max"]),
        "candidates_younger_than_min_age": (len(young), gates["candidates_younger_than_min_age_max"]),
        "impossible_age": (len(impossible), gates["impossible_age_max"]),
        "plan_wall_seconds": (round(result["plan_ms"] / 1000, 1), gates["plan_wall_seconds_max"]),
        "plan_exit_code_ok": (0 if result["plan_rc"] in (0, 1) else 1, 0),
    }
    passed = all(v <= limit for v, limit in checks.values())
    summary = plan.get("summary", {})
    return {
        "host": result["host"],
        "version": result["version"],
        "passed": passed,
        "checks": {k: {"value": v, "max": m, "ok": v <= m} for k, (v, m) in checks.items()},
        "violations": violations,
        "young": young[:10],
        "impossible": impossible[:10],
        "counts": {
            "scanned": summary.get("total_processes_scanned"),
            "protected": summary.get("protected_filtered"),
            "evaluated": summary.get("candidates_evaluated"),
            "candidates": len(cands),
            "actions": actions,
        },
        "should_surface": {k: {"present": present[k], "score_ge_50": surfaced[k]} for k in surf},
        "top": [
            {"pid": c.get("pid"), "score": c.get("score"), "action": c.get("recommended_action"),
             "command": (c.get("command") or "")[:100]}
            for c in sorted(cands, key=lambda c: -(c.get("score") or 0))[:5]
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hosts", required=True, help="comma-separated SSH host aliases")
    ap.add_argument("--binary", help="local Linux pt-core build to stage on each host")
    ap.add_argument("--use-installed", action="store_true", help="test ~/.local/bin/pt-core as installed")
    ap.add_argument("--tag", default=None, help="staging tag under ~/.cache/pt-e2e/ (default: run id)")
    ap.add_argument("--timeout", type=int, default=1200)
    args = ap.parse_args()
    if not args.use_installed and not args.binary:
        ap.error("pass --binary PATH or --use-installed")

    labels = json.loads(LABELS.read_text())
    run_id = "fleet-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    tag = args.tag or run_id
    out_dir = REPO / "target" / "test-logs" / "e2e" / "fleet" / run_id
    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "plans").mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "logs" / "fleet_reality.jsonl"
    git_sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                             capture_output=True, text=True).stdout.strip()
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    log_event(log_path, run_id, event="run_started", hosts=hosts, git_sha=git_sha, tag=tag,
              binary=args.binary, use_installed=args.use_installed)
    t0 = time.monotonic()

    with cf.ThreadPoolExecutor(max_workers=min(len(hosts), 16)) as ex:
        results = list(ex.map(lambda h: run_host(h, args.binary, tag, args.use_installed, args.timeout), hosts))

    commands, artifacts, reports = [], [], []
    failures = 0
    for res in results:
        commands.extend(res.get("commands", []))
        host = res["host"]
        if "error" in res:
            failures += 1
            log_event(log_path, run_id, event="host_error", host=host, error=res["error"])
            reports.append({"host": host, "passed": False, "error": res["error"]})
            print(f"[FAIL] {host}: {res['error']}")
            continue
        plan_path = out_dir / "plans" / f"{host}.plan.json"
        plan_path.write_text(res["plan_text"])
        (out_dir / "logs" / f"{host}.stderr.log").write_text(res.get("stderr", ""))
        artifacts.append({"path": f"plans/{host}.plan.json", "kind": "plan",
                          "sha256": sha256_file(plan_path), "bytes": plan_path.stat().st_size,
                          "redaction_profile": "debug"})
        rep = evaluate(res, labels)
        reports.append(rep)
        failures += 0 if rep["passed"] else 1
        log_event(log_path, run_id, event="host_result", **{k: rep[k] for k in ("host", "version", "passed", "checks", "counts")})
        status = "PASS" if rep["passed"] else "FAIL"
        c = rep["counts"]
        print(f"[{status}] {host} ({rep['version']}): {res['plan_ms']/1000:.1f}s scanned={c['scanned']} "
              f"protected={c['protected']} candidates={c['candidates']} actions={c['actions']} "
              f"violations={len(rep['violations'])}")
        for v in rep["violations"][:5]:
            print(f"        !! {v['class']} pid={v['pid']} {v['action']} score={v['score']} :: {v['command'][:90]}")

    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps({"run_id": run_id, "git_sha": git_sha, "hosts": reports}, indent=2))
    artifacts.append({"path": "report.json", "kind": "other", "sha256": sha256_file(report_path),
                      "bytes": report_path.stat().st_size})
    total_ms = int((time.monotonic() - t0) * 1000)
    log_event(log_path, run_id, event="run_finished", failures=failures, total_ms=total_ms)
    logs = [{"path": "logs/fleet_reality.jsonl", "kind": "jsonl", "sha256": sha256_file(log_path),
             "bytes": log_path.stat().st_size}]
    for p in sorted((out_dir / "logs").glob("*.stderr.log")):
        logs.append({"path": f"logs/{p.name}", "kind": "stderr", "sha256": sha256_file(p),
                     "bytes": p.stat().st_size})
    manifest = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "suite": "fleet-reality",
        "test_id": "agent-plan-read-only",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "env": {"os": platform.system().lower(), "arch": platform.machine(),
                "kernel": platform.release(), "ci_provider": "local",
                "runner": "scripts/fleet_reality_e2e.py", "git_sha": git_sha,
                "hosts": hosts, "binary": args.binary or "installed"},
        "commands": commands,
        "logs": logs,
        "artifacts": artifacts,
        "metrics": {"timings_ms": {"total": total_ms},
                    "counts": {"tests": len(hosts), "failures": failures},
                    "flake_retries": 0},
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    manifest["manifest_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    verdict = "PASS" if failures == 0 else "FAIL"
    print(f"\n{verdict}: {len(hosts) - failures}/{len(hosts)} hosts passed. Artifacts: {out_dir}")
    print(f"validate: scripts/validate_e2e_manifest.py {shlex.quote(str(out_dir / 'manifest.json'))}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
