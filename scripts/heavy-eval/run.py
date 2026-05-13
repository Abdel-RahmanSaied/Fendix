#!/usr/bin/env python3
"""Heavy-eval harness — Track 4 of docs/accuracy.md.

Runs fendix against:
  4a   Juliet-style Python labeled corpus       (line-anchored scoring)
  4b   CVE-anchored Python repos                (category-count scoring)
  4c   CVE-anchored Node repos                  (category-count scoring)
  4d   CVE-anchored Go repos                    (category-count scoring)
  4e   DAST targets (containerised vuln apps)   (category-count scoring)
  4f   Performance profile across the above    (p50/p95/p99 wall + RSS)

Usage:
    # Full sweep (~2 hrs with DAST + perf):
    python3 scripts/heavy-eval/run.py --binary ./bin/fendix --all

    # Fast: SAST stages only (~5 min):
    python3 scripts/heavy-eval/run.py --binary ./bin/fendix --fast

    # Single stage (use to iterate on one corpus):
    python3 scripts/heavy-eval/run.py --binary ./bin/fendix --stage 4a

Outputs:
    bench-results/heavy/<UTC-ISO>/
        results.json                # the everything-aggregate
        stage-<id>.json             # per-stage detail
        targets/<target_id>/...     # raw fendix output per target

The repro flow is `make heavy-eval` (full) or `make heavy-eval-fast`
(SAST stages only).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HEAVY_DIR = Path(__file__).resolve().parent
REPO_ROOT = HEAVY_DIR.parent.parent
RESULTS_ROOT = REPO_ROOT / "bench-results" / "heavy"
CACHE_DIR = HEAVY_DIR / "corpus-cache"

sys.path.insert(0, str(HEAVY_DIR))
from corpus import (  # noqa: E402
    STAGES, STAGE_DESCRIPTIONS, all_stages, fast_stages, targets_for,
)
from score import score, aggregate_targets, load_manifest  # noqa: E402
from perf import profile_scan  # noqa: E402


# ─── cli ─────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--binary", default=str(REPO_ROOT / "bin" / "fendix"))
    p.add_argument("--python-engine", action="store_true",
                   help="Pass --python-engine to fendix (needed for AST-based detectors)")
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--all", action="store_true", help="Run every stage (4a–4f)")
    grp.add_argument("--fast", action="store_true", help="Run SAST stages only (4a–4d)")
    grp.add_argument("--stage", action="append", default=None,
                     help="Run a specific stage (repeatable: --stage 4a --stage 4b)")
    p.add_argument("--perf-repeats", type=int, default=5,
                   help="Repeats per target for stage 4f (default: 5)")
    p.add_argument("--skip-perf-on", default="",
                   help="Comma-separated target ids to skip in stage 4f (e.g. slow DAST repeats)")
    p.add_argument("--results-dir", default=None,
                   help="Output directory (default: bench-results/heavy/<UTC-ISO>)")
    p.add_argument("--no-docker", action="store_true",
                   help="Skip DAST (stage 4e) even if --all is set")
    return p.parse_args()


# ─── logging ─────────────────────────────────────────────────────────


def log(msg: str) -> None:
    print(f"\033[36m→\033[0m {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"\033[33m!\033[0m {msg}", flush=True)


def err(msg: str) -> None:
    print(f"\033[31m✗\033[0m {msg}", flush=True)


def good(msg: str) -> None:
    print(f"\033[32m✓\033[0m {msg}", flush=True)


# ─── target materialisation ─────────────────────────────────────────


def _materialise_git(target: dict) -> Path | None:
    dest = CACHE_DIR / target["id"]
    if dest.exists() and any(dest.iterdir()):
        log(f"  cache hit: {target['id']}")
        return dest
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    sha = target.get("sha", "HEAD")
    url = target["url"]
    log(f"  clone {url} @ {sha[:12]} -> {dest}")
    # depth=1 then fetch the exact SHA if it's pinned
    if sha == "HEAD":
        proc = subprocess.run(
            ["git", "clone", "--depth=1", url, str(dest)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            err(f"  clone failed: {proc.stderr.strip()[:200]}")
            return None
        return dest
    # pinned sha: shallow clone, then fetch the SHA
    proc = subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        err(f"  clone failed: {proc.stderr.strip()[:200]}")
        return None
    proc = subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth=1", "origin", sha],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        # fall back to default branch — sha might be a tag
        proc2 = subprocess.run(
            ["git", "-C", str(dest), "checkout", sha],
            capture_output=True, text=True,
        )
        if proc2.returncode != 0:
            warn(f"  could not pin to {sha}; using default branch")
            subprocess.run(
                ["git", "-C", str(dest), "checkout"], capture_output=True, text=True,
            )
            return dest
        return dest
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "FETCH_HEAD"],
        capture_output=True, text=True,
    )
    return dest


def _materialise_local(target: dict) -> Path | None:
    path = HEAVY_DIR / target["path"]
    if not path.exists():
        err(f"  local path missing: {path}")
        return None
    return path


def _docker_run(target: dict) -> str | None:
    """Start a DAST container; return its name on success, None on
    skip. Caller must stop it via _docker_rm."""
    name = f"fendix-heavy-{target['id']}"
    img = target["image"]
    host_port = target.get("host_port", target["port"])
    container_port = target["port"]
    boot_wait = target.get("boot_wait_sec", 30)

    subprocess.run(["docker", "rm", "-f", name],
                   capture_output=True, text=True)
    log(f"  docker run {img} (-> localhost:{host_port})")
    proc = subprocess.run(
        ["docker", "run", "-d", "--name", name,
         "-p", f"{host_port}:{container_port}", img],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        err(f"  docker run failed: {proc.stderr.strip()[:300]}")
        return None

    base_url = f"http://localhost:{host_port}{target.get('url_path', '/')}"
    log(f"  waiting up to {boot_wait}s for {base_url}")
    deadline = time.time() + boot_wait
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url, timeout=2) as resp:
                if resp.status < 500:
                    good(f"  ready: {base_url} -> HTTP {resp.status}")
                    return name
        except (urllib.error.URLError, ConnectionResetError, TimeoutError):
            pass
        except urllib.error.HTTPError as e:
            # 4xx still means the app is up
            if e.code < 500:
                good(f"  ready: {base_url} -> HTTP {e.code}")
                return name
        time.sleep(2)
    err(f"  boot wait exceeded for {target['id']}")
    _docker_rm(name)
    return None


def _docker_rm(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name],
                   capture_output=True, text=True)


# ─── scan execution ─────────────────────────────────────────────────


def _run_fendix(binary: str, scan_args: list[str], python_engine: bool,
                out_path: Path) -> tuple[dict, str]:
    cmd = [binary, "scan"] + scan_args + ["--format", "json"]
    if python_engine:
        cmd.append("--python-engine")
    # Run from repo root so fendix's spawner can resolve python/ tree.
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if proc.stdout:
        out_path.write_text(proc.stdout)
    stderr_path = out_path.with_suffix(".stderr")
    stderr_path.write_text(proc.stderr[:200000])
    if proc.returncode not in (0, 1):
        warn(f"  fendix exited {proc.returncode}; stderr head: {proc.stderr[:300]}")
    if not proc.stdout.strip():
        return {"findings": []}, proc.stderr
    try:
        return json.loads(proc.stdout), proc.stderr
    except json.JSONDecodeError as e:
        warn(f"  could not parse fendix JSON: {e}")
        return {"findings": []}, proc.stderr


# ─── per-target driver ──────────────────────────────────────────────


def run_target(target: dict, *, binary: str, python_engine: bool,
               results_dir: Path) -> dict[str, Any]:
    tid = target["id"]
    log(f"target: {tid} ({target.get('kind')} / {target.get('language', '?')})")

    target_out = results_dir / "targets" / tid
    target_out.mkdir(parents=True, exist_ok=True)

    kind = target["kind"]
    code_path: Path | None = None
    container_name: str | None = None
    scan_args: list[str] = []

    if kind == "git":
        code_path = _materialise_git(target)
        if code_path is None:
            return {"target_id": tid, "status": "skip", "reason": "clone failed"}
        sub = target.get("code_subpath")
        if sub:
            code_path = code_path / sub
        scan_args = ["--code", str(code_path)]
    elif kind == "local":
        code_path = _materialise_local(target)
        if code_path is None:
            return {"target_id": tid, "status": "skip", "reason": "local path missing"}
        scan_args = ["--code", str(code_path)]
    elif kind == "docker":
        container_name = _docker_run(target)
        if container_name is None:
            return {"target_id": tid, "status": "skip", "reason": "docker boot failed"}
        host_port = target.get("host_port", target["port"])
        base_url = f"http://localhost:{host_port}{target.get('url_path', '/')}"
        scan_args = ["--url", base_url]
    else:
        return {"target_id": tid, "status": "skip", "reason": f"unknown kind {kind}"}

    try:
        report, _ = _run_fendix(
            binary, scan_args, python_engine,
            target_out / "report.json",
        )

        labels_path = HEAVY_DIR / target["labels_file"]
        if not labels_path.exists():
            warn(f"  no labels for {tid}; emitting raw report only")
            score_obj = None
        else:
            manifest = load_manifest(labels_path)
            score_obj = score(manifest, report.get("findings", []))
            (target_out / "score.json").write_text(json.dumps(score_obj, indent=2))

        return {
            "target_id": tid,
            "status": "ok",
            "kind": kind,
            "language": target.get("language"),
            "findings_count": len(report.get("findings", [])),
            "score": score_obj,
        }
    finally:
        if container_name is not None:
            _docker_rm(container_name)


# ─── stages 4a–4e ───────────────────────────────────────────────────


def run_stage(stage: str, *, binary: str, python_engine: bool,
              results_dir: Path, skip_docker: bool) -> dict[str, Any]:
    if stage == "4f":
        return {"stage": "4f", "skipped": True, "reason": "use --stage 4f explicitly"}
    targets = targets_for(stage)
    if not targets:
        return {"stage": stage, "skipped": True, "reason": "no targets"}
    if stage == "4e" and skip_docker:
        return {"stage": stage, "skipped": True, "reason": "docker disabled"}

    log(f"=== stage {stage} — {STAGE_DESCRIPTIONS[stage]} ===")
    target_results = []
    for t in targets:
        res = run_target(t, binary=binary, python_engine=python_engine,
                         results_dir=results_dir)
        target_results.append(res)

    agg = aggregate_targets(target_results)
    out = {
        "stage": stage,
        "description": STAGE_DESCRIPTIONS[stage],
        "target_count": len(targets),
        "targets": target_results,
        "aggregate": agg,
    }
    stage_file = results_dir / f"stage-{stage}.json"
    stage_file.write_text(json.dumps(out, indent=2))
    log(f"  -> {stage_file}")
    return out


# ─── stage 4f (perf) ─────────────────────────────────────────────────


def run_perf_stage(*, binary: str, python_engine: bool, repeats: int,
                   results_dir: Path, skip_docker: bool,
                   skip_targets: set[str]) -> dict[str, Any]:
    log(f"=== stage 4f — perf profile ({repeats} repeats per target) ===")
    perf_targets: list[dict] = []
    for stage in ("4a", "4b", "4c", "4d"):
        perf_targets.extend(targets_for(stage))
    if not skip_docker:
        perf_targets.extend(targets_for("4e"))

    perf_results = []
    perf_log_dir = results_dir / "perf-logs"
    perf_log_dir.mkdir(parents=True, exist_ok=True)

    for target in perf_targets:
        tid = target["id"]
        if tid in skip_targets:
            log(f"  skip {tid} (--skip-perf-on)")
            continue
        log(f"perf: {tid}")
        kind = target["kind"]
        if kind == "git":
            code_path = CACHE_DIR / tid
            if not code_path.exists():
                code_path = _materialise_git(target)
            if code_path is None:
                continue
            scan_args = ["--code", str(code_path)]
        elif kind == "local":
            code_path = _materialise_local(target)
            if code_path is None:
                continue
            scan_args = ["--code", str(code_path)]
        elif kind == "docker":
            name = _docker_run(target)
            if name is None:
                continue
            host_port = target.get("host_port", target["port"])
            base_url = f"http://localhost:{host_port}{target.get('url_path', '/')}"
            scan_args = ["--url", base_url]
            code_path = None
        else:
            continue
        if python_engine:
            scan_args = scan_args + ["--python-engine"]

        try:
            row = profile_scan(
                fendix_bin=binary,
                scan_args=scan_args,
                code_path=code_path,
                repeats=repeats,
                label=tid,
                log_dir=perf_log_dir,
            )
            row["target_id"] = tid
            row["language"] = target.get("language")
            row["kind"] = kind
            perf_results.append(row)
        finally:
            if kind == "docker":
                _docker_rm(f"fendix-heavy-{tid}")

    out = {
        "stage": "4f",
        "description": STAGE_DESCRIPTIONS["4f"],
        "repeats_per_target": repeats,
        "targets": perf_results,
    }
    (results_dir / "stage-4f.json").write_text(json.dumps(out, indent=2))
    return out


# ─── main ────────────────────────────────────────────────────────────


def main() -> int:
    args = parse_args()
    binary = args.binary
    if not os.access(binary, os.X_OK):
        err(f"binary not executable: {binary}")
        return 2

    if args.results_dir:
        results_dir = Path(args.results_dir)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        results_dir = RESULTS_ROOT / ts
    results_dir.mkdir(parents=True, exist_ok=True)
    log(f"results: {results_dir}")

    if args.all:
        stages = all_stages()
    elif args.fast:
        stages = fast_stages()
    elif args.stage:
        stages = args.stage
    else:
        stages = fast_stages()

    skip_perf = set(s for s in args.skip_perf_on.split(",") if s)
    stage_results: dict[str, Any] = {}
    for s in stages:
        if s == "4f":
            stage_results["4f"] = run_perf_stage(
                binary=binary,
                python_engine=args.python_engine,
                repeats=args.perf_repeats,
                results_dir=results_dir,
                skip_docker=args.no_docker,
                skip_targets=skip_perf,
            )
        else:
            stage_results[s] = run_stage(
                s,
                binary=binary,
                python_engine=args.python_engine,
                results_dir=results_dir,
                skip_docker=args.no_docker,
            )

    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "binary": binary,
        "python_engine": args.python_engine,
        "stages_run": stages,
        "stages": stage_results,
    }
    (results_dir / "results.json").write_text(json.dumps(summary, indent=2))
    good(f"wrote {results_dir}/results.json")

    # short stdout summary
    print()
    print("=" * 70)
    print(f"  Heavy-eval summary — {results_dir.name}")
    print("=" * 70)
    for s, sr in stage_results.items():
        if sr.get("skipped"):
            print(f"  stage {s}: SKIPPED ({sr.get('reason')})")
            continue
        if s == "4f":
            n = len(sr.get("targets", []))
            print(f"  stage {s}: perf profile across {n} target(s)")
            continue
        agg = sr.get("aggregate", {})
        la = agg.get("line_anchored_aggregate", {})
        cc = agg.get("category_count_aggregate", {})
        bits = []
        if la.get("f1") is not None:
            bits.append(f"line-anchored F1={la['f1']:.3f}")
        if cc.get("expectation_recall") is not None:
            bits.append(f"cat-recall={cc['expectation_recall']:.3f} "
                        f"({cc['hits']}/{cc['hits'] + cc['miss']} expectations met)")
        print(f"  stage {s} ({sr.get('target_count')} targets): {'; '.join(bits) or '(no scoring)'}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
