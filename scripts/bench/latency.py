#!/usr/bin/env python3
"""Reproducible latency benchmark for `fendix scan` (audit item 46).

Supersedes scripts/bench/coldstart.py for published numbers. That script
reported min/p50/p95/max over 30 runs with no warmup, no p99, no standard
deviation, and no machine-readable output — so a published figure could not be
compared against a later one, and nothing recorded WHERE it was measured.

The docs currently disagree with themselves (docs landing: ~6.1 ms p50 default
/ ~40.7 ms with the Python engine; performance page: ~43 ms for both). This
harness is how that gets settled by measurement rather than by picking a
number.

Every run writes a JSON artifact under bench-results/ capturing the full
environment, so a result is either reproducible or visibly not.

Usage:
    python3 scripts/bench/latency.py                     # default binary
    python3 scripts/bench/latency.py --runs 30 --warmup 5
    python3 scripts/bench/latency.py --binary /path/to/fendix --label ci-runner
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / "bin" / "fendix"
DEFAULT_FIXTURE = REPO_ROOT / "python" / "tests" / "fixtures" / "secrets_target"
ENGINE_CACHE = Path.home() / ".fendix" / "engine"
RESULTS_DIR = REPO_ROOT / "bench-results"


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def environment(label: str) -> dict:
    """Everything needed to decide whether a number is comparable.

    `load_average` and `noisy` are recorded deliberately: a figure captured on
    a loaded developer machine is real data about that machine and must never
    be published as a product characteristic.
    """
    sha = _run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"])
    dirty = bool(_run(["git", "-C", str(REPO_ROOT), "status", "--porcelain"]))
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = -1.0

    if platform.system() == "Darwin":
        cpu = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        mem_bytes = _run(["sysctl", "-n", "hw.memsize"])
        cores = _run(["sysctl", "-n", "hw.ncpu"])
    else:
        cpu = _run(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"])
        mem_bytes = _run(["sh", "-c", "awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo"])
        cores = _run(["nproc"])

    return {
        "label": label,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "commit_sha": sha,
        "worktree_dirty": dirty,
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "cpu": cpu,
        "cpu_cores": cores,
        "memory_bytes": mem_bytes,
        "python_version": platform.python_version(),
        "go_version": _run(["go", "version"]),
        "load_average": {"1m": load1, "5m": load5, "15m": load15},
        # A machine under load is not a benchmark environment. Recorded rather
        # than inferred later, so a stale artifact cannot be mistaken for a
        # clean capture.
        "noisy": load1 > 1.0,
    }


def dataset(fixture: Path) -> dict:
    files = [p for p in fixture.rglob("*") if p.is_file()]
    return {
        "path": str(fixture.relative_to(REPO_ROOT)),
        "file_count": len(files),
        "total_bytes": sum(p.stat().st_size for p in files),
    }


def measure(cmd: list[str], *, runs: int, warmup: int, cold: bool) -> dict:
    """Time `cmd`, discarding `warmup` runs. Cold mode wipes the engine cache
    before every invocation so each one pays full extraction cost."""
    samples: list[float] = []
    for i in range(warmup + runs):
        if cold:
            shutil.rmtree(ENGINE_CACHE, ignore_errors=True)
        started = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = (time.perf_counter() - started) * 1000.0
        if proc.returncode not in (0, 1):
            # 0 = clean, 1 = findings at/above --fail-on. Anything else means
            # the run did not do the work being measured.
            raise SystemExit(
                f"benchmark aborted: {' '.join(cmd)} exited {proc.returncode}\n{proc.stderr[:800]}"
            )
        if i >= warmup:
            samples.append(elapsed)

    ordered = sorted(samples)

    def pct(p: float) -> float:
        idx = min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1))))
        return round(ordered[idx], 3)

    return {
        "command": " ".join(cmd),
        "warmup_runs": warmup,
        "measured_runs": runs,
        "min_ms": round(ordered[0], 3),
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
        "max_ms": round(ordered[-1], 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "stdev_ms": round(statistics.stdev(ordered), 3) if len(ordered) > 1 else 0.0,
        "samples_ms": [round(s, 3) for s in samples],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    parser.add_argument("--runs", type=int, default=30, help="measured runs per configuration")
    parser.add_argument("--warmup", type=int, default=5, help="discarded runs per configuration")
    parser.add_argument("--label", default="unlabelled", help="where this was captured")
    args = parser.parse_args()

    binary, fixture = Path(args.binary), Path(args.fixture)
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary} — build it first (make build)")
    if not fixture.exists():
        raise SystemExit(f"fixture not found: {fixture}")
    if args.runs < 30 or args.warmup < 5:
        raise SystemExit("published numbers require >=30 measured runs and >=5 warmup runs")

    env = environment(args.label)
    version = _run([str(binary), "version"])

    # Local fixture only. Never a network target: a latency benchmark must not
    # be the thing that sends traffic to somebody else's system.
    base = [str(binary), "scan", "--code", str(fixture), "--format", "json"]
    configurations = {
        "default_cold": (base, True),
        "default_warm": (base, False),
        "python_engine_cold": (base + ["--python-engine"], True),
        "python_engine_warm": (base + ["--python-engine"], False),
    }

    results = {}
    for name, (cmd, cold) in configurations.items():
        print(f"measuring {name} ({args.warmup} warmup + {args.runs} runs)…", file=sys.stderr)
        results[name] = measure(cmd, runs=args.runs, warmup=args.warmup, cold=cold)

    artifact = {
        "schema": 1,
        "engine_version": version,
        "environment": env,
        "dataset": dataset(fixture),
        "configurations": results,
        "publishable": not env["noisy"] and not env["worktree_dirty"],
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = env["captured_at"].replace(":", "").replace("-", "")[:15]
    out = RESULTS_DIR / f"latency-{args.label}-{stamp}.json"
    out.write_text(json.dumps(artifact, indent=2) + "\n")

    print(f"\nwrote {out.relative_to(REPO_ROOT)}")
    for name, r in results.items():
        print(f"  {name:22s} p50={r['p50_ms']:9.3f}ms  p95={r['p95_ms']:9.3f}ms  sd={r['stdev_ms']:8.3f}")
    if not artifact["publishable"]:
        reasons = []
        if env["noisy"]:
            reasons.append(f"machine under load ({env['load_average']['1m']:.2f})")
        if env["worktree_dirty"]:
            reasons.append("dirty worktree")
        print(f"\nNOT PUBLISHABLE: {', '.join(reasons)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
