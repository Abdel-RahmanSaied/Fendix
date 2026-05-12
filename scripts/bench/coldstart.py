#!/usr/bin/env python3
"""Cold-start benchmark for `fendix scan` (TASK-118).

Wipes ~/.fendix/engine before every run so each invocation pays the
full cold-start cost (process spawn + argv parse + scan + JSON render
+ exit). Reports min / p50 / p95 / max / mean over N=30 runs against
the bundled secrets-target fixture.

Numbers in docs/benchmarks.md come from this script.

Usage:
    python3 scripts/bench/coldstart.py            # default: ./bin/fendix
    python3 scripts/bench/coldstart.py /path/to/fendix
    FIXTURE=/some/path python3 scripts/bench/coldstart.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / "bin" / "fendix"
DEFAULT_FIXTURE = REPO_ROOT / "python" / "tests" / "fixtures" / "secrets_target"
ENGINE_CACHE = Path.home() / ".fendix" / "engine"
RUNS = 30


def measure(label: str, args: list[str]) -> None:
    """Run args RUNS times and print percentile summary."""
    times: list[float] = []
    for _ in range(RUNS):
        if ENGINE_CACHE.exists():
            shutil.rmtree(ENGINE_CACHE, ignore_errors=True)
        t0 = time.monotonic()
        subprocess.run(args, capture_output=True)
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    n = len(times)
    print(
        f"[{label}] N={n}  "
        f"min={times[0]:.1f}  "
        f"p50={times[n // 2]:.1f}  "
        f"p95={times[int(n * 0.95)]:.1f}  "
        f"max={times[-1]:.1f}  "
        f"mean={sum(times) / n:.1f}  (ms)"
    )


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BINARY
    fixture = Path(os.environ.get("FIXTURE", DEFAULT_FIXTURE))
    if not binary.exists():
        print(f"binary not found: {binary} — run `make build`", file=sys.stderr)
        return 1
    if not fixture.exists():
        print(f"fixture not found: {fixture}", file=sys.stderr)
        return 1
    print(f"binary:  {binary}")
    print(f"fixture: {fixture}")
    print(f"runs:    {RUNS}")
    print()
    measure(
        "default (no Python whitebox)",
        [str(binary), "scan", "--code", str(fixture), "--format", "json"],
    )
    measure(
        "--python-engine (opt-in)",
        [str(binary), "scan", "--code", str(fixture), "--python-engine", "--format", "json"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
