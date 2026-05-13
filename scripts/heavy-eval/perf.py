"""Performance profiler for the heavy-eval harness.

Wraps each fendix scan with /usr/bin/time -l (macOS) or
GNU `time -v` (Linux) and parses peak RSS + user/sys CPU out of
the stderr stream. Runs each target N times and reports p50/p95/p99
wall-clock + min/max + peak-RSS + cold-vs-warm delta.

Cold = clear ~/.fendix/cache before scan. Warm = preserve cache.
Both are reported.

Output shape:
    {
        "target_id": "...",
        "n": 5,
        "wall_clock_ms": {
            "cold_p50": ..., "cold_p95": ..., "cold_p99": ...,
            "warm_p50": ..., "warm_p95": ..., "warm_p99": ...,
            "cold_min": ..., "cold_max": ...,
            "warm_min": ..., "warm_max": ...,
            "samples_cold_ms": [...],
            "samples_warm_ms": [...]
        },
        "peak_rss_kb": {
            "cold_p50": ..., "warm_p50": ...,
            "cold_max": ..., "warm_max": ...
        },
        "code_size_bytes": ...,
        "loc_python": ..., "loc_node": ..., "loc_go": ...,
        "throughput_loc_per_sec_warm": ...,
        "findings_count_warm": ...,
    }
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any

HOME_CACHE = Path.home() / ".fendix" / "cache"


# ─── time wrapper ────────────────────────────────────────────────────


def _time_cmd() -> list[str]:
    """Return the prefix to wrap a command for time/RSS capture."""
    if platform.system() == "Darwin":
        return ["/usr/bin/time", "-l"]
    # Linux: GNU time -v
    return ["/usr/bin/time", "-v"]


def _parse_time_stderr(stderr: str) -> dict[str, float]:
    """Pull wall-clock + peak RSS out of /usr/bin/time output.

    Returns {"wall_sec": float, "peak_rss_kb": float}. Missing fields
    are returned as 0.0 — the caller can fall back to its own
    wall-clock measurement.
    """
    wall = 0.0
    rss_kb = 0.0
    # macOS /usr/bin/time -l format:
    #         0.42 real         0.30 user         0.10 sys
    #   123456789  maximum resident set size
    if platform.system() == "Darwin":
        m = re.search(r"^\s*([\d.]+)\s+real\s", stderr, re.MULTILINE)
        if m:
            wall = float(m.group(1))
        m = re.search(r"^\s*(\d+)\s+maximum resident set size", stderr, re.MULTILINE)
        if m:
            rss_kb = float(m.group(1)) / 1024.0  # bytes -> KB on darwin
    else:
        # GNU time -v
        m = re.search(r"Elapsed \(wall clock\) time.*?:\s*(.+)", stderr)
        if m:
            wall = _parse_gnu_elapsed(m.group(1))
        m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
        if m:
            rss_kb = float(m.group(1))
    return {"wall_sec": wall, "peak_rss_kb": rss_kb}


def _parse_gnu_elapsed(s: str) -> float:
    s = s.strip()
    parts = s.split(":")
    parts = [float(p) for p in parts]
    if len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    return parts[0] if parts else 0.0


# ─── cache control ───────────────────────────────────────────────────


def _clear_fendix_cache() -> None:
    if HOME_CACHE.exists():
        shutil.rmtree(HOME_CACHE, ignore_errors=True)


# ─── LOC measurement ─────────────────────────────────────────────────


def measure_code_size(path: Path) -> dict[str, int]:
    out = {"size_bytes": 0, "loc_python": 0, "loc_node": 0, "loc_go": 0}
    if not path.exists():
        return out
    if path.is_file():
        out["size_bytes"] = path.stat().st_size
        return out
    for p in path.rglob("*"):
        try:
            if not p.is_file():
                continue
            sz = p.stat().st_size
            out["size_bytes"] += sz
            suffix = p.suffix.lower()
            if suffix in (".py",):
                out["loc_python"] += _quick_line_count(p)
            elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                out["loc_node"] += _quick_line_count(p)
            elif suffix in (".go",):
                out["loc_go"] += _quick_line_count(p)
        except OSError:
            continue
    return out


def _quick_line_count(p: Path) -> int:
    try:
        with p.open("rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


# ─── percentiles ─────────────────────────────────────────────────────


def _pct(samples: list[float], p: float) -> float | None:
    if not samples:
        return None
    samples_sorted = sorted(samples)
    if len(samples_sorted) == 1:
        return samples_sorted[0]
    k = (len(samples_sorted) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(samples_sorted) - 1)
    if f == c:
        return samples_sorted[f]
    return samples_sorted[f] + (k - f) * (samples_sorted[c] - samples_sorted[f])


# ─── public entry point ─────────────────────────────────────────────


def profile_scan(
    *,
    fendix_bin: str,
    scan_args: list[str],
    code_path: Path | None,
    repeats: int = 5,
    label: str = "scan",
    log_dir: Path | None = None,
) -> dict[str, Any]:
    """Run `fendix scan <scan_args>` `repeats` times each in cold + warm
    mode and return aggregated wall-clock / RSS / throughput stats.

    `code_path` is only used for size+LOC measurement; the actual scan
    target comes from scan_args.
    """
    cold_wall: list[float] = []
    warm_wall: list[float] = []
    cold_rss: list[float] = []
    warm_rss: list[float] = []
    last_warm_findings = 0
    last_warm_stdout: str | None = None
    last_warm_stderr: str | None = None

    time_prefix = _time_cmd()
    base_cmd = [fendix_bin, "scan"] + scan_args + ["--format", "json"]
    full_cmd = time_prefix + base_cmd

    for i in range(repeats):
        # cold
        _clear_fendix_cache()
        t0 = time.monotonic()
        proc = subprocess.run(full_cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent.parent))
        dt = time.monotonic() - t0
        parsed = _parse_time_stderr(proc.stderr)
        cold_wall.append((parsed["wall_sec"] or dt) * 1000)
        cold_rss.append(parsed["peak_rss_kb"])
        if log_dir is not None and i == 0:
            (log_dir / f"{label}.cold.first.stderr").write_text(proc.stderr[:8000])
            (log_dir / f"{label}.cold.first.stdout.head").write_text(proc.stdout[:8000])

        # warm (right after cold so the FS cache is hot)
        t0 = time.monotonic()
        proc = subprocess.run(full_cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent.parent))
        dt = time.monotonic() - t0
        parsed = _parse_time_stderr(proc.stderr)
        warm_wall.append((parsed["wall_sec"] or dt) * 1000)
        warm_rss.append(parsed["peak_rss_kb"])
        last_warm_stdout = proc.stdout
        last_warm_stderr = proc.stderr
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
            last_warm_findings = len(payload.get("findings", []))
        except json.JSONDecodeError:
            last_warm_findings = 0

    size_info = (
        measure_code_size(code_path) if code_path is not None
        else {"size_bytes": 0, "loc_python": 0, "loc_node": 0, "loc_go": 0}
    )
    total_loc = size_info["loc_python"] + size_info["loc_node"] + size_info["loc_go"]

    warm_p50_ms = _pct(warm_wall, 50) or 0
    throughput_loc_per_sec = (total_loc / (warm_p50_ms / 1000.0)) if warm_p50_ms else None

    if log_dir is not None and last_warm_stdout is not None:
        (log_dir / f"{label}.warm.last.stdout").write_text(last_warm_stdout[:200000])
        (log_dir / f"{label}.warm.last.stderr").write_text((last_warm_stderr or "")[:8000])

    return {
        "label": label,
        "repeats": repeats,
        "wall_clock_ms": {
            "cold_p50": _pct(cold_wall, 50),
            "cold_p95": _pct(cold_wall, 95),
            "cold_p99": _pct(cold_wall, 99),
            "cold_min": min(cold_wall) if cold_wall else None,
            "cold_max": max(cold_wall) if cold_wall else None,
            "warm_p50": _pct(warm_wall, 50),
            "warm_p95": _pct(warm_wall, 95),
            "warm_p99": _pct(warm_wall, 99),
            "warm_min": min(warm_wall) if warm_wall else None,
            "warm_max": max(warm_wall) if warm_wall else None,
            "cold_mean": statistics.fmean(cold_wall) if cold_wall else None,
            "warm_mean": statistics.fmean(warm_wall) if warm_wall else None,
            "samples_cold_ms": cold_wall,
            "samples_warm_ms": warm_wall,
        },
        "peak_rss_kb": {
            "cold_p50": _pct(cold_rss, 50),
            "cold_max": max(cold_rss) if cold_rss else None,
            "warm_p50": _pct(warm_rss, 50),
            "warm_max": max(warm_rss) if warm_rss else None,
        },
        "code": {
            **size_info,
            "total_loc": total_loc,
        },
        "throughput_loc_per_sec_warm": throughput_loc_per_sec,
        "findings_count_warm_last": last_warm_findings,
    }
