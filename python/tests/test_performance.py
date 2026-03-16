"""Performance tests for the Python engine.

TASK-037: Engine startup and scan time benchmarks.
Requirement: engine startup < 2 seconds (measured end-to-end).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

ENGINE_PATH = Path(__file__).parent.parent / "engine.py"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Absolute limit: engine must respond in under 2 seconds for empty request
STARTUP_LIMIT_SECONDS = 2.0

# Limit for scanning the test fixtures directory (small codebase)
FIXTURE_SCAN_LIMIT_SECONDS = 5.0


def _run_timed(request: dict, timeout: int = 30) -> tuple[float, subprocess.CompletedProcess]:
    """Run the engine and return (elapsed_seconds, result)."""
    t0 = time.perf_counter()
    result = subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - t0
    return elapsed, result


class TestEngineStartupTime:
    def test_startup_under_2_seconds_empty_request(self) -> None:
        """Engine must start up and emit done in under 2 seconds for an empty request."""
        # Run 3 times and take the median to avoid cold-start skew
        times = []
        for _ in range(3):
            elapsed, result = _run_timed({"mode": "whitebox", "checks": []})
            assert result.returncode == 0
            times.append(elapsed)
        times.sort()
        median = times[1]
        assert median < STARTUP_LIMIT_SECONDS, (
            f"Engine startup median {median:.2f}s exceeds {STARTUP_LIMIT_SECONDS}s limit. "
            f"All times: {[f'{t:.2f}' for t in times]}"
        )

    def test_startup_with_nonexistent_code_path_under_2_seconds(self) -> None:
        """Even with a failing code_path, engine must complete in under 2s."""
        elapsed, result = _run_timed({
            "mode": "whitebox",
            "checks": ["secrets", "deps"],
            "code_path": "/nonexistent",
        })
        assert result.returncode == 0
        assert elapsed < STARTUP_LIMIT_SECONDS, (
            f"Engine took {elapsed:.2f}s with nonexistent path"
        )


class TestFixtureScanTime:
    def test_secrets_scan_fixture_dir_under_limit(self) -> None:
        """Scanning the test fixtures directory for secrets must complete in time."""
        elapsed, result = _run_timed({
            "mode": "whitebox",
            "checks": ["secrets"],
            "code_path": str(FIXTURES_DIR),
        }, timeout=30)
        assert result.returncode == 0
        assert elapsed < FIXTURE_SCAN_LIMIT_SECONDS, (
            f"Secrets scan of fixtures took {elapsed:.2f}s, limit {FIXTURE_SCAN_LIMIT_SECONDS}s"
        )

    def test_ast_scan_fixture_dir_under_limit(self) -> None:
        """AST scan of test fixtures must complete within the time limit."""
        elapsed, result = _run_timed({
            "mode": "whitebox",
            "checks": ["injection"],
            "code_path": str(FIXTURES_DIR),
        }, timeout=30)
        assert result.returncode == 0
        assert elapsed < FIXTURE_SCAN_LIMIT_SECONDS, (
            f"AST scan took {elapsed:.2f}s, limit {FIXTURE_SCAN_LIMIT_SECONDS}s"
        )

    def test_combined_scan_fixture_dir_under_10_seconds(self) -> None:
        """Running all local checks on fixtures must finish in under 10 seconds."""
        elapsed, result = _run_timed({
            "mode": "whitebox",
            "checks": ["secrets", "injection", "deps"],
            "code_path": str(FIXTURES_DIR),
        }, timeout=30)
        assert result.returncode == 0
        assert elapsed < 10.0, (
            f"Combined scan took {elapsed:.2f}s, limit 10.0s"
        )


class TestEngineOutputDuringPerf:
    def test_startup_emits_valid_done_terminator(self) -> None:
        """The done terminator must always be valid JSON."""
        _, result = _run_timed({"mode": "whitebox", "checks": []})
        lines = [l for l in result.stdout.strip().split("\n") if l]
        last = json.loads(lines[-1])
        assert last["done"] is True
        assert isinstance(last["total"], int)

    def test_no_stdout_written_before_any_findings(self) -> None:
        """Startup diagnostics must not appear on stdout."""
        _, result = _run_timed({"mode": "whitebox", "checks": [], "verbose": True})
        # All stdout lines must be valid JSON
        for line in result.stdout.strip().split("\n"):
            if line:
                json.loads(line)  # raises if not JSON
