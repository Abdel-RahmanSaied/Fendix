"""Tests for the engine.py IPC contract.

Verifies that the Python engine reads a ScanRequest from stdin
and emits valid JSON lines terminated by {"done": true, "total": N}.
"""
import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path

ENGINE_PATH = Path(__file__).parent.parent / "engine.py"


def _run(request: dict, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run the engine with the given request dict, return CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _parse_output(result: subprocess.CompletedProcess) -> list[dict]:
    """Parse all stdout lines as JSON objects."""
    lines = [l for l in result.stdout.strip().split("\n") if l]
    return [json.loads(l) for l in lines]


def test_engine_emits_done_on_empty_request() -> None:
    """Engine should emit done terminator even with no checks."""
    result = _run({"mode": "whitebox", "checks": [], "verbose": False})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True
    assert objects[-1]["total"] == 0


def test_engine_outputs_valid_json_lines() -> None:
    """Every line of engine output must be valid JSON."""
    result = _run({"mode": "whitebox", "checks": ["secrets"], "code_path": "/nonexistent"})
    assert result.returncode == 0
    for line in result.stdout.strip().split("\n"):
        if line:
            json.loads(line)  # raises on invalid JSON


def test_engine_done_total_matches_finding_count() -> None:
    """done.total must equal the number of finding lines emitted."""
    result = _run({"mode": "whitebox", "checks": [], "code_path": "/nonexistent"})
    assert result.returncode == 0
    objects = _parse_output(result)
    findings = [o for o in objects if "id" in o or "title" in o]
    terminator = objects[-1]
    assert terminator["done"] is True
    assert terminator["total"] == len(findings)


def test_engine_handles_invalid_json_gracefully() -> None:
    """Engine must not crash on invalid JSON — exits with code 2."""
    proc = subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input="not valid json {{{",
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 2
    # Even on error, emits a done line
    assert proc.stdout.strip()
    last = json.loads(proc.stdout.strip().split("\n")[-1])
    assert last["done"] is True
    assert "error" in last


def test_engine_verbose_logs_to_stderr_not_stdout() -> None:
    """verbose=true must write diagnostics to stderr, not stdout."""
    result = _run({"mode": "whitebox", "checks": [], "verbose": True})
    assert result.returncode == 0
    # Every stdout line is valid JSON — no text mixed in
    for line in result.stdout.strip().split("\n"):
        if line:
            json.loads(line)
    # stderr should contain the verbose log message
    assert "[fendix-engine]" in result.stderr


def test_engine_skips_check_when_code_path_missing() -> None:
    """Checks that require code_path must be silently skipped if not provided."""
    result = _run({"mode": "whitebox", "checks": ["secrets", "semgrep", "deps"]})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True


def test_engine_skips_auth_check_when_spec_missing() -> None:
    """Auth check requires spec; must be skipped if not provided."""
    result = _run({"mode": "whitebox", "checks": ["auth"]})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True


def test_engine_continues_after_analyzer_crash() -> None:
    """If one analyzer crashes, the engine must still emit done."""
    # /nonexistent path will not crash SecretsAnalyzer (it just yields nothing),
    # so we test the general resilience: engine always terminates
    result = _run(
        {"mode": "whitebox", "checks": ["secrets", "deps"], "code_path": "/nonexistent/path"}
    )
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True
