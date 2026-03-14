"""Tests for the engine.py IPC contract.

Verifies that the Python engine reads a ScanRequest from stdin
and emits valid JSON lines terminated by {"done": true, "total": N}.
"""
import json
import subprocess
import sys
from pathlib import Path

ENGINE_PATH = Path(__file__).parent.parent / "engine.py"


def test_engine_emits_done_on_empty_request() -> None:
    """Engine should emit done terminator even with no checks."""
    request = json.dumps({"mode": "whitebox", "checks": [], "verbose": False})
    result = subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input=request,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    lines = result.stdout.strip().split("\n")
    last = json.loads(lines[-1])
    assert last["done"] is True
    assert last["total"] == 0


def test_engine_outputs_valid_json_lines() -> None:
    """Every line of engine output must be valid JSON."""
    request = json.dumps(
        {"mode": "whitebox", "checks": ["secrets"], "code_path": "/nonexistent"}
    )
    result = subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input=request,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    for line in result.stdout.strip().split("\n"):
        json.loads(line)  # raises on invalid JSON
