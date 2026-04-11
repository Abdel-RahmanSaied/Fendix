"""Self-audit test — run Fendix against its own codebase.

Verifies that:
1. The engine runs successfully against its own source code
2. All findings are from test fixtures (intentional test data), not production code
3. No real secrets are hardcoded in production analyzers or engine code
"""
import json
import subprocess
import sys

import pytest


def test_self_audit_runs_successfully() -> None:
    """Engine should complete a self-scan without errors."""
    request = json.dumps({
        "mode": "whitebox",
        "code_path": "python/",
        "checks": ["secrets", "ast"],
        "verbose": False,
    })
    result = subprocess.run(
        [sys.executable, "python/engine.py"],
        input=request,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Engine exited with code {result.returncode}: {result.stderr}"

    # Parse output — last line should be done message
    lines = result.stdout.strip().split("\n")
    assert len(lines) >= 1
    done = json.loads(lines[-1])
    assert done.get("done") is True


def test_self_audit_no_production_secrets() -> None:
    """No findings should come from production code (analyzers/, engine.py).

    All secrets findings should be from tests/ or tests/fixtures/ only.
    """
    request = json.dumps({
        "mode": "whitebox",
        "code_path": "python/",
        "checks": ["secrets"],
        "verbose": False,
    })
    result = subprocess.run(
        [sys.executable, "python/engine.py"],
        input=request,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0

    lines = result.stdout.strip().split("\n")
    findings = []
    for line in lines:
        data = json.loads(line)
        if data.get("done"):
            continue
        findings.append(data)

    # All secrets findings should be from test fixtures, not production code
    production_findings = [
        f for f in findings
        if f.get("category") == "secrets"
        and not f.get("endpoint", "").startswith("tests/")
    ]
    assert production_findings == [], (
        f"Found {len(production_findings)} secret(s) in production code: "
        + ", ".join(f["endpoint"] for f in production_findings)
    )
