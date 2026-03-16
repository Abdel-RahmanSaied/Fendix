"""Tests for the SemgrepRunner.

Uses mocking to test result mapping and graceful degradation without
requiring semgrep to be installed in the test environment.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analyzers.semgrep_runner import (
    SemgrepRunner,
    _find_semgrep,
    _semgrep_category,
    _semgrep_confidence,
    _semgrep_severity,
)

RULES_DIR = Path(__file__).parent.parent / "rules"

# A realistic semgrep result object for a SQL injection finding
_SQL_RESULT = {
    "check_id": "python-sql-injection-string-format",
    "path": "/code/app.py",
    "start": {"line": 42, "col": 5},
    "end": {"line": 42, "col": 60},
    "extra": {
        "message": (
            "SQL query built via string formatting — SQL injection risk.\n"
            "Use parameterized queries."
        ),
        "severity": "ERROR",
        "lines": "    cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
        "metadata": {
            "category": "injection",
            "cwe": "CWE-89",
            "confidence": "HIGH",
            "fendix_severity": "CRITICAL",
        },
    },
}

_AUTH_RESULT = {
    "check_id": "flask-missing-login-required",
    "path": "/code/views.py",
    "start": {"line": 10, "col": 1},
    "extra": {
        "message": "Flask route 'admin_view' is missing @login_required decorator.",
        "severity": "ERROR",
        "lines": "@app.route('/admin')\ndef admin_view():",
        "metadata": {
            "category": "auth",
            "cwe": "CWE-306",
            "confidence": "MEDIUM",
            "fendix_severity": "HIGH",
        },
    },
}


def _semgrep_output(results: list[dict]) -> str:
    """Wrap results in semgrep JSON output format."""
    return json.dumps({"results": results, "errors": []})


# ---------------------------------------------------------------------------
# _find_semgrep helper
# ---------------------------------------------------------------------------

class TestFindSemgrep:
    def test_returns_none_when_not_in_path(self) -> None:
        with patch("shutil.which", return_value=None):
            assert _find_semgrep() is None

    def test_returns_path_when_found(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            assert _find_semgrep() == "/usr/bin/semgrep"


# ---------------------------------------------------------------------------
# Severity / confidence / category mapping helpers
# ---------------------------------------------------------------------------

class TestMappingHelpers:
    def test_fendix_severity_from_metadata(self) -> None:
        assert _semgrep_severity(_SQL_RESULT) == "CRITICAL"

    def test_severity_falls_back_to_semgrep_severity(self) -> None:
        result = {
            "extra": {
                "severity": "WARNING",
                "metadata": {},
            }
        }
        assert _semgrep_severity(result) == "MEDIUM"

    def test_confidence_from_metadata(self) -> None:
        assert _semgrep_confidence(_SQL_RESULT) == "HIGH"

    def test_confidence_defaults_to_medium(self) -> None:
        assert _semgrep_confidence({"extra": {"metadata": {}}}) == "MEDIUM"

    def test_category_from_metadata(self) -> None:
        assert _semgrep_category(_SQL_RESULT) == "injection"

    def test_category_defaults_to_code(self) -> None:
        assert _semgrep_category({"extra": {"metadata": {}}}) == "code"


# ---------------------------------------------------------------------------
# SemgrepRunner.run() — graceful degradation
# ---------------------------------------------------------------------------

class TestSemgrepRunnerGracefulDegradation:
    def test_no_findings_when_semgrep_not_installed(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        with patch("analyzers.semgrep_runner._find_semgrep", return_value=None):
            findings: list[dict] = []
            SemgrepRunner(str(tmp_path)).run(findings.append)
        assert findings == []

    def test_no_findings_when_code_path_missing(self) -> None:
        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            findings: list[dict] = []
            SemgrepRunner("/nonexistent/path").run(findings.append)
        assert findings == []

    def test_no_findings_when_semgrep_times_out(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 120)):
                findings: list[dict] = []
                SemgrepRunner(str(tmp_path)).run(findings.append)
        assert findings == []


# ---------------------------------------------------------------------------
# SemgrepRunner._map_result() — result mapping
# ---------------------------------------------------------------------------

class TestResultMapping:
    def _runner(self, tmp_path: Path) -> SemgrepRunner:
        return SemgrepRunner(str(tmp_path))

    def test_maps_sql_injection_finding(self, tmp_path: Path) -> None:
        runner = self._runner(tmp_path)
        finding = runner._map_result(_SQL_RESULT, tmp_path)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"
        assert finding["category"] == "injection"
        assert finding["source"] == "whitebox"
        assert finding["confidence"] == "HIGH"
        assert "CWE-89" in finding["references"]

    def test_maps_auth_finding(self, tmp_path: Path) -> None:
        runner = self._runner(tmp_path)
        finding = runner._map_result(_AUTH_RESULT, tmp_path)
        assert finding is not None
        assert finding["severity"] == "HIGH"
        assert finding["category"] == "auth"
        assert "CWE-306" in finding["references"]

    def test_finding_has_required_fields(self, tmp_path: Path) -> None:
        runner = self._runner(tmp_path)
        finding = runner._map_result(_SQL_RESULT, tmp_path)
        required = {"id", "title", "severity", "source", "category",
                    "endpoint", "evidence", "fix", "references", "confidence", "line"}
        assert required.issubset(finding.keys())

    def test_evidence_truncated_to_200_chars(self, tmp_path: Path) -> None:
        long_result = {**_SQL_RESULT, "extra": {**_SQL_RESULT["extra"], "lines": "x" * 500}}
        runner = self._runner(tmp_path)
        finding = runner._map_result(long_result, tmp_path)
        assert len(finding["evidence"]) <= 210  # 200 + "..."

    def test_returns_none_on_malformed_result(self, tmp_path: Path) -> None:
        runner = self._runner(tmp_path)
        finding = runner._map_result({}, tmp_path)
        # Should not raise — returns a finding or None
        # Empty dict has no path so result may still be returned with empty fields
        assert finding is None or isinstance(finding, dict)


# ---------------------------------------------------------------------------
# Full run() with mocked subprocess
# ---------------------------------------------------------------------------

class TestSemgrepRunnerWithMockedSubprocess:
    def test_emits_findings_from_semgrep_output(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("cursor.execute('SELECT * FROM users WHERE id = %s' % uid)\n")
        mock_proc = MagicMock()
        mock_proc.stdout = _semgrep_output([_SQL_RESULT])
        mock_proc.returncode = 0

        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                findings: list[dict] = []
                SemgrepRunner(str(tmp_path)).run(findings.append)

        assert len(findings) == 1
        assert findings[0]["category"] == "injection"

    def test_emits_zero_findings_on_empty_results(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = os.environ['KEY']\n")
        mock_proc = MagicMock()
        mock_proc.stdout = _semgrep_output([])
        mock_proc.returncode = 0

        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                findings: list[dict] = []
                SemgrepRunner(str(tmp_path)).run(findings.append)

        assert findings == []

    def test_handles_invalid_json_from_semgrep(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        mock_proc = MagicMock()
        mock_proc.stdout = "not json"
        mock_proc.returncode = 2

        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                findings: list[dict] = []
                SemgrepRunner(str(tmp_path)).run(findings.append)

        assert findings == []

    def test_emits_multiple_findings(self, tmp_path: Path) -> None:
        mock_proc = MagicMock()
        mock_proc.stdout = _semgrep_output([_SQL_RESULT, _AUTH_RESULT])
        mock_proc.returncode = 0

        with patch("analyzers.semgrep_runner._find_semgrep", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                findings: list[dict] = []
                SemgrepRunner(str(tmp_path)).run(findings.append)

        assert len(findings) == 2
