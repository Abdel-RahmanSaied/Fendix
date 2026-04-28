"""Tests for the SecretsAnalyzer.

Verifies all 7 pattern types are detected and clean files produce no findings.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Callable

import pytest

from analyzers.secrets import SecretsAnalyzer, _truncate_secret, _is_minified

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "secrets_target"


def _collect(path: str) -> list[dict]:
    """Run SecretsAnalyzer and return all findings."""
    findings: list[dict] = []
    SecretsAnalyzer(path).run(findings.append)
    return findings


def _categories(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


# ---------------------------------------------------------------------------
# Pattern type tests
# ---------------------------------------------------------------------------

class TestPatternDetection:
    def test_aws_access_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-AWS_ACCESS_KEY" in ids

    def test_aws_secret_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-AWS_SECRET_KEY" in ids

    def test_private_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-PRIVATE_KEY" in ids

    def test_generic_api_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-GENERIC_API_KEY" in ids

    def test_hardcoded_password_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-HARDCODED_PASSWORD" in ids

    def test_jwt_token_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-JWT_TOKEN" in ids

    def test_db_connection_string_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        ids = _categories(findings)
        assert "SEC-DB_CONNECTION_STRING" in ids

    # Provider-specific patterns added in TASK-085 for v0.3 coverage parity.

    def test_github_token_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-GITHUB_TOKEN" in _categories(findings)

    def test_stripe_live_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-STRIPE_LIVE_KEY" in _categories(findings)

    def test_slack_token_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-SLACK_TOKEN" in _categories(findings)

    def test_google_api_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-GOOGLE_API_KEY" in _categories(findings)

    def test_anthropic_api_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-ANTHROPIC_API_KEY" in _categories(findings)

    def test_openai_api_key_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-OPENAI_API_KEY" in _categories(findings)

    def test_npm_token_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-NPM_TOKEN" in _categories(findings)

    def test_gcp_service_account_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-GCP_SERVICE_ACCOUNT" in _categories(findings)

    def test_env_unquoted_secret_detected(self) -> None:
        """Regression for TASK-085: .env files use unquoted KEY=value, which the
        generic HARDCODED_PASSWORD regex (requires quotes) misses entirely.
        Also covers the related Path.suffix bug — files literally named .env
        have suffix='' and were previously skipped by the file-extension walk."""
        findings = _collect(str(FIXTURES_DIR))
        env_findings = [
            f for f in findings
            if f["id"] == "SEC-ENV_SECRET" and ".env" in f["endpoint"]
        ]
        assert env_findings, (
            f"expected SEC-ENV_SECRET findings on .env file, got "
            f"ids={_categories(findings)}"
        )

    def test_anti_overlap_openai_does_not_match_anthropic(self) -> None:
        """OpenAI's sk- prefix is broad; ensure it doesn't fire on Anthropic keys."""
        findings = _collect(str(FIXTURES_DIR))
        # Anthropic value in fixture is sk-ant-api03-...; the OpenAI regex must
        # not also match it (would be a duplicate finding on the same line).
        ant_endpoint_lines = [
            f["endpoint"] for f in findings if f["id"] == "SEC-ANTHROPIC_API_KEY"
        ]
        openai_endpoints = {
            f["endpoint"] for f in findings if f["id"] == "SEC-OPENAI_API_KEY"
        }
        for ep in ant_endpoint_lines:
            assert ep not in openai_endpoints, (
                f"OpenAI regex incorrectly matched an Anthropic key at {ep}"
            )


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------

class TestFindingStructure:
    def test_findings_have_required_fields(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        required = {"id", "title", "severity", "source", "category", "endpoint", "evidence", "fix", "references", "confidence", "line"}
        for f in findings:
            missing = required - f.keys()
            assert not missing, f"Finding {f.get('id')} missing fields: {missing}"

    def test_source_is_whitebox(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            assert f["source"] == "whitebox"

    def test_category_is_secrets(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            assert f["category"] == "secrets"

    def test_severity_values_valid(self) -> None:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            assert f["severity"] in valid

    def test_evidence_is_truncated(self) -> None:
        """Evidence must not contain the full raw secret value."""
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            # Evidence lines should not be excessively long
            assert len(f["evidence"]) <= 150, f"Evidence too long in {f['id']}"

    def test_line_field_has_filename_and_lineno(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            assert ":" in f["line"], f"line field missing colon: {f['line']}"
            parts = f["line"].rsplit(":", 1)
            assert parts[1].isdigit(), f"line number not numeric: {f['line']}"


# ---------------------------------------------------------------------------
# Clean file test
# ---------------------------------------------------------------------------

class TestCleanFile:
    def test_clean_file_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            clean = Path(FIXTURES_DIR) / "clean.py"
            import shutil
            shutil.copy(clean, Path(tmpdir) / "clean.py")
            findings = _collect(tmpdir)
            assert findings == [], f"Expected no findings but got: {findings}"


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_nonexistent_path_produces_no_findings(self) -> None:
        findings = _collect("/nonexistent/path/that/does/not/exist")
        assert findings == []

    def test_empty_directory_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = _collect(tmpdir)
            assert findings == []

    def test_skips_git_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            secret_file = git_dir / "config"
            secret_file.write_text('password = "hardcoded_secret_12345"')
            findings = _collect(tmpdir)
            assert findings == []

    def test_skips_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";')
            findings = _collect(tmpdir)
            assert findings == []

    def test_large_file_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            big = Path(tmpdir) / "big.py"
            # Write a >1MB file with a secret buried in it
            big.write_bytes(b"x = 1\n" * 200_000 + b'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            findings = _collect(tmpdir)
            assert findings == []


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_truncate_secret_short_string(self) -> None:
        result = _truncate_secret("abc")
        assert "..." in result or result == "***"

    def test_truncate_secret_long_string(self) -> None:
        long_secret = "A" * 40
        result = _truncate_secret(long_secret)
        assert result.endswith("...")
        assert len(result) <= 25

    def test_is_minified_long_js_line(self) -> None:
        path = Path("bundle.min.js")
        assert _is_minified(path, "x" * 600)

    def test_is_minified_normal_js_line(self) -> None:
        path = Path("app.js")
        assert not _is_minified(path, "const x = 1;")

    def test_is_minified_python_file(self) -> None:
        path = Path("script.py")
        assert not _is_minified(path, "x" * 600)
