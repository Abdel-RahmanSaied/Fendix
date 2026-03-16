"""Tests for the OpenAPI spec parser.

Tests OpenAPI 3.x and Swagger 2.0 specs for auth-related security issues.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from analyzers.spec_parser import SpecParser

SPECS_DIR = Path(__file__).parent / "fixtures" / "specs"


def _check(spec_file: str) -> list[dict]:
    """Run check_auth on a fixture spec and return all findings."""
    findings: list[dict] = []
    SpecParser(str(SPECS_DIR / spec_file)).check_auth(findings.append)
    return findings


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


# ---------------------------------------------------------------------------
# OpenAPI 3.x tests
# ---------------------------------------------------------------------------

class TestOpenAPI3:
    def test_secure_spec_no_global_auth_finding(self) -> None:
        """A spec with global security should not flag SEC-SPEC-NO-GLOBAL-AUTH."""
        findings = _check("openapi3_secure.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-NO-GLOBAL-AUTH" not in ids

    def test_secure_spec_flags_open_health_endpoint(self) -> None:
        """security:[] on /health should be flagged as open endpoint."""
        findings = _check("openapi3_secure.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-OPEN-ENDPOINT" in ids

    def test_no_global_auth_flagged(self) -> None:
        """Spec with security schemes but no global security → SEC-SPEC-NO-GLOBAL-AUTH."""
        findings = _check("openapi3_no_global_auth.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-NO-GLOBAL-AUTH" in ids

    def test_endpoints_without_auth_flagged_when_no_global(self) -> None:
        """Endpoints with no security field + no global security → SEC-SPEC-NO-AUTH."""
        findings = _check("openapi3_no_global_auth.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-NO-AUTH" in ids

    def test_http_server_url_flagged(self) -> None:
        """Server URL starting with http:// → SEC-SPEC-HTTP-SERVER."""
        findings = _check("openapi3_http_server.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-HTTP-SERVER" in ids

    def test_basic_auth_flagged(self) -> None:
        """HTTP Basic auth scheme → SEC-SPEC-BASIC-AUTH."""
        findings = _check("openapi3_basic_auth.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-BASIC-AUTH" in ids

    def test_https_server_not_flagged(self) -> None:
        """HTTPS server URL should not produce an HTTP-server finding."""
        findings = _check("openapi3_secure.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-HTTP-SERVER" not in ids


# ---------------------------------------------------------------------------
# Swagger 2.0 tests
# ---------------------------------------------------------------------------

class TestSwagger2:
    def test_http_scheme_flagged(self) -> None:
        """Swagger 2.0 with 'http' in schemes → SEC-SPEC-HTTP-SCHEME."""
        findings = _check("swagger2_http_scheme.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-HTTP-SCHEME" in ids

    def test_basic_auth_swagger2_flagged(self) -> None:
        """Swagger 2.0 with type:basic security → SEC-SPEC-BASIC-AUTH."""
        findings = _check("swagger2_basic_auth.yaml")
        ids = _ids(findings)
        assert "SEC-SPEC-BASIC-AUTH" in ids


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------

class TestFindingStructure:
    def test_required_fields_present(self) -> None:
        required = {"id", "title", "severity", "source", "category", "endpoint",
                    "evidence", "fix", "references", "confidence", "line"}
        findings = _check("openapi3_no_global_auth.yaml")
        for f in findings:
            missing = required - f.keys()
            assert not missing, f"Finding {f.get('id')} missing: {missing}"

    def test_source_is_whitebox(self) -> None:
        for f in _check("openapi3_no_global_auth.yaml"):
            assert f["source"] == "whitebox"

    def test_category_is_auth(self) -> None:
        for f in _check("openapi3_no_global_auth.yaml"):
            assert f["category"] == "auth"


# ---------------------------------------------------------------------------
# get_endpoints tests
# ---------------------------------------------------------------------------

class TestGetEndpoints:
    def test_returns_all_paths(self) -> None:
        parser = SpecParser(str(SPECS_DIR / "openapi3_secure.yaml"))
        endpoints = parser.get_endpoints()
        paths = {e["path"] for e in endpoints}
        assert "/users" in paths
        assert "/health" in paths

    def test_endpoint_has_method_and_path(self) -> None:
        parser = SpecParser(str(SPECS_DIR / "openapi3_secure.yaml"))
        for ep in parser.get_endpoints():
            assert ep["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
            assert ep["path"].startswith("/")

    def test_health_endpoint_has_empty_security(self) -> None:
        parser = SpecParser(str(SPECS_DIR / "openapi3_secure.yaml"))
        health = next(e for e in parser.get_endpoints() if e["path"] == "/health")
        assert health["security"] == []


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_missing_file_emits_parse_error_finding(self) -> None:
        findings: list[dict] = []
        SpecParser("/nonexistent/spec.yaml").check_auth(findings.append)
        assert len(findings) == 1
        assert findings[0]["id"] == "SEC-SPEC-PARSE"

    def test_invalid_yaml_emits_parse_error_finding(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("{{{{ not valid yaml ::::")
            fname = f.name
        findings: list[dict] = []
        SpecParser(fname).check_auth(findings.append)
        assert any(f["id"] == "SEC-SPEC-PARSE" for f in findings)

    def test_json_spec_is_accepted(self) -> None:
        """A valid JSON OpenAPI spec should be parseable."""
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {},
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(spec, f)
            fname = f.name
        findings: list[dict] = []
        SpecParser(fname).check_auth(findings.append)
        # Should not have a parse error
        assert not any(f["id"] == "SEC-SPEC-PARSE" for f in findings)
