"""Tests for the DepsAnalyzer.

Verifies requirements.txt and package.json parsing, version comparison,
and known-vulnerability detection.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from analyzers.deps import (
    DepsAnalyzer,
    _extract_pinned_version,
    _is_vulnerable,
    _parse_package_json,
    _parse_requirements,
    _parse_version,
)


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

class TestVersionParsing:
    def test_parse_simple(self) -> None:
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_parse_with_prefix(self) -> None:
        assert _parse_version("v1.2.3") == (1, 2, 3)
        assert _parse_version("^1.2.3") == (1, 2, 3)
        assert _parse_version("~1.2.3") == (1, 2, 3)

    def test_parse_empty(self) -> None:
        assert _parse_version("") == (0,)

    def test_parse_prerelease(self) -> None:
        # Pre-release: 1.2.3-beta → only numeric part used
        result = _parse_version("1.2.3-beta")
        assert result[0] == 1

    def test_is_vulnerable_old_version(self) -> None:
        assert _is_vulnerable("2.19.0", "2.20.0") is True

    def test_is_vulnerable_exact_safe_version(self) -> None:
        assert _is_vulnerable("2.20.0", "2.20.0") is False

    def test_is_vulnerable_newer_version(self) -> None:
        assert _is_vulnerable("3.0.0", "2.20.0") is False


# ---------------------------------------------------------------------------
# requirements.txt parsing
# ---------------------------------------------------------------------------

class TestRequirementsParsing:
    def test_pinned_version(self) -> None:
        text = "requests==2.19.0\n"
        pkgs = _parse_requirements(text)
        assert ("requests", "==2.19.0") in pkgs

    def test_range_spec(self) -> None:
        text = "pyyaml>=5.0\n"
        pkgs = _parse_requirements(text)
        assert any(p[0] == "pyyaml" for p in pkgs)

    def test_skips_comments(self) -> None:
        text = "# this is a comment\nrequests==2.28.0\n"
        pkgs = _parse_requirements(text)
        assert all(p[0] != "#" for p in pkgs)

    def test_skips_blank_lines(self) -> None:
        text = "\n\nrequests==2.28.0\n\n"
        pkgs = _parse_requirements(text)
        assert len(pkgs) == 1

    def test_skips_flags(self) -> None:
        text = "-r base.txt\n-e .\nrequests==2.28.0\n"
        pkgs = _parse_requirements(text)
        assert len(pkgs) == 1

    def test_normalizes_underscores_to_hyphens(self) -> None:
        text = "my_package==1.0.0\n"
        pkgs = _parse_requirements(text)
        assert pkgs[0][0] == "my-package"

    def test_extract_pinned_version(self) -> None:
        assert _extract_pinned_version("==2.19.0") == "2.19.0"
        assert _extract_pinned_version(">=2.0") is None
        assert _extract_pinned_version("") is None


# ---------------------------------------------------------------------------
# package.json parsing
# ---------------------------------------------------------------------------

class TestPackageJsonParsing:
    def test_parses_dependencies(self) -> None:
        pkg = json.dumps({"dependencies": {"lodash": "4.17.20"}})
        result = _parse_package_json(pkg)
        assert ("lodash", "4.17.20") in result

    def test_parses_dev_dependencies(self) -> None:
        pkg = json.dumps({"devDependencies": {"jest": "^27.0.0"}})
        result = _parse_package_json(pkg)
        assert any(p[0] == "jest" for p in result)

    def test_handles_invalid_json(self) -> None:
        result = _parse_package_json("not json {{{{")
        assert result == []

    def test_empty_object(self) -> None:
        assert _parse_package_json("{}") == []


# ---------------------------------------------------------------------------
# DepsAnalyzer — no files
# ---------------------------------------------------------------------------

class TestDepsAnalyzerNoFiles:
    def test_nonexistent_path_no_findings(self) -> None:
        findings: list[dict] = []
        DepsAnalyzer("/nonexistent").run(findings.append)
        assert findings == []

    def test_empty_directory_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings: list[dict] = []
            DepsAnalyzer(tmpdir).run(findings.append)
            assert findings == []


# ---------------------------------------------------------------------------
# Local PyPI known-vuln check
# ---------------------------------------------------------------------------

class TestLocalPyPICheck:
    def _run_reqs(self, content: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text(content)
            with patch("shutil.which", return_value=None):  # no pip-audit
                findings: list[dict] = []
                DepsAnalyzer(tmpdir).run(findings.append)
            return findings

    def test_detects_vulnerable_pyyaml(self) -> None:
        findings = self._run_reqs("pyyaml==5.0\n")
        assert any("CVE-2017-18342" in f["evidence"] for f in findings)

    def test_detects_vulnerable_requests(self) -> None:
        findings = self._run_reqs("requests==2.19.0\n")
        assert any("CVE-2018-18074" in f["evidence"] for f in findings)

    def test_safe_version_not_flagged(self) -> None:
        findings = self._run_reqs("requests==2.28.0\n")
        assert not any("requests" in f["evidence"] for f in findings)

    def test_unpinned_known_vuln_emits_info(self) -> None:
        findings = self._run_reqs("pyyaml>=5.0\n")
        info = [f for f in findings if f["severity"] == "INFO"]
        assert any("pyyaml" in f["title"].lower() for f in info)

    def test_finding_has_required_fields(self) -> None:
        findings = self._run_reqs("pyyaml==5.0\n")
        required = {"id", "title", "severity", "source", "category",
                    "endpoint", "evidence", "fix", "references", "confidence", "line"}
        for f in findings:
            assert required.issubset(f.keys()), f"Missing: {required - f.keys()}"

    def test_source_is_whitebox(self) -> None:
        for f in self._run_reqs("pyyaml==5.0\n"):
            assert f["source"] == "whitebox"

    def test_category_is_deps(self) -> None:
        for f in self._run_reqs("pyyaml==5.0\n"):
            assert f["category"] == "deps"

    def test_multiple_vulnerable_packages(self) -> None:
        findings = self._run_reqs("pyyaml==5.0\nrequests==2.19.0\n")
        ids = {f["id"] for f in findings}
        assert any("CVE_2017_18342" in i for i in ids)
        assert any("CVE_2018_18074" in i for i in ids)

    def test_no_findings_for_untracked_package(self) -> None:
        findings = self._run_reqs("somepackage==1.0.0\n")
        assert findings == []


# ---------------------------------------------------------------------------
# Local npm known-vuln check
# ---------------------------------------------------------------------------

class TestLocalNpmCheck:
    def _run_npm(self, pkg_json: dict) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").write_text(json.dumps(pkg_json))
            with patch("shutil.which", return_value=None):  # no npm
                findings: list[dict] = []
                DepsAnalyzer(tmpdir).run(findings.append)
            return findings

    def test_detects_vulnerable_lodash(self) -> None:
        pkg = {"dependencies": {"lodash": "4.17.20"}}
        findings = self._run_npm(pkg)
        assert any("CVE-2021-23337" in f["evidence"] for f in findings)

    def test_safe_lodash_not_flagged(self) -> None:
        pkg = {"dependencies": {"lodash": "4.17.21"}}
        findings = self._run_npm(pkg)
        assert not any("lodash" in f.get("evidence", "") for f in findings)

    def test_detects_vulnerable_minimist(self) -> None:
        pkg = {"dependencies": {"minimist": "1.2.5"}}
        findings = self._run_npm(pkg)
        assert any("minimist" in f["evidence"] for f in findings)
