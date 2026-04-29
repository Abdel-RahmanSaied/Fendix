"""Tests for the DepsAnalyzer.

Verifies requirements.txt and package.json parsing, version comparison,
and known-vulnerability detection. Includes TASK-090 coverage for primary
tool paths (pip-audit, npm audit, govulncheck) using mocked subprocess
output so the suite runs the same on machines without those tools.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analyzers.deps import (
    DepsAnalyzer,
    _extract_pinned_version,
    _is_vulnerable,
    _parse_govulncheck_json,
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


# ---------------------------------------------------------------------------
# TASK-090: pip-audit primary path with mocked subprocess
#
# We can't depend on pip-audit being installed in CI/dev, so we mock
# subprocess.run and shutil.which. Each test exercises one branch of the
# primary→fallback decision tree.
# ---------------------------------------------------------------------------

_PIP_AUDIT_OUTPUT = json.dumps({
    "dependencies": [
        {
            "name": "django",
            "version": "1.11.0",
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "fix_versions": ["3.2.19"],
                    "description": "Django XSS in template tag (sample)",
                    "aliases": ["CVE-2023-31047"],
                }
            ],
        },
        {"name": "requests", "version": "2.30.0", "vulns": []},  # safe row
    ],
})


class TestPipAuditPrimaryPath:
    """pip-audit run path: success, failure, fallback semantics."""

    def _run(self, mock_run, *, content: str = "django==1.11.0\n") -> list[dict]:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text(content)
            findings: list[dict] = []
            with patch("analyzers.deps.shutil.which", return_value="/usr/bin/pip-audit"), \
                 patch("analyzers.deps.subprocess.run", side_effect=mock_run):
                DepsAnalyzer(tmpdir).run(findings.append)
            return findings

    def test_pip_audit_success_emits_findings(self) -> None:
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=1, stdout=_PIP_AUDIT_OUTPUT, stderr="")
        findings = self._run(fake_run)
        # pip-audit should produce the GHSA finding; local fallback NOT run
        assert any("GHSA-xxxx-yyyy-zzzz" in f["title"] for f in findings)
        # If the local fallback had also fired we'd see the DJANGO CVE-2023-31047
        # AS WELL — there'd be 2 findings on django==1.11.0 in that case.
        django_findings = [f for f in findings if "django" in f["title"].lower()]
        assert len(django_findings) == 1, (
            f"Expected exactly 1 django finding (pip-audit primary, no fallback), "
            f"got {len(django_findings)}: {[f['title'] for f in django_findings]}"
        )

    def test_pip_audit_timeout_falls_back_to_local(self) -> None:
        def fake_run(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="pip-audit", timeout=120)
        findings = self._run(fake_run)
        # Local fallback should have fired and emitted Django CVE-2023-31047
        assert any("CVE-2023-31047" in f["evidence"] for f in findings), (
            "Expected local fallback to emit Django CVE after pip-audit timeout; "
            f"got {[f['title'] for f in findings]}"
        )

    def test_pip_audit_nonzero_exit_falls_back(self) -> None:
        def fake_run(*_args, **_kwargs):
            # Exit codes other than 0 (clean) or 1 (vulns found) = tool error
            return MagicMock(returncode=2, stdout="", stderr="Network unreachable")
        findings = self._run(fake_run)
        assert any("CVE-2023-31047" in f["evidence"] for f in findings)

    def test_pip_audit_invalid_json_falls_back(self) -> None:
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=0, stdout="this is not json", stderr="")
        findings = self._run(fake_run)
        assert any("CVE-2023-31047" in f["evidence"] for f in findings)

    def test_pip_audit_legacy_vulnerabilities_key(self) -> None:
        """Older pip-audit builds emit 'vulnerabilities' instead of 'dependencies';
        we accept both for forward/backward compatibility."""
        legacy = json.dumps({
            "vulnerabilities": [
                {"name": "django", "version": "1.11.0", "vulns": [
                    {"id": "GHSA-legacy", "fix_versions": [], "description": "x"}
                ]}
            ]
        })
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=1, stdout=legacy, stderr="")
        findings = self._run(fake_run)
        assert any("GHSA-legacy" in f["title"] for f in findings)


# ---------------------------------------------------------------------------
# TASK-090: npm audit primary path
# ---------------------------------------------------------------------------

_NPM_AUDIT_OUTPUT = json.dumps({
    "vulnerabilities": {
        "lodash": {
            "severity": "high",
            "via": [
                {"url": "https://github.com/advisories/GHSA-jf85-cpcp-j695", "title": "Prototype pollution"}
            ],
        },
    },
})


class TestNpmAuditPrimaryPath:
    """npm audit run path: lockfile detection, success, failure."""

    def _run(self, mock_run, *, has_lockfile: bool = True,
             pkg_json: dict | None = None) -> list[dict]:
        pkg_json = pkg_json or {"dependencies": {"lodash": "4.17.20"}}
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").write_text(json.dumps(pkg_json))
            if has_lockfile:
                (Path(tmpdir) / "package-lock.json").write_text("{}")
            findings: list[dict] = []
            with patch("analyzers.deps.shutil.which", return_value="/usr/bin/npm"), \
                 patch("analyzers.deps.subprocess.run", side_effect=mock_run):
                DepsAnalyzer(tmpdir).run(findings.append)
            return findings

    def test_npm_audit_success_emits_findings(self) -> None:
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=1, stdout=_NPM_AUDIT_OUTPUT, stderr="")
        findings = self._run(fake_run)
        # npm audit emits the lodash finding once; local fallback NOT run.
        lodash = [f for f in findings if "lodash" in f["title"].lower()]
        assert len(lodash) == 1, (
            f"Expected single lodash finding from npm audit, got {len(lodash)}: "
            f"{[f['title'] for f in lodash]}"
        )

    def test_npm_audit_no_lockfile_falls_back(self) -> None:
        # No lockfile → primary path is skipped; local list runs directly.
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=0, stdout="{}", stderr="")
        findings = self._run(fake_run, has_lockfile=False)
        # Local fallback must produce the lodash CVE
        assert any("CVE-2021-23337" in f["evidence"] for f in findings)

    def test_npm_audit_failure_falls_back(self) -> None:
        def fake_run(*_args, **_kwargs):
            return MagicMock(returncode=2, stdout="", stderr="ENETUNREACH")
        findings = self._run(fake_run)
        assert any("CVE-2021-23337" in f["evidence"] for f in findings)


# ---------------------------------------------------------------------------
# TASK-090: govulncheck JSON parser
# ---------------------------------------------------------------------------

# Minimal NDJSON sample modelled on real govulncheck output: one OSV record
# plus one finding entry with a function trace (= "called", emitting fendix
# finding) and one finding entry with no function (= "imported only", skipped).
_GOVULNCHECK_NDJSON = "\n".join([
    json.dumps({"config": {"go_version": "go1.22"}}),
    json.dumps({"progress": {"message": "Scanning..."}}),
    json.dumps({"osv": {
        "id": "GO-2024-2611",
        "summary": "Symlink traversal in archive/zip",
        "details": "When opening a malicious archive, archive/zip can write outside the destination directory.",
        "aliases": ["CVE-2024-12345"],
        "affected": [{
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.22.4"}]}],
        }],
    }}),
    json.dumps({"finding": {
        "osv": "GO-2024-2611",
        "fixed_version": "v1.22.4",
        "trace": [{"module": "stdlib", "package": "archive/zip", "function": "OpenReader"}],
    }}),
    # Imported-but-not-called → no `function` in trace → skipped:
    json.dumps({"osv": {
        "id": "GO-2024-1111",
        "summary": "Imported but uncalled vuln",
        "details": "Should not be flagged — vendored code never reached.",
        "affected": [{"ranges": [{"events": [{"fixed": "1.0.0"}]}]}],
    }}),
    json.dumps({"finding": {
        "osv": "GO-2024-1111",
        "trace": [{"module": "vendor/lib", "package": "vendor/lib"}],  # no function
    }}),
])


class TestGovulncheckParser:
    def test_emits_finding_for_called_vuln(self) -> None:
        findings = _parse_govulncheck_json(_GOVULNCHECK_NDJSON)
        ids = [f["id"] for f in findings]
        assert ids == ["SEC-DEPS-GO-GO_2024_2611"], ids

    def test_skips_imported_but_uncalled_vuln(self) -> None:
        findings = _parse_govulncheck_json(_GOVULNCHECK_NDJSON)
        assert not any("GO_2024_1111" in f["id"] for f in findings), (
            "Imported-only vulns shouldn't emit findings — they're vendored noise"
        )

    def test_finding_carries_fix_version(self) -> None:
        findings = _parse_govulncheck_json(_GOVULNCHECK_NDJSON)
        assert "1.22.4" in findings[0]["fix"]

    def test_finding_carries_aliases_in_references(self) -> None:
        findings = _parse_govulncheck_json(_GOVULNCHECK_NDJSON)
        refs = findings[0]["references"]
        assert "GO-2024-2611" in refs
        assert "CVE-2024-12345" in refs

    def test_required_fields_present(self) -> None:
        findings = _parse_govulncheck_json(_GOVULNCHECK_NDJSON)
        required = {"id", "title", "severity", "source", "category",
                    "evidence", "fix", "references", "confidence"}
        for f in findings:
            assert required.issubset(f.keys()), f"Missing: {required - f.keys()}"

    def test_malformed_lines_are_skipped(self) -> None:
        bad = "\n".join([
            "not json",
            json.dumps({"osv": {"id": "GO-OK", "summary": "ok", "affected": []}}),
            "{ invalid",
            json.dumps({"finding": {"osv": "GO-OK", "trace": [{"function": "f"}]}}),
        ])
        findings = _parse_govulncheck_json(bad)
        assert any("GO_OK" in f["id"] for f in findings)

    def test_empty_input_returns_empty_list(self) -> None:
        assert _parse_govulncheck_json("") == []
        assert _parse_govulncheck_json("\n\n\n") == []

    def test_pretty_printed_multiline_json(self) -> None:
        """Real govulncheck output is pretty-printed (multi-line per object),
        not single-line NDJSON. The parser must consume both forms — a real
        bug surfaced during in-session testing where `splitlines()` saw only
        single-line JSON and missed every multi-line object."""
        pretty = """{
  "config": {
    "go_version": "go1.22"
  }
}
{
  "osv": {
    "id": "GO-2024-PRETTY",
    "summary": "Multi-line print",
    "details": "Test"
  }
}
{
  "finding": {
    "osv": "GO-2024-PRETTY",
    "fixed_version": "v1.0.0",
    "trace": [
      {
        "module": "user/code",
        "package": "user/code",
        "function": "main"
      }
    ]
  }
}
"""
        findings = _parse_govulncheck_json(pretty)
        assert any("GO_2024_PRETTY" in f["id"] for f in findings), (
            f"Pretty-printed govulncheck output not parsed; got: {findings}"
        )


class TestGovulncheckIntegration:
    """End-to-end: DepsAnalyzer with go.mod + govulncheck installed."""

    def test_runs_govulncheck_on_go_mod(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "go.mod").write_text("module test\n\ngo 1.22\n")
            findings: list[dict] = []
            def fake_run(*_args, **_kwargs):
                return MagicMock(returncode=3, stdout=_GOVULNCHECK_NDJSON, stderr="")
            with patch("analyzers.deps.shutil.which", return_value="/usr/bin/govulncheck"), \
                 patch("analyzers.deps.subprocess.run", side_effect=fake_run):
                DepsAnalyzer(tmpdir).run(findings.append)
            assert any("GO_2024_2611" in f["id"] for f in findings)
            # endpoint + line should be go.mod (the manifest filename)
            assert all(f["endpoint"] == "go.mod" for f in findings if "GO-" in f["id"])

    def test_no_govulncheck_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "go.mod").write_text("module test\n")
            findings: list[dict] = []
            with patch("analyzers.deps.shutil.which", return_value=None):
                DepsAnalyzer(tmpdir).run(findings.append)
            assert findings == []  # No tool, no fallback for Go

    def test_no_go_mod_no_call(self) -> None:
        # Make sure we don't accidentally invoke govulncheck on Python-only projects.
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text("requests==2.30.0\n")
            findings: list[dict] = []
            with patch("analyzers.deps.shutil.which", return_value=None) as which_mock:
                DepsAnalyzer(tmpdir).run(findings.append)
            # govulncheck should never have been looked up
            assert not any(call.args[0] == "govulncheck"
                           for call in which_mock.call_args_list)
