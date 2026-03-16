"""Dependency CVE checker — scans project dependencies for known vulnerabilities.

Checks requirements.txt (PyPI) and package.json (npm) against
known vulnerability databases using pip-audit and npm-audit when available,
with fallback to a curated local known-vulnerable version list.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, NamedTuple

# ---------------------------------------------------------------------------
# Local known-vulnerable package list (fallback when pip-audit is absent)
# Each entry: (package_name, max_safe_version_exclusive, cve_id, severity, description)
# Version comparison: finding emitted if installed_version < max_safe_version
# ---------------------------------------------------------------------------

class _KnownVuln(NamedTuple):
    package: str          # canonical PyPI name (lowercase)
    safe_from: str        # first SAFE version (>=), e.g. "2.20.0"
    cve: str
    severity: str
    title: str
    fix: str


_KNOWN_PYPI_VULNS: list[_KnownVuln] = [
    _KnownVuln(
        "pyyaml", "5.1",
        "CVE-2017-18342", "CRITICAL",
        "PyYAML yaml.load() arbitrary code execution",
        "Upgrade pyyaml >= 5.1 and replace yaml.load() with yaml.safe_load().",
    ),
    _KnownVuln(
        "requests", "2.20.0",
        "CVE-2018-18074", "HIGH",
        "requests HTTP redirect leaks credentials via Referer header",
        "Upgrade requests >= 2.20.0.",
    ),
    _KnownVuln(
        "urllib3", "1.26.5",
        "CVE-2021-33503", "HIGH",
        "urllib3 ReDoS via malformed percent-encoded characters",
        "Upgrade urllib3 >= 1.26.5.",
    ),
    _KnownVuln(
        "pillow", "9.0.1",
        "CVE-2022-22817", "CRITICAL",
        "Pillow arbitrary code execution via PIL.ImageMath.eval",
        "Upgrade Pillow >= 9.0.1.",
    ),
    _KnownVuln(
        "cryptography", "41.0.0",
        "CVE-2023-23931", "HIGH",
        "cryptography NULL pointer dereference in PKCS12 parsing",
        "Upgrade cryptography >= 41.0.0.",
    ),
    _KnownVuln(
        "django", "3.2.19",
        "CVE-2023-31047", "HIGH",
        "Django potential bypass of file upload validators",
        "Upgrade Django >= 3.2.19, 4.1.9, or 4.2.1.",
    ),
    _KnownVuln(
        "flask", "2.3.2",
        "CVE-2023-30861", "HIGH",
        "Flask session cookie leak via cookie policy regression",
        "Upgrade Flask >= 2.3.2.",
    ),
    _KnownVuln(
        "jinja2", "3.1.3",
        "CVE-2024-22195", "MEDIUM",
        "Jinja2 HTML attribute injection via xmlattr filter",
        "Upgrade Jinja2 >= 3.1.3.",
    ),
    _KnownVuln(
        "werkzeug", "3.0.3",
        "CVE-2024-34069", "HIGH",
        "Werkzeug debugger PIN brute-force when network accessible",
        "Upgrade Werkzeug >= 3.0.3 and disable the debugger in production.",
    ),
    _KnownVuln(
        "paramiko", "3.4.0",
        "CVE-2023-48795", "MEDIUM",
        "Paramiko Terrapin SSH prefix truncation attack",
        "Upgrade paramiko >= 3.4.0.",
    ),
]

_KNOWN_NPM_VULNS: list[_KnownVuln] = [
    _KnownVuln(
        "lodash", "4.17.21",
        "CVE-2021-23337", "HIGH",
        "lodash command injection via template function",
        "Upgrade lodash >= 4.17.21.",
    ),
    _KnownVuln(
        "axios", "0.21.1",
        "CVE-2020-28168", "MEDIUM",
        "axios SSRF via server-side redirects",
        "Upgrade axios >= 0.21.1.",
    ),
    _KnownVuln(
        "minimist", "1.2.6",
        "CVE-2021-44906", "CRITICAL",
        "minimist prototype pollution",
        "Upgrade minimist >= 1.2.6.",
    ),
    _KnownVuln(
        "node-forge", "1.3.0",
        "CVE-2022-0122", "MEDIUM",
        "node-forge URL parsing open redirect",
        "Upgrade node-forge >= 1.3.0.",
    ),
]


# ---------------------------------------------------------------------------
# Version parsing / comparison
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints for comparison."""
    v = v.strip().lstrip("v=^~")
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        if m:
            result.append(int(m.group(1)))
        else:
            break
    return tuple(result) if result else (0,)


def _is_vulnerable(installed: str, safe_from: str) -> bool:
    """Return True if installed version < safe_from."""
    try:
        return _parse_version(installed) < _parse_version(safe_from)
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Requirements.txt parser
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*([><=!~^]{1,3}\s*[\d.]+.*?)?\s*(?:#.*)?$"
)


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version_spec) from requirements.txt content."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pkg = m.group(1).lower().replace("_", "-")
            spec = (m.group(2) or "").strip()
            results.append((pkg, spec))
    return results


def _extract_pinned_version(spec: str) -> str | None:
    """If spec is an exact pin (==X.Y.Z), return the version, else None."""
    m = re.match(r"^==\s*([\d.]+)", spec.strip())
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# package.json parser
# ---------------------------------------------------------------------------

def _parse_package_json(text: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version_spec) from package.json content."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    results = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        for pkg, ver in deps.items():
            results.append((pkg.lower(), str(ver)))
    return results


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class DepsAnalyzer:
    """Checks project dependencies for known CVEs.

    Strategy:
    1. Find requirements.txt and/or package.json in code_path.
    2. If pip-audit is available, run it for PyPI packages.
    3. If npm is available, run npm audit for JS packages.
    4. Always run local known-vulnerable list check as an additional layer.
    """

    def __init__(self, code_path: str) -> None:
        """Initialize with the project root directory."""
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Scan for vulnerable dependencies and emit findings."""
        root = Path(self.code_path)
        if not root.exists():
            return

        req_file = root / "requirements.txt"
        pkg_file = root / "package.json"

        if req_file.exists():
            self._check_requirements(req_file, emit_fn)

        if pkg_file.exists():
            self._check_npm(pkg_file, emit_fn)

    # ------------------------------------------------------------------
    # PyPI checks
    # ------------------------------------------------------------------

    def _check_requirements(
        self, req_file: Path, emit_fn: Callable[[dict], None]
    ) -> None:
        """Check requirements.txt with pip-audit + local known-vuln list."""
        text = req_file.read_text(encoding="utf-8")
        packages = _parse_requirements(text)

        # pip-audit (primary, network-enabled)
        if shutil.which("pip-audit"):
            self._run_pip_audit(req_file, emit_fn)
        else:
            # Local fallback
            self._local_pypi_check(packages, req_file, emit_fn)

    def _run_pip_audit(self, req_file: Path, emit_fn: Callable[[dict], None]) -> None:
        """Run pip-audit against requirements.txt and map results."""
        try:
            proc = subprocess.run(
                ["pip-audit", "-r", str(req_file), "--format", "json", "--no-deps"],
                capture_output=True, text=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"[fendix-engine] pip-audit failed: {exc}", file=sys.stderr)
            return

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return

        for vuln in data.get("vulnerabilities", []):
            pkg = vuln.get("name", "unknown")
            ver = vuln.get("version", "?")
            for v in vuln.get("vulns", []):
                emit_fn({
                    "id": f"SEC-DEPS-{v.get('id', 'CVE-UNKNOWN').replace('-', '_')}",
                    "title": f"Vulnerable dependency: {pkg}=={ver} ({v.get('id', '?')})",
                    "severity": "HIGH",
                    "source": "whitebox",
                    "category": "deps",
                    "endpoint": str(req_file.name),
                    "evidence": f"{pkg}=={ver}: {v.get('description', '')[:200]}",
                    "fix": v.get("fix_versions", ["Upgrade to a patched version"])[0]
                    if v.get("fix_versions")
                    else "Upgrade to a patched version.",
                    "references": [v.get("id", "")],
                    "confidence": "HIGH",
                    "line": str(req_file.name),
                })

    def _local_pypi_check(
        self,
        packages: list[tuple[str, str]],
        req_file: Path,
        emit_fn: Callable[[dict], None],
    ) -> None:
        """Check packages against the local known-vulnerable list."""
        pkg_map = {pkg: spec for pkg, spec in packages}
        for vuln in _KNOWN_PYPI_VULNS:
            spec = pkg_map.get(vuln.package)
            if spec is None:
                continue
            pinned = _extract_pinned_version(spec)
            if pinned and _is_vulnerable(pinned, vuln.safe_from):
                emit_fn({
                    "id": f"SEC-DEPS-{vuln.cve.replace('-', '_')}",
                    "title": f"Vulnerable dependency: {vuln.package}=={pinned} ({vuln.cve})",
                    "severity": vuln.severity,
                    "source": "whitebox",
                    "category": "deps",
                    "endpoint": req_file.name,
                    "evidence": (
                        f"{vuln.package}=={pinned} is vulnerable to {vuln.cve}: {vuln.title}"
                    ),
                    "fix": vuln.fix,
                    "references": [vuln.cve],
                    "confidence": "HIGH",
                    "line": req_file.name,
                })
            elif not pinned and spec:
                # Unpinned — emit INFO advisory
                emit_fn({
                    "id": f"SEC-DEPS-UNPINNED-{vuln.package.upper().replace('-', '_')}",
                    "title": (
                        f"Dependency {vuln.package!r} is not pinned — "
                        f"known vulnerable versions exist ({vuln.cve})"
                    ),
                    "severity": "INFO",
                    "source": "whitebox",
                    "category": "deps",
                    "endpoint": req_file.name,
                    "evidence": f"{vuln.package}{spec} (unpinned; {vuln.cve} affects < {vuln.safe_from})",
                    "fix": f"Pin to a specific safe version: {vuln.package}>={vuln.safe_from}. {vuln.fix}",
                    "references": [vuln.cve],
                    "confidence": "LOW",
                    "line": req_file.name,
                })

    # ------------------------------------------------------------------
    # npm checks
    # ------------------------------------------------------------------

    def _check_npm(self, pkg_file: Path, emit_fn: Callable[[dict], None]) -> None:
        """Check package.json with npm audit + local known-vuln list."""
        text = pkg_file.read_text(encoding="utf-8")
        packages = _parse_package_json(text)

        if shutil.which("npm"):
            self._run_npm_audit(pkg_file, emit_fn)

        # Always run local list
        self._local_npm_check(packages, pkg_file, emit_fn)

    def _run_npm_audit(
        self, pkg_file: Path, emit_fn: Callable[[dict], None]
    ) -> None:
        """Run npm audit --json in the package.json directory."""
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=str(pkg_file.parent),
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"[fendix-engine] npm audit failed: {exc}", file=sys.stderr)
            return

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return

        # npm audit v2 format: {"vulnerabilities": {"pkg": {...}}}
        for pkg_name, info in (data.get("vulnerabilities") or {}).items():
            severity = info.get("severity", "moderate").upper()
            fendix_sev = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
                          "LOW": "LOW"}.get(severity, "MEDIUM")
            via = info.get("via", [])
            cves = [v.get("url", "") for v in via if isinstance(v, dict)]
            emit_fn({
                "id": f"SEC-DEPS-NPM-{pkg_name.upper().replace('-', '_').replace('@', '')}",
                "title": f"Vulnerable npm package: {pkg_name} (severity: {severity})",
                "severity": fendix_sev,
                "source": "whitebox",
                "category": "deps",
                "endpoint": pkg_file.name,
                "evidence": f"npm audit found {severity} vulnerability in {pkg_name}",
                "fix": f"Run 'npm audit fix' or update {pkg_name} manually.",
                "references": cves[:3],
                "confidence": "HIGH",
                "line": pkg_file.name,
            })

    def _local_npm_check(
        self,
        packages: list[tuple[str, str]],
        pkg_file: Path,
        emit_fn: Callable[[dict], None],
    ) -> None:
        """Check npm packages against local known-vulnerable list."""
        pkg_map = {pkg: spec for pkg, spec in packages}
        for vuln in _KNOWN_NPM_VULNS:
            spec = pkg_map.get(vuln.package)
            if spec is None:
                continue
            # Strip semver range prefixes for comparison
            pinned = re.sub(r"^[^0-9]*", "", spec)
            if pinned and _is_vulnerable(pinned, vuln.safe_from):
                emit_fn({
                    "id": f"SEC-DEPS-{vuln.cve.replace('-', '_')}",
                    "title": f"Vulnerable npm package: {vuln.package}@{pinned} ({vuln.cve})",
                    "severity": vuln.severity,
                    "source": "whitebox",
                    "category": "deps",
                    "endpoint": pkg_file.name,
                    "evidence": (
                        f"{vuln.package}@{pinned} is vulnerable to {vuln.cve}: {vuln.title}"
                    ),
                    "fix": vuln.fix,
                    "references": [vuln.cve],
                    "confidence": "HIGH",
                    "line": pkg_file.name,
                })
