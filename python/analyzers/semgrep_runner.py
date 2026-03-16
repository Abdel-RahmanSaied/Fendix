"""Semgrep runner — integrates Semgrep static analysis with Fendix.

Runs custom Semgrep rules against the target codebase and maps
results to Fendix Finding format.  If semgrep is not installed,
the runner emits no findings and logs a warning to stderr.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

# Rules directory relative to this file's location
_RULES_DIR = Path(__file__).parent.parent / "rules"

# Mapping from Semgrep severity to Fendix severity
_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

# Mapping from Semgrep rule metadata fendix_severity to Fendix severity
_FENDIX_SEVERITY_VALID = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _find_semgrep() -> str | None:
    """Return the path to the semgrep binary, or None if not found."""
    return shutil.which("semgrep")


def _semgrep_severity(result: dict) -> str:
    """Resolve Fendix severity from a Semgrep result dict."""
    meta = result.get("extra", {}).get("metadata", {})
    fendix_sev = meta.get("fendix_severity", "")
    if fendix_sev in _FENDIX_SEVERITY_VALID:
        return fendix_sev
    semgrep_sev = result.get("extra", {}).get("severity", "WARNING")
    return _SEVERITY_MAP.get(semgrep_sev.upper(), "MEDIUM")


def _semgrep_confidence(result: dict) -> str:
    """Resolve Fendix confidence from Semgrep result metadata."""
    meta = result.get("extra", {}).get("metadata", {})
    conf = meta.get("confidence", "MEDIUM").upper()
    return conf if conf in {"HIGH", "MEDIUM", "LOW"} else "MEDIUM"


def _semgrep_category(result: dict) -> str:
    """Resolve Fendix category from Semgrep result metadata."""
    meta = result.get("extra", {}).get("metadata", {})
    return meta.get("category", "code")


def _semgrep_cwe(result: dict) -> list[str]:
    """Extract CWE references from Semgrep result metadata."""
    meta = result.get("extra", {}).get("metadata", {})
    cwe = meta.get("cwe", "")
    if isinstance(cwe, list):
        return [str(c) for c in cwe]
    return [str(cwe)] if cwe else []


class SemgrepRunner:
    """Runs Semgrep with custom Fendix rules and maps results to findings.

    Requires semgrep to be installed and available in PATH.
    If semgrep is not found, emits no findings (graceful degradation).
    """

    def __init__(self, code_path: str, language: Optional[str] = None) -> None:
        """Initialize with the directory to scan and optional language filter."""
        self.code_path = code_path
        self.language = language

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run Semgrep and emit a finding for each match."""
        semgrep = _find_semgrep()
        if not semgrep:
            print(
                "[fendix-engine] semgrep not found in PATH — skipping semgrep checks. "
                "Install with: pip install semgrep",
                file=sys.stderr,
                flush=True,
            )
            return

        code_path = Path(self.code_path)
        if not code_path.exists():
            return

        rules_dir = _RULES_DIR
        if not rules_dir.exists():
            print(
                f"[fendix-engine] semgrep rules directory not found: {rules_dir}",
                file=sys.stderr,
                flush=True,
            )
            return

        results = self._run_semgrep(semgrep, str(code_path), str(rules_dir))
        for result in results:
            finding = self._map_result(result, code_path)
            if finding:
                emit_fn(finding)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_semgrep(
        self, semgrep_bin: str, code_path: str, rules_path: str
    ) -> list[dict]:
        """Execute semgrep and return parsed results list."""
        cmd = [
            semgrep_bin,
            "--config", rules_path,
            "--json",
            "--no-git-ignore",
            "--quiet",
            code_path,
        ]
        if self.language:
            cmd += ["--lang", self.language]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            print(
                "[fendix-engine] semgrep timed out after 120s",
                file=sys.stderr,
                flush=True,
            )
            return []
        except OSError as exc:
            print(f"[fendix-engine] semgrep execution failed: {exc}", file=sys.stderr)
            return []

        try:
            output = json.loads(proc.stdout)
        except json.JSONDecodeError:
            if proc.returncode not in {0, 1}:
                print(
                    f"[fendix-engine] semgrep exited with code {proc.returncode}: {proc.stderr[:200]}",
                    file=sys.stderr,
                )
            return []

        return output.get("results", [])

    def _map_result(self, result: dict, root: Path) -> dict | None:
        """Map a single Semgrep result to a Fendix finding dict."""
        try:
            path = result.get("path", "")
            rel_path = os.path.relpath(path, root) if path else path
            start_line = result.get("start", {}).get("line", 0)
            rule_id = result.get("check_id", "semgrep-unknown")
            message = result.get("extra", {}).get("message", "Semgrep finding")
            snippet = result.get("extra", {}).get("lines", "")

            # Truncate snippet to avoid overly long evidence
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."

            return {
                "id": f"SEC-{rule_id.upper().replace('-', '_').replace('.', '_')}",
                "title": message.split("\n")[0][:120],
                "severity": _semgrep_severity(result),
                "source": "whitebox",
                "category": _semgrep_category(result),
                "endpoint": f"{rel_path}:{start_line}",
                "evidence": snippet.strip(),
                "fix": message.strip(),
                "references": _semgrep_cwe(result),
                "confidence": _semgrep_confidence(result),
                "line": f"{rel_path}:{start_line}",
            }
        except Exception as exc:  # noqa: BLE001
            print(f"[fendix-engine] failed to map semgrep result: {exc}", file=sys.stderr)
            return None
