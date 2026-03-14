"""Dependency CVE checker — scans project dependencies for known vulnerabilities.

Checks requirements.txt (PyPI) and package.json (npm) against
known vulnerability databases.
"""
from __future__ import annotations

from typing import Callable


class DepsAnalyzer:
    """Checks project dependencies for known CVEs."""

    def __init__(self, code_path: str) -> None:
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run dependency CVE check. Implementation in TASK-036."""
        pass
