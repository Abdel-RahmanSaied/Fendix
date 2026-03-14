"""Semgrep runner — integrates Semgrep static analysis with Fendix.

Runs custom Semgrep rules against the target codebase and maps
results to Fendix Finding format.
"""
from __future__ import annotations

from typing import Callable, Optional


class SemgrepRunner:
    """Runs Semgrep with custom rules and maps results to findings."""

    def __init__(self, code_path: str, language: Optional[str] = None) -> None:
        self.code_path = code_path
        self.language = language

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run Semgrep analysis. Implementation in TASK-034."""
        pass
