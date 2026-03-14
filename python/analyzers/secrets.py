"""Secrets analyzer — detects hardcoded secrets in source code.

Walks the code path recursively and matches against known secret patterns.
Skips .git/, node_modules/, vendor/, and minified JS files.
"""
from __future__ import annotations

from typing import Callable


class SecretsAnalyzer:
    """Detects hardcoded secrets using regex pattern matching."""

    def __init__(self, code_path: str) -> None:
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run secrets detection. Implementation in TASK-029."""
        pass
