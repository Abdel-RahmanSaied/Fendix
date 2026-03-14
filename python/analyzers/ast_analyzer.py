"""AST analyzer — Python and JavaScript AST-based security analysis.

Performs deeper analysis than regex by parsing the abstract syntax tree
to detect security-relevant patterns like unsafe eval, exec, and SQL construction.
"""
from __future__ import annotations

from typing import Callable


class ASTAnalyzer:
    """Analyzes source code ASTs for security patterns."""

    def __init__(self, code_path: str, language: str = "python") -> None:
        self.code_path = code_path
        self.language = language

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Run AST analysis. Implementation in TASK-035."""
        pass
