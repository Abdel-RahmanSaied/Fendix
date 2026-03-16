"""AST analyzer — Python and JavaScript AST-based security analysis.

Performs deeper analysis than regex by parsing the abstract syntax tree
to detect security-relevant patterns like unsafe eval, exec, SQL construction,
and dangerous subprocess usage.

JavaScript analysis uses regex-backed heuristics since a full JS AST parser
is not a Python stdlib dependency.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Callable

# Skip directories (same as secrets analyzer)
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox",
})

_MAX_FILE_BYTES = 1_048_576  # 1 MB

# ---------------------------------------------------------------------------
# JavaScript heuristic patterns (regex-based; no JS AST required)
# ---------------------------------------------------------------------------

_JS_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str, str]] = [
    (
        "JS_EVAL",
        "Unsafe use of eval() in JavaScript",
        re.compile(r"\beval\s*\("),
        "HIGH",
        "HIGH",
        "CWE-95",
    ),
    (
        "JS_INNER_HTML",
        "Unsafe assignment to innerHTML — XSS risk",
        re.compile(r"\.innerHTML\s*="),
        "HIGH",
        "MEDIUM",
        "CWE-79",
    ),
    (
        "JS_DOCUMENT_WRITE",
        "Unsafe use of document.write() — XSS risk",
        re.compile(r"\bdocument\.write\s*\("),
        "MEDIUM",
        "MEDIUM",
        "CWE-79",
    ),
    (
        "JS_SQL_TEMPLATE",
        "SQL query built via template literal — injection risk",
        re.compile(r'`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{'),
        "HIGH",
        "HIGH",
        "CWE-89",
    ),
]


class ASTAnalyzer:
    """Analyzes source code ASTs for security-relevant patterns.

    For Python files: uses the stdlib ``ast`` module.
    For JavaScript files: uses regex heuristics.
    Language is auto-detected by file extension if not explicitly specified.
    """

    def __init__(self, code_path: str, language: str = "python") -> None:
        """Initialize with root directory and optional language hint."""
        self.code_path = code_path
        self.language = language.lower() if language else "python"

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Walk code_path and emit findings for security patterns detected."""
        root = Path(self.code_path)
        if not root.exists():
            return

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                rel = str(fpath.relative_to(root))

                if fpath.suffix == ".py":
                    self._analyze_python(fpath, rel, emit_fn)
                elif fpath.suffix in {".js", ".ts", ".jsx", ".tsx"}:
                    self._analyze_js_heuristic(fpath, rel, emit_fn)

    # ------------------------------------------------------------------
    # Python AST analysis
    # ------------------------------------------------------------------

    def _analyze_python(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Parse and analyze a Python file's AST."""
        try:
            if filepath.stat().st_size > _MAX_FILE_BYTES:
                return
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(filepath))
        except (OSError, SyntaxError):
            return

        visitor = _PythonSecurityVisitor(source.splitlines(), rel, emit_fn)
        visitor.visit(tree)

    # ------------------------------------------------------------------
    # JavaScript heuristic analysis
    # ------------------------------------------------------------------

    def _analyze_js_heuristic(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Apply regex heuristics to a JavaScript/TypeScript file."""
        try:
            if filepath.stat().st_size > _MAX_FILE_BYTES:
                return
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        lines = source.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if len(line) > 500:  # skip minified lines
                continue
            for pat_id, title, pattern, severity, confidence, cwe in _JS_PATTERNS:
                if pattern.search(line):
                    emit_fn({
                        "id": f"SEC-{pat_id}",
                        "title": title,
                        "severity": severity,
                        "source": "whitebox",
                        "category": "injection",
                        "endpoint": f"{rel}:{lineno}",
                        "evidence": line.strip()[:200],
                        "fix": _JS_FIX.get(pat_id, "Review and sanitize this usage."),
                        "references": [cwe],
                        "confidence": confidence,
                        "line": f"{rel}:{lineno}",
                    })


# Fixes for JS patterns
_JS_FIX: dict[str, str] = {
    "JS_EVAL": (
        "Replace eval() with safer alternatives. Never pass user-controlled input to eval()."
    ),
    "JS_INNER_HTML": (
        "Use textContent or createElement() instead of innerHTML. "
        "If HTML is required, sanitize with DOMPurify."
    ),
    "JS_DOCUMENT_WRITE": (
        "Replace document.write() with DOM manipulation methods like "
        "document.createElement() and appendChild()."
    ),
    "JS_SQL_TEMPLATE": (
        "Use parameterized queries or an ORM instead of building SQL with template literals."
    ),
}


# ---------------------------------------------------------------------------
# Python AST visitor
# ---------------------------------------------------------------------------

class _PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor that emits findings for dangerous Python patterns."""

    def __init__(
        self,
        source_lines: list[str],
        rel_path: str,
        emit_fn: Callable[[dict], None],
    ) -> None:
        self._lines = source_lines
        self._rel = rel_path
        self._emit = emit_fn

    def _line_text(self, lineno: int) -> str:
        """Return the source line (1-indexed), or empty string."""
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()[:200]
        return ""

    def _emit_finding(
        self,
        pat_id: str,
        title: str,
        severity: str,
        confidence: str,
        cwe: str,
        fix: str,
        lineno: int,
    ) -> None:
        self._emit({
            "id": f"SEC-{pat_id}",
            "title": title,
            "severity": severity,
            "source": "whitebox",
            "category": "injection",
            "endpoint": f"{self._rel}:{lineno}",
            "evidence": self._line_text(lineno),
            "fix": fix,
            "references": [cwe],
            "confidence": confidence,
            "line": f"{self._rel}:{lineno}",
        })

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Detect dangerous function calls."""
        # eval() and exec()
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            # Only flag if argument is not a plain string literal
            if not (node.args and isinstance(node.args[0], ast.Constant)):
                self._emit_finding(
                    "PY_EVAL",
                    f"Unsafe {node.func.id}() with dynamic argument",
                    "HIGH",
                    "MEDIUM",
                    "CWE-95",
                    (
                        f"Replace {node.func.id}() with a safer alternative. "
                        "Never pass user-controlled data to eval/exec."
                    ),
                    node.lineno,
                )

        # os.system()
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            self._emit_finding(
                "PY_OS_SYSTEM",
                "Unsafe os.system() call — command injection risk",
                "HIGH",
                "HIGH",
                "CWE-78",
                (
                    "Replace os.system() with subprocess.run() using a list of arguments "
                    "and shell=False."
                ),
                node.lineno,
            )

        # subprocess with shell=True
        elif self._is_subprocess_shell_true(node):
            self._emit_finding(
                "PY_SUBPROCESS_SHELL",
                "subprocess called with shell=True — command injection risk",
                "HIGH",
                "HIGH",
                "CWE-78",
                (
                    "Remove shell=True and pass arguments as a list. "
                    "Never build shell commands from user input."
                ),
                node.lineno,
            )

        # cursor.execute() with string formatting
        elif self._is_sql_injection(node):
            self._emit_finding(
                "PY_SQL_INJECTION",
                "SQL query built via string formatting — injection risk",
                "CRITICAL",
                "HIGH",
                "CWE-89",
                (
                    "Use parameterized queries: cursor.execute('SELECT ... WHERE x = %s', (val,)). "
                    "Never build SQL with % formatting or f-strings."
                ),
                node.lineno,
            )

        self.generic_visit(node)

    def _is_subprocess_shell_true(self, node: ast.Call) -> bool:
        """Return True if the call is subprocess.<fn>(..., shell=True)."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if not (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            return False
        if node.func.attr not in {"run", "call", "Popen", "check_output", "check_call"}:
            return False
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                return True
        return False

    def _is_sql_injection(self, node: ast.Call) -> bool:
        """Return True if the call is cursor.execute(<non-literal>)."""
        if not (
            isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
        ):
            return False
        if not node.args:
            return False
        first_arg = node.args[0]
        # Flagged: any non-constant first argument (variable, join, format, f-string)
        if isinstance(first_arg, ast.Constant):
            return False
        # Flagged: BinOp (string % ...), JoinedStr (f-string), Call (.format())
        return isinstance(first_arg, (ast.BinOp, ast.JoinedStr, ast.Call))
