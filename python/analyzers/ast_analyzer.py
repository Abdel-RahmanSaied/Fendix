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
        # Stack of variable-assignment scopes. Outermost element is module
        # scope; each FunctionDef pushes a new scope. Used by `_is_sql_injection`
        # to resolve `cursor.execute(name)` to the value `name` was assigned —
        # closes the multi-step string-concat SQLi gap (TASK-087).
        self._scopes: list[dict[str, ast.AST]] = [{}]

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
        category: str = "injection",
        taint_chain: list[dict] | None = None,
    ) -> None:
        finding: dict = {
            "id": f"SEC-{pat_id}",
            "title": title,
            "severity": severity,
            "source": "whitebox",
            "category": category,
            "endpoint": f"{self._rel}:{lineno}",
            "evidence": self._line_text(lineno),
            "fix": fix,
            "references": [cwe],
            "confidence": confidence,
            "line": f"{self._rel}:{lineno}",
        }
        if taint_chain:
            # TASK-114: when the visitor proves user input flows from a
            # source (request.args/POST/form/etc.) through one or more
            # intra-function assignments to this sink, attach the chain
            # so the correlator can escalate severity and the report
            # surfaces *why* this is a real exploit path. Each entry is
            # {file, line, expr}; the engine treats this as opaque metadata.
            finding["taint_chain"] = taint_chain
            finding["reachable"] = True
        self._emit(finding)

    # ------------------------------------------------------------------
    # Taint-chain helpers (TASK-114)
    # ------------------------------------------------------------------

    def _collect_taint_chain(
        self, sink_arg: ast.AST, sink_lineno: int, sink_expr: str
    ) -> list[dict] | None:
        """Walk back from ``sink_arg`` through scope assignments to a request source.

        Returns an ordered chain (source first, sink last) when reachable,
        else None. The walker recurses through complex assignments — a
        chain like ``q = request.args.get('q'); sql = '...' + q;
        cursor.execute(sql)`` resolves via two hops: first ``sql`` ->
        BinOp containing Name ``q``, then ``q`` -> Call referencing
        ``request.args``.

        Each link is ``{"file": str, "line": int, "expr": str}``.
        """
        # Inline case: the sink's argument is itself a request-input
        # reference (no intermediate variables). The chain is two links:
        # source @ sink-lineno → sink @ sink-lineno.
        if _references_request_input(sink_arg):
            return [
                self._link(sink_lineno, _ast_expr_text(sink_arg)),
                self._link(sink_lineno, sink_expr),
            ]

        prefix = self._trace_to_source(sink_arg, frozenset())
        if prefix is None:
            return None
        return prefix + [self._link(sink_lineno, sink_expr)]

    def _trace_to_source(
        self, expr: ast.AST, visited: frozenset[str]
    ) -> list[dict] | None:
        """Recursively trace Names in ``expr`` through scope assignments.

        Returns the chain prefix (oldest assignment first) up to and
        including the assignment that introduced the request source.
        ``visited`` guards against assignment cycles (``a = b; b = a``).
        """
        for n in ast.walk(expr):
            if not isinstance(n, ast.Name) or n.id in visited:
                continue
            for scope in reversed(self._scopes):
                if n.id not in scope:
                    continue
                assigned = scope[n.id]
                lineno = getattr(assigned, "lineno", 0)
                link = self._link(lineno, _ast_expr_text(assigned))
                if _references_request_input(assigned):
                    return [link]
                deeper = self._trace_to_source(assigned, visited | {n.id})
                if deeper is not None:
                    return deeper + [link]
                # Name resolved but didn't lead to a source; don't keep
                # searching siblings — we found the assignment for n.id.
                break
        return None

    def _link(self, lineno: int, expr: str) -> dict:
        return {"file": self._rel, "line": int(lineno), "expr": expr}

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

        # cursor.execute() with string formatting (or with a variable assigned
        # from a formatted/concatenated string elsewhere in the function).
        elif self._is_sql_injection(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"cursor.execute({_ast_expr_text(node.args[0])})",
                )
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
                taint_chain=chain,
            )

        # pickle.load() / pickle.loads() — always dangerous on untrusted input.
        # Unlike yaml.load there's no "safe" variant; the right answer is
        # always JSON or msgpack.
        elif self._is_pickle_load(node):
            self._emit_finding(
                "PY_PICKLE_LOAD",
                "Unsafe pickle deserialization — RCE risk",
                "CRITICAL",
                "HIGH",
                "CWE-502",
                (
                    "Never deserialize untrusted data with pickle. "
                    "Use JSON for cross-process data; if you must, sign and verify a HMAC first."
                ),
                node.lineno,
            )

        # yaml.load() without Loader=SafeLoader (or yaml.unsafe_load).
        # PyYAML's load() defaults to FullLoader since 5.1 but pre-5.1 was
        # equivalent to UnsafeLoader; explicitly check for SafeLoader to match
        # what's universally safe.
        elif self._is_unsafe_yaml_load(node):
            self._emit_finding(
                "PY_YAML_UNSAFE_LOAD",
                "Unsafe yaml.load() — RCE risk",
                "HIGH",
                "HIGH",
                "CWE-502",
                (
                    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader. "
                    "yaml.load() and yaml.unsafe_load() can execute arbitrary Python on untrusted input."
                ),
                node.lineno,
            )

        # hashlib.md5/sha1 used to hash a value that looks password-related.
        # MD5 and SHA1 are fast, unsalted, and rainbow-table-friendly; both are
        # disqualified by NIST/OWASP for password storage. We require a
        # password-y identifier in the arg subtree to keep noise low — md5 of
        # a file checksum is fine.
        elif self._is_weak_password_hash(node):
            self._emit_finding(
                "PY_WEAK_CRYPTO_PASSWORD",
                "Weak hash (MD5/SHA1) used for password — credential exposure risk",
                "HIGH",
                "MEDIUM",
                "CWE-916",
                (
                    "Use a password hashing function: argon2 (preferred), bcrypt, or scrypt. "
                    "MD5 and SHA1 are unsuitable for password storage — they're fast and "
                    "vulnerable to rainbow tables."
                ),
                node.lineno,
                category="secrets",
            )

        # redirect()/HttpResponseRedirect() with request-derived input.
        # Pattern: flask.redirect(request.args.get('url'))  or
        #          HttpResponseRedirect(request.GET['next'])
        elif self._is_open_redirect(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"redirect({_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_OPEN_REDIRECT",
                "Open redirect — user-controlled redirect target",
                "HIGH",
                "MEDIUM",
                "CWE-601",
                (
                    "Validate redirect targets against an allow-list of safe URLs/paths "
                    "before passing to redirect(). Reject anything outside your domain."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # requests.get/post/etc. with non-literal first arg → potential SSRF.
        # MEDIUM confidence because legitimate HTTP-client use is common; the
        # signal is that the URL itself is dynamic.
        elif self._is_ssrf(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"requests.{node.func.attr}({_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_SSRF",
                "Potential SSRF — dynamic URL passed to HTTP client",
                "HIGH",
                "MEDIUM",
                "CWE-918",
                (
                    "Validate the URL against an allow-list before fetching. "
                    "Disallow internal addresses (127.0.0.1, 169.254.169.254, RFC1918 ranges) "
                    "and use a SSRF-aware HTTP client wrapper."
                ),
                node.lineno,
                taint_chain=chain,
            )

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Statement-level visitors (for scope tracking and If-based patterns)
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Push a new scope for assignment tracking, recurse, then pop."""
        self._scopes.append({})
        self.generic_visit(node)
        self._scopes.pop()

    # async def is the same shape — share the implementation.
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """Record `name = value` so later cursor.execute(name) can resolve."""
        # Only single-target Name assignments — tuple unpacking and attribute
        # assignment are out of scope; they'd add complexity without changing
        # detection rate on the patterns we care about.
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and self._scopes
        ):
            self._scopes[-1][node.targets[0].id] = node.value
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        """Detect auth-header-trust patterns at if-statement boundaries."""
        if _is_request_header_trust(node.test):
            self._emit_finding(
                "PY_AUTH_HEADER_TRUST",
                "Auth decision based on a client-controllable header",
                "HIGH",
                "MEDIUM",
                "CWE-290",
                (
                    "Never trust client-supplied headers (X-Admin, X-Role, etc.) for auth. "
                    "Use a verified session token or signed JWT instead."
                ),
                node.lineno,
                category="auth_bypass",
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
        """Return True if the call is cursor.execute(<unsafe>).

        Unsafe means: an inline BinOp/JoinedStr/Call (`%`/`+`/f-string/.format()),
        OR a Name that resolves to one of those via intra-function tracking
        (closes the multi-step assignment gap — TASK-087).
        """
        if not (
            isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
        ):
            return False
        if not node.args:
            return False
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant):
            return False
        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
            return True
        # Name lookup in scope chain — innermost wins.
        if isinstance(first_arg, ast.Name):
            for scope in reversed(self._scopes):
                if first_arg.id in scope:
                    assigned = scope[first_arg.id]
                    return isinstance(assigned, (ast.BinOp, ast.JoinedStr, ast.Call))
        return False

    def _is_pickle_load(self, node: ast.Call) -> bool:
        """Return True if the call is pickle.load() or pickle.loads()."""
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"load", "loads"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"pickle", "cPickle", "_pickle"}
        )

    def _is_unsafe_yaml_load(self, node: ast.Call) -> bool:
        """Return True for yaml.load() without SafeLoader, or yaml.unsafe_load*."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"):
            return False
        # Always-unsafe variants.
        if node.func.attr in {"unsafe_load", "unsafe_load_all", "load_all"}:
            return True
        if node.func.attr != "load":
            return False
        # yaml.load(stream) — check for Loader= keyword that names a safe loader.
        loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
        if loader_kw is None:
            return True
        return not _is_safe_loader_expr(loader_kw.value)

    def _is_weak_password_hash(self, node: ast.Call) -> bool:
        """Return True if hashlib.md5/sha1 is hashing a password-like value."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib"):
            return False
        algo: str | None = None
        if node.func.attr in {"md5", "sha1"}:
            algo = node.func.attr
        elif node.func.attr == "new" and node.args:
            # hashlib.new("md5", data) — first arg is the algo name.
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.lower() in {"md5", "sha1"}:
                    algo = first.value.lower()
        if algo is None:
            return False
        # Find the data argument: arg[0] for md5/sha1, arg[1] for new(algo, data).
        data_arg = None
        if node.func.attr in {"md5", "sha1"} and node.args:
            data_arg = node.args[0]
        elif node.func.attr == "new" and len(node.args) >= 2:
            data_arg = node.args[1]
        if data_arg is None:
            return False
        return _arg_subtree_looks_like_password(data_arg)

    def _is_open_redirect(self, node: ast.Call) -> bool:
        """Return True if redirect(...)/HttpResponseRedirect(...) gets request input."""
        is_redirect_func = (
            isinstance(node.func, ast.Name)
            and node.func.id in {"redirect", "HttpResponseRedirect"}
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"redirect", "HttpResponseRedirect"}
        )
        if not (is_redirect_func and node.args):
            return False
        return _references_request_input(node.args[0])

    def _is_ssrf(self, node: ast.Call) -> bool:
        """Return True if requests.<method>() is called with a non-literal URL."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "requests"):
            return False
        if node.func.attr not in {"get", "post", "put", "delete", "head", "patch", "options", "request"}:
            return False
        if not node.args:
            return False
        first = node.args[0]
        # Constant string URL is fine — no user input involved.
        if isinstance(first, ast.Constant):
            return False
        # Name that resolves to a constant in the local scope is also fine.
        if isinstance(first, ast.Name):
            for scope in reversed(self._scopes):
                if first.id in scope and isinstance(scope[first.id], ast.Constant):
                    return False
        return True


# ---------------------------------------------------------------------------
# Module-level helpers (no visitor state required)
# ---------------------------------------------------------------------------

# Loader names that yaml.load accepts as safe (i.e. don't construct arbitrary
# Python objects). Compared by attribute or name, not value.
_SAFE_LOADER_NAMES: frozenset[str] = frozenset({
    "SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader",
})


def _is_safe_loader_expr(expr: ast.expr) -> bool:
    """Return True if the expression names a safe YAML loader.

    Accepts both attribute form (`yaml.SafeLoader`) and bare name (`SafeLoader`
    after a `from yaml import SafeLoader`).
    """
    if isinstance(expr, ast.Attribute):
        return expr.attr in _SAFE_LOADER_NAMES
    if isinstance(expr, ast.Name):
        return expr.id in _SAFE_LOADER_NAMES
    return False


# Long, distinctive password-related substrings — substring match is safe.
_PASSWORD_SUBSTR_TOKENS: tuple[str, ...] = (
    "password", "passwd", "passphrase", "secret",
)

# Short password abbreviations — substring match would false-positive
# (e.g. "pw" matching "power"), so require these as whole snake_case parts.
_PASSWORD_WORD_TOKENS: frozenset[str] = frozenset({"pw", "pwd"})

# Token splitter: snake_case, kebab-case, dotted, camelCase boundary.
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _looks_like_password_id(name: str) -> bool:
    """Return True if an identifier name suggests a password/secret value."""
    lower = name.lower()
    if any(tok in lower for tok in _PASSWORD_SUBSTR_TOKENS):
        return True
    # Whole-token check for short abbreviations like `pw`, `pwd`, `user_pw`.
    return any(part in _PASSWORD_WORD_TOKENS for part in _TOKEN_SPLIT_RE.split(lower))


def _arg_subtree_looks_like_password(node: ast.AST) -> bool:
    """Return True if any Name/Attribute in the subtree has a password-y id."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and _looks_like_password_id(n.id):
            return True
        if isinstance(n, ast.Attribute) and _looks_like_password_id(n.attr):
            return True
    return False


# Attributes on the `request` object that carry user-controlled data across
# Flask, Django, FastAPI/Starlette. `headers` deliberately excluded — we have
# a dedicated header-trust check (`_is_request_header_trust`).
_REQUEST_INPUT_ATTRS: frozenset[str] = frozenset({
    "GET", "POST", "args", "values", "form", "data", "json",
    "query_params", "path_params", "params", "body", "files",
})


def _ast_expr_text(node: ast.AST) -> str:
    """Return a short text representation of an AST expression.

    Uses ast.unparse on Python ≥3.9 (always available in our supported
    versions). Trims to a reasonable length so taint chains don't blow
    out report rendering or push the IPC pipeline past readFindings'
    1MiB-per-line cap.
    """
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001 — unparse can hit unsupported nodes
        text = type(node).__name__
    text = text.strip()
    if len(text) > 200:
        text = text[:200] + "…"
    return text


def _references_request_input(arg: ast.AST) -> bool:
    """Return True if the subtree references request.GET/POST/args/etc.

    Recognizes both the global `request` and the handler-arg name `req`
    (see _REQUEST_NAMES).
    """
    for n in ast.walk(arg):
        if isinstance(n, ast.Attribute):
            if (
                isinstance(n.value, ast.Name)
                and n.value.id in _REQUEST_NAMES
                and n.attr in _REQUEST_INPUT_ATTRS
            ):
                return True
            # request.GET.get(...), request.args.get(...) — the .get is on
            # the inner attribute. Walk handles both via the outer iteration.
        if isinstance(n, ast.Subscript):
            value = n.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id in _REQUEST_NAMES
                and value.attr in _REQUEST_INPUT_ATTRS
            ):
                return True
    return False


# Common identifiers for the request object across Flask/Django/FastAPI.
# Conventional handler-arg names — `request` is the global/Django/FastAPI
# convention, `req` is the standard Flask handler-arg abbreviation.
_REQUEST_NAMES: frozenset[str] = frozenset({"request", "req"})


def _is_request_header_trust(test: ast.expr) -> bool:
    """Return True if an If-test reads a header for an auth decision.

    Matches:  if request.headers.get('X-Admin'):
              if request.headers.get('X-Role') == 'admin':
              if request.headers['X-Admin']:
              if req.headers.get('X-Admin'):    (handler-arg form)
    """
    # Compare(left=..., comparators=[...]) — unwrap to inspect left side.
    target: ast.expr = test
    if isinstance(test, ast.Compare):
        target = test.left

    # <req>.headers.get(...) call.
    if isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute):
        if target.func.attr == "get":
            inner = target.func.value
            if (
                isinstance(inner, ast.Attribute)
                and inner.attr == "headers"
                and isinstance(inner.value, ast.Name)
                and inner.value.id in _REQUEST_NAMES
            ):
                return True

    # <req>.headers[...] subscript.
    if isinstance(target, ast.Subscript):
        value = target.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "headers"
            and isinstance(value.value, ast.Name)
            and value.value.id in _REQUEST_NAMES
        ):
            return True

    return False
