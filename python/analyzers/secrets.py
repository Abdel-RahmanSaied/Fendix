"""Secrets analyzer — detects hardcoded secrets in source code.

Walks the code path recursively and matches against 15 secret pattern types
(7 generic + 8 provider-specific). Plus a .env-only pattern for unquoted
KEY=value lines, which the generic password regex misses.

Skips .git/, node_modules/, vendor/, and minified JS files.
Evidence is truncated to avoid leaking full secret values in reports.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Pattern registry. Each entry: (pattern_id, title, regex, severity, cwe).
# Generic patterns first, then provider-specific high-confidence prefixes.
# Provider patterns use lookarounds to anchor the prefix and avoid matches
# inside concatenated strings (e.g. "ghp_..." inside a base64 blob).
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str]] = [
    (
        "AWS_ACCESS_KEY",
        "AWS Access Key ID hardcoded",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "AWS_SECRET_KEY",
        "AWS Secret Access Key hardcoded",
        re.compile(
            r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key["\s]*[=:]["\s]*'
            r'([A-Za-z0-9/+=]{40})'
        ),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "PRIVATE_KEY",
        "Private key material hardcoded",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        "CRITICAL",
        "CWE-321",
    ),
    (
        "GENERIC_API_KEY",
        "Hardcoded API key or token",
        re.compile(
            r'(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|'
            r'auth[_\-]?token|client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_.+/]{20,})["\']'
        ),
        "HIGH",
        "CWE-798",
    ),
    (
        "HARDCODED_PASSWORD",
        "Hardcoded password in source code",
        re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'
        ),
        "HIGH",
        "CWE-259",
    ),
    (
        "JWT_TOKEN",
        "Hardcoded JWT token",
        re.compile(
            r'\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b'
        ),
        "HIGH",
        "CWE-798",
    ),
    (
        "DB_CONNECTION_STRING",
        "Database connection string with credentials",
        re.compile(
            r'(?i)(?:mongodb|postgresql|postgres|mysql|mssql|redis|sqlite)'
            r'://[^:@\s]+:[^@\s]+@[^\s"\']+'
        ),
        "HIGH",
        "CWE-214",
    ),
    # Provider-specific token prefixes. High confidence because the prefix
    # uniquely identifies the issuer; length/charset constraints reduce
    # false positives in random base64.
    (
        "GITHUB_TOKEN",
        "GitHub token hardcoded",
        # Personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
        # server-to-server (ghs_), refresh (ghr_).
        re.compile(r"(?<![A-Za-z0-9])gh[opusr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "STRIPE_LIVE_KEY",
        "Stripe live secret key hardcoded",
        re.compile(r"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "SLACK_TOKEN",
        "Slack token hardcoded",
        # xoxa-/xoxb-/xoxp-/xoxr-/xoxs-.
        re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"),
        "HIGH",
        "CWE-798",
    ),
    (
        "GOOGLE_API_KEY",
        "Google API key hardcoded",
        re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9_\-])"),
        "HIGH",
        "CWE-798",
    ),
    (
        "ANTHROPIC_API_KEY",
        "Anthropic API key hardcoded",
        re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "OPENAI_API_KEY",
        "OpenAI API key hardcoded",
        # Legacy sk-<48 alnum>; project sk-proj-<...>; service-account sk-svcacct-<...>.
        # Cannot match Anthropic sk-ant-* because `-` after `ant` breaks the alnum body.
        re.compile(
            r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9]{32,}(?![A-Za-z0-9])"
        ),
        "CRITICAL",
        "CWE-798",
    ),
    (
        "NPM_TOKEN",
        "npm registry token hardcoded",
        re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        "HIGH",
        "CWE-798",
    ),
    (
        "GCP_SERVICE_ACCOUNT",
        "GCP service-account JSON key hardcoded",
        # Canonical signature line in Google's downloaded SA JSON files.
        re.compile(r'"type"\s*:\s*"service_account"'),
        "CRITICAL",
        "CWE-798",
    ),
]

# .env-only patterns. The generic HARDCODED_PASSWORD regex requires quoted
# values, but .env files use unquoted KEY=value. Applying these patterns
# globally would cause false positives in regular source where unquoted
# assignments are normal syntax — so they are gated to .env* files only via
# _is_env_file() in _scan_file.
_ENV_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str]] = [
    (
        "ENV_SECRET",
        "Hardcoded credential in .env file",
        # KEY ends with a credential-y suffix (KEY/TOKEN/SECRET/PASSWORD/...);
        # value is unquoted, ≥4 chars, not starting with whitespace/quote/#.
        re.compile(
            r"^([A-Z][A-Z0-9_]*"
            r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)S?"
            r"(?:_[A-Z0-9_]+)?)"
            r"\s*=\s*"
            r"([^\s\"'#][^\n#]{3,})\s*$"
        ),
        "HIGH",
        "CWE-798",
    ),
]


def _is_env_file(p: Path) -> bool:
    """Return True if p is a .env-style config file (.env, .env.local, .env.production)."""
    name = p.name
    return name == ".env" or name.startswith(".env.") or p.suffix == ".env"

# Files/directories to skip
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox",
})

# Extensions to scan (text files only)
_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".env", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".tf", ".hcl", ".sh", ".bash", ".zsh", ".conf", ".config",
})

# Max file size to scan (1 MB)
_MAX_FILE_BYTES = 1_048_576

# Evidence truncation length
_EVIDENCE_MAX_LEN = 120


def _is_minified(path: Path, line: str) -> bool:
    """Heuristic: skip minified JS (very long lines)."""
    return path.suffix in {".js", ".ts"} and len(line) > 500


def _truncate_secret(match: str, max_len: int = 20) -> str:
    """Show only first N chars + ellipsis so reports are safe to share."""
    if len(match) <= max_len:
        return match[:4] + "..." if len(match) > 4 else "***"
    return match[:max_len] + "..."


def _truncate_evidence(line: str, match_start: int) -> str:
    """Return a context window around the match, capped at _EVIDENCE_MAX_LEN."""
    start = max(0, match_start - 20)
    snippet = line[start:start + _EVIDENCE_MAX_LEN].rstrip()
    return snippet + ("..." if len(line) - start > _EVIDENCE_MAX_LEN else "")


class SecretsAnalyzer:
    """Detects hardcoded secrets using regex pattern matching.

    Walks code_path recursively, scans each eligible text file line-by-line,
    and emits a Finding for each matched pattern.
    """

    def __init__(self, code_path: str) -> None:
        """Initialize with the root directory to scan."""
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Walk code_path and emit a finding for each secret detected."""
        root = Path(self.code_path)
        if not root.exists():
            return

        for filepath in self._walk(root):
            self._scan_file(filepath, root, emit_fn)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _walk(self, root: Path):
        """Yield scannable file paths under root, skipping noise directories."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                # .env / .env.local / .env.production: pathlib reports
                # suffix="" or suffix=".local", neither in _SCAN_EXTENSIONS.
                # Match by name explicitly so the env-pattern path can fire.
                if fpath.suffix in _SCAN_EXTENSIONS or _is_env_file(fpath):
                    yield fpath

    def _scan_file(
        self, filepath: Path, root: Path, emit_fn: Callable[[dict], None]
    ) -> None:
        """Scan a single file for secret patterns."""
        try:
            size = filepath.stat().st_size
            if size > _MAX_FILE_BYTES:
                return
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel = str(filepath.relative_to(root))
        patterns = _PATTERNS + _ENV_PATTERNS if _is_env_file(filepath) else _PATTERNS

        for lineno, line in enumerate(text.splitlines(), start=1):
            if _is_minified(filepath, line):
                continue
            for pat_id, title, pattern, severity, cwe in patterns:
                for m in pattern.finditer(line):
                    secret_val = m.group(0)
                    safe_evidence = _truncate_evidence(
                        re.sub(re.escape(secret_val), _truncate_secret(secret_val), line),
                        m.start(),
                    )
                    emit_fn({
                        "id": f"SEC-{pat_id}",
                        "title": title,
                        "severity": severity,
                        "source": "whitebox",
                        "category": "secrets",
                        "endpoint": f"{rel}:{lineno}",
                        "evidence": safe_evidence,
                        "fix": (
                            "Remove the hardcoded credential. Store secrets in environment "
                            "variables or a secrets manager (e.g. Vault, AWS Secrets Manager). "
                            "Rotate the exposed credential immediately."
                        ),
                        "references": [cwe],
                        "confidence": "HIGH",
                        "line": f"{rel}:{lineno}",
                    })
