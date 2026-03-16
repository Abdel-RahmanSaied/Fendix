#!/usr/bin/env python3
"""Fendix Python Engine.

Reads a ScanRequest JSON from stdin, runs white-box analyzers,
and streams Finding JSON objects to stdout (one per line).
Terminates with {"done": true, "total": N}.

Usage:
    echo '{"mode":"whitebox","code_path":"./src","checks":["secrets"]}' | python engine.py
"""
import json
import sys
from typing import Callable


def _log(msg: str) -> None:
    """Write a diagnostic message to stderr (never stdout)."""
    print(f"[fendix-engine] {msg}", file=sys.stderr, flush=True)


def emit(finding: dict) -> None:
    """Write a single finding as a JSON line to stdout."""
    print(json.dumps(finding), flush=True)


def _run_check(name: str, fn: Callable[[], None], verbose: bool) -> None:
    """Run a single check function, catching and logging any exceptions."""
    try:
        if verbose:
            _log(f"starting check: {name}")
        fn()
        if verbose:
            _log(f"finished check: {name}")
    except Exception as exc:  # noqa: BLE001
        _log(f"check '{name}' failed: {exc}")


def main() -> None:
    """Entry point: read ScanRequest from stdin, run checks, emit findings."""
    try:
        raw = sys.stdin.read()
        request = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        _log(f"invalid ScanRequest JSON: {exc}")
        print(json.dumps({"done": True, "total": 0, "error": str(exc)}), flush=True)
        sys.exit(2)

    checks = request.get("checks", [])
    code_path = request.get("code_path", "")
    spec_path = request.get("spec", "")
    language = request.get("language")
    verbose = bool(request.get("verbose", False))

    counter = 0

    def emit_finding(f: dict) -> None:
        nonlocal counter
        counter += 1
        emit(f)

    if "secrets" in checks and code_path:
        from analyzers.secrets import SecretsAnalyzer

        _run_check("secrets", lambda: SecretsAnalyzer(code_path).run(emit_finding), verbose)

    if "auth" in checks and spec_path:
        from analyzers.spec_parser import SpecParser

        _run_check("auth (spec)", lambda: SpecParser(spec_path).check_auth(emit_finding), verbose)

    if "semgrep" in checks and code_path:
        from analyzers.semgrep_runner import SemgrepRunner

        _run_check(
            "semgrep",
            lambda: SemgrepRunner(code_path, language).run(emit_finding),
            verbose,
        )

    if "injection" in checks and code_path:
        from analyzers.ast_analyzer import ASTAnalyzer

        _run_check(
            "injection (ast)",
            lambda: ASTAnalyzer(code_path, language or "python").run(emit_finding),
            verbose,
        )

    if "deps" in checks and code_path:
        from analyzers.deps import DepsAnalyzer

        _run_check("deps", lambda: DepsAnalyzer(code_path).run(emit_finding), verbose)

    if verbose:
        _log(f"engine completed {counter} findings")

    print(json.dumps({"done": True, "total": counter}), flush=True)


if __name__ == "__main__":
    main()
