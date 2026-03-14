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


def emit(finding: dict) -> None:
    """Write a single finding as a JSON line to stdout."""
    print(json.dumps(finding), flush=True)


def main() -> None:
    """Entry point: read ScanRequest, run checks, emit findings."""
    raw = sys.stdin.read()
    request = json.loads(raw)

    checks = request.get("checks", [])
    counter = 0

    def emit_finding(f: dict) -> None:
        nonlocal counter
        counter += 1
        emit(f)

    if "secrets" in checks and request.get("code_path"):
        from analyzers.secrets import SecretsAnalyzer

        SecretsAnalyzer(request["code_path"]).run(emit_finding)

    if "semgrep" in checks and request.get("code_path"):
        from analyzers.semgrep_runner import SemgrepRunner

        SemgrepRunner(request["code_path"], request.get("language")).run(emit_finding)

    if "auth" in checks and request.get("spec"):
        from analyzers.spec_parser import SpecParser

        SpecParser(request["spec"]).check_auth(emit_finding)

    if request.get("verbose"):
        print(
            json.dumps({"log": f"Python engine completed {counter} findings"}),
            flush=True,
        )

    print(json.dumps({"done": True, "total": counter}), flush=True)


if __name__ == "__main__":
    main()
