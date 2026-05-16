#!/usr/bin/env python3
"""Score a SAST tool's output against the fixture manifest.

Each supported tool emits JSON in a different shape:

- fendix: {"findings": [{"endpoint": "path:line", ...}, ...]}
- semgrep: {"results": [{"start": {"line": N}, "path": "..."}, ...]}
- bandit: {"results": [{"line_number": N, "filename": "..."}, ...]}

We don't care about the rule that fired — only that *some* finding
landed on a manifest-labeled TP line (counts as a hit) or on a
manifest-labeled TN line (counts as a false positive). Findings on
lines NOT in either set are ignored (they're typically style /
import-hygiene rules that aren't part of the benchmark scope).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Iterable


def fendix_lines(report: dict) -> Iterable[int]:
    """Yield line numbers from a `fendix scan --format json` payload.

    fendix encodes location as "path:line" in .endpoint AND mirrors it
    into .line for findings that have a line. We tolerate either field
    being missing; ":" inside the path means we look for the LAST ":".
    """
    for f in report.get("findings", []):
        loc = f.get("line") or f.get("endpoint") or ""
        if isinstance(loc, str) and ":" in loc:
            try:
                yield int(loc.rsplit(":", 1)[1])
            except ValueError:
                continue


def semgrep_lines(report: dict) -> Iterable[int]:
    for r in report.get("results", []):
        start = r.get("start", {}) or {}
        line = start.get("line")
        if isinstance(line, int):
            yield line


def bandit_lines(report: dict) -> Iterable[int]:
    for r in report.get("results", []):
        line = r.get("line_number")
        if isinstance(line, int):
            yield line


PARSERS = {
    "fendix": fendix_lines,
    "semgrep": semgrep_lines,
    "bandit": bandit_lines,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True, choices=list(PARSERS))
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output", required=True, help="Tool's stdout/JSON file")
    args = ap.parse_args()

    manifest = json.loads(pathlib.Path(args.manifest).read_text("utf-8"))
    tp_set = set(manifest.get("tp_lines", []))
    tn_set = set(manifest.get("tn_lines", []))

    try:
        raw = pathlib.Path(args.output).read_text("utf-8")
    except OSError as e:
        print(f"# score.py: read {args.output}: {e}", file=sys.stderr)
        print("TP=NA FP=NA")
        return 0
    if not raw.strip():
        # Empty output is a legitimate "found nothing" — TP=0, FP=0.
        print("TP=0 FP=0")
        return 0
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"# score.py: JSON decode failed: {e}", file=sys.stderr)
        print("TP=NA FP=NA")
        return 0

    hit_tp_lines: set[int] = set()
    hit_fp_lines: set[int] = set()
    for line in PARSERS[args.tool](report):
        if line in tp_set:
            hit_tp_lines.add(line)
        elif line in tn_set:
            hit_fp_lines.add(line)
        # else: ignored — outside the labeled-line set.

    print(f"TP={len(hit_tp_lines)} FP={len(hit_fp_lines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
