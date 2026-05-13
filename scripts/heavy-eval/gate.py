#!/usr/bin/env python3
"""CI quality gates for the heavy-eval harness.

Reads a results directory (bench-results/heavy/<UTC-ISO>/) and exits
non-zero if any gate fails:

  G1  Stage 4a Juliet F1 >= 0.90
  G2  Stage 4a bandit-examples expectation_recall >= 0.85
  G3  Stages 4b/4c/4d aggregate expectation_recall >= 0.90 (if present)

The gates are deliberately set just BELOW the current measured numbers,
so the first regression is what trips them — not random run-to-run jitter.
Bump these in lockstep with engine improvements.

Run locally:
    python3 scripts/heavy-eval/gate.py bench-results/heavy/2026-05-14T00-00-00Z

Exit codes:
    0  all gates pass (or input has no scored stages — vacuous pass)
    1  at least one gate failed
    2  results dir missing or unreadable
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


JULIET_F1_FLOOR = 0.95               # bumped after Phase 2 engine fixes (F1 = 0.987)
BANDIT_RECALL_FLOOR = 0.95           # bumped after Phase 2 engine fixes (10/10)
SAST_REAL_REPO_RECALL_FLOOR = 0.95   # bumped after Phase 2 engine fixes (1.000)


def _load(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: gate.py <results-dir>", file=sys.stderr)
        return 2
    results_dir = Path(argv[1])
    if not results_dir.is_dir():
        print(f"results dir not found: {results_dir}", file=sys.stderr)
        return 2

    stage_4a = _load(results_dir / "stage-4a.json")
    stage_4b = _load(results_dir / "stage-4b.json")
    stage_4c = _load(results_dir / "stage-4c.json")
    stage_4d = _load(results_dir / "stage-4d.json")

    failed: list[str] = []
    passed: list[str] = []

    # G1: Juliet F1
    if stage_4a is not None:
        juliet_f1 = None
        for t in stage_4a.get("targets", []):
            if t.get("target_id") == "juliet-python":
                sc = t.get("score") or {}
                juliet_f1 = (sc.get("aggregate") or {}).get("f1")
                break
        if juliet_f1 is None:
            failed.append("G1 Juliet F1: not measured (no juliet-python target in stage-4a.json)")
        elif juliet_f1 < JULIET_F1_FLOOR:
            failed.append(f"G1 Juliet F1: {juliet_f1:.3f} < floor {JULIET_F1_FLOOR}")
        else:
            passed.append(f"G1 Juliet F1: {juliet_f1:.3f} >= {JULIET_F1_FLOOR}")

        # G2: bandit-examples cat-recall
        bandit_recall = None
        for t in stage_4a.get("targets", []):
            if t.get("target_id") == "bandit-examples":
                sc = t.get("score") or {}
                bandit_recall = sc.get("expectation_recall")
                break
        if bandit_recall is None:
            failed.append("G2 bandit-examples recall: not measured")
        elif bandit_recall < BANDIT_RECALL_FLOOR:
            failed.append(f"G2 bandit-examples recall: {bandit_recall:.3f} < floor {BANDIT_RECALL_FLOOR}")
        else:
            passed.append(f"G2 bandit-examples recall: {bandit_recall:.3f} >= {BANDIT_RECALL_FLOOR}")

    # G3: aggregate over 4b/4c/4d
    hits = miss = 0
    for stage in (stage_4b, stage_4c, stage_4d):
        if stage is None:
            continue
        for t in stage.get("targets", []):
            sc = t.get("score")
            if sc is None or sc.get("mode") != "category_counts":
                continue
            hits += sc.get("hits", 0)
            miss += sc.get("miss", 0)
    if hits + miss > 0:
        recall = hits / (hits + miss)
        if recall < SAST_REAL_REPO_RECALL_FLOOR:
            failed.append(f"G3 4b+4c+4d aggregate recall: {recall:.3f} < floor {SAST_REAL_REPO_RECALL_FLOOR} ({hits}/{hits+miss})")
        else:
            passed.append(f"G3 4b+4c+4d aggregate recall: {recall:.3f} >= {SAST_REAL_REPO_RECALL_FLOOR} ({hits}/{hits+miss})")

    print("=== heavy-eval gates ===")
    for line in passed:
        print(f"  \033[32mPASS\033[0m {line}")
    for line in failed:
        print(f"  \033[31mFAIL\033[0m {line}")
    print()
    if failed:
        print(f"\033[31m{len(failed)} gate(s) failed\033[0m")
        return 1
    print(f"\033[32mall {len(passed)} gate(s) passed\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
