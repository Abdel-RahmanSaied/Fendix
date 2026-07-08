"""Labeled accuracy benchmark runner for the fendix Python taint engine.

Loads the labeled corpus (corpus.json), runs every case through the real
ASTAnalyzer in-process, and computes precision / recall / F1 — overall and
per category. Turns "is it more accurate?" from opinion into a tracked number.

Scoring (per case, w.r.t. its `expect` finding id):
  - vulnerable case → engine SHOULD emit `expect`:
        emitted  → true positive (TP)
        missing  → false negative (FN)   [a missed real vuln — recall hit]
  - safe case → engine must NOT emit `expect`:
        emitted  → false positive (FP)   [noise — precision hit]
        missing  → true negative (TN)

  precision = TP / (TP + FP)
  recall    = TP / (TP + FN)
  F1        = 2·P·R / (P + R)

Usage:
    python -m benchmark.run_benchmark            # human-readable table
    python -m benchmark.run_benchmark --json     # machine-readable metrics
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer

CORPUS_PATH = Path(__file__).parent / "corpus.json"


def _findings(code: str) -> list[dict]:
    """Run one code sample through the engine; return its findings."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "case.py").write_text(code)
        out: list[dict] = []
        ASTAnalyzer(tmp).run(out.append)
        return out


def _case_detected(case: dict) -> bool:
    """Did the engine detect this case's expected finding?

    A case tagged ``require_reachable`` only counts when the finding carries a
    proven taint chain (``reachable: true``) — so a conservative "non-constant
    arg → emit" doesn't falsely credit interprocedural/dataflow recall."""
    fs = [f for f in _findings(case["code"]) if f["id"] == case["expect"]]
    if not fs:
        return False
    if case.get("require_reachable"):
        return any(f.get("reachable") for f in fs)
    return True


def evaluate(corpus: list[dict]) -> dict:
    """Run the corpus and return metrics overall + per category.

    Two overall numbers are reported:
      - ``handled`` — excludes cases tagged ``known_gap`` (documented engine
        limitations). This is the REGRESSION GATE: it must stay ~1.0; a drop
        means a real change broke detection.
      - ``honest`` — includes the known-gap cases, so it reflects true accuracy
        against everything we know the engine *should* eventually catch. The gap
        between the two numbers IS the roadmap (interprocedural taint, crypto,
        secrets-in-logs, library RCE sinks).
    """
    cells = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    cells_handled = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    misses: list[dict] = []
    known_gaps: list[dict] = []

    for case in corpus:
        hit = _case_detected(case)
        cat = case["category"]
        is_gap = case.get("known_gap", False)
        if case["label"] == "vulnerable":
            outcome = "tp" if hit else "fn"
        else:
            outcome = "fp" if hit else "tn"

        cells[cat][outcome] += 1
        if not is_gap:
            cells_handled[cat][outcome] += 1

        if is_gap:
            known_gaps.append({**_slim(case), "now_detected": hit})
        elif outcome == "fn":
            misses.append({**_slim(case), "outcome": "false_negative"})
        elif outcome == "fp":
            misses.append({**_slim(case), "outcome": "false_positive"})

    def _total(cellmap):
        t = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for c in cellmap.values():
            for k in t:
                t[k] += c[k]
        return t

    return {
        "handled": _metrics(
            _total(cells_handled)
        ),  # regression gate (excl. known gaps)
        "honest": _metrics(_total(cells)),  # true accuracy (incl. known gaps)
        "per_category": {cat: _metrics(c) for cat, c in sorted(cells.items())},
        "misses": misses,
        "known_gaps": known_gaps,
        "n_cases": len(corpus),
        "n_known_gaps": len(known_gaps),
    }


def _slim(case: dict) -> dict:
    return {"id": case["id"], "category": case["category"], "expect": case["expect"]}


def _metrics(c: dict) -> dict:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def load_corpus() -> list[dict]:
    return json.loads(CORPUS_PATH.read_text())


def _print_table(results: dict) -> None:
    h, hon = results["handled"], results["honest"]
    print(
        f"\nFendix Python-engine accuracy benchmark — {results['n_cases']} labeled cases "
        f"({results['n_known_gaps']} known-gap)\n"
    )
    print(
        f"{'category':10s} {'P':>7} {'R':>7} {'F1':>7}   {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}"
    )
    print("-" * 56)
    for cat, m in results["per_category"].items():
        print(
            f"{cat:10s} {m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:7.3f}   "
            f"{m['tp']:3d} {m['fp']:3d} {m['fn']:3d} {m['tn']:3d}"
        )
    print("-" * 56)
    print(
        f"{'HANDLED':10s} {h['precision']:7.3f} {h['recall']:7.3f} {h['f1']:7.3f}   "
        f"{h['tp']:3d} {h['fp']:3d} {h['fn']:3d} {h['tn']:3d}   (regression gate, excl. known gaps)"
    )
    print(
        f"{'HONEST':10s} {hon['precision']:7.3f} {hon['recall']:7.3f} {hon['f1']:7.3f}   "
        f"{hon['tp']:3d} {hon['fp']:3d} {hon['fn']:3d} {hon['tn']:3d}   (true accuracy, incl. known gaps)"
    )
    if results["misses"]:
        print("\nUnexpected mis-scores (would FAIL the gate):")
        for m in results["misses"]:
            print(f"  {m['outcome']:15s} {m['id']:30s} expect={m['expect']}")
    if results["known_gaps"]:
        print("\nKnown gaps (roadmap — expected miss; flips to detected when fixed):")
        for g in results["known_gaps"]:
            mark = "NOW DETECTED ✓" if g["now_detected"] else "still missed"
            print(f"  {mark:16s} {g['id']:30s} ({g['category']})")
    print()


def main() -> int:
    results = evaluate(load_corpus())
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
    else:
        _print_table(results)
    # --gate: exit non-zero on any HANDLED regression so CI can call this
    # script directly as the synthetic-corpus gate (F1 must stay 1.000; the
    # in-scope FP/FN counts must stay 0; no unexpected mis-scores).
    if "--gate" in sys.argv:
        h = results["handled"]
        failed = (
            h["f1"] != 1.0
            or h["fp"] != 0
            or h["fn"] != 0
            or bool(results["misses"])
        )
        if failed:
            print(
                f"\nGATE FAILED: HANDLED f1={h['f1']} fp={h['fp']} fn={h['fn']} "
                f"misses={len(results['misses'])} (require f1==1.0, fp==0, fn==0, 0 misses)",
                file=sys.stderr,
            )
            return 1
        print("\nGATE OK: HANDLED F1 == 1.000, 0 FP / 0 FN / 0 unexpected misses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
