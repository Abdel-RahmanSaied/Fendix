#!/usr/bin/env python3
"""Fendix accuracy harness.

Runs `fendix scan --code corpus/` against the labeled corpus, classifies
each emitted finding as TP/FP/FN against the manifest, and prints a
per-category precision/recall scorecard.

Matching strategy (line-level with a ±2 tolerance):

  - An emitted finding F is considered to match an EXPECT_TP case C if
    F.endpoint references C.file AND F.line is within [C.line - 2,
    C.line + 2] AND F.id starts with one of the category's allowed
    finding-id prefixes.
  - An emitted finding that lands on a TP line counts as a TP.
  - An emitted finding that lands on a TN line counts as an FP.
  - A TP line with no matching finding counts as an FN.
  - An emitted finding on neither (e.g. a line we didn't label)
    counts as an "extra" — not penalised but reported for awareness.

Per-category metrics:
  - precision = TP / (TP + FP)
  - recall    = TP / (TP + FN)
  - F1        = 2 * P * R / (P + R)

The harness is deliberately liberal about which finding IDs count per
category — see manifest.categories.<name>.expected_finding_id_prefixes.
This lets us measure detection at the category level, not the specific
sub-pattern level (which is more brittle and less informative for
end users).

Usage:
    python3 scripts/accuracy/run.py [path/to/fendix-binary]
    # Defaults to ./bin/fendix
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

LINE_TOLERANCE = 6  # +/- lines for finding-to-case matching (covers def-line vs sink-line)

SCRIPT_DIR = Path(__file__).resolve().parent
CORPUS_DIR = SCRIPT_DIR / "corpus"
MANIFEST_PATH = SCRIPT_DIR / "manifest.json"
REPO_ROOT = SCRIPT_DIR.parent.parent


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "binary",
        nargs="?",
        default=str(REPO_ROOT / "bin" / "fendix"),
        help="Path to fendix binary (default: ./bin/fendix)",
    )
    p.add_argument(
        "--python-engine",
        action="store_true",
        help="Pass --python-engine to fendix (needed for AST-based reachable categories)",
    )
    p.add_argument(
        "--output-json",
        default=None,
        help="Optional: write the scorecard as JSON to this path (for CI consumption)",
    )
    p.add_argument(
        "--min-f1",
        type=float,
        default=None,
        help="CI gate: exit non-zero if the OVERALL F1 falls below this floor "
        "(e.g. 0.98). Prevents the published synthetic number from silently drifting.",
    )
    return p.parse_args()


def run_fendix(binary: str, code_path: Path, python_engine: bool) -> dict:
    cmd = [binary, "scan", "--code", str(code_path), "--format", "json"]
    if python_engine:
        cmd.append("--python-engine")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        # 0 = no findings, 1 = findings at threshold (we set no --fail-on, so
        # any non-zero exit other than 1 indicates a binary failure).
        sys.stderr.write(f"fendix exited {proc.returncode}\n")
        sys.stderr.write(proc.stderr)
        sys.exit(2)
    if not proc.stdout.strip():
        sys.stderr.write("fendix produced no stdout — assuming empty report\n")
        return {"findings": []}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"could not parse fendix JSON output: {e}\n")
        sys.stderr.write(proc.stdout[:500])
        sys.exit(2)


def parse_endpoint(endpoint: str) -> tuple[str, int | None]:
    """Split 'corpus/sqli.py:42' into ('corpus/sqli.py', 42)."""
    if ":" not in endpoint:
        return endpoint, None
    file_part, _, line_part = endpoint.rpartition(":")
    try:
        return file_part, int(line_part)
    except ValueError:
        return endpoint, None


def finding_matches_category(finding: dict, spec: dict) -> bool:
    """Match by (category field exact) AND (any title_substring substring).

    The engine renumbers IDs to SEC-NNN at scan-end so we can't match
    on ID prefix; title is preserved. category is the broad bucket
    (e.g. 'injection' covers SQLi + cmdi + path-traversal + …), so we
    need the title substring to disambiguate.
    """
    if finding.get("category", "") != spec.get("expected_category", ""):
        return False
    title = finding.get("title", "")
    return any(s in title for s in spec.get("title_substrings", []))


def explode_findings(findings: list[dict]) -> list[dict]:
    """Yield one virtual finding per affected_endpoint.

    Fendix's dedup pass collapses duplicate (title, category, severity)
    findings across endpoints; affected_endpoints[] preserves the
    original endpoint list. For accuracy scoring we want to match each
    endpoint independently.
    """
    out = []
    for f in findings:
        eps = f.get("affected_endpoints") or [f.get("endpoint", "")]
        for ep in eps:
            virt = dict(f)
            virt["endpoint"] = ep
            out.append(virt)
    return out


def score_category(
    name: str, spec: dict, findings: list[dict]
) -> dict:
    """Compute TP/FP/FN for one category. Returns metrics dict."""
    fixture_file = spec["file"]
    fixture_basename = os.path.basename(fixture_file)
    tp_lines = {entry["line"]: entry for entry in spec.get("tp_lines", [])}
    tn_lines = {entry["line"]: entry for entry in spec.get("tn_lines", [])}

    # Filter findings to this category + this file
    category_findings = []
    for f in findings:
        if not finding_matches_category(f, spec):
            continue
        ep_file, ep_line = parse_endpoint(f.get("endpoint", ""))
        # Fendix can emit endpoints as either "corpus/sqli.py:10" or
        # "sqli.py:10" depending on how --code was passed. Match on the
        # basename for tolerance.
        if not (ep_file.endswith(fixture_file) or os.path.basename(ep_file) == fixture_basename):
            continue
        category_findings.append((ep_line, f))

    matched_tp_lines: set[int] = set()
    fps: list[tuple[int, dict]] = []
    extras: list[tuple[int, dict]] = []

    # Sort emissions by line so we match in source order — gives the
    # CLOSEST unclaimed TP, which is the intuitive pairing.
    for ep_line, f in sorted(category_findings, key=lambda x: x[0] or 0):
        if ep_line is None:
            extras.append((ep_line, f))
            continue
        # Try to match against the NEAREST unclaimed TP line (within
        # tolerance). Earlier version took first-fit which let a single
        # TP be claimed multiple times, leaving other TPs as "missed".
        candidates = [
            (abs(ep_line - tp_line), tp_line)
            for tp_line in tp_lines
            if tp_line not in matched_tp_lines and abs(ep_line - tp_line) <= LINE_TOLERANCE
        ]
        if candidates:
            candidates.sort()
            matched_tp_lines.add(candidates[0][1])
            continue
        # Try to match against a TN line
        matched_tn = None
        for tn_line in tn_lines:
            if abs(ep_line - tn_line) <= LINE_TOLERANCE:
                matched_tn = tn_line
                break
        if matched_tn is not None:
            fps.append((ep_line, f))
            continue
        # Neither — note as extra (not penalised)
        extras.append((ep_line, f))

    tp = len(matched_tp_lines)
    fp = len(fps)
    fn = len(tp_lines) - tp
    tn = len(tn_lines) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    return {
        "category": name,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "missed_lines": sorted(set(tp_lines) - matched_tp_lines),
        "false_positives": [(line, f["id"]) for line, f in fps],
        "extras_count": len(extras),
    }


def render_scorecard(per_category: list[dict]) -> str:
    lines = []
    lines.append(f"{'CATEGORY':<18} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'PREC':>7} {'REC':>7} {'F1':>7}")
    lines.append("-" * 70)
    total_tp = total_fp = total_fn = total_tn = 0
    for row in per_category:
        prec = f"{row['precision']:.3f}" if row["precision"] is not None else "n/a"
        rec = f"{row['recall']:.3f}" if row["recall"] is not None else "n/a"
        f1 = f"{row['f1']:.3f}" if row["f1"] is not None else "n/a"
        lines.append(
            f"{row['category']:<18} "
            f"{row['tp']:>4} {row['fp']:>4} {row['fn']:>4} {row['tn']:>4} "
            f"{prec:>7} {rec:>7} {f1:>7}"
        )
        total_tp += row["tp"]
        total_fp += row["fp"]
        total_fn += row["fn"]
        total_tn += row["tn"]
    lines.append("-" * 70)
    total_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    total_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    total_f1 = (
        2 * total_prec * total_rec / (total_prec + total_rec)
        if (total_prec + total_rec) > 0
        else 0
    )
    lines.append(
        f"{'OVERALL':<18} "
        f"{total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4} "
        f"{total_prec:>7.3f} {total_rec:>7.3f} {total_f1:>7.3f}"
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if not os.access(args.binary, os.X_OK):
        sys.stderr.write(f"binary not executable: {args.binary}\n")
        return 2
    manifest = json.loads(MANIFEST_PATH.read_text())

    print(f"Running {args.binary} scan --code {CORPUS_DIR}...")
    report = run_fendix(args.binary, CORPUS_DIR, args.python_engine)
    raw_findings = report.get("findings", [])
    findings = explode_findings(raw_findings)
    print(f"  {len(raw_findings)} unique findings  ({len(findings)} after exploding affected_endpoints)")
    print()

    per_category = [
        score_category(name, spec, findings)
        for name, spec in manifest["categories"].items()
    ]
    print(render_scorecard(per_category))
    print()

    # Detail: misses + FPs per category
    has_issues = False
    for row in per_category:
        if not row["missed_lines"] and not row["false_positives"]:
            continue
        has_issues = True
        print(f"  {row['category']} detail:")
        if row["missed_lines"]:
            print(f"    missed (FN) lines: {row['missed_lines']}")
        if row["false_positives"]:
            print(f"    false-positive flags:")
            for line, fid in row["false_positives"]:
                print(f"      line {line}: {fid}")
    if not has_issues:
        print("  (no missed cases, no false-positive flags — clean run)")

    # Overall aggregate — the gateable headline number.
    o_tp = sum(r["tp"] for r in per_category)
    o_fp = sum(r["fp"] for r in per_category)
    o_fn = sum(r["fn"] for r in per_category)
    o_prec = o_tp / (o_tp + o_fp) if (o_tp + o_fp) > 0 else 0.0
    o_rec = o_tp / (o_tp + o_fn) if (o_tp + o_fn) > 0 else 0.0
    o_f1 = (2 * o_prec * o_rec / (o_prec + o_rec)) if (o_prec + o_rec) > 0 else 0.0
    overall = {
        "tp": o_tp, "fp": o_fp, "fn": o_fn,
        "precision": o_prec, "recall": o_rec, "f1": o_f1,
    }

    if args.output_json:
        Path(args.output_json).write_text(
            json.dumps(
                {
                    "binary": args.binary,
                    "python_engine": args.python_engine,
                    "overall": overall,
                    "categories": per_category,
                },
                indent=2,
            )
        )
        print(f"\nwrote {args.output_json}")

    # CI gate (opt-in via --min-f1): fail the build if the published synthetic
    # F1 drifts below the floor. This is the guard whose absence let the
    # headline number silently fall from 1.000 to 0.987 (v0.26 MF-1).
    if args.min_f1 is not None and o_f1 < args.min_f1:
        sys.stderr.write(
            f"\nACCURACY GATE FAILED: overall F1 {o_f1:.3f} < floor {args.min_f1:.3f}\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
