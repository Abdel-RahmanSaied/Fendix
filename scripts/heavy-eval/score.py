"""Scoring for the heavy-eval harness.

Two scoring modes:

  1. line_anchored  — stage 4a (Juliet) + any other target with
     per-line ground truth. Matches the existing Track-1 scorer.

  2. category_counts — stages 4b/4c/4d/4e where we only label
     "this target should produce >=N findings in category C with
     title matching regex R". Used for real codebases where
     hand-labeling every line is impractical.

The aggregate produced by both modes has the same shape so the
final report can stack them.
"""
from __future__ import annotations

import json
import os
import random
import re
from pathlib import Path
from typing import Any

LINE_TOLERANCE = 6
BOOTSTRAP_ITERATIONS = 1000
BOOTSTRAP_SEED = 20260514  # fixed seed for reproducibility


def _safe_div(num: float, den: float) -> float | None:
    return num / den if den > 0 else None


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None:
        return None
    if (p + r) == 0:
        return 0.0
    return 2 * p * r / (p + r)


# ─── shared helpers ─────────────────────────────────────────────────


def parse_endpoint(endpoint: str) -> tuple[str, int | None]:
    if ":" not in endpoint:
        return endpoint, None
    file_part, _, line_part = endpoint.rpartition(":")
    try:
        return file_part, int(line_part)
    except ValueError:
        return endpoint, None


def explode_findings(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        eps = f.get("affected_endpoints") or [f.get("endpoint", "")]
        for ep in eps:
            virt = dict(f)
            virt["endpoint"] = ep
            out.append(virt)
    return out


# ─── line-anchored scoring (stage 4a) ───────────────────────────────


def _finding_matches_category(finding: dict, spec: dict) -> bool:
    if finding.get("category", "") != spec.get("expected_category", ""):
        return False
    title = finding.get("title", "")
    return any(s in title for s in spec.get("title_substrings", []))


def _score_category_line_anchored(name: str, spec: dict, findings: list[dict]) -> dict:
    fixture_file = spec["file"]
    fixture_basename = os.path.basename(fixture_file)
    tp_lines = {entry["line"]: entry for entry in spec.get("tp_lines", [])}
    tn_lines = {entry["line"]: entry for entry in spec.get("tn_lines", [])}

    category_findings = []
    for f in findings:
        if not _finding_matches_category(f, spec):
            continue
        ep_file, ep_line = parse_endpoint(f.get("endpoint", ""))
        if not (ep_file.endswith(fixture_file) or os.path.basename(ep_file) == fixture_basename):
            continue
        category_findings.append((ep_line, f))

    matched_tp_lines: set[int] = set()
    fps: list[tuple[int, dict]] = []
    extras: list[tuple[int, dict]] = []

    for ep_line, f in sorted(category_findings, key=lambda x: x[0] or 0):
        if ep_line is None:
            extras.append((ep_line, f))
            continue
        candidates = [
            (abs(ep_line - tp_line), tp_line)
            for tp_line in tp_lines
            if tp_line not in matched_tp_lines and abs(ep_line - tp_line) <= LINE_TOLERANCE
        ]
        if candidates:
            candidates.sort()
            matched_tp_lines.add(candidates[0][1])
            continue
        matched_tn = None
        for tn_line in tn_lines:
            if abs(ep_line - tn_line) <= LINE_TOLERANCE:
                matched_tn = tn_line
                break
        if matched_tn is not None:
            fps.append((ep_line, f))
            continue
        extras.append((ep_line, f))

    tp = len(matched_tp_lines)
    fp = len(fps)
    fn = len(tp_lines) - tp
    tn = len(tn_lines) - fp

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _f1(precision, recall)

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
        "false_positives": [(line, f.get("id")) for line, f in fps],
        "extras_count": len(extras),
    }


def score_line_anchored(manifest: dict, raw_findings: list[dict]) -> dict:
    findings = explode_findings(raw_findings)
    per_cat = [
        _score_category_line_anchored(name, spec, findings)
        for name, spec in manifest["categories"].items()
    ]
    tp = sum(r["tp"] for r in per_cat)
    fp = sum(r["fp"] for r in per_cat)
    fn = sum(r["fn"] for r in per_cat)
    tn = sum(r["tn"] for r in per_cat)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    ci = _bootstrap_f1_ci(per_cat)
    return {
        "mode": "line_anchored",
        "per_category": per_cat,
        "aggregate": {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "f1_bootstrap_ci_95": ci,
        },
    }


def _bootstrap_f1_ci(per_category: list[dict]) -> dict[str, float | None]:
    """Bootstrap 95% confidence interval on aggregate F1.

    Treats each labeled case (TP-line or TN-line) as a Bernoulli observation:
    a TP-line "succeeds" if the engine flagged it (contributes to TP) and
    "fails" otherwise (FN); a TN-line "succeeds" if the engine left it alone
    (TN) and "fails" otherwise (FP). Resample WITH REPLACEMENT N=1000 times
    and report the 2.5/97.5 percentiles of F1.

    The interval reflects label-level sampling variance — i.e., "if we
    drew a different but similarly-sized labeled corpus, where might F1
    land?". It does NOT reflect engine non-determinism (the engine is
    deterministic across reruns).
    """
    observations: list[tuple[str, bool]] = []
    for cat in per_category:
        for _ in range(cat["tp"]):
            observations.append(("pos", True))    # labeled-positive, engine flagged
        for _ in range(cat["fn"]):
            observations.append(("pos", False))   # labeled-positive, engine missed
        for _ in range(cat["fp"]):
            observations.append(("neg", False))   # labeled-negative, engine flagged
        for _ in range(cat["tn"]):
            observations.append(("neg", True))    # labeled-negative, engine left alone
    if not observations:
        return {"p2_5": None, "p97_5": None, "iterations": 0}

    f1_samples: list[float] = []
    n = len(observations)
    # Local RNG seeded per call: the interval depends ONLY on the observations,
    # not on how much randomness earlier code consumed. Keeps the published CI
    # reproducible even if a second line-anchored target is added later.
    rng = random.Random(BOOTSTRAP_SEED)
    for _ in range(BOOTSTRAP_ITERATIONS):
        # Resample with replacement
        sample = [observations[rng.randrange(n)] for _ in range(n)]
        tp = sum(1 for kind, ok in sample if kind == "pos" and ok)
        fn = sum(1 for kind, ok in sample if kind == "pos" and not ok)
        fp = sum(1 for kind, ok in sample if kind == "neg" and not ok)
        p = _safe_div(tp, tp + fp)
        r = _safe_div(tp, tp + fn)
        f = _f1(p, r)
        if f is not None:
            f1_samples.append(f)
    if not f1_samples:
        return {"p2_5": None, "p97_5": None, "iterations": BOOTSTRAP_ITERATIONS}
    f1_samples.sort()
    lo_idx = int(0.025 * len(f1_samples))
    hi_idx = int(0.975 * len(f1_samples)) - 1
    return {
        "p2_5": f1_samples[lo_idx],
        "p97_5": f1_samples[max(hi_idx, 0)],
        "iterations": BOOTSTRAP_ITERATIONS,
        "samples_used": len(f1_samples),
    }


# ─── category-count scoring (stages 4b/4c/4d/4e) ────────────────────


def score_category_counts(manifest: dict, raw_findings: list[dict]) -> dict:
    """Grade by per-category presence and counts.

    Each expected entry:
        {"category": "injection", "title_re": "SQL",
         "cwe": "CWE-89",        # optional — drives per-CWE aggregate
         "min_count": 1, "max_count": null}

    - hit  = category-matching findings >= min_count and (max_count is None or <= max_count)
    - miss = category-matching findings < min_count (FN)
    - over = category-matching findings > max_count (FP-ish; only when max_count set)

    Anything emitted outside the expected categories is reported as
    "extras" (informational; NOT counted as FP). For real codebases we
    can't enumerate "everything fendix shouldn't say" so we score
    presence/recall instead of precision in the strict sense.
    """
    findings = explode_findings(raw_findings)
    expected = manifest.get("expected", [])
    rows: list[dict[str, Any]] = []

    hits_total = 0
    miss_total = 0
    over_total = 0
    permitted_absent_total = 0
    consumed_finding_idx: set[int] = set()

    for exp in expected:
        cat = exp["category"]
        title_re = re.compile(exp.get("title_re", "."), re.IGNORECASE)
        file_glob = exp.get("file_glob")
        min_count = exp.get("min_count", 1)
        max_count = exp.get("max_count")

        matched: list[tuple[int, dict]] = []
        for i, f in enumerate(findings):
            if i in consumed_finding_idx:
                continue
            if f.get("category", "") != cat:
                continue
            if not title_re.search(f.get("title", "")):
                continue
            if file_glob:
                ep_file, _ = parse_endpoint(f.get("endpoint", ""))
                if not Path(ep_file).match(file_glob):
                    continue
            matched.append((i, f))

        for i, _ in matched:
            consumed_finding_idx.add(i)

        n = len(matched)
        if min_count == 0:
            # "permitted_absent": absence is explicitly allowed, so this row can
            # NEVER miss — counting it as a hit (the old `n >= 0` path) inflated
            # the hit COUNT and let targets whose every row is min_count:0 score
            # a fabricated recall=1.000 (v0.27 MF-4). It is advisory only and
            # excluded from the hits+miss recall denominator. An over-count
            # (> max_count) is still reported as "over".
            if max_count is not None and n > max_count:
                status = "over"
                over_total += 1
            else:
                status = "permitted_absent"
                permitted_absent_total += 1
        elif n >= min_count and (max_count is None or n <= max_count):
            status = "hit"
            hits_total += 1
        elif n < min_count:
            status = "miss"
            miss_total += 1
        else:
            status = "over"
            over_total += 1

        rows.append({
            "category": cat,
            "cwe": exp.get("cwe"),
            "title_re": exp.get("title_re", "."),
            "file_glob": file_glob,
            "min_count": min_count,
            "max_count": max_count,
            "observed_count": n,
            "status": status,
            "sample_titles": [m[1].get("title", "")[:80] for m in matched[:3]],
        })

    extras = [
        {
            "id": f.get("id"),
            "category": f.get("category"),
            "title": f.get("title", "")[:80],
            "endpoint": f.get("endpoint", "")[:120],
        }
        for i, f in enumerate(findings)
        if i not in consumed_finding_idx
    ]

    total = hits_total + miss_total + over_total
    recall_like = _safe_div(hits_total, total) if total else None

    # Per-CWE roll-up: aggregate rows that share a CWE tag.
    cwe_buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        cwe = r.get("cwe") or "UNTAGGED"
        b = cwe_buckets.setdefault(cwe, {"hit": 0, "miss": 0, "over": 0, "permitted_absent": 0})
        b[r["status"]] += 1
    per_cwe = [
        {
            "cwe": cwe,
            "hit": b["hit"],
            "miss": b["miss"],
            "over": b["over"],
            "permitted_absent": b["permitted_absent"],
            "recall": _safe_div(b["hit"], b["hit"] + b["miss"]),
        }
        for cwe, b in sorted(cwe_buckets.items())
    ]

    return {
        "mode": "category_counts",
        "expected_total": total,
        "hits": hits_total,
        "miss": miss_total,
        "over": over_total,
        # permitted_absent: min_count:0 advisory rows — NOT counted toward
        # recall (they can never miss). A target whose rows are ALL
        # permitted_absent has expectation_recall=null, not a fabricated 1.000.
        "permitted_absent": permitted_absent_total,
        "expectation_recall": recall_like,
        "rows": rows,
        "per_cwe": per_cwe,
        "extras_count": len(extras),
        "extras_sample": extras[:25],
    }


# ─── unified entry point ────────────────────────────────────────────


def score(manifest: dict, raw_findings: list[dict]) -> dict:
    if "categories" in manifest:
        return score_line_anchored(manifest, raw_findings)
    if "expected" in manifest:
        return score_category_counts(manifest, raw_findings)
    raise ValueError("manifest must contain 'categories' or 'expected'")


def aggregate_targets(target_results: list[dict]) -> dict:
    """Combine per-target results into a Track-4 headline.

    For line-anchored targets we sum TP/FP/FN/TN. For category-count
    targets we sum hits/miss/over. The headline reports both numbers
    side by side rather than collapsing them into one score — they
    measure different things.
    """
    la_tp = la_fp = la_fn = la_tn = 0
    cc_hits = cc_miss = cc_over = 0
    line_anchored = 0
    cat_count = 0
    for tr in target_results:
        score_obj = tr.get("score")
        if not score_obj:
            continue
        if score_obj["mode"] == "line_anchored":
            line_anchored += 1
            agg = score_obj["aggregate"]
            la_tp += agg["tp"]
            la_fp += agg["fp"]
            la_fn += agg["fn"]
            la_tn += agg["tn"]
        elif score_obj["mode"] == "category_counts":
            cat_count += 1
            cc_hits += score_obj["hits"]
            cc_miss += score_obj["miss"]
            cc_over += score_obj["over"]

    la_prec = _safe_div(la_tp, la_tp + la_fp)
    la_rec = _safe_div(la_tp, la_tp + la_fn)
    la_f1 = _f1(la_prec, la_rec)
    cc_recall = _safe_div(cc_hits, cc_hits + cc_miss)

    return {
        "line_anchored_targets": line_anchored,
        "line_anchored_aggregate": {
            "tp": la_tp, "fp": la_fp, "fn": la_fn, "tn": la_tn,
            "precision": la_prec, "recall": la_rec, "f1": la_f1,
        },
        "category_count_targets": cat_count,
        "category_count_aggregate": {
            "hits": cc_hits, "miss": cc_miss, "over": cc_over,
            "expectation_recall": cc_recall,
        },
    }


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text())
