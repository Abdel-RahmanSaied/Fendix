"""Regression gate on the labeled accuracy benchmark.

The HANDLED metrics (excluding documented known-gaps) must stay perfect: any
in-scope false positive or false negative is a real regression and fails CI.
The HONEST recall is asserted at its current floor so a *new* missed category
is caught, while the known roadmap gaps don't fail the build.

Run the full report with:  python -m benchmark.run_benchmark
"""

from __future__ import annotations

from benchmark.run_benchmark import evaluate, load_corpus


def _results():
    return evaluate(load_corpus())


def test_handled_precision_and_recall_perfect():
    # In-scope behavior must be exact — no FP, no FN on handled patterns.
    h = _results()["handled"]
    assert h["fp"] == 0, f"in-scope false positives: {h['fp']}"
    assert h["fn"] == 0, f"in-scope false negatives: {h['fn']}"
    assert h["f1"] == 1.0


def test_no_unexpected_misscores():
    # `misses` only ever contains non-known-gap mis-scores; must be empty.
    assert _results()["misses"] == []


def test_honest_recall_floor():
    # True recall (incl. known gaps) must not drop below the recorded floor —
    # catches a NEW category becoming undetected. Raise this when gaps close.
    hon = _results()["honest"]
    assert hon["precision"] == 1.0, f"precision regressed: {hon['precision']}"
    assert hon["recall"] >= 0.80, f"honest recall regressed: {hon['recall']}"


def test_corpus_has_both_labels_per_category():
    # A category with only-vulnerable or only-safe cases can't measure both
    # precision and recall — guard the corpus stays balanced enough.
    corpus = load_corpus()
    assert len(corpus) >= 30
    assert sum(1 for c in corpus if c["label"] == "vulnerable") >= 10
    assert sum(1 for c in corpus if c["label"] == "safe") >= 10
