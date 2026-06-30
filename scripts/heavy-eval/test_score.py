"""Tests for the heavy-eval scorer — v0.27 MF-4 (min_count:0 recall honesty).

Run: cd scripts/heavy-eval && python3 -m pytest test_score.py -q
"""
from score import score_category_counts


def _find(cat, title, ep="app.py:1"):
    return {"category": cat, "title": title, "endpoint": ep}


def test_min_count_zero_is_permitted_absent_not_a_hit():
    # One real expectation (detected) + one min_count:0 advisory (absent).
    manifest = {
        "expected": [
            {"category": "sqli", "title_re": "SQL", "min_count": 1},
            {"category": "ssrf", "title_re": "SSRF", "min_count": 0},
        ]
    }
    findings = [_find("sqli", "SQL injection")]  # ssrf absent
    r = score_category_counts(manifest, findings)
    assert r["hits"] == 1
    assert r["miss"] == 0
    assert r["permitted_absent"] == 1          # the min_count:0 row, NOT a hit
    assert r["expectation_recall"] == 1.0      # over the 1 real row only


def test_all_permitted_absent_recall_is_undefined_not_one():
    # Every row min_count:0 and nothing detected — must NOT fabricate 1.000.
    manifest = {
        "expected": [
            {"category": "a", "title_re": ".", "min_count": 0},
            {"category": "b", "title_re": ".", "min_count": 0},
        ]
    }
    r = score_category_counts(manifest, [])
    assert r["hits"] == 0
    assert r["permitted_absent"] == 2
    assert r["expectation_recall"] is None     # undefined, not 1.0 (MF-4 fix)


def test_real_miss_still_counts():
    manifest = {"expected": [{"category": "sqli", "title_re": "SQL", "min_count": 1}]}
    r = score_category_counts(manifest, [])    # expected but absent
    assert r["hits"] == 0
    assert r["miss"] == 1
    assert r["expectation_recall"] == 0.0
