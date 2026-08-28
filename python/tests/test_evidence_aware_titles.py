"""RC-6: a finding's title must never claim evidence stronger than it holds.

The analyzer already knows the difference — it downgrades confidence when a
reachability-dependent sink has no proven source->sink path — but the title is
passed in as one fixed string, so the same words are printed either way. A
chainless path-traversal match therefore reported "user input flows to
filesystem path" while asserting nothing of the kind, and a PROVEN SSRF
reported "Potential SSRF" while holding a complete taint chain.

The invariant under test: the wording of a finding is a function of the
evidence that finding carries.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer


def _analyze(source: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "views.py"
        target.write_text(source)
        findings: list[dict] = []
        ASTAnalyzer(str(td)).run(findings.append)
        return findings


def _one(findings: list[dict], finding_id: str) -> dict:
    matches = [f for f in findings if f["id"] == finding_id]
    assert matches, f"expected a {finding_id} finding, got {[f['id'] for f in findings]}"
    return matches[0]


# --- claims that outran the evidence ------------------------------------

SINK_ONLY_PATH = """
def read_report(name):
    # No request source anywhere: the argument is whatever the caller passes.
    return open(name).read()
"""

PROVEN_PATH = """
from flask import request

def read_report():
    name = request.args.get("name")
    return open(name).read()
"""


def test_sink_only_path_traversal_does_not_claim_a_flow():
    f = _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert "user input flows to" not in f["title"], (
        f"title claims a proven flow the finding does not hold: {f['title']!r}"
    )
    assert "user-controlled" not in f["title"], (
        f"title asserts user control that was never established: {f['title']!r}"
    )


def test_proven_path_traversal_states_the_flow():
    f = _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert f.get("taint_chain"), "fixture is meant to prove a source->sink path"
    assert "Potential" not in f["title"], (
        f"a proven taint path is not 'potential': {f['title']!r}"
    )


SINK_ONLY_SSRF = """
import requests

def fetch(url):
    return requests.get(url)
"""

PROVEN_SSRF = """
import requests
from flask import request

def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""


def test_sink_only_ssrf_is_marked_potential():
    f = _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert f["title"].startswith("Potential"), (
        f"a sink-only observation must be hedged: {f['title']!r}"
    )


def test_proven_ssrf_drops_the_hedge():
    f = _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF")
    assert f.get("taint_chain"), "fixture is meant to prove a source->sink path"
    assert not f["title"].startswith("Potential"), (
        f"a proven source->sink path is no longer merely potential: {f['title']!r}"
    )
    assert "user-controlled" in f["title"], (
        f"a proven flow should say so plainly: {f['title']!r}"
    )


SINK_ONLY_REDIRECT = """
from flask import redirect

def go(target):
    return redirect(target)
"""


def test_sink_only_open_redirect_does_not_claim_user_control():
    f = _one(_analyze(SINK_ONLY_REDIRECT), "SEC-PY_OPEN_REDIRECT")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert "user-controlled" not in f["title"], (
        f"title asserts user control that was never established: {f['title']!r}"
    )


# --- the vocabulary is consistent, not per-rule improvisation -----------

def test_hedged_and_proven_titles_are_drawn_from_one_vocabulary():
    """Every reachability-dependent family hedges the same way.

    A reader scanning a report should be able to tell proven from observed at
    a glance, which only works if the marker is the same word everywhere.
    """
    chainless = [
        _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF"),
        _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL"),
        _one(_analyze(SINK_ONLY_REDIRECT), "SEC-PY_OPEN_REDIRECT"),
    ]
    for f in chainless:
        assert f["title"].startswith("Potential "), (
            f"{f['id']} hedges differently from its siblings: {f['title']!r}"
        )

    proven = [
        _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF"),
        _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL"),
    ]
    for f in proven:
        assert not f["title"].startswith("Potential "), (
            f"{f['id']} still hedges despite a proven chain: {f['title']!r}"
        )


def test_retitling_does_not_change_the_finding_identity_inputs():
    """RC-6 must not undo RC-5.

    Identity is keyed on rule, file, symbol and sink — never on the title —
    so the hedged and proven forms of one finding differ in wording and in
    nothing that identity reads.
    """
    sink_only = _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF")
    proven = _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF")

    assert sink_only["title"] != proven["title"], "fixtures should differ in wording"
    assert sink_only["id"] == proven["id"], "the rule identity must not move with the title"
    assert sink_only["category"] == proven["category"]
