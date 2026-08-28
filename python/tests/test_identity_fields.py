"""Every Python-emitted finding must carry the identity the v2 fingerprint keys on.

The end-to-end baseline experiment caught what the Go unit corpus could not:
the Python dependency analyzer emits findings with no rule_id and no
dependency block, so four different CVEs across three different packages
collapsed into ONE identity —

    cat=deps + manifest=requirements.txt

and nothing else. Suppressing one of those findings would have suppressed all
four, silently. Identity can only key on what the emitter actually sends.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.deps import DepsAnalyzer

REQUIREMENTS = """flask==0.12.2
requests==2.19.0
urllib3==1.24.1
"""


def _deps_findings() -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "requirements.txt").write_text(REQUIREMENTS)
        findings: list[dict] = []
        DepsAnalyzer(td).run(findings.append)
        return findings


def _vulnerable(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["severity"] != "INFO"]


def test_dependency_findings_carry_their_advisory_id():
    for f in _vulnerable(_deps_findings()):
        assert f.get("rule_id"), (
            f"no rule_id on {f['title']!r} — identity has no advisory to key on"
        )


def test_dependency_findings_carry_the_package_they_are_about():
    for f in _vulnerable(_deps_findings()):
        dep = f.get("dependency")
        assert dep, f"no dependency block on {f['title']!r}"
        assert dep.get("ecosystem") == "PyPI", f"ecosystem = {dep.get('ecosystem')!r}"
        assert dep.get("package"), f"no package name on {f['title']!r}"
        assert dep.get("version"), f"no version on {f['title']!r}"


def test_distinct_advisories_do_not_share_one_identity():
    """The exact collision the A/B experiment surfaced.

    Four CVEs across three packages must be four identities, not one.
    """
    findings = _vulnerable(_deps_findings())
    assert len(findings) >= 4, f"fixture produced only {len(findings)} findings"

    identities = set()
    for f in findings:
        dep = f.get("dependency") or {}
        identities.add((f.get("rule_id"), dep.get("ecosystem"), dep.get("package")))

    assert len(identities) == len(findings), (
        f"{len(findings)} distinct advisories collapsed into {len(identities)} identities: "
        f"{sorted(identities)}"
    )


def test_unpinned_advisories_are_distinct_from_pinned_ones():
    """An unpinned-dependency advisory is a different claim from a vulnerable
    pin, so it must not share the pinned finding's identity."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "requirements.txt").write_text("flask>=0.10\nrequests==2.19.0\n")
        findings: list[dict] = []
        DepsAnalyzer(td).run(findings.append)

    info = [f for f in findings if f["severity"] == "INFO"]
    assert info, "fixture should produce at least one unpinned advisory"
    for f in info:
        assert f.get("rule_id"), f"no rule_id on unpinned advisory {f['title']!r}"


AST_SOURCE = """
import requests
from flask import request

def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""


def test_ast_findings_carry_an_explicit_rule_id():
    """The AST analyzer's rule identity lived only in the positional-looking
    `id` field. Identity fell back to parsing it, which works only because
    SEC-PY_SSRF happens not to look like the orchestrator's SEC-001 counter —
    too fragile a thing to leave implicit."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "views.py").write_text(AST_SOURCE)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)

    assert findings, "fixture produced no findings"
    for f in findings:
        assert f.get("rule_id"), f"no rule_id on {f['title']!r}"
