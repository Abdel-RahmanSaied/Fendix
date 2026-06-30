"""Corpus definitions for the heavy-eval harness (Track 4).

Each stage has a list of TARGETS, where a target is a dict with the
fields the runner needs to materialise it on disk and the scorer needs
to grade it.

Target shape:
    {
        "id":            "py-cve-2020-25032",     # stable identifier
        "kind":          "git",                    # git | docker | local
        "url":           "https://github.com/...", # for kind=git
        "sha":           "<pinned commit>",        # for kind=git (REQUIRED)
        "image":         "owasp/...:tag@sha256:.", # for kind=docker
        "port":          3000,                     # for kind=docker
        "scan":          "code",                   # code | url | both
        "url_path":      "/",                      # for scan=url
        "language":      "python",                 # primary lang
        "labels_file":   "labels/py-cve-...json",  # relative to scripts/heavy-eval/
        "notes":         "CVE-2020-25032 ...",
    }

Labels file shape (per-target ground truth):
    {
        "target_id":   "py-cve-2020-25032",
        "source":      "CVE / OWASP-Top-10 / NIST-Juliet / ...",
        "expected": [
            {"category": "injection", "title_re": "SQL", "file_glob": "app/db.py", "min_count": 1},
            ...
        ],
        "category_caps": {            # optional per-category cap to avoid runaway-FP scoring
            "headers_missing": 50      # >50 missing-header hits across a real codebase counts as 50
        }
    }

Stages:
    4a   Juliet-STYLE Python labeled corpus (hand-authored; NOT NIST SARD —
         see note below — Juliet-shape good/bad pairs we wrote ourselves)
    4b   CVE-anchored Python repos
    4c   CVE-anchored Node repos
    4d   CVE-anchored Go repos
    4e   DAST targets (containerised vulnerable web apps)
    4f   Performance profile (no new targets — re-runs prior stages)

Honest scope notes (read these before reading the numbers):

    - This is a Juliet-STYLE corpus, NOT NIST SARD. NIST's Juliet test
      suite covers Java/C/C++ only — there is no official NIST Python
      Juliet subset (see stage 4a's second target note). Stage 4a is
      hand-authored good/bad pairs in the Juliet SHAPE for the
      categories fendix supports. The "thousands of samples" framing
      applies only to Java SAST tools like the OWASP Benchmark.
    - CVE-anchored real repos are hand-curated: each one points at a
      specific vulnerable SHA + the CVE description + the file(s)
      that hold the sink. Hand-curation is why this stage is ~30
      targets instead of 300 — every label costs ~10 min of human
      review.
    - DAST targets pull pinned docker images. The expected-finding
      catalog is OWASP-class-level ("juice-shop should surface at
      least one missing-security-headers finding"), NOT line-level.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

HEAVY_DIR = Path(__file__).resolve().parent
CACHE_DIR = HEAVY_DIR / "corpus-cache"
LABELS_DIR = HEAVY_DIR / "labels"


# ─── Stage 4a — Juliet-STYLE Python (hand-authored, NOT NIST SARD) ────
#
# NIST SARD's Juliet suite is Java/C/C++ only — it has no Python subset.
# So this is a hand-authored corpus in the Juliet SHAPE: labeled
# good/bad pairs for the canonical CWEs fendix is supposed to detect
# (taint-chain SQLi/cmdi/path-traversal/SSRF/XSS/open-redirect +
# secrets). Cases are standalone .py files in labels/juliet-python/ so
# we can score with line-level precision exactly like Track 1 does. We
# call it "Juliet-style" everywhere, never "NIST Juliet", so the name
# can't imply an external benchmark we don't actually run.
JULIET_PYTHON: list[dict[str, Any]] = [
    {
        "id": "juliet-python",
        "kind": "local",
        "path": "labels/juliet-python",      # rel to HEAVY_DIR
        "scan": "code",
        "language": "python",
        "labels_file": "labels/juliet-python.json",
        "notes": "Juliet-style Python labeled good/bad pairs (hand-authored, not NIST SARD)",
    },
    {
        # NIST SARD has no Python suite (Java/C/C++ only) — bandit's
        # examples/ tree is the closest publicly-curated authoritative
        # labeled corpus for Python SAST. 91 files covering the full
        # surface fendix targets (taint sinks + secrets + deser + xss).
        "id": "bandit-examples",
        "kind": "git",
        "url": "https://github.com/PyCQA/bandit.git",
        "sha": "8309bc39605ef3e78eb5ec85096eb638bff1b025",  # captured 2026-05-14
        "code_subpath": "examples",
        "scan": "code",
        "language": "python",
        "labels_file": "labels/bandit-examples.json",
        "notes": "PyCQA/bandit examples/ — 91 hand-labeled Python files by the bandit maintainers; used as an external cross-validator for Track 4a",
    },
]


# ─── Stage 4b — CVE-anchored Python repos ────────────────────────────
#
# Each entry is pinned at the vulnerable SHA. The harness clones at
# depth=1 and checks out the SHA into corpus-cache/<id>/. Labels point
# at the file(s) that hold the sink and the expected category.
#
# We deliberately mix small (~1 KLOC) and large (~50 KLOC) repos so
# the perf profile (stage 4f) can plot scan-time vs codebase size.
PYTHON_CVE_REPOS: list[dict[str, Any]] = [
    {
        "id": "py-pygoat",
        "kind": "git",
        "url": "https://github.com/adeyosemanputra/pygoat.git",
        "sha": "19d17cc8874861142b330636d068bbde54e86b85",  # captured 2026-05-14
        "scan": "code",
        "language": "python",
        "labels_file": "labels/py-pygoat.json",
        "notes": "OWASP-Top-10 Django demo with deliberate vulns",
    },
    {
        "id": "py-dvpwa",
        "kind": "git",
        "url": "https://github.com/anxolerd/dvpwa.git",
        "sha": "a1d8f89fac2e57093189853c6527c2b01fc1d9c1",  # captured 2026-05-14
        "scan": "code",
        "language": "python",
        "labels_file": "labels/py-dvpwa.json",
        "notes": "Damn Vulnerable Python Web App — async aiohttp app with SQLi/XSS/CSRF/IDOR",
    },
    {
        "id": "py-vulpy",
        "kind": "git",
        "url": "https://github.com/fportantier/vulpy.git",
        "sha": "5249cc8b05a1c37f6b2f757b1cf16a509c327122",  # captured 2026-05-14
        "scan": "code",
        "language": "python",
        "labels_file": "labels/py-vulpy.json",
        "notes": "vulpy — vulnerable Flask app for OWASP exercises (sqli, xss, path-traversal, cmdi)",
    },
    {
        "id": "py-django-vuln",
        "kind": "git",
        "url": "https://github.com/nVisium/django.nV.git",
        "sha": "a48901f106da4888417339b7b44b8ed56b64c63f",  # captured 2026-05-14
        "scan": "code",
        "language": "python",
        "labels_file": "labels/py-django-nV.json",
        "notes": "Django.nV — vulnerable Django training app from nVisium",
    },
    {
        "id": "py-flask-vuln",
        "kind": "git",
        "url": "https://github.com/we45/Vulnerable-Flask-App.git",
        "sha": "b6a4f97afd466e83e1f60781494252dec1c37039",  # captured 2026-05-14
        "scan": "code",
        "language": "python",
        "labels_file": "labels/py-flask-vuln.json",
        "notes": "we45/Vulnerable-Flask-App — Flask app with SQLi/XSS/SSRF/cmdi",
    },
]


# ─── Stage 4c — CVE-anchored Node repos ──────────────────────────────
NODE_CVE_REPOS: list[dict[str, Any]] = [
    {
        "id": "node-nodegoat",
        "kind": "git",
        "url": "https://github.com/OWASP/NodeGoat.git",
        "sha": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",  # captured 2026-05-14
        "scan": "code",
        "language": "javascript",
        "labels_file": "labels/node-nodegoat.json",
        "notes": "OWASP NodeGoat — express app with OWASP Top-10 vulns",
    },
    {
        "id": "node-juice-shop-src",
        "kind": "git",
        "url": "https://github.com/juice-shop/juice-shop.git",
        "sha": "39b46860612990ae18d499a20472172839fe8c77",  # tag v17.1.1, captured 2026-05-14
        "scan": "code",
        "language": "javascript",
        "labels_file": "labels/node-juice-shop.json",
        "notes": "Juice Shop source @ v17.1.1 — same image we DAST-scan; SAST view of the same surface",
    },
    {
        "id": "node-dvna",
        "kind": "git",
        "url": "https://github.com/appsecco/dvna.git",
        "sha": "9ba473add536f66ac9007966acb2a775dd31277a",  # captured 2026-05-14
        "scan": "code",
        "language": "javascript",
        "labels_file": "labels/node-dvna.json",
        "notes": "Damn Vulnerable Node App",
    },
    {
        "id": "node-vulnerable-app",
        "kind": "git",
        "url": "https://github.com/SasanLabs/VulnerableApp-facade.git",
        "sha": "6a025cdf5f1d489176334d432c66ff46d2b84625",  # captured 2026-05-14
        "scan": "code",
        "language": "javascript",
        "labels_file": "labels/node-vulnerableapp-facade.json",
        "notes": "SasanLabs VulnerableApp-facade — JS UI for the multi-language vuln corpus",
    },
]


# ─── Stage 4d — CVE-anchored Go repos ────────────────────────────────
#
# These exist to exercise fendix's native dep-CVE scanner (TASK-119,
# govulncheck-based). The "label" is the set of CVEs govulncheck
# itself reports — we use govulncheck as the oracle for what's
# *reachable* in the codebase, and check that fendix surfaces the
# same CVEs (modulo reachability differences when the call graph
# proves the sink is unreachable from main()).
GO_CVE_REPOS: list[dict[str, Any]] = [
    {
        "id": "go-vulnerable-module",
        "kind": "local",
        "path": "labels/go-vulnerable-module",      # tiny generated module that imports known-vulnerable deps
        "scan": "code",
        "language": "go",
        "labels_file": "labels/go-vulnerable-module.json",
        "notes": "Generated tiny Go module with deliberately-vulnerable transitive deps (govulncheck oracle)",
    },
    {
        "id": "go-vulnerable-app",
        "kind": "git",
        "url": "https://github.com/securego/gosec.git",
        "sha": "de65614d10a6b84029e3e1215567b8ce7e490f23",  # captured 2026-05-14
        "scan": "code",
        "language": "go",
        "labels_file": "labels/go-gosec-corpus.json",
        "notes": "gosec's own test corpus — exercises many Go SAST patterns",
    },
]


# ─── Stage 4e — DAST targets (containerised vulnerable web apps) ─────
DAST_TARGETS: list[dict[str, Any]] = [
    {
        "id": "dast-juice-shop",
        "kind": "docker",
        "image": "bkimminich/juice-shop:v17.1.1",
        "port": 3000,
        "host_port": 13000,
        "scan": "url",
        "url_path": "/",
        "labels_file": "labels/dast-juice-shop.json",
        "notes": "Juice Shop v17.1.1 — Track 2 baseline; re-graded here against OWASP class labels",
        "boot_wait_sec": 60,
    },
    {
        "id": "dast-dvwa",
        "kind": "docker",
        "image": "vulnerables/web-dvwa:latest",
        "port": 80,
        "host_port": 8081,
        "scan": "url",
        "url_path": "/login.php",
        "labels_file": "labels/dast-dvwa.json",
        "notes": "Damn Vulnerable Web App — classic PHP vuln playground",
        "boot_wait_sec": 30,
    },
    {
        "id": "dast-webgoat",
        "kind": "docker",
        "image": "webgoat/webgoat:latest",
        "port": 8080,
        "host_port": 8082,
        "scan": "url",
        "url_path": "/WebGoat",
        "labels_file": "labels/dast-webgoat.json",
        "notes": "OWASP WebGoat — Java training app",
        "boot_wait_sec": 90,
    },
    {
        "id": "dast-bwapp",
        "kind": "docker",
        "image": "raesene/bwapp:latest",
        "port": 80,
        "host_port": 8083,
        "scan": "url",
        "url_path": "/install.php",
        "labels_file": "labels/dast-bwapp.json",
        "notes": "bWAPP — buggy web app w/ 100+ vulns",
        "boot_wait_sec": 30,
    },
    {
        "id": "dast-vulnerableapp",
        "kind": "docker",
        "image": "sasanlabs/owasp-vulnerableapp:latest",
        "port": 9090,
        "host_port": 9090,
        "scan": "url",
        "url_path": "/",
        "labels_file": "labels/dast-vulnerableapp.json",
        "notes": "SasanLabs VulnerableApp — modern multi-vuln target",
        "boot_wait_sec": 120,
    },
]


# ─── Master registry ─────────────────────────────────────────────────
STAGES: dict[str, list[dict[str, Any]]] = {
    "4a": JULIET_PYTHON,
    "4b": PYTHON_CVE_REPOS,
    "4c": NODE_CVE_REPOS,
    "4d": GO_CVE_REPOS,
    "4e": DAST_TARGETS,
}

STAGE_DESCRIPTIONS: dict[str, str] = {
    "4a": "Juliet Python (NIST SARD curated subset, labeled good/bad)",
    "4b": "CVE-anchored Python repos (real codebases pinned at vulnerable SHAs)",
    "4c": "CVE-anchored Node repos (real codebases pinned at vulnerable SHAs)",
    "4d": "CVE-anchored Go repos (govulncheck-oracle for dep-CVE scanner)",
    "4e": "DAST targets (containerised vulnerable web apps)",
    "4f": "Performance profile (p50/p95/p99 + RSS + cold/warm across all targets)",
}


def all_stages() -> list[str]:
    return ["4a", "4b", "4c", "4d", "4e", "4f"]


def fast_stages() -> list[str]:
    """Stages that don't need docker or the long perf sweep.

    Useful for CI smoke runs: ~5 min wall-clock vs ~2 hrs for the
    full set."""
    return ["4a", "4b", "4c", "4d"]


def targets_for(stage: str) -> list[dict[str, Any]]:
    return STAGES.get(stage, [])
