# Fendix Benchmarks

**Every number on this page is reproducible from this repository.** Each entry
lists the exact command, the corpus, the binary version + date it was captured,
whether it is CI-gated, and the honest caveat. If you can't re-run it, we don't
claim it (Product Constitution Rule 5). Scoring is deterministic Python/Go — no
AI decides a score or a label (Rule 8).

> Captured 2026-06-30 on the binary built from `v0.19.0-41-g17e8937`,
> macOS/arm64, Go 1.x. (v0.26 changed only docs, the Python harness, and CI —
> the scanner binary is unchanged, so these numbers stand for current `main`.)
> Re-run any command below to reproduce. Numbers in the older `docs/accuracy.md`
> are a historical snapshot pinned to **v0.11.0** — this page supersedes them.

---

## 1. Python taint-engine corpus — *the most defensible number, CI-gated*

```
cd python && PYTHONPATH=. python3 benchmark/run_benchmark.py
```

| Metric | Value |
|---|---:|
| Precision | **1.000** |
| Recall | **1.000** |
| F1 | **1.000** |
| Cases | 40 labeled (20 vulnerable / 20 safe), 10 categories |
| Known gaps | 0 (HANDLED == HONEST) |

- **Corpus:** `python/benchmark/corpus.json` (hand-authored, in-repo).
- **CI-gated:** yes — `python/tests/test_benchmark_gate.py` runs on every
  push/PR; a regression fails the build.
- **Caveat:** this measures the interprocedural **taint engine** on a curated
  corpus we control, not detection on arbitrary production code.

---

## 2. SAST synthetic corpus — full binary, end-to-end

```
make build
python3 scripts/accuracy/run.py --python-engine bin/fendix
```

| Metric | Value |
|---|---:|
| Precision | **1.000** |
| Recall | **0.974** |
| F1 | **0.987** |
| True positives | 37 / 38 expected |
| False positives | 0 |
| False negatives | **1** |
| Categories | 7 (sqli, cmdi, path_traversal, ssrf, open_redirect, xss, secrets) |

- **Corpus:** `scripts/accuracy/manifest.json` + `scripts/accuracy/corpus/`
  (56 cases: 38 EXPECT_TP + 18 EXPECT_TN; the binary detects 37 of the 38).
- **Known false negative (disclosed):** one multi-hop SSRF case —
  `target = request.args["x"]; url = "https://" + target; requests.get(url)` —
  is missed because taint does not propagate through the string-concatenation
  `BinOp` into the `requests.get` sink (`scripts/accuracy/corpus/ssrf.py:19`).
  Tracked for a v0.27 taint-engine improvement. We publish 0.987, not a
  rounded-up 1.000.
- **CI-gated:** as of v0.26, on push/PR (see `.github/workflows/`), floor F1 ≥ 0.98.
- **Caveat:** canonical-pattern corpus we author; it measures whether the full
  `fendix scan` binary flags these shapes, not real-world detection rate.

---

## 3. DAST — DVWA + OWASP Juice Shop (black-box HTTP)

```
fendix benchmark run --target all      # requires Docker
```

| Target | Found | Raw FP | Image |
|---|---:|---:|---|
| DVWA | 13 / 13 | 0 | `vulnerables/web-dvwa` |
| OWASP Juice Shop | 12 / 12 | 5 | `bkimminich/juice-shop` (pinned **v17.1.1**) |

- **Source:** committed baseline `benchmarks/baselines/baseline.json`
  (captured `v0.19.0-3-g5d999f6`, 2026-06-28).
- **Caveats (read these):**
  - **"Found" is regression coverage, NOT a detection rate.** Ground truth is
    the set Fendix detects on the **unauthenticated black-box surface**; FN = 0
    *by construction*, so this is not "100% recall" of all DVWA/Juice Shop bugs.
  - **Precision is a lower bound** — there is no labeled negative corpus, so we
    report the **raw false-positive count** (5 on Juice Shop), never an
    FP-*rate*.
  - Authenticated/deep flows (SQLi/XSS/CSRF behind login) are out of this
    target's scope.

---

## 4. govulncheck parity (Go dependency CVEs)

The Go SAST track (`scripts/heavy-eval` stage 4d) grades Fendix against
`govulncheck` — the tool it wraps. This is **tool parity**, not an independent
accuracy measurement, and is labelled as such.

## Additional CI-gated SAST track

`scripts/heavy-eval/run.py` runs a line-anchored, Juliet-**style**
(hand-authored, ~56 labeled cases — *not* NIST SARD Juliet) Python/Go corpus,
gated in `.github/workflows/heavy-eval.yml` at floor **F1 ≥ 0.95**. See that
harness for its current bootstrapped number; it is enforced in CI rather than
re-asserted here.

---

## Not benchmarked yet (honest omissions)

| Item | Why | When |
|---|---|---|
| **OWASP Benchmark** (recall/precision) | It is a **Java** application; Fendix has **no Java analyzer until v0.27**. Running it now yields recall ≈ 0 — a misleading baseline (Rule 5). The target **loud-SKIPs** (`go/internal/benchmark/targets/owasp.go`). | v0.27 (Java analyzer) |
| Competitor head-to-head (Semgrep/ZAP/Bandit) | No published shared-corpus methodology exists; implied superiority without one violates Rule 5. | post-v0.26 |
| Correlation-specific FP reduction | No harness yet isolates the with/without-correlation effect; claims are stated as mechanism, not measured reduction. | post-v0.26 |
| Real-code precision / FP-rate | No labeled negative corpus on real repos yet; DAST precision stays a lower bound. | v0.27 corpus work |

---

*Methodology questions or a number that doesn't reproduce? Open an issue — a
non-reproducing number is a bug.*
