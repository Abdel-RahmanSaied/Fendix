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
| Recall | **1.000** |
| F1 | **1.000** |
| True positives | 38 / 38 expected |
| False positives | 0 |
| False negatives | 0 |
| Categories | 7 (sqli, cmdi, path_traversal, ssrf, open_redirect, xss, secrets) |

- **Corpus:** `scripts/accuracy/manifest.json` + `scripts/accuracy/corpus/`
  (56 cases: 38 EXPECT_TP + 18 EXPECT_TN).
- **v0.27 SSRF fix:** v0.26 disclosed one multi-hop SSRF false negative
  (`target = request.args["x"]; url = "https://" + target; requests.get(url)` —
  taint didn't propagate through the scheme-concatenation into the
  `requests.get` sink). v0.27 fixed the taint engine (a bare/unterminated
  scheme literal is no longer treated as a fixed host), so this case is now
  detected and F1 is **1.000 — legitimately reproduced and CI-gated**, not the
  stale v0.11.0 claim. Re-run the command above to verify.
- **CI-gated:** on push/PR (`.github/workflows/heavy-eval.yml`), floor F1 ≥ 0.99
  (trips on the first real regression, e.g. re-introducing the SSRF FN → 0.987).
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

## 5. Real-world SAST precision track — TWISCOPE seed corpus (v1.1)

> Captured 2026-07-08 on the binary built from `feat/v1.1-real-world-precision`,
> macOS/arm64. The full `--python-engine` scan of the seed target completes in
> **9.0 s** (Python engine pass 2.2 s) after the v1.1 O(fan-out) perf fix
> (`perf(sast): memoize _expr_references_secret`); before that fix a single
> 907-line file took ~45 s and the whole-repo scan ~50 min, which is why no
> real number existed before v1.1.

The v1.1 initiative added a real-world SAST track: a source tree at a pinned
revision scored against a committed `labels.yaml` by a stable `(rule+file+line±3)`
key, with an `unknown` bucket for unlabeled findings that is **excluded from
precision** until triaged (that exclusion is what makes the number defensible).
The seed target is **TWISCOPE-backend** (~1,188 Python files); its labels are
private (source path lives in a git-ignored `benchmarks/realworld/local.yaml`),
so this track **loud-SKIPs** on any machine without the checkout — it never
silently reports green.

```
FENDIX_ENGINE=$PWD/python ./bin/fendix scan --code <twiscope> \
  --python-engine --format json --output /tmp/twiscope.json          # ~9 s
cd go && FENDIX_SCORE_JSON=/tmp/twiscope.json \
  FENDIX_SCORE_LABELS=$PWD/../benchmarks/realworld/twiscope/labels.yaml \
  FENDIX_SCORE_SRC=<twiscope> FENDIX_SCORE_NAME=twiscope \
  go test ./internal/benchmark/targets/ -run TestOfflineScore -v
```

| Metric | Value |
|---|---:|
| Total findings emitted | 72 |
| SAST taint findings (the only labeled surface) | **5** (was ~90 pre-Phase-B) |
| Labeled findings that still fire | 3 (1 tp, 2 fp) |
| Precision over labeled | **33.3 %** (thin-denominator lower bound — see caveat) |
| Confirmed TP retained | 1 (Instagram-proxy SSRF, `views.py:602`) |
| False negatives | **0** |
| Labeled FP classes eliminated | **8 of 11** |
| Residual labeled FPs | 2 (`safe-api-misread`, `constant-authority`) |
| findings/KLOC (labeled surface) | 0.03 |

**Per-class deltas (B1–B8, each locked by a positive+negative corpus case):**

| fp_class | Fix (commit) | Effect on TWISCOPE |
|---|---|---|
| `const-fold-miss` | SQL const-fold for %-format/join/ternary (`7157793`) | SQLi FP on folded-constant SQL removed |
| `guard-dominance` | membership-guard must dominate the sink (`b34ed4a`) | guarded-then-sink SSRF FP removed |
| `double-sanitize` | recognize `Markup`/escaped f-string wrap (`f5f2238`) | escaped-value XSS FP removed |
| `heuristic-overfire` | weak-crypto skips metadata-named ids (`a8645fb`) | md5-of-non-password FP removed |
| `version-range-floor` | npm caret/tilde ranges → INFO (`1d0fa6d`) | SCA over-assertion demoted |
| `fabricated-chain` | from-imported non-fs `open()` ≠ traversal (`90fb9ad`) | 8 path-traversal `open()` FPs removed |
| `test-fixture` | test-fixture findings → INFO, via `--deescalate-tests` / `scan.deescalate_tests` (`cec1efe`, wired end-to-end in the v1.1 wiring pass) | fixture-file noise demoted |
| `http-4xx-context` | DAST 4xx de-escalation (`a03ce63`) | DAST context noise demoted |
| `static-asset-context` | header/CORS findings on static assets de-escalated (`a03ce63`, producer added in the v1.1 wiring pass) | DAST context noise demoted |
| `constant-authority` | settings.\*-host SSRF suppressed (C2, corpus lock) | TwitterAPI / FileGenerator / notificationApp / health_check FPs removed |
| `receiver-confusion` | redis `.get/.delete` ≠ HTTP client | 2 admin redis SSRF FPs removed |
| `safe-api-misread` | psycopg2 `sql.SQL(...).format` ≠ str.format SQLi | SQLi FP removed |

> **Wiring correction (post-capture).** Two rows above described behaviour that
> was implemented and unit-tested but not reachable through the production
> pipeline at the time this baseline was captured: `test-fixture` (the decision
> layer's `DecideWithOptions` was never called by the orchestrator, and no
> config field could enable it) and `static-asset-context` (no scanner ever
> produced the tag the confidence scorer penalises; static assets were instead
> hard-skipped in the rate-limit check). Both are now wired end-to-end and
> gated by pipeline-level tests. The **TWISCOPE numbers in the table above
> predate that fix and have not been recaptured** — the seed corpus is private,
> so a re-run is only possible on a machine with the checkout. Treat the
> per-class effects for those two rows as *now-shipped mechanisms*, not as
> contributors to the captured measurement. Every other row was already live
> when the baseline was taken.

**Caveats (read before quoting 33.3 %):**

- **Thin denominator / label coverage.** The labels were authored against the
  June (pre-Phase-B) triage; most FP entries now describe findings the engine no
  longer emits. A suppressed FP produces **no finding**, so it drops OUT of the
  `tp+fp` denominator — which is precisely why the ratio looks low. The
  defensible statement is not "33 % precision" but "**1 confirmed TP retained, 0
  FN, 8/11 known FP classes eliminated, SAST taint noise cut ~90 → 5, 2 residual
  FPs quantified.**"
- **Out-of-scope unknowns.** 67 of the 69 `unknown` findings are SCA dep-CVEs,
  hardcoded-secrets, FastAPI missing-authn, and Dockerfile findings — categories
  the SAST FP-class labels don't cover. They are correctly **excluded** from
  precision, not counted against it. 2 unlabeled SAST unknowns
  (`data_handling.py:450` path-traversal, `connection_views.py:247` open-redirect)
  are queued for the next label pass.
- **Seed tier is private / not CI-gated.** This number is reproducible only on a
  machine with the TWISCOPE checkout. The **public** real-world tier (committed,
  pinned-SHA repos) is what carries CI — see §D2 / `.github/workflows`.

## Language coverage (capability, not an accuracy number)

| Language | How | Tier |
|---|---|---|
| Python | interprocedural taint engine (source→sink, sanitizer-aware) | proven taint |
| Go / JS / TS | regex SAST (line-local) + Go dep-CVE | regex / SCA |
| **Java (v0.27–v0.28)** | **regex SAST (line-local): command injection, SQLi-by-concat, weak crypto, insecure deserialization, XXE, insecure cookie, weak randomness, LDAP injection, SSRF** | **regex** |
| any language | hardcoded-secrets scanner (15 pattern families) | regex |

Java (v0.27–v0.28) is **regex pattern-matching, line-local** — the same tier as the
Go/JS rules, NOT taint analysis. We publish **no Java recall/precision number**:
there is no labeled Java corpus yet, so any number would be unsourced. Deep
Java taint analysis (what OWASP Benchmark needs) is a future phase.

---

## Not benchmarked yet (honest omissions)

| Item | Why | When |
|---|---|---|
| **OWASP Benchmark** (recall/precision) | It is a **Java** application scored on deep, sanitizer-aware, interprocedural taint. v0.27 ships Java **regex** SAST (line-local) — real coverage, but a regex matcher scores ≈ 0 on the FP-penalized Youden metric (half the cases are sanitized FP twins). The target **loud-SKIPs in both `Scan()` and `Run()`** (`go/internal/benchmark/targets/owasp.go`). | v0.28+ (deep Java taint engine + labeled corpus) |
| Competitor head-to-head (Semgrep/ZAP/Bandit) | No published shared-corpus methodology exists; implied superiority without one violates Rule 5. | post-v0.26 |
| Correlation-specific FP reduction | No harness yet isolates the with/without-correlation effect; claims are stated as mechanism, not measured reduction. | post-v0.26 |
| Real-code precision / FP-rate (**public CI tier**) | v1.1 shipped the seed tier (§5, TWISCOPE — private, not CI-gated). The public pinned-SHA tier is wired but the committed corpus is still seed-only; DAST precision stays a lower bound until public labels land. | v1.1+ public labels |

---

*Methodology questions or a number that doesn't reproduce? Open an issue — a
non-reproducing number is a bug.*
