# Fendix v0.21 — Earn Trust
Kickoff prepared by: Orchestrator Agent
Handoff from: v0.20 completion (2026-06-28)

## Baseline established (v0.20)

Live Docker run, fendix `v0.19.0-3-g5d999f6`, fully triaged. Stored in
`benchmarks/baselines/baseline.json`; future runs gate via
`fendix benchmark compare` (>10% worse on any metric = regression).

| Metric | dvwa | juiceshop |
|--------|------|-----------|
| Precision | 100% | 70.6% |
| Recall | 100% | 100% |
| TP / FP / FN | 13 / 0 / 0 | 12 / 5 / 0 |
| Scan duration | 12.8s | 28.6s |
| FPRate | n/a (no negative corpus) | n/a |
| OWASP | SKIPPED (Java → v0.27) | — |

Memory baseline is captured per-scan via `FENDIX_METRICS` (HeapAlloc at
scan end) and by `make bench` (in-process `BenchmarkScan`).

## Pre-existing HIGH/security issues to fix in v0.21

From `ENTERPRISE_REVIEW_2026-06-07.md` + `tasks/enterprise-readiness/` +
the v0.20 benchmark triage (see `TASK_MANIFEST.md` → "Pre-existing issues
found"):

1. **Config-file-exposure false positives (NEW, found via benchmark).** The
   exposure/configleak DAST check flags `/.env`, `/.git/HEAD`, `/.htaccess`,
   `/.htpasswd`, `/.DS_Store` on HTTP 200 alone, without validating the
   response body. SPA catch-all servers (Express/Next/React) return
   `index.html` for every unknown path → spurious **CRITICAL**s (5 on Juice
   Shop, all identical 3748-byte bodies). High-impact trust issue.
   **Fix:** require the body to match the target file (content-type /
   signature / ≠ the SPA fallback) before flagging.
2. **Repo-local plugin execution** — `--allow-repo-local-plugins` runs code
   from the scanned tree (RCE on untrusted PRs). Confirm the default guard.
3. **GitHub-App token handling** — historical token-in-`.git/config`/process-args
   findings (`internal/ghapp`, `cmd/fendix-app`).
4. **Offline-mode hermeticity** — verify `--offline` truly makes no outbound
   call (govulncheck needs network → must record SKIPPED).
5. **SSRF egress** — confirm `netguard` + `--allow-private-targets` cover the
   metadata IP / RFC1918 on attacker-controlled scan targets.

## Roadmap decisions for the owner (flagged in v0.20)

- **BLOCKER #2 — OWASP Benchmark vs Java timeline.** OWASP Benchmark is Java
  but is listed in v0.20 *and* v0.26, while Java support is v0.27. The v0.20
  target loudly skips. Decide: move OWASP to v0.27, and/or wrap the existing
  `scripts/heavy-eval` Juliet-style Python/Go corpus as a real SAST baseline
  target sooner.

## v0.21 rules (from the roadmap)
- No new features. No new scan engines. No UI work. No language expansion.
- Fix every HIGH security issue first.
- Trust Center published; threat model + privacy docs; responsible disclosure.
- **Exit criteria:** zero unresolved HIGH findings; every security claim
  documented and reproducible.

## v0.21 agent prompt
Generate `fendix-v021-agents.md` (same multi-agent structure as
`fendix-v020-agents.md`), oriented around the trust-hardening deliverables.
