# Code Review — Fendix v0.21 (Earn Trust)
Reviewed by: Reviewer Agent
Date: 2026-06-28

## Exit criteria: **PASS**

> Roadmap: *"Zero unresolved HIGH security issues. Every security claim documented and reproducible."*

### Zero unresolved HIGH
| HIGH finding | Resolution | Locked by |
|--------------|-----------|-----------|
| F-H1 SSRF egress | Fixed (pre-v0.21) | `netguard` `TestIsBlockedAddr` (metadata IP + RFC1918) |
| F-H2 Plugin sandboxing | Fixed (pre-v0.21) | `TestDefaultRoots_OmitsRepoLocalByDefault` |
| F-H3 GitHub-App token | Fixed (pre-v0.21) + new env-scrub lock | `TestFendixScanner_Run_Success`, `TestScrubTokenFromEnv` |
| F-H5a Webhook async | Fixed (pre-v0.21) | `worker_test.go` |
| F-H5b AST recursion bomb | Fixed (pre-v0.21) | `_MAX_TAINT_HOPS` + cycle/interproc caps |
| F-H4 `--offline` no-op | Verified actually wired (subagent claim was wrong); hermetic by construction | `*_offline_test.go` |
| Config-leak FP (v0.20 find) | **Fixed in v0.21 (V1)** | new SPA-fallback tests |
| F-M1/F-M2 install verify | **Fixed in v0.21 (V4)** | `sh -n`; manual review |

No unresolved HIGH remain.

### Every claim documented & reproducible
- [Trust Center](docs/trust-center.md), [Privacy](docs/privacy.md), [threat model](docs/threat-model.md), [SECURITY.md](SECURITY.md).
- Each Trust Center claim links to code/test, and a "verify it yourself" section gives the exact commands (tcpdump, `--offline`, `benchmark run`, `cosign verify-blob`).

## Product Constitution: **PASS**
| Rule | Status | Note |
|------|--------|------|
| 1 Never rewrite working systems | ✅ | V1 adds a guard to the existing check (no rewrite); V4 hardens install.sh in place; verified-already-done items were left untouched |
| 2 Trust before features | ✅ | v0.21 shipped zero features — only trust hardening + docs |
| 4 Every decision explainable | ✅ | Config-leak suppression and fail-closed verification are deterministic + commented |
| 5 Benchmark before marketing | ✅ | Trust docs are honest — no SOC2 claim; the config-leak FP was disclosed (v0.20) before being fixed |
| 6 Performance regressions are bugs | ✅ | Config-leak adds a bounded 512-byte sniff; negligible. Suite green |
| 7 Backward compatibility | ✅* | *Intentional* behavior change: config-leak no longer emits a false CRITICAL on SPA targets. That's the bug fix, not a break; true positives (plaintext config files) still fire. CLI flags/output schema unchanged |
| 9 Developer experience | ✅ | install.sh failure messages are actionable; trust docs are navigable |
| 10 Engineering time saved | ✅ | Did NOT re-fix the already-done HIGH items; verified + locked them instead |

## Issues found
- **None blocking.** One LOW (config-leak FN edge case on a server serving a real `.env` as text/html) — documented, acceptable trade-off (see SECURITY_AUDIT_v021).

## Notable
The honest finding of this phase: **most of "fix every HIGH issue" was already
done** by the enterprise-readiness sprints. v0.21's real value was (a) closing
the genuine remaining gaps — the config-leak FP and fail-open installer — and
(b) making the trust story *documented and reproducible* (Trust Center +
Privacy). Three subagent "OPEN" verdicts (offline, AST recursion, install) were
checked against code directly; two were already fixed, one (install) was real.

## Recommendation: **SHIP**

Reason: zero unresolved HIGH, every security claim now documented and
independently reproducible, and the two genuine gaps (config-leak FP,
fail-open install verification) are closed with tests / fail-closed defaults.
No features were added; trust was the only deliverable, and it was met.
Build/vet/gofmt/tests green.
