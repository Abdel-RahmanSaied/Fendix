# Fendix Enterprise Readiness — Master Plan

**Generated:** 2026-05-14
**Source brief:** the user's prompt of 2026-05-14 ("Fendix — Enterprise Readiness Implementation Plan")
**Audit reference:** [FENDIX_AUDIT_REPORT.md](../../FENDIX_AUDIT_REPORT.md)
**Current branch context:** `fix/track4-engine-gaps` (the 3 Track 4 gap fixes from the previous session)
**Plan owner:** human + AI-assisted implementer per sprint

---

## Read this first

This is not a brief. It's a sprint-by-sprint commitment. Each sprint:
- Is one PR
- Has hard pre-conditions (read these files; confirm these claims)
- Has a definition of done that includes tests passing AND `make bench` showing no regression
- Has explicit risks called out and the cuts we made vs. the source brief

**Honest sizing.** The source brief packed 17 sprints into 4 minor versions and implied "one session" delivery. The realistic effort, at the quality bar set by [CLAUDE.md](../../CLAUDE.md) and the existing test suite, is **50–55 engineer-days** for one person. Calendar time at 70% sprint capacity: ~10 weeks solo, ~5 weeks for two.

If you can't fund all 18 sprints, the **recommended ordering** at the bottom of this document tells you what to ship first.

---

## Sprint roster

| # | Phase | Sprint title | Days | Risk | Ships in |
|---|---|---|---:|---|---|
| [01](sprint-01-pip-audit-naming.md) | 1.1 | pip-audit naming + fallback flag | 1 | Low | v0.11.1 |
| [02](sprint-02-osv-batch.md) | 1.2 | OSV batch queries + concurrency cap | 1.5 | Med | v0.11.1 |
| [03](sprint-03-verify-scope.md) | 1.3 | `fendix verify` scope + exit codes | 0.5 | Low | v0.11.1 |
| [04](sprint-04-go-sast.md) | 2.1 | Go SAST engine (5 rules) | 5–7 | **High** | v0.12.0 |
| [05](sprint-05-js-sast.md) | 2.2 | JS/TS regex SAST (6 rules) | 4 | Med | v0.12.0 |
| [06](sprint-06-iac-sast.md) | 2.3 | IaC scanner (Dockerfile + k8s) | 4 | Med | v0.12.0 |
| [07](sprint-07-fendix-serve.md) | 3.1 | `fendix serve` REST API (in-memory) | 5 | **High** | v0.12.1 |
| [08](sprint-08-oidc.md) | 3.2 | OIDC login for `fendix serve` | 3 | Med | v0.12.1 |
| [09](sprint-09-offline-mode.md) | 4.1 | Offline mode + `fendix db` | 4 | **High** | v0.13.0 |
| [10](sprint-10-arabic-html.md) | 4.2 | Arabic HTML report (i18n) | 2 | Low | v0.13.0 |
| [11](sprint-11-pdf-report.md) | 4.3 | PDF executive report | 4 | Med | v0.13.0 |
| 12 | 4.4 | NCA ECC compliance report | — | **DEFERRED** | — |
| [13](sprint-13-github-app-handler.md) | 5.1 | GitHub App handler glue | 4 | Med | v0.13.1 |
| [14](sprint-14-jira.md) | 5.2 | Jira integration | 3 | Med | v0.13.1 |
| [15](sprint-15-slack-teams.md) | 5.3 | Slack / Teams webhook alerts | 2 | Low | v0.13.1 |
| [16](sprint-16-benchmarks.md) | 6.1 | Enterprise benchmark harness | 1.5 | Low | v0.14.0 |
| [17](sprint-17-ci-templates.md) | 6.2 | GitLab + CircleCI templates | 1 | Low | v0.14.0 |
| [18](sprint-18-semgrep-rules.md) | 6.3 | Semgrep rule pack expansion | 2 | Low | v0.14.0 |

**Total: 50–53 days.**

---

## Cuts we made vs. the source brief

The source brief was an enthusiastic ask. These are the things we are deliberately NOT doing in the form it described:

| Cut | Reason | Where it ended up |
|---|---|---|
| **Sprint 12 — NCA ECC report** | Brief's mapping table (e.g. `ECC-2-3-1 → secrets`) cannot be verified against an authoritative NCA ECC-1:2018 document in this tree. Shipping unverified compliance mappings is worse than not shipping. | Deferred to a separate procurement track. See [`sprint-12-nca-ecc-deferred.md`](sprint-12-nca-ecc-deferred.md). |
| **Go SAST cut from 7 to 5 rules** | `GO_XXE` and `GO_INSECURE_RAND` need cross-function/type context to avoid a flood of FPs in stdlib code. Without `go/types` (which the brief rules out), shallow versions of these rules would damage trust more than not having them. | Carried as Sprint 4.5 in a follow-up. |
| **JS SAST cut from 8 to 6 rules** | `JS_PROTO_POLLUTION` and `JS_INSECURE_RAND` (proximity-based) produce too many FPs with the regex+context-window approach the brief mandates. | Carried as Sprint 5.5. |
| **Terraform regex IaC** | HCL has multi-line blocks, heredocs, interpolations. Regex-based TF rules generate wrong-block-context FPs. Either (a) add `hashicorp/hcl/v2` (MPL-2.0) for real TF support, or (b) defer. | See decision gate D2 below. |
| **GitHub App "stub" framing** | Brief says `webhook.go:7` is a stub. Actually `webhook.go` is 227 LOC of working signature/transport code; only `handler.go` business logic is missing. Sprint 13 is smaller than the brief implies (~100 LOC of glue, not "rebuild the App"). | Corrected scope inside Sprint 13. |
| **SAML SSO "can follow"** | Half a sprint's worth of scope hiding in a single sentence. Defer until a customer asks. | Not in any sprint. Tracking issue when needed. |

---

## Decision gates — must be made BEFORE the sprint runs

### D1 — Persistence story (affects Sprints 7, 14, others)

Sprint 7 ships `fendix serve` in-memory. Sprints 14 (Jira) and 15 (Slack/Teams dedup) implicitly want scan results to outlive a process restart.

**Decision needed:**
- **Option A:** Add a Sprint 7.5 introducing SQLite as the serve persistence layer. ~3 days of work; one new direct dep (`modernc.org/sqlite` — pure Go, no CGo). Touches every later sprint's data model.
- **Option B:** Stay in-memory forever. Document the restart-loses-state caveat on every integration. Cheap but limits enterprise viability.

**Default if not decided:** Option B (the brief's stated posture). Revisit after Sprint 7 ships and customers complain.

### D2 — Terraform license acceptance (affects Sprint 6)

Real Terraform support requires an HCL parser. The only credible one is `github.com/hashicorp/hcl/v2`, MPL-2.0 licensed.

**Decision needed:**
- **Option A:** Accept MPL-2.0 as a runtime dependency. Most enterprise customers find this fine; some defence/government customers require permissive only.
- **Option B:** Stay regex-only on TF. Sprint 6 ships Dockerfile + k8s, defers TF entirely. Acceptable if you ship Sprint 6 with no TF claim.
- **Option C:** Build a hand-rolled HCL subset parser in `internal/scanner/iac/hcl/`. ~2 weeks of work. Last-resort.

**Default if not decided:** Option B. TF stays deferred.

### D3 — Phase 4 customer commitment (affects Sprints 9, 10, 11)

Offline mode, Arabic HTML, and PDF reports only make sense if there's a real customer behind them. The brief implied Saudi government interest but didn't confirm.

**Decision needed:**
- **Option A:** Confirmed customer / contract — ship Sprints 9, 10, 11 as ordered.
- **Option B:** Speculative — push Phase 4 to *last* and ship integrations (Phase 5) before government features (Phase 4). Most customers will value Jira+Slack before air-gapped CVE DB.

**Default if not decided:** Option B. Reorder roster.

### D4 — Canonical install path (affects Sprint 13, marketing)

The README promotes both:
- GitHub Actions workflow (works today via `fendix init`)
- GitHub App (handler stubbed; Sprint 13 finishes it)

**Decision needed:** Which is the canonical path? Doubling the marketing surface area for both is expensive.

**Default if not decided:** Make GitHub App the canonical path *after* Sprint 13 ships. Until then, recommend the Actions workflow.

---

## Cross-cutting requirements (every sprint MUST honor)

These are the non-negotiables from the brief, lifted here so every sprint file can reference them without repetition:

### Performance floor
- SAST throughput must not drop below **25k LOC/s** after the sprint lands.
- Peak RSS must not exceed **150 MB** for a 100k LOC scan target.
- Run `make bench` before and after the sprint. Profile and fix any regression before merging.

### Dependency posture
- **No new CGo** under any circumstance. The binary must remain cross-compilable without a C toolchain.
- New direct `go.mod` entries allowed across all sprints (the *only* ones):
  - `golang.org/x/oauth2` — Sprint 8
  - `github.com/go-pdf/fpdf` — Sprint 11
  - `github.com/hashicorp/hcl/v2` — Sprint 6 (only if D2 = A)
  - `modernc.org/sqlite` — Sprint 7.5 (only if D1 = A)
- All other functionality stdlib-only.

### Config precedence
CLI flag > env var (`FENDIX_*`) > `.fendix.yaml` > default. Use the existing `policy.CLISet` / `flags.Visit` pattern from `go/cmd/fendix/main.go:260-284`. Never invert.

### Backward compatibility
No breaking changes to:
- `.fendix.yaml` key names
- CLI flag names
- Finding struct JSON field names
- SARIF output structure

Additive changes only. New flags get added; existing flags never change semantics.

### Honest `--help`
Every new flag / subcommand appears in `--help` *only* when fully implemented. Stubs use `cobra.Command{Hidden: true}` and carry a `// TODO: <sprint-N>` comment.

### Error messages
Every `fmt.Errorf` must tell the user what failed AND what to do. No bare `"something failed"`. Pattern:

```go
return fmt.Errorf("offline mode requires a local CVE database. Run: fendix db update --source <snapshot.zip>: %w", err)
```

### Definition of done (per sprint)
1. `make test` passes (zero failures, zero race detector hits — `-race` is on in CI)
2. `make e2e` passes
3. `make bench` shows no throughput regression vs. the pre-sprint baseline
4. `bin/fendix --help` and all subcommand `--help` outputs reflect the new features accurately. No dead-end flags. No stub commands.
5. [`CHANGELOG.md`](../../CHANGELOG.md) updated under the correct version heading
6. The audit-report section that motivated the feature is explicitly cited in the PR description (`FENDIX_AUDIT_REPORT.md §<N>`)
7. Sprint file itself is updated with the final status (estimate vs. actual, surprises, follow-ups)

---

## Recommended ordering if you can't ship all 18 sprints

If forced to cut, ship in this order. Each row is independently shippable and creates user value on its own:

| Order | Sprint(s) | Why first | Ships |
|---|---|---|---|
| 1 | 01, 02, 03 (Phase 1) | Highest leverage. Audit's §15.5 "single most important fix before external evaluation." 3 days total. | v0.11.1 |
| 2 | 13 (GitHub App handler) | ~90% of the ghapp code already exists; sprint is glue. Big perceived-value win. | v0.11.2 |
| 3 | 07, 08 (serve + OIDC) | Unlocks every integration in Phase 5. | v0.12.0 |
| 4 | 14, 15 (Jira + Slack/Teams) | Highest-perceived-value integrations once serve exists. | v0.12.1 |
| 5 | 18 (semgrep pack) | Cheap, high-perceived-value, 2 days. | v0.12.2 |
| 6 | 04, 05, 06 (new SAST engines) | Biggest scope, most risk. Do after the rest of the system stabilises. | v0.13.0 |
| 7 | 09, 10, 11 (Phase 4 gov features) | **Only if a customer is signing the cheque.** | v0.14.0 |
| 8 | 16, 17 (benchmarks + CI templates) | Polish, do last. | v0.14.1 |

NCA ECC stays deferred regardless of order.

---

## Maintenance of this plan

When a sprint completes:
1. Mark it ✅ in the roster table at the top
2. Update the sprint file with actual-vs-estimate and any surprises
3. If the sprint discovered a new gap that needs a follow-up sprint, add it to the table with a new number (e.g. Sprint 4.5)
4. If a sprint's risk turned out higher than estimated, note that in the [risk register](RISKS.md) so future sprints can budget more buffer

If a decision gate is resolved:
1. Strike through the gate in this document
2. Update the affected sprint files
3. Add a note to [DECISIONS.md](DECISIONS.md) with the date and rationale

---

## Where to look next

- **Starting work?** Open the sprint file you've been assigned (e.g. [`sprint-01-pip-audit-naming.md`](sprint-01-pip-audit-naming.md)) and follow its "Read first" list before writing any code.
- **Reviewing the plan?** The sprint files are self-contained — pick the one whose phase concerns you and read just that.
- **Estimating budget?** Sum the `Days` column for the sprints you want to fund. Add 20% for unplanned work surfaced during review.
- **Auditing what's been deferred?** [`sprint-12-nca-ecc-deferred.md`](sprint-12-nca-ecc-deferred.md) and the "Cuts" table above.
