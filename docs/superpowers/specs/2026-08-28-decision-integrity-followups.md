# Decision Integrity — Tracked Follow-Ups

Deferred from the decision-integrity branch (`fix/decision-integrity-core`).
None blocks that merge: every invariant it establishes holds without them. They
are recorded here so deferral is a decision rather than an omission.

Parent spec: `2026-08-28-sarif-decision-integrity-design.md`.

---

## RC-5 — Semantic fingerprints (NEXT PASS)

**The highest-priority follow-up.** Should be the next hardening pass.

`models.Fingerprint(f) = sha1(Category | Endpoint | Title)`, and for whitebox
findings `Endpoint` **is** `path:line`:

- `internal/scanner/secrets/scanner.go:612` — `lineRef := fmt.Sprintf("%s:%d", rel, lineno)`
- `internal/scanner/textscan/textscan.go:498` — the same `path:line` string

So inserting one import at the top of a file rewrites every whitebox fingerprint
in it. Baselines and `.fendix-ignore` `fingerprint:` rules detach on cosmetic
edits.

Symmetrically, `Title` carries volatile prose: dependency titles embed the pinned
version and CVE, so a patch bump rewrites both the fingerprint and the SARIF
`ruleId` (`ruleKeyFor` = `fendix.<category>.<title-slug>`), orphaning GitHub
alert dismissals.

**Shape of the fix:** a `fendix/v2` partial fingerprint from rule family +
line-stripped repo-relative path + enclosing symbol + normalized sink identity +
endpoint identity + package/advisory identity. Emit `fendix/v1` alongside it for
one release so existing baselines keep matching — SARIF `partialFingerprints` is
a map precisely so both can coexist.

**Why it does not block this merge:** fingerprints are an identity-stability
problem, not a decision-integrity one. No BLOCK is produced or withheld
incorrectly because of it.

---

## RC-6 — Evidence-aware titles across every rule

`Path traversal — user input flows to filesystem path` ships with no
`codeFlows`, no source location and evidence that is only the sink line. Message
strength is a constant in the rule table rather than a function of whether a
taint chain exists.

Partially addressed already: the auth claim now tracks its evidence
(`Authentication requirement bypassed` vs `Unauthenticated endpoint observed`),
and the SSRF pair is correctly separated by decision rather than by title. The
remaining work is to apply the same principle to the rule titles themselves
across taint-backed rules.

---

## RC-7 — `security-severity` re-baseline

`sarifSecuritySeverity` is a pure function of severity and is contractually
forbidden from reading the scored confidence axis
(`internal/reporters/sarif.go`, "Working rule 8"). The severity cap keys off the
producer `Confidence` enum, not the v0.23 `ConfidenceBand`.

Consequence: a `FAKE_API_KEY` in a test file carries enum HIGH, so no cap fires,
so `security-severity: "8.0"` — GitHub files it as **High** — while the same
result reports `confidence_score: 25`, `confidence_band: "LOW"`, `status: WARN`.

**Deferred deliberately.** Fixing it is a severity re-baseline across the whole
product with an attached migration for every stored baseline. It needs its own
spec and its own release note.

---

## RC-8 — SARIF representation

- One result carrying 883 `logicalLocations`; most consumers (GitHub included)
  surface `locations[0]` only, so the rest are invisible while the payload cost
  is paid in full. Prefer a compact representation with the full endpoint set in
  structured metadata.
- `internal/scanner/ratelimit.go` probes with a hardcoded `"GET"` but labels the
  finding with the spec's method, so every `DELETE`/`PUT`/`PATCH`/`POST` entry is
  a claim about a verb never exercised.
- The same loop counts **any** completed response toward `successfulProbes`, so
  the `rateLimitMinProbes` floor — which exists to reject inconclusive runs — is
  satisfied by twenty 404s.

The rate-limit items are detection-correctness, not presentation, and are the
more valuable half of this entry.

---

## RC-9 — `automationDetails.id`

`sarifAutomationID = "fendix/scan"` is a constant. GitHub uses it as the analysis
category; two Fendix analyses of one commit close each other's alerts. Should
vary by mode/target.

---

## Carried from this pass

**`configleak` catch-all guard covers HTML and JSON only.** A plain-text or XML
catch-all would still defeat it. The guard is now two-shape; a third shape is
plausible. Consider inverting it — require the body to look like the file type
being probed — rather than enumerating fallback shapes.

**Auth expectation has one source.** `models.AuthExpectation` declares
`static-route` and `differential` as sources but only `openapi` is implemented.
A target scanned without a spec gets `unknown` everywhere, so no auth finding can
gate. Static route analysis (the Python route extractor already binds handlers)
is the natural second source.

**`ComponentNotImported` deprecation.** Retained as a derived alias for one
release; `evidence.ApplicabilityOf` resolves the pair. Remove it once no
out-of-tree producer sets it.

**IDOR same-URL fallback.** `Potential IDOR — identical responses for different
users` now records its two-account differential and is BLOCK-eligible again,
which restores pre-branch behaviour. Whether a shape that also matches a
genuinely shared/global resource *should* gate is a product question worth
revisiting on its own merits.
