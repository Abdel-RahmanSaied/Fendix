# SARIF Decision Integrity & Evidence Quality — Design Spec

**Date:** 2026-08-28
**Status:** Accepted, phased
**Regression specimen:** a v2.1.0 SARIF export of `gateway.twiscope.net` + a Python
monorepo (883-endpoint spec inventory, 29 results, 28 rules, 7 BLOCKs).

---

## Product invariant

Fendix must keep four states distinct and must never silently promote one to the next:

| State | Meaning |
|---|---|
| **Observed condition** | a scanner observed something potentially relevant |
| **Security evidence** | the observation supports a security claim |
| **Confirmed vulnerability** | sufficient independent/correlated evidence exists |
| **Blocking decision** | evidence meets the explicit policy required to fail CI |

**A finding MUST NOT become `BLOCK` merely because its rule carries a high static
severity.** Every BLOCK must be reconstructable from the exported SARIF result alone.

Detection coverage must not be reduced to achieve this. De-escalate, never delete.

---

## Confirmed root causes

Each was traced from the specimen back to production code and reconciled
arithmetically against the exported `confidence_score`.

### RC-1 — `liveRuntimeObservation` makes every blackbox finding self-corroborating

`internal/decision/decision.go:corroborations()`:

```go
liveRuntimeObservation := ev.Source == models.SourceBlackbox || ev.Source == models.SourceCorrelated
...
if liveRuntimeObservation {
    sigs = append(sigs, "live runtime observation")
}
```

`applyConfidenceGate` blocks a MEDIUM-band finding when `len(sigs) > 0`. Since
"the finding came from a live probe" is a restatement of `Source` — not an
observation independent of the claim — **every blackbox finding at or above
`--fail-on` with a MEDIUM band blocks unconditionally.**

Reconciliation against the specimen's `auth_bypass` result:

```
base 35 + runtimeEvidence 10          = 45   (matches confidence_score: 45)
band(45)                              = MEDIUM
severity                              = CRITICAL (static, set by the scanner)
corroborations()                      = ["live runtime observation"]
→ MEDIUM + ≥1 signal                  → BLOCK          (matches status: BLOCK)
```

The BLOCK is therefore fully determined by a static severity constant plus the
tautology. This is the exact invariant violation named above.

### RC-2 — the auth scanner has no notion of expected authentication

`internal/scanner/auth.go:checkUnauthenticated()` emits
`models.SeverityCritical` for **any** 2xx returned without credentials:

```go
Title:    "Missing authentication on endpoint",
Severity: models.SeverityCritical,
Evidence: fmt.Sprintf("HTTP %d returned without Authorization header", resp.StatusCode),
```

`scanner.Endpoint` (`internal/scanner/scanner.go:23`) carries
`{Method, Path, FullURL, Params, Headers, BodyParams}` — no auth-expectation
field. The scanner structurally cannot distinguish a public endpoint from a
bypassed one.

The knowledge exists and is discarded: `python/analyzers/spec_parser.py` already
parses per-operation `security`, global `security`, and `_allows_anon()`
(`security: []` and `security: [{}]` both permit anonymous). It emits that as a
*separate* finding and never plumbs it to the Go endpoint inventory.

`confidenceFor(bodyLen)` grades confidence off **response body length**, which is
a proxy for "returned content", not for "authentication was expected".

### RC-3 — `Deduplicate` erases positive evidence

`internal/engine/dedup.go` groups on `dedupKey = Severity|Category|Title` and
accumulates order-invariantly only: `endpoints`, `refs`, `Confidence` (max),
`Source` (most-trusted). Every other field rides along with whichever member wins
`findingLess` (Endpoint → Evidence → Fix → Line, lexicographic).

`Reachable`, `ProvenPath`, `RouteConfirmed`, `TaintChain`, `Route` and
`SourceTier` live in the **render block**, so `ProvenanceIndex` — which exists
precisely to carry the *internal* half across the projection — never captures
them. They are silently taken from the lexicographic minimum.

```
A: Reachable=true,  TaintChain=[…], Endpoint="z/views.py:674"
B: Reachable=false, TaintChain=nil, Endpoint="a/util.py:10"
same (Severity, Category, Title) → same group
findingLess(B, A) → B wins → merged finding has Reachable=false, TaintChain=nil
```

A proven source→sink path is destroyed by a lexicographically-earlier
unconfirmed duplicate. `corroborations()` reads `Reachable`/`ProvenPath`/
`RouteConfirmed`, so this can demote a genuinely confirmed finding to WARN.

In the specimen the two SSRF findings escaped this only by accident:
`escalateNonCorrelatedReachable` bumped the reachable one MEDIUM→HIGH, and
`dedupKey` includes `Severity`, so they landed in different groups.

### RC-4 — dependency applicability is a two-state bool where four states exist

`Evidence.ComponentNotImported bool` conflates "the component IS imported" with
"we never evaluated applicability". It contributes `componentNotImported = -10`
to the score and nothing to the decision.

Reconciliation against the specimen's Django result:

```
base 35 + staticEvidence 10 + deterministicDetn 30 - componentNotImported 10 = 65
band(65)                              = MEDIUM
corroborations()                      = ["deterministic detection in production code"]
→ MEDIUM + ≥1 signal                  → BLOCK
```

So Fendix wrote *"affected component not imported (django.contrib.gis);
effective risk reduced"* into the evidence text and blocked the build anyway. The
mitigation moved the score by 10 points and the decision by nothing.

### RC-5 — whitebox fingerprints are line-coupled

`models.Fingerprint(f) = sha1(Category | Endpoint | Title)`.

For whitebox findings `Endpoint` **is** `path:line`:
- `internal/scanner/secrets/scanner.go:612` — `lineRef := fmt.Sprintf("%s:%d", rel, lineno)`
- `internal/scanner/textscan/textscan.go:498` — `Endpoint: endpoint` (the same `path:line` string)

Inserting one import at the top of a file changes every whitebox fingerprint in
it. Baselines and `.fendix-ignore` `fingerprint:` rules detach on cosmetic edits.

Symmetrically, `Title` carries volatile prose: dependency titles embed the pinned
version and CVE (`Vulnerable dependency: cryptography==48.0.1 (CVE-2026-69247)`),
so a patch bump rewrites the fingerprint *and* the SARIF `ruleId`
(`ruleKeyFor` = `fendix.<category>.<title-slug>`).

### RC-6 — titles claim evidence strength the export does not carry

`Path traversal — user input flows to filesystem path` ships with no `codeFlows`,
no source location and evidence that is only the sink line. Message strength is
a constant in the rule table; it is not a function of whether a taint chain
exists.

### RC-7 — rule-level `security-severity` ignores the scored confidence axis

`Evidence.Confidence` (producer enum) and `Evidence.ConfidenceBand` (v0.23
scorer) are two independent axes by design (`internal/models/finding.go:184`).
`MaxSeverityForConfidence` caps severity off the **enum**;
`sarifSecuritySeverity` is contractually forbidden from reading the scored axis
(`internal/reporters/sarif.go:369`, "Working rule 8").

Consequence: `fendix.secrets.hardcoded-api-key-or-token` — a `FAKE_API_KEY`
constant in a test file — carries enum `HIGH`, so no cap fires, so
`security-severity: "8.0"`, so GitHub Code Scanning files it as **High**, while
the same result reports `confidence_score: 25`, `confidence_band: "LOW"`,
`status: "WARN"`.

### RC-8 — one result, 883 logical locations

`RenderSARIF` emits one `SARIFLocation` per `AffectedEndpoints` entry. Most
consumers (GitHub included) surface `locations[0]` only, so 882 endpoints are
invisible while the payload cost is paid in full.

Separately, `internal/scanner/ratelimit.go` probes with a hardcoded `"GET"` but
labels the finding `fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)`. Every
`DELETE`/`PUT`/`PATCH`/`POST` location in the specimen's 883-entry list is
therefore a rate-limit claim about a verb that was never exercised — and write
verbs are exactly where throttling most often differs from reads.

The same loop counts **any** completed response toward `successfulProbes`:

```go
resp, err := client.Do(req)
if err != nil { continue }
resp.Body.Close()
successfulProbes++          // 404, 401, 403 all count
```

so the `rateLimitMinProbes` floor — which exists to reject inconclusive runs —
is satisfied by twenty 404s. (`crawler.substitutePathPlaceholders` does
substitute `{id}` before the request, so the URLs themselves are plausible; the
defect is the missing status filter, not unsubstituted templates.)

### RC-9 — `automationDetails.id` is a constant

`sarifAutomationID = "fendix/scan"` (`internal/reporters/sarif.go:34`). GitHub
uses this as the analysis category; two Fendix analyses of one commit close each
other's alerts.

---

## Design decisions

### D1 — Corroboration is split into *independent* and *self-evident* classes

`corroborations()` returns one flat list today. It becomes two:

- **Independent** — an observation distinct from the one that produced the
  claim: cross-engine agreement, cross-tool corroboration, reachable taint path,
  proven path, confirmed route, payload-validated probe, confirmed auth
  expectation.
- **Self-evident** — the claim *is* the observation: direct observation of a
  live response, deterministic detection in production code.

`applyConfidenceGate` requires **≥1 independent signal** to lift a MEDIUM band to
BLOCK. Self-evident signals continue to pay their confidence deltas and are
exported, but no longer substitute for confirmation.

`liveRuntimeObservation` is removed as a signal entirely — it is derivable from
`Source`, which is already exported.

**Coverage protection.** The existing code comment warns that removing it strips
every active-probe DAST finding of its only corroborator. That is true *because*
`payloadValidated` is dead: it requires `Evidence.Response`, which no production
producer sets. The migration therefore has two halves and the second is not
optional:

1. reclassify the signals (this changes decisions), and
2. make the active-probe scanners populate `Response`, which restores
   `payload-validated probe` as a genuine independent signal for injection, XSS,
   SSRF and GraphQL.

Shipping (1) without (2) would be a coverage regression, not a precision fix.

### D2 — Authentication expectation becomes first-class

```go
type AuthExpectation string

const (
    AuthExpectationUnknown  AuthExpectation = ""         // never evaluated
    AuthExpectationPublic   AuthExpectation = "public"   // declared anonymous
    AuthExpectationRequired AuthExpectation = "required" // declared protected
)
```

Carried on `scanner.Endpoint`, sourced from the spec parser's existing
`security` / `_allows_anon` logic, and on `Evidence` as
`AuthExpectation` + `AuthExpectationSource` (`openapi` | `static-route` |
`differential`).

Scanner behaviour:

| expectation | unauthenticated 2xx | title | severity | eligible to BLOCK |
|---|---|---|---|---|
| `required` | yes | `Authentication requirement bypassed` | CRITICAL | yes |
| `unknown` | yes | `Unauthenticated endpoint observed` | MEDIUM | **no** |
| `public` | yes | `Unauthenticated endpoint observed` | INFO | no |

No path is hardcoded. `/status` is not special; a `/status` that the spec
declares protected still blocks.

### D3 — Positive render-block evidence folds by proof union in dedup

`Reachable`, `ProvenPath`, `RouteConfirmed` fold by OR. `TaintChain` and `Route`
are adopted from the deterministic minimum member *that carries one*.
`SourceTier` folds to maximum trust. This mirrors the `CrossToolCorroborated`
proof-union exception already documented in `mergeScoringProvenance` and extends
it to the render block, which `ProvenanceIndex` structurally cannot reach.

Dedup can then never manufacture evidence (only members that carried it
contribute) and never erase it.

### D4 — Applicability becomes a four-state enum

```go
type Applicability string

const (
    ApplicabilityUnknown       Applicability = ""                  // not evaluated
    ApplicabilityConfirmed     Applicability = "confirmed"         // affected component imported
    ApplicabilityLikely        Applicability = "likely"            // package used, component undetermined
    ApplicabilityEvidenceAgainst Applicability = "evidence_against" // component never imported
)
```

`ComponentNotImported bool` maps to `ApplicabilityEvidenceAgainst` and is
retained as a deprecated alias for one release.

Decision effect: `ApplicabilityEvidenceAgainst` holds a dependency finding at
WARN unless policy explicitly opts in (`--block-on-inapplicable`). The finding,
its severity, its CVE identity and its full evidence text are preserved — this
is de-escalation, never suppression.

Conservatism: absence of a static import is **not** proof of non-reachability
(`importlib.import_module`, plugin registries, reflection). The state is named
`evidence_against`, not `not_applicable`, for that reason.

### D5 — Every decision exports its justification

New SARIF `result.properties.decision` object, additive, never replacing the
existing `status` / `confidence_score` / `confidence_band` keys:

```json
{
  "decision": {
    "status": "BLOCK",
    "reason": "confirmed_source_to_sink_flow",
    "independent_signals": ["reachable taint path", "proven path"],
    "self_evident_signals": [],
    "evidence": {
      "source_controlled": true,
      "sink_detected": true,
      "flow_established": true,
      "reachable": true,
      "auth_expectation": "unknown",
      "applicability": "unknown"
    }
  }
}
```

Every field is tri-state where absence is meaningful: `true` / `false` /
key omitted. **A missing key means "not evaluated" and must never be rendered as
`false`.**

Invariant, enforced by test: no result with `status == "BLOCK"` may export an
empty `independent_signals` array.

### D6 — Fingerprint identity becomes semantic

`fendix/v2` partial fingerprint, computed from:

```
rule family (category + normalized rule id, never the rendered title)
+ repository-relative path with the line stripped
+ enclosing symbol when the analyzer knows one
+ normalized sink identity for taint findings
+ endpoint identity (method + templated path) for blackbox findings
+ package name + advisory id for dependency findings
```

`fendix/v1` continues to be emitted unchanged for one release so existing
baselines keep matching, and `fendix/v2` is added alongside it. SARIF
`partialFingerprints` is a map precisely so both can coexist.

### D7 — Message strength follows evidence strength

A `strength` field on the rule definition selects the title:

| evidence | wording |
|---|---|
| sink only | `Potential path traversal — dynamic path reaches filesystem sink` |
| taint chain present | `Path traversal — user-controlled input reaches filesystem path` |

Applied across taint-backed rules, not only path traversal. If the chain exists
internally but is lost before export, the export is fixed — the title is not
weakened to match a lossy renderer.

---

## Explicitly out of scope

- Changing `sarifSecuritySeverity` to read the scored axis (RC-7). This is a
  live product decision with a severity re-baseline attached; it is documented
  here and deferred to its own spec.
- Any AI/LLM participation in a deterministic security decision (Constitution
  Rule 8).
- Path-based suppression of any kind.

---

## Phasing

| Plan | Covers | Gate |
|---|---|---|
| **1** | RC-1, RC-2, RC-3, D5 — the decision-integrity core | must land first; everything else reads its taxonomy |
| **2** | RC-4, RC-6 — applicability states + message strength | after Plan 1 |
| **3** | RC-5 — semantic fingerprints | after Plan 1 (needs the rule-family identity) |
| **4** | RC-8, RC-9 — SARIF representation + rate-limit probe correctness | independent, may run in parallel with 2/3 |

Plans 2–4 are separate documents. Each produces working, testable software on
its own.
