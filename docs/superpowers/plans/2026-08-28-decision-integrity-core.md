# Decision Integrity Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `BLOCK` require evidence independent of the claim it supports, so no finding gates a build on the strength of a static severity constant alone.

**Architecture:** Three changes that interlock. (1) `decision.corroborations` splits its flat signal list into *independent* and *self-evident* classes, and the MEDIUM-band BLOCK arm requires an independent one. (2) Authentication expectation becomes a first-class field carried from the OpenAPI spec through `scanner.Endpoint` onto `Evidence`, so the auth scanner can distinguish a public endpoint from a bypassed one. (3) `engine.Deduplicate` folds positive render-block evidence by proof union instead of letting it ride on the lexicographic-minimum group member. A fourth task exports the resulting decision justification into SARIF so every BLOCK is reconstructable from the report.

**Tech Stack:** Go 1.26.6, standard library only. `go test ./...` from `go/`.

**Spec:** `docs/superpowers/specs/2026-08-28-sarif-decision-integrity-design.md`

## Global Constraints

- **Constitution Rule 3 — evidence is de-escalated, never deleted.** No task may drop a finding, edit its evidence text, or remove a field from the public JSON.
- **Constitution Rule 8 — no AI in the decision path.** Every rule added here is a fixed, documented, pure function.
- **Public contract.** `models.Finding`'s JSON shape is frozen. New fields go on `evidence.Evidence` (internal) or into SARIF `result.properties` (additive only).
- **Determinism (F-L6).** Every fold added must be commutative, associative and idempotent. Output is a function of the input *set*, never the arrival order.
- **Unknown is not false.** A field that was never evaluated must be distinguishable from one evaluated to false, at every layer including export.
- **Baseline:** `go test ./...` is green at HEAD — 39 packages ok, 0 failures, exit 0. Any red after a change is caused by that change.
- **Score arithmetic.** Every reason line appended to `Score.Reasons` carries an explicit signed delta prefix and the lines must sum to `ConfidenceScore` (`engine.assertReasonsSumToScore`, `confidence.TestReasonsSumToValue`). A decision move appends `+0 ` lines only.
- **Working directory** for all commands: `/Users/asaied/WorkDir/Fendix/fendix-services/Fendix/go`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `internal/decision/decision.go` | the single BLOCK policy | split corroboration into two classes; gate MEDIUM on independent signals |
| `internal/decision/corroboration_test.go` | taxonomy regression | **create** |
| `internal/decision/block_invariant_test.go` | property test over every BLOCK-capable category | **create** |
| `internal/scanner/scanner.go` | `Endpoint` shape | add `AuthExpectation` |
| `internal/scanner/crawler.go` | spec → endpoint inventory | read `security` / global `security` into the new field |
| `internal/scanner/auth.go` | auth checks | gate the claim + severity on expectation |
| `internal/evidence/evidence.go` | domain object | add `AuthExpectation`, `AuthExpectationSource` |
| `internal/evidence/provenance.go` | provenance carry | carry the two new fields |
| `internal/engine/dedup.go` | identity + merge | proof-union fold for render-block evidence |
| `internal/reporters/sarif.go` | export | emit `properties.decision` |
| `internal/engine/orchestrator.go` | wiring | thread decision justification onto the finding |

Tasks 1–2 are the decision layer. Tasks 3–4 are the auth semantics. Task 5 is dedup. Tasks 6–7 are export and the invariant lock.

---

### Task 1: Split corroboration into independent and self-evident classes

**Files:**
- Modify: `internal/decision/decision.go:180-240` (`corroborations`, `applyConfidenceGate`, `DecideWithOptions`)
- Test: `internal/decision/corroboration_test.go` (create)

**Interfaces:**
- Consumes: `evidence.Evidence`, `confidence.HasDeterministicDetection`
- Produces: `type corroboration struct { Independent, SelfEvident []string }`, `func corroborate(ev evidence.Evidence) corroboration`. Task 6 reads both slices for export; Task 7 asserts `len(Independent) > 0` on every BLOCK.

- [ ] **Step 1: Write the failing test**

Create `internal/decision/corroboration_test.go`:

```go
package decision

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// A blackbox finding whose ONLY support is "a live probe produced it" must not
// reach BLOCK. "The scan ran" is a restatement of Source, not an observation
// independent of the claim — see RC-1 in the design spec.
func TestBlackboxSourceAloneIsNotIndependentCorroboration(t *testing.T) {
	ev := evidence.Evidence{
		Title:      "Missing authentication on endpoint",
		Category:   "auth_bypass",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Endpoint:   "GET /status",
		Confidence: models.ConfidenceMedium,
	}

	c := corroborate(ev)
	if len(c.Independent) != 0 {
		t.Errorf("Independent = %v, want empty — a bare blackbox source corroborates nothing", c.Independent)
	}

	d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusWarn {
		t.Errorf("Status = %q, want WARN (score %d, band %s, reason %q)",
			d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
}

// A proven source→sink chain IS independent of the pattern match that found the
// sink, so it still blocks. This is the coverage half of the invariant.
func TestReachableTaintPathRemainsIndependentCorroboration(t *testing.T) {
	ev := evidence.Evidence{
		Title:      "Potential SSRF — dynamic URL passed to HTTP client",
		Category:   "injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Endpoint:   "app/views.py:674",
		Confidence: models.ConfidenceHigh,
		SourceTier: models.TierTreeSitter,
		Reachable:  true,
	}

	c := corroborate(ev)
	if !contains(c.Independent, "reachable taint path") {
		t.Errorf("Independent = %v, want it to contain %q", c.Independent, "reachable taint path")
	}

	d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — a reachable taint path must still gate", d.Status)
	}
}

// A deterministic read of a live response is self-evident, not independent: the
// claim IS the observation. It keeps paying its confidence delta and is still
// exported, but it cannot lift a MEDIUM band on its own.
func TestDirectObservationIsSelfEvidentNotIndependent(t *testing.T) {
	ev := evidence.Evidence{
		Title:             "CORS wildcard origin with credentials allowed",
		Category:          "cors",
		Severity:          models.SeverityCritical,
		Source:            models.SourceBlackbox,
		Endpoint:          "POST /api/auth/refresh/",
		Confidence:        models.ConfidenceHigh,
		DirectObservation: true,
	}

	c := corroborate(ev)
	if !contains(c.SelfEvident, "direct observation of a live response") {
		t.Errorf("SelfEvident = %v, want it to contain the direct-observation signal", c.SelfEvident)
	}
	if contains(c.Independent, "direct observation of a live response") {
		t.Errorf("Independent = %v, must not contain the direct-observation signal", c.Independent)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/decision/ -run 'Corroboration|Independent|SelfEvident' -v`
Expected: FAIL — `undefined: corroborate`, `undefined: corroboration`.

- [ ] **Step 3: Write the implementation**

In `internal/decision/decision.go`, replace `corroborations` with:

```go
// corroboration partitions the signals supporting a claim into two classes.
//
// INDEPENDENT signals come from an observation distinct from the one that
// produced the claim: another engine agreed, a taint path was proved, a route
// was confirmed live, a probe payload elicited a predicted response, an
// external tool reported the same weakness at the same location, or a declared
// authentication requirement was contradicted. These are the only signals that
// may lift a MEDIUM band to BLOCK.
//
// SELF-EVIDENT signals restate the observation that produced the claim: a
// deterministic read of a live response, a deterministic pattern match in
// production source. They are strong — they carry the largest confidence
// deltas in the scorer (+30 each) — but they are not confirmation, because
// there is no second observation to disagree. They are exported so a reader
// sees the full support, and they never substitute for an independent signal.
//
// REMOVED IN THIS CHANGE: "live runtime observation", which fired for every
// Source=blackbox finding. It was a restatement of a field the report already
// exports, so it made every blackbox finding self-corroborating and reduced the
// MEDIUM-band gate to "severity >= --fail-on" (RC-1). Active-probe scanners
// earn "payload-validated probe" instead, which is a real differential — see
// Task 2 of the implementation plan.
//
// Both slices are built by a FIXED sequence of ifs, never a map, because they
// are joined into Decision.Reason and exported into SARIF; order must be a pure
// function of the evidence.
type corroboration struct {
	Independent []string
	SelfEvident []string
}

// Any reports whether any signal at all fired, independent or not.
func (c corroboration) Any() bool {
	return len(c.Independent) > 0 || len(c.SelfEvident) > 0
}

func corroborate(ev evidence.Evidence) corroboration {
	var c corroboration

	if ev.Source == models.SourceCorrelated {
		c.Independent = append(c.Independent, "cross-engine agreement")
	}
	if ev.RouteConfirmed {
		c.Independent = append(c.Independent, "confirmed route")
	}
	if ev.Reachable {
		c.Independent = append(c.Independent, "reachable taint path")
	}
	if ev.ProvenPath {
		c.Independent = append(c.Independent, "proven path")
	}
	if ev.Payload != "" && ev.Response != "" {
		c.Independent = append(c.Independent, "payload-validated probe")
	}
	if ev.CrossToolCorroborated {
		c.Independent = append(c.Independent, "independent cross-tool corroboration")
	}

	if ev.DirectObservation {
		c.SelfEvident = append(c.SelfEvident, "direct observation of a live response")
	}
	if confidence.HasDeterministicDetection(ev) {
		c.SelfEvident = append(c.SelfEvident, "deterministic detection in production code")
	}
	return c
}
```

Then rewrite `applyConfidenceGate`'s body to key off `Independent`:

```go
func applyConfidenceGate(d *Decision, ev evidence.Evidence) {
	c := corroborate(ev)
	sigs := c.Independent

	hold := func(reason string) {
		d.Status = StatusWarn
		d.Reason = reason
		d.Score.Reasons = appendReason(d.Score.Reasons, "+0 held at WARN: "+reason)
	}

	switch {
	case ev.UnconfirmedByLiveScan && len(sigs) == 0:
		hold("severity at or above the --fail-on threshold but the finding is unconfirmed " +
			"by live scan and uncorroborated — needs independent corroboration to block")
	case d.Score.Band == models.ConfidenceLow:
		hold("severity above threshold but confidence LOW — needs independent corroboration to block")
	case len(sigs) == 0:
		// Covers BOTH remaining bands. A HIGH band with no independent signal
		// is the RC-1 shape: a self-evident observation plus a static severity
		// constant. It is a strong warning, not a confirmed vulnerability.
		hold("severity above threshold but no evidence independent of the observation that " +
			"produced the claim — needs independent corroboration to block")
	default:
		d.Status = StatusBlock
		d.Reason = "severity at or above the --fail-on threshold; corroborated by: " +
			strings.Join(sigs, ", ")
	}
}
```

Finally, in `DecideWithOptions`, change the test-fixture arm's predicate from
`len(corroborations(ev)) == 0` to `len(corroborate(ev).Independent) == 0` —
self-evident detection is already excluded from test code by
`HasDeterministicDetection`'s `!ev.InTest` conjunct, so this is the conservative
reading and not a behaviour change for that arm.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/decision/ -run 'Corroboration|Independent|SelfEvident' -v`
Expected: PASS

- [ ] **Step 5: Run the decision + engine suites and triage every break**

Run: `go test ./internal/decision/ ./internal/engine/ ./internal/confidence/ 2>&1 | tail -40`

Expected: several existing tests fail. Each is a **decision change to be
classified, not a test to be edited into agreement**. For each failure record in
the task's commit message which of these it is:
1. the test asserted the RC-1 behaviour (blackbox self-corroboration) — update the test and note the policy change;
2. the test asserted coverage that Task 2 restores — mark it `t.Skip("restored by Task 2: payload-validated probe")` and reference it in Task 2's step 5;
3. the test found a real regression — stop and fix the implementation.

Do not proceed to Step 6 with any failure in class 3.

- [ ] **Step 6: Commit**

```bash
git add internal/decision/
git commit -m "fix(decision): require evidence independent of the claim to BLOCK

corroborations() counted 'live runtime observation' — a restatement of
Source=blackbox — as a corroborating signal, so every blackbox finding at or
above --fail-on with a MEDIUM band blocked unconditionally. A CRITICAL static
severity plus the tautology was sufficient to fail a build.

Signals are now partitioned: independent (cross-engine agreement, confirmed
route, reachable taint path, proven path, payload-validated probe, cross-tool
corroboration) vs self-evident (direct observation, deterministic detection).
Only independent signals lift a band to BLOCK. Both are exported.

POLICY CHANGE: scans that exited 1 on a bare blackbox finding now exit 0.
--enforce-confidence=false is unaffected.

Refs RC-1."
```

---

### Task 2: Restore `payload-validated probe` by populating `Evidence.Response`

**Files:**
- Modify: `internal/scanner/injection.go`, `internal/scanner/xss.go`, `internal/scanner/ssrf.go`, `internal/scanner/openredirect.go`
- Test: `internal/scanner/probe_response_test.go` (create)

**Interfaces:**
- Consumes: `corroborate` from Task 1.
- Produces: active-probe evidence carrying both `Payload` and `Response`, which makes `payload-validated probe` a live independent signal.

**Why this task is not optional:** `confidence.payloadValidated` requires both
`Payload` and `Response`. No production producer sets `Response`, so the rule has
never fired outside tests — the package doc says so explicitly. Task 1 removed
the tautological signal these scanners were leaning on; without this task they
lose their only corroborator and every active-probe finding drops to WARN. That
is a coverage regression, which the spec forbids.

- [ ] **Step 1: Write the failing test**

Create `internal/scanner/probe_response_test.go`:

```go
package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// An active probe that elicited a confirming response must carry BOTH the
// payload it sent and a bounded excerpt of what came back. Payload alone is not
// a differential — the pair is what distinguishes "we sent something" from "the
// target reacted the way the check predicted".
func TestActiveProbeEvidenceCarriesPayloadAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the injection marker so the check fires.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SQL syntax error near 'fendix-probe'"))
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{TargetURL: srv.URL, EnableActive: true}
	ep := Endpoint{Method: "GET", Path: "/search", FullURL: srv.URL + "/search", Params: []string{"q"}}

	got := CheckInjection(context.Background(), cfg, ep)
	if len(got) == 0 {
		t.Fatal("CheckInjection returned no evidence; expected the reflected SQL error to fire")
	}
	for _, e := range got {
		if e.Payload == "" {
			t.Errorf("%q: Payload is empty", e.Title)
		}
		if e.Response == "" {
			t.Errorf("%q: Response is empty — payloadValidated can never fire", e.Title)
		}
		if len(e.Response) > probeResponseLimit {
			t.Errorf("%q: Response is %d bytes, want <= %d", e.Title, len(e.Response), probeResponseLimit)
		}
		if strings.Contains(e.Response, "\x00") {
			t.Errorf("%q: Response carries a NUL byte; excerpt must be sanitized", e.Title)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestActiveProbeEvidenceCarriesPayloadAndResponse -v`
Expected: FAIL — `undefined: probeResponseLimit`, and `Response is empty`.

- [ ] **Step 3: Write the implementation**

Add to `internal/scanner/httpclient.go`:

```go
// probeResponseLimit bounds the response excerpt stored on active-probe
// evidence. Large enough to carry the matched indicator with context, small
// enough that a hostile response cannot bloat the report. The excerpt feeds
// confidence.payloadValidated and is INTERNAL — evidence.Evidence.Response is
// never projected onto models.Finding, so it never reaches SARIF.
const probeResponseLimit = 512

// ProbeExcerpt returns a bounded, control-character-free excerpt of a probe
// response body for storage on Evidence.Response. Deterministic: the same body
// always yields the same excerpt, so confidence scoring stays reproducible.
func ProbeExcerpt(body string) string {
	if len(body) > probeResponseLimit {
		body = body[:probeResponseLimit]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, body)
}
```

Then in each of the four scanners, at the point where the check already has the
response body in hand and is constructing evidence, set:

```go
Payload:  payload,
Response: ProbeExcerpt(body),
```

Locate each construction site with:

```bash
grep -n "Payload:" internal/scanner/injection.go internal/scanner/xss.go \
    internal/scanner/ssrf.go internal/scanner/openredirect.go
```

Every site that sets `Payload` must also set `Response`. A site that does not
have the body in scope needs the body threaded to it — do not fabricate a value.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run TestActiveProbeEvidenceCarriesPayloadAndResponse -v`
Expected: PASS

- [ ] **Step 5: Un-skip the Task 1 class-2 tests and confirm coverage is restored**

Remove every `t.Skip("restored by Task 2: payload-validated probe")` added in
Task 1 Step 5.

Run: `go test ./internal/decision/ ./internal/scanner/ ./internal/engine/ 2>&1 | tail -30`
Expected: PASS, including the previously skipped tests.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/
git commit -m "feat(scanner): record probe response excerpts so payloadValidated can fire

confidence.payloadValidated requires Payload AND Response; no production
producer set Response, so the +10 rule and the 'payload-validated probe'
corroboration signal were dead code. Active-probe checks now store a bounded,
sanitized excerpt of the response that made them fire.

This restores an INDEPENDENT corroborator for injection/XSS/SSRF/open-redirect
findings, which Task 1 relies on: those checks previously leaned on the
tautological 'live runtime observation' signal.

Response is Evidence-internal and never reaches models.Finding or SARIF."
```

---

### Task 3: Carry authentication expectation from the spec to the endpoint inventory

**Files:**
- Modify: `internal/scanner/scanner.go:23-30` (`Endpoint`)
- Modify: `internal/scanner/crawler.go:295-343` (`fromSpec`)
- Modify: `internal/evidence/evidence.go` (render-internal block)
- Modify: `internal/evidence/provenance.go` (`ScoringProvenance`, `NewProvenanceIndex`, `Restore`, `mergeScoringProvenance`)
- Test: `internal/scanner/authexpectation_test.go` (create)

**Interfaces:**
- Produces: `models.AuthExpectation` (`""` unknown / `"public"` / `"required"`),
  `Endpoint.AuthExpectation`, `Evidence.AuthExpectation`,
  `Evidence.AuthExpectationSource`. Task 4 consumes all three.

- [ ] **Step 1: Write the failing test**

Create `internal/scanner/authexpectation_test.go`:

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// OpenAPI 3.x: `security: []` and `security: [{}]` BOTH make auth optional.
// A global requirement is inherited by any operation that does not override it.
func TestSpecEndpointsCarryAuthExpectation(t *testing.T) {
	spec := `{
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.com"}],
      "security": [{"jwtAuth": []}],
      "components": {"securitySchemes": {"jwtAuth": {"type": "http", "scheme": "bearer"}}},
      "paths": {
        "/inherits":     {"get": {"responses": {"200": {"description": "ok"}}}},
        "/explicit":     {"get": {"security": [{"jwtAuth": []}], "responses": {"200": {"description": "ok"}}}},
        "/opted-out":    {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/anon-object":  {"get": {"security": [{}], "responses": {"200": {"description": "ok"}}}}
      }
    }`

	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Crawler{cfg: &models.ScanConfig{SpecPath: path}}
	endpoints, err := c.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}

	want := map[string]models.AuthExpectation{
		"/inherits":    models.AuthExpectationRequired,
		"/explicit":    models.AuthExpectationRequired,
		"/opted-out":   models.AuthExpectationPublic,
		"/anon-object": models.AuthExpectationPublic,
	}
	got := map[string]models.AuthExpectation{}
	for _, ep := range endpoints {
		got[ep.Path] = ep.AuthExpectation
	}
	for path, w := range want {
		if got[path] != w {
			t.Errorf("%s: AuthExpectation = %q, want %q", path, got[path], w)
		}
	}
}

// No global security and no operation security means Fendix never established
// an expectation. That must stay UNKNOWN — not Public — because "the spec is
// silent" is not "the spec declares this open".
func TestSpecWithoutSecurityLeavesExpectationUnknown(t *testing.T) {
	spec := `{
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.com"}],
      "paths": {"/silent": {"get": {"responses": {"200": {"description": "ok"}}}}}
    }`

	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Crawler{cfg: &models.ScanConfig{SpecPath: path}}
	endpoints, err := c.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(endpoints))
	}
	if endpoints[0].AuthExpectation != models.AuthExpectationUnknown {
		t.Errorf("AuthExpectation = %q, want unknown", endpoints[0].AuthExpectation)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run AuthExpectation -v`
Expected: FAIL — `undefined: models.AuthExpectation`, `ep.AuthExpectation undefined`.

- [ ] **Step 3: Write the implementation**

Add to `internal/models/finding.go`:

```go
// AuthExpectation is what Fendix established about whether an endpoint is
// SUPPOSED to require authentication, independently of what it actually did
// when probed.
//
// The zero value is UNKNOWN and that is load-bearing: a target scanned with no
// spec and no static route analysis has no expectation, and "we never
// established one" must never render as "this endpoint is declared public".
// Treating unknown as public would silently suppress real bypasses; treating it
// as required would flag every public endpoint. It is its own state.
type AuthExpectation string

const (
	// AuthExpectationUnknown — never evaluated. NOT a claim in either direction.
	AuthExpectationUnknown AuthExpectation = ""
	// AuthExpectationPublic — a source of truth declares anonymous access
	// intentional (OpenAPI `security: []` or `security: [{}]`).
	AuthExpectationPublic AuthExpectation = "public"
	// AuthExpectationRequired — a source of truth declares authentication
	// required (an operation-level `security` requirement, or an inherited
	// global one the operation does not override).
	AuthExpectationRequired AuthExpectation = "required"
)
```

Add to `internal/scanner/scanner.go`'s `Endpoint`:

```go
	// AuthExpectation is what a source of truth (today: the OpenAPI spec)
	// declares about authentication for this operation. Zero value = unknown.
	// The auth scanner reads it to distinguish "this endpoint is public" from
	// "this endpoint's authentication requirement was bypassed" — see
	// checkUnauthenticated.
	AuthExpectation models.AuthExpectation
```

Add to `internal/scanner/crawler.go`, above `fromSpec`:

```go
// specAllowsAnon reports whether an OpenAPI `security` value permits anonymous
// access. Mirrors python/analyzers/spec_parser.py:_allows_anon so the two
// analyzers cannot drift.
//
// In OpenAPI 3.x BOTH `security: []` and a list containing the empty object
// `security: [{}]` make auth optional. `len([{}]) != 0`, so the empty-object
// form must be checked explicitly — the bug that check exists to prevent.
func specAllowsAnon(security interface{}) bool {
	list, ok := security.([]interface{})
	if !ok {
		return false // absent or malformed: not a claim of anonymity
	}
	if len(list) == 0 {
		return true // `security: []`
	}
	for _, req := range list {
		if m, ok := req.(map[string]interface{}); ok && len(m) == 0 {
			return true // `security: [{}]`
		}
	}
	return false
}

// authExpectationFor resolves the declared authentication expectation for one
// operation. opSecurity is the operation's own `security` value (nil = inherits);
// globalSecurity is the spec's top-level one.
//
// Returns Unknown when NEITHER level declares anything — silence in the spec is
// not a declaration of public access.
func authExpectationFor(opSecurity, globalSecurity interface{}) models.AuthExpectation {
	if opSecurity != nil {
		if specAllowsAnon(opSecurity) {
			return models.AuthExpectationPublic
		}
		if list, ok := opSecurity.([]interface{}); ok && len(list) > 0 {
			return models.AuthExpectationRequired
		}
		return models.AuthExpectationUnknown
	}
	if globalSecurity != nil {
		if specAllowsAnon(globalSecurity) {
			return models.AuthExpectationPublic
		}
		if list, ok := globalSecurity.([]interface{}); ok && len(list) > 0 {
			return models.AuthExpectationRequired
		}
	}
	return models.AuthExpectationUnknown
}
```

In `fromSpec`, capture the global value once before the `for path, methods` loop:

```go
	globalSecurity := spec["security"]
```

and add the field to the `Endpoint` literal at `crawler.go:332`:

```go
			ep := Endpoint{
				Method:          strings.ToUpper(method),
				Path:            path,
				FullURL:         fullURL,
				Params:          mergeParams(extractPathParams(path), pathLevelParams, opParams),
				Headers:         mergeParams(pathLevelHeaders, opHeaders),
				BodyParams:      mergeParams(pathLevelBodyParams, opBodyParams),
				AuthExpectation: authExpectationFor(opMap["security"], globalSecurity),
			}
```

Add to `internal/evidence/evidence.go`, in the internal-provenance block:

```go
	// AuthExpectation is what a source of truth declared about authentication
	// for this endpoint, and AuthExpectationSource names that source
	// ("openapi", "static-route", "differential"). Together they are what lets
	// the decision layer treat a contradicted requirement as INDEPENDENT
	// corroboration while an unauthenticated 200 on an endpoint of unknown
	// expectation stays observational.
	//
	// Like DirectObservation these have NO endpoint-derived fallback — nothing
	// on a projected Finding can reconstruct them — so they must be carried by
	// ScoringProvenance and restored before scoring, or the rule is dead.
	// INTERNAL — never projected onto Finding.
	AuthExpectation       models.AuthExpectation
	AuthExpectationSource string
```

Add the same two fields to `ScoringProvenance` in `internal/evidence/provenance.go`,
copy them in `NewProvenanceIndex` (with no derived fallback — add the comment
saying so), restore them in `Restore` guarded on the zero value, and fold them in
`mergeScoringProvenance` with `agreementOr`:

```go
		AuthExpectation:       models.AuthExpectation(agreementOr(string(a.AuthExpectation), string(b.AuthExpectation))),
		AuthExpectationSource: agreementOr(a.AuthExpectationSource, b.AuthExpectationSource),
```

Agreement-or-drop is correct here: two endpoints in one dedup group that
disagree about whether auth was expected collapse to unknown, which is the
conservative reading and keeps the fold commutative.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run AuthExpectation -v`
Expected: PASS

- [ ] **Step 5: Verify the provenance coverage tests still hold**

`TestScoringProvenanceCoversEveryScoredField` reflects over `ScoringProvenance`
and fails on any field no fixture exercises. Add the two new fields to the
fixture it reads.

Run: `go test ./internal/evidence/ ./internal/confidence/ -v 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/models/finding.go internal/scanner/scanner.go internal/scanner/crawler.go internal/evidence/
git commit -m "feat(scanner): carry declared auth expectation from the spec onto endpoints

scanner.Endpoint carried no auth-expectation field, so the auth scanner could
not distinguish a public endpoint from a bypassed one and emitted CRITICAL for
any 2xx without credentials. The knowledge existed — the Python spec parser
reads per-operation and global security — and was discarded.

fromSpec now resolves it in Go (the spec map is already in hand) into a
three-state models.AuthExpectation. Unknown is its own state: spec silence is
not a declaration of public access.

specAllowsAnon mirrors spec_parser._allows_anon, including the security: [{}]
form that a naive truthiness check misreads as a requirement.

Refs RC-2."
```

---

### Task 4: Gate the auth-bypass claim on the declared expectation

**Files:**
- Modify: `internal/scanner/auth.go:170-205` (`checkUnauthenticated`)
- Modify: `internal/decision/decision.go` (`corroborate` — add the auth signal)
- Test: `internal/scanner/auth_expectation_semantics_test.go` (create)

**Interfaces:**
- Consumes: `Endpoint.AuthExpectation` (Task 3), `corroborate` (Task 1).
- Produces: two distinct titles and a `contradicted authentication requirement`
  independent signal.

- [ ] **Step 1: Write the failing test**

Create `internal/scanner/auth_expectation_semantics_test.go`:

```go
package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func serve200(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","uptime":123}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func authCfg(target string) *models.ScanConfig {
	return &models.ScanConfig{
		TargetURL: target,
		Auth:      &models.AuthContext{Type: "bearer", Value: "eyJhbGciOiJIUzI1NiJ9.e30.sig"},
	}
}

// The RC-2 case: a 200 without credentials on an endpoint whose expectation was
// never established is an OBSERVATION. It must not claim bypass and must not
// carry a severity that can gate a build.
func TestUnknownExpectationYieldsObservationNotBypass(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{Method: "GET", Path: "/status", FullURL: srv.URL + "/status"} // AuthExpectation zero

	got := CheckAuth(context.Background(), authCfg(srv.URL), ep)
	if len(got) == 0 {
		t.Fatal("expected an observational finding, got none — evidence must be preserved, not dropped")
	}
	f := got[0]
	if f.Title != "Unauthenticated endpoint observed" {
		t.Errorf("Title = %q, want %q", f.Title, "Unauthenticated endpoint observed")
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want MEDIUM", f.Severity)
	}
	if f.AuthExpectation != models.AuthExpectationUnknown {
		t.Errorf("AuthExpectation = %q, want unknown", f.AuthExpectation)
	}
}

// A spec-declared protected endpoint returning 200 unauthenticated IS a bypass:
// the live observation contradicts a declared requirement.
func TestRequiredExpectationYieldsConfirmedBypass(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{
		Method:          "GET",
		Path:            "/api/users",
		FullURL:         srv.URL + "/api/users",
		AuthExpectation: models.AuthExpectationRequired,
	}

	got := CheckAuth(context.Background(), authCfg(srv.URL), ep)
	if len(got) == 0 {
		t.Fatal("expected a bypass finding, got none")
	}
	f := got[0]
	if f.Title != "Authentication requirement bypassed" {
		t.Errorf("Title = %q, want %q", f.Title, "Authentication requirement bypassed")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", f.Severity)
	}
	if f.AuthExpectationSource != "openapi" {
		t.Errorf("AuthExpectationSource = %q, want %q", f.AuthExpectationSource, "openapi")
	}
}

// A spec-declared public endpoint returning 200 is working as designed.
func TestPublicExpectationIsInformational(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{
		Method:          "GET",
		Path:            "/health",
		FullURL:         srv.URL + "/health",
		AuthExpectation: models.AuthExpectationPublic,
	}

	got := CheckAuth(context.Background(), authCfg(srv.URL), ep)
	for _, f := range got {
		if f.Category == "auth_bypass" && f.Severity != models.SeverityInfo {
			t.Errorf("declared-public endpoint produced %q at %q, want INFO", f.Title, f.Severity)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run 'Expectation' -v`
Expected: FAIL — all three findings still titled `Missing authentication on endpoint` at CRITICAL.

- [ ] **Step 3: Write the implementation**

Replace the evidence construction in `checkUnauthenticated`:

```go
	twoXX, bodyLen := readOutcome(resp)
	if !twoXX {
		return nil
	}

	// The claim is a function of what Fendix ESTABLISHED about this endpoint,
	// not of the status code alone. A 200 without credentials is the same
	// observation in all three cases; only the expectation changes what it
	// means. Nothing here is path-based — a /status the spec declares protected
	// still reports a bypass, and an /api/admin the spec declares public does
	// not.
	title, severity := "Unauthenticated endpoint observed", models.SeverityMedium
	fix := "If this endpoint is intended to be public, declare it so in the API " +
		"specification. If not, require authentication and return 401."

	switch endpoint.AuthExpectation {
	case models.AuthExpectationRequired:
		title, severity = "Authentication requirement bypassed", models.SeverityCritical
		fix = "Require authentication. Return 401 for unauthenticated requests."
	case models.AuthExpectationPublic:
		severity = models.SeverityInfo
		fix = "No action needed: the specification declares this endpoint public."
	}

	evidenceText := fmt.Sprintf("HTTP %d returned without Authorization header", resp.StatusCode)
	switch endpoint.AuthExpectation {
	case models.AuthExpectationRequired:
		evidenceText += "; the API specification declares an authentication requirement for this operation"
	case models.AuthExpectationPublic:
		evidenceText += "; the API specification declares this operation public"
	default:
		evidenceText += "; no authentication requirement was established for this operation " +
			"(no specification security requirement and no static route evidence), so this is an " +
			"observation, not a confirmed bypass"
	}

	source := ""
	if endpoint.AuthExpectation != models.AuthExpectationUnknown {
		source = "openapi"
	}

	return &ev.Evidence{
		Title:                 title,
		Severity:              severity,
		Source:                models.SourceBlackbox,
		Category:              "auth_bypass",
		Endpoint:              epLabel,
		Evidence:              evidenceText,
		Fix:                   fix,
		References:            []string{"CWE-306", "OWASP-A01"},
		Confidence:            confidenceFor(bodyLen),
		AuthExpectation:       endpoint.AuthExpectation,
		AuthExpectationSource: source,
	}
```

Add the independent signal to `corroborate` in `internal/decision/decision.go`,
after the `CrossToolCorroborated` arm so existing signal order is unchanged:

```go
	// A live unauthenticated success that contradicts a DECLARED requirement is
	// two observations disagreeing — the spec says protected, the wire says
	// open. That is independent of the probe that produced the claim, which is
	// why it may lift a band. An unknown expectation contributes nothing: it is
	// not evidence in either direction.
	if ev.AuthExpectation == models.AuthExpectationRequired {
		c.Independent = append(c.Independent, "contradicted authentication requirement")
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run 'Expectation' -v`
Expected: PASS

- [ ] **Step 5: Verify the end-to-end decision for both shapes**

Run: `go test ./internal/scanner/ ./internal/decision/ ./internal/e2e/ 2>&1 | tail -30`
Expected: PASS. `internal/e2e/e2e_test.go:657` references the spec-parser auth
finding — confirm it still asserts what it intends.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/auth.go internal/decision/decision.go
git commit -m "fix(auth): separate unauthenticated observation from confirmed bypass

checkUnauthenticated emitted CRITICAL 'Missing authentication on endpoint' for
any 2xx returned without credentials, so every public endpoint — docs, health,
an SPA route — produced a CRITICAL that the confidence gate then blocked on.

The claim now follows the DECLARED expectation:
  required → 'Authentication requirement bypassed', CRITICAL, and the
             contradiction counts as independent corroboration
  unknown  → 'Unauthenticated endpoint observed', MEDIUM, never blocks
  public   → INFO

No path is hardcoded. Evidence is preserved in all three cases (Rule 3); only
the claim's strength changes.

Refs RC-2."
```

---

### Task 5: Fold positive render-block evidence by proof union in dedup

**Files:**
- Modify: `internal/engine/dedup.go:60-115` (`Deduplicate`)
- Test: `internal/engine/dedup_provenance_test.go` (create)

**Interfaces:**
- Consumes: `models.Finding`, `models.SourceTier.TrustRank`.
- Produces: a merged finding whose `Reachable` / `ProvenPath` / `RouteConfirmed`
  / `TaintChain` / `Route` / `SourceTier` are a function of the group's member
  set, not of `findingLess`.

- [ ] **Step 1: Write the failing test**

Create `internal/engine/dedup_provenance_test.go`:

```go
package engine

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func strptr(s string) *string { return &s }

// RC-3: dedup keeps the total-order-minimum member as the primary and lets
// every un-accumulated field ride along with it. A confirmed occurrence whose
// endpoint sorts LATER than an unconfirmed one had its proof erased.
func TestDedupPreservesConfirmedEvidenceAgainstUnknownDuplicate(t *testing.T) {
	confirmed := models.Finding{
		Title:      "Potential SSRF — dynamic URL passed to HTTP client",
		Category:   "injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Endpoint:   "z/views.py:674", // sorts AFTER the unconfirmed one
		Reachable:  true,
		ProvenPath: true,
		SourceTier: models.TierTreeSitter,
		TaintChain: []models.TaintLink{{File: "z/views.py", Line: 652, Expr: "request.query_params.get('url')"}},
		Line:       strptr("z/views.py:674"),
	}
	unknown := models.Finding{
		Title:      "Potential SSRF — dynamic URL passed to HTTP client",
		Category:   "injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Endpoint:   "a/util.py:10", // sorts FIRST → wins findingLess today
		SourceTier: models.TierSemgrepShim,
		Line:       strptr("a/util.py:10"),
	}

	for _, tc := range []struct {
		name string
		in   []models.Finding
	}{
		{"confirmed first", []models.Finding{confirmed, unknown}},
		{"unknown first", []models.Finding{unknown, confirmed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Deduplicate(tc.in)
			if len(out) != 1 {
				t.Fatalf("got %d findings, want 1 merged group", len(out))
			}
			g := out[0]
			if !g.Reachable {
				t.Error("Reachable = false — a proved taint path was erased by an unconfirmed duplicate")
			}
			if !g.ProvenPath {
				t.Error("ProvenPath = false — proof erased")
			}
			if len(g.TaintChain) == 0 {
				t.Error("TaintChain is empty — the chain was dropped with the losing member")
			}
			if g.SourceTier != models.TierTreeSitter {
				t.Errorf("SourceTier = %q, want the most-trusted tier in the group", g.SourceTier)
			}
		})
	}
}

// Dedup must PRESERVE evidence, never manufacture it: a group in which nobody
// proved reachability must not come out reachable.
func TestDedupDoesNotManufactureEvidence(t *testing.T) {
	a := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "a"}
	b := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "b"}

	out := Deduplicate([]models.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	if out[0].Reachable || out[0].ProvenPath || out[0].RouteConfirmed {
		t.Errorf("dedup manufactured evidence: reachable=%v provenPath=%v routeConfirmed=%v",
			out[0].Reachable, out[0].ProvenPath, out[0].RouteConfirmed)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestDedupPreservesConfirmedEvidence -v`
Expected: FAIL on the `unknown first` subtest — `Reachable = false`, `TaintChain is empty`.
(The `confirmed first` subtest may pass by luck; that asymmetry is the bug.)

- [ ] **Step 3: Write the implementation**

In `internal/engine/dedup.go`, inside the merge branch and alongside the
existing `mergedConfidence` / `mergedSource` computations — i.e. BEFORE the
`findingLess` primary swap — add:

```go
		// Positive render-block evidence folds by PROOF UNION, not by riding
		// along with whichever member wins findingLess.
		//
		// These fields live in the render block, so ProvenanceIndex — which
		// exists to carry the Evidence-INTERNAL half across the projection —
		// structurally cannot reach them. Before this fold, a confirmed
		// occurrence whose endpoint sorted after an unconfirmed one had its
		// proof silently deleted, and decision.corroborate reads exactly these
		// fields, so dedup could demote a confirmed finding to WARN.
		//
		// OR / max-trust is safe in both directions: only members that CARRIED
		// the evidence contribute, so the fold can never manufacture it, and it
		// is commutative, associative and idempotent, so the result is a pure
		// function of the member set (F-L6).
		mergedReachable := g.primary.Reachable || f.Reachable
		mergedProvenPath := g.primary.ProvenPath || f.ProvenPath
		mergedRouteConfirmed := g.primary.RouteConfirmed || f.RouteConfirmed
		mergedTier := g.primary.SourceTier
		if f.SourceTier.TrustRank() > mergedTier.TrustRank() {
			mergedTier = f.SourceTier
		}
		mergedChain := preferChain(g.primary, f)
		mergedRoute := preferRoute(g.primary, f)
```

and after the swap, alongside the existing two re-applications:

```go
		g.primary.Confidence = mergedConfidence
		g.primary.Source = mergedSource
		g.primary.Reachable = mergedReachable
		g.primary.ProvenPath = mergedProvenPath
		g.primary.RouteConfirmed = mergedRouteConfirmed
		g.primary.SourceTier = mergedTier
		g.primary.TaintChain = mergedChain
		g.primary.Route = mergedRoute
```

Add the two helpers at the bottom of the file:

```go
// preferChain picks the taint chain to keep for a merged group. A member that
// proved a chain always beats one that did not; when both proved one, the
// deterministic minimum under findingLess wins so the result is independent of
// arrival order (F-L6).
func preferChain(a, b models.Finding) []models.TaintLink {
	switch {
	case len(a.TaintChain) == 0:
		return b.TaintChain
	case len(b.TaintChain) == 0:
		return a.TaintChain
	case findingLess(b, a):
		return b.TaintChain
	default:
		return a.TaintChain
	}
}

// preferRoute is preferChain for the bound route: a known route beats an
// unknown one, ties break on the same total order.
func preferRoute(a, b models.Finding) *models.Route {
	switch {
	case a.Route == nil:
		return b.Route
	case b.Route == nil:
		return a.Route
	case findingLess(b, a):
		return b.Route
	default:
		return a.Route
	}
}
```

Update `Deduplicate`'s doc comment's "Merge rules" list to name the new fold.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/ -run 'TestDedupPreservesConfirmedEvidence|TestDedupDoesNotManufactureEvidence' -v`
Expected: PASS, both subtests.

- [ ] **Step 5: Confirm determinism still holds**

Run: `go test ./internal/engine/ -run 'Determinism|Property|Fuzz' -count=3 2>&1 | tail -20`
Expected: PASS. `dedup_determinism_test.go` and `dedup_property_test.go` permute
inputs; a non-commutative fold fails them.

- [ ] **Step 6: Commit**

```bash
git add internal/engine/dedup.go internal/engine/dedup_provenance_test.go
git commit -m "fix(engine): preserve proved evidence across deduplication

Deduplicate accumulated only endpoints, references, Confidence and Source
order-invariantly; Reachable, ProvenPath, RouteConfirmed, TaintChain, Route and
SourceTier rode along with whichever member won findingLess (endpoint, then
evidence, then fix, then line — lexicographic).

So a confirmed occurrence at z/views.py:674 merged with an unconfirmed one at
a/util.py:10 lost its taint chain and its Reachable flag. decision.corroborate
reads those fields, so dedup could silently demote a confirmed finding to WARN.

These fields are in the render block, which ProvenanceIndex cannot reach by
construction — it carries the Evidence-internal half. They now fold by proof
union (OR / max-trust / prefer-the-member-that-proved-it), which cannot
manufacture evidence and is commutative, associative and idempotent.

Refs RC-3."
```

---

### Task 6: Export the decision justification into SARIF

**Files:**
- Modify: `internal/models/finding.go` (add `DecisionReason`, `IndependentSignals`, `SelfEvidentSignals`)
- Modify: `internal/engine/orchestrator.go:1207-1225` (`stampDecisions`)
- Modify: `internal/decision/decision.go` (expose the corroboration on `Decision`)
- Modify: `internal/reporters/sarif.go:~800` (`sarifResultProperties`)
- Test: `internal/reporters/sarif_decision_test.go` (create)

**Interfaces:**
- Consumes: `corroboration` (Task 1), `Decision.Reason`.
- Produces: SARIF `result.properties.decision` — `{status, reason, independent_signals, self_evident_signals, evidence{...}}`.

- [ ] **Step 1: Write the failing test**

Create `internal/reporters/sarif_decision_test.go`:

```go
package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func renderOne(t *testing.T, f models.Finding) map[string]interface{} {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, []models.Finding{f}, ScanMetadata{}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []map[string]interface{} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want exactly one run with one result")
	}
	return doc.Runs[0].Results[0]
}

// Every BLOCK must be reconstructable from the exported result alone.
func TestBlockExportsItsJustification(t *testing.T) {
	res := renderOne(t, models.Finding{
		Title:              "Potential SSRF — dynamic URL passed to HTTP client",
		Category:           "injection",
		Severity:           models.SeverityHigh,
		Source:             models.SourceWhitebox,
		Endpoint:           "app/views.py:674",
		Status:             "BLOCK",
		DecisionReason:     "severity at or above the --fail-on threshold; corroborated by: reachable taint path",
		IndependentSignals: []string{"reachable taint path"},
		Reachable:          true,
	})

	props, _ := res["properties"].(map[string]interface{})
	dec, ok := props["decision"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties.decision is missing — a BLOCK is not auditable from the report")
	}
	if dec["status"] != "BLOCK" {
		t.Errorf("decision.status = %v, want BLOCK", dec["status"])
	}
	sigs, _ := dec["independent_signals"].([]interface{})
	if len(sigs) == 0 {
		t.Error("decision.independent_signals is empty on a BLOCK — invariant violated")
	}
	evi, _ := dec["evidence"].(map[string]interface{})
	if evi["reachable"] != true {
		t.Errorf("decision.evidence.reachable = %v, want true", evi["reachable"])
	}
}

// Unknown must stay unknown: a field never evaluated is ABSENT, never false.
func TestUnevaluatedEvidenceIsAbsentNotFalse(t *testing.T) {
	res := renderOne(t, models.Finding{
		Title:    "Unauthenticated endpoint observed",
		Category: "auth_bypass",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
		Endpoint: "GET /status",
		Status:   "WARN",
	})

	props, _ := res["properties"].(map[string]interface{})
	dec, _ := props["decision"].(map[string]interface{})
	evi, _ := dec["evidence"].(map[string]interface{})

	if _, present := evi["auth_expectation"]; present {
		t.Errorf("auth_expectation is present (%v) but was never established — "+
			"absence is the only honest encoding of unknown", evi["auth_expectation"])
	}
	if v, present := evi["flow_established"]; present && v == false {
		t.Error("flow_established rendered as false; no taint analysis ran, so it must be absent")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/reporters/ -run 'TestBlockExportsItsJustification|TestUnevaluatedEvidenceIsAbsent' -v`
Expected: FAIL — `unknown field DecisionReason`, then `properties.decision is missing`.

- [ ] **Step 3: Write the implementation**

Add to `models.Finding`, in the v0.24 decision-report block, all `omitempty`
so a report produced without the decision pass stays byte-identical:

```go
	// DecisionReason is the plain-text justification for Status, verbatim from
	// decision.Decision.Reason.
	DecisionReason string `json:"decision_reason,omitempty"`
	// IndependentSignals / SelfEvidentSignals are the two corroboration classes
	// behind Status. Only Independent may lift a band to BLOCK; both are
	// published so a reader can reconstruct the verdict.
	IndependentSignals []string `json:"independent_signals,omitempty"`
	SelfEvidentSignals []string `json:"self_evident_signals,omitempty"`
```

Mirror them in `evidence.Evidence`'s render block and in `FromFinding` /
`ToFinding` — the round-trip identity tests enforce this.

Export the classes from the decision layer by adding to `Decision`:

```go
	// Corroboration is the partitioned signal set behind Status. Exported so
	// the orchestrator can stamp it onto the finding without re-deriving — and
	// therefore drifting from — the predicate the gate actually used.
	Corroboration corroboration
```

set it in `decide()` (`d.Corroboration = corroborate(ev)`) and have
`applyConfidenceGate` read `d.Corroboration.Independent` rather than calling
`corroborate` a second time.

In `stampDecisions`, add:

```go
		findings[i].DecisionReason = d.Reason
		findings[i].IndependentSignals = d.Corroboration.Independent
		findings[i].SelfEvidentSignals = d.Corroboration.SelfEvident
```

In `internal/reporters/sarif.go`, `sarifResultProperties` returns the typed
`*SARIFResultProperties` (struct, not a map), so add one field to it:

```go
	// Decision is the machine-readable justification for Status. Pointer +
	// omitempty so a report produced without the decision pass stays
	// byte-identical.
	Decision *SARIFDecision `json:"decision,omitempty"`
```

and declare:

```go
// SARIFDecision is the auditable justification for one finding's verdict.
type SARIFDecision struct {
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	IndependentSignals []string `json:"independent_signals,omitempty"`
	SelfEvidentSignals []string `json:"self_evident_signals,omitempty"`
	// Evidence is a MAP, not a struct, on purpose — see decisionProperties.
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}
```

Note the early-return guard at `sarifResultProperties`'s top already tests
`f.Status == ""`, so any finding carrying a decision passes it unchanged; no
guard edit is needed.

Build the block with a helper. Use `map[string]interface{}` for the evidence
sub-object specifically so an unevaluated field can be **omitted**, which a
`bool` field cannot express:

```go
// decisionProperties renders the machine-readable justification for a finding's
// verdict.
//
// The evidence sub-object is a map, not a struct, on purpose: a struct field is
// either true or false, and this contract requires a third state. A key that is
// ABSENT means "not evaluated" — never "evaluated and false". Rendering unknown
// as false is the single most misleading thing this exporter could do, because
// a consumer cannot tell a cleared check from a check that never ran.
func decisionProperties(f models.Finding) *SARIFDecision {
	if f.Status == "" {
		return nil // no decision pass ran; emit nothing rather than a hollow block
	}
	evi := map[string]interface{}{}
	if f.Reachable {
		evi["reachable"] = true
		evi["flow_established"] = len(f.TaintChain) > 0
	}
	if len(f.TaintChain) > 0 {
		evi["source_controlled"] = true
		evi["sink_detected"] = true
	}
	if f.RouteConfirmed {
		evi["route_confirmed"] = true
	}
	if f.AuthExpectation != models.AuthExpectationUnknown {
		evi["auth_expectation"] = string(f.AuthExpectation)
	}

	out := &SARIFDecision{
		Status:             f.Status,
		Reason:             NeutralizeText(f.DecisionReason),
		IndependentSignals: neutralizeTags(f.IndependentSignals),
		SelfEvidentSignals: neutralizeTags(f.SelfEvidentSignals),
	}
	if len(evi) > 0 {
		out.Evidence = evi
	}
	return out
}
```

and attach it in `sarifResultProperties` with `p.Decision = decisionProperties(f)`.

Note: `AuthExpectation` must be added to the `models.Finding` render block for
this to compile — it is exported here because the *decision* depends on it, and
an auditable decision cannot reference a field the report withholds.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/reporters/ -run 'TestBlockExportsItsJustification|TestUnevaluatedEvidenceIsAbsent' -v`
Expected: PASS

- [ ] **Step 5: Regenerate and inspect the SARIF snapshots**

Run: `go test ./internal/reporters/ ./internal/engine/ ./tests/regression/ 2>&1 | tail -30`

Snapshot tests will fail on the added key. Review each diff by eye and confirm
it contains **only** the additive `decision` block — any change to an existing
key is a contract break and must be fixed, not accepted.

- [ ] **Step 6: Commit**

```bash
git add internal/models/finding.go internal/evidence/ internal/decision/ internal/engine/orchestrator.go internal/reporters/
git commit -m "feat(sarif): export machine-readable decision justification

A consumer could see status/confidence_score/confidence_band/source_tier and
still not answer 'why exactly did this BLOCK?'. Results now carry
properties.decision: the verdict, its plain-text reason, the independent and
self-evident signal lists, and the evidence flags behind them.

The evidence sub-object is a map so an unevaluated check can be ABSENT. A struct
would force every field to true or false and render 'never ran' as 'ran and
found nothing', which is the failure mode this whole change exists to remove.

Additive only: every existing key is byte-identical, and a report produced
without the decision pass emits no decision block at all."
```

---

### Task 7: Lock the BLOCK invariant with a property test over every category

**Files:**
- Test: `internal/decision/block_invariant_test.go` (create)

**Interfaces:**
- Consumes: everything above. Adds no production code.

- [ ] **Step 1: Write the test**

Create `internal/decision/block_invariant_test.go`:

```go
package decision

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// blockCapableCategories is every category that can currently reach CRITICAL or
// HIGH severity, i.e. every category that can meet a --fail-on threshold. Adding
// a category to the engine without adding it here leaves its BLOCK path
// unguarded, so this list is deliberately explicit rather than derived.
var blockCapableCategories = []string{
	"auth_bypass", "auth", "injection", "secrets", "cors", "deps",
	"idor", "xss", "ssrf", "rate_limiting", "headers", "cookie", "iac",
}

// THE INVARIANT. No evidence may reach BLOCK without at least one signal from an
// observation independent of the one that produced the claim. This is the
// property the whole plan exists to establish; it must hold for every category,
// at every severity, under the shipped policy.
func TestNoBlockWithoutIndependentCorroboration(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	}
	sources := []models.Source{
		models.SourceBlackbox, models.SourceWhitebox,
		models.SourceCorrelated, models.SourceImported,
	}
	confidences := []models.Confidence{
		models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow,
	}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	for _, cat := range blockCapableCategories {
		for _, sev := range severities {
			for _, src := range sources {
				for _, conf := range confidences {
					for _, failOn := range []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
						ev := evidence.Evidence{
							Title:      "synthetic " + cat,
							Category:   cat,
							Severity:   sev,
							Source:     src,
							Confidence: conf,
							Endpoint:   "GET /synthetic",
						}
						d := DecideWithOptions(ev, failOn, opts)
						if d.Status == StatusBlock && len(d.Corroboration.Independent) == 0 {
							t.Errorf("BLOCK with no independent corroboration: "+
								"category=%s severity=%s source=%s confidence=%s failOn=%s "+
								"score=%d band=%s reason=%q",
								cat, sev, src, conf, failOn,
								d.Score.Value, d.Score.Band, d.Reason)
						}
					}
				}
			}
		}
	}
}

// The converse guard: the gate must not have become unreachable. At least one
// realistic shape must still BLOCK, or Task 1 silently disabled enforcement.
func TestConfirmedFindingsStillBlock(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	cases := map[string]evidence.Evidence{
		"reachable taint path": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter, Reachable: true,
		},
		"cross-engine agreement": {
			Category: "secrets", Severity: models.SeverityHigh, Source: models.SourceCorrelated,
			Confidence: models.ConfidenceHigh,
		},
		"contradicted auth requirement": {
			Category: "auth_bypass", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, AuthExpectation: models.AuthExpectationRequired,
		},
		"payload-validated probe": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, Payload: "' OR 1=1--", Response: "SQL syntax error",
		},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			ev.Title, ev.Endpoint = name, "GET /x"
			if d := DecideWithOptions(ev, "HIGH", opts); d.Status != StatusBlock {
				t.Errorf("Status = %q, want BLOCK (score=%d band=%s reason=%q)",
					d.Status, d.Score.Value, d.Score.Band, d.Reason)
			}
		})
	}
}

// Determinism: the same evidence must always yield the same verdict, reason and
// signal lists. Run the whole matrix twice and compare.
func TestDecisionIsDeterministic(t *testing.T) {
	ev := evidence.Evidence{
		Title: "determinism probe", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		SourceTier: models.TierTreeSitter, Reachable: true, Endpoint: "app/x.py:1",
	}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	first := DecideWithOptions(ev, "HIGH", opts)
	for i := 0; i < 50; i++ {
		got := DecideWithOptions(ev, "HIGH", opts)
		if got.Status != first.Status || got.Reason != first.Reason ||
			got.Score.Value != first.Score.Value ||
			len(got.Corroboration.Independent) != len(first.Corroboration.Independent) {
			t.Fatalf("iteration %d diverged: %+v vs %+v", i, got, first)
		}
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/decision/ -run 'Invariant|StillBlock|Deterministic' -v`
Expected: PASS. **Any failure here is a real hole in the policy, not a test to relax.**

- [ ] **Step 3: Run the full suite**

Run: `go test ./... 2>&1 | tail -50`
Expected: 39 packages ok, 0 FAIL — matching the recorded baseline.

- [ ] **Step 4: Verify determinism end to end**

Run: `go test ./... -count=2 2>&1 | grep -E "FAIL|ok " | tail -45`
Expected: identical results across both runs.

- [ ] **Step 5: Commit**

```bash
git add internal/decision/block_invariant_test.go
git commit -m "test(decision): lock the BLOCK invariant across every category

Property test over category × severity × source × confidence × --fail-on
asserting that no combination reaches BLOCK without an independent corroborating
signal, plus a converse test proving the gate is still reachable for genuinely
confirmed findings, plus a determinism check.

The category list is explicit rather than derived: a new category must be added
here consciously, so its BLOCK path cannot ship unguarded."
```

---

## Self-Review

**Spec coverage.** RC-1 → Tasks 1, 2, 7. RC-2 → Tasks 3, 4. RC-3 → Task 5.
D5 → Task 6. RC-4 (applicability), RC-5 (fingerprints), RC-6 (message strength),
RC-7 (security-severity, deferred by the spec), RC-8 and RC-9 (SARIF
representation) are **not** covered here — they are Plans 2–4 in the spec's
phasing table.

**Placeholder scan.** No TBDs. Task 2 Step 3 asks the implementer to `grep` for
the construction sites rather than listing them, because the exact line numbers
depend on Task 1's edits; the grep command is given verbatim and the acceptance
condition ("every site that sets `Payload` must also set `Response`") is exact.

**Type consistency.** `corroborate`/`corroboration` (Tasks 1, 4, 6, 7);
`models.AuthExpectation` with the three constants (Tasks 3, 4, 6, 7);
`Endpoint.AuthExpectation` (Tasks 3, 4); `Evidence.AuthExpectation` +
`AuthExpectationSource` (Tasks 3, 4); `Finding.DecisionReason` /
`IndependentSignals` / `SelfEvidentSignals` (Task 6);
`Decision.Corroboration` (Tasks 6, 7); `ProbeExcerpt`/`probeResponseLimit`
(Task 2); `preferChain`/`preferRoute` (Task 5). Task 6 additionally promotes
`AuthExpectation` onto `models.Finding` — noted inline there because it widens
the public JSON contract and is the one place this plan does so.

**Known risk.** Task 1 changes shipped security policy: builds that exited 1 will
exit 0. The commit message says so explicitly, and `--enforce-confidence=false`
remains a byte-for-byte escape hatch. Release notes must carry it.
