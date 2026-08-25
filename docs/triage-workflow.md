# Triage Workflow

How to turn a Fendix report into action items. This guide covers the
recommended sequence for going through findings, the suppression model,
and how baseline diffs reduce ongoing noise.

> **Audience:** engineers and security reviewers who own remediation.
> A 5–50-finding report is the sweet spot; for larger reports skip to
> [Reducing report volume](#reducing-report-volume) first.

---

## The triage funnel

Process findings in this order. Don't try to read sequentially.

```
0. status: BLOCK           →  these are what failed the build
1. Critical + correlated   →  fix this week
2. Critical (uncorrelated) →  verify, then fix
3. High (correlated)       →  fix this sprint
4. High (uncorrelated)     →  verify
5. Medium                  →  bulk-classify
6. Low / Info              →  scan-pass quality signal, not work items
```

Why this order:

- **`status: BLOCK` is the engine's own answer to "what needs action now".**
  Since v2.0 a finding reaches `BLOCK` only when it meets `--fail-on` *and* its
  deterministic `confidence_band` supports the claim. Everything held at `WARN`
  is still real output worth reading — it just did not clear the evidence bar,
  and `confidence_reasons` says which signal was missing.
- **Correlated findings have the lowest false-positive rate.** Both
  engines independently agreed on the same endpoint and category. Cross-engine
  agreement is one of the eight corroborating signals the gate reads.
- **Critical severity = direct exploitation.** Hardcoded production keys.
  Auth disabled. Don't let those age in a backlog.
- **Lows and INFOs are best-read in aggregate.** A 30-finding INFO list
  is rarely 30 separate work items — it's usually one missing config
  rolled out to N endpoints.

## Per-finding decision tree

For each finding, ask in this order:

1. **Is it a true positive?** Open the report's evidence; find the line
   or endpoint. If the evidence doesn't actually demonstrate the
   vulnerability, mark it as a false positive (see
   [Suppressing](#suppressing-findings)).
2. **Is it exploitable in your context?** A hardcoded key in a public
   sample fixture isn't a leak; the same in production code is.
3. **What's the blast radius?** Use the `severity` and `references`
   (CWE) fields. Severity is intentional pessimism — read it as the
   worst-case impact when exploitable.
4. **Who fixes it?** Map the finding's `endpoint` (URL or `file:line`)
   to the team that owns that surface.

If a finding is a true positive but you've decided not to fix it (risk
accepted, compensating control elsewhere), suppress with a reason
attached. Don't ignore silently.

## Reducing report volume

When a first-time scan produces hundreds of findings, work down the
volume before triaging individual items.

### 1. Set a baseline

Tell Fendix "everything that exists today is the existing state":

```bash
fendix scan --code ./src --url https://staging.example.com \
  --format json --output findings.json \
  --save-baseline .fendix/baseline.json
```

> **Regenerate baselines saved before v2.0.** A baseline entry matches on
> `sha1(category|endpoint|title)`. v2.0 renamed two classes of finding, so those
> entries silently stop matching and a `--diff` scan reports them as new:
> dependency findings now carry the **canonical CVE id** in their title
> (`SEC-DEPS-PYSEC_2026_3552` → `SEC-DEPS-CVE_2026_69247`), and a
> `csrftoken` / `XSRF-TOKEN` / `_csrf` cookie without `HttpOnly` is no longer
> titled "Session cookie missing HttpOnly flag". The same applies to
> `.fendix-ignore` `fingerprint:` rules pinned to either. Re-save the baseline
> once against a 2.x binary. (`fendix verify` needs no action — it matches on
> the preserved `references` id set as well as the id.)

Subsequent runs comparing against this baseline only show *new* findings
introduced by recent changes:

```bash
fendix scan --code ./src --url https://staging.example.com \
  --format json --output findings.json \
  --baseline .fendix/baseline.json \
  --save-baseline .fendix/baseline.json
```

This is the right pattern for CI gating — see
[`docs/ci-cd-integration.md`](./ci-cd-integration.md). The baseline
becomes the unfixed-but-known set; the diff is what to gate on.

### 2. Look for dedup-collapsed findings

Fendix automatically collapses identical findings that span many
endpoints into one finding with `affected_endpoints: [...]`. A 21-row
"Missing CSP" finding is one work item: add the header at the reverse
proxy, all 21 endpoints clear together. Don't open 21 tickets.

### 3. Suppress test fixtures and intentional patterns

Test fixtures often have intentional secrets (`API_KEY = "test-key-123"`).
Add a fixture suppression rule once; don't fight it per-finding. See
[`.fendix-ignore.example`](../.fendix-ignore.example).

Reach for that less often than you used to. Since v2.0 the engine handles the
two commonest cases itself, by de-escalation rather than suppression — the
findings are still in the report, they just stop gating:

- A **fixture-shaped value** (`FAKE_`/`TEST_`/`DUMMY_`-prefixed key, a
  placeholder word inside the value, a long identical run, a too-short value)
  loses 20 confidence points and forfeits the deterministic-detection bonus,
  landing in the `LOW` band.
- A finding in **test/fixture code** with no corroborating signal is held at
  `WARN` even when it meets `--fail-on` (`--deescalate-tests`, on by default). A
  corroborated one — a proven taint path, a provider-validated live credential —
  still blocks.

Suppress only what survives both.

---

## Suppressing findings

Suppression lives in `.fendix-ignore` at your project root (or use
`--ignore <path>`). Suppressions are diffable, reviewable, and require
a `reason` field.

### Suppression options

```yaml
ignore:
  # By finding ID — useful for one-off accepted risks
  - id: SEC-014
    reason: "Rate limiting handled at API gateway"
    until: 2026-12-01

  # By endpoint — public health check, intentional
  - endpoint: GET /health
    reason: "Public health check by design"

  # By endpoint + category — auth-not-required surface
  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints are unauthenticated by design"

  # By category for an entire path tree — test fixtures
  - endpoint: "tests/fixtures/*"
    category: secrets
    reason: "Test fixtures contain intentional sample secrets"

  # By category, scope-wide — handled by another control
  - category: headers
    reason: "Security headers added at the reverse proxy"
    until: 2026-06-30
```

**Rules:**

- A rule matches when **all** specified fields match the finding (AND
  logic). Omitted fields match everything.
- `endpoint` supports glob patterns (`*` and `?`).
- `until` uses `YYYY-MM-DD`. Expired rules stop applying — you'll see
  the finding again on the next scan.
- `reason` is required. Without it, the rule is rejected.

### When NOT to suppress

- **Don't suppress to make CI green.** The whole point of `--fail-on` is
  to gate on real risk; suppressing the finding to ship is the same as
  removing the gate.
- **Don't suppress a category you've never read findings in.** Read at
  least one before deciding the whole category is noise.
- **Don't add `until` dates beyond the next quarter without a calendar
  reminder.** `until: 2030-01-01` is "forget about it" — that's what
  silent suppression looks like.

### Reviewing suppressions

The orchestrator logs at scan end how many findings were suppressed and
by which rules. Suppressions should themselves be triaged periodically:

1. Walk `.fendix-ignore` once a quarter.
2. Drop expired `until:` rules.
3. Remove rules whose underlying findings would no longer fire (the
   code is gone, the endpoint is removed).

---

## Working with the JSON output

The HTML report is for browsing; the
[JSON output](./schema.md) is for programmatic triage. A few common
recipes (using `jq`):

```bash
# All CRITICAL findings
jq '.findings[] | select(.severity == "CRITICAL")' findings.json

# Group by category
jq '.findings | group_by(.category) | map({category: .[0].category, count: length})' findings.json

# What actually failed the build
jq '.findings[] | select(.status == "BLOCK")' findings.json

# Why a threshold-crossing finding was held at WARN instead
jq -r '.findings[] | select(.status == "WARN") | "\(.id)\t\(.confidence_band)\t\(.confidence_reasons | join("; "))"' findings.json

# Just the deduped + correlated set (highest signal)
jq '.findings[] | select(.source == "correlated")' findings.json

# Finding IDs to suppress in bulk
jq -r '.findings[] | select(.category == "headers") | .id' findings.json
```

The report contract carries its own version, `metadata.schema_version`
(today `1`), independent of the engine's release version — engine v2.0.0 left it
at `1`. See [`docs/schema.md`](./schema.md) for the contract and for the field
*values* v2.0 moved.

---

## Closing the loop

After every triage pass:

1. **Update `.fendix-ignore`** with the new accepted-risk set.
2. **Refresh the baseline** (`--save-baseline`) so the next scan compares
   against today's state.
3. **Open issues** for the rest, with the finding's `id` + `endpoint` +
   `evidence` quoted in the description so the reviewer can validate
   without re-running the scan.
4. **Re-scan after fixes land** to confirm the finding is gone (rather
   than just suppressed).

Two anti-patterns to avoid:

- **Treating Fendix as a one-shot audit.** The value compounds when it
  runs every PR. See [CI/CD integration](./ci-cd-integration.md).
- **Treating baseline as a permanent freeze.** Re-baseline only when you
  intentionally accept the current state. Don't re-baseline to silence a
  failing build.

---

## See also

- [JSON schema reference](./schema.md) — every field documented.
- [CI/CD integration](./ci-cd-integration.md) — automating triage with
  baseline diffs and PR comments.
- [Suppression file template](../.fendix-ignore.example).
