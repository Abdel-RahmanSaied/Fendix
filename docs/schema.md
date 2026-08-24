# Fendix JSON Report Schema

This document defines the public schema for `fendix scan --format json` output.
A machine-readable JSON Schema (draft-07) lives alongside this file at
[`schema.json`](./schema.json) and is used by Fendix's own test suite to
validate every report produced.

The schema is **stable** for the 1.x line: within `1.x`, additive changes (new
optional fields) are allowed in any release, and removals or type changes are
reserved for a `2.0.0` major bump. v1.1.0 added no output fields.

Reports produced by `0.x` builds validate against this schema too — every
change across the `0.x` line was additive — but `0.x` is end of life (see
[`SECURITY.md`](../SECURITY.md)) and the version-gated notes below (`v0.24`,
etc.) record when a field first appeared, not a support commitment.

---

## Top-level shape

```json
{
  "metadata":  { ... ScanMetadata ... },
  "summary":   { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "sources":   { "blackbox": 0, "whitebox": 0, "correlated": 0 },
  "total":     0,
  "decisions": { "total": 0, "confirmed": 0, "blocking": 0, "warning": 0, "informational": 0 },
  "findings":  [ { ... Finding ... }, ... ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `metadata` | object | yes | Scan-level metadata (target, timing, mode). |
| `summary` | object | yes | Severity counts. Sums to `total`. |
| `sources` | object | yes | Source counts (blackbox / whitebox / correlated). Sums to `total`. |
| `total` | integer | yes | Total findings in `findings`. |
| `decisions` | object | effectively yes | **v0.24+** decision summary (`StatusCounts`): `total`, `confirmed` (HIGH-confidence), `blocking` (status BLOCK), `warning` (WARN), `informational` (INFO). The reporter serialises it **unconditionally** (`JSONReport.Decisions` has no `omitempty`), so every report a current build produces carries it. It stays out of `schema.json`'s root `required` set purely so pre-v0.24 archived reports still validate — a consumer reading current output can rely on it being present. |
| `findings` | array of `Finding` | yes | Each finding produced by the scan, sorted deterministically. May be empty. |

---

## ScanMetadata

```json
{
  "schema_version":    1,
  "target":            "https://api.example.com",
  "started_at":        "2026-04-29T10:00:00Z",
  "duration":          "12.5s",
  "version":              "1.1.0",
  "mode":                 "hybrid",
  "endpoints_scanned":    21,
  "endpoints_discovered": 34,
  "endpoints_truncated":  true,
  "active_probes":        false,
  "checks_run":           ["headers", "cors", "exposure", "ratelimit", "secrets", "semgrep", "deps"],
  "scanner_status": [
    {"name": "secrets",  "state": "ok"},
    {"name": "semgrep",  "state": "skipped", "detail": "semgrep binary not installed"},
    {"name": "npm",      "state": "failed",  "detail": "npm audit: exit status 1"}
  ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | integer | effectively yes | Version of this report contract. `RenderJSON` stamps it on **every** report it writes (overwriting whatever the caller set), so any report a current build produces carries it. It stays out of `schema.json`'s `required` set so pre-v1.2.2 archived reports still validate: those omit the key, and an absent key means "pre-versioned", **not** invalid. A consumer that does not recognise the value should warn, not fail — `ParseJSONReport` accepts any value, including 0 and unknown future ones. Bumped only for a change consumers must react to; purely additive keys do not bump it. |
| `target` | string | yes | The `--url` value, or empty string for `--code`-only scans. |
| `started_at` | string (RFC 3339 timestamp) | yes | When the scan started. |
| `duration` | string (Go-formatted duration, e.g. `"12.5s"`) | yes | Wall-clock duration of the scan. |
| `version` | string | yes | Fendix version, e.g. `"1.1.0"` or `"dev"`. |
| `mode` | string enum | yes | One of `blackbox`, `whitebox`, `hybrid`. |
| `endpoints_scanned` | integer | yes | Number of endpoints actually scanned — i.e. *after* the `--max-endpoints` cap was applied. May be 0 for `--code`-only. |
| `endpoints_discovered` | integer | no | Number of endpoints found **before** `--max-endpoints` truncated the list. Omitted when zero. Without it, `endpoints_scanned: 500` cannot be distinguished from "found exactly 500" vs "found 801, capped to 500". When no cap fires, this equals `endpoints_scanned`. |
| `endpoints_truncated` | boolean | no | `true` when the `--max-endpoints` cap actually dropped endpoints. Omitted when false. Pair with `endpoints_discovered` to detect a silent coverage gap from a CI gate. |
| `active_probes` | boolean | yes | Whether `--enable-active` was set. |
| `checks_run` | array of string | no | Names of checks executed. Omitted when empty. |
| `scanner_status` | array of `ScannerStatus` | no | Per-scanner outcome for the dependency-CVE, secrets, semgrep and textscan passes. Omitted (empty) for pure black-box scans that run no code scanners. See below. |

### ScannerStatus

```json
{"name": "govulncheck", "state": "skipped", "detail": "offline mode"}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Scanner identity: `govulncheck`, `pip`, `npm`, `secrets`, `semgrep`, `textscan`. |
| `state` | string enum | yes | One of `ok`, `skipped`, `failed`. |
| `detail` | string | no | Short human-readable reason — the skip cause or an error excerpt. Omitted when empty. |

`scanner_status` ends the historical fail-open behaviour where a scanner crash
was logged at WARN and silently dropped. A `skipped` state is **not** a failure
— it means the precondition was absent (no manifest, tool not installed) or the
scanner cannot run in the current mode (e.g. `govulncheck` under `--offline`,
which needs `vuln.go.dev`). Only `failed` counts as a failure: it feeds
`--fail-on-scanner-error` and SARIF's `invocations[].executionSuccessful`. A
consumer that wants "was this scan complete?" should check for any `failed`
entry rather than inferring coverage from `total`.

---

## Finding

```json
{
  "id":                  "SEC-001",
  "title":               "Hardcoded API key detected",
  "severity":            "CRITICAL",
  "source":              "whitebox",
  "category":            "secrets",
  "endpoint":            "src/config.py:14",
  "affected_endpoints":  ["src/config.py:14", "src/admin.py:22"],
  "evidence":            "API_KEY = 'sk-live-abc... [REDACTED]'",
  "fix":                 "Move to environment variable. Rotate the exposed key immediately.",
  "references":          ["CWE-798"],
  "confidence":          "HIGH",
  "line":                "src/config.py:14",
  "taint_chain":         [
    {"file": "app/views.py", "line": 12, "expr": "q = request.args.get('q')"},
    {"file": "app/views.py", "line": 14, "expr": "sql = 'SELECT * FROM users WHERE name=' + q"},
    {"file": "app/views.py", "line": 15, "expr": "cursor.execute(sql)"}
  ],
  "reachable":           true
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string (`SEC-NNN`) | yes | Sequential ID assigned by the orchestrator. Stable for a single scan only. |
| `title` | string | yes | Human-readable finding title. |
| `severity` | string enum | yes | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `source` | string enum | yes | One of `blackbox`, `whitebox`, `correlated`. |
| `category` | string | yes | Taxonomy category (`auth_bypass`, `injection`, `secrets`, `idor`, `data_exposure`, `cors`, `headers`, `info_disclosure`, `auth`, ...). |
| `endpoint` | string | yes | URL path or `file:line`. Primary endpoint for this finding. |
| `affected_endpoints` | array of string | no | Populated only when dedup collapsed `N≥2` occurrences into one finding. Includes the primary `endpoint`. |
| `evidence` | string | yes | Snippet showing what was detected. Credentials are masked as `[REDACTED]`. May end with the suffix `[Unconfirmed by live scan]` when correlation against a live scan ran but produced no match. |
| `fix` | string | yes | Remediation guidance. |
| `references` | array of string | yes | CWE / OWASP / RFC identifiers. May be empty array. |
| `confidence` | string enum | yes | One of `HIGH`, `MEDIUM`, `LOW`. |
| `line` | string \| null | yes | File and line for whitebox findings, e.g. `"src/config.py:14"`. Always serialised; `null` when not applicable. |
| `taint_chain` | array of `TaintLink` | no | Whitebox dataflow proof: ordered chain from source (e.g. `request.args.get`) through intermediate assignments to the sink. Each link is `{file, line, expr}`. Emitted by the Python AST analyzer for SQLi / SSRF / open-redirect / XSS / command-injection findings when intra-function dataflow resolves end-to-end. Inherited onto the merged `source: "correlated"` finding. Omitted when no chain was proven. |
| `reachable` | boolean | no | Whitebox-proven that user input reaches the sink. Currently implies `taint_chain` is non-empty. Used by the correlator to apply a *second* severity escalation on top of the standard correlated-bonus (so MEDIUM × MEDIUM × reachable → CRITICAL). Omitted (treat as `false`) when not proven. |
| `fingerprint` | string | no | Content-derived stable identity `sha1(category\|endpoint\|title)`; survives across scans for suppressions/baselines. |
| `source_tier` | string enum | no | Analyzer tier that produced a whitebox finding: `native_go`, `tree_sitter_sidecar`, `semgrep_shim`. |
| `route` | object | no | HTTP route binding `{method, pattern, handler, file, line}` (Proven Path v1). |
| `route_confirmed` | boolean | no | A live blackbox scan hit the finding's `route.pattern`. |
| `proven_path` | boolean | no | `route_confirmed` AND `reachable` — DAST hit + SAST taint path + exact route. |
| `status` | string enum | no | **v0.24** decision verdict: `BLOCK`, `WARN`, `INFO`. Since v1.2.2 `BLOCK` additionally requires the confidence band to support the claim — see the decision-summary section below. |
| `confidence_score` | integer (0–100) | no | **v0.24** deterministic confidence score (see Confidence Engine). |
| `confidence_band` | string enum | no | **v0.24** score-derived band `HIGH`/`MEDIUM`/`LOW`. Distinct from `confidence` (the scanner/correlator enum, unchanged for back-compat). |
| `confidence_reasons` | array of string | no | **v0.24** plain-text, per-rule breakdown of the score (no black boxes). |

### Decision summary & confidence (v0.24)

`decisions` reduces the finding list to "what needs action": `blocking`
(status `BLOCK` — the build-failing set), `warning`, `informational`, and
`confirmed` (HIGH-confidence, the v0.23 score axis — kept distinct from
`sources.correlated`). Per-finding `status` + `confidence_*` mirror this. The
score is deterministic and rule-based (no AI); see `internal/confidence`. All
v0.24 fields are additive/optional — existing consumers are unaffected
(minor-release additive policy above).

**`BLOCK` is not "severity ≥ `--fail-on`" as of v1.2.2.** Meeting the threshold
is necessary but no longer sufficient: under the default `--enforce-confidence`
a finding also needs its band to support the claim — HIGH always blocks, MEDIUM
blocks only with at least one corroborating signal, LOW never blocks — and a
finding the correlator marked unconfirmed-by-live-scan never blocks
uncorroborated. `--enforce-confidence=false` restores the severity-only mapping.
`confidence_reasons` carries a `+0` line naming the reason whenever a
threshold-crossing finding was held at WARN, so the demotion is always
attributable from the report alone. See CHANGELOG `[Unreleased]` for the full
rule table.

**SARIF level note:** as of v0.24 the SARIF result `level` follows the
decision verdict (`BLOCK`→`error`, `WARN`→`warning`, `INFO`→`note`), not raw
severity. Because nothing is `BLOCK` without a threshold, a bare
`fendix scan --format sarif` (no `--fail-on`) emits every result at
`warning`/`note` and zero `error`. SARIF consumers that key off `error` level
should pass `--fail-on` (the GitHub Action defaults to `fail-on: HIGH`).
Build-blocking is driven by the exit code, not the SARIF level.

### Severity ↔ confidence consistency

The orchestrator enforces a consistency rule before reports are written: a
finding with `confidence: "LOW"` cannot have `severity` higher than `MEDIUM`.
This matches the implicit cap from the scoring formula (`base × 0.5` is
≤ 5.0 for every category, which lands at MEDIUM or below). Findings that
violate the rule have their severity downgraded; the original score is
preserved in the scoring formula's intent.

### `[Unconfirmed by live scan]` suffix semantics

The suffix is appended to a whitebox finding's `evidence` only when:

1. Both engines actually ran (the orchestrator only invokes correlation when
   blackbox **and** whitebox findings exist), AND
2. The whitebox finding's `endpoint` normalises to a URL path (e.g. `/users`
   or `GET /users`) — i.e. live scanning could in principle have caught it.

Source-only findings (e.g. a hardcoded secret at `src/config.py:14`) never
receive the suffix because a live scan cannot observe source files.

As of v1.2.2 the suffix has an internal machine-readable counterpart
(`evidence.Evidence.UnconfirmedByLiveScan`) produced at the same moment by the
same code, which the decision layer reads: a finding carrying it cannot reach
status `BLOCK` under the default policy unless a corroborating signal is also
present. **No new JSON field is added** — the public `Finding` shape is
unchanged and the suffix text is byte-identical — so consumers that parse the
prose suffix keep working exactly as before. The marker exists so that
enforcement gates on structure instead of on a published string.

---

## Severity values

| Value | Numeric rank | Meaning |
|---|---|---|
| `CRITICAL` | 4 | Immediate exploit risk; e.g. unauth admin endpoint, exposed live API key. |
| `HIGH` | 3 | High-impact bug requiring privileged access or specific conditions. |
| `MEDIUM` | 2 | Defence-in-depth violation (missing security header, weak CORS). |
| `LOW` | 1 | Informational with mild impact. |
| `INFO` | 0 | Diagnostic only; no exploit path. |

## Confidence values

| Value | Meaning |
|---|---|
| `HIGH` | Detected by direct evidence (regex hit, error response, `correlated` finding). |
| `MEDIUM` | Pattern match with potential false positives (boolean-based SQLi, semgrep MEDIUM). |
| `LOW` | Heuristic or statistical signal. |

## Source values

| Value | Meaning |
|---|---|
| `blackbox` | Produced by the Go HTTP scanner against a live target. |
| `whitebox` | Produced by a static analyser against source / spec. Since TASK-115/116 this covers the native-Go secrets scanner and the Go Semgrep shell-out as well as the (opt-in `--python-engine`) Python AST and spec analysers — `source` does not distinguish which; use `source_tier` for that. |
| `correlated` | Produced by the correlator when both engines agree on the same endpoint + related category. Severity is escalated by one level; confidence is `HIGH`. |

---

## Stability guarantees

- New optional fields may be added in minor releases (`1.1.0` added none).
- Existing field types and enum values do **not** change in minor releases.
- A field marked optional may become required only in a major release.
- Removing a field is reserved for major releases (next: `2.0.0`).
- "Optional" in `schema.json` means *this schema will validate a report that
  omits it*, not *current builds may omit it*. Fields whose Go struct tag
  carries no `omitempty` — `decisions` today — are always emitted by a current
  build; the optional marking exists so archived reports from older releases
  still validate.

If you build tooling that consumes Fendix JSON, validate against
[`schema.json`](./schema.json) and pin the schema version through your CI.
