# Fendix — Full Build Specification for Claude Code

> **Hand this entire document to Claude Code.** It contains everything needed to scaffold, implement, and test the full Fendix project from scratch. Read it completely before writing any code.

---

## Project Overview

**Fendix** is a hybrid API and code security scanner with two engines:

- **Go layer** — CLI interface, HTTP black-box scanner, orchestrator, report renderer
- **Python layer** — White-box static analysis engine (Semgrep, AST, secrets detection)

The user interacts only with the Go binary. Go spawns Python as a subprocess when white-box analysis is requested. Communication is newline-delimited JSON over stdin/stdout.

---

## Repository Layout

```
fendix/
├── go/
│   ├── cmd/fendix/main.go
│   ├── internal/
│   │   ├── scanner/
│   │   │   ├── crawler.go
│   │   │   ├── headers.go
│   │   │   ├── cors.go
│   │   │   ├── auth.go
│   │   │   ├── injection.go
│   │   │   ├── ratelimit.go
│   │   │   └── exposure.go
│   │   ├── engine/
│   │   │   ├── orchestrator.go
│   │   │   └── correlator.go
│   │   ├── models/
│   │   │   ├── finding.go
│   │   │   └── config.go
│   │   └── reporters/
│   │       ├── json.go
│   │       ├── html.go
│   │       └── sarif.go
│   ├── go.mod
│   └── go.sum
│
├── python/
│   ├── engine.py
│   ├── analyzers/
│   │   ├── spec_parser.py
│   │   ├── secrets.py
│   │   ├── semgrep_runner.py
│   │   ├── ast_analyzer.py
│   │   └── deps.py
│   ├── rules/
│   │   ├── auth.yaml
│   │   ├── injection.yaml
│   │   └── secrets.yaml
│   └── requirements.txt
│
├── scripts/
│   ├── build.sh
│   └── install.sh
├── Dockerfile
├── .fendix-ignore.example
└── README.md
```

---

## Part 1 — Shared Data Contract

This is the most important section. Both Go and Python must implement this contract exactly.

### Finding (Python → Go, newline-delimited JSON)

```json
{
  "id": "SEC-001",
  "title": "Missing authentication on endpoint",
  "severity": "CRITICAL",
  "source": "blackbox",
  "category": "auth",
  "endpoint": "GET /api/users",
  "evidence": "HTTP 200 returned without Authorization header",
  "fix": "Require Bearer token. Return 401 for unauthenticated requests.",
  "references": ["CWE-306", "OWASP-A01"],
  "confidence": "HIGH",
  "line": null
}
```

Fields:
- `id` — sequential, prefixed `SEC-`, assigned by Go orchestrator
- `severity` — one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `source` — one of: `blackbox`, `whitebox`, `correlated`
- `confidence` — one of: `HIGH`, `MEDIUM`, `LOW`
- `line` — file:line for whitebox findings, null for blackbox

### ScanRequest (Go → Python, single JSON line on stdin)

```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

### Python stream terminator

When Python finishes, it writes exactly:
```json
{"done": true, "total": 12}
```

---

## Part 2 — Go Layer

### 2.1 CLI (cobra)

Commands:

```
fendix scan     — run a scan
fendix report   — re-render a saved JSON findings file
fendix verify   — re-run a single finding by ID
fendix version  — print version info
```

#### `scan` flags

| Flag | Type | Description |
|---|---|---|
| `--url` | string | Target API base URL (black-box) |
| `--spec` | string | Path to OpenAPI/Swagger YAML or JSON |
| `--code` | string | Path to source code directory (white-box) |
| `--auth` | string | Auth header value e.g. `"Bearer token123"` |
| `--auth-type` | string | `bearer`, `apikey`, `basic`, `cookie` (default: auto-detect) |
| `--auth-header` | string | Custom auth header name (default: `Authorization`) |
| `--output` | string | Output file path (default: stdout) |
| `--format` | string | `json`, `html`, `sarif` (default: `json`) |
| `--fail-on` | string | Exit 1 if findings at this severity or above: `CRITICAL`, `HIGH`, `MEDIUM` |
| `--baseline` | string | Path to previous findings JSON for diff mode |
| `--save-baseline` | string | Save current findings to this path |
| `--enable-active` | bool | Enable active injection probes (default: false) |
| `--workers` | int | Concurrent HTTP workers (default: 10) |
| `--timeout` | int | HTTP timeout in seconds (default: 10) |
| `--delay` | int | Milliseconds between requests (default: 100) |
| `--ignore` | string | Path to .fendix-ignore file |
| `--verbose` | bool | Print all requests and raw findings |

#### Exit codes

- `0` — scan completed, no findings at or above `--fail-on` threshold
- `1` — scan completed, findings found at or above threshold
- `2` — scan error (network failure, invalid config, etc.)

### 2.2 Models (go/internal/models/)

#### finding.go

```go
package models

type Severity string
const (
    SeverityCritical Severity = "CRITICAL"
    SeverityHigh     Severity = "HIGH"
    SeverityMedium   Severity = "MEDIUM"
    SeverityLow      Severity = "LOW"
    SeverityInfo     Severity = "INFO"
)

type Confidence string
const (
    ConfidenceHigh   Confidence = "HIGH"
    ConfidenceMedium Confidence = "MEDIUM"
    ConfidenceLow    Confidence = "LOW"
)

type Source string
const (
    SourceBlackbox   Source = "blackbox"
    SourceWhitebox   Source = "whitebox"
    SourceCorrelated Source = "correlated"
)

type Finding struct {
    ID         string     `json:"id"`
    Title      string     `json:"title"`
    Severity   Severity   `json:"severity"`
    Source     Source     `json:"source"`
    Category   string     `json:"category"`
    Endpoint   string     `json:"endpoint"`
    Evidence   string     `json:"evidence"`
    Fix        string     `json:"fix"`
    References []string   `json:"references"`
    Confidence Confidence `json:"confidence"`
    Line       *string    `json:"line"`
}

// SeverityRank returns numeric rank for comparison (higher = worse)
func SeverityRank(s Severity) int {
    switch s {
    case SeverityCritical: return 4
    case SeverityHigh:     return 3
    case SeverityMedium:   return 2
    case SeverityLow:      return 1
    default:               return 0
    }
}
```

#### config.go

```go
package models

type AuthContext struct {
    Type   string // bearer | apikey | basic | cookie
    Value  string
    Header string // default: Authorization
}

type ScanConfig struct {
    URL          string
    SpecPath     string
    CodePath     string
    Auth         *AuthContext
    EnableActive bool
    Workers      int
    Timeout      int
    DelayMs      int
    Checks       []string
    Verbose      bool
    IgnorePath   string
    BaselinePath string
}
```

### 2.3 HTTP Scanner Checks

Implement each check as a function with this signature:

```go
type CheckFn func(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding
```

Where `Endpoint` is:
```go
type Endpoint struct {
    Method  string
    Path    string
    FullURL string
    Params  []string
}
```

#### headers.go — Security Headers Check

For each endpoint, send a GET request and check response headers.

| Header | Expected | Missing = Severity |
|---|---|---|
| `Strict-Transport-Security` | present | MEDIUM |
| `X-Content-Type-Options` | `nosniff` | LOW |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | LOW |
| `Content-Security-Policy` | present | MEDIUM |
| `X-XSS-Protection` | `0` (deprecated) or absent | INFO |
| `Server` | absent or generic | INFO (if version disclosed) |
| `X-Powered-By` | absent | INFO |

#### cors.go — CORS Misconfiguration

Send request with header `Origin: https://evil.example.com`.

Check response:
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` → CRITICAL
- `Access-Control-Allow-Origin: *` → MEDIUM
- `Access-Control-Allow-Origin` reflects arbitrary origin → HIGH
- `Access-Control-Allow-Methods` includes non-standard methods → LOW

#### auth.go — Authentication Checks

For each endpoint that requires auth:

1. Send request without any auth header → expect 401/403. If 200 → CRITICAL finding "Missing authentication"
2. Send request with malformed JWT (`Authorization: Bearer invalid.jwt.token`) → expect 401. If 200 → CRITICAL finding "JWT not validated"
3. Send request with expired JWT (generate one with `exp` in the past, signed with known secret `"secret"`) → expect 401. If 200 → CRITICAL finding "Expired JWT accepted"
4. Check if JWT uses `alg: none` → accept it → CRITICAL finding "JWT algorithm confusion"

JWT generation for test tokens: use `github.com/golang-jwt/jwt/v5`.

#### injection.go — Injection Detection (active only, requires `--enable-active`)

**SQL Injection — time-based blind:**

For each parameter (query string, path param, JSON body field):
1. Record baseline response time (3 requests, take median)
2. Send payload: append `' AND SLEEP(5)--` (MySQL), `' AND pg_sleep(5)--` (Postgres)
3. If response time > baseline + 4 seconds → HIGH finding "Potential SQL Injection"
4. Confidence: HIGH if consistent across 2 probes, MEDIUM if single measurement

**Command Injection — use safe echo payload:**

Send payload: `; echo fendix_canary_$(date +%s)` in string parameters.
If response body contains `fendix_canary_` → CRITICAL finding "Command Injection confirmed".

**Header Injection — CRLF:**

Inject `%0d%0aSET-COOKIE: fendix=injected` into header values.
If response contains `fendix=injected` cookie → HIGH finding "Header Injection / CRLF".

#### ratelimit.go — Rate Limiting Detection

Send 20 identical requests to an endpoint in rapid succession (no delay).
If all 20 return 200 with no 429/throttle header → MEDIUM finding "No rate limiting detected".
Check for headers: `X-RateLimit-*`, `Retry-After`, `X-Rate-Limit-*`.

#### exposure.go — Sensitive Data Exposure

Scan response bodies for:

| Pattern | Finding |
|---|---|
| `"password":` in JSON response | CRITICAL |
| `"secret":` or `"api_key":` in JSON | CRITICAL |
| `"token":` with long string value | HIGH |
| Internal IDs that look sequential (1, 2, 3) in user endpoints | MEDIUM (IDOR risk) |
| Stack traces in error responses | MEDIUM |
| Internal IP addresses (10.x, 172.16.x, 192.168.x) | LOW |
| Software version strings | INFO |

Use regex patterns for each. Log evidence as a truncated snippet (max 200 chars).

### 2.4 Crawler (go/internal/scanner/crawler.go)

Endpoint discovery priority order:

1. **From OpenAPI spec** — parse all `paths` entries, generate full URL for each method. This is the primary source when `--spec` is provided.
2. **From JS files** — fetch base URL, look for `<script src=...>` tags, download each JS file, extract string patterns matching `/api/...` paths using regex.
3. **Common path brute-force** — try a hardcoded list of ~50 common API paths (`/api/v1/users`, `/api/health`, `/api/docs`, `/swagger.json`, etc.)

Return deduplicated `[]Endpoint` list.

### 2.5 Orchestrator (go/internal/engine/orchestrator.go)

```
1. Parse config and validate
2. Run crawler → get []Endpoint
3. Run all blackbox checks concurrently (worker pool, cfg.Workers goroutines)
4. If cfg.CodePath or cfg.SpecPath provided:
   a. Build ScanRequest JSON
   b. Spawn python/engine.py as subprocess
   c. Write ScanRequest to subprocess stdin
   d. Read Finding JSON lines from stdout until {"done":true}
   e. Collect whitebox findings
5. Run correlator on combined findings
6. Assign sequential IDs (SEC-001, SEC-002, ...)
7. Apply ignore rules from .fendix-ignore
8. Apply baseline diff if --baseline provided
9. Render report
10. Exit with appropriate code
```

### 2.6 Correlator (go/internal/engine/correlator.go)

Cross-correlate blackbox and whitebox findings:

- If whitebox finds "missing auth check on route X" AND blackbox confirms endpoint X returns 200 without auth:
  → Merge into single finding, source=`correlated`, confidence=`HIGH`, severity escalated by one level
- If whitebox finds issue but blackbox does NOT confirm:
  → Keep whitebox finding, confidence=`MEDIUM`, add note "Unconfirmed by live scan"
- If blackbox finds issue but no whitebox counterpart:
  → Keep as-is

Match endpoints by normalizing paths (strip version prefix, lowercase).

### 2.7 Reporters

#### json.go
Output full findings array as pretty-printed JSON. Include scan metadata (timestamp, target URL, total counts by severity).

#### html.go
Generate self-contained single-file HTML report. Include:
- Executive summary with severity counts (use inline CSS, no external dependencies)
- Findings table sortable by severity
- Expandable rows showing evidence and fix
- Color coding: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=gray
- Scan metadata footer

#### sarif.go
Output SARIF 2.1.0 format. Map:
- `Finding.ID` → `ruleId`
- `Finding.Severity` → `level` (CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`)
- `Finding.Fix` → `help.text`
- `Finding.References` → `helpUri` (first reference)

---

## Part 3 — Python Layer

### 3.1 engine.py (entrypoint)

```python
#!/usr/bin/env python3
"""
Fendix Python Engine
Reads ScanRequest from stdin, streams Finding JSON to stdout.
Usage: python engine.py < request.json
"""
import sys, json
from analyzers.spec_parser import SpecParser
from analyzers.secrets import SecretsAnalyzer
from analyzers.semgrep_runner import SemgrepRunner
from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.deps import DepsAnalyzer

def emit(finding: dict):
    print(json.dumps(finding), flush=True)

def main():
    raw = sys.stdin.read()
    request = json.loads(raw)
    
    checks = request.get("checks", [])
    findings = []
    counter = [0]

    def emit_finding(f):
        counter[0] += 1
        emit(f)

    if "secrets" in checks and request.get("code_path"):
        SecretsAnalyzer(request["code_path"]).run(emit_finding)

    if "semgrep" in checks and request.get("code_path"):
        SemgrepRunner(request["code_path"], request.get("language")).run(emit_finding)

    if "auth" in checks and request.get("spec"):
        SpecParser(request["spec"]).check_auth(emit_finding)

    if request.get("verbose"):
        print(json.dumps({"log": f"Python engine completed {counter[0]} findings"}), flush=True)

    print(json.dumps({"done": True, "total": counter[0]}), flush=True)

if __name__ == "__main__":
    main()
```

### 3.2 analyzers/spec_parser.py

Parse OpenAPI 2.0 / 3.x YAML or JSON spec.

```python
class SpecParser:
    def __init__(self, spec_path: str):
        # Load and parse spec
        # Support both JSON and YAML
        # Support OpenAPI 2.0 (swagger) and 3.x

    def get_endpoints(self) -> list[dict]:
        # Return list of {method, path, parameters, security, operationId}

    def check_auth(self, emit_fn):
        # For each endpoint:
        # - If no security scheme defined → emit MEDIUM finding "No auth defined in spec"
        # - If security scheme is apiKey in query param → emit LOW "API key in URL"
        # - If no global security and endpoint has no local security → emit HIGH
```

### 3.3 analyzers/secrets.py

Walk code_path recursively. Skip: `.git/`, `node_modules/`, `vendor/`, `*.min.js`.

Detect using regex patterns:

```python
PATTERNS = {
    "aws_key":       (r"AKIA[0-9A-Z]{16}", "CRITICAL", "AWS Access Key"),
    "private_key":   (r"-----BEGIN (RSA |EC )?PRIVATE KEY", "CRITICAL", "Private key in source"),
    "generic_secret":(r"(?i)(secret|password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}", "HIGH", "Hardcoded secret"),
    "api_key":       (r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{8,}", "HIGH", "Hardcoded API key"),
    "jwt_secret":    (r"(?i)jwt[_-]?secret\s*=\s*['\"][^'\"]{4,}", "HIGH", "Hardcoded JWT secret"),
    "db_url":        (r"(?i)(postgres|mysql|mongodb)://[^'\"@]+:[^'\"@]+@", "HIGH", "Database credentials in URL"),
    "bearer_token":  (r"(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}", "MEDIUM", "Hardcoded Bearer token"),
}
```

For each match, emit finding with `line` field set to `filename:lineno`.
Truncate evidence to 100 chars, mask the middle of the secret value.

### 3.4 analyzers/semgrep_runner.py

```python
import subprocess, json

class SemgrepRunner:
    RULES_PATH = Path(__file__).parent.parent / "rules"

    def run(self, emit_fn):
        result = subprocess.run([
            "semgrep", "--config", str(self.RULES_PATH),
            "--json", "--quiet",
            self.code_path
        ], capture_output=True, text=True)

        data = json.loads(result.stdout)
        for r in data.get("results", []):
            emit_fn({
                "title": r["check_id"].replace(".", " ").title(),
                "severity": self._map_severity(r["extra"]["severity"]),
                "source": "whitebox",
                "category": "semgrep",
                "endpoint": f"{r['path']}:{r['start']['line']}",
                "evidence": r["extra"]["message"],
                "fix": r["extra"].get("fix", "See rule documentation"),
                "references": [r["extra"].get("metadata", {}).get("cwe", "")],
                "confidence": "MEDIUM",
                "line": f"{r['path']}:{r['start']['line']}"
            })
```

### 3.5 rules/auth.yaml (Semgrep rule example)

```yaml
rules:
  - id: missing-auth-decorator
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @login_required
          def $FUNC(...):
              ...
      - pattern-not: |
          @jwt_required
          def $FUNC(...):
              ...
    message: "Flask route $FUNC has no authentication decorator"
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-306
      category: auth

  - id: express-no-auth-middleware
    patterns:
      - pattern: app.$METHOD($PATH, $HANDLER)
      - pattern-not: app.$METHOD($PATH, authenticate, $HANDLER)
      - pattern-not: app.$METHOD($PATH, requireAuth, $HANDLER)
    message: "Express route may be missing authentication middleware"
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-306
      category: auth
```

### 3.6 rules/injection.yaml

```yaml
rules:
  - id: sql-string-concat
    pattern: |
      $QUERY = "SELECT " + $VAR
    message: "String concatenation in SQL query — potential SQL injection"
    severity: ERROR
    languages: [python, javascript]
    metadata:
      cwe: CWE-89

  - id: python-exec-user-input
    patterns:
      - pattern: exec($INPUT)
      - pattern: eval($INPUT)
    message: "exec/eval with potentially untrusted input"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-78

  - id: subprocess-shell-true
    pattern: subprocess.run(..., shell=True, ...)
    message: "subprocess with shell=True may allow command injection"
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-78
```

### 3.7 rules/secrets.yaml

```yaml
rules:
  - id: hardcoded-jwt-secret
    pattern: |
      jwt.encode(..., "$SECRET", ...)
    pattern-not: |
      jwt.encode(..., os.environ[...], ...)
    message: "Hardcoded JWT secret"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-798
```

### 3.8 requirements.txt

```
semgrep>=1.45.0
bandit>=1.7.5
pyyaml>=6.0
openapi-spec-validator>=0.7.1
detect-secrets>=1.4.0
packaging>=23.0
```

---

## Part 4 — Configuration Files

### .fendix-ignore.example

```yaml
# Fendix ignore file
# Place as .fendix-ignore in your project root or pass via --ignore

ignore:
  # Suppress by finding ID
  - id: SEC-014
    reason: "Rate limiting handled at API gateway level"
    until: 2025-12-01  # optional expiry date

  # Suppress entire endpoint
  - endpoint: GET /health
    reason: "Public health check endpoint by design"

  # Suppress by category on specific endpoint
  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints intentionally unauthenticated"
```

### go.mod

```
module github.com/yourusername/fendix

go 1.21

require (
    github.com/spf13/cobra v1.8.0
    github.com/go-resty/resty/v2 v2.11.0
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/fatih/color v1.16.0
)
```

---

## Part 5 — Build & Distribution

### scripts/build.sh

```bash
#!/bin/bash
set -e

echo "→ Installing Python dependencies..."
pip install -r python/requirements.txt --target python/vendor/ -q

echo "→ Building Go binary..."
cd go
go build -ldflags="-s -w -X main.Version=$(git describe --tags --always)" \
  -o ../bin/fendix ./cmd/fendix/
cd ..

echo "✓ Built: bin/fendix"
```

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS go-builder
WORKDIR /build
COPY go/ .
RUN go build -o /fendix ./cmd/fendix/

FROM python:3.11-slim
RUN pip install semgrep bandit detect-secrets pyyaml openapi-spec-validator packaging
COPY --from=go-builder /fendix /usr/local/bin/fendix
COPY python/ /opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/engine.py
ENTRYPOINT ["fendix"]
```

---

## Part 6 — Severity Scoring Logic

```go
// go/internal/models/scoring.go

var ImpactBase = map[string]float64{
    "auth_bypass":    10.0,
    "injection":       9.5,
    "secrets":         9.0,
    "idor":            8.5,
    "data_exposure":   7.0,
    "cors":            6.5,
    "headers":         4.0,
    "info_disclosure": 2.0,
}

var ConfidenceMult = map[Confidence]float64{
    ConfidenceHigh:   1.0,
    ConfidenceMedium: 0.75,
    ConfidenceLow:    0.5,
}

var SourceMult = map[Source]float64{
    SourceCorrelated: 1.1,  // correlated = higher confidence
    SourceBlackbox:   1.0,
    SourceWhitebox:   0.9,
}

func CalculateSeverity(category string, confidence Confidence, source Source) Severity {
    base := ImpactBase[category]
    score := base * ConfidenceMult[confidence] * SourceMult[source]

    switch {
    case score >= 9.0: return SeverityCritical
    case score >= 7.0: return SeverityHigh
    case score >= 4.0: return SeverityMedium
    case score >= 1.0: return SeverityLow
    default:           return SeverityInfo
    }
}
```

---

## Part 7 — Testing Requirements

### Go tests (go/internal/...)

Write table-driven tests for:
- `TestHeadersCheck` — mock HTTP server returning various header combinations
- `TestCORSCheck` — mock server with CORS misconfiguration scenarios
- `TestAuthCheck` — mock server returning 200 for unauthenticated requests
- `TestCorrelator` — unit test merging sample blackbox + whitebox findings
- `TestSeverityScoring` — all category/confidence/source combinations
- `TestFindingIDAssignment` — sequential ID generation

Use `net/http/httptest` for mock servers.

### Python tests (python/tests/)

Write pytest tests for:
- `test_spec_parser.py` — parse sample OpenAPI 2.0 and 3.0 specs
- `test_secrets.py` — detect all pattern types in sample code snippets
- `test_engine_contract.py` — verify engine.py outputs valid Finding JSON

Include sample fixture files in `python/tests/fixtures/`.

---

## Part 8 — README.md

Write a complete README with:

1. **Quick start** (3 commands: install, run first scan, view report)
2. **Installation** (brew, curl install script, Docker, build from source)
3. **Usage examples** — one per common scenario (black-box only, white-box only, hybrid, CI/CD)
4. **All CLI flags** with descriptions and defaults
5. **Report formats** with example output
6. **CI/CD integration** — GitHub Actions example workflow
7. **Configuration** — .fendix-ignore format
8. **Architecture** — brief explanation of Go+Python hybrid
9. **Contributing** — how to add new checks
10. **License**

---

## Implementation Order

Build in this exact order to always have something runnable:

1. `go/internal/models/finding.go` + `config.go` — data models first
2. `go/internal/models/scoring.go` — severity logic
3. `go/cmd/fendix/main.go` + cobra CLI skeleton — runnable but does nothing
4. `go/internal/scanner/headers.go` — first real check, passive, safe
5. `go/internal/scanner/cors.go` — second passive check
6. `go/internal/scanner/crawler.go` — endpoint discovery
7. `go/internal/reporters/json.go` — output something useful
8. `go/internal/reporters/html.go` — visual report
9. `go/internal/scanner/auth.go` — auth checks
10. `go/internal/scanner/exposure.go` — response scanning
11. `go/internal/engine/orchestrator.go` — wire everything together
12. `python/engine.py` + `analyzers/secrets.py` — Python engine starts
13. `python/analyzers/spec_parser.py`
14. `python/analyzers/semgrep_runner.py` + rules
15. `go/internal/engine/correlator.go` — cross-correlation
16. `go/internal/reporters/sarif.go` — CI/CD format
17. `go/internal/scanner/injection.go` — active probes (last, most dangerous)
18. Tests throughout
19. `scripts/build.sh` + `Dockerfile`
20. `README.md`

---

## Constraints & Non-Negotiables

1. **Never run active checks by default.** `--enable-active` must be explicitly passed.
2. **Every HTTP request must respect `--delay` between calls.**
3. **Auth credentials must never appear in report output** — mask them as `[REDACTED]`.
4. **The Python engine must be spawnable independently** for debugging: `echo '{"mode":"whitebox","code_path":"./src","checks":["secrets"]}' | python python/engine.py`
5. **All findings must be deterministic** — same input produces same output (sort by endpoint+category before ID assignment).
6. **The HTML report must be a single self-contained file** — no external CSS/JS dependencies.
7. **Baseline diff must only report new findings** — never re-report suppressed or pre-existing issues.
8. **SARIF output must be valid** against the SARIF 2.1.0 schema.

---

*End of Fendix specification. Claude Code should now have everything needed to build the complete project.*
