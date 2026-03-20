# Fendix

**Find vulnerabilities before attackers do.**

Fendix is a hybrid API and code security scanner that combines black-box HTTP probing with white-box static analysis to produce high-confidence security findings with evidence. When both engines agree on a vulnerability, it becomes a *correlated* finding — fewer false positives, more actionable results.

---

## Quick Start

```bash
# 1. Install
curl -fsSL https://get.fendix.dev | sh

# 2. Run your first scan
fendix scan --url https://api.example.com --format html --output report.html

# 3. Open the report
open report.html
```

That's it. Fendix scans the API for missing security headers, CORS misconfigurations, authentication bypasses, sensitive data exposure, and rate limiting issues — all without sending any destructive payloads.

---

## Installation

### Homebrew (macOS / Linux)

```bash
brew tap fendix/tap
brew install fendix
```

### curl (macOS / Linux)

```bash
curl -fsSL https://get.fendix.dev | sh
```

This downloads the latest release binary to `/usr/local/bin/fendix`.

### Docker

```bash
docker pull ghcr.io/fendix/fendix:latest
docker run --rm ghcr.io/fendix/fendix scan --url https://api.example.com
```

The Docker image includes Python and all static analysis dependencies, so hybrid mode works out of the box.

### Build from Source

Requires Go 1.21+ and Python 3.9+.

```bash
git clone https://github.com/Abdel-RahmanSaied/Fendix.git
cd fendix
make build
./bin/fendix version
```

For white-box analysis, install Python dependencies:

```bash
pip install -r python/requirements.txt
```

---

## Usage Examples

### Black-box scan (HTTP probing only)

Point Fendix at a live API. No source code needed.

```bash
fendix scan --url https://api.example.com
```

This runs all passive checks: security headers, CORS, authentication bypass, sensitive data exposure, and rate limiting.

### White-box scan (static analysis only)

Analyze source code without making any network requests.

```bash
fendix scan --code ./src --spec openapi.yaml
```

This runs secrets detection, Semgrep rules, AST analysis, OpenAPI spec checks, and dependency CVE scanning.

### Hybrid scan (maximum coverage)

Run both engines and cross-correlate findings for highest confidence.

```bash
fendix scan \
  --url https://api.example.com \
  --code ./src \
  --spec openapi.yaml \
  --format html \
  --output report.html
```

When the black-box scanner and static analyzer both identify the same vulnerability, Fendix merges them into a single `correlated` finding with elevated confidence.

### Authenticated scan

Provide credentials to test endpoints behind authentication.

```bash
# Bearer token
fendix scan --url https://api.example.com --auth "Bearer eyJhbG..."

# API key with custom header
fendix scan --url https://api.example.com \
  --auth "sk-live-abc123" \
  --auth-type apikey \
  --auth-header "X-API-Key"

# Basic auth
fendix scan --url https://api.example.com \
  --auth "admin:password" \
  --auth-type basic
```

Auth credentials are **always masked as `[REDACTED]`** in all report output.

### Active injection testing (opt-in)

Test for SQL injection, command injection, and header injection. **Off by default** — requires explicit consent.

```bash
fendix scan --url https://api.example.com --enable-active
```

A legal disclaimer is printed when active probing is enabled. Only use this against systems you own or have written authorization to test.

### CI/CD gating

Fail the pipeline if critical or high severity findings are detected.

```bash
fendix scan \
  --url https://api.staging.example.com \
  --code ./src \
  --fail-on HIGH \
  --format sarif \
  --output results.sarif
```

Exit code `1` means findings were found at or above the threshold. Exit code `0` means the scan passed.

### Baseline diff mode

Only report **new** findings compared to a previous scan. Ideal for PR workflows.

```bash
# Save a baseline
fendix scan --url https://api.example.com --save-baseline baseline.json

# Later, compare against it
fendix scan --url https://api.example.com --baseline baseline.json
```

### Re-render a report

Convert a saved JSON findings file to HTML or SARIF without re-scanning.

```bash
fendix report --input findings.json --format html --output report.html
```

---

## CLI Reference

### Commands

| Command | Description |
|---|---|
| `fendix scan` | Run a security scan against an API, source code, or both |
| `fendix report` | Re-render a saved JSON findings file to another format |
| `fendix verify <id>` | Re-run a single finding by ID to verify it still exists |
| `fendix version` | Print version, OS, and architecture information |

### Scan Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--url` | string | | Target API base URL (black-box scanning) |
| `--spec` | string | | Path to OpenAPI/Swagger YAML or JSON spec |
| `--code` | string | | Path to source code directory (white-box scanning) |
| `--auth` | string | | Auth header value, e.g. `"Bearer token123"` |
| `--auth-type` | string | auto-detect | Auth type: `bearer`, `apikey`, `basic`, `cookie` |
| `--auth-header` | string | `Authorization` | Custom auth header name |
| `-o, --output` | string | stdout | Output file path |
| `-f, --format` | string | `json` | Output format: `json`, `html`, `sarif` |
| `--fail-on` | string | | Exit 1 if findings at this severity: `CRITICAL`, `HIGH`, `MEDIUM` |
| `--baseline` | string | | Path to previous findings JSON for diff mode |
| `--save-baseline` | string | | Save current findings to this path |
| `--enable-active` | bool | `false` | Enable active injection probes |
| `-w, --workers` | int | `10` | Concurrent HTTP workers |
| `--timeout` | int | `10` | HTTP timeout in seconds |
| `--delay` | int | `100` | Milliseconds between HTTP requests |
| `--ignore` | string | | Path to `.fendix-ignore` suppression file |
| `-v, --verbose` | bool | `false` | Print all requests and raw findings |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings at or above `--fail-on` threshold |
| `1` | Scan completed, findings found at or above threshold |
| `2` | Scan error (network failure, invalid config, etc.) |

---

## Output Formats

### JSON (default)

Machine-readable findings with scan metadata.

```json
{
  "scan": {
    "target": "https://api.example.com",
    "timestamp": "2026-03-14T10:30:00Z",
    "duration_ms": 4521,
    "total_findings": 3,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 1,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "id": "SEC-001",
      "title": "Missing authentication on endpoint",
      "severity": "CRITICAL",
      "source": "correlated",
      "category": "auth",
      "endpoint": "GET /api/users",
      "evidence": "HTTP 200 returned without Authorization header",
      "fix": "Require Bearer token. Return 401 for unauthenticated requests.",
      "references": ["CWE-306", "OWASP-A01"],
      "confidence": "HIGH",
      "line": "src/routes/users.py:42"
    }
  ]
}
```

### HTML (self-contained)

A single-file HTML report with no external dependencies. Includes:

- Executive summary with severity breakdown
- Color-coded findings table (sortable by severity)
- Expandable rows with evidence and remediation
- Print-friendly CSS

```bash
fendix scan --url https://api.example.com --format html --output report.html
```

### SARIF 2.1.0 (CI/CD integration)

Standard format for static analysis results. Compatible with GitHub Code Scanning, Azure DevOps, and other CI platforms.

```bash
fendix scan --code ./src --format sarif --output results.sarif
```

Severity mapping:

| Fendix Severity | SARIF Level |
|---|---|
| CRITICAL, HIGH | `error` |
| MEDIUM | `warning` |
| LOW, INFO | `note` |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Fendix
        run: curl -fsSL https://get.fendix.dev | sh

      - name: Run scan
        run: |
          fendix scan \
            --url ${{ secrets.STAGING_API_URL }} \
            --code . \
            --spec openapi.yaml \
            --fail-on HIGH \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Baseline diff in PRs

Run baseline diffs to only flag **new** vulnerabilities introduced in a PR:

```yaml
      - name: Download baseline
        run: gh release download --pattern baseline.json || echo '[]' > baseline.json

      - name: Scan with baseline
        run: |
          fendix scan \
            --code . \
            --baseline baseline.json \
            --fail-on MEDIUM
```

---

## Configuration

### .fendix-ignore

Suppress known findings or exempt endpoints from scanning. Place as `.fendix-ignore` in your project root or pass via `--ignore`.

```yaml
# Suppress by finding ID
ignore:
  - id: SEC-014
    reason: "Rate limiting handled at API gateway level"
    until: 2026-12-01  # optional expiry date

  # Suppress entire endpoint
  - endpoint: GET /health
    reason: "Public health check endpoint by design"

  # Suppress by category on specific endpoints
  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints intentionally unauthenticated"
```

See [.fendix-ignore.example](.fendix-ignore.example) for a full template.

---

## Architecture

Fendix is a hybrid scanner with two engines communicating via newline-delimited JSON over stdin/stdout:

```
User CLI Command
       |
       v
+------------------+
|   Go Binary      |
|  - CLI (cobra)   |
|  - HTTP Scanner  |  <-- Black-box: sends real HTTP requests
|  - Orchestrator  |
|  - Correlator    |
|  - Reporters     |
+--------+---------+
         |
         | JSON over stdin/stdout
         |
+--------+---------+
|  Python Engine   |
|  - Secrets       |  <-- White-box: analyzes source code
|  - Semgrep       |
|  - Spec Parser   |
|  - AST Analyzer  |
|  - Deps Checker  |
+------------------+
```

**Why two languages?**

- **Go** excels at concurrent HTTP scanning, compiles to a single binary, and provides fast CLI startup.
- **Python** has the best security analysis ecosystem: Semgrep, Bandit, detect-secrets, and mature AST libraries.

The **correlator** is the core differentiator. When the black-box scanner confirms a vulnerability that the static analyzer also flagged, the finding is elevated to `correlated` source with `HIGH` confidence. This dramatically reduces false positives.

**Severity scoring model:**

```
Score = ImpactBase[category] x ConfidenceMult[confidence] x SourceMult[source]

CRITICAL  >= 9.0    |  ImpactBase:         ConfidenceMult:   SourceMult:
HIGH      >= 7.0    |    auth_bypass: 10.0   HIGH:   1.0      correlated: 1.1
MEDIUM    >= 4.0    |    injection:    9.5   MEDIUM: 0.75     blackbox:   1.0
LOW       >= 1.0    |    secrets:      9.0   LOW:    0.5      whitebox:   0.9
INFO      <  1.0    |    idor:         8.5
                    |    data_exposure: 7.0
                    |    cors:          6.5
                    |    headers:       4.0
                    |    info_disclosure: 2.0
```

For full architectural rationale, see [ADR-001](docs/adr/ADR-001-go-python-hybrid.md) and [ADR-002](docs/adr/ADR-002-ndjson-ipc.md).

---

## Security Checks

### Black-box (HTTP Scanner)

| Check | What It Detects | Default Severity |
|---|---|---|
| **Security Headers** | Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, server version disclosure | MEDIUM - INFO |
| **CORS** | Wildcard origins with credentials, reflected origins, permissive methods | CRITICAL - LOW |
| **Authentication** | Missing auth, malformed JWT accepted, expired JWT accepted, alg:none bypass | CRITICAL |
| **Data Exposure** | Passwords/secrets/tokens in responses, stack traces, internal IPs, sequential IDs | CRITICAL - INFO |
| **Rate Limiting** | No rate limiting detected on endpoints | MEDIUM |
| **SQL Injection** | Time-based blind SQLi (MySQL, Postgres, MSSQL) | HIGH |
| **Command Injection** | Echo canary detection (safe, non-destructive) | CRITICAL |
| **Header Injection** | CRLF injection in response headers | HIGH |

Injection checks (last 3 rows) require `--enable-active`.

### White-box (Static Analysis)

| Check | What It Detects |
|---|---|
| **Secrets** | AWS keys, private keys, hardcoded passwords, API keys, JWT secrets, DB URLs, bearer tokens |
| **Semgrep Rules** | Missing auth decorators, SQL string concatenation, exec/eval with user input, subprocess shell=True, hardcoded JWT secrets |
| **Spec Parser** | Missing security schemes in OpenAPI spec, API keys in query params, unauthenticated endpoints |
| **AST Analysis** | Python and JavaScript security-relevant patterns via AST parsing |
| **Dependencies** | Known CVEs in PyPI and npm packages |

---

## How to Add a Check

Fendix is designed to be extensible. Here's how to add a new security check:

### Adding a black-box check (Go)

1. Create a new file in `go/internal/scanner/` (e.g., `mycheck.go`)
2. Implement the `CheckFn` signature:

```go
package scanner

import (
    "context"
    "github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// CheckMyThing scans for [describe what it checks].
func CheckMyThing(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
    var findings []models.Finding

    // 1. Send HTTP request(s) to endpoint.FullURL
    // 2. Analyze response
    // 3. If issue found, append to findings

    return findings
}
```

3. Write table-driven tests in `mycheck_test.go` using `net/http/httptest`
4. Register the check in the orchestrator (`go/internal/engine/orchestrator.go`)
5. Document the check in `docs/checks/mycheck.md`

### Adding a white-box check (Python)

1. Create a new analyzer in `python/analyzers/` (e.g., `myanalyzer.py`)
2. Implement the analyzer class:

```python
class MyAnalyzer:
    """Describe what this analyzer detects."""

    def __init__(self, code_path: str) -> None:
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        # Walk files, analyze, call emit_fn with Finding dicts
        emit_fn({
            "title": "Issue found",
            "severity": "HIGH",
            "source": "whitebox",
            "category": "mycategory",
            "endpoint": "file.py:42",
            "evidence": "what was found",
            "fix": "how to fix it",
            "references": ["CWE-XXX"],
            "confidence": "MEDIUM",
            "line": "file.py:42"
        })
```

3. Write pytest tests in `python/tests/test_myanalyzer.py`
4. Register the analyzer in `python/engine.py`

### Adding a Semgrep rule

Add a YAML rule file to `python/rules/`:

```yaml
rules:
  - id: my-custom-rule
    pattern: dangerous_function($INPUT)
    message: "Potentially unsafe use of dangerous_function"
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-XXX
      category: mycategory
```

Semgrep rules are automatically picked up by the Semgrep runner.

---

## Project Structure

```
fendix/
├── go/                          # Go layer — CLI, HTTP scanner, orchestrator
│   ├── cmd/fendix/main.go       # CLI entrypoint (cobra)
│   ├── internal/
│   │   ├── scanner/             # Black-box check implementations
│   │   ├── engine/              # Orchestrator + correlator
│   │   ├── models/              # Finding, ScanConfig, severity scoring
│   │   └── reporters/           # JSON, HTML, SARIF renderers
│   ├── go.mod
│   └── go.sum
├── python/                      # Python layer — static analysis engine
│   ├── engine.py                # Entrypoint: reads stdin, streams findings
│   ├── analyzers/               # Secrets, Semgrep, spec parser, AST, deps
│   ├── rules/                   # Custom Semgrep YAML rules
│   └── tests/                   # pytest test suite
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   └── checks/                  # One page per check explaining detection logic
├── scripts/                     # Build and install scripts
├── .github/workflows/           # CI/CD workflows
├── Makefile                     # make build, test, lint, clean
└── Dockerfile                   # Multi-stage build
```

---

## Development

### Prerequisites

- Go 1.21+
- Python 3.9+
- Make

### Build and test

```bash
make build          # Build Go binary to bin/fendix
make test           # Run Go and Python tests
make lint           # Run gofmt, go vet, ruff, black
make clean          # Remove build artifacts and caches
```

### Running tests individually

```bash
# Go tests
cd go && go test -race -v ./...

# Python tests
cd python && python -m pytest tests/ -v
```

---

## Responsible Use

Fendix is a security testing tool designed for **authorized use only**.

- **Always get written permission** before scanning systems you do not own
- **Active probing** (`--enable-active`) sends payloads that may trigger alerts or affect system behavior — use only in controlled environments
- **Never use Fendix against production systems** without explicit authorization from the system owner
- Fendix is intended for security professionals, developers testing their own APIs, and CI/CD pipelines scanning pre-deployment code

Misuse of security scanning tools may violate applicable laws. The authors assume no liability for unauthorized use.

## License

MIT License. See [LICENSE](LICENSE) for details.
