# Fendix

**DAST + SAST in one PR check. Fails only when both engines confirm.**

Fendix runs a runtime probe and a static analyzer on every scan. Only findings where both engines independently flag the same vulnerability at the same endpoint become `correlated` — high-confidence results that earn a build-failing exit code. Everything else is downgraded so your triage queue stays small and every alert means something.

- **Confirmed findings.** Both engines must agree on category and endpoint before the build fails.
- **Single binary.** Drop into CI in 30 seconds. Active probes off by default; opt in with `--enable-active`.
- **Signed and silent.** Releases signed via [cosign keyless](#verifying-signed-releases) (Sigstore Fulcio). [No telemetry](#what-fendix-sends-to-the-network) — verify with `tcpdump`.
- **Open source under MIT.** Read the source, audit the wedge, fork it, ship plugins. See [ADR-007](docs/adr/ADR-007-open-source.md) for the strategic posture.

---

## What Fendix sends to the network

The trust statement, before anything else.

| When | Outbound traffic |
|---|---|
| **Default scan** (`fendix scan --url ...`) | Only HTTP requests to the URL you passed. Nothing to `fendix.dev`, nothing to a vendor. |
| **Active probing** (`--enable-active`) | Probe payloads to the same target, only. Audit-logged. Off by default. |
| **`fendix scan --code ...` (white-box only)** | Zero outbound. Reads source from disk. |
| **`fendix scan` with no flags** | Errors out — there's no work to do. Zero outbound. |
| **Telemetry / phone-home / usage stats** | None. There is no telemetry code. Verify with `tcpdump`, or read [`go/internal/`](go/internal/) — there's nothing to find. |

If a future release adds anything that talks to a non-target host, it'll be opt-in, documented in this section, and named in the CHANGELOG. That's the contract.

---

## Quick Start

```bash
# 1. Install (downloads the latest release binary for your platform)
curl -fsSL https://get.fendix.dev/install.sh | sh

# 2. Run your first scan
fendix scan --url https://api.example.com --format html --output report.html

# 3. Open the report
open report.html
```

That's it. Fendix scans the API for missing security headers, CORS misconfigurations, authentication bypasses, sensitive data exposure, and rate limiting issues — all without sending any destructive payloads.

---

## Installation

> Engine source lives in this private repo; install artifacts (binaries, Homebrew formula, install script) are published to the public mirror at [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix). All install paths below pull from the mirror.

### Homebrew (macOS / Linux)

```bash
brew tap Abdel-RahmanSaied/fendix
brew install fendix
```

### curl (macOS / Linux)

```bash
curl -fsSL https://get.fendix.dev/install.sh | sh
```

Downloads the latest release binary, verifies its sha256 checksum, and installs to `/usr/local/bin/fendix`. Override the install directory with `FENDIX_DIR=$HOME/.local/bin` and the version with `FENDIX_VERSION=v0.6.0`.

`get.fendix.dev` is the engine repo's short URL — it's a CNAME to the [`homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix) mirror, served via GitHub Pages. To inspect the script before piping to a shell:

```bash
curl -fsSL https://get.fendix.dev/install.sh | less
```

If `get.fendix.dev` is ever unreachable, the `raw.githubusercontent.com` URL is the documented fallback — see [`docs/install.md`](docs/install.md#install-script-curl--sh).

### Debian / Ubuntu (.deb)

```bash
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
VERSION=v0.5.0
URL="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${ARCH}.deb"
curl -fsSL -o fendix.deb "${URL}"
sudo dpkg -i fendix.deb && sudo apt-get install -f
```

Pulls in `python3` automatically; recommends `semgrep` for deeper static
analysis. Uninstall with `sudo apt-get remove fendix`.

### RHEL / Fedora / CentOS (.rpm)

```bash
case "$(uname -m)" in
  x86_64)  PKG_ARCH=amd64 ;;
  aarch64) PKG_ARCH=arm64 ;;
esac
VERSION=v0.5.0
sudo dnf install \
  "https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${PKG_ARCH}.rpm"
```

### Docker

```bash
docker pull ghcr.io/abdel-rahmansaied/fendix:latest
docker run --rm ghcr.io/abdel-rahmansaied/fendix scan --url https://api.example.com
```

The Docker image includes Python and all static analysis dependencies, so hybrid mode works out of the box. Available from **v0.4.1 onwards** (the v0.4.0 release predates the Docker publish workflow).

### Manual binary download

Pick a binary for your platform from the [latest release](https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/latest) (linux/amd64, darwin/amd64, darwin/arm64), verify the matching `.sha256` file, and place it on your PATH:

```bash
curl -fsSL -o fendix https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/v0.4.0/fendix-v0.4.0-darwin-arm64
shasum -a 256 fendix  # compare against the .sha256 alongside the binary
chmod +x fendix && sudo mv fendix /usr/local/bin/fendix
```

### Build from Source

Requires Go 1.21+ and Python 3.9+.

```bash
git clone https://github.com/Abdel-RahmanSaied/Fendix.git
cd Fendix
make build
./bin/fendix version
```

For white-box analysis, install Python dependencies:

```bash
pip install -r python/requirements.txt
```

---

## Verifying signed releases

Every release artifact (binary, `.deb`, `.rpm`, multi-arch Docker manifest) ships with a `.crt` + `.sig` sidecar produced by [cosign](https://docs.sigstore.dev/cosign/overview/) keyless signing — Sigstore Fulcio anchors the signature to the GitHub Actions OIDC identity that built the release. No static public key, no rotation surface, no key-loss recovery story to maintain.

Verify a binary:

```bash
VERSION=v0.6.0
ASSET=fendix-${VERSION}-linux-amd64
BASE="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}"

curl -fsSL -o "$ASSET"     "$BASE/$ASSET"
curl -fsSL -o "$ASSET.crt" "$BASE/$ASSET.crt"
curl -fsSL -o "$ASSET.sig" "$BASE/$ASSET.sig"

cosign verify-blob \
  --certificate "$ASSET.crt" \
  --signature   "$ASSET.sig" \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer     "https://token.actions.githubusercontent.com" \
  "$ASSET"
# → Verified OK
```

Same pattern verifies a `.deb`, `.rpm`, or Docker image — swap the asset name. For Docker, use `cosign verify` (not `verify-blob`) against the image reference:

```bash
cosign verify ghcr.io/abdel-rahmansaied/fendix:v0.6.0 \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer     "https://token.actions.githubusercontent.com"
```

Releases cut before cosign signing was activated (any tag earlier than `v0.6.0-rc2`) won't have sidecar files — fall back to the `.sha256` companion in those cases. See [`SECURITY.md`](SECURITY.md) for the broader artifact-trust policy and supported-versions table.

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
        run: curl -fsSL https://get.fendix.dev/install.sh | sh

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

## Performance

Fendix is designed to keep scanner overhead well under the network latency
floor — even on a localhost target, a 1000-endpoint scan finishes in under
35 ms of pool/coordination cost.

Numbers below are from `make bench` on an Apple M1 (8 cores, Go 1.21).
Each row reflects the cost of running the worker pool against an
`httptest` server with N endpoints × 3 checks per endpoint (3N total real
HTTP roundtrips) at a fixed pool size of 32 workers.

| Endpoints | Roundtrips | Wall time | Memory   | Allocs    | Peak goroutines |
|----------:|-----------:|----------:|---------:|----------:|----------------:|
|        10 |         30 |    0.8 ms |  336 KB  |   2,896   |             130 |
|       100 |        300 |    5.1 ms |  2.6 MB  |  24,345   |             143 |
|       500 |       1500 |   19.0 ms | 12.4 MB  | 119,453   |             175 |
|      1000 |       3000 |   31.7 ms | 24.7 MB  | 238,256   |             166 |

Reading the numbers:

- **Throughput scales linearly** with endpoint count — Fendix's pool
  coordination is not the bottleneck, the HTTP transport is.
- **Memory is bounded.** ~25 KB per endpoint at 1000 endpoints, including
  finding allocation, slog formatting, and HTTP response buffers. A
  scan against 10,000 endpoints would still fit in well under 256 MB.
- **Goroutine count is bounded** by `--workers` plus a small fixed
  overhead (HTTP transport idle pool, slog handler, the test fixture's
  goroutine-tracking probe). The pool clamps to your worker budget no
  matter how many endpoints get crawled — verified by TASK-097's
  fuzzed cancellation test and the 1000-endpoint `-race` job.

Reproduce locally:

```sh
make bench                    # default, 5 iterations per size
make bench BENCHTIME=2s        # longer runs, more stable numbers
```

Real-world scans against remote targets are network-bound, not
Fendix-bound — expect the per-endpoint wall time to be dominated by
the round-trip latency to your target, plus `--delay` (default
100 ms) between requests. Use `--max-requests` and `--max-duration`
to bound total work.

For component-level micro-benchmarks (correlator, JSON parser, severity
scoring, reporters), run `cd go && go test -bench . -benchmem ./...`.

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

## Documentation

- [Install reference](docs/install.md) — every install path (Homebrew, apt/dnf, Docker, source) with cosign verification.
- [5-minute walkthrough — OWASP Juice Shop](docs/walkthrough-juice-shop.md) — try a real hybrid scan in under 5 minutes.
- [CI/CD integration](docs/ci-cd-integration.md) — drop-in GitHub Actions workflow with SARIF upload and PR comment.
- [Triage workflow](docs/triage-workflow.md) — what to do when a report lands.
- [JSON schema reference](docs/schema.md) — every field of the JSON output, with stability guarantees.
- [Semgrep rule guide](docs/semgrep-rules.md) — write project-specific static-analysis rules.
- [Per-check reference](docs/checks/) — one page per built-in check.
- [Architecture decision records](docs/adr/) — why Fendix is built the way it is.
- [Security policy](SECURITY.md) and [active-scanner threat model](docs/threat-model.md).

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
