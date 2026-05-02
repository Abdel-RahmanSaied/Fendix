# Fendix — Open Source Launch Post

> Draft for HN / r/devops / r/golang / r/netsec.
> Adapt tone per platform. HN version below (Show HN format).

---

## Show HN: Fendix — DAST + SAST in one scan, correlated findings (MIT, Go + Python)

**Link:** https://github.com/Abdel-RahmanSaied/Fendix

**Text:**

Hi HN,

I built Fendix because I was tired of running three separate security tools in CI and still drowning in false positives.

**The problem:** SAST tools find patterns that look dangerous but might be dead code. DAST tools confirm exploitability but can't tell you which line to fix. Running both means two reports, two triage workflows, and no connection between them.

**The solution:** Fendix runs both engines in a single `fendix scan` invocation and cross-correlates the results. When both engines find the same vulnerability, Fendix merges them into a correlated finding with escalated severity and confidence. When taint analysis also proves data flows from source to sink, it escalates two severity levels (e.g., MEDIUM → CRITICAL). You configure `--fail-on` to set your threshold — set it to CRITICAL and only confirmed, correlated findings block your build.

**What it does:**
- Black-box: auth bypass, SQLi (time/error/boolean-based), CORS, headers, secrets in responses, rate limit detection
- White-box: secrets (15 provider patterns), AST-based taint analysis, Semgrep rules, dependency CVEs (pip-audit/npm audit/govulncheck)
- Correlation: matching findings get elevated confidence; reachability-proven findings get double severity escalation
- Output: JSON, HTML (self-contained single file), SARIF (GitHub Code Scanning compatible)

**How to use it:**
```
brew install fendix
cd your-repo
fendix scan --code ./ --url https://your-api.dev --format html --output report.html
```

Or install the GitHub App for zero-config PR scanning.

**Technical details:**
- Go for the CLI + HTTP scanner + orchestrator
- Python for the static analysis engine
- Communication via NDJSON over stdin/stdout (no gRPC, no sockets)
- Plugin system: drop a script in `~/.fendix/plugins/`, receive ScanRequest on stdin, emit findings on stdout
- Single distributable binary (Python engine bundled via `go:embed`, extracted at first run; requires Python 3.x on PATH)

**What it's NOT:**
- Not a SaaS. Self-hosted only. No telemetry, no cloud dependency.
- Not a container scanner (Trivy does that better).
- Not a compliance dashboard.
- Not trying to replace Burp Suite for manual pentesting.

MIT licensed. The strategic rationale for open-sourcing is documented in ADR-007 — TLDR: closed-source protects nothing at this stage and costs trust + contributions + auditability.

I'd love feedback on the correlation approach and the plugin contract. The plugin system is intentionally minimal (NDJSON in/out, same as the internal engine IPC) — is that too minimal for real-world custom checks, or is the simplicity the point?

---

## r/devops version (shorter)

**Title:** We open-sourced our security scanner — DAST + SAST in one PR check, correlated findings get elevated severity

Fendix is a hybrid API and code security scanner that runs both a black-box probe and static analysis in a single invocation, then cross-correlates the results.

The key insight: when both engines find the same vulnerability, the finding gets escalated severity and confidence. Set `--fail-on CRITICAL` and only double-confirmed findings block your build. This kills false-positive fatigue without missing confirmed exploitable bugs.

**Quick start:**
```
brew install fendix
fendix scan --code ./ --url https://your-staging-api.dev
```

Or install the GitHub App → zero-config, automatic PR comments + SARIF annotations.

- MIT licensed, fully open source
- Single distributable binary (Go + embedded Python; requires Python 3.x on PATH)
- Plugin system for custom checks
- No telemetry, no cloud dependency

GitHub: https://github.com/Abdel-RahmanSaied/Fendix

Feedback welcome — especially on the correlation approach and whether the plugin contract (NDJSON stdin/stdout) is too minimal.

---

## r/golang version (technical focus)

**Title:** Fendix: Hybrid security scanner in Go — plugin system, NDJSON IPC, embedded Python (MIT)

Built a security scanner that uses Go for the HTTP/DAST layer and shells out to an embedded Python engine for SAST. Sharing because the architecture might be interesting to other Go developers building hybrid-language tools.

**Interesting Go patterns used:**
- `go:embed` to bundle the entire Python engine into the binary
- NDJSON over stdin/stdout as the IPC contract (no gRPC, no sockets — just `bufio.Scanner`)
- Plugin system that discovers executables in `~/.fendix/plugins/` and speaks the same NDJSON contract
- `sync.Once` + atomic counter for scan budget enforcement across goroutines
- Worker pool with fuzz-tested cancellation (native Go fuzzer, 4000+ corpus entries)
- Single-flight token cache for GitHub App installation tokens

**What it does:** DAST + SAST in one `fendix scan`, cross-correlates findings, outputs SARIF for Code Scanning. Findings only fail CI when both engines confirm.

The Python embedding was a pragmatic choice (Semgrep + pip-audit + AST analysis), but the roadmap includes porting regex-based checks to native Go and making Python optional. The plugin system (Phase 15, just shipped) means community checks don't need to be in either language.

https://github.com/Abdel-RahmanSaied/Fendix

Would love feedback on the NDJSON IPC approach vs alternatives (gRPC, Unix sockets, Wasm). We chose NDJSON for debuggability (`| jq .`) but curious about performance tradeoffs at scale.
