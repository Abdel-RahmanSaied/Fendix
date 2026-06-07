# Fendix Security Scanner — Enterprise-Readiness Review

**Scope:** `/Users/asaied/WorkDir/Fendix/fendix-engine` (Go + Python). A multi-agent, per-finding adversarially-verified review. Refuted findings excluded.
**Date:** 2026-06-07

---

## 1. Executive Summary

Fendix is a security scanner with a notably mature defensive baseline for a tool of its age: constant-time HMAC webhook verification, SHA-pinned CI actions, cosign-keyless release signing, env redaction before plugin execution, digest-pinned non-root container images, and a documented threat model with an explicit "active-scanner safety envelope." That care, however, is applied unevenly. The product's own stated guarantees are contradicted in three high-impact places — the "Zero outbound" trust claim for code scans, the same-host-only crawl promise in the threat model, and the "exact-pinning" claim for Python dependencies — and the highest-exposure surfaces (the GitHub App webhook → clone → scan path, and the plugin runner) lack the isolation their risk demands.

The single most important thing to fix is the **absence of any SSRF egress guard on scanner outbound HTTP combined with default redirect-following** (`scanner-no-ssrf-guard-outbound`): it directly breaks the threat model's same-host promise and is the load-bearing weakness behind the multi-tenant/hosted ambitions the roadmap implies. Closely coupled are two unauthenticated-RCE-class supply-chain gaps — repo-local plugin execution from untrusted PRs via the project's own reference CI workflow, and the GitHub App processing fork-PR code in a process holding a live write-scoped installation token that is also leaked via process args and `.git/config`.

**Verdict: Not-ready for enterprise GA as a hosted/multi-tenant service; Ready-with-conditions for the single-operator authorized-target CLI.** Justification: every Critical-adjacent High requires either an untrusted scan target, an untrusted PR, or the hosted GitHub App to be exploitable — exactly the deployment modes the project is marketing toward. The CLI-scanning-your-own-asset path is meaningfully safer, but the trust-claim contradictions (false "Zero outbound", no-op `--offline`) make even that path non-compliant for regulated/air-gapped buyers until corrected.

---

## 2. Severity Scoreboard

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 6 |
| Medium | 5 |
| Low | 11 |
| Info | 6 |
| **Total verified** | **28** |

> Note: severities reflect post-verification adjudicated severity, not the originally-claimed severity. Two items (`ghapp-checkrun-headsha-clone-url`, `plugin-env-substring-redaction-bypass`) were adjudicated **duplicate-or-known** and are folded into their parents below.

### Top 5 must-fix (before enterprise GA)

- [ ] **F-H1 — SSRF egress guard + redirect re-validation** on all scanner HTTP clients (`go/internal/budget/budget.go:92-138`; crawler/cors/injection clients). Breaks the threat model's same-host guarantee today.
- [ ] **F-H2 — Stop executing repo-local plugins from untrusted code** (`go/internal/plugin/plugin.go:187-216, 294-310`). Poisoned-pipeline RCE via the shipped reference GitHub Actions workflow.
- [ ] **F-H3 — Remove the installation token from git argv/`.git/config`** (`go/internal/ghapp/scanner.go:100-116,162-176`). Use `http.extraheader`/credential helper; drop token before scanning.
- [ ] **F-H4 — Fix the "Zero outbound" trust claim** for `fendix scan --code` (`README.md:20-22`) and wire `--offline` to actually be hermetic (`go/cmd/fendix/main.go:397-398`).
- [ ] **F-H5 — Make the GitHub App webhook asynchronous + bounded-concurrency** and harden taint-tracer recursion that lets one bomb file suppress an entire analysis pass (`go/internal/ghapp/handler.go:113-152`; `python/analyzers/ast_analyzer.py:274-300`).

---

## 3. Findings by Severity

### HIGH

---

**F-H1 — No SSRF guard on scanner outbound HTTP; unbounded redirect-following**
`go/internal/budget/budget.go:92-138` · category: SSRF

**What/why.** Every scanner HTTP client is built on `budget.Transport()/WrapTransport()`, which wraps `http.DefaultTransport` with only an atomic request counter — no custom `DialContext`, no IP filtering (confirmed: no `net.ParseIP`/`IsLoopback`/`IsPrivate`/`IsLinkLocal`/`169.254`/metadata checks anywhere outside comments). The crawler, CORS, and injection clients set no `CheckRedirect`, so they follow Go's default 10 redirects to *any* host including `127.0.0.1`, `169.254.169.254`, and RFC1918. Critically, this is reachable in **default passive mode**: a scanned target serving `Sitemap: http://169.254.169.254/latest/meta-data/...` in `/robots.txt` is fetched by `fromSitemap` (`crawler.go:789`) *before* the host filter at `crawler.go:807-815` (which only decides which discovered endpoints are *kept*, not which docs are *fetched*).

**Enterprise impact.** A malicious or attacker-influenced scan target can pivot Fendix into the operator's internal network or cloud metadata service, yielding SSRF and potential cloud-credential theft. This directly breaks threat-model envelope #4 ("No automatic crawl beyond same-host") and #3 ("cannot be hijacked into being a scan-launcher"), which the docs themselves classify as security vulnerabilities if broken. Impact is bounded for single-operator authorized scans, but is fully realized for the hosted GitHub App and any `fendix serve`/multi-tenant deployment.

**Fix.** Install a shared `DialContext` that refuses loopback, link-local (`169.254.0.0/16`, `fe80::/10`), unique-local, RFC1918/RFC4193, and `0.0.0.0`/multicast — re-checking after DNS resolution (anti-rebinding) and on every redirect hop. Add `CheckRedirect` to the crawler/CORS/injection clients capping hop count and re-applying the IP policy. Opt-out only for explicitly local/dev targets.

---

**F-H2 — Plugin runner follows symlinks and execs repo-local plugins from untrusted code (poisoned-pipeline RCE)**
`go/internal/plugin/plugin.go:187-216, 294-310` · category: supply-chain
*Merged: incorporates the env-redaction substring-match observation (`plugin-env-substring-redaction-bypass`), which verification found to be a documented/accepted tradeoff and not an independent boundary — the dominant risk is plugin execution itself.*

**What/why.** `Discover` `os.Stat`s entries specifically to follow symlinked plugin dirs, and `Run` execs `filepath.Join(p.Dir, p.Entrypoint)` directly with no check on file ownership, world/group-writability, or symlink escape. `validate()` blocks `..` and absolute entrypoints but not a symlinked dir/entrypoint. The repo-local root `.fendix/plugins/` lives inside the scanned repository, and plugins run by default (gated only on `!NoPlugins`). The shipped reference workflow `examples/github-actions/fendix-scan.yml` runs `on: pull_request`, checks out the PR, and runs `fendix scan --code ./` from the workspace cwd — so a fork PR adding `.fendix/plugins/evil/plugin.yaml` + an executable entrypoint achieves arbitrary code execution on the CI runner. The plugin env redaction (substring match on ~40 secret-name fragments) reduces credential exposure but does not prevent execution, and is a denylist that misses vendor-specific secret names.

**Enterprise impact.** Unauthenticated code execution on the scanning host/CI runner from untrusted PR content, via a default-on feature and the project's own recommended CI integration. The threat model excludes "malicious target → Fendix" and never contemplates a plugin arriving inside the scanned repo. Docs (`plugins.md`) wrongly claim symlinks are skipped during discovery.

**Fix.** Do not auto-discover repo-local plugins when scanning untrusted code (require explicit opt-in/allowlist). Before exec, `lstat` the resolved entrypoint and reject symlink-escape, group/other-writable files/parents, or owner mismatch. Stop following symlinked plugin dirs. Move plugin env handling to an allowlist (manifest-declared vars + `PATH`/`HOME`/locale) per the referenced FX-PLUG-2 follow-up. Correct the stale `plugins.md` symlink claim.

---

**F-H3 — Installation token leaks via git process args and `.git/config`**
`go/internal/ghapp/scanner.go:100-116, 162-176` · category: secret-handling

**What/why.** `injectInstallationToken` sets `url.UserPassword("x-access-token", token)` and the full token-bearing URL is passed as a literal argv element to `git remote add origin <authedURL>`. Git persists that URL — token included — into `<tmpdir>/.git/config`. The token is thus exposed in two cleartext sinks: the process arg list (`ps auxww`, `/proc/<pid>/cmdline`) and on-disk `.git/config`, which persists for the entire `fendix scan` of the untrusted repo (the `defer os.RemoveAll` only fires when `Run()` returns). The temp dir is `0700`, closing the cross-UID on-disk vector, but the process-args vector is world-readable and the same-UID vector (the scan subprocess / a compromised dependency in scanned code) is fully open.

**Enterprise impact.** A co-located process/user, or a compromised dependency in the scanned code, can read a live GitHub App installation token (~1h, write scope to all installation repos) — privilege escalation to repo write/PR/Code-Scanning across the installation. Contradicts the threat model's "nothing persists to disk" stance.

**Fix.** Do not put the token in the URL/argv. Use `git -c http.extraheader="Authorization: Basic <base64(x-access-token:token)>"` fed via config/stdin, or a `GIT_ASKPASS`/credential helper over a pipe. Ensure the token never reaches `.git/config`, and drop it from the environment before invoking the scanner.

---

**F-H4 — "Zero outbound" trust claim for code scans is false; dep scanners hit osv.dev / vuln.go.dev by default**
`README.md:20-22` · category: docs-vs-reality
*Closely related to F-M4 (`--offline` no-op): together these defeat any expectation of a hermetic code scan.*

**What/why.** The README trust table states `fendix scan --code ...` → "Zero outbound. Reads source from disk," and codifies an explicit "opt-in, documented, named-in-CHANGELOG" contract for any non-target network access. But `orchestrator.go:206-273` runs three native dep-CVE scanners on every `--code` scan by default (`NoNativeDeps` defaults false): pip and npm POST to `https://api.osv.dev`, govulncheck queries `https://vuln.go.dev`. The README even self-contradicts (line 187 "without making any network requests" vs line 193 "runs dependency CVE scanning"). Outbound calls fire only when an ecosystem manifest exists — but that is the common case for the very repos a dep scan targets.

**Enterprise impact.** A regulated/air-gapped customer running `fendix scan --code` believing it hermetic silently transmits their dependency inventory (package names + pinned versions) to two external services — a compliance violation and a breach of an explicitly stated contract that enterprises evaluate the tool on.

**Fix.** Update the trust table to disclose that `--code` scans query osv.dev/vuln.go.dev for dep CVEs unless `--no-native-deps`/`--offline` is set (naming the hosts), or make dep-CVE lookups opt-in. Wire `--offline` (see F-M4) so code scans can be genuinely hermetic; reconcile with the threat model.

---

**F-H5a — GitHub App runs a 15-minute clone+scan synchronously inside the webhook handler with no concurrency limit**
`go/internal/ghapp/handler.go:113-152` · category: concurrency

**What/why.** `HandlePullRequest`/`HandleCheckRun` call `runScan()` synchronously inside `ServeHTTP`'s dispatch; the HTTP 200 only returns after the scan completes (up to a 15-min timeout derived from `context.Background()`, so client/server timeouts don't cancel it). Server `WriteTimeout` is 60s; GitHub's delivery timeout is ~10s. There is no semaphore/queue/in-flight cap, and `fly.toml` runs a single shared-cpu-2x/1GB machine. The `fly.toml` comment even claims "responds 200 immediately and processes async" — directly contradicted by the code.

**Enterprise impact.** Every real scan exceeds the delivery timeout → GitHub marks delivery failed, redelivers (duplicate concurrent scans), and persistent failures auto-disable the webhook. N open PRs spawn N concurrent clone+scan subprocesses on one VM → CPU/memory/disk exhaustion. Unfit for multi-repo enterprise installs as written.

**Fix.** Acknowledge the webhook immediately (200/202 after signature verify + decode), run scans on a bounded background worker pool with a semaphore + queue, dedupe by `X-GitHub-Delivery`/(repo,headSHA), and report via the Checks API. Document max-concurrent-scans and machine sizing.

---

**F-H5b — Unbounded recursion in the Python taint tracer lets one crafted file suppress all injection findings**
`python/analyzers/ast_analyzer.py:274-300, 100-113, 79-94` · category: resource-exhaustion (finding-suppression)

**What/why.** `_trace_to_source()` recurses through scope assignments with only a cycle guard (`visited`) and no depth limit. A long linear assignment chain (`a1=a0; a2=a1; … sink(aN)`) raises `RecursionError`. The visitor call at line 113 is *outside* the parse `try/except` (which catches only `OSError`/`SyntaxError`), so the error propagates out of the `os.walk` loop and is caught only by `engine._run_check`'s broad `except Exception` — abandoning the walk. Reproduced end-to-end: a ~16KB bomb file yields `{"done": true, "total": 0}`, exit 0, and a co-located file with real `os.system(request.args.get('cmd'))` is never analyzed. The Go side treats the empty result as authoritative and posts a clean PR comment.

**Enterprise impact.** Denial-of-analysis: an attacker opening a malicious PR includes one innocuous-looking bomb file alongside their real vuln; the injection pass aborts and Fendix gives a clean bill of health. Scoped to the Python AST injection family (Go-native secrets/semgrep still run), and requires walk-ordering control the attacker generally has.

**Fix.** Wrap the per-file `visitor.visit(tree)` in its own `try/except Exception` that logs and continues. Add a depth/hop cap (~50) to `_trace_to_source` and cap `taint_chain` length.

---

### MEDIUM

---

**F-M1 — install.sh has no signature verification and fetches the checksum from the same origin as the binary**
`scripts/install.sh:62-102` · category: supply-chain

**What/why.** The advertised `curl … | sh` path downloads the binary from GitHub releases and, for integrity, downloads `${URL}.sha256` from the *same* base URL and compares. The cosign `.sig`/`.crt` sidecars that `release.yml` produces and `SECURITY.md` documents at length are never fetched or verified by the installer. A same-origin checksum provides corruption detection, not authenticity. `benchmark.yml` pipes this exact one-liner into CI runners.

**Enterprise impact.** The most common install path for a security tool ships with no supply-chain authenticity, while SECURITY.md claims "every release binary … signed with cosign," creating false assurance. (Downgraded from High because the binary transits GitHub HTTPS, not an attacker-controllable plaintext channel; SECURITY.md partially acknowledges the gap and recommends tag-pinning.)

**Fix.** Have install.sh fetch `.sig`/`.crt` and run `cosign verify-blob` (or a detached minisign/GPG signature with a baked-in public key), failing closed when tooling/signatures are absent. Until then, stop advertising cosign as the security story for the default path; pin the checksum source to a different trust domain than the binary.

---

**F-M2 — install.sh silently skips checksum verification when `sha256sum`/`shasum` are absent (fail-open)**
`scripts/install.sh:90-102` · category: supply-chain

**What/why.** With neither hashing tool on PATH, the script warns and sets `ACTUAL="$EXPECTED"`, guaranteeing the equality check passes; the checksum-download block is also best-effort (`2>/dev/null`) with no `else`, so a failed download skips verification silently. The binary is then `chmod +x`'d and a green "installed successfully" banner prints. Realistic on slim/distroless CI images.

**Enterprise impact.** On minimal/CI environments the only integrity control degrades to a no-op while the user sees success. Combined with F-M1, integrity is best-effort at best, silently absent at worst.

**Fix.** Fail closed: if a checksum is published but no hashing tool is available, or the checksum download fails, error out for non-interactive installs rather than assuming a match.

---

**F-M3 — Release-critical tools (nfpm, syft, actionlint) installed via mutable `go install …@vN`, bypassing the SHA-pin policy**
`.github/workflows/release.yml:95-99, 191-192, 468-470` · category: supply-chain

**What/why.** The repo's CI guard fails on any floating `@vN` in `uses:` lines, but it only greps `uses:` — so three tools that touch shipped artifacts (nfpm builds the .deb/.rpm; syft generates the SBOMs; actionlint) are installed via `go install <module>@vN`, none in `go.sum`. A workflow comment claims dependabot will bump them, but dependabot watches only `github-actions` and `gomod` (where these don't appear). (Downgraded from High: `sum.golang.org` already protects against retroactive tag-moves for already-published versions; the genuine residual is a brand-new malicious release under a compromised publisher account, and actionlint touches no shipped artifact.)

**Enterprise impact.** Inconsistent application of the very policy meant to close third-party build-tooling risk, on the exact tools that produce signed packages and provenance.

**Fix.** Pin via a `go.mod` `tool` directive + committed `go.sum`, or install from SHA-pinned release artifacts with checksum verification. Extend the SHA-pin guard to flag `go install …@vN` in workflow files.

---

**F-M4 — `--offline` / `--offline-db` scan flags accepted but completely unwired (silent no-op)**
`go/cmd/fendix/main.go:397-398` · category: configuration

**What/why.** `scan` registers `--offline`/`--offline-db`, but `newScanCmd`'s `RunE` never reads them and `ScanConfig` has no corresponding field; the offline package only powers `fendix db`. The flags do nothing and dep scanners still hit osv.dev/vuln.go.dev. (Downgraded from High because the flag help text candidly states it is a "no-op honest stub" with integration pending — an operator reading `--help` is told it does nothing.)

**Enterprise impact.** An air-gapped operator running `--offline --offline-db snapshot.json` sees success and assumes no egress, when dep scanners attempted outbound calls (and may have silently failed, hiding CVEs). Manufactures false confidence in the highest-assurance deployment, tempered only by the honest help text.

**Fix.** Until per-scanner offline wiring lands, hide/remove the scan-side flags (keep them on `db`). If kept, fail loudly: when `--offline` is set, refuse any outbound request and error unless every dep scanner routes through the snapshot. Add `Offline`/`OfflineDBPath` to `ScanConfig` and thread them through.

---

**F-M5 — GitHub App scans untrusted fork-PR code while a write-scoped installation token is live (pull_request_target-equivalent)**
`go/internal/ghapp/handler.go:113-152, 167-226` · category: untrusted-code-execution
*Incorporates `ghapp-checkrun-headsha-clone-url`, adjudicated a duplicate of the same shared `Scanner.Run` sink reached via a second event (`check_run` rerequested). Fix once in `Scanner.Run` (hex-SHA validation + `--` end-of-options) to cover both event paths.*

**What/why.** On `pull_request` opened/synchronize/reopened the handler acquires an installation token (scopes include `security_events:write`, `checks:write`, `pull_requests:write`) and then clones the PR head (`Head.Repo.CloneURL` = attacker's fork for fork PRs) and runs `fendix scan` over attacker-authored source — Python AST, semgrep, dep-manifest parsing — in the same process tree that holds the token (also in the clone URL and the TokenSource cache for ~1h). No sandbox/network isolation. The k8s reference manifest drops caps + `readOnlyRootFilesystem`, but the documented primary deploy (Fly.io) applies none of that hardening.

**Enterprise impact.** If any bundled analyzer can be coerced into code execution or exfiltration over a malicious repo (poisoned `setup.py`, semgrep rule resolution, git submodule), the attacker reaches a token that can write check-runs/SARIF/comments to every repo the App is installed in. (Medium/medium-confidence: conditional on an unproven analyzer-RCE primitive; tokens short-lived and installation-scoped; k8s path is hardened.)

**Fix.** Scan untrusted code in a network-isolated, unprivileged sandbox that does *not* carry the installation token in its env (clone with the token, then drop it before invoking the scanner). Disable egress for the scan subprocess. Document the trust boundary and apply k8s-equivalent hardening to the Fly.io deploy.

---

### LOW

The following are real but bounded. Grouped by theme.

**Report-content spoofing / fidelity (untrusted scan data into reports).** These share a root cause: finding fields originate from scanned targets/code, and only `html/template`'s HTML-metacharacter escaping is applied — no Unicode/control-char normalization, and non-HTML render contexts get no escaping at all. Fix once with a shared `NeutralizeBidi`/normalization step (extend `SanitizeFindings`) applied to Title/Evidence/Fix/Endpoint/Category/AffectedEndpoints/TaintChain across all formats.

- **F-L1 — Bidi/RTL control characters not stripped** (`go/internal/reporters/html.go:118-130`). Trojan-Source-style visual reordering of finding text in HTML/PDF/SARIF; deceives a human triager. Only raw `%s`/unformatted fields are affected (`%q`-formatted evidence already neutralizes bidi).
- **F-L2 — C0/C1 and zero-width control characters pass through** (`go/internal/reporters/html.go:114-128`). Defeats in-report Ctrl-F search and visual de-duplication; strengthens F-L1.
- **F-L3 — Attacker-influenced data into SARIF uri/name/message/tags without validation** (`go/internal/reporters/sarif.go:220-282`). `helpUri` is http/https-filtered but `artifactLocation.uri` and location/name are not. Impact is largely misleading text/labels in a dashboard (Code Scanning renders message text as inert plain text; the freely-resolvable URI field is sourced from local code, not remote input) — report-hygiene, not confused-deputy URI injection. Fix: normalize/validate location URIs (relative, no scheme, no traversal); strip control/bidi from text; document downstream-consumer untrust.
- **F-L4 — PDF reporter uses Latin-1 fonts with no bidi handling** (`go/internal/reporters/pdf.go:150-235`). Non-Latin/RTL text silently mangled; bidi controls not neutralized. The glyph half is a documented deferred-font tradeoff; the bidi/control-strip gap is the actionable part. No active PDF content sink.
- **F-L11 — Untrusted finding fields rendered raw into PR-comment Markdown** (`go/internal/ghapp/comment.go:135-154`). `fmt.Fprintf` of `Title`/endpoint into Markdown with no escaping; a crafted filename/title can break out of a code fence or spoof fake findings to socially-engineer a reviewer. GitHub sanitizes raw HTML, so content-spoofing, not XSS. Endpoint is `%q`-quoted in the YAML fence; line 141 is the unescaped sink. Fix: escape Markdown metacharacters in Title/endpoint and guard code-fence content.

**Concurrency / determinism / fail-open.**

- **F-L5 — `CheckInjection` ignores ctx cancellation between probes** (`go/internal/scanner/injection.go:354-405, 138-157`). After a budget/duration soft-stop, an in-progress endpoint keeps iterating remaining probes (bounded by `MaxProbesPerEndpoint`). The security-relevant half holds — `budget.Transport` rejects over-cap requests with no network I/O and ctx-cancelled `client.Do` returns immediately — so the leak is wasted local work + misleading `status=0` audit records, not new payloads on the wire. Fix: `select`-on-`ctx.Done()` at the top of the target/payload loops, mirroring `ratelimit.go`.
- **F-L6 — Dedup primary is the nondeterministic worker-completion order** (`go/internal/engine/dedup.go:34-96`). Findings sharing `(severity,category,title)` but differing in Evidence/Fix/Line: which survives is nondeterministic; the later `sort.Slice` is non-stable. Breaks snapshot/reproducibility expectations (baseline keys survive; human-facing evidence flaps). *The team has explicitly documented this as accepted (`dedup.go:22`, `dedup_property_test.go`)* — surfaced for visibility. Fix if determinism is a hard requirement: sort before dedup or pick primary deterministically; switch to `SliceStable` with a total tiebreaker.
- **F-L7 — Native dep/secrets/semgrep/textscan failures logged at WARN and swallowed (fail-open, exit 0)** (`go/internal/engine/orchestrator.go:206-326`). A genuine scanner failure (build error, OSV 5xx, semgrep crash) yields zero findings + one WARN + a clean-looking pass, with no report signal distinguishing attempted-and-failed from attempted-and-clean. These use raw `slog.Warn` (not `logagg`), so they don't even reach the end-of-scan warning summary. Documented intent ("a network blip doesn't stop a scan") but a real fail-open for a trusted CI gate. Fix: track per-scanner status in `ScanMetadata`, surface it in report + summary, add opt-in (CI-default) `--fail-on-scanner-error`.
- **F-L13 — SARIF `executionSuccessful` hardcoded true even on partial scanner failure** (`go/internal/reporters/sarif.go:300-304`). Same fail-open root as F-L7: a failed dep-CVE call still reports `executionSuccessful=true` with no `toolExecutionNotifications`, which Code Scanning reads as "ran clean." Fix: set false when any required scanner errored; emit notifications. (Mislabeled "report-injection"; it's fail-open.)
- **F-L14 — Ignore-file parse and save-baseline errors are fail-open in CI** (`go/internal/engine/orchestrator.go:398-410`). An unparseable `--ignore` or a failed `--save-baseline` only logs (at ERROR) and proceeds; exit code unaffected, unlike discovery/render failures which return 2. The `--config` policy path *is* validated, making this inconsistent. Fix: treat explicit-but-unparseable `--ignore`/failed `--save-baseline` as exit 2.

**Python engine robustness (operator-supplied / untrusted-repo inputs).**

- **F-L8 — Deeply-nested YAML spec raises `RecursionError` that bypasses `check_auth`'s except tuple** (`python/analyzers/spec_parser.py:65-83, 261-292`). The intended `SEC-SPEC-PARSE` "spec could not be parsed" finding is lost; the operator can't tell analyzed-and-clean from never-parsed (a stderr line is still emitted). JSON path refuted (iterative C scanner). Fix: catch `RecursionError` and emit `SEC-SPEC-PARSE`.
- **F-L9 — SpecParser fetches arbitrary URLs (SSRF) with redirect-following and no response size cap** (`python/analyzers/spec_parser.py:270-279`). `--spec` is operator-supplied (never attacker-derived in shipped flows), and "no allowlist" matches the accepted Go-side design — so the SSRF framing is largely defense-in-depth. The genuine, asymmetric gap is the **unbounded `resp.read()`** where the Go twin caps at 50MB (`crawler.go:363-370`): an operator pointing `--spec` at a hostile/huge endpoint can OOM the engine. Fix: add a `LimitReader`-equivalent cap; restrict to https and re-validate redirects if hardening further.
- **F-L10 — Manifest and local-spec reads have no size cap (OOM)** (`python/analyzers/deps.py:275, 429, 208-219`). `requirements.txt`/`package.json`/spec read fully into memory with no guard, inconsistent with `ast_analyzer.py`'s 1MB `_MAX_FILE_BYTES`. A hostile repo can OOM-kill the engine subprocess; the Go spawner reads the kill as a scan failure. Fix: apply the same stat-check guard before `read_text()`.
- **F-L12 — Symlinked source files read; matched line can surface out-of-tree content in findings** (`python/analyzers/ast_analyzer.py:85-94, 107, 200-204, 130-148`). `os.walk` skips symlinked dirs but enumerates symlinked *files*; up to ~200 chars of an out-of-tree file appears in `evidence` if a line matches a sink regex. Notably, the project's own Go `textscan` walker deliberately skips symlinks for this exact reason — the Python analyzer does not. Bounded data exposure, requires the documented untrusted-PR-scan use case. Fix: skip symlinked entries or `Path.resolve()`-confirm-under-root before reading.

### INFO

- **F-I1 — Plugin env redaction is substring-match, over-redacts and misses some secret shapes** (`go/internal/plugin/plugin.go:70-96, 304-310`). Documented and test-pinned as intentional over-redaction; denylist gaps (`STRIPE_KEY`, `SENTRY_DSN`) are real residual but the dominant risk is plugin execution (F-H2). Allowlist model recommended.
- **F-I2 — `comment.go`/`sarif.go` error strings embed GitHub response bodies without token redaction** (`go/internal/ghapp/comment.go:203-206`). Token is header-only today (no leak); the issue is inconsistency vs `scanner.go`'s `redactToken`, a latent trap for a future edit. Apply a consistent redaction helper + regression test.
- **F-I3 — Arabic locale ships machine-generated, security-unreviewed strings selectable via `--lang ar`** (`go/internal/reporters/i18n/ar.go:1-62`). Static, auto-escaped (no injection); spot-checked severity labels are actually correct. Tracked in RISKS.md, gated on stable promotion. `ScanSubtitle` placeholder tokens are inert. Gate behind beta/feature-flag until native-speaker review.
- **F-I4 — Per-endpoint probe cap is soft; SQLi confirmation double-record overshoots by +1** (`go/internal/scanner/injection.go:366-466, 507-510`). Not a TOCTOU/concurrency race (single-goroutine per endpoint; subordinate probes re-check). Worst case cap+1 on a confirmed-vulnerable endpoint; audit log stays accurate. Document as approximate or `TryReserve` atomically.
- **F-I5 — Malformed UTF-8 handled via `errors='replace'`** (`python/analyzers/ast_analyzer.py:107, 126`). Positive confirmation — analyzers do not crash on bad encoding; `spec_parser` degrades to a parse-error finding. No change required.
- **F-I6 — Reference workflow uses floating action tags and `go install …@latest`** (`examples/github-actions/fendix-scan.yml:51-67, 118, 129`). Propagates poor CI hygiene (and the F-H2 RCE surface) to adopters, contradicting the repo's own SHA-pin policy. Non-executing template; documented as interim. SHA-pin the example and replace `@latest` with the verified install path.
- **F-I7 — `configleak` TLS block is dead code whose comment claims the opposite behavior** (`go/internal/scanner/configleak.go:110-115`). `InsecureSkipVerify:false` (verification on) under a comment claiming verification off, in an unreachable type-assertion block. No security impact (TLS verification is on via default transport). Not repeated elsewhere. Delete the dead block; centralize TLS posture.
- **(Quality) Report metadata `Version` hardcoded `"dev"`** (`go/internal/engine/orchestrator.go:437-446`). Every released binary's SARIF/PDF/JSON misreports the tool version, breaking Code Scanning provenance and audit reproducibility. One-line fix: `Version: o.version` (also set it in `NewOrchestratorWithSpawner`). *Adjudicated low/observability — listed here for visibility.*
- **(Quality) No panic recovery in worker pool or decode loops** (`go/internal/engine/workerpool.go:62-91`). Zero `recover()` in non-test code; a panic in any check aborts the whole scan with no report. No concrete panicking path was demonstrated (stdlib parsers used are panic-safe), so this is defense-in-depth. Add per-job `recover()` + a fuzz/adversarial-input test.
- **(Quality) Embedded-Python-engine code path and messages stale post-TASK-118** (`go/internal/engine/python_check.go:50-55`). `PythonRequiredMessage` lists secrets/semgrep as Python-dependent though they're now native Go; `fendix engine info` advertises a no-longer-bundled extract flow at the support-triage entry point. Scope the message to auth/injection/deps; update the subcommand help.

---

## 4. Cross-Cutting Themes

1. **SSRF posture is the dominant architectural gap.** No egress IP policy exists anywhere in Go (F-H1) or Python (F-L9), and most scanner clients follow redirects to any host. The threat model promises same-host-only crawling; the code breaks it in default passive mode. **Recommendation:** a single shared, IP-filtering, redirect-revalidating transport factory used by *every* outbound client (scanner, integrations, Python `urlopen`), with explicit local/dev opt-out. This is the highest-leverage architectural change.

2. **Docs-vs-reality drift undermines the trust model.** Three verified contradictions of stated guarantees: "Zero outbound" (F-H4), the same-host crawl envelope (F-H1), and "exact-pinning" of Python deps (requirements floating `>=`, no hashes). The CI SHA-pin policy is also applied inconsistently (F-M3, F-I6). For a security product, an inaccurate trust claim is itself a finding. **Recommendation:** treat the threat model and README trust table as testable invariants — add CI assertions (e.g., the SHA-pin guard extended to `go install`; a hermeticity test that fails if `--code --offline` makes any socket call).

3. **Untrusted-code execution with elevated context is re-implemented in three places.** The GitHub App holds a write-scoped token while scanning fork PRs (F-M5), leaks that token via git (F-H3), and the plugin runner executes repo-local code from PRs (F-H2). All three are the `pull_request_target`-equivalent anti-pattern. **Recommendation:** one isolation primitive — clone-then-drop-credentials, network-isolated unprivileged sandbox, no auto-discovery of repo-supplied plugins — applied uniformly; mirror the hardened k8s securityContext onto Fly.io.

4. **Fail-open as a recurring default.** Scanner errors swallowed at WARN (F-L7), SARIF `executionSuccessful` always true (F-L13), ignore/baseline errors don't affect exit code (F-L14), and the AST recursion bomb (F-H5b) all share a posture of "degrade silently and report clean." For a gating tool this is the worst failure mode. **Recommendation:** thread per-scanner success/failure into report metadata + exit code; offer a `--strict`/CI mode that fails on incomplete coverage.

5. **Secret-handling is good where deliberate, inconsistent where incidental.** `scanner.go` redacts tokens from errors; `comment.go`/`sarif.go` (F-I2) and the git argv path (F-H3) do not. **Recommendation:** a single credential-redaction helper used across the `ghapp` package + a regression test asserting no token appears in any returned error or process arg.

---

## 5. What's Already Strong (preserve these)

- **Constant-time HMAC webhook verification** (`webhook.go:52-71`, `hmac.Equal`) with a 4 MiB body cap and capped token-response reads (64 KiB).
- **Active-probe gating and safety envelope**: injection probes only fire under `--enable-active` with a printed disclaimer; per-endpoint probe caps; a global probe-audit log; a budget `RoundTripper` that caps outbound request volume.
- **Deliberate secret-leak defenses**: `notify.go` avoids `%w`-wrapping transport errors and strips webhook secret paths before logging; `jira.Config.String/GoString` redact tokens; `scanner.go` redacts the installation token from git error strings; the diagnostic bundle redacts all credential surfaces before writing.
- **Injection-resistant integration code**: JQL injection defended (finding-ID allowlist `^[A-Za-z0-9._-]+$` + `quoteJQL` escaping); plugin-install URL allowlist (rejects `file://`, `ext::`, CVE-2017-1000117 family) with a locked derived-dir-name regex and `0700` root.
- **Contextual auto-escaping in the HTML reporter** (`html/template`), with `%q` already neutralizing bidi in many evidence paths; SARIF/JSON via encoders.
- **Strict config parsing**: `KnownFields(true)` for `.fendix.yaml` and `plugin.yaml` with a version gate.
- **Supply-chain build hardening**: cosign keyless signing with an `enforce-signing` gate, SHA-pinned `uses:` actions with a CI guard, digest-pinned non-root multi-stage Docker images, `--no-cache-dir`/apt cleanup, tini, and a k8s manifest with `readOnlyRootFilesystem` + drop-ALL caps + `runAsNonRoot` + seccomp `RuntimeDefault`.
- **In-process govulncheck** (library, not subprocess) — a cleaner trust boundary than the Python `deps.py` path.
- **Robust input handling** where it counts: `errors='replace'` decoding (no crash on malformed UTF-8), 1 MB per-file cap in the AST analyzer, 50 MB spec-fetch cap and 5 MB JS cap in the Go crawler.

---

## 6. Recommended Remediation Roadmap

### Before enterprise GA (blockers)
1. **F-H1** — Shared SSRF-filtering transport + redirect re-validation (Go scanner clients); extend to Python `urlopen` (F-L9) and add the missing response-size cap.
2. **F-H2** — Disable repo-local plugin auto-discovery for untrusted scans; ownership/symlink/permission checks before exec; SHA-pin the reference workflow (F-I6); correct `plugins.md`.
3. **F-H3** — Remove installation token from git argv/`.git/config`; consistent token redaction across `ghapp` (F-I2).
4. **F-H4 + F-M4** — Fix the "Zero outbound" trust claim; either wire `--offline` to be genuinely hermetic or remove the scan-side flags; reconcile threat model and README; pin Python deps with hashes.
5. **F-H5a** — Async webhook + bounded-concurrency worker pool + delivery dedup.
6. **F-H5b** — Per-file `try/except` + recursion depth cap in the taint tracer.
7. **F-M5** — Clone-then-drop-token + network-isolated sandbox for untrusted-PR scans; apply k8s-equivalent hardening to Fly.io.

### Next quarter
8. **F-M1 / F-M2** — install.sh cosign verification + fail-closed checksum handling.
9. **F-M3** — Pin build tooling (nfpm/syft/actionlint) via `go.mod` tool directive/`go.sum`; extend the SHA-pin guard to `go install`.
10. **F-L7 / F-L13 / F-L14** — End fail-open: per-scanner status in report metadata + exit code; SARIF `executionSuccessful`/notifications; exit-2 on bad `--ignore`/`--save-baseline`.
11. **Report normalization (F-L1–L4, F-L11)** — One shared bidi/control-char neutralization step across HTML/PDF/SARIF/Markdown/Slack/Teams; SARIF URI validation.
12. **F-L8 / F-L10 / F-L12** — Python robustness: `RecursionError` → `SEC-SPEC-PARSE`; manifest/spec size caps; skip/resolve symlinked source files.

### Hardening backlog
13. **F-L5** — ctx-cancellation checks inside injection probe loops.
14. **F-L6** — Deterministic dedup primary + `SliceStable` (if determinism is promoted to a hard requirement).
15. **Quality** — Report `Version` fix; per-job `recover()` + fuzz test; stale embedded-engine messaging.
16. **F-I1 / F-I3 / F-I4 / F-I7** — Plugin env allowlist; gate `--lang ar` as beta; atomic probe-cap reservation; delete the dead `configleak` TLS block.

---

## 7. Methodology & Coverage

This was a **multi-agent review with per-finding adversarial verification**: each candidate finding was independently challenged against the actual source (exact file:line reads, and in several cases end-to-end reproduction — e.g., the AST recursion bomb, the spec `RecursionError`, the git token landing in `.git/config`, and html/template control-char passthrough). Severities reported here are the **post-verification adjudicated** values, which in many cases differ from the original claim (e.g., several High→Medium/Low downgrades where exploitability was contingent on operator-controlled inputs or already-present mitigations). **13 additional candidate findings were refuted during verification** and are excluded; refutations turned on non-shell `exec` (argv, not shell), GitHub-computed SHAs, `sum.golang.org` protection against tag-moves, `helpUri` filtering, and documented/accepted tradeoffs — i.e., the corpus has been pruned of false positives, so the items above carry higher confidence.

**Dimensions covered:** injection/SSRF/subprocess; auth/crypto/secrets/webhook; Python engine (AST, spec parser, deps, spawner); report-injection (HTML/PDF/SARIF/Markdown/Slack/Teams); concurrency/correctness; supply-chain/CI (install.sh, release pipeline, Docker, k8s, reference workflows); quality/maintainability (docs-vs-reality, observability, fail-open). A full attack-surface inventory (entry points, every `os/exec` site, every outbound HTTP call, every untrusted-data parse, every report-injection sink) backed the review.

**Coverage gaps the agents flagged:**
- **No demonstrated panic path** for the worker-pool no-recover concern (F-I), and **no demonstrated analyzer-RCE primitive** for F-M5 — both are real-but-conditional architectural exposures, not proven exploits. A targeted fuzzing pass over the analyzers (semgrep rule resolution, `setup.py`/submodule handling, AST/JS regex on adversarial input) would resolve whether F-M5 is Medium or High.
- **`DIST_REPO_TOKEN` scope is unverifiable from the repo** (it may already be a fine-grained single-repo PAT), so the release-mirror PAT concern is a hardening recommendation, not a confirmed over-scope.
- **Runtime/deployment posture** (actual Fly.io hardening, egress firewalling, secret rotation) is outside source-only review and should be validated against the live environment before hosted GA.
- Findings assume GitHub's documented webhook/payload guarantees (e.g., `head_sha` is a hex commit SHA); a change in those guarantees would re-open the (currently low) git-arg-injection surface.