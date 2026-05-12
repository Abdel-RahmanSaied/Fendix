# Fendix benchmarks

This page tracks Fendix's performance and detection coverage on
deliberately-vulnerable target applications. The wedge — *"DAST + SAST
in one PR check, fails only when both engines confirm"* — needs
evidence, not just framing. This page is where we put the numbers.

## Cold-start latency (TASK-118 / v0.9)

Phase 17b's exit gate is **<500 ms p50 cold start for code-only scans
without Semgrep**. v0.9 ships with native Go secrets (TASK-115) and
shelled-out Semgrep (TASK-116), and as of TASK-118 the Python whitebox
spawn is opt-in via `--python-engine` (the embedded Python distribution
is no longer bundled in the binary). The default scan path is now
Python-free.

Methodology: 30 cold-start runs, `~/.fendix/engine` cache cleared
between every run. Subprocess wall-clock measured via Python's
`time.monotonic()` so timing includes process spawn, argv parse, scan
setup, scan execution, JSON render, and exit. Hardware: Apple M-series.
Fixture: `python/tests/fixtures/secrets_target/` — 5 small files,
30 secrets findings. Both binaries built `go build -ldflags="-s -w"`.

| Configuration | p50 | p95 | mean | exit gate |
|---|---:|---:|---:|---|
| **POST-TASK-118 (default — what v0.9 ships)** | **5.6 ms** | **6.3 ms** | **5.6 ms** | ✅ 89× under 500 ms |
| POST-TASK-118 + `--python-engine` (opt-in) | 24.4 ms | 26.3 ms | 24.4 ms | ✅ 20× under 500 ms |
| PRE-TASK-118 (v0.8.0 with embedded Python) | 7.3 ms | 8.1 ms | 7.2 ms | ✅ 68× under 500 ms |

Reading the table:

- **Default v0.9 is 23 % faster than v0.8** (5.6 ms vs 7.3 ms) on this
  fixture, with no loss of coverage — secrets findings are identical
  byte-for-byte (verified via TASK-115 parity test).
- **The opt-in path costs ~4.4× the default** (24.4 ms vs 5.6 ms) —
  that gap is the actual cost of Python interpreter startup + engine
  extraction + whitebox check execution that we removed from the
  default path. Users who explicitly want the Python `auth` /
  `injection` / `deps` checks pay it; everyone else doesn't.
- **Both PRE and POST are far under the 500 ms gate.** v0.8 already
  cleared it on small fixtures; the win on large codebases scales with
  what Python actually does (which is now zero in the default path).

Binary size delta:

| Binary | Bytes |
|---|---:|
| PRE-TASK-118 (with embedded Python) | 19,002,482 |
| POST-TASK-118 (no embedded Python) | 18,903,282 |
| Δ | −99,200 bytes (−0.5 %) |

The size delta is small because Go's binary build compresses embedded
text aggressively. The real win is the dependency posture — fendix no
longer carries a Python interpreter requirement at all in the default
path; users can now run scans on machines without Python installed.

Re-run with:

```bash
make build && python3 scripts/bench/coldstart.py  # see scripts/bench/ for the harness
```

(The harness lives next to other dev-only scripts; numbers in this
table come from a clean Apple M-series box.)


## How to read these numbers

Each benchmark fixture is a known-vulnerable target maintained by an
OWASP project or similar. We pin the target image to a specific
version so numbers are reproducible across releases. We run a stock
`fendix scan --url …` (no custom flags, no policy tuning) so the
numbers represent **what a developer dropping Fendix in for the first
time would see**, not a hand-tuned demo.

The intent is *honesty*, not advocacy: if Fendix misses a vuln class
juice-shop ships, the numbers will say so, and the gap shows up as a
backlog item in `tasks/PHASES.md`.

## Targets

| Target | Image | Why this fixture |
|---|---|---|
| OWASP Juice Shop | `bkimminich/juice-shop:v17.1.1` | Comprehensive web-app vuln library, OWASP Top 10 coverage, well-known to AppSec audience |

vAPI and crapi will be added in a follow-up commit (BACKLOG candidates
for Phase 14). One fixture is enough to start producing numbers; the
infra to add more is the same `scripts/benchmark/run-<target>.sh`
pattern.

## Running locally

Requires Docker, `jq`, `curl`, and `fendix` on PATH:

```bash
# Install Fendix if you haven't already
curl -fsSL https://get.fendix.dev/install.sh | sh

# Run the juice-shop benchmark
make benchmark
```

The Makefile target shells out to `scripts/benchmark/run-juice-shop.sh`,
which:

1. Pulls the pinned juice-shop image
2. Starts it on `localhost:3000` and waits for `/rest/admin/application-version` to respond
3. Runs `fendix scan --url http://localhost:3000 --format json --output findings.json`
4. Parses findings + scan duration into `summary.json`
5. Prints a human-readable summary
6. Cleans up the container

Results land in `bench-results/juice-shop/<UTC-timestamp>/`. The
directory is gitignored — these are local runs, not committed.

## Running in CI

`.github/workflows/benchmark.yml` exposes the same recipe as a
`workflow_dispatch`-only workflow (manually triggered, not on every
push, because spinning up juice-shop costs ~2 minutes of runner time).
The workflow uploads the `summary.json` and `findings.json` as a build
artifact.

To trigger:

1. Go to the Actions tab
2. Pick "Benchmark"
3. Click "Run workflow"

Numbers from each manual run can be pasted into the table below.

## Latest results

| Date | Fendix version | Target | Endpoints | Total findings | CRIT | HIGH | MED | LOW | INFO | Correlated | Scan time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-05-01 | v0.6.1 | juice-shop v17.1.1 | 97 | 7 | 0 | 0 | 4 | 2 | 1 | 0 | 42s |

**Reading the row.** All 7 findings are blackbox (passive) — this
was a stock `fendix scan --url http://localhost:3000`, no
`--enable-active`, no `--code`. The MEDIUM/LOW/INFO mix matches
juice-shop's published-as-running-software-with-default-headers
posture: missing CSP, missing HSTS, missing
X-Content-Type-Options, missing X-Frame-Options, no rate limiting
detected, CORS allows any origin, software version disclosed at
`/metrics`. **97 endpoints discovered** (1 from robots.txt + 13 from
JS link extraction + 83 from the default 117-path brute-force
wordlist), **391 raw findings before dedup → 7 after** (TASK-088
collapses identical-finding-across-N-endpoints into a single row
with affected-endpoint count).

**What this row does NOT measure.** Juice-shop ships with intentional
SQLi, XSS, IDOR, and broken-auth vulnerabilities. None of those are
detectable by passive HTTP probing alone. Reproducing the wedge
("DAST + SAST in one PR check, fails only when both engines confirm")
on this fixture requires the `--enable-active` and/or `--code` flags
plus a checkout of juice-shop's source — adding `--enable-active`
runs SQLi / CMDi / CRLF probes; adding `--code ./juice-shop` runs
the white-box engine and unlocks the `correlated` column. Both are
follow-up commits to this benchmark.

**Source.** Captured by [GitHub Actions run 25193548945](https://github.com/Abdel-RahmanSaied/Fendix/actions/runs/25193548945)
on 2026-05-01. Raw artifacts (findings.json, summary.json,
scan.stderr) are downloadable from that run page for 30 days.

## Caveats

- **Single-scan runs vary.** Network jitter, Docker startup variance,
  and randomized response handling on juice-shop's side can move
  numbers by a few findings between runs. Take the numbers as a
  baseline shape, not a stable signature.
- **Stock-config only.** These runs are intentionally not tuned. A
  team running Fendix in production with a `.fendix.yaml` policy
  (severity threshold, custom Semgrep rules, suppressions) will see
  different numbers — usually fewer, more actionable findings.
- **No ZAP / Semgrep comparison yet.** Apples-to-apples comparison
  benchmarks against ZAP-baseline and Semgrep CI on the same fixture
  is a follow-up; doing it well requires controlling for runtime,
  rule-pack version, and reporting format.
- **Cosign verification of the binary used.** The CI workflow installs
  Fendix via `https://get.fendix.dev/install.sh`, which fetches the
  signed v0.6.0 binary from GitHub Releases. The benchmark therefore
  also acts as a smoke test of the published install pipe.

## Methodology — what counts as a finding

Fendix categorizes findings by source:

- **`correlated`** — both engines (DAST + SAST) independently flagged
  the same vulnerability category at the same endpoint. Build-failing.
- **`blackbox`** — only the runtime probe flagged it. Configurable
  severity threshold via `--fail-on`.
- **`whitebox`** — only the static analyzer flagged it. Same gate.

The "Total findings" column counts everything; the "Correlated"
column counts only the `correlated` source. **The correlated number
is the one that demonstrates the wedge.**

## Adding a new fixture

1. Pick a deliberately-vulnerable, OSS, Docker-able target (vAPI, crapi,
   DVWA, WebGoat, etc.).
2. Pin the image to a specific version tag.
3. Copy `scripts/benchmark/run-juice-shop.sh` to
   `scripts/benchmark/run-<target>.sh` and adjust the image, port, and
   health-check URL.
4. Add a row to the **Targets** table above.
5. Add a `make benchmark-<target>` Makefile target that shells out to
   the new script.
6. Add a step to `.github/workflows/benchmark.yml` (or a sibling
   workflow if the runtime gets long).
