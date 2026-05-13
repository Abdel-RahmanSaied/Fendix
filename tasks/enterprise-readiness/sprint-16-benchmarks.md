# Sprint 16 — Enterprise benchmark harness

**Phase:** 6.1 | **Estimate:** 1.5 days | **Risk:** Low | **Ships:** v0.14.0

---

## Why

Fendix has `scripts/benchmark/` (Juice Shop) and `scripts/heavy-eval/` (Track 4 corpus). Neither compares fendix to competitors. This sprint adds a harness that runs fendix vs. semgrep vs. bandit on shared fixtures and produces a markdown comparison table.

---

## Honesty constraint

Cross-tool comparisons are **politically loaded**. Different tools cover different languages/categories. Bandit is Python-only; semgrep covers many languages but ships small default rule packs; fendix has DAST that the others don't.

The benchmark MUST include a scoping statement:
> "These numbers measure Python SAST performance on a 500-LOC fixture. They do NOT compare DAST coverage (only fendix), JS coverage (semgrep), or general-purpose SAST (semgrep with a full rule pack). Apples-to-apples comparison limited to: each tool's default Python SAST against the same Python file."

---

## Concrete deliverables

### 1. Fixture repos

```
scripts/benchmark-enterprise/fixtures/
  python-vulns/
    app.py           — 500 LOC with 5 intentional vulns + 5 safe-but-similar patterns
    requirements.txt
    README.md        — describes each labeled vuln line
  go-vulns/
    main.go          — equivalent for Go
    go.mod
    README.md
```

The 5 Python vulnerabilities:
1. SQL injection via string concat (CWE-89)
2. Hardcoded AWS access key (CWE-798)
3. Path traversal in `open()` (CWE-22)
4. SSRF via `requests.get(user_url)` (CWE-918)
5. Open redirect via `flask.redirect(user_target)` (CWE-601)

The 5 safe-but-similar patterns (FP probes):
1. Parameterised `cursor.execute(sql, (user,))`
2. AWS key loaded from `os.environ`
3. `open(os.path.join(BASE, basename(user_input)))` with `basename` sanitiser
4. `requests.get(WHITELIST[user_choice])`
5. `redirect(url_for("home"))` (constant)

### 2. Runner

`scripts/benchmark-enterprise/run.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

FIXTURE="${1:-fixtures/python-vulns}"

# Detect time command (GNU vs BSD)
TIME_CMD="/usr/bin/time -v"
if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v gtime &>/dev/null; then
        echo "Install gtime: brew install gnu-time"; exit 1
    fi
    TIME_CMD="gtime -v"
fi

run_tool() {
    local tool="$1"; shift
    local out
    out=$(mktemp)
    local stderr_out
    stderr_out=$(mktemp)
    $TIME_CMD "$@" >"$out" 2>"$stderr_out" || true
    local wall_clock
    wall_clock=$(grep "Elapsed" "$stderr_out" | awk '{print $NF}')
    local peak_rss
    peak_rss=$(grep "Maximum resident" "$stderr_out" | awk '{print $NF}')
    echo "$tool|$wall_clock|$peak_rss|$out"
}

echo "=== Benchmark: $FIXTURE ==="
echo "| Tool | Wall-clock | Peak RSS (KB) | TP count | FP count |"
echo "|---|---|---|---|---|"

# Fendix
fendix_result=$(run_tool fendix ../../bin/fendix scan --code "$FIXTURE" --format json --output -)
# ... parse, compute TP/FP using the README labels, append row

# Semgrep (if installed)
if command -v semgrep &>/dev/null; then
    semgrep_result=$(run_tool semgrep semgrep --config auto --json "$FIXTURE")
    # ... append row
fi

# Bandit (Python only — gate behind path check)
if [[ "$FIXTURE" == *python* ]] && command -v bandit &>/dev/null; then
    bandit_result=$(run_tool bandit bandit -r "$FIXTURE" -f json)
    # ... append row
fi
```

TP/FP scoring uses a manifest file `fixtures/python-vulns/manifest.json` that maps line numbers → expected vulnerability. Mirror the shape of `scripts/accuracy/manifest.json`.

### 3. CI integration

Add a job to `.github/workflows/benchmark.yml` (existing file from prior work):

```yaml
benchmark-enterprise:
  runs-on: ubuntu-latest
  if: startsWith(github.ref, 'refs/tags/v')
  steps:
    - uses: actions/checkout@v4
    - name: Install bandit + semgrep
      run: |
        pip install bandit semgrep
    - name: Build fendix
      run: make build
    - name: Run benchmark
      run: bash scripts/benchmark-enterprise/run.sh
    - name: Post results as job summary
      run: cat scripts/benchmark-enterprise/RESULTS.md >> $GITHUB_STEP_SUMMARY
```

Results posted as a GitHub Actions job summary on release tags only.

## CHANGELOG

```markdown
### Added (v0.14.0)

- **Enterprise benchmark harness** — `scripts/benchmark-enterprise/`.
  Compares fendix vs. semgrep vs. bandit on shared Python and Go
  fixtures. Measures wall-clock, peak RSS, true positive count,
  false positive count. Scoping statement: comparison limited to
  Python SAST on the same fixture; does not measure DAST or
  cross-language coverage.
```

---

## Risks

- **Politically loaded numbers.** The scoping statement is non-negotiable. Don't claim general SAST superiority.
- **macOS users** need `gtime` (`brew install gnu-time`); BSD `time` doesn't expose peak RSS the same way.

## Definition of done

Standard DoD plus:
- Fixture README files document each labeled vuln line
- Runner produces stable output across consecutive runs (no per-run jitter > 10%)
- Job summary on a release tag renders cleanly

## Status

**Not started.**
