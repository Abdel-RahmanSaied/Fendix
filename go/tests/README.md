# Fendix test suites (v0.20)

Subprocess-level guards that protect every future release from silently
breaking existing behavior. They build the real `fendix` binary (via
[`harness`](./harness)) and invoke it as a user would. **No Docker, no
network** — scans use `--fast` against committed code fixtures.

## Layout

| Path | What it protects |
|------|------------------|
| `harness/` | Builds the fendix binary once per run; `Run`/`RunEnv` helpers |
| `fixtures/` | Minimal projects with a known planted finding (unpinned Docker base image) |
| `smoke/` | The public CLI surface: `version`, `--help`, `scan` (json/sarif), `benchmark`, `metrics` |
| `regression/` | Output-snapshot drift, benchmark-baseline integrity, scan performance |
| `regression/snapshots/` | Committed normalized scan outputs — the drift baseline |

## Running

```bash
# everything (also runs as part of `go test ./...` in CI)
go test ./tests/...

# just one suite
go test ./tests/smoke/
go test ./tests/regression/
```

CI runs these on every push/PR through the existing `ci.yml` `go` job
(`go test -race ./...`). No separate workflow — `./...` already covers them.

## What each suite catches

- **smoke** — a command or flag stops working, exit codes change, or
  `--format json/sarif` stops emitting valid output.
- **regression/output_format** — the set of findings for a fixture changes
  (the normalized `category|severity|title` projection drifts from the
  committed snapshot). This is the guard against silent detection changes.
- **regression/benchmark_regression** — the committed
  `benchmarks/baselines/baseline.json` is missing/corrupt, or the
  regression-comparison logic stops flagging a >10% drop.
- **regression/performance** — a `--fast` scan of a trivial fixture takes
  > 30s or peaks over 500MB (memory read from the scan's own
  `FENDIX_METRICS` event).

## Updating snapshots (deliberately)

Output snapshots are committed and must change **only on purpose**:

```bash
FENDIX_UPDATE_SNAPSHOTS=1 go test ./tests/regression/ -run TestOutputFormatSnapshots
git diff tests/regression/snapshots/   # review every change before committing
```

If a snapshot changes and you did **not** intend it, that's a regression —
investigate the scanner change, don't blindly re-baseline.

## Adding a regression test

1. Add a fixture under `fixtures/` (use `//go:build ignore` on any `.go`
   file so it stays out of the module build).
2. Register it in `output_format_test.go`'s `fixtures` map.
3. Generate its snapshot with `FENDIX_UPDATE_SNAPSHOTS=1`, review, commit.

## When a test fails

- **smoke** — a user-facing contract broke. Fix the code, not the test,
  unless the change is intentional and documented.
- **snapshot drift** — confirm the detection change is intended; if so,
  re-baseline deliberately (above). If not, it's a bug.
- **performance** — profile the scan; a >10% regression is a bug (Rule 6).
