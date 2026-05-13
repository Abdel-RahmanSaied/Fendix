# Sprint 02 — OSV.dev batch queries + concurrency cap

**Phase:** 1.2 (Honesty & Trust Fixes)
**Estimate:** 1.5 days
**Risk:** Med
**Ships in:** v0.11.1
**Audit reference:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §15.4 — "what would break first under enterprise load: OSV.dev rate limiting / outage"

---

## Why this sprint exists

The pip and npm scanners currently call OSV.dev one package at a time, in serial. A monorepo with 200 pinned deps and a cold cache hits OSV.dev 200 times sequentially. Under enterprise load:
- Wall-clock stalls (each request is ~150–500 ms RTT to OSV.dev)
- Rate limiting kicks in (~10 req/s per IP, undocumented but real)
- An OSV.dev brownout makes the whole scan fail

OSV.dev exposes a `/v1/querybatch` endpoint that accepts up to 100 packages per request. This sprint switches to it and caps concurrent batches at 4.

---

## Read first

- [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go) lines 79–110 (`queryOSV`) — the per-package query you're replacing.
- [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go) lines 161–208 (`ScanRecursive` — now `scanViaOSV` after Sprint 01).
- [`go/internal/scanner/deps/npm/scanner.go`](../../go/internal/scanner/deps/npm/scanner.go) — same per-package serial pattern. This sprint mirrors the fix into npm.
- [`go/go.mod`](../../go/go.mod) — confirm `golang.org/x/sync` is an **indirect** dep (it is, via x/vuln). You will promote it to direct.
- OSV.dev batch API docs: https://google.github.io/osv.dev/post-v1-querybatch/

**Known wart to internalise before coding:** OSV.dev's `/v1/querybatch` response includes vuln IDs but NOT their aliases. To get aliases (CVE-* refs that appear in `buildFinding`), you need a follow-up `GET /v1/vulns/{id}` per ID. This sprint accepts that trade-off and ships batch findings *without* CVE aliases, with a `TODO: hydrate aliases via GET /v1/vulns/<id>` comment. Sprint 02.5 (future) can add alias hydration if customers complain.

---

## Concrete deliverables

### 1. New function `queryOSVBatch` in `pip/scanner.go`

```go
const (
    // OSV.dev's documented max batch size for /v1/querybatch.
    osvBatchMaxSize = 100

    // Max concurrent batch requests. Conservative for OSV.dev's
    // undocumented ~10 req/s per-IP rate limit. Benchmark before bumping.
    osvMaxConcurrentBatches = 4
)

// queryOSVBatch sends one /v1/querybatch request with up to osvBatchMaxSize
// packages. The response contains vuln IDs but NOT aliases — aliases require
// a follow-up GET /v1/vulns/{id} per vuln. This implementation does NOT
// hydrate aliases; findings get a single OSV-id reference and skip the
// CVE-* aliases the per-package /v1/query path includes. Sprint 02.5 can
// add alias hydration if customers complain.
//
// Returns map[<pkg>@<version>]vulns so callers can correlate responses
// back to their request packages. Cache-misses only — caller is responsible
// for cache lookups before deciding which packages to batch.
func queryOSVBatch(ctx context.Context, client *http.Client, pkgs []pinnedPackage) (map[string][]osvVuln, error) {
    if len(pkgs) == 0 {
        return map[string][]osvVuln{}, nil
    }
    if len(pkgs) > osvBatchMaxSize {
        return nil, fmt.Errorf("batch size %d exceeds OSV.dev limit of %d — caller must chunk", len(pkgs), osvBatchMaxSize)
    }
    type batchQuery struct {
        Package osvPackage `json:"package"`
        Version string     `json:"version"`
    }
    type batchRequest struct {
        Queries []batchQuery `json:"queries"`
    }
    type batchResultEntry struct {
        Vulns []struct {
            ID string `json:"id"`
        } `json:"vulns"`
    }
    type batchResponse struct {
        Results []batchResultEntry `json:"results"`
    }

    reqBody := batchRequest{Queries: make([]batchQuery, len(pkgs))}
    for i, p := range pkgs {
        reqBody.Queries[i] = batchQuery{
            Package: osvPackage{Ecosystem: "PyPI", Name: p.name},
            Version: p.version,
        }
    }
    body, err := json.Marshal(&reqBody)
    if err != nil {
        return nil, fmt.Errorf("encode batch request: %w", err)
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIBase+"/v1/querybatch", bytes.NewReader(body))
    if err != nil {
        return nil, fmt.Errorf("build batch request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("post batch to %s: %w", osvAPIBase, err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
        return nil, fmt.Errorf("osv batch returned %d: %s", resp.StatusCode, snippet)
    }
    var parsed batchResponse
    if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
        return nil, fmt.Errorf("decode batch response: %w", err)
    }
    if len(parsed.Results) != len(pkgs) {
        return nil, fmt.Errorf("osv batch response length mismatch: %d results for %d packages", len(parsed.Results), len(pkgs))
    }

    out := make(map[string][]osvVuln, len(pkgs))
    for i, entry := range parsed.Results {
        if len(entry.Vulns) == 0 {
            continue
        }
        vulns := make([]osvVuln, 0, len(entry.Vulns))
        for _, v := range entry.Vulns {
            // TODO(sprint-02.5): hydrate aliases via GET /v1/vulns/{id}.
            // Today: batch findings get a single OSV-id reference; the
            // per-package /v1/query path remains the way to get full
            // CVE-* aliases.
            vulns = append(vulns, osvVuln{ID: v.ID})
        }
        out[pkgs[i].name+"@"+pkgs[i].version] = vulns
    }
    return out, nil
}
```

### 2. Promote `golang.org/x/sync` to direct dep

```bash
cd go && go get golang.org/x/sync@v0.10.0
```

Confirm `go.mod` now shows `golang.org/x/sync` in the **direct** require block.

### 3. New batch-orchestration function

Replace the per-package serial loop inside `scanViaOSV` (the function renamed from `ScanRecursive` in Sprint 01) with a batch-orchestrating loop:

```go
// scanViaOSV scans all manifests under codePath, batching OSV.dev queries
// across packages. Cache hits are processed first, then cache misses are
// chunked into osvBatchMaxSize-sized batches, with up to
// osvMaxConcurrentBatches in flight at once.
//
// If /v1/querybatch returns a non-2xx, falls back to the per-package
// /v1/query path with a logged warning. Per-batch failures don't sink
// the whole scan.
func scanViaOSV(ctx context.Context, codePath string, maxDepth int) ([]models.Finding, error) {
    abs, err := filepath.Abs(codePath)
    if err != nil {
        return nil, fmt.Errorf("pip: resolve path: %w", err)
    }
    manifests, err := findRequirementsManifests(abs, maxDepth)
    if err != nil {
        return nil, fmt.Errorf("pip: walk for requirements.txt: %w", err)
    }
    if len(manifests) == 0 {
        return []models.Finding{}, nil
    }

    type pkgWithManifest struct {
        pkg      pinnedPackage
        manifest string // relative path
    }

    // Phase 1: collect all (package, manifest) pairs across all manifests.
    var allPairs []pkgWithManifest
    for _, m := range manifests {
        content, err := os.ReadFile(m)
        if err != nil {
            fmt.Fprintf(os.Stderr, "[fendix] pip: read %s failed: %v\n", m, err)
            continue
        }
        rel, _ := filepath.Rel(abs, m)
        if rel == "" {
            rel = "requirements.txt"
        }
        for _, p := range parseRequirements(string(content)) {
            allPairs = append(allPairs, pkgWithManifest{pkg: p, manifest: rel})
        }
    }
    if len(allPairs) == 0 {
        return []models.Finding{}, nil
    }

    // Phase 2: cache lookup. Anything in cache produces findings now;
    // misses go into the batch queue.
    client := &http.Client{Timeout: httpTimeout}
    cache, _ := cacheDir()
    var findings []models.Finding
    var misses []pkgWithManifest
    for _, p := range allPairs {
        if vulns, ok := readCache(cache, p.pkg.name, p.pkg.version); ok {
            for _, v := range vulns {
                findings = append(findings, buildFinding(p.pkg, v, p.manifest))
            }
            continue
        }
        misses = append(misses, p)
    }

    // Phase 3: batch the misses. Chunk into osvBatchMaxSize-sized groups,
    // run up to osvMaxConcurrentBatches in flight.
    sem := semaphore.NewWeighted(osvMaxConcurrentBatches)
    var batchMu sync.Mutex
    batchFindings := make([]models.Finding, 0)
    var wg sync.WaitGroup
    for start := 0; start < len(misses); start += osvBatchMaxSize {
        end := start + osvBatchMaxSize
        if end > len(misses) {
            end = len(misses)
        }
        chunk := misses[start:end]
        if err := sem.Acquire(ctx, 1); err != nil {
            return nil, fmt.Errorf("acquire batch slot: %w", err)
        }
        wg.Add(1)
        go func(chunk []pkgWithManifest) {
            defer wg.Done()
            defer sem.Release(1)
            chunkFindings := runBatchOrFallback(ctx, client, cache, chunk)
            batchMu.Lock()
            batchFindings = append(batchFindings, chunkFindings...)
            batchMu.Unlock()
        }(chunk)
    }
    wg.Wait()
    findings = append(findings, batchFindings...)
    sortFindingsByID(findings)
    return findings, nil
}

// runBatchOrFallback tries /v1/querybatch; falls back to per-package
// /v1/query on any batch failure. Writes cache entries for both paths.
func runBatchOrFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []models.Finding {
    pkgs := make([]pinnedPackage, len(chunk))
    for i, p := range chunk {
        pkgs[i] = p.pkg
    }
    results, err := queryOSVBatch(ctx, client, pkgs)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[fendix] pip: querybatch failed (%v); falling back to per-package /v1/query for %d packages\n", err, len(chunk))
        return runSerialFallback(ctx, client, cache, chunk)
    }
    var findings []models.Finding
    for _, p := range chunk {
        key := p.pkg.name + "@" + p.pkg.version
        vulns := results[key]
        writeCache(cache, p.pkg.name, p.pkg.version, vulns)
        for _, v := range vulns {
            findings = append(findings, buildFinding(p.pkg, v, p.manifest))
        }
    }
    return findings
}

func runSerialFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []models.Finding {
    var findings []models.Finding
    for _, p := range chunk {
        vulns, err := queryOSV(ctx, client, cache, p.pkg.name, p.pkg.version)
        if err != nil {
            fmt.Fprintf(os.Stderr, "[fendix] pip: query %s==%s failed: %v\n", p.pkg.name, p.pkg.version, err)
            continue
        }
        for _, v := range vulns {
            findings = append(findings, buildFinding(p.pkg, v, p.manifest))
        }
    }
    return findings
}
```

Imports to add at the top of `scanner.go`:

```go
"sync"
"golang.org/x/sync/semaphore"
```

### 4. Mirror into npm

Same shape for `internal/scanner/deps/npm/scanner.go`. Ecosystem string is `"npm"` instead of `"PyPI"`; per-package query function is `queryOSV` in the npm package (already exists). Cache dir is `~/.fendix/cache/osv-npm/` (already exists).

If timeboxed, npm can slip to Sprint 02.5; pip is the priority since it's the higher-traffic ecosystem.

### 5. Tests

Add to `pip/scanner_test.go`:

```go
// TestScanViaOSV_BatchUsedWhenManyPackages asserts that the new path
// uses /v1/querybatch (not /v1/query) when >1 cache-miss package present.
// Mocks OSV.dev with an httptest server that counts /v1/querybatch hits.
func TestScanViaOSV_BatchUsedWhenManyPackages(t *testing.T) { ... }

// TestScanViaOSV_CacheHitsSkipBatch asserts that fully-cached packages
// do NOT trigger any HTTP call. Pre-warm cache with writeCache, then
// scan with a httptest server that fails on ANY hit.
func TestScanViaOSV_CacheHitsSkipBatch(t *testing.T) { ... }

// TestScanViaOSV_BatchFailureFallsBackToSerial asserts that a 500 response
// from /v1/querybatch triggers the per-package serial fallback. Mock server
// returns 500 for /v1/querybatch, normal results for /v1/query.
func TestScanViaOSV_BatchFailureFallsBackToSerial(t *testing.T) { ... }

// TestScanViaOSV_BatchSizeRespected asserts that >100 packages are chunked
// into multiple batches of <=100 each.
func TestScanViaOSV_BatchSizeRespected(t *testing.T) { ... }

// TestScanViaOSV_ConcurrencyCapRespected asserts that at most 4 batches
// are in flight simultaneously. Mock server tracks max-concurrent-hits.
func TestScanViaOSV_ConcurrencyCapRespected(t *testing.T) { ... }

// TestQueryOSVBatch_LengthMismatchErrors asserts that a misbehaving OSV.dev
// (returns fewer results than queries) produces a clean error, not a panic.
func TestQueryOSVBatch_LengthMismatchErrors(t *testing.T) { ... }
```

### 6. Benchmark before merging

Run `make bench` against a fixture with 150+ pinned deps:

```
Pre-sprint:  scan duration: 12.3s (150 deps × ~80 ms each, serial)
Post-sprint: scan duration: <2s   (2 batches × ~700 ms each, parallel)
```

Capture both numbers in the PR description. If post-sprint is not at least 4x faster on this fixture, profile and fix.

---

## Definition of done

- [ ] Cross-cutting requirements from [`PLAN.md`](PLAN.md) honored
- [ ] `make test` passes — zero failures, zero race-detector hits
- [ ] `make bench` shows ≥4x speedup on a 150-dep fixture (numbers in PR)
- [ ] `bin/fendix scan --code <large-monorepo>` against a real cold-cache target shows the expected speedup (manual verify, log capture in PR)
- [ ] Test that no `/v1/query` (per-package) hits occur on the happy path when `/v1/querybatch` works — `httptest.NewServer` fails the test if that endpoint is hit unexpectedly
- [ ] [`CHANGELOG.md`](../../CHANGELOG.md) entry under `[Unreleased]`
- [ ] PR description cites `FENDIX_AUDIT_REPORT.md §15.4`
- [ ] npm mirroring either complete or split into Sprint 02.5 with a tracking issue

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| OSV.dev's batch endpoint returns vuln IDs without aliases — findings lose CVE-* references | Confirmed | Documented as accepted trade-off. TODO comment in code. Sprint 02.5 can hydrate. |
| Cache-write race when multiple batches finish at once | Med | `writeCache` is per-file; multiple goroutines writing different cache files is safe. Concurrent writes to the SAME file (same package, somehow batched twice) shouldn't happen but the writer uses `os.WriteFile` which is atomic on POSIX — test asserts this. |
| OSV.dev rate-limits us at concurrency=4 anyway | Low | Default is conservative; if customers complain, bump. The semaphore makes this a one-line tuning change. |
| Batch response length mismatch crashes the scanner | Low | `queryOSVBatch` returns an explicit error on mismatch; tested. |
| `golang.org/x/sync` promotion adds an unwanted transitive | Low | Already an indirect dep — promotion has zero net effect on `go.sum`. |

---

## Follow-ups (NOT in scope)

- **Sprint 02.5:** Alias hydration via `GET /v1/vulns/{id}` for batch findings. Maintains CVE-* references parity with the per-package path.
- **Sprint 02.6:** Same batch treatment for npm scanner (if timeboxed out of this sprint).
- Backoff / retry on transient 5xx from OSV.dev. Today we fail-fast; could add a single retry with jitter.

---

## Status

**Not started.**

```
**Started:**
**Branch:**
**PR:**
**Status:** not-started
**Actual effort:**
**Surprises:**
**Follow-ups created:**
```
