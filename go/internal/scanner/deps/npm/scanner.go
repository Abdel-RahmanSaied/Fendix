// Package npm runs an in-process npm dependency CVE scan against
// package-lock.json v2/v3 manifests and emits fendix Findings for any
// resolved version that matches an OSV.dev vulnerability record.
//
// Behavioural parity with python/analyzers/deps.py::_check_package_json:
//   - One Finding per (package, resolved-version, OSV-id) tuple.
//   - ID shape: SEC-DEPS-<vid-with-underscores> (no NPM prefix; matches
//     the Python output so dedup collapses overlap during the
//     transition window before Phase 17b drops the embedded Python
//     deps path).
//   - Fix line picks the first OSV `affected[].ranges[].events[].fixed`
//     entry per OSV schema.
//   - References include the OSV ID followed by the first alias.
//
// Why package-lock.json, not package.json:
// `package.json` lists ranges (`"^4.17.1"`); only the lockfile records
// the resolved exact version that ended up in `node_modules`. That's
// what npm audit also reads. lockfileVersion 2 + 3 share the same
// flat `packages` map; v1 (legacy) used a nested `dependencies` tree
// and is out of scope today (Phase 17b can revisit if anyone files an
// issue for a v1 project).
//
// Cache: OSV.dev responses live at
//
//	~/.fendix/cache/osv-npm/<pkg>@<version>.json
//
// with a 24h TTL.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/offline"
)

// ErrLockfileMissingButPackageJsonPresent is returned when the
// directory contains `package.json` (so it IS a Node project) but no
// `package-lock.json` was checked into source control. Surfaced by
// the Track 4 heavy-eval — many vulnerable-app OSS repos ship only
// package.json and expect users to run `npm install` to materialise
// the lock. Caller can emit a single INFO finding to flag the gap
// without producing a noisy multi-CVE report.
var ErrLockfileMissingButPackageJsonPresent = errors.New("npm: package.json present but package-lock.json missing — run `npm install` to enable dep-CVE scanning")

// ErrNoLockfile is returned when codePath has no package-lock.json. The
// orchestrator skips silently — not every Node project commits a
// lockfile (yarn / pnpm projects), and not every codePath is a Node
// project at all.
var ErrNoLockfile = errors.New("npm: no package-lock.json at path root")

// osvAPIBase is the OSV.dev REST endpoint. Var-not-const so tests can
// point it at an httptest server.
var osvAPIBase = "https://api.osv.dev"

// cacheTTL matches the pip scanner — same 24h freshness window.
//
// Staleness window: an advisory published in the last 24h is not seen
// until the entry for that exact (package, version) expires, and one
// withdrawn in the last 24h keeps being reported. There is no cache-bust
// flag — delete ~/.fendix/cache/osv-npm/ to force a refresh. Entries are
// shape-versioned as well as time-bounded; see cacheSchema.
const cacheTTL = 24 * time.Hour

const httpTimeout = 15 * time.Second

// osvBatchMaxSize mirrors the pip scanner — OSV.dev's documented max
// batch size for /v1/querybatch
// (https://google.github.io/osv.dev/post-v1-querybatch/).
const osvBatchMaxSize = 100

// osvMaxConcurrentBatches mirrors the pip scanner's concurrency cap.
// At 4 in-flight batches of up to 100 packages each, a 400-dep
// lockfile completes in one wave with effectively zero rate-limit
// risk against OSV.dev's undocumented ~10 req/s per-IP cap.
const osvMaxConcurrentBatches = 4

// Scan reads package-lock.json at codePath and returns one Finding per
// (package, resolved-version, OSV-id) tuple. ErrNoLockfile signals
// "not a Node project (or yarn/pnpm-only)" — caller skips silently.
//
// Sprint 02.5: cache misses now go through /v1/querybatch (chunked into
// batches of osvBatchMaxSize, up to osvMaxConcurrentBatches in flight).
// Falls back per-chunk to the per-package /v1/query path on any
// batch-level failure so a transient batch-only outage cannot hide
// CVE coverage.
//
// Sprint-02 trade-off (carried into npm): /v1/querybatch responses
// include vuln IDs but NOT aliases. Findings via the batch path carry
// only an OSV-id reference; the serial fallback preserves the alias
// behaviour for any chunk that hits it. CVE-* alias hydration via
// GET /v1/vulns/{id} is deferred to Sprint 02.6.
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("npm: resolve path: %w", err)
	}
	lockfile := filepath.Join(abs, "package-lock.json")
	if _, err := os.Stat(lockfile); err != nil {
		if os.IsNotExist(err) {
			// If there's a package.json sitting next to the missing
			// lock, the user has a Node project but didn't `npm
			// install` — that's a real gap worth flagging once.
			if _, perr := os.Stat(filepath.Join(abs, "package.json")); perr == nil {
				return nil, ErrLockfileMissingButPackageJsonPresent
			}
			return nil, ErrNoLockfile
		}
		return nil, fmt.Errorf("npm: stat package-lock.json: %w", err)
	}

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return nil, fmt.Errorf("npm: read package-lock.json: %w", err)
	}
	pkgs, err := parseLockfile(content)
	if err != nil {
		return nil, fmt.Errorf("npm: parse lockfile: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir()
	const manifestName = "package-lock.json"

	// Phase 1: collect all (package, manifest) pairs. npm reads one
	// lockfile per Scan invocation so the manifest stamp is constant;
	// the pair shape mirrors pip's pkgWithManifest so the helpers below
	// stay structurally identical to pip's.
	allPairs := make([]pkgWithManifest, 0, len(pkgs))
	for _, p := range pkgs {
		allPairs = append(allPairs, pkgWithManifest{pkg: p, manifest: manifestName})
	}

	// Phase 2: cache lookup. Anything fresh in cache produces findings
	// now; misses go into the batch queue.
	var findings []evidence.Evidence
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

	// Phase 3: batch the misses. Chunk into osvBatchMaxSize-sized
	// groups, run up to osvMaxConcurrentBatches concurrently. Failures
	// of a chunk fall back to per-package /v1/query so CVE coverage
	// survives a /v1/querybatch outage.
	if len(misses) > 0 {
		sem := semaphore.NewWeighted(osvMaxConcurrentBatches)
		var batchMu sync.Mutex
		batchFindings := make([]evidence.Evidence, 0)
		var wg sync.WaitGroup
		for start := 0; start < len(misses); start += osvBatchMaxSize {
			end := start + osvBatchMaxSize
			if end > len(misses) {
				end = len(misses)
			}
			chunk := misses[start:end]
			if err := sem.Acquire(ctx, 1); err != nil {
				// Context cancellation surfaces here; bail with whatever
				// we've already gathered (cache hits + completed batches).
				wg.Wait()
				batchMu.Lock()
				findings = append(findings, batchFindings...)
				batchMu.Unlock()
				sortFindingsByID(findings)
				return findings, fmt.Errorf("npm: acquire batch slot: %w", err)
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
	}

	sortFindingsByID(findings)
	return findings, nil
}

// ScanOffline reads package-lock.json at codePath and matches every
// resolved version against the in-memory offline snapshot instead of
// osv.dev. It makes ZERO network calls — the air-gapped dep-CVE path
// (F-M4/F-H4). Findings carry the identical shape to the online path so
// dedup/correlation/reporters cannot tell the two apart.
//
// ErrNoLockfile / ErrLockfileMissingButPackageJsonPresent are returned
// for the same conditions as the online Scan, so the orchestrator can
// errors.Is-check them and emit the same advisory / skip.
func ScanOffline(codePath string, snap *offline.Snapshot) ([]evidence.Evidence, error) {
	if snap == nil {
		return nil, errors.New("npm: offline snapshot is nil")
	}
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("npm: resolve path: %w", err)
	}
	lockfile := filepath.Join(abs, "package-lock.json")
	if _, err := os.Stat(lockfile); err != nil {
		if os.IsNotExist(err) {
			if _, perr := os.Stat(filepath.Join(abs, "package.json")); perr == nil {
				return nil, ErrLockfileMissingButPackageJsonPresent
			}
			return nil, ErrNoLockfile
		}
		return nil, fmt.Errorf("npm: stat package-lock.json: %w", err)
	}

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return nil, fmt.Errorf("npm: read package-lock.json: %w", err)
	}
	pkgs, err := parseLockfile(content)
	if err != nil {
		return nil, fmt.Errorf("npm: parse lockfile: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	const manifestName = "package-lock.json"
	var findings []evidence.Evidence
	for _, p := range pkgs {
		for _, a := range snap.LookupVulnerable("npm", p.name, p.version) {
			findings = append(findings, buildFinding(p, advisoryToOSV(a), manifestName))
		}
	}
	sortFindingsByID(findings)
	return findings, nil
}

// advisoryToOSV adapts an offline snapshot Advisory to the osvVuln shape
// buildFinding consumes, so the offline path reuses the exact online
// finding constructor (one source of truth for the finding shape).
func advisoryToOSV(a offline.Advisory) osvVuln {
	v := osvVuln{
		ID:      a.ID,
		Summary: a.Summary,
		Aliases: a.Aliases,
	}
	if fix := a.FirstFixedVersion(); fix != "" {
		// Stamp the type explicitly: a snapshot fix IS an ecosystem
		// version, and saying so keeps the GIT filter from having to
		// guess about a synthesised range.
		v.Affected = []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: fix}}}}}}
	}
	return v
}

// pkgWithManifest carries the manifest stamp for a resolvedPackage.
// npm only scans one lockfile per Scan call today, but the
// (pkg, manifest) pair shape keeps this function structurally identical
// to pip's batch path and makes a future recursive-walk extension
// trivial.
type pkgWithManifest struct {
	pkg      resolvedPackage
	manifest string
}

// runBatchOrFallback tries /v1/querybatch for a single chunk; on any
// batch-level failure (non-2xx, length mismatch, transport error) it
// falls back to the per-package /v1/query path so individual findings
// still surface. Cache writes happen on both paths.
func runBatchOrFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []evidence.Evidence {
	pkgs := make([]resolvedPackage, len(chunk))
	for i, p := range chunk {
		pkgs[i] = p.pkg
	}
	results, err := queryOSVBatch(ctx, client, pkgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fendix] npm: querybatch failed (%v); falling back to per-package /v1/query for %d packages\n", err, len(chunk))
		return runSerialFallback(ctx, client, cache, chunk)
	}
	var findings []evidence.Evidence
	for _, p := range chunk {
		key := p.pkg.name + "@" + p.pkg.version
		vulns := results[key]
		// Cache the batch result even when empty — that's a valid
		// "no known vulns" answer worth caching for 24h.
		writeCache(cache, p.pkg.name, p.pkg.version, vulns)
		for _, v := range vulns {
			findings = append(findings, buildFinding(p.pkg, v, p.manifest))
		}
	}
	return findings
}

// runSerialFallback walks the chunk one package at a time using the
// classic /v1/query endpoint. Used when /v1/querybatch fails so any
// transient batch-only outage doesn't hide CVE coverage.
func runSerialFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []evidence.Evidence {
	var findings []evidence.Evidence
	for _, p := range chunk {
		vulns, err := queryOSV(ctx, client, cache, p.pkg.name, p.pkg.version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] npm: query %s@%s failed: %v\n", p.pkg.name, p.pkg.version, err)
			continue
		}
		for _, v := range vulns {
			findings = append(findings, buildFinding(p.pkg, v, p.manifest))
		}
	}
	return findings
}

// queryOSVBatch sends one /v1/querybatch request with up to
// osvBatchMaxSize packages and returns map[<pkg>@<version>]vulns.
//
// Known limitation: /v1/querybatch's response shape includes vuln IDs
// but NOT aliases. To get the CVE-* aliases the per-package /v1/query
// path includes, a follow-up GET /v1/vulns/{id} per vuln would be
// needed. This is intentionally NOT done here:
//
//   - Batch path (this function): N packages → 1 round trip, no aliases
//   - Serial fallback (runSerialFallback): N packages → N round trips,
//     full aliases
//
// Sprint 02.6 can hydrate aliases here if customers complain. Today we
// accept the alias gap to win the throughput improvement.
func queryOSVBatch(ctx context.Context, client *http.Client, pkgs []resolvedPackage) (map[string][]osvVuln, error) {
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
			Package: osvPackage{Ecosystem: "npm", Name: p.name},
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
			// TODO(sprint-02.6): hydrate aliases via GET /v1/vulns/{id}.
			// Today: batch findings get a single OSV-id reference; the
			// per-package /v1/query path remains the way to get full
			// CVE-* aliases.
			vulns = append(vulns, osvVuln{ID: v.ID})
		}
		out[pkgs[i].name+"@"+pkgs[i].version] = vulns
	}
	return out, nil
}

// resolvedPackage is one (name, version) entry extracted from a
// package-lock.json v2/v3 `packages` map.
type resolvedPackage struct {
	name    string
	version string
	// dev is true when npm marked this entry as a dev-only dep. Reserved
	// for future use — today's scan reports prod+dev uniformly because
	// pip-audit + the Python deps.py path do the same.
	dev bool
}

// lockfileV2 is the subset of package-lock.json v2/v3 we read. The
// `packages` map keys are directory paths relative to the project
// root (`""` for the root, `"node_modules/<name>"` for each install,
// nested `"node_modules/<parent>/node_modules/<child>"` for resolved
// duplicates). v1 lockfiles use a different `dependencies` tree and
// are deliberately not parsed.
type lockfileV2 struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string]lockfileV2Package `json:"packages"`
}

type lockfileV2Package struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

// parseLockfile walks the `packages` map and yields one resolvedPackage
// per non-root entry. Deduplication is keyed on (name, version) so
// multiple installs of the same version (e.g. `node_modules/lodash`
// and `node_modules/express/node_modules/lodash` at the same version)
// only count once.
func parseLockfile(content []byte) ([]resolvedPackage, error) {
	var lf lockfileV2
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("decode lockfile JSON: %w", err)
	}
	if lf.LockfileVersion < 2 {
		// v1 lockfiles are missing the flat `packages` map; bail with
		// a sentinel-ish error the caller can wrap. Today's policy:
		// log + skip rather than spam findings for an unsupported shape.
		return nil, fmt.Errorf("unsupported lockfileVersion %d (need >= 2)", lf.LockfileVersion)
	}

	seen := map[string]bool{}
	var out []resolvedPackage
	for path, p := range lf.Packages {
		if path == "" {
			continue // root project, not a dep
		}
		name := nameFromPath(path, p.Name)
		if name == "" || p.Version == "" {
			continue
		}
		key := name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, resolvedPackage{name: name, version: p.Version, dev: p.Dev})
	}
	// Deterministic order so the report is stable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].version < out[j].version
	})
	return out, nil
}

// nameFromPath extracts the package name from a `packages` map key.
// Examples:
//
//	"node_modules/express"                          → "express"
//	"node_modules/@scope/pkg"                       → "@scope/pkg"
//	"node_modules/express/node_modules/qs"          → "qs"
//	"node_modules/express/node_modules/@scope/pkg"  → "@scope/pkg"
//
// Falls back to the explicit `name` field when the path can't be
// parsed (rare but happens with link: deps).
func nameFromPath(path, explicit string) string {
	if path == "" {
		return explicit
	}
	// Find the last `node_modules/` separator and take everything after.
	const sep = "node_modules/"
	idx := strings.LastIndex(path, sep)
	if idx < 0 {
		// Not a normal node_modules path; trust the explicit name.
		return explicit
	}
	tail := path[idx+len(sep):]
	// Scoped packages: tail starts with `@`, take `@scope/name`.
	if strings.HasPrefix(tail, "@") {
		parts := strings.SplitN(tail, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return tail
	}
	// Unscoped: take the first segment only (defends against any
	// trailing `node_modules/...` chain that LastIndex didn't catch).
	if i := strings.Index(tail, "/"); i >= 0 {
		return tail[:i]
	}
	return tail
}

// osvQueryRequest is the /v1/query payload — identical to the pip
// scanner's, redeclared here so the two packages don't share types
// (lets them diverge cleanly when one ecosystem grows ecosystem-
// specific fields).
type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Aliases  []string      `json:"aliases"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	// Type is the OSV range type: "ECOSYSTEM", "SEMVER" or "GIT". See the
	// pip scanner's copy for the full rationale — the short version is
	// that a GIT range's `fixed` event is a COMMIT SHA, and printing one
	// in "Upgrade to lodash@<sha>" is worse than saying nothing. Empty is
	// treated as ECOSYSTEM-equivalent (synthesised ranges, old caches).
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

// queryOSV hits /v1/query for one (package, version) pair, with a
// 24h-TTL local cache backing it.
func queryOSV(ctx context.Context, client *http.Client, cacheDir, pkg, version string) ([]osvVuln, error) {
	if cached, ok := readCache(cacheDir, pkg, version); ok {
		return cached, nil
	}

	body, _ := json.Marshal(osvQueryRequest{
		Package: osvPackage{Ecosystem: "npm", Name: pkg},
		Version: version,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", osvAPIBase+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("osv.dev returned %d", resp.StatusCode)
	}
	var out osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	writeCache(cacheDir, pkg, version, out.Vulns)
	return out.Vulns, nil
}

// buildFinding maps one OSV vulnerability to a fendix Finding, matching
// the Python deps.py output shape exactly so dedup catches the overlap.
func buildFinding(pkg resolvedPackage, v osvVuln, manifestName string) evidence.Evidence {
	summary := v.Summary
	if summary == "" {
		summary = v.ID
	}
	desc := v.Details
	if desc == "" {
		desc = summary
	}
	if len(desc) > 200 {
		desc = desc[:200]
	}

	fix := fixCandidate(v, pkg.version)
	fixMsg := "Upgrade to a patched version (no fix listed in OSV)."
	if fix != "" {
		fixMsg = fmt.Sprintf("Upgrade to %s@%s or later.", pkg.name, fix)
	}

	refs := []string{v.ID}
	if len(v.Aliases) > 0 {
		refs = append(refs, v.Aliases[0])
	}

	idSlug := strings.ReplaceAll(v.ID, "-", "_")
	line := manifestName
	return evidence.Evidence{
		ID:         "SEC-DEPS-" + idSlug,
		Title:      fmt.Sprintf("Vulnerable dependency: %s@%s (%s)", pkg.name, pkg.version, v.ID),
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "deps",
		Endpoint:   manifestName,
		Evidence:   fmt.Sprintf("%s@%s: %s", pkg.name, pkg.version, desc),
		Fix:        fixMsg,
		References: refs,
		Confidence: models.ConfidenceHigh,
		Line:       &line,
		RuleID:     v.ID,
	}
}

// usableRange reports whether an OSV range's `fixed` events name real
// package versions. GIT ranges name commit SHAs, which are useless in an
// "Upgrade to X" message and meaningless to a version comparator. An
// empty type is accepted: the offline-snapshot adapter synthesises
// ECOSYSTEM-equivalent ranges without setting it.
func usableRange(r osvRange) bool { return r.Type != "GIT" }

// firstFixVersion returns the first non-GIT `fixed` event, installed-
// version-agnostic. fixCandidate is what the finding constructor uses.
func firstFixVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if !usableRange(r) {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// fixedVersions collects every `fixed` event across an advisory's non-GIT
// ranges, in document order.
func fixedVersions(v osvVuln) []string {
	var out []string
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if !usableRange(r) {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					out = append(out, ev.Fixed)
				}
			}
		}
	}
	return out
}

// lowerVersion / higherVersion pick between two version strings using the
// shared offline comparator, breaking a comparator TIE lexicographically
// so the winner is a pure function of the input set (Rule 8) — npm
// pre-releases collapse to their release core under that comparator, so
// ties are reachable here. "" means "no candidate yet".
func lowerVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	switch c := offline.CompareVersions(a, b); {
	case c < 0:
		return a
	case c > 0:
		return b
	}
	if a < b {
		return a
	}
	return b
}

func higherVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	switch c := offline.CompareVersions(a, b); {
	case c > 0:
		return a
	case c < 0:
		return b
	}
	if a > b {
		return a
	}
	return b
}

// fixCandidate is level (a) of FIX-06's two-level rule: the LOWEST `fixed`
// version strictly greater than the installed pin, across every non-GIT
// range of ONE advisory. An advisory that patches several release branches
// lists a fixed event per branch, and a user pinned inside the oldest
// branch wants the patch on THEIR branch, not the newest major.
//
// Fallback ladder (never invent a version, never claim "no fix" when OSV
// named one):
//
//  1. Something compares strictly greater than installed → the lowest
//     such, lexicographic tie-break.
//  2. Nothing does (the comparator cannot rank a pre-release pin, or a
//     stale cache carries a fix below the pin) → the lowest listed fixed
//     version.
//  3. No usable fixed event at all → "", and the caller prints the honest
//     "no fix listed in OSV" message.
func fixCandidate(v osvVuln, installed string) string {
	fixed := fixedVersions(v)
	if len(fixed) == 0 {
		return ""
	}
	var above, lowest string
	for _, f := range fixed {
		lowest = lowerVersion(lowest, f)
		if installed == "" || offline.CompareVersions(f, installed) > 0 {
			above = lowerVersion(above, f)
		}
	}
	if above != "" {
		return above
	}
	return lowest
}

// mergedFixVersion is level (b): across the alias-merged members of one
// component, the MAX of the per-advisory candidates, so the printed
// version actually fixes every vulnerability the merged finding reports.
func mergedFixVersion(members []osvVuln, installed string) string {
	var best string
	for _, m := range members {
		best = higherVersion(best, fixCandidate(m, installed))
	}
	return best
}

func sortFindingsByID(fs []evidence.Evidence) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
}

// --- cache ------------------------------------------------------------

// cacheDir returns ~/.fendix/cache/osv-npm, creating it lazily.
func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	d := filepath.Join(home, ".fendix", "cache", "osv-npm")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

func cachePath(dir, pkg, version string) string {
	// Scoped names (`@scope/name`) contain `/`; replace to keep cache
	// keys flat and filesystem-safe.
	safe := strings.ReplaceAll(pkg, "/", "_") + "@" + strings.ReplaceAll(version, "/", "_")
	return filepath.Join(dir, safe+".json")
}

func readCache(dir, pkg, version string) ([]osvVuln, bool) {
	if dir == "" {
		return nil, false
	}
	p := cachePath(dir, pkg, version)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var vulns []osvVuln
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, false
	}
	return vulns, true
}

func writeCache(dir, pkg, version string, vulns []osvVuln) {
	if dir == "" {
		return
	}
	data, err := json.Marshal(vulns)
	if err != nil {
		return
	}
	p := cachePath(dir, pkg, version)
	tmp, err := os.CreateTemp(dir, "osv-")
	if err != nil {
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return
	}
	tmp.Close()
	_ = os.Rename(tmp.Name(), p)
}
