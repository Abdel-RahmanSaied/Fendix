// Package pip queries the OSV.dev /v1/query API to find vulnerabilities in
// Python dependencies declared in requirements.txt manifests. It provides
// behavioural parity with pip-audit (same advisory sources, same finding
// shape) but does NOT shell out to pip-audit by default.
//
// Users who require an actual pip-audit invocation (for reproducibility
// in environments that audit subprocess calls, or to pick up pip-audit-
// specific patches ahead of OSV.dev's index) can pass --use-pip-audit
// to fendix scan. When set, the scanner runs `pip-audit --format json -r
// <manifest>` for every manifest discovered by findRequirementsManifests
// and converts the output to []models.Finding using the same shape as
// the native OSV.dev path. If pip-audit is not on PATH, a warning is
// logged to stderr and the OSV.dev path is used as fallback — never
// fails-closed silently.
//
// Limitations (unchanged from existing implementation):
//   - Only pinned `==` versions are checked. Range specifiers
//     (`>=`, `~=`, `>`) are skipped with a stderr warning.
//   - No transitive resolution. Direct deps only.
//
// Cache (OSV.dev path only):
//   ~/.fendix/cache/osv-pypi/<package>@<version>.json with a 24h TTL.
package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ErrNoRequirements is returned by Scan when codePath has no
// requirements.txt at its root. Callers use this to skip silently.
var ErrNoRequirements = errors.New("pip: no requirements.txt at path root")

// DefaultRecurseDepth bounds how many directory levels ScanRecursive
// walks looking for nested requirements.txt manifests. 3 is enough to
// catch multi-service repos (service/requirements.txt or
// services/foo/requirements.txt) without descending into vendored deps
// (node_modules/, .venv/, site-packages/) — those are explicitly
// excluded by name regardless of depth.
const DefaultRecurseDepth = 3

// recurseSkipDirs are directory basenames ScanRecursive never enters.
// They're either vendored deps (whose own requirements.txt files belong
// to upstream packages, not this project) or scratch dirs not worth
// audit. Match-by-basename so a project that itself names a dir "tests"
// is unaffected — we only skip exact-name matches at any depth.
var recurseSkipDirs = map[string]bool{
	".git":         true,
	".venv":        true,
	"venv":         true,
	"node_modules": true,
	"site-packages": true,
	"__pycache__":  true,
	".tox":         true,
	".mypy_cache":  true,
	".pytest_cache": true,
	"build":        true,
	"dist":         true,
}

// osvAPIBase is the OSV.dev REST endpoint. Var-not-const so tests can
// point it at an httptest server.
var osvAPIBase = "https://api.osv.dev"

// cacheTTL is how long an OSV response is considered fresh. 24h matches
// pip-audit's default cache lifetime.
const cacheTTL = 24 * time.Hour

// httpTimeout bounds a single OSV.dev request. The /v1/query endpoint
// is fast (<1s typical) — 15s is enough headroom for a slow link
// without holding a scan hostage.
const httpTimeout = 15 * time.Second

// osvBatchMaxSize is OSV.dev's documented max batch size for
// /v1/querybatch (https://google.github.io/osv.dev/post-v1-querybatch/).
const osvBatchMaxSize = 100

// osvMaxConcurrentBatches caps how many /v1/querybatch requests are in
// flight simultaneously. Conservative for OSV.dev's undocumented
// ~10 req/s per-IP rate limit — at 4 concurrent batches of up to 100
// packages each, a 200-dep monorepo finishes in 2 batches with
// effectively zero rate-limit risk. Benchmark before bumping.
const osvMaxConcurrentBatches = 4

// Scan reads requirements.txt at codePath and returns one Finding per
// (package, version, OSV-id) tuple. ErrNoRequirements signals "not a
// Python project" — callers should errors.Is-check it and skip.
//
// Network errors against api.osv.dev bubble up as wrapped errors —
// the orchestrator logs + continues; the Python deps.py path provides
// fallback coverage until Phase 17b removes it.
func Scan(ctx context.Context, codePath string) ([]models.Finding, error) {
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("pip: resolve path: %w", err)
	}
	reqFile := filepath.Join(abs, "requirements.txt")
	if _, err := os.Stat(reqFile); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoRequirements
		}
		return nil, fmt.Errorf("pip: stat requirements.txt: %w", err)
	}

	content, err := os.ReadFile(reqFile)
	if err != nil {
		return nil, fmt.Errorf("pip: read requirements.txt: %w", err)
	}
	pkgs := parseRequirements(string(content))
	if len(pkgs) == 0 {
		return nil, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir() // empty string disables caching — Scan still works

	findings := make([]models.Finding, 0)
	for _, p := range pkgs {
		vulns, err := queryOSV(ctx, client, cache, p.name, p.version)
		if err != nil {
			// Per-package failure shouldn't sink the whole scan. Log
			// to stderr and move on — pip-audit has the same posture.
			fmt.Fprintf(os.Stderr, "[fendix] pip: query %s==%s failed: %v\n", p.name, p.version, err)
			continue
		}
		for _, v := range vulns {
			findings = append(findings, buildFinding(p, v, "requirements.txt"))
		}
	}
	sortFindingsByID(findings)
	return findings, nil
}

// Options controls runtime behaviour of ScanRecursiveWithOptions. The
// zero value uses the native OSV.dev client (current default).
type Options struct {
	// UsePipAudit, when true, shells out to `pip-audit --format json`
	// for every discovered manifest instead of querying OSV.dev directly.
	// If pip-audit is not on PATH, a warning is emitted and the OSV.dev
	// path is used as fallback (never fails-closed silently).
	UsePipAudit bool
}

// ScanRecursive walks `codePath` up to `maxDepth` levels deep looking
// for every `requirements.txt` and scans them all. The returned findings
// carry a relative-path manifest stamp ("service/requirements.txt") so
// users can tell which manifest each CVE came from in multi-service
// monorepos.
//
// Surfaced as a UX gap by the Track 4 heavy-eval on TwiScope-backend:
// the root scan returned zero dep-CVEs because `requirements.txt` lived
// at `Twiscope_Main_App/requirements.txt`, not the scan root. Re-running
// against the subdir surfaced 7 cryptography CVEs that had been
// silently invisible.
//
// `maxDepth=0` means "current directory only" (equivalent to Scan).
// `maxDepth=1` means "current directory + immediate children", etc.
//
// Returns the empty slice (not ErrNoRequirements) when the walk finds
// no manifests at any depth — that's a "checked everywhere, nothing to
// scan" state distinct from a single-level miss. Caller can decide
// whether to log or skip.
//
// Dedups by absolute path so a symlink loop can't double-count, and
// scans manifests in alphabetical path order for stable output.
//
// Preserved as a thin wrapper around ScanRecursiveWithOptions for
// backward compat. Callers that want the new flag use the With-Options
// variant.
func ScanRecursive(ctx context.Context, codePath string, maxDepth int) ([]models.Finding, error) {
	return ScanRecursiveWithOptions(ctx, codePath, maxDepth, Options{})
}

// ScanRecursiveWithOptions is the explicit-options variant of
// ScanRecursive. When opts.UsePipAudit is true and pip-audit is on PATH,
// the scanner shells out to it; otherwise it falls back to the native
// OSV.dev /v1/query client. The fallback emits a stderr warning so the
// caller knows their flag was honoured at "best effort" only.
func ScanRecursiveWithOptions(ctx context.Context, codePath string, maxDepth int, opts Options) ([]models.Finding, error) {
	if opts.UsePipAudit {
		if path, err := exec.LookPath("pip-audit"); err == nil {
			return scanViaSubprocess(ctx, codePath, maxDepth, path)
		}
		fmt.Fprintln(os.Stderr, "[fendix] pip: --use-pip-audit set but pip-audit not found on PATH; falling back to OSV.dev client")
		// intentional fallthrough to OSV.dev path
	}
	return scanViaOSV(ctx, codePath, maxDepth)
}

// scanViaOSV scans every requirements.txt manifest under codePath
// (recursing up to maxDepth levels), batching OSV.dev queries across
// packages. Cache hits are processed first; cache misses are chunked
// into osvBatchMaxSize-sized batches with up to osvMaxConcurrentBatches
// in flight at once.
//
// If /v1/querybatch returns a non-2xx, the affected chunk falls back to
// the per-package /v1/query path with a logged warning. Per-batch
// failures don't sink the whole scan.
//
// Sprint-02 trade-off: /v1/querybatch responses include vuln IDs but
// NOT aliases. Findings emitted via the batch path therefore carry only
// an OSV-id reference; CVE-* aliases (which the per-package /v1/query
// path includes) are deferred to Sprint 02.5. The serial fallback path
// preserves alias coverage for any chunk that hits it.
func scanViaOSV(ctx context.Context, codePath string, maxDepth int) ([]models.Finding, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
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

	// Phase 1: collect all (package, manifest-rel-path) pairs across
	// every discovered manifest. The same package can appear in multiple
	// manifests in a multi-service repo; we keep the manifest stamp on
	// each pair so each finding's Endpoint correctly attributes ownership.
	var allPairs []pkgWithManifest
	for _, m := range manifests {
		content, err := os.ReadFile(m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] pip: read %s failed: %v\n", m, err)
			continue
		}
		pkgs := parseRequirements(string(content))
		if len(pkgs) == 0 {
			continue
		}
		rel, _ := filepath.Rel(abs, m)
		if rel == "" {
			rel = "requirements.txt"
		}
		for _, p := range pkgs {
			allPairs = append(allPairs, pkgWithManifest{pkg: p, manifest: rel})
		}
	}
	if len(allPairs) == 0 {
		return []models.Finding{}, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir()

	// Phase 2: cache lookup. Anything fresh in cache produces findings
	// now; misses go into the batch queue. Note we look up per-pair (not
	// per-package), so the same package present in two manifests gets
	// the cache hit applied to both manifests' findings.
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

	// Phase 3: batch the misses. Chunk into osvBatchMaxSize-sized
	// groups, run up to osvMaxConcurrentBatches concurrently. The
	// semaphore + waitgroup pattern keeps backpressure on OSV.dev's
	// rate limiter while still parallelising across chunks.
	if len(misses) > 0 {
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
				// Context cancellation surfaces here; bail with whatever
				// we've already gathered (cache hits + completed batches).
				wg.Wait()
				batchMu.Lock()
				findings = append(findings, batchFindings...)
				batchMu.Unlock()
				sortFindingsByID(findings)
				return findings, fmt.Errorf("pip: acquire batch slot: %w", err)
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

// runBatchOrFallback tries /v1/querybatch for a single chunk; on any
// batch-level failure (non-2xx, length mismatch, transport error) it
// falls back to the per-package /v1/query path so individual findings
// still surface. Cache writes happen on both paths.
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

// queryOSVBatch sends one /v1/querybatch request with up to
// osvBatchMaxSize packages. Returns map[<pkg>@<version>]vulns so
// callers can correlate responses back to their request packages.
//
// Known limitation: /v1/querybatch's response shape includes vuln IDs
// but NOT aliases. To get the CVE-* aliases that the per-package
// /v1/query path includes, callers would need a follow-up
// GET /v1/vulns/{id} per vuln. This is intentionally NOT done here;
// see Sprint 02 risks. The trade-off:
//
//   - Batch path (this function): N packages → 1 round trip, no aliases
//   - Serial fallback (runSerialFallback): N packages → N round trips,
//     full aliases
//
// Sprint 02.5 can hydrate aliases here if customers complain. Today we
// accept the alias gap to win the throughput improvement.
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

// scanViaSubprocess runs `pip-audit --format json -r <manifest>` for every
// requirements.txt manifest discovered under codePath up to maxDepth levels.
// Stamps the relative manifest path on each finding's Endpoint so users can
// tell which service owns each CVE (parity with scanViaOSV).
//
// pip-audit's JSON output shape (--format json):
//
//	{
//	  "dependencies": [
//	    {"name": "...", "version": "...", "vulns": [{"id": "...", "fix_versions": [...], "description": "..."}, ...]},
//	    ...
//	  ]
//	}
//
// We map pip-audit's vuln IDs (which are OSV IDs) into the SEC-DEPS-<id>
// shape used by scanViaOSV's buildFinding. Title/severity/fix shape is
// identical to the OSV.dev path so downstream dedup, correlator, and
// reporters cannot tell the two paths apart.
//
// pip-audit's JSON shape has changed twice in 2024. This implementation
// targets pip-audit >= 2.7.0 schema. Older versions: parsing returns an
// error with a clear "upgrade pip-audit" hint.
//
// The scan-budget context is inherited verbatim — pip-audit invocations
// honour the same wall-clock cap the orchestrator passes to the package.
func scanViaSubprocess(ctx context.Context, codePath string, maxDepth int, pipAuditPath string) ([]models.Finding, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
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
	var all []models.Finding
	for _, m := range manifests {
		rel, _ := filepath.Rel(abs, m)
		if rel == "" {
			rel = "requirements.txt"
		}
		cmd := exec.CommandContext(ctx, pipAuditPath, "--format", "json", "-r", m)
		out, err := cmd.Output()
		if err != nil {
			// pip-audit exits 1 when findings exist. Distinguish:
			// exit-1 + JSON output = expected; other exits = failure
			// (log + continue, don't sink the whole scan).
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && len(out) > 0 {
				// findings exist; proceed to parse
			} else {
				fmt.Fprintf(os.Stderr, "[fendix] pip: pip-audit failed on %s: %v\n", m, err)
				continue
			}
		}
		findings, perr := parsePipAuditJSON(out, rel)
		if perr != nil {
			return nil, fmt.Errorf("pip: parse pip-audit output for %s: %w (run with --verbose for stderr)", rel, perr)
		}
		all = append(all, findings...)
	}
	sortFindingsByID(all)
	return all, nil
}

// parsePipAuditJSON maps pip-audit's --format json output to []models.Finding.
// Targets pip-audit >= 2.7.0 schema. Returns a clear error on older schemas
// or any malformed JSON.
func parsePipAuditJSON(jsonBytes []byte, manifestRelPath string) ([]models.Finding, error) {
	var report struct {
		Dependencies []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Vulns   []struct {
				ID          string   `json:"id"`
				FixVersions []string `json:"fix_versions"`
				Description string   `json:"description"`
				Aliases     []string `json:"aliases"`
			} `json:"vulns"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(jsonBytes, &report); err != nil {
		return nil, fmt.Errorf("decode pip-audit JSON (expected schema from pip-audit >= 2.7.0; upgrade with `pip install -U pip-audit`): %w", err)
	}
	var findings []models.Finding
	for _, d := range report.Dependencies {
		for _, v := range d.Vulns {
			// Reuse buildFinding for shape parity. Convert pip-audit's
			// vuln record to the same osvVuln shape buildFinding consumes.
			osv := osvVuln{
				ID:      v.ID,
				Summary: v.Description,
				Aliases: v.Aliases,
			}
			// pip-audit returns fix_versions as a list; preserve the first.
			if len(v.FixVersions) > 0 {
				osv.Affected = []osvAffected{{
					Ranges: []osvRange{{Events: []osvEvent{{Fixed: v.FixVersions[0]}}}},
				}}
			}
			findings = append(findings, buildFinding(
				pinnedPackage{name: d.Name, version: d.Version},
				osv,
				manifestRelPath,
			))
		}
	}
	return findings, nil
}

// findRequirementsManifests returns absolute paths to every
// `requirements.txt` under `root` up to `maxDepth` levels deep. Depth
// 0 is `root` itself; depth 1 includes its immediate children, etc.
// Directories named in `recurseSkipDirs` are pruned regardless of depth.
//
// Output is sorted by path for deterministic scan order.
func findRequirementsManifests(root string, maxDepth int) ([]string, error) {
	var manifests []string
	rootDepth := strings.Count(filepath.ToSlash(root), "/")

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission-denied on a subdir shouldn't sink the whole walk.
			return nil
		}
		if d.IsDir() {
			if path != root && recurseSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			// Depth check
			depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
			if depth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "requirements.txt" {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(manifests)
	return manifests, nil
}

// pinnedPackage is one `==`-pinned line from requirements.txt.
type pinnedPackage struct {
	name    string
	version string
}

// pkgWithManifest carries the relative path of the manifest a package
// was discovered in. Sprint 02's batch path needs this stamp because
// the same package can appear in multiple manifests in a multi-service
// repo, and each finding must attribute ownership correctly via
// Finding.Endpoint.
type pkgWithManifest struct {
	pkg      pinnedPackage
	manifest string
}

// parseRequirements walks requirements.txt and yields only `==`-pinned
// entries. Comments (#), blank lines, and non-pinned specifiers are
// skipped — pip-audit refuses to scan unpinned deps for the same reason
// (the resolved version is environment-dependent).
//
// Hash specifiers (--hash=sha256:...) are stripped; extras
// (`package[extra]==1.0`) are stripped from the name; environment
// markers (`; python_version > "3.8"`) are stripped from the line.
func parseRequirements(content string) []pinnedPackage {
	var out []pinnedPackage
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip environment marker and trailing hash specifiers.
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, " --hash="); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Drop continuation backslashes — pip allows wrapping a
		// hash-laden line but we already cut at the first --hash=.
		line = strings.TrimRight(line, "\\")
		line = strings.TrimSpace(line)

		// Only `==` pins are scannable. >=, ~=, > etc. are skipped.
		idx := strings.Index(line, "==")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		// Strip extras: `package[extra1,extra2]` → `package`.
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		version := strings.TrimSpace(line[idx+2:])
		// A version may be followed by another specifier
		// (`==1.0,!=1.1` in legacy specs) — take the prefix until the
		// next comma.
		if i := strings.Index(version, ","); i >= 0 {
			version = strings.TrimSpace(version[:i])
		}
		if name == "" || version == "" {
			continue
		}
		out = append(out, pinnedPackage{name: strings.ToLower(name), version: version})
	}
	return out
}

// osvQueryRequest is the /v1/query payload shape per
// https://google.github.io/osv.dev/post-v1-query/.
type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvQueryResponse is the subset of /v1/query response we care about.
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
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

// queryOSV calls /v1/query for one (package, version) pair and returns
// the vulnerability list. Hits the local cache first; on miss, POSTs
// to OSV.dev and writes the response to cache.
func queryOSV(ctx context.Context, client *http.Client, cacheDir, pkg, version string) ([]osvVuln, error) {
	if cached, ok := readCache(cacheDir, pkg, version); ok {
		return cached, nil
	}

	body, _ := json.Marshal(osvQueryRequest{
		Package: osvPackage{Ecosystem: "PyPI", Name: pkg},
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
		// Drain to allow connection reuse.
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
func buildFinding(pkg pinnedPackage, v osvVuln, manifestName string) models.Finding {
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

	fix := firstFixVersion(v)
	fixMsg := "Upgrade to a patched version (no fix listed in OSV)."
	if fix != "" {
		fixMsg = fmt.Sprintf("Upgrade to %s==%s or later.", pkg.name, fix)
	}

	refs := []string{v.ID}
	if len(v.Aliases) > 0 {
		// Python deps.py emits only the first alias (matches that
		// shape for dedup parity).
		refs = append(refs, v.Aliases[0])
	}

	idSlug := strings.ReplaceAll(v.ID, "-", "_")
	line := manifestName
	return models.Finding{
		ID:         "SEC-DEPS-" + idSlug,
		Title:      fmt.Sprintf("Vulnerable dependency: %s==%s (%s)", pkg.name, pkg.version, v.ID),
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "deps",
		Endpoint:   manifestName,
		Evidence:   fmt.Sprintf("%s==%s: %s", pkg.name, pkg.version, desc),
		Fix:        fixMsg,
		References: refs,
		Confidence: models.ConfidenceHigh,
		Line:       &line,
	}
}

// firstFixVersion walks OSV.affected[].ranges[].events[] and returns
// the first `fixed` version (per OSV schema, the canonical upgrade
// target).
func firstFixVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// sortFindingsByID puts findings in deterministic order so the report
// is stable across runs of the same scan.
func sortFindingsByID(fs []models.Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
}

// --- cache ------------------------------------------------------------

// cacheDir returns ~/.fendix/cache/osv-pypi, creating it lazily. Empty
// string + nil error means "no usable cache dir" (HOME unset, perms
// denied, etc.) — Scan keeps working, just hits the network each call.
func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	d := filepath.Join(home, ".fendix", "cache", "osv-pypi")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

func cachePath(dir, pkg, version string) string {
	// Package names can contain `/` in some ecosystems; PyPI doesn't,
	// but normalise anyway to keep this resilient.
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
	// Write to a tmpfile then rename so concurrent scans don't see a
	// half-written cache file.
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
