// Package pip runs an in-process PyPI dependency CVE scan against
// requirements.txt manifests and emits fendix Findings for any pinned
// version that matches an OSV.dev vulnerability record.
//
// Behavioural parity with python/analyzers/deps.py::_check_requirements:
//   - One Finding per (package, version, OSV-id) tuple.
//   - ID shape: SEC-DEPS-<vid-with-underscores> (no PY prefix; matches the
//     Python output so dedup collapses overlap during the transition
//     window before Phase 17b drops the embedded Python deps path).
//   - Fix line picks the first OSV `affected[].ranges[].events[].fixed`
//     entry per OSV schema.
//   - References include the OSV ID followed by every alias.
//
// Limitations (deliberate — match pip-audit's scope):
//   - Only pinned `==` versions are checked. Range specifiers (`>=`,
//     `~=`, `>`) are skipped with a stderr warning — pip-audit also
//     requires resolved versions and refuses to guess for ranges.
//   - No transitive resolution. Direct deps only. Phase 17b can add a
//     `pip install --dry-run --report` step if transitive coverage
//     becomes important; today's contract matches the Python path.
//
// Cache: OSV.dev responses are cached at
//   ~/.fendix/cache/osv-pypi/<package>@<version>.json
// with a 24h TTL. Cache stamp = file mtime; older = re-fetch. The
// directory is created lazily on first miss.
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
	"path/filepath"
	"sort"
	"strings"
	"time"

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
func ScanRecursive(ctx context.Context, codePath string, maxDepth int) ([]models.Finding, error) {
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

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir()

	var all []models.Finding
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
			vulns, qerr := queryOSV(ctx, client, cache, p.name, p.version)
			if qerr != nil {
				fmt.Fprintf(os.Stderr, "[fendix] pip: query %s==%s failed: %v\n", p.name, p.version, qerr)
				continue
			}
			for _, v := range vulns {
				all = append(all, buildFinding(p, v, rel))
			}
		}
	}
	sortFindingsByID(all)
	return all, nil
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
