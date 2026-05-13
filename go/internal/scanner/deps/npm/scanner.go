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
//   ~/.fendix/cache/osv-npm/<pkg>@<version>.json
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
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
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
const cacheTTL = 24 * time.Hour

const httpTimeout = 15 * time.Second

// Scan reads package-lock.json at codePath and returns one Finding per
// (package, resolved-version, OSV-id) tuple. ErrNoLockfile signals
// "not a Node project (or yarn/pnpm-only)" — caller skips silently.
func Scan(ctx context.Context, codePath string) ([]models.Finding, error) {
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

	findings := make([]models.Finding, 0)
	for _, p := range pkgs {
		vulns, err := queryOSV(ctx, client, cache, p.name, p.version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] npm: query %s@%s failed: %v\n", p.name, p.version, err)
			continue
		}
		for _, v := range vulns {
			findings = append(findings, buildFinding(p, v, "package-lock.json"))
		}
	}
	sortFindingsByID(findings)
	return findings, nil
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
func buildFinding(pkg resolvedPackage, v osvVuln, manifestName string) models.Finding {
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
		fixMsg = fmt.Sprintf("Upgrade to %s@%s or later.", pkg.name, fix)
	}

	refs := []string{v.ID}
	if len(v.Aliases) > 0 {
		refs = append(refs, v.Aliases[0])
	}

	idSlug := strings.ReplaceAll(v.ID, "-", "_")
	line := manifestName
	return models.Finding{
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
	}
}

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

func sortFindingsByID(fs []models.Finding) {
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
