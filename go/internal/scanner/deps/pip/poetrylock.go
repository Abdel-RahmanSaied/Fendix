package pip

import (
	"encoding/json"
	"strings"
)

// poetry.lock and Pipfile.lock give the *fully resolved transitive closure*
// of a Python project — every package and its exact pinned version, not just
// the direct deps a requirements.txt typically lists. Parsing them is what
// turns the pip scanner from "PyPI direct-deps only" into real transitive
// SCA coverage (90-day cut, item 3): a CVE in a sub-dependency three levels
// down is invisible to requirements.txt but present in the lockfile.
//
// We parse poetry.lock with a small purpose-built scanner rather than pull
// in a TOML dependency — the format is regular enough (a flat list of
// [[package]] tables, each with `name` and `version` string fields) that a
// line scanner is both sufficient and dependency-free, matching the
// codebase's "no new external deps in the scanner" stance.

// parsePoetryLock extracts pinned (name, version) packages from a poetry.lock
// file's TOML content. poetry.lock is a flat sequence of [[package]] tables:
//
//	[[package]]
//	name = "flask"
//	version = "2.0.1"
//	description = "..."
//	...
//	[[package]]
//	name = "werkzeug"
//	version = "2.0.3"
//
// Only the name and version are needed for an OSV lookup. We deliberately
// ignore everything else (dependencies, hashes, markers) — OSV resolves
// vulnerability by (ecosystem, name, version), and the lockfile already
// pins the resolved version, so no constraint solving is required.
//
// Robustness choices:
//   - A [[package]] block contributes a package only if BOTH name and
//     version were seen before the next [[package]] (or EOF). A malformed
//     block missing one is skipped, not guessed.
//   - name/version values are unquoted (poetry always double-quotes them);
//     a bare value is accepted too, defensively.
//   - Lines inside nested tables of a package (e.g. [package.dependencies])
//     are ignored: only the top-level name/version keys of the package table
//     count. We track this by only reading name/version when we're directly
//     under a [[package]] header and have not yet descended into a sub-table.
func parsePoetryLock(content string) []pinnedPackage {
	var pkgs []pinnedPackage

	var (
		inPackage  bool   // currently inside a [[package]] table
		inSubTable bool   // descended into a [package.xxx] sub-table
		curName    string // name captured for the current package
		curVersion string // version captured for the current package
	)

	flush := func() {
		if inPackage && curName != "" && curVersion != "" {
			pkgs = append(pkgs, pinnedPackage{name: curName, version: curVersion})
		}
		curName, curVersion = "", ""
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Table headers.
		if strings.HasPrefix(line, "[[package]]") {
			flush() // close out the previous package, if any
			inPackage = true
			inSubTable = false
			continue
		}
		if strings.HasPrefix(line, "[") {
			// Some other table header. If it's a sub-table of the current
			// package (e.g. [package.dependencies], [package.extras]) we stop
			// reading name/version from it. If it's a different top-level
			// table (e.g. [metadata]), the package context ends.
			if strings.HasPrefix(line, "[package.") || strings.HasPrefix(line, "[[package.") {
				inSubTable = true
			} else {
				flush()
				inPackage = false
				inSubTable = false
			}
			continue
		}

		if !inPackage || inSubTable {
			continue
		}

		// key = value
		key, val, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		switch key {
		case "name":
			curName = val
		case "version":
			curVersion = val
		}
	}
	flush() // last package at EOF

	return pkgs
}

// splitKeyValue parses a `key = "value"` TOML assignment, returning the
// unquoted value. Returns ok=false for lines that aren't a simple scalar
// assignment (arrays, inline tables, etc.) — those are never name/version.
func splitKeyValue(line string) (key, val string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	// Strip an inline comment outside of the quotes. poetry doesn't emit
	// inline comments on name/version, but be defensive.
	if !strings.HasPrefix(rest, "\"") {
		if hash := strings.IndexByte(rest, '#'); hash >= 0 {
			rest = strings.TrimSpace(rest[:hash])
		}
	}
	val = unquoteTOML(rest)
	if val == "" {
		return "", "", false
	}
	return key, val, true
}

// parsePipfileLock extracts pinned (name, version) packages from a
// Pipfile.lock (pipenv's lockfile, JSON format). The shape is:
//
//	{
//	  "default":  { "flask": {"version": "==2.0.1", ...}, ... },
//	  "develop":  { "pytest": {"version": "==7.0.0", ...}, ... }
//	}
//
// Both the "default" (runtime) and "develop" (dev) sections are the fully
// resolved transitive closure with exact, ==-pinned versions. We scan both
// — a CVE in a dev dependency is still a finding worth surfacing (it ships
// in CI images and developer machines). The leading "==" on each version is
// stripped to the bare version OSV expects.
func parsePipfileLock(content string) []pinnedPackage {
	var doc struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	var pkgs []pinnedPackage
	collect := func(m map[string]struct {
		Version string `json:"version"`
	}) {
		for name, entry := range m {
			v := strings.TrimSpace(entry.Version)
			v = strings.TrimPrefix(v, "==")
			if name == "" || v == "" {
				continue
			}
			pkgs = append(pkgs, pinnedPackage{name: name, version: v})
		}
	}
	collect(doc.Default)
	collect(doc.Develop)
	return pkgs
}

// unquoteTOML strips matching double or single quotes from a TOML string
// value. A bare (unquoted) token is returned as-is. Arrays/tables (starting
// with [ or {) yield "" so the caller skips them.
func unquoteTOML(s string) string {
	if s == "" {
		return ""
	}
	if s[0] == '[' || s[0] == '{' {
		return ""
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
