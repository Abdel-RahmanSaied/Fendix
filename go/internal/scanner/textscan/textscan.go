// Package textscan ships a regex-based SAST engine that drives the
// Sprint-04 (Go), Sprint-05 (JS/TS), and Sprint-06 (Dockerfile + k8s
// YAML) rulesets in one unified scanner. The brief originally
// scoped these as three separate sprints with three separate code
// trees; consolidating them is the plan-finish session's deliberate
// scope decision — see PLAN.md and the per-sprint Status notes.
//
// Design constraints:
//
//   - No new external deps (per PLAN.md). Pure stdlib + the
//     existing models package.
//   - No CGo. The engine walks files with filepath.WalkDir and
//     runs regexes (regexp package).
//   - Conservative rule design. Each rule has a FP/FN class
//     documented in its inline comment; LOW-confidence patterns
//     ship with severity capped at MEDIUM (the orchestrator's
//     consistency rule from docs/semgrep-rules.md).
//   - Filename-extension routing. .go → Go rules, .js/.ts/.jsx/.tsx
//     → JS rules, .dockerfile / Dockerfile / Dockerfile.* → Docker
//     rules, .yaml/.yml under detection of k8s shape (apiVersion +
//     kind) → k8s rules.
//
// What this package deliberately does NOT do (vs. the briefs):
//
//   - **No Go AST walking.** GO_XXE and GO_INSECURE_RAND from
//     Sprint 04's brief need cross-function context to avoid
//     drowning the user in stdlib false-positives. They're cut to
//     Sprint 04.5 (genuine AST-walker work).
//   - **No JS proximity context.** JS_PROTO_POLLUTION and
//     JS_INSECURE_RAND from Sprint 05's brief are cut to Sprint
//     5.5 for the same reason — the regex+window approach has too
//     many false positives.
//   - **No Terraform HCL.** Sprint 06's D2 gate is at its default
//     (no TF). Sprint 06 ships Dockerfile + k8s only.
//
// Each shipped rule has a deliberately small surface — fewer rules,
// higher precision, no trust-eroding flood of FPs. Customers can
// layer in their own via the existing semgrep rule-pack mechanism.
package textscan

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/gitdiff"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Rule describes one SAST pattern. A file matches a rule when its
// path passes Applies() and the rule's Pattern matches any line.
type Rule struct {
	ID         string
	Title      string
	Severity   models.Severity
	Confidence models.Confidence
	Category   string // "injection" | "secrets" | "auth" | "iac" | "crypto" ...
	CWE        string
	Pattern    *regexp.Regexp
	NegPattern *regexp.Regexp // optional: line must NOT also match
	Fix        string
	// Applies returns true when path falls under this rule's
	// language-extension set.
	Applies func(path string) bool
}

// Scan walks rootDir and returns a Finding per (rule, line) match.
// Files larger than maxFileBytes are skipped (the scanner is meant
// for source, not data blobs). Default cap: 1 MiB per file.
//
// Errors during file reads are logged via the slog default and
// skipped — one unreadable file doesn't fail the scan.
func Scan(rootDir string, rules []Rule) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(rootDir, rules, nil)
}

// ScanWithAllowlist is Scan scoped to a diff-aware file allowlist. When
// allow is nil the behaviour is identical to Scan (full walk). When set,
// only files whose absolute path is in the allowlist are scanned — the
// engine half of `fendix scan --diff`. Directories are still walked (so
// skip-dir pruning still happens) but non-allowlisted files are skipped
// before they are read, keeping diff scans sub-second on large trees.
func ScanWithAllowlist(rootDir string, rules []Rule, allow *gitdiff.Allowlist) ([]evidence.Evidence, error) {
	var findings []evidence.Evidence

	if rootDir == "" {
		return nil, fmt.Errorf("textscan: rootDir is required")
	}
	if _, err := os.Stat(rootDir); err != nil {
		return nil, fmt.Errorf("textscan: %s: %w", rootDir, err)
	}

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (the orchestrator also short-circuits) since this is exported.
	if allow.Empty() {
		return nil, nil
	}

	// Diff-aware fast path: when the allowlist names specific changed files,
	// scan exactly those — O(changed files) — instead of walking the whole
	// tree to filter down to them. The reachable set stays a strict subset of
	// the walk's: skip symlinks (the walk refuses them) AND any file reached
	// through a symlinked parent dir (which WalkDir never descends, and which
	// could escape rootDir), plus the same pruned dirs; then run the shared
	// scanCandidate body. (Empty allowlists already returned above.)
	if allow != nil {
		for _, path := range allow.AbsPaths() {
			info, err := os.Lstat(path)
			if err != nil || info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
				continue
			}
			if underSkipDir(rootDir, path) || gitdiff.TraversesSymlink(rootDir, path) {
				continue
			}
			findings = append(findings, scanCandidate(rootDir, path, fs.FileInfoToDirEntry(info), rules)...)
		}
		return findings, nil
	}

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries; don't fail the walk
		}
		// Skip symlinks unconditionally — both file and directory
		// symlinks. filepath.WalkDir does not follow symlinks (it uses
		// lstat), so a directory symlink shows up here with
		// d.Type()&fs.ModeSymlink != 0 and IsDir() == false; refuse
		// to descend or read either way. Prevents loops and silent
		// privilege boundary crossings (e.g. /tmp symlink to /etc).
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			// Skip noisy build / vendor / VCS dirs.
			if _, skip := textSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		// Diff-aware scoping: skip files outside the allowlist before any
		// read. A nil allowlist allows everything (full-scan default).
		if !allow.Allows(path) {
			return nil
		}
		findings = append(findings, scanCandidate(rootDir, path, d, rules)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	return findings, nil
}

// textSkipDirs are the build / vendor / VCS directories pruned from the scan.
// Single-sourced so the full walk and the diff-aware fast path agree on what
// to skip.
var textSkipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "__pycache__": {},
	".venv": {}, "build": {}, "dist": {}, ".pytest_cache": {},
	".next": {}, ".nuxt": {}, ".svelte-kit": {}, ".cache": {}, "target": {},
}

const textMaxFileBytes = 1 << 20 // 1 MiB

// scanCandidate runs the applicable rules against a single file that has
// already passed the symlink / dir / allowlist gates. Shared by the full walk
// and the diff-aware fast path so both apply identical rule-applicability,
// size, and binary-sniff logic — no parity drift between the two code paths.
func scanCandidate(rootDir, path string, d fs.DirEntry, rules []Rule) []evidence.Evidence {
	applicable := make([]*Rule, 0, len(rules))
	for i := range rules {
		if rules[i].Applies != nil && rules[i].Applies(path) {
			applicable = append(applicable, &rules[i])
		}
	}
	if len(applicable) == 0 {
		return nil
	}
	info, err := d.Info()
	if err != nil || info.Size() > textMaxFileBytes {
		return nil
	}
	// Skip binary blobs. Reading PNGs/jars/sqlite line-by-line against every
	// regex is CPU waste and produces false-positive AKIA hits in binary
	// noise; sniff the first 512 bytes so the AWS-key et al. rules never run
	// on non-text.
	if looksBinary, _ := isBinaryFile(path); looksBinary {
		return nil
	}
	got, err := scanFile(rootDir, path, applicable)
	if err != nil {
		return nil
	}
	return got
}

// underSkipDir reports whether any directory component of abs (relative to
// root) is a pruned directory — preserving walk parity for the diff-aware
// fast path (e.g. a committed vendor/ file the walk would never reach).
func underSkipDir(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, part := range parts[:len(parts)-1] { // dir components only, not the file
		if _, skip := textSkipDirs[part]; skip {
			return true
		}
	}
	return false
}

// dockerfileHasUSER reports whether a Dockerfile-shaped file
// contains a `USER` directive. Used to suppress IAC_DOCKER_RUNS_AS_ROOT
// when the image actually drops privileges. Cheap whole-file pre-pass
// so the per-line scan can stay stateless.
func dockerfileHasUSER(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if regexp.MustCompile(`^USER\s+\S`).MatchString(line) {
			return true
		}
	}
	return false
}

// scanFile reads one file line-by-line and applies the supplied
// rules. We use bufio.Scanner with a generous buffer to handle
// auto-generated source files with long lines.
func scanFile(rootDir, path string, rules []*Rule) ([]evidence.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel := pathRel(rootDir, path)

	// Whole-file pre-pass for rules that need context outside one
	// line. Today: IAC_DOCKER_RUNS_AS_ROOT is suppressed when any
	// `USER <name>` directive exists in the Dockerfile.
	suppressRule := map[string]bool{}
	if IsDockerfile(path) && dockerfileHasUSER(path) {
		suppressRule["IAC_DOCKER_RUNS_AS_ROOT"] = true
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // 1 MiB max line

	var findings []evidence.Evidence
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		// Strip leading/trailing whitespace for the snippet but use
		// the original for pattern matching (some rules care about
		// leading whitespace).
		for _, r := range rules {
			if suppressRule[r.ID] {
				continue
			}
			if !r.Pattern.MatchString(line) {
				continue
			}
			if r.NegPattern != nil && r.NegPattern.MatchString(line) {
				continue
			}
			endpoint := fmt.Sprintf("%s:%d", rel, lineNo)
			endpointCopy := endpoint
			snippet := strings.TrimSpace(line)
			if utf8.RuneCountInString(snippet) > 200 {
				runes := []rune(snippet)
				snippet = string(runes[:199]) + "…"
			}
			findings = append(findings, evidence.Evidence{
				ID:         r.ID,
				RuleID:     r.ID,
				Title:      r.Title,
				Severity:   r.Severity,
				Source:     models.SourceWhitebox,
				SourceTier: models.TierNativeGo,
				Category:   r.Category,
				Endpoint:   endpoint,
				Evidence:   snippet,
				Fix:        r.Fix,
				References: []string{r.CWE},
				Confidence: r.Confidence,
				Line:       &endpointCopy,
			})
		}
	}
	return findings, sc.Err()
}

// pathRel returns path relative to rootDir using forward slashes.
// Errors degrade to the absolute path.
func pathRel(rootDir, path string) string {
	if rel, err := filepath.Rel(rootDir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// HasGoExtension is a small exported helper used by Applies funcs.
func HasGoExtension(path string) bool {
	return strings.HasSuffix(path, ".go")
}

// HasJSExtension reports JavaScript / TypeScript files.
func HasJSExtension(path string) bool {
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// IsDockerfile reports paths the Dockerfile rules apply to.
// Matches `Dockerfile`, `Dockerfile.<anything>`, and `*.dockerfile`.
func IsDockerfile(path string) bool {
	base := filepath.Base(path)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(base), ".dockerfile")
}

// IsYAML reports paths with a YAML extension. Caller (the k8s rule)
// is responsible for checking content shape (`apiVersion:` + `kind:`)
// before flagging anything.
func IsYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// isBinaryFile sniffs the first 512 bytes of path and reports whether
// the file looks binary. The heuristic: any NUL byte → binary. This
// is the same shape stdlib http.DetectContentType uses internally and
// is robust enough for the scanner's "skip blobs" need. Returns
// (false, nil) when the file can't be opened — the caller will then
// try to scan it (and probably fail similarly), which is fine.
func isBinaryFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}
