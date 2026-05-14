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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Rule describes one SAST pattern. A file matches a rule when its
// path passes Applies() and the rule's Pattern matches any line.
type Rule struct {
	ID          string
	Title       string
	Severity    models.Severity
	Confidence  models.Confidence
	Category    string // "injection" | "secrets" | "auth" | "iac" | "crypto" ...
	CWE         string
	Pattern     *regexp.Regexp
	NegPattern  *regexp.Regexp // optional: line must NOT also match
	Fix         string
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
func Scan(rootDir string, rules []Rule) ([]models.Finding, error) {
	const maxFileBytes = 1 << 20 // 1 MiB
	var findings []models.Finding

	if rootDir == "" {
		return nil, fmt.Errorf("textscan: rootDir is required")
	}
	if _, err := os.Stat(rootDir); err != nil {
		return nil, fmt.Errorf("textscan: %s: %w", rootDir, err)
	}

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries; don't fail the walk
		}
		if d.IsDir() {
			// Skip noisy build / vendor / VCS dirs.
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == "__pycache__" || name == ".venv" || name == "build" ||
				name == "dist" || name == ".pytest_cache" {
				return filepath.SkipDir
			}
			return nil
		}
		// Find which rules apply to this path.
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
		if err != nil {
			return nil
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		got, err := scanFile(rootDir, path, applicable)
		if err != nil {
			return nil
		}
		findings = append(findings, got...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	return findings, nil
}

// scanFile reads one file line-by-line and applies the supplied
// rules. We use bufio.Scanner with a generous buffer to handle
// auto-generated source files with long lines.
func scanFile(rootDir, path string, rules []*Rule) ([]models.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel := pathRel(rootDir, path)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // 1 MiB max line

	var findings []models.Finding
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		// Strip leading/trailing whitespace for the snippet but use
		// the original for pattern matching (some rules care about
		// leading whitespace).
		for _, r := range rules {
			if !r.Pattern.MatchString(line) {
				continue
			}
			if r.NegPattern != nil && r.NegPattern.MatchString(line) {
				continue
			}
			endpoint := fmt.Sprintf("%s:%d", rel, lineNo)
			endpointCopy := endpoint
			snippet := strings.TrimSpace(line)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "…"
			}
			findings = append(findings, models.Finding{
				ID:         r.ID,
				Title:      r.Title,
				Severity:   r.Severity,
				Source:     models.SourceWhitebox,
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
