// Package semgrep shells out to a host-installed semgrep binary,
// running fendix's bundled rule pack and mapping every match to a
// fendix Finding (TASK-116). Replaces the embedded
// python/analyzers/semgrep_runner.py path so the engine no longer
// requires Python at runtime for Semgrep checks.
//
// Behavioural parity with python/analyzers/semgrep_runner.py:
//   - SEC-<RULE_ID> finding IDs (uppercased, '-' and '.' → '_').
//   - Severity: rule metadata.fendix_severity wins; else map Semgrep's
//     ERROR/WARNING/INFO → HIGH/MEDIUM/LOW.
//   - Confidence: rule metadata.confidence; default MEDIUM.
//   - Category: rule metadata.category; default "code".
//   - References: rule metadata.cwe (string or list).
//   - Evidence: matched source lines, truncated at 200 chars + "...".
//   - 120s default timeout per invocation, mirroring Python.
//
// Distribution: rules are embedded into the binary via //go:embed
// and extracted to a per-process temp directory on first Scan call so
// the user's host semgrep can read them as files (semgrep --config
// requires a path on disk; it does not read stdin or in-memory rules).
//
// Graceful absence: if semgrep is not on $PATH the package returns
// ErrSemgrepUnavailable and the orchestrator logs an "install
// semgrep for X% more checks" notice and continues — matches the
// existing posture for missing Python.
package semgrep

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ErrSemgrepUnavailable signals that no `semgrep` binary was found on
// $PATH. Callers errors.Is-check it and emit the install-hint log line
// without treating it as a scan failure.
var ErrSemgrepUnavailable = errors.New("semgrep: binary not found on PATH")

// ErrCodePathMissing signals codePath is empty or doesn't exist —
// silent-skip parity with the Python `if not code_path.exists(): return`.
var ErrCodePathMissing = errors.New("semgrep: code path does not exist")

// defaultTimeout matches python semgrep_runner.py (120s). Bounded
// per scan so a runaway rule can't hold the orchestrator hostage.
const defaultTimeout = 120 * time.Second

// evidenceMaxLen mirrors python truncate-at-200-chars + "..." behaviour.
const evidenceMaxLen = 200

// titleMaxLen mirrors python message.split("\n")[0][:120].
const titleMaxLen = 120

//go:embed rules/*.yaml
var embeddedRules embed.FS

// rulesOnce caches the extracted rules-dir path across Scan calls so
// repeated scans within one process don't re-extract.
var (
	rulesOnce  sync.Once
	rulesDir   string
	rulesErr   error
	rulesClean func() // optional cleanup for test override
)

// LookPath wraps exec.LookPath and is var-not-func so tests can
// inject a fake binary location without touching $PATH.
var LookPath = exec.LookPath

// commandContext wraps exec.CommandContext for the same reason.
var commandContext = exec.CommandContext

// Scan runs the bundled fendix rule pack against codePath via the
// host's semgrep binary. Returns ErrSemgrepUnavailable when semgrep
// isn't installed; ErrCodePathMissing when codePath doesn't exist.
//
// Other failures (timeout, malformed JSON, non-success exit) return a
// wrapped error and an empty findings slice — the orchestrator logs +
// continues so a flaky semgrep run can't fail the whole scan.
//
// The provided ctx is honoured: cancellation kills the semgrep
// subprocess. A 120s deadline is layered onto ctx if ctx has no
// shorter deadline already.
func Scan(ctx context.Context, codePath string) ([]models.Finding, error) {
	if codePath == "" {
		return nil, ErrCodePathMissing
	}
	if info, err := os.Stat(codePath); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCodePathMissing
		}
		return nil, fmt.Errorf("semgrep: stat %q: %w", codePath, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("semgrep: %q is not a directory", codePath)
	}

	bin, err := LookPath("semgrep")
	if err != nil {
		return nil, ErrSemgrepUnavailable
	}

	rules, err := ensureRules()
	if err != nil {
		return nil, fmt.Errorf("semgrep: extract rules: %w", err)
	}

	runCtx, cancel := contextWithDefaultTimeout(ctx, defaultTimeout)
	defer cancel()

	cmd := commandContext(runCtx, bin,
		"--config", rules,
		"--json",
		"--no-git-ignore",
		"--quiet",
		codePath,
	)
	// On ctx cancel/timeout, the default Cancel hook SIGKILLs the
	// semgrep entrypoint, but Wait blocks until any orphaned children
	// (semgrep's worker processes) also exit. WaitDelay bounds that to
	// 1s — after which Go closes the I/O pipes and returns from Wait
	// even if children are still alive. Stops the cancel-budget test
	// blowing past its 2s assertion on slow Linux CI runners.
	cmd.WaitDelay = 1 * time.Second
	stdout, err := cmd.Output()
	if err != nil {
		// Context errors (cancel/deadline) are always real failures —
		// surface them so the orchestrator can stop the scan.
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("semgrep: timed out after %s", defaultTimeout)
		}
		if errors.Is(runCtx.Err(), context.Canceled) {
			return nil, runCtx.Err()
		}
		// If semgrep emitted parseable JSON we accept it regardless of
		// exit code. Semgrep returns 1 for "matches found" (success
		// case), and 2/5/7 for various rule-parse / engine errors —
		// in all cases the JSON envelope is well-formed and the
		// `results` field is meaningful (often empty when rules
		// failed to parse). Matches python semgrep_runner.py which
		// silently absorbs non-{0,1} exits as long as stdout parses.
		if findings, perr := parseAndMap(stdout, codePath); perr == nil && (len(findings) > 0 || isParseableEmpty(stdout)) {
			return findings, nil
		}
		// Truly broken: no parseable output AND non-zero exit.
		var exitErr *exec.ExitError
		stderr := ""
		if errors.As(err, &exitErr) {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
			if len(stderr) > 200 {
				stderr = stderr[:200] + "..."
			}
		}
		return nil, fmt.Errorf("semgrep: %w (stderr: %s)", err, stderr)
	}

	return parseAndMap(stdout, codePath)
}

// isParseableEmpty reports whether stdout decodes as a Semgrep JSON
// envelope, even one with zero results — this is how we distinguish
// "rule parse failure with valid JSON envelope" (treat as 0 findings)
// from "subprocess crashed before writing JSON" (real failure).
func isParseableEmpty(stdout []byte) bool {
	if len(stdout) == 0 {
		return false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &probe); err != nil {
		return false
	}
	_, hasResults := probe["results"]
	return hasResults
}

// contextWithDefaultTimeout returns a context with the given timeout
// only when ctx itself has no earlier deadline; otherwise returns a
// no-op cancel + the original context.
func contextWithDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		if time.Until(dl) <= d {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, d)
}

// semgrepResult mirrors the subset of the Semgrep JSON schema we use.
type semgrepResult struct {
	CheckID string         `json:"check_id"`
	Path    string         `json:"path"`
	Start   semgrepLineCol `json:"start"`
	Extra   semgrepExtra   `json:"extra"`
}

type semgrepLineCol struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	Lines    string                 `json:"lines"`
	Metadata map[string]interface{} `json:"metadata"`
}

// semgrepOutput wraps a top-level Semgrep --json document.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

// parseAndMap decodes Semgrep's stdout JSON and converts each result
// into a fendix Finding. Empty or malformed stdout returns (nil, nil)
// so the orchestrator treats the scan as zero-findings rather than
// failed — matches python semgrep_runner.py which silently absorbs
// JSONDecodeError and returns an empty list. The Scan caller is
// responsible for surfacing real failures (timeout, ctx cancel,
// non-success exit with no parseable output).
func parseAndMap(stdout []byte, codeRoot string) ([]models.Finding, error) {
	if len(stdout) == 0 {
		return nil, nil
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		return nil, nil
	}
	absRoot, err := filepath.Abs(codeRoot)
	if err != nil {
		absRoot = codeRoot
	}
	findings := make([]models.Finding, 0, len(out.Results))
	for i := range out.Results {
		f, ok := mapResult(&out.Results[i], absRoot)
		if !ok {
			continue
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// mapResult converts one Semgrep result to a fendix Finding. Returns
// (zero, false) if the result lacks the minimal fields needed to be
// useful (no path or no rule id).
func mapResult(r *semgrepResult, absRoot string) (models.Finding, bool) {
	if r.CheckID == "" || r.Path == "" {
		return models.Finding{}, false
	}
	rel := r.Path
	if absPath, err := filepath.Abs(r.Path); err == nil {
		if rp, err := filepath.Rel(absRoot, absPath); err == nil && !strings.HasPrefix(rp, "..") {
			rel = rp
		}
	}
	rel = filepath.ToSlash(rel)
	endpoint := fmt.Sprintf("%s:%d", rel, r.Start.Line)
	endpointCopy := endpoint

	title := strings.TrimSpace(r.Extra.Message)
	if i := strings.IndexByte(title, '\n'); i >= 0 {
		title = title[:i]
	}
	if len(title) > titleMaxLen {
		title = title[:titleMaxLen]
	}
	if title == "" {
		title = "Semgrep finding"
	}

	snippet := strings.TrimSpace(r.Extra.Lines)
	if len(snippet) > evidenceMaxLen {
		snippet = snippet[:evidenceMaxLen] + "..."
	}

	id := "SEC-" + strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(r.CheckID), "-", "_"), ".", "_")

	return models.Finding{
		ID:         id,
		Title:      title,
		Severity:   resolveSeverity(r),
		Source:     models.SourceWhitebox,
		Category:   resolveCategory(r),
		Endpoint:   endpoint,
		Evidence:   snippet,
		Fix:        strings.TrimSpace(r.Extra.Message),
		References: resolveCWE(r),
		Confidence: resolveConfidence(r),
		Line:       &endpointCopy,
	}, true
}

// validFendixSeverities is the allowed set for the metadata.fendix_severity
// override field.
var validFendixSeverities = map[string]models.Severity{
	"CRITICAL": models.SeverityCritical,
	"HIGH":     models.SeverityHigh,
	"MEDIUM":   models.Severity("MEDIUM"),
	"LOW":      models.Severity("LOW"),
	"INFO":     models.Severity("INFO"),
}

// semgrepSeverityMap mirrors python _SEVERITY_MAP. Falls back to
// MEDIUM for unknown values, matching the Python default.
var semgrepSeverityMap = map[string]models.Severity{
	"ERROR":   models.SeverityHigh,
	"WARNING": models.Severity("MEDIUM"),
	"INFO":    models.Severity("LOW"),
}

func resolveSeverity(r *semgrepResult) models.Severity {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["fendix_severity"].(string); ok {
			if sev, ok := validFendixSeverities[strings.ToUpper(v)]; ok {
				return sev
			}
		}
	}
	if sev, ok := semgrepSeverityMap[strings.ToUpper(r.Extra.Severity)]; ok {
		return sev
	}
	return models.Severity("MEDIUM")
}

func resolveConfidence(r *semgrepResult) models.Confidence {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["confidence"].(string); ok {
			switch strings.ToUpper(v) {
			case "HIGH":
				return models.ConfidenceHigh
			case "MEDIUM":
				return models.Confidence("MEDIUM")
			case "LOW":
				return models.Confidence("LOW")
			}
		}
	}
	return models.Confidence("MEDIUM")
}

func resolveCategory(r *semgrepResult) string {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["category"].(string); ok && v != "" {
			return v
		}
	}
	return "code"
}

// resolveCWE accepts both string and []string shapes — Semgrep rule
// metadata supports either; Python coerces to a list either way.
func resolveCWE(r *semgrepResult) []string {
	if r.Extra.Metadata == nil {
		return nil
	}
	raw, ok := r.Extra.Metadata["cwe"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// ensureRules extracts the embedded YAML rule files to a per-process
// temp directory on first call and returns its absolute path. Repeats
// of Scan within one process reuse the same directory — the rules are
// compiled into the binary so re-extraction would be wasted work.
//
// The temp dir is intentionally not cleaned up: it lives for the
// process lifetime; the OS reclaims /tmp/* on reboot. Cleanup on
// signal would race with in-flight semgrep subprocesses and is
// strictly worse than the no-op.
func ensureRules() (string, error) {
	rulesOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fendix-semgrep-rules-")
		if err != nil {
			rulesErr = err
			return
		}
		err = fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			data, err := embeddedRules.ReadFile(path)
			if err != nil {
				return err
			}
			out := filepath.Join(dir, filepath.Base(path))
			return os.WriteFile(out, data, 0o644)
		})
		if err != nil {
			rulesErr = err
			return
		}
		rulesDir = dir
	})
	return rulesDir, rulesErr
}

// resetRulesCacheForTesting wipes the once-cached rules dir so a new
// extraction can happen in the next Scan call. Used by tests that need
// to assert extraction behaviour deterministically.
func resetRulesCacheForTesting() {
	if rulesClean != nil {
		rulesClean()
	}
	rulesOnce = sync.Once{}
	rulesDir = ""
	rulesErr = nil
	rulesClean = nil
}
