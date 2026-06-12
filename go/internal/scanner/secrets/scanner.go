// Package secrets detects hardcoded secrets in source code via regex
// pattern matching, ported in-process from python/analyzers/secrets.py
// (TASK-115). Walks codePath recursively and emits one Finding per
// (pattern, file, line) match.
//
// Behavioural parity with python/analyzers/secrets.py:
//   - Same 15 patterns + ENV_SECRET (.env-only).
//   - Same SEC-<PATTERN_ID> finding IDs so dedup collapses any overlap
//     during the transition window before TASK-118 deletes secrets.py.
//   - Same skip-dirs / file-extension gate / .env name match.
//   - Same 1MB file-size cap and >500-char minified-JS-line skip.
//   - Same evidence truncation (first 20 chars of the secret + "...",
//     embedded in a 120-char window around the match).
//
// Regex notes: Go's RE2 doesn't support lookbehinds/lookaheads, so
// patterns that anchor token prefixes (ghp_, sk_live_, AKIA, etc.) in
// Python via (?<![A-Za-z0-9]) have the lookarounds stripped here and
// boundary characters validated manually post-match. See boundaryOK.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/gitdiff"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ErrCodePathMissing signals the codePath argument is empty or points
// nowhere. Callers errors.Is-check it and silently skip — matches the
// Python `if not root.exists(): return` early-out.
var ErrCodePathMissing = errors.New("secrets: code path does not exist")

const (
	// maxFileBytes mirrors python secrets.py _MAX_FILE_BYTES (1 MB).
	maxFileBytes = 1 << 20
	// evidenceMaxLen mirrors python _EVIDENCE_MAX_LEN.
	evidenceMaxLen = 120
	// minifiedLineLen mirrors python _is_minified (>500 chars in .js/.ts).
	minifiedLineLen = 500
	// secretShowLen mirrors python _truncate_secret default (first 20 chars).
	secretShowLen = 20
	// fixText mirrors python finding `fix` field.
	fixText = "Remove the hardcoded credential. Store secrets in environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager). Rotate the exposed credential immediately."
)

// skipDirs mirrors python _SKIP_DIRS. Pruned in-place during the walk
// so we never descend into them.
var skipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "__pycache__": {},
	".venv": {}, "venv": {}, "dist": {}, "build": {}, ".tox": {},
}

// scanExtensions mirrors python _SCAN_EXTENSIONS. Lower-case match on
// filepath.Ext.
var scanExtensions = map[string]struct{}{
	".py": {}, ".js": {}, ".ts": {}, ".jsx": {}, ".tsx": {}, ".go": {},
	".java": {}, ".rb": {}, ".php": {}, ".env": {}, ".cfg": {}, ".ini": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".json": {}, ".xml": {},
	".tf": {}, ".hcl": {}, ".sh": {}, ".bash": {}, ".zsh": {},
	".conf": {}, ".config": {},
}

// pattern represents one detection rule. Regex is the body of the
// Python pattern with any (?<!...) / (?!...) stripped; leftBoundary
// and rightBoundary (when non-nil) match a single character that, if
// present immediately before or after the match, REJECTS the match.
//
// Severity values are pinned to the Python equivalents.
type pattern struct {
	id            string
	title         string
	regex         *regexp.Regexp
	severity      models.Severity
	cwe           string
	leftBoundary  *regexp.Regexp
	rightBoundary *regexp.Regexp
}

// boundaryAlnum matches a single [A-Za-z0-9] byte. Used as the default
// reject-on-touch set for most provider-token patterns.
var boundaryAlnum = regexp.MustCompile(`^[A-Za-z0-9]$`)

// boundaryUpperDigit matches [A-Z0-9] — used by AWS_ACCESS_KEY which
// in Python anchored on the uppercase alphanumeric set specifically.
var boundaryUpperDigit = regexp.MustCompile(`^[A-Z0-9]$`)

// boundaryAlnumDash matches [A-Za-z0-9-] — used by SLACK_TOKEN's right
// boundary (Python: (?![A-Za-z0-9-])) so a trailing hyphen also blocks.
var boundaryAlnumDash = regexp.MustCompile(`^[A-Za-z0-9-]$`)

// boundaryAlnumUnderDash matches [A-Za-z0-9_-] — GOOGLE_API_KEY right
// boundary and ANTHROPIC_API_KEY both sides.
var boundaryAlnumUnderDash = regexp.MustCompile(`^[A-Za-z0-9_-]$`)

// patterns is the registry in Python's order. Order matters for tests
// that index findings, but not for correctness — every match is
// reported with its own SEC-* id.
var patterns = []pattern{
	{
		id:            "AWS_ACCESS_KEY",
		title:         "AWS Access Key ID hardcoded",
		regex:         regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryUpperDigit,
		rightBoundary: boundaryUpperDigit,
	},
	{
		// Recognises both the canonical `aws_secret_access_key = "..."`
		// and the shorter `aws_secret = "..."` / `aws_secret_key = "..."`
		// variants. The 40-char value shape is what AWS issues — we
		// require it to limit FP risk on arbitrary base64 strings.
		// Track 4 heavy-eval surfaced the short-prefix variant as a
		// real-world miss on customer codebases.
		id:       "AWS_SECRET_KEY",
		title:    "AWS Secret Access Key hardcoded",
		regex:    regexp.MustCompile(`(?i)aws[_\-\s]*secret(?:[_\-\s]*(?:access[_\-\s]*)?key)?["\s]*[=:]["\s]*([A-Za-z0-9/+=]{40})`),
		severity: models.SeverityCritical,
		cwe:      "CWE-798",
	},
	{
		id:       "PRIVATE_KEY",
		title:    "Private key material hardcoded",
		regex:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		severity: models.SeverityCritical,
		cwe:      "CWE-321",
	},
	{
		id:       "GENERIC_API_KEY",
		title:    "Hardcoded API key or token",
		regex:    regexp.MustCompile(`(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|auth[_\-]?token|client[_\-]?secret)\s*[=:]\s*["']([A-Za-z0-9\-_.+/]{20,})["']`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:       "HARDCODED_PASSWORD",
		title:    "Hardcoded password in source code",
		regex:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']`),
		severity: models.SeverityHigh,
		cwe:      "CWE-259",
	},
	{
		// Catches compound-suffix assignments through subscript or
		// attribute targets that the bare HARDCODED_PASSWORD regex
		// misses. Real-world examples (vflask, default Flask configs):
		//   app.config['SECRET_KEY_HMAC'] = 'secret'
		//   app.config["JWT_SECRET_KEY"] = "rotate-me"
		//   app.secret_key = 'F12Zr47j...'
		//   APP_SECRET = "..."
		// The keyword family is intentionally narrower than ENV_SECRET's
		// shotgun list — we anchor on tokens that strongly imply a
		// credential (secret_key, jwt_secret, hmac_key, app_secret, etc.)
		// to keep false-positive rate on non-credential variables low.
		// Minimum value length 4 to catch short placeholder secrets like
		// 'secret' / 'admin' / 'test' that the API-key regex's 20-char
		// floor rejects.
		id:    "HARDCODED_SECRET_CONFIG",
		title: "Hardcoded secret value in config-style assignment",
		regex: regexp.MustCompile(
			`(?i)(?:^|[.\[ \t])["']?(secret_key|api_secret|app_secret|jwt_secret|hmac_key|encryption_key|signing_key|csrf_secret|session_secret|cookie_secret)(?:[_\-]\w+)*["']?\s*\]?\s*[=:]\s*["']([^"'\n]{4,})["']`,
		),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:       "JWT_TOKEN",
		title:    "Hardcoded JWT token",
		regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:       "DB_CONNECTION_STRING",
		title:    "Database connection string with credentials",
		regex:    regexp.MustCompile(`(?i)(?:mongodb|postgresql|postgres|mysql|mssql|redis|sqlite)://[^:@\s]+:[^@\s]+@[^\s"']+`),
		severity: models.SeverityHigh,
		cwe:      "CWE-214",
	},
	{
		id:    "GITHUB_TOKEN",
		title: "GitHub token hardcoded",
		// Personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
		// server-to-server (ghs_), refresh (ghr_).
		regex:         regexp.MustCompile(`gh[opusr]_[A-Za-z0-9]{36}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:            "STRIPE_LIVE_KEY",
		title:         "Stripe live secret key hardcoded",
		regex:         regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:    "SLACK_TOKEN",
		title: "Slack token hardcoded",
		// xoxa-/xoxb-/xoxp-/xoxr-/xoxs-.
		regex:         regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnumDash,
	},
	{
		id:            "GOOGLE_API_KEY",
		title:         "Google API key hardcoded",
		regex:         regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnumUnderDash,
	},
	{
		id:            "ANTHROPIC_API_KEY",
		title:         "Anthropic API key hardcoded",
		regex:         regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnumUnderDash,
		rightBoundary: boundaryAlnumUnderDash,
	},
	{
		id:    "OPENAI_API_KEY",
		title: "OpenAI API key hardcoded",
		// Legacy sk-<48 alnum>; project sk-proj-<...>; service-account sk-svcacct-<...>.
		// The body forbids `-` so the regex naturally cannot match
		// across the `sk-ant-` Anthropic prefix.
		regex:         regexp.MustCompile(`sk-(?:proj-|svcacct-)?[A-Za-z0-9]{32,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:            "NPM_TOKEN",
		title:         "npm registry token hardcoded",
		regex:         regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:    "GCP_SERVICE_ACCOUNT",
		title: "GCP service-account JSON key hardcoded",
		// Canonical signature line in Google's downloaded SA JSON files.
		regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		severity: models.SeverityCritical,
		cwe:      "CWE-798",
	},
}

// envPatterns mirrors python _ENV_PATTERNS. Applied only to files where
// isEnvFile returns true — the unquoted KEY=value shape would produce
// false positives in regular source.
var envPatterns = []pattern{
	{
		id:    "ENV_SECRET",
		title: "Hardcoded credential in .env file",
		// KEY ends with a credential-y suffix; value is unquoted, ≥4
		// chars, not starting with whitespace/quote/#. The Python
		// regex is multiline-anchored via ^...$; in Go the (?m) flag
		// has the same effect, but we apply per-line so plain
		// anchors are fine.
		regex:    regexp.MustCompile(`^([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)S?(?:_[A-Z0-9_]+)?)\s*=\s*([^\s"'#][^\n#]{3,})\s*$`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
}

// Scan walks codePath, scans every eligible text file line-by-line for
// the secret patterns, and returns the resulting Findings. Behaviour
// matches python/analyzers/secrets.py except for cross-file ordering
// (Go walks in lexical order; the orchestrator's stable sort at step 6
// normalises this before ID assignment so the difference is invisible
// to downstream consumers).
//
// codePath must point at an existing directory; otherwise returns
// ErrCodePathMissing so the caller can silently skip. Walk errors on
// individual files are non-fatal — the file is skipped and the walk
// continues, matching the os.walk + try/except OSError pattern in Python.
//
// The context is checked between files; cancellation aborts the walk
// with ctx.Err().
func Scan(ctx context.Context, codePath string) ([]models.Finding, error) {
	return ScanWithAllowlist(ctx, codePath, nil)
}

// ScanWithAllowlist is Scan scoped to a diff-aware file allowlist. A nil
// allowlist scans every eligible file (full-scan parity with Scan). When
// set, only files whose absolute path is in the allowlist are read — the
// secrets half of `fendix scan --diff`. The directory walk and skip-dir
// pruning are unchanged; non-allowlisted files are skipped before scanFile
// opens them.
func ScanWithAllowlist(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]models.Finding, error) {
	if codePath == "" {
		return nil, ErrCodePathMissing
	}
	info, err := os.Stat(codePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCodePathMissing
		}
		return nil, fmt.Errorf("secrets: stat %q: %w", codePath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets: %q is not a directory", codePath)
	}

	absRoot, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("secrets: resolve %q: %w", codePath, err)
	}

	var findings []models.Finding

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErrIn error) error {
		if walkErrIn != nil {
			// Permissions errors / vanished files — skip but keep walking.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path == absRoot {
				return nil
			}
			if _, skip := skipDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}

		// Diff-aware scoping: skip files outside the allowlist before any
		// read. A nil allowlist allows everything (full-scan default).
		if !allow.Allows(path) {
			return nil
		}

		fileFindings, err := scanFile(path, absRoot, d)
		if err != nil {
			// Per-file errors are non-fatal (matches Python's
			// try/except OSError: return).
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if walkErr != nil {
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			return findings, walkErr
		}
		return findings, fmt.Errorf("secrets: walk %q: %w", absRoot, walkErr)
	}
	return findings, nil
}

// scanFile reads one file, applies the pattern registry, and returns
// any findings it produces. The file is silently skipped if it isn't
// readable, exceeds maxFileBytes, or has an extension that's not in
// scanExtensions (unless it's a .env-style file).
func scanFile(path, root string, d fs.DirEntry) ([]models.Finding, error) {
	name := d.Name()
	envFile := isEnvFile(name)
	if !envFile {
		ext := strings.ToLower(filepath.Ext(name))
		if _, ok := scanExtensions[ext]; !ok {
			return nil, nil
		}
	}

	info, err := d.Info()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileBytes {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)

	active := patterns
	if envFile {
		active = make([]pattern, 0, len(patterns)+len(envPatterns))
		active = append(active, patterns...)
		active = append(active, envPatterns...)
	}

	var out []models.Finding
	isJSOrTS := strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts")
	text := string(data)
	lineno := 0
	for _, line := range splitLines(text) {
		lineno++
		if isJSOrTS && len(line) > minifiedLineLen {
			continue
		}
		for i := range active {
			pat := &active[i]
			locs := pat.regex.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				if !boundaryOK(line, loc[0], loc[1], pat.leftBoundary, pat.rightBoundary) {
					continue
				}
				secret := line[loc[0]:loc[1]]
				safeEvidence := truncateEvidence(strings.ReplaceAll(line, secret, truncateSecret(secret)), loc[0])
				lineRef := fmt.Sprintf("%s:%d", rel, lineno)
				lineCopy := lineRef
				out = append(out, models.Finding{
					ID:         "SEC-" + pat.id,
					Title:      pat.title,
					Severity:   pat.severity,
					Source:     models.SourceWhitebox,
					Category:   "secrets",
					Endpoint:   lineRef,
					Evidence:   safeEvidence,
					Fix:        fixText,
					References: []string{pat.cwe},
					Confidence: models.ConfidenceHigh,
					Line:       &lineCopy,
				})
			}
		}
	}
	return out, nil
}

// splitLines splits text on \n and \r\n line endings without including
// the terminator in each line. Mirrors python str.splitlines() closely
// enough for this scanner's purposes (we don't care about exotic
// terminators like U+2028 — secrets in those would also be exotic).
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	// Normalise \r\n → \n, then split on \n. Drop trailing empty if
	// the file ends in a newline so line numbers match Python's
	// splitlines (which also drops trailing empty).
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// boundaryOK returns false when the character immediately before
// (start-1) or after (end) the match satisfies the corresponding
// boundary regex — i.e. the lookaround would have rejected this match
// in the Python original. nil predicates short-circuit to true.
func boundaryOK(line string, start, end int, leftRE, rightRE *regexp.Regexp) bool {
	if leftRE != nil && start > 0 {
		if leftRE.MatchString(line[start-1 : start]) {
			return false
		}
	}
	if rightRE != nil && end < len(line) {
		if rightRE.MatchString(line[end : end+1]) {
			return false
		}
	}
	return true
}

// truncateSecret returns a redacted form of match for inclusion in
// evidence: first secretShowLen chars + "..." for long values; "<4
// chars>..." for shorter; "***" for very short values. Mirrors Python
// _truncate_secret.
func truncateSecret(match string) string {
	if len(match) <= secretShowLen {
		if len(match) > 4 {
			return match[:4] + "..."
		}
		return "***"
	}
	return match[:secretShowLen] + "..."
}

// truncateEvidence returns a context window around matchStart, capped
// at evidenceMaxLen chars. Mirrors Python _truncate_evidence: 20 chars
// of context on the left, the rest of the window on the right.
func truncateEvidence(line string, matchStart int) string {
	start := matchStart - 20
	if start < 0 {
		start = 0
	}
	end := start + evidenceMaxLen
	if end > len(line) {
		end = len(line)
	}
	snippet := strings.TrimRight(line[start:end], " \t\r\n")
	if len(line)-start > evidenceMaxLen {
		return snippet + "..."
	}
	return snippet
}

// isEnvFile mirrors python _is_env_file: .env exactly, anything
// beginning with .env., or any file whose extension is .env.
func isEnvFile(name string) bool {
	if name == ".env" {
		return true
	}
	if strings.HasPrefix(name, ".env.") {
		return true
	}
	if filepath.Ext(name) == ".env" {
		return true
	}
	return false
}
