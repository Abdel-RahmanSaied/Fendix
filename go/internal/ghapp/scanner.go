package ghapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ScanRequest is the input to a scan run for a PR head.
type ScanRequest struct {
	// CloneURL is the repository's HTTPS clone URL from the webhook
	// payload, e.g. "https://github.com/owner/repo.git".
	CloneURL string
	// HeadSHA is the commit SHA at the head of the PR. The scan
	// runs against this exact commit.
	HeadSHA string
	// InstallationToken is a short-lived GitHub installation token
	// from TokenSource. Used as the username in the clone URL
	// ("https://x-access-token:<token>@…") so we can fetch private
	// repositories the App is installed in.
	InstallationToken string
}

// ScanResult holds both report formats produced by a scan: the JSON
// findings (consumed by the PR-comment renderer) and the SARIF blob
// (consumed by the Code Scanning uploader). Re-rendering SARIF from
// the same JSON guarantees both surfaces describe the same findings.
type ScanResult struct {
	FindingsJSON []byte
	SARIF        []byte
}

// Scanner runs a fendix scan against a PR head SHA. The interface
// exists so handler tests can inject fakes; production code uses
// FendixScanner.
type Scanner interface {
	Run(ctx context.Context, req ScanRequest) (*ScanResult, error)
}

// FendixScanner is the production Scanner. It shells out to git +
// fendix on PATH (configurable via the binary fields). The choice of
// shelling out vs importing the scanner package directly keeps the
// fendix-app binary independent of the scanner's dependency graph
// and makes upgrades trivial — operators bump the fendix binary in
// the image without rebuilding fendix-app.
type FendixScanner struct {
	// FendixBinary is the path to the `fendix` executable. Default:
	// "fendix" (resolved on PATH).
	FendixBinary string
	// GitBinary is the path to the `git` executable. Default: "git".
	GitBinary string
	// WorkDir is the parent directory for per-scan temp dirs.
	// Default: os.TempDir().
	WorkDir string
	// Sandbox isolates the `fendix scan` of untrusted fork-PR code.
	// Default: NewSandbox (best-effort on most hosts, network +
	// privilege drop on Linux when available). The token is always
	// dropped from the scan child's env regardless of the Sandbox.
	Sandbox Sandbox
	// Logger receives sandbox/scan diagnostics. Default: slog.Default().
	Logger *slog.Logger
}

// Run clones the repo at HeadSHA into a temp directory, runs `fendix
// scan --code <tmp> --format json`, then re-renders SARIF from the
// JSON. The temp dir is removed on return regardless of outcome.
//
// Clone strategy: init + remote + shallow fetch of the exact SHA.
// GitHub supports SHA-targeted fetch (uploadpack.allowReachableSHA1
// InWant), so we never download history we don't need.
func (s *FendixScanner) Run(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if req.CloneURL == "" {
		return nil, errors.New("scan: clone URL required")
	}
	if req.HeadSHA == "" {
		return nil, errors.New("scan: head SHA required")
	}
	if req.InstallationToken == "" {
		return nil, errors.New("scan: installation token required")
	}

	gitBin := s.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	fendixBin := s.FendixBinary
	if fendixBin == "" {
		fendixBin = "fendix"
	}
	parent := s.WorkDir
	if parent == "" {
		parent = os.TempDir()
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sandbox := s.Sandbox
	if sandbox == nil {
		sandbox = NewSandbox(logger)
	}

	dir, err := os.MkdirTemp(parent, "fendix-scan-")
	if err != nil {
		return nil, fmt.Errorf("scan: mkdir temp: %w", err)
	}
	defer os.RemoveAll(dir)

	// F-H3: the remote is added WITHOUT credentials so the token never
	// lands in .git/config or in a long-lived remote URL. The token is
	// supplied per-invocation via the http.extraheader config (an
	// Authorization: Basic header), passed with `git -c` so it lives
	// only in that single process's argv and is never persisted.
	if err := validateHTTPSCloneURL(req.CloneURL); err != nil {
		return nil, fmt.Errorf("scan: clone URL: %w", err)
	}
	authHeaderArg := "http.extraheader=Authorization: Basic " + basicAuthToken(req.InstallationToken)

	steps := [][]string{
		{gitBin, "init", "--quiet", dir},
		{gitBin, "-C", dir, "remote", "add", "origin", req.CloneURL},
		{gitBin, "-C", dir, "-c", authHeaderArg, "-c", "protocol.version=2",
			"fetch", "--quiet", "--depth=1", "origin", req.HeadSHA},
		{gitBin, "-C", dir, "checkout", "--quiet", "FETCH_HEAD"},
	}
	for _, step := range steps {
		if err := runCommand(ctx, step[0], step[1:]); err != nil {
			return nil, fmt.Errorf("scan: %s: %w", redactToken(strings.Join(step, " "), req.InstallationToken), err)
		}
	}

	findingsPath := filepath.Join(dir, "fendix-findings.json")
	sarifPath := filepath.Join(dir, "fendix-results.sarif")

	// Run the scan. We deliberately don't pass --fail-on; the App
	// surfaces severity in the PR comment, gating is the consumer's
	// call (e.g. via branch protection requiring the SARIF results
	// to be clean). A non-zero exit here is a real scan failure.
	//
	// F-M5: the scan executes untrusted fork-PR code. We hand it to the
	// Sandbox with a token-dropped environment (the clone+fetch above
	// already retrieved the code, so the token is no longer needed) and,
	// where the host supports it, network + privilege isolation. We log
	// which isolation was actually applied so the choice is observable.
	scanEnv := scrubTokenFromEnv(os.Environ(), req.InstallationToken)
	logger.Info("running fendix scan in sandbox",
		"isolation", sandbox.Isolation(),
		"head_sha", req.HeadSHA,
	)
	scanCmd := sandbox.Command(ctx, logger, fendixBin,
		[]string{
			"scan",
			"--code", dir,
			"--format", "json",
			"--output", findingsPath,
		},
		scanEnv,
	)
	if out, err := scanCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("scan: fendix scan failed: %w (output: %s)", err, truncate(out, 1024))
	}

	findingsJSON, err := os.ReadFile(findingsPath)
	if err != nil {
		return nil, fmt.Errorf("scan: read findings: %w", err)
	}

	// Re-render the same JSON as SARIF — the github-script template
	// in examples/github-actions/fendix-scan.yml uses this same
	// pattern (single scan + re-render) so PR comment + SARIF tab
	// describe identical findings.
	reportCmd := exec.CommandContext(ctx, fendixBin,
		"report",
		"--input", findingsPath,
		"--format", "sarif",
		"--output", sarifPath,
	)
	reportCmd.Env = scanEnv
	if out, err := reportCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("scan: fendix report (sarif) failed: %w (output: %s)", err, truncate(out, 1024))
	}

	sarif, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("scan: read sarif: %w", err)
	}

	return &ScanResult{FindingsJSON: findingsJSON, SARIF: sarif}, nil
}

// validateHTTPSCloneURL rejects non-HTTPS clone URLs. We only fetch
// over HTTPS so the installation-token Authorization header is sent
// over TLS; an http:// or ssh:// remote would either leak the header
// in cleartext or not use it at all.
func validateHTTPSCloneURL(cloneURL string) error {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https clone URLs are supported, got %q", u.Scheme)
	}
	return nil
}

// basicAuthToken encodes the installation token as the password half of
// an HTTP Basic credential. GitHub installation tokens authenticate as
// the username "x-access-token" with the token as the password (per
// GitHub's documented App-to-Git auth flow); the result is base64 of
// "x-access-token:<token>". This value is passed per-invocation via
// `git -c http.extraheader=Authorization: Basic <this>` so it is never
// persisted to .git/config or embedded in a remote URL.
func basicAuthToken(token string) string {
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
}

// scrubTokenFromEnv returns a copy of env with any entry whose value
// contains the installation token removed. The clone+fetch above has
// already retrieved the code, so the scan (and report) subprocesses —
// which may execute untrusted fork-PR code — must not be able to read
// the token from their environment. We match on value rather than a
// fixed key name so a token that leaked into any inherited variable is
// still dropped.
func scrubTokenFromEnv(env []string, token string) []string {
	if token == "" {
		return env
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		// Split on the first '=' to inspect the value half; an entry
		// like "FOO=...token..." is dropped, but the comparison never
		// trips on a variable literally named after the token.
		if i := strings.IndexByte(e, '='); i >= 0 {
			if strings.Contains(e[i+1:], token) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func runCommand(ctx context.Context, name string, args []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, truncate(stderr.Bytes(), 512))
	}
	return nil
}

func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "[REDACTED]")
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
