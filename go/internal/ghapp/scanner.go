package ghapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

	dir, err := os.MkdirTemp(parent, "fendix-scan-")
	if err != nil {
		return nil, fmt.Errorf("scan: mkdir temp: %w", err)
	}
	defer os.RemoveAll(dir)

	authedURL, err := injectInstallationToken(req.CloneURL, req.InstallationToken)
	if err != nil {
		return nil, fmt.Errorf("scan: clone URL: %w", err)
	}

	steps := [][]string{
		{gitBin, "init", "--quiet", dir},
		{gitBin, "-C", dir, "remote", "add", "origin", authedURL},
		{gitBin, "-C", dir, "-c", "protocol.version=2",
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
	scanCmd := exec.CommandContext(ctx, fendixBin,
		"scan",
		"--code", dir,
		"--format", "json",
		"--output", findingsPath,
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
	if out, err := reportCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("scan: fendix report (sarif) failed: %w (output: %s)", err, truncate(out, 1024))
	}

	sarif, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("scan: read sarif: %w", err)
	}

	return &ScanResult{FindingsJSON: findingsJSON, SARIF: sarif}, nil
}

// injectInstallationToken rewrites an HTTPS clone URL to embed the
// installation token as the userinfo. GitHub installation tokens
// authenticate as the username "x-access-token" with the token as
// the password (per GitHub's documented App-to-Git auth flow).
func injectInstallationToken(cloneURL, token string) (string, error) {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("only https clone URLs are supported, got %q", u.Scheme)
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String(), nil
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
