//go:build e2e

// Package e2e contains end-to-end tests that exercise the built fendix
// binary against externally-observable effects (files written, exit codes,
// report contents). Run with:
//
//	make e2e
//	# or
//	go test -tags e2e ./internal/e2e/...
//
// These tests catch CLI-wiring bugs that pass unit tests — for example,
// a flag that's declared in cobra but never read into ScanConfig
// (the bug behind TASK-079). Every CLI flag should have a matching
// e2e test here.
package e2e

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// repoRoot returns the repository root by walking up from this test file.
// e2e_test.go lives at <repo>/go/internal/e2e/, so root is three levels up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// buildOnce builds the fendix binary once per test process. The first test
// to call it triggers `make build`, subsequent calls return the cached path.
// Builds via `make build` to ensure the embedded Python engine is bundled —
// raw `go build` would skip embed-engine and the white-box path would fail.
var (
	buildOnceMu  sync.Mutex
	buildOnceErr error
	buildPath    string
)

func fendixBinary(t *testing.T) string {
	t.Helper()
	buildOnceMu.Lock()
	defer buildOnceMu.Unlock()
	if buildPath != "" || buildOnceErr != nil {
		if buildOnceErr != nil {
			t.Fatalf("fendix binary build failed: %v", buildOnceErr)
		}
		return buildPath
	}
	root := repoRoot(t)
	cmd := exec.Command("make", "build")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		buildOnceErr = err
		t.Fatalf("make build failed: %v\n%s", err, out)
	}
	buildPath = filepath.Join(root, "bin", "fendix")
	return buildPath
}

// mockTarget returns an httptest server with one weak-headers endpoint.
// Sufficient to produce non-zero findings so save-baseline has something to
// write — we want to verify the file is created, not validate its contents
// in detail (other tests cover JSON schema).
func mockTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestActiveProbe_UsesSpecParam is the regression test for TASK-081.
// Pre-fix, the active scanner ignored OpenAPI `parameters` arrays and always
// probed the hardcoded `id` query param. Here we record every incoming request
// to a mock target, declare a single endpoint with one query param `host`,
// and assert at least one probe arrived with `?host=` set — proving spec
// params now flow into Endpoint.Params and out to injection.go.
func TestActiveProbe_UsesSpecParam(t *testing.T) {
	bin := fendixBinary(t)

	var (
		mu          sync.Mutex
		hostProbes  int
		idProbes    int
		totalProbes int
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		totalProbes++
		q := r.URL.Query()
		if q.Get("host") != "" {
			hostProbes++
		}
		if q.Get("id") != "" {
			idProbes++
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	specBody := `openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: ` + target.URL + `
paths:
  /api/ping:
    get:
      parameters:
        - name: host
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--spec", specPath,
		"--enable-active",
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--output", filepath.Join(dir, "report.json"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if totalProbes == 0 {
		t.Fatalf("no requests reached the target — scan never ran active probes\noutput:\n%s", out)
	}
	if hostProbes == 0 {
		t.Fatalf("active scanner never probed the spec-declared 'host' query param "+
			"(TASK-081 regressed). hostProbes=%d idProbes=%d total=%d\noutput:\n%s",
			hostProbes, idProbes, totalProbes, out)
	}
}

// TestCodeOnlyScan_ProducesFindings is the regression test for TASK-080.
// Before the fix, the orchestrator early-exited on "no endpoints discovered"
// before reaching the white-box branch — so `fendix scan --code ./repo` always
// failed with exit 2, even though the CLI accepted the flag combination.
// We assert the scan completes (exit 0 or 1) and the report contains at least
// one secret finding from the embedded fixture.
func TestCodeOnlyScan_ProducesFindings(t *testing.T) {
	bin := fendixBinary(t)

	// Self-contained fixture: one file with an obviously-fake AWS key matching
	// the AKIA[0-9A-Z]{16} pattern in python/analyzers/secrets.py. Using the
	// well-known AWS-doc example keeps this readable and avoids triggering
	// any real-secret scanners on this repo.
	codeDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(codeDir, "config.py"),
		[]byte(`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--code", codeDir,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
	)
	out, err := cmd.CombinedOutput()
	// Exit 0 (no findings above --fail-on threshold) or 1 (findings) both fine.
	// Exit 2 = the bug we're guarding against.
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() == 2 {
			t.Fatalf("code-only scan returned exit 2 (TASK-080 regressed) or unexpected error: %v\noutput:\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}
	if !contains(string(report), "AKIA") && !contains(string(report), "AWS Access Key") {
		t.Fatalf("expected report to contain AWS-key finding, got:\n%s\n\nfendix output:\n%s", report, out)
	}
}

// TestSpecURL_FetchedAndParsed is the regression test for TASK-082.
// Before the fix, --spec http://host/openapi.json was passed to os.ReadFile
// which silently failed; the crawler then fell back to brute-force discovery,
// effectively ignoring the user's spec. We assert the spec path actually wins
// by serving a spec with one declared endpoint and asserting the scanner logs
// "endpoints from spec count=1" — anything else means the URL wasn't honored.
func TestSpecURL_FetchedAndParsed(t *testing.T) {
	bin := fendixBinary(t)

	specSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "openapi": "3.0.0",
		  "info": {"title":"e2e","version":"1"},
		  "servers": [{"url": "` + r.Host + `/api"}],
		  "paths": {"/widgets": {"get": {"summary":"x"}}}
		}`))
	}))
	t.Cleanup(specSrv.Close)
	apiSrv := mockTarget(t)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", apiSrv.URL,
		"--spec", specSrv.URL+"/openapi.json",
		"--output", outputPath,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
	)
	out, err := cmd.CombinedOutput()
	// Accept exit 0 or 1 (findings vs. no findings); reject 2 (config/network error).
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	// Confirm the URL path was taken (not silent fallback to brute-force).
	if !contains(string(out), "endpoints from spec") {
		t.Fatalf("expected 'endpoints from spec' in stderr — URL spec was not parsed.\noutput:\n%s", out)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestSaveBaseline_WritesFile is the regression test for TASK-079.
// Before the fix, --save-baseline was declared in cobra but never read into
// ScanConfig, so the orchestrator's SaveBaseline path was unreachable. The
// existing unit test at baseline_test.go:156 called SaveBaseline() directly
// and passed — it didn't catch the missing CLI wiring. This test runs the
// actual binary and asserts the file appears on disk.
func TestSaveBaseline_WritesFile(t *testing.T) {
	bin := fendixBinary(t)
	srv := mockTarget(t)

	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--save-baseline", baselinePath,
		"--output", outputPath,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
	)
	out, err := cmd.CombinedOutput()
	// Exit code 1 is acceptable: --fail-on default may trigger when findings
	// exist on the mock target. We only care that the file was written.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed unexpectedly: %v\n%s", err, out)
		}
	}

	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline file not written at %s: %v\nfendix output:\n%s",
			baselinePath, err, out)
	}

	info, err := os.Stat(baselinePath)
	if err == nil && info.Size() == 0 {
		t.Fatalf("baseline file is empty at %s\nfendix output:\n%s", baselinePath, out)
	}
}
