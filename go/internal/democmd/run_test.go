package democmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDocker records every Run/Output call and lets a test program
// assertions about argument shape, plus inject errors. Mirrors the
// realDocker shape so production paths exercise the exact dispatch.
type fakeDocker struct {
	mu     sync.Mutex
	calls  [][]string
	failOn map[string]error // first arg → error to return
	stdout map[string]string
}

func (f *fakeDocker) record(args []string) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{}, args...))
	f.mu.Unlock()
}

func (f *fakeDocker) Run(_ context.Context, args ...string) error {
	f.record(args)
	if len(args) > 0 && f.failOn != nil {
		if err, ok := f.failOn[args[0]]; ok {
			return err
		}
	}
	return nil
}

func (f *fakeDocker) Output(_ context.Context, args ...string) (string, error) {
	f.record(args)
	if len(args) > 0 && f.stdout != nil {
		if s, ok := f.stdout[args[0]]; ok {
			return s, nil
		}
	}
	return "", nil
}

func (f *fakeDocker) callArgs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]string{}, c...)
	}
	return out
}

// startFakeJuiceShop starts an httptest.Server that responds 200 OK on
// /rest/admin/application-version after `becomesHealthyAfter` polls.
// Returns the server's port (extracted from the listen URL) so tests
// can pass it to Run via Options.Port.
func startFakeJuiceShop(t *testing.T, becomesHealthyAfter int32) (port int, hits *atomic.Int32, srv *httptest.Server) {
	t.Helper()
	hits = new(atomic.Int32)
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/admin/application-version", func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n <= becomesHealthyAfter {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"version":"v17.1.1"}`)
	})
	// Use httptest.NewServer (random port) — production hits a fixed
	// port, but waitForJuiceShop only knows about the port we feed it
	// via Options.Port, so a random port is fine in tests.
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return p, hits, srv
}

// fakeFendixBinary writes a tiny POSIX shell script that mimics
// `fendix scan --url X --format html --output Y`: it scans args for
// --output and writes a stub HTML there. Returns the absolute path so
// tests can pass it via Options.FendixBin.
func fakeFendixBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-fendix")
	const script = `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    out="$1"
  fi
  shift
done
if [ -n "$out" ]; then
  echo "<html><body>fake fendix scan</body></html>" > "$out"
fi
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake fendix: %v", err)
	}
	return path
}

func TestWaitForJuiceShop_Success(t *testing.T) {
	port, _, _ := startFakeJuiceShop(t, 0)
	if err := waitForJuiceShop(context.Background(), port, 3*time.Second, 50*time.Millisecond); err != nil {
		t.Fatalf("waitForJuiceShop: %v", err)
	}
}

func TestWaitForJuiceShop_BecomesHealthyAfterDelay(t *testing.T) {
	// First 3 polls return 503; 4th returns 200. Should still succeed
	// well within the timeout.
	port, hits, _ := startFakeJuiceShop(t, 3)
	if err := waitForJuiceShop(context.Background(), port, 3*time.Second, 50*time.Millisecond); err != nil {
		t.Fatalf("waitForJuiceShop: %v", err)
	}
	if got := hits.Load(); got < 4 {
		t.Errorf("expected ≥4 polls before healthy, got %d", got)
	}
}

func TestWaitForJuiceShop_Timeout(t *testing.T) {
	// Server always returns 503 → wait should hit deadline.
	port, _, _ := startFakeJuiceShop(t, 1<<30)
	err := waitForJuiceShop(context.Background(), port, 200*time.Millisecond, 50*time.Millisecond)
	if !errors.Is(err, ErrJuiceShopNotReady) {
		t.Fatalf("expected ErrJuiceShopNotReady, got %v", err)
	}
}

func TestWaitForJuiceShop_ContextCancel(t *testing.T) {
	port, _, _ := startFakeJuiceShop(t, 1<<30)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	err := waitForJuiceShop(ctx, port, 5*time.Second, 50*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRun_HappyPath(t *testing.T) {
	// docker is faked (calls succeed and are recorded). Juice-shop is
	// faked via httptest. fendix binary is faked via a shell script
	// that writes the --output path. End-to-end success path.
	port, _, _ := startFakeJuiceShop(t, 0)
	docker := &fakeDocker{}
	fakeBin := fakeFendixBinary(t)
	out := filepath.Join(t.TempDir(), "demo.html")

	var stdout, stderr bytes.Buffer
	report, err := Run(context.Background(), Options{
		Port:           port,
		FendixBin:      fakeBin,
		OutputPath:     out,
		HealthTimeout:  3 * time.Second,
		HealthInterval: 50 * time.Millisecond,
		Stdout:         &stdout,
		Stderr:         &stderr,
		docker:         docker,
	})
	if err != nil {
		t.Fatalf("Run: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if report != out {
		t.Errorf("report path mismatch: got %q want %q", report, out)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected report file at %s, got %v", out, err)
	}
	// docker should have been called for: pre-cleanup rm, run, defer
	// cleanup rm. That's 3 calls minimum.
	calls := docker.callArgs()
	if len(calls) < 3 {
		t.Fatalf("expected ≥3 docker calls (rm, run, rm), got %d: %v", len(calls), calls)
	}
	// First call: rm -f
	if calls[0][0] != "rm" || calls[0][1] != "-f" {
		t.Errorf("first call should be `rm -f`, got %v", calls[0])
	}
	// Second call: run with image and port mapping
	runCall := calls[1]
	if runCall[0] != "run" {
		t.Errorf("second call should be `run`, got %v", runCall)
	}
	if !containsArg(runCall, fmt.Sprintf("%d:3000", port)) {
		t.Errorf("expected port mapping %d:3000 in run args, got %v", port, runCall)
	}
	if !containsArg(runCall, DefaultImageRef) {
		t.Errorf("expected default image %s in run args, got %v", DefaultImageRef, runCall)
	}
	// Cleanup rm should be the last call.
	last := calls[len(calls)-1]
	if last[0] != "rm" {
		t.Errorf("last call should be cleanup rm, got %v", last)
	}
}

func TestRun_DockerRunFails(t *testing.T) {
	// docker run errors → Run returns wrapped error and still tries
	// cleanup.
	port, _, _ := startFakeJuiceShop(t, 0)
	docker := &fakeDocker{
		failOn: map[string]error{"run": errors.New("image pull failed")},
	}
	fakeBin := fakeFendixBinary(t)
	_, err := Run(context.Background(), Options{
		Port:           port,
		FendixBin:      fakeBin,
		OutputPath:     filepath.Join(t.TempDir(), "demo.html"),
		HealthTimeout:  500 * time.Millisecond,
		HealthInterval: 50 * time.Millisecond,
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		docker:         docker,
	})
	if err == nil {
		t.Fatalf("expected error when docker run fails, got nil")
	}
	if !strings.Contains(err.Error(), "image pull failed") {
		t.Errorf("expected wrapped error to contain root cause, got %v", err)
	}
}

func TestRun_HealthCheckFailsTriggersCleanup(t *testing.T) {
	// juice-shop never becomes healthy → Run returns ErrJuiceShopNotReady
	// AND cleanup rm is invoked (defer).
	port, _, _ := startFakeJuiceShop(t, 1<<30) // never healthy
	docker := &fakeDocker{}
	fakeBin := fakeFendixBinary(t)
	_, err := Run(context.Background(), Options{
		Port:           port,
		FendixBin:      fakeBin,
		OutputPath:     filepath.Join(t.TempDir(), "demo.html"),
		HealthTimeout:  150 * time.Millisecond,
		HealthInterval: 50 * time.Millisecond,
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		docker:         docker,
	})
	if !errors.Is(err, ErrJuiceShopNotReady) {
		t.Fatalf("expected ErrJuiceShopNotReady, got %v", err)
	}
	// Verify the deferred cleanup ran by counting `rm` calls — we
	// expect at least 2: pre-cleanup and post-failure cleanup.
	rmCount := 0
	for _, c := range docker.callArgs() {
		if len(c) > 0 && c[0] == "rm" {
			rmCount++
		}
	}
	if rmCount < 2 {
		t.Errorf("expected ≥2 rm calls (pre + cleanup), got %d", rmCount)
	}
}

func TestRun_FendixBinaryMissing(t *testing.T) {
	// Pointing FendixBin at a nonexistent path → scan should fail
	// (exec returns "no such file") and Run wraps it as ErrScanFailed.
	port, _, _ := startFakeJuiceShop(t, 0)
	docker := &fakeDocker{}
	_, err := Run(context.Background(), Options{
		Port:           port,
		FendixBin:      "/no/such/binary",
		OutputPath:     filepath.Join(t.TempDir(), "demo.html"),
		HealthTimeout:  3 * time.Second,
		HealthInterval: 50 * time.Millisecond,
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		docker:         docker,
	})
	if !errors.Is(err, ErrScanFailed) {
		t.Fatalf("expected ErrScanFailed when fendix bin missing, got %v", err)
	}
}

func TestResolve_Defaults(t *testing.T) {
	o := (Options{}).resolve()
	if o.ImageRef != DefaultImageRef {
		t.Errorf("ImageRef default mismatch: %q", o.ImageRef)
	}
	if o.Port != DefaultPort {
		t.Errorf("Port default mismatch: %d", o.Port)
	}
	if o.ContainerName != DefaultContainerName {
		t.Errorf("ContainerName default mismatch: %q", o.ContainerName)
	}
	if o.HealthTimeout != DefaultHealthTimeout {
		t.Errorf("HealthTimeout default mismatch: %v", o.HealthTimeout)
	}
	if !strings.Contains(o.OutputPath, "fendix-demo-") {
		t.Errorf("OutputPath should contain fendix-demo-, got %q", o.OutputPath)
	}
}

func TestResolve_PreservesOverrides(t *testing.T) {
	o := Options{
		ImageRef:      "custom/image:tag",
		Port:          4000,
		ContainerName: "my-demo",
		OutputPath:    "/tmp/explicit.html",
		HealthTimeout: 10 * time.Second,
	}.resolve()
	if o.ImageRef != "custom/image:tag" {
		t.Errorf("ImageRef override lost: %q", o.ImageRef)
	}
	if o.Port != 4000 {
		t.Errorf("Port override lost: %d", o.Port)
	}
	if o.ContainerName != "my-demo" {
		t.Errorf("ContainerName override lost: %q", o.ContainerName)
	}
	if o.OutputPath != "/tmp/explicit.html" {
		t.Errorf("OutputPath override lost: %q", o.OutputPath)
	}
	if o.HealthTimeout != 10*time.Second {
		t.Errorf("HealthTimeout override lost: %v", o.HealthTimeout)
	}
}

// containsArg returns true if needle appears anywhere in args.
func containsArg(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}
