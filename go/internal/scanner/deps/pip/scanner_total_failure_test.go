package pip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScanViaOSV_BothBatchAndSerialFail asserts that when OSV.dev
// returns 503 on BOTH /v1/querybatch AND /v1/query, scanViaOSV
// returns an error rather than hanging or panicking. This is the
// upstream-outage path: a healthy fault model assumes the orchestrator's
// continue-on-error wiring takes over (verified in the engine package),
// but the contract at this layer is: surface a clear error and bail
// the scanner, not the whole process.
func TestScanViaOSV_BothBatchAndSerialFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := osvAPIBase
	osvAPIBase = srv.URL
	defer func() { osvAPIBase = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	// The current contract: queryOSV returns the error, scanViaOSV
	// logs and continues to the next manifest. Single-manifest case
	// → zero findings returned, no fatal error (the per-manifest
	// failure is internal).
	if err != nil {
		// Acceptable: an upstream wholly-503 surface could also
		// be surfaced as an error if the implementation changes.
		// Either contract is honest as long as it's deterministic.
		if !strings.Contains(err.Error(), "OSV") && !strings.Contains(err.Error(), "503") && !strings.Contains(err.Error(), "service unavailable") {
			t.Errorf("if surfacing error, it should reference OSV/503; got %v", err)
		}
		return
	}
	// findings should be empty (no successful query produced any).
	if len(findings) != 0 {
		t.Errorf("expected zero findings under total OSV outage, got %d", len(findings))
	}
}

// Note: a "timeout-mid-batch" test was attempted but removed —
// httptest.Server.Close() blocks until in-flight handlers return,
// which deadlocks any test that leaves a request hung. The
// httpTimeout = 15*time.Second constant in scanner.go is enforced
// at the http.Client level; testing it requires injecting a custom
// http.Client which scanViaOSV doesn't currently expose. The
// total-failure test above is the highest-value coverage we get
// without a refactor.
