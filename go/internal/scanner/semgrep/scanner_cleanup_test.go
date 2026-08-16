package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Extracted-rules temp-dir lifecycle.
//
// ensureRules() extracts the //go:embed rule pack to a fresh os.MkdirTemp
// directory, memoized once per process. Before the fix nothing ever removed
// it: every fendix process left a /tmp/fendix-semgrep-rules-* behind forever,
// and a long-lived host (the webhook server) held one for its whole lifetime
// with no way to release it on shutdown.
//
// The fix is an explicit Cleanup() that is safe against the once-per-process
// memoization: in-flight scans hold a reference, and Cleanup defers the
// removal until the last one releases.
// ---------------------------------------------------------------------------

func TestCleanup_RemovesExtractedRulesDir(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("rules dir not extracted: %v", err)
	}

	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("extracted rules dir %s still on disk after Cleanup (stat err = %v)", dir, err)
	}
}

// After a Cleanup the memo must be re-armed: a later scan in the same
// process has to re-extract rather than hand semgrep a deleted path.
func TestCleanup_ReExtractsOnNextUse(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	first, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	second, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules after Cleanup: %v", err)
	}
	if second == first {
		t.Fatalf("re-used the removed dir %s after Cleanup", first)
	}
	if _, err := os.Stat(filepath.Join(second, "injection.yaml")); err != nil {
		t.Errorf("rules not re-extracted after Cleanup: %v", err)
	}
}

// Cleanup must never yank the directory out from under a scan that is
// already using it — semgrep reads --config off disk for the whole run.
func TestCleanup_DeferredWhileScanInFlight(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	dir, release, err := acquireRules()
	if err != nil {
		t.Fatalf("acquireRules: %v", err)
	}

	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("rules dir removed while a scan still held it: %v", err)
	}

	release()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("rules dir %s not removed after the last holder released (stat err = %v)", dir, err)
	}
}

// Two overlapping scans: the dir survives until BOTH release.
func TestCleanup_WaitsForEveryHolder(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	dir, releaseA, err := acquireRules()
	if err != nil {
		t.Fatalf("acquireRules A: %v", err)
	}
	dirB, releaseB, err := acquireRules()
	if err != nil {
		t.Fatalf("acquireRules B: %v", err)
	}
	if dirB != dir {
		t.Fatalf("concurrent scans got different rules dirs: %q vs %q", dir, dirB)
	}

	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	releaseA()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("rules dir removed while scan B still held it: %v", err)
	}
	releaseB()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("rules dir %s not removed after the last holder released (stat err = %v)", dir, err)
	}
}

// A release must be idempotent so a double-defer can't drive the refcount
// negative and let Cleanup delete a dir another scan is still reading.
func TestReleaseRules_IsIdempotent(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	dir, releaseA, err := acquireRules()
	if err != nil {
		t.Fatalf("acquireRules A: %v", err)
	}
	_, releaseB, err := acquireRules()
	if err != nil {
		t.Fatalf("acquireRules B: %v", err)
	}
	releaseA()
	releaseA() // double release — must be a no-op

	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("rules dir removed while scan B still held it: %v", err)
	}
	releaseB()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("rules dir %s not removed after the last holder released (stat err = %v)", dir, err)
	}
}

// Cleanup on a process that never scanned is a no-op, not an error —
// a server's shutdown path must be able to call it unconditionally.
func TestCleanup_NoExtractionIsNoOp(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	if err := Cleanup(); err != nil {
		t.Errorf("Cleanup with nothing extracted: %v", err)
	}
	if err := Cleanup(); err != nil {
		t.Errorf("second Cleanup: %v", err)
	}
}

// A completed Scan must not leave a lingering reference — otherwise the
// deferred-removal path would never fire and Cleanup would silently do
// nothing for the rest of the process's life.
func TestScan_ReleasesRulesReferenceSoCleanupWorks(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	installFakeSemgrep(t, `{"results": []}`, "", 0)
	if _, err := Scan(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}

	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Scan leaked a rules reference — %s survived Cleanup (stat err = %v)", dir, err)
	}
}

// Concurrent acquire/release must not race (run under -race).
func TestAcquireRules_ConcurrentIsRaceFree(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, release, err := acquireRules()
			if err != nil {
				t.Errorf("acquireRules: %v", err)
				return
			}
			if dir == "" {
				t.Error("empty rules dir")
			}
			release()
		}()
	}
	wg.Wait()
	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
