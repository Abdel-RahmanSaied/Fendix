package logagg

import (
	"sync"
	"testing"
)

// resetForTest restores fresh package state. Tests in this package run
// sequentially within one Go test process, so a reset at the top of each
// test is sufficient isolation.
func resetForTest(t *testing.T) {
	t.Helper()
	Reset()
	SetCap(DefaultCap)
}

func TestWarn_BelowCap_AllEmitAtWarn(t *testing.T) {
	resetForTest(t)
	for i := 0; i < DefaultCap; i++ {
		Warn("headers", "msg", "n", i)
	}
	w, s := Stats("headers")
	if w != DefaultCap {
		t.Errorf("warned: got %d, want %d", w, DefaultCap)
	}
	if s != 0 {
		t.Errorf("suppressed: got %d, want 0", s)
	}
}

func TestWarn_AboveCap_DowngradesRemaining(t *testing.T) {
	resetForTest(t)
	for i := 0; i < 10; i++ {
		Warn("auth", "msg", "n", i)
	}
	w, s := Stats("auth")
	if w != DefaultCap {
		t.Errorf("warned: got %d, want %d", w, DefaultCap)
	}
	if s != 10-DefaultCap {
		t.Errorf("suppressed: got %d, want %d", s, 10-DefaultCap)
	}
}

func TestWarn_PerKeyIsolation(t *testing.T) {
	resetForTest(t)
	// Saturate "auth" but not "cors" — counts must not bleed across keys.
	for i := 0; i < 10; i++ {
		Warn("auth", "msg", "n", i)
	}
	for i := 0; i < 2; i++ {
		Warn("cors", "msg", "n", i)
	}
	if w, _ := Stats("auth"); w != DefaultCap {
		t.Errorf("auth warned: got %d, want %d", w, DefaultCap)
	}
	if w, s := Stats("cors"); w != 2 || s != 0 {
		t.Errorf("cors: warned=%d suppressed=%d, want 2/0", w, s)
	}
}

func TestSetCap_Zero_DisablesCapping(t *testing.T) {
	resetForTest(t)
	SetCap(0)
	for i := 0; i < 100; i++ {
		Warn("headers", "msg")
	}
	w, s := Stats("headers")
	if w != 100 {
		t.Errorf("warned: got %d, want 100 (cap=0 disables)", w)
	}
	if s != 0 {
		t.Errorf("suppressed: got %d, want 0", s)
	}
}

func TestSetCap_Negative_TreatedAsZero(t *testing.T) {
	resetForTest(t)
	SetCap(-5)
	for i := 0; i < 5; i++ {
		Warn("k", "msg")
	}
	if w, _ := Stats("k"); w != 5 {
		t.Errorf("warned: got %d, want 5 (negative cap should disable)", w)
	}
}

func TestReset_ClearsAllCounters(t *testing.T) {
	resetForTest(t)
	for i := 0; i < 10; i++ {
		Warn("headers", "msg")
		Warn("auth", "msg")
	}
	Reset()
	if w, s := Stats("headers"); w != 0 || s != 0 {
		t.Errorf("after reset, headers: warned=%d suppressed=%d, want 0/0", w, s)
	}
	if w, s := Stats("auth"); w != 0 || s != 0 {
		t.Errorf("after reset, auth: warned=%d suppressed=%d, want 0/0", w, s)
	}
}

func TestSummary_EmptyWhenNoEvents(t *testing.T) {
	resetForTest(t)
	if attrs := Summary(); attrs != nil {
		t.Errorf("expected nil summary on clean slate, got %v", attrs)
	}
}

func TestSummary_KeysSortedAlphabetically(t *testing.T) {
	resetForTest(t)
	// Insert in non-alphabetical order — the output must still be sorted.
	Warn("zoo", "msg")
	Warn("alpha", "msg")
	Warn("middle", "msg")
	attrs := Summary()
	if len(attrs) != 6 {
		t.Fatalf("expected 6 attrs (3 keys × 2 each), got %d: %v", len(attrs), attrs)
	}
	wantKeys := []string{"alpha", "middle", "zoo"}
	for i, want := range wantKeys {
		got, ok := attrs[i*2].(string)
		if !ok || got != want {
			t.Errorf("attrs[%d]: got %v, want %s", i*2, attrs[i*2], want)
		}
	}
}

func TestSummary_ContentReflectsCounts(t *testing.T) {
	resetForTest(t)
	for i := 0; i < 5; i++ {
		Warn("headers", "msg")
	}
	for i := 0; i < 2; i++ {
		Warn("auth", "msg")
	}
	attrs := Summary()
	// alpha order: auth (2 warned, 0 suppressed), headers (3 warned, 2 suppressed)
	if attrs[0] != "auth" || attrs[1] != "warned=2" {
		t.Errorf("auth row: got %v=%v, want auth=warned=2", attrs[0], attrs[1])
	}
	if attrs[2] != "headers" || attrs[3] != "warned=3 suppressed=2" {
		t.Errorf("headers row: got %v=%v, want headers=warned=3 suppressed=2", attrs[2], attrs[3])
	}
}

func TestWarn_GoroutineSafe(t *testing.T) {
	// Worker pool emits Warn from N goroutines concurrently. The aggregator
	// must not corrupt counts under contention. This test floods the
	// aggregator from 50 goroutines and checks the totals.
	resetForTest(t)

	const goroutines = 50
	const eventsPerGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				Warn("headers", "msg", "j", j)
			}
		}()
	}
	wg.Wait()

	w, s := Stats("headers")
	total := goroutines * eventsPerGoroutine
	if w+s != total {
		t.Errorf("total events lost: warned=%d suppressed=%d sum=%d want=%d", w, s, w+s, total)
	}
	if w != DefaultCap {
		t.Errorf("warned: got %d, want %d", w, DefaultCap)
	}
}
