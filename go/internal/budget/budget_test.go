package budget

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func resetForTest(t *testing.T) {
	t.Helper()
	Reset()
	SetMaxRequests(0)
	SetCancelFunc(nil)
}

// passthrough records every RoundTrip call without any cap; used to
// exercise the wrapper's bookkeeping in isolation.
type passthrough struct {
	calls atomic.Int64
}

func (p *passthrough) RoundTrip(req *http.Request) (*http.Response, error) {
	p.calls.Add(1)
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

func makeReq(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRoundTrip_NoCap_AllPassThrough(t *testing.T) {
	resetForTest(t)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	for i := 0; i < 10; i++ {
		_, err := rt.RoundTrip(makeReq(t, "http://x/"))
		if err != nil {
			t.Fatalf("unexpected err on call %d: %v", i, err)
		}
	}
	if pt.calls.Load() != 10 {
		t.Errorf("inner calls: got %d, want 10", pt.calls.Load())
	}
	sent, rejected := Stats()
	if sent != 10 || rejected != 0 {
		t.Errorf("stats: sent=%d rejected=%d, want 10/0", sent, rejected)
	}
}

func TestRoundTrip_BelowCap_AllPassThrough(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(5)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	for i := 0; i < 5; i++ {
		_, err := rt.RoundTrip(makeReq(t, "http://x/"))
		if err != nil {
			t.Fatalf("unexpected err on call %d: %v", i, err)
		}
	}
	if pt.calls.Load() != 5 {
		t.Errorf("inner calls: got %d, want 5", pt.calls.Load())
	}
	sent, rejected := Stats()
	if sent != 5 || rejected != 0 {
		t.Errorf("stats: sent=%d rejected=%d, want 5/0", sent, rejected)
	}
}

func TestRoundTrip_AboveCap_ReturnsErrAndIncrementsRejected(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(3)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	for i := 0; i < 10; i++ {
		_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	}
	if pt.calls.Load() != 3 {
		t.Errorf("inner calls (under-cap only): got %d, want 3", pt.calls.Load())
	}
	sent, rejected := Stats()
	if sent != 10 {
		t.Errorf("sent: got %d, want 10 (every attempt counted)", sent)
	}
	if rejected != 7 {
		t.Errorf("rejected: got %d, want 7 (10 attempts - 3 cap)", rejected)
	}
}

func TestRoundTrip_AboveCap_ReturnsErrBudgetExceeded(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(1)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	_, err := rt.RoundTrip(makeReq(t, "http://x/"))
	if err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	_, err = rt.RoundTrip(makeReq(t, "http://x/"))
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second call: got %v, want ErrBudgetExceeded", err)
	}
}

func TestSetCancelFunc_FiresExactlyOnceOnCapHit(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(2)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	var cancelCalls atomic.Int32
	SetCancelFunc(func() { cancelCalls.Add(1) })

	// 5 calls; 2 below cap, 3 over → cancel fires once on the 3rd attempt.
	for i := 0; i < 5; i++ {
		_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	}
	if cancelCalls.Load() != 1 {
		t.Errorf("cancel calls: got %d, want 1 (capHitOnce should bound to 1)", cancelCalls.Load())
	}
}

func TestSetCancelFunc_NotCalledWhenCapNotHit(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(0) // unlimited
	pt := &passthrough{}
	rt := WrapTransport(pt)

	var cancelCalls atomic.Int32
	SetCancelFunc(func() { cancelCalls.Add(1) })

	for i := 0; i < 100; i++ {
		_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	}
	if cancelCalls.Load() != 0 {
		t.Errorf("cancel calls: got %d, want 0 (cap=0 = unlimited)", cancelCalls.Load())
	}
}

func TestReset_ClearsCountersAndReArmsOnce(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(1)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	var cancelCalls atomic.Int32
	SetCancelFunc(func() { cancelCalls.Add(1) })

	// First scan: hit cap, cancel fires once.
	_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	if cancelCalls.Load() != 1 {
		t.Fatalf("first scan: cancel calls=%d, want 1", cancelCalls.Load())
	}

	// Second scan: Reset; cancel must fire again on cap hit.
	Reset()
	if sent, rejected := Stats(); sent != 0 || rejected != 0 {
		t.Errorf("after Reset: sent=%d rejected=%d, want 0/0", sent, rejected)
	}
	_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
	if cancelCalls.Load() != 2 {
		t.Errorf("after Reset: cancel calls=%d, want 2 (re-armed)", cancelCalls.Load())
	}
}

func TestSetMaxRequests_Negative_TreatedAsZero(t *testing.T) {
	resetForTest(t)
	SetMaxRequests(-5)
	if MaxRequests() != 0 {
		t.Errorf("got %d, want 0 (negative → 0)", MaxRequests())
	}
}

func TestRoundTrip_GoroutineSafe_HitsCapWithoutLostCounts(t *testing.T) {
	// Concurrent requests must produce consistent counts: sent + (cap - missed)
	// math is fragile under races. With cap=50 and 10 goroutines × 20 calls
	// = 200 attempts: sent should equal 200, rejected should equal sent-cap=150.
	resetForTest(t)
	const cap = int64(50)
	const goroutines = 10
	const callsPer = 20

	SetMaxRequests(cap)
	pt := &passthrough{}
	rt := WrapTransport(pt)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsPer; j++ {
				_, _ = rt.RoundTrip(makeReq(t, "http://x/"))
			}
		}()
	}
	wg.Wait()

	sent, rejected := Stats()
	total := int64(goroutines * callsPer)
	if sent != total {
		t.Errorf("sent: got %d, want %d", sent, total)
	}
	if rejected != total-cap {
		t.Errorf("rejected: got %d, want %d", rejected, total-cap)
	}
	if pt.calls.Load() != cap {
		t.Errorf("inner calls: got %d, want %d (only under-cap requests pass)", pt.calls.Load(), cap)
	}
}

func TestWrapTransport_NilDefaultsToHTTPDefault(t *testing.T) {
	// A nil inner transport must not panic; we use a simple httptest server
	// to confirm the request actually goes out via http.DefaultTransport.
	resetForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	rt := WrapTransport(nil)
	resp, err := rt.RoundTrip(makeReq(t, srv.URL))
	if err != nil {
		t.Fatalf("RoundTrip with nil inner: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Errorf("got status %d, want 204", resp.StatusCode)
	}
}
