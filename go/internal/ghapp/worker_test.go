package ghapp

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingScanner blocks each Run until release is closed, recording the
// peak number of concurrent in-flight scans. started is closed once the
// first scan has entered Run, letting a test observe in-flight work.
type blockingScanner struct {
	release chan struct{}

	mu       sync.Mutex
	active   int
	peak     int
	total    atomic.Int32
	firstHit sync.Once
	started  chan struct{}
}

func newBlockingScanner() *blockingScanner {
	return &blockingScanner{
		release: make(chan struct{}),
		started: make(chan struct{}),
	}
}

func (b *blockingScanner) Run(ctx context.Context, _ ScanRequest) (*ScanResult, error) {
	b.total.Add(1)
	b.firstHit.Do(func() { close(b.started) })

	b.mu.Lock()
	b.active++
	if b.active > b.peak {
		b.peak = b.active
	}
	b.mu.Unlock()

	select {
	case <-b.release:
	case <-ctx.Done():
	}

	b.mu.Lock()
	b.active--
	b.mu.Unlock()

	return &ScanResult{
		FindingsJSON: []byte(`{"metadata":{},"summary":{},"sources":{},"total":0,"findings":[]}`),
		SARIF:        []byte(`{"runs":[]}`),
	}, ctx.Err()
}

func (b *blockingScanner) peakActive() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

// ctxWithDelivery builds an event Context with a specific delivery ID so
// dedup-key behaviour is controllable from tests.
func ctxWithDelivery(delivery string) Context {
	c := eventCtx()
	c.Delivery = delivery
	return c
}

// F-H5a: the webhook handler must acknowledge immediately — it returns
// while the (slow) scan is still running on the background pool.
func TestHandlePullRequest_ImmediateAck(t *testing.T) {
	scanner := newBlockingScanner()
	h, _ := newTestHandler(t, scanner)
	h.PostComment = func(context.Context, string, string, string, int, string) error { return nil }
	h.UploadSARIF = func(context.Context, string, string, string, string, string, []byte) error { return nil }

	done := make(chan error, 1)
	go func() {
		done <- h.HandlePullRequest(eventCtx(), samplePullRequestPayload("opened", 123))
	}()

	// The handler must return promptly even though the scan is blocked.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandlePullRequest should ack with nil err, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandlePullRequest did not return immediately (still blocked on scan)")
	}

	// Confirm the scan really is in flight (i.e. the ack happened before
	// the scan finished), then release it.
	select {
	case <-scanner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan never started on the background pool")
	}
	close(scanner.release)
}

// F-H5a: the pool runs at most max-concurrent scans at once.
func TestScanPool_ConcurrencyCap(t *testing.T) {
	const cap = 2
	const jobs = 6
	scanner := newBlockingScanner()

	tokenSrv := installationTokenServer(t, "ghs_test_token")
	t.Cleanup(tokenSrv.Close)
	creds := &AppCredentials{AppID: 1, PrivateKey: genTestKey(t)}
	tokens := NewTokenSource(creds, tokenSrv.Client(), tokenSrv.URL)
	h := NewHandler(tokens, "", tokenSrv.Client(), cap)
	h.Scanner = scanner
	h.PostComment = func(context.Context, string, string, string, int, string) error { return nil }
	h.UploadSARIF = func(context.Context, string, string, string, string, string, []byte) error { return nil }

	for i := 0; i < jobs; i++ {
		// Distinct delivery IDs → distinct dedup keys → all admitted.
		if err := h.HandlePullRequest(ctxWithDelivery("d"+strconv.Itoa(i)), samplePullRequestPayload("opened", 123)); err != nil {
			t.Fatalf("HandlePullRequest %d: %v", i, err)
		}
	}

	// Wait until the pool is saturated (cap scans active), then release.
	deadline := time.After(3 * time.Second)
	for {
		if scanner.peakActive() >= cap {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("pool never reached %d concurrent scans (peak=%d)", cap, scanner.peakActive())
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(scanner.release)
	drainScans(t, h)

	if peak := scanner.peakActive(); peak > cap {
		t.Errorf("concurrency cap exceeded: peak=%d cap=%d", peak, cap)
	}
	if got := scanner.total.Load(); int(got) != jobs {
		t.Errorf("expected all %d jobs to run, got %d", jobs, got)
	}
}

// F-H5a: a redelivered webhook (same delivery ID) while a scan is in
// flight is deduped — the scan runs once, not twice.
func TestScanPool_DedupByDelivery(t *testing.T) {
	scanner := newBlockingScanner()
	h, _ := newTestHandler(t, scanner)
	h.PostComment = func(context.Context, string, string, string, int, string) error { return nil }
	h.UploadSARIF = func(context.Context, string, string, string, string, string, []byte) error { return nil }

	ctx := ctxWithDelivery("dup-delivery")
	if err := h.HandlePullRequest(ctx, samplePullRequestPayload("opened", 123)); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Wait for the first scan to be in flight before the duplicate.
	select {
	case <-scanner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first scan never started")
	}
	// Same delivery while in flight → deduped, no second run.
	if err := h.HandlePullRequest(ctx, samplePullRequestPayload("opened", 123)); err != nil {
		t.Fatalf("duplicate submit: %v", err)
	}

	close(scanner.release)
	drainScans(t, h)

	if got := scanner.total.Load(); got != 1 {
		t.Errorf("expected deduped to a single scan, ran %d times", got)
	}
}

// The pool releases a dedup reservation once its scan completes, so an
// identical key submitted *after* the first finished is admitted again.
func TestScanPool_DedupReleasedAfterCompletion(t *testing.T) {
	p := newScanPool(1, 4, time.Minute)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	var runs atomic.Int32
	first := make(chan struct{})
	job := func(key string) scanJob {
		return scanJob{key: key, run: func(context.Context) {
			runs.Add(1)
			close(first)
		}}
	}
	if err := p.submit(job("k")); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	<-first
	// Give the worker a moment to release the reservation.
	deadline := time.After(2 * time.Second)
	for {
		err := p.submit(scanJob{key: "k", run: func(context.Context) { runs.Add(1) }})
		if err == nil {
			break
		}
		if !errors.Is(err, errDuplicate) {
			t.Fatalf("unexpected submit error: %v", err)
		}
		select {
		case <-deadline:
			t.Fatal("dedup reservation never released after completion")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// A full queue is reported (not blocked); the caller already acked the
// webhook, so the scan is dropped for GitHub to retry.
func TestScanPool_QueueFull(t *testing.T) {
	// cap=1 worker, queueDepth=1. Occupy the worker with a blocking job,
	// fill the single queue slot, then the next submit must report full.
	p := newScanPool(1, 1, time.Minute)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	release := make(chan struct{})
	blocking := scanJob{key: "block", run: func(context.Context) { <-release }}
	if err := p.submit(blocking); err != nil {
		t.Fatalf("submit blocking: %v", err)
	}
	// Wait for the worker to pick up the blocking job so the queue is empty.
	deadline := time.After(2 * time.Second)
	for {
		p.mu.Lock()
		inFlight := len(p.inFlight)
		queued := len(p.queue)
		p.mu.Unlock()
		if inFlight == 1 && queued == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("blocking job never started")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// The single worker is occupied by the blocking job, so no queued
	// job can start. Keep submitting distinct (so dedup doesn't trip)
	// jobs; once the bounded queue (plus the one item the dispatcher has
	// pulled and is parked on the semaphore with) is saturated, submit
	// must report errQueueFull rather than block.
	var got error
	for i := 0; i < 50; i++ {
		got = p.submit(scanJob{key: "q" + strconv.Itoa(i), run: func(context.Context) {}})
		if got != nil {
			break
		}
	}
	if !errors.Is(got, errQueueFull) {
		t.Errorf("expected errQueueFull once the queue saturates, got %v", got)
	}
	close(release)
}

// After Shutdown, further submissions are rejected with errPoolClosed.
func TestScanPool_SubmitAfterShutdown(t *testing.T) {
	p := newScanPool(1, 1, time.Minute)
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := p.submit(scanJob{key: "x", run: func(context.Context) {}}); !errors.Is(err, errPoolClosed) {
		t.Errorf("expected errPoolClosed after shutdown, got %v", err)
	}
}
