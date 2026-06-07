package ghapp

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultMaxConcurrentScans is the default worker-pool size when a
// Handler is constructed without an explicit cap. Scans are CPU- and
// IO-heavy (clone + Semgrep), so the default is deliberately small; a
// 2-vCPU machine (the reference Fly/k8s sizing) comfortably runs two
// concurrent scans. Tune via NewHandler / WithMaxConcurrentScans.
const DefaultMaxConcurrentScans = 2

// DefaultScanQueueDepth bounds how many scans may wait for a free
// worker before new submissions are rejected (and GitHub left to
// retry). Bounding the queue stops a webhook storm from growing an
// unbounded backlog of stale work in memory.
const DefaultScanQueueDepth = 64

// errPoolClosed is returned by submit after the pool has shut down.
var errPoolClosed = errors.New("scan pool closed")

// errQueueFull is returned by submit when the bounded queue is at
// capacity. The caller has already acknowledged the webhook (200), so
// a full queue means the scan is dropped and GitHub's redelivery (or
// the next synchronize event) will retry — preferable to growing an
// unbounded in-memory backlog.
var errQueueFull = errors.New("scan queue full")

// scanJob is a unit of work for the pool: the deduplication key plus
// the closure that performs the scan. The closure captures its own
// scanInputs and the Handler it runs against.
type scanJob struct {
	key string
	run func(ctx context.Context)
}

// scanPool is the bounded-concurrency background worker pool that runs
// clone+scan off the webhook request path (F-H5a). Webhook handlers
// acknowledge immediately and submit a scanJob here; the pool runs at
// most maxConcurrent jobs at once, dedupes in-flight jobs by key, and
// gives each job a context with its own timeout that is cancelled on
// shutdown.
type scanPool struct {
	sem     chan struct{} // capacity == maxConcurrent
	queue   chan scanJob  // bounded backlog
	timeout time.Duration

	// baseCtx is cancelled by Shutdown so in-flight scans stop promptly.
	baseCtx context.Context
	cancel  context.CancelFunc

	wg sync.WaitGroup

	mu       sync.Mutex
	inFlight map[string]struct{} // dedup set keyed by scanJob.key
	closed   bool
}

// newScanPool starts a pool with the given concurrency cap, queue
// depth, and per-scan timeout. The dispatcher goroutine and the worker
// goroutines run until Shutdown is called.
func newScanPool(maxConcurrent, queueDepth int, timeout time.Duration) *scanPool {
	if maxConcurrent < 1 {
		maxConcurrent = DefaultMaxConcurrentScans
	}
	if queueDepth < 1 {
		queueDepth = DefaultScanQueueDepth
	}
	if timeout <= 0 {
		timeout = HandlerScanTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &scanPool{
		sem:      make(chan struct{}, maxConcurrent),
		queue:    make(chan scanJob, queueDepth),
		timeout:  timeout,
		baseCtx:  ctx,
		cancel:   cancel,
		inFlight: make(map[string]struct{}),
	}
	p.wg.Add(1)
	go p.dispatch()
	return p
}

// submit enqueues a job. It returns:
//   - nil when the job was queued,
//   - errDuplicate when an identical (key) job is already in flight or
//     queued (deduped, not an error the caller should surface),
//   - errQueueFull when the bounded queue is at capacity,
//   - errPoolClosed after Shutdown.
//
// submit never blocks: the webhook has already been acknowledged, so we
// must not pin the request goroutine.
func (p *scanPool) submit(job scanJob) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errPoolClosed
	}
	if job.key != "" {
		if _, dup := p.inFlight[job.key]; dup {
			p.mu.Unlock()
			return errDuplicate
		}
		p.inFlight[job.key] = struct{}{}
	}
	p.mu.Unlock()

	select {
	case p.queue <- job:
		return nil
	default:
		// Queue full — release the dedup reservation so a later retry
		// can be accepted.
		p.releaseKey(job.key)
		return errQueueFull
	}
}

// errDuplicate signals a deduped submission. Distinct from an error
// condition — the caller logs it and moves on.
var errDuplicate = errors.New("duplicate scan in flight")

func (p *scanPool) releaseKey(key string) {
	if key == "" {
		return
	}
	p.mu.Lock()
	delete(p.inFlight, key)
	p.mu.Unlock()
}

// dispatch pulls jobs off the queue and runs each on a worker bounded
// by the semaphore. It exits when the queue is closed by Shutdown.
func (p *scanPool) dispatch() {
	defer p.wg.Done()
	for job := range p.queue {
		p.sem <- struct{}{} // block until a worker slot frees
		p.wg.Add(1)
		go func(job scanJob) {
			defer p.wg.Done()
			defer func() { <-p.sem }()
			defer p.releaseKey(job.key)

			ctx, cancel := context.WithTimeout(p.baseCtx, p.timeout)
			defer cancel()
			job.run(ctx)
		}(job)
	}
}

// Shutdown stops accepting new jobs and drains the queue: queued and
// in-flight scans are allowed to finish gracefully. It blocks until the
// pool is idle or the caller's ctx expires; on ctx expiry it cancels
// the in-flight scan contexts (via the base context) so a stuck scan
// can't block shutdown indefinitely, then returns ctx.Err(). Safe to
// call once; later calls are no-ops.
func (p *scanPool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.queue) // dispatcher drains remaining jobs, then exits
	p.mu.Unlock()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Hard deadline hit — cancel in-flight scans and wait for them
		// to unwind so we don't leak goroutines.
		p.cancel()
		<-done
		return ctx.Err()
	}
}
