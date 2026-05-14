// Package logagg caps the per-check WARN log volume for a single scan and
// reports an aggregated summary at scan end. It exists because real-world
// scans against unreliable hosts (transient TLS handshake failures, slow
// drips, DNS hiccups) can produce thousands of "request failed" WARN lines
// — one per endpoint per check. That floods operator terminals and CI logs
// for no signal: the same root cause repeats N times.
//
// The aggregator emits the first DefaultCap WARN events per key (typically
// a check name like "headers" or "auth") at slog.Warn level so operators
// see something is wrong; subsequent events are downgraded to slog.Debug.
// Summary() returns slog-compatible attrs ready to splat into a single
// slog.Info line at scan end with per-key (warned, suppressed) counts.
//
// State is package-level. A Fendix CLI invocation runs a single scan, so
// concurrent scans aren't a concern. Tests should call Reset() at the top
// to start from a clean slate. The whole API is goroutine-safe — the
// scanner worker pool calls Warn() concurrently from multiple goroutines.
package logagg

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// DefaultCap is the per-key WARN-emission limit used when SetCap is not
// called. Three is enough for an operator to notice the failure mode on
// the first few endpoints without drowning the terminal.
const DefaultCap = 3

type entry struct {
	warned     int // number of events emitted at slog.Warn
	suppressed int // number of events downgraded to slog.Debug
}

var (
	mu        sync.Mutex
	capPerKey = DefaultCap
	entries   = map[string]*entry{}
)

// SetCap configures the per-key WARN cap. Pass 0 to disable capping
// (every Warn call emits at slog.Warn). Negative values are treated as 0.
// Safe to call concurrently with Warn — the new cap takes effect on
// subsequent calls.
func SetCap(c int) {
	if c < 0 {
		c = 0
	}
	mu.Lock()
	capPerKey = c
	mu.Unlock()
}

// Reset clears all per-key counters. Call at the start of each scan so
// per-key suppression starts fresh.
func Reset() {
	mu.Lock()
	entries = map[string]*entry{}
	mu.Unlock()
}

// Warn records one event under key and emits at slog.Warn if the per-key
// count is below the cap, otherwise at slog.Debug. The args slice follows
// the slog convention (alternating string keys and any-typed values).
//
// A nil receiver is not a special case here because Warn is package-level;
// callers don't need a guard. To bypass capping entirely, pass cap=0 via
// SetCap.
func Warn(key, msg string, args ...any) {
	mu.Lock()
	e := entries[key]
	if e == nil {
		e = &entry{}
		entries[key] = e
	}
	cap := capPerKey
	emitWarn := cap == 0 || e.warned < cap
	if emitWarn {
		e.warned++
	} else {
		e.suppressed++
	}
	mu.Unlock()

	if emitWarn {
		slog.Warn(msg, args...)
	} else {
		slog.Debug(msg, args...)
	}
}

// Summary returns slog-compatible attrs describing per-key (warned,
// suppressed) counts across all keys with at least one event. Keys are
// alphabetically sorted so the output is deterministic. Returns nil if no
// events have been recorded since the last Reset.
//
// Typical caller usage:
//
//	if attrs := logagg.Summary(); len(attrs) > 0 {
//	    slog.Info("warning summary", attrs...)
//	}
//
// Each key produces one attr whose value is a small struct-shaped string
// like "warned=3 suppressed=47" — slog's default text formatter renders
// it as "headers=warned=3 suppressed=47". Compact and grep-friendly.
func Summary() []any {
	mu.Lock()
	defer mu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys)*2)
	for _, k := range keys {
		e := entries[k]
		out = append(out, k, formatEntry(*e))
	}
	return out
}

// formatEntry renders an entry as a compact summary string. Public-ish
// shape so tests can assert on it without depending on slog's render.
func formatEntry(e entry) string {
	if e.suppressed == 0 {
		return fmt.Sprintf("warned=%d", e.warned)
	}
	return fmt.Sprintf("warned=%d suppressed=%d", e.warned, e.suppressed)
}

// Stats returns the per-key (warned, suppressed) counts as plain ints.
// Useful in tests where assertions on the slog-rendered string are brittle.
func Stats(key string) (warned, suppressed int) {
	mu.Lock()
	defer mu.Unlock()
	e := entries[key]
	if e == nil {
		return 0, 0
	}
	return e.warned, e.suppressed
}
