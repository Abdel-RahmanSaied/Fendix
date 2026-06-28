// Package metrics provides Fendix's internal, opt-in product metrics
// collection (v0.20 — Establish Baselines). It records structural facts
// about a scan — durations, finding counts, memory — so engineers can
// track product health release-over-release. It is off by default.
//
// PRIVACY: this package must never log source code, finding content, file
// paths, hostnames, secrets, or any user data — only structural counts and
// timings. MetricEvent has no field that can carry such data; keep it that
// way. Anything richer belongs in a debug bundle, not here.
package metrics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EnvFlag is the environment variable that turns metrics collection on.
// Any of "1", "true", "yes" (case-insensitive) enables it; everything
// else — including unset — disables it. Opt-in is mandatory.
const EnvFlag = "FENDIX_METRICS"

// EnvPathFlag optionally overrides where the event log is written. Useful
// for tests and for sandboxes where the default relative path isn't
// writable. Ignored unless EnvFlag is enabled.
const EnvPathFlag = "FENDIX_METRICS_PATH"

// DefaultPath is where the append-only event log lives, relative to the
// working directory. It is gitignored — it is local-only telemetry.
const DefaultPath = "metrics/events.jsonl"

// defaultMaxBytes caps the event log so an always-on collector can never
// grow unbounded. When the file would exceed this, it is rotated once to
// <path>.1 before the new events are written. 10 MiB ~= 100k events.
const defaultMaxBytes int64 = 10 << 20

// MetricEvent is one structural observation about a scan phase or CLI
// invocation. Every field is a count, a duration, a version string, a
// command name, or an error CLASS — never user data (no paths, args, hosts,
// or finding content). PRIVACY: keep it that way.
type MetricEvent struct {
	Version      string    `json:"version"`
	Phase        string    `json:"phase"` // "scan" (a scan) or "cli" (one invocation)
	DurationMs   int64     `json:"duration_ms"`
	FindingCount int       `json:"finding_count"`
	MemoryMB     float64   `json:"memory_mb"`
	Timestamp    time.Time `json:"timestamp"`
	// --- v0.25 CLI-success-rate instrumentation (phase "cli") -----------
	// Command is the subcommand name only ("scan", "version", …) — never the
	// args. ErrorClass is a coarse bucket ("usage", "scan-findings",
	// "scan-error", …), never the error text. All omitempty so scan-phase
	// events are byte-identical to pre-v0.25.
	Command    string `json:"command,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Success    bool   `json:"success,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

// Collector records metric events. Record must be cheap (it is called on
// the scan hot path); durable I/O is deferred to Flush.
type Collector interface {
	// Record buffers an event. It must add negligible overhead.
	Record(event MetricEvent) error
	// Flush persists any buffered events. Safe to call multiple times.
	Flush() error
}

// NoopCollector discards everything. It is the default when metrics are
// disabled, so instrumented code can call Record/Flush unconditionally
// with zero overhead and zero I/O.
type NoopCollector struct{}

// Record discards the event.
func (NoopCollector) Record(MetricEvent) error { return nil }

// Flush does nothing.
func (NoopCollector) Flush() error { return nil }

// FromEnv returns a FileCollector writing to path when EnvFlag is set to a
// truthy value, otherwise a NoopCollector. This is the one entry point
// instrumented code should use, so the opt-in check lives in exactly one
// place. An empty path falls back to DefaultPath.
func FromEnv(path string) Collector {
	if !enabled() {
		return NoopCollector{}
	}
	if path == "" {
		if p := os.Getenv(EnvPathFlag); p != "" {
			path = p
		} else {
			path = DefaultPath
		}
	}
	return NewFileCollector(path)
}

func enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvFlag))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// FileCollector buffers events in memory and appends them as
// newline-delimited JSON on Flush. It is safe for concurrent use.
type FileCollector struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	buf      []MetricEvent
}

// NewFileCollector returns a FileCollector writing to path with the
// default size cap. The file and its parent directory are created lazily
// on the first Flush.
func NewFileCollector(path string) *FileCollector {
	return &FileCollector{path: path, maxBytes: defaultMaxBytes}
}

// Record buffers event in memory. It performs no I/O, so its cost is a
// slice append under a mutex — well under the < 1ms-per-scan budget.
func (c *FileCollector) Record(event MetricEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, event)
	return nil
}

// Flush appends all buffered events to the log as NDJSON, then clears the
// buffer. If the existing log already exceeds the size cap it is rotated
// to <path>.1 (one generation) before writing, bounding disk use.
func (c *FileCollector) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return fmt.Errorf("creating metrics dir: %w", err)
	}
	if err := c.rotateIfTooLarge(); err != nil {
		return err
	}
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening metrics log: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w) // Encode writes a trailing newline → NDJSON
	for _, ev := range c.buf {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encoding metric event: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flushing metrics log: %w", err)
	}
	c.buf = c.buf[:0]
	return nil
}

// rotateIfTooLarge renames the current log to <path>.1 when it has reached
// the size cap, so the active file restarts empty. Caller holds the mutex.
func (c *FileCollector) rotateIfTooLarge() error {
	info, err := os.Stat(c.path)
	if err != nil {
		return nil // no file yet (or unreadable) — nothing to rotate
	}
	if info.Size() < c.maxBytes {
		return nil
	}
	if err := os.Rename(c.path, c.path+".1"); err != nil {
		return fmt.Errorf("rotating metrics log: %w", err)
	}
	return nil
}

// MemoryMB converts a byte count (e.g. runtime.MemStats.HeapAlloc) to MiB
// for the MemoryMB field, so callers don't repeat the unit math.
func MemoryMB(bytes uint64) float64 {
	return float64(bytes) / (1 << 20)
}
