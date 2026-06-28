package metrics

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNoopCollector(t *testing.T) {
	var c Collector = NoopCollector{}
	if err := c.Record(MetricEvent{Phase: "scan"}); err != nil {
		t.Errorf("Record: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("Flush: %v", err)
	}
}

func TestFileCollectorWritesNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "events.jsonl") // exercises MkdirAll
	c := NewFileCollector(path)
	events := []MetricEvent{
		{Version: "v0.20.0", Phase: "scan", DurationMs: 1200, FindingCount: 23, MemoryMB: 142, Timestamp: time.Unix(1, 0).UTC()},
		{Version: "v0.20.0", Phase: "correlation", DurationMs: 30, FindingCount: 4, MemoryMB: 142, Timestamp: time.Unix(2, 0).UTC()},
	}
	for _, e := range events {
		if err := c.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var n int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev MetricEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d not valid JSON: %v", n, err)
		}
		n++
	}
	if n != 2 {
		t.Errorf("wrote %d NDJSON lines, want 2", n)
	}
}

func TestFileCollectorFlushIsAppendAndIdempotentWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	c := NewFileCollector(path)
	// Flush with nothing buffered must not create a file or error.
	if err := c.Flush(); err != nil {
		t.Fatalf("empty Flush: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("empty Flush should not create the log file")
	}
	// Two record/flush cycles should append, not truncate.
	_ = c.Record(MetricEvent{Phase: "scan"})
	_ = c.Flush()
	_ = c.Record(MetricEvent{Phase: "scan"})
	_ = c.Flush()
	data, _ := os.ReadFile(path)
	var lines int
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("append produced %d lines, want 2", lines)
	}
}

func TestFileCollectorRotatesWhenTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	c := NewFileCollector(path)
	c.maxBytes = 50 // tiny cap to force rotation deterministically

	// First flush writes a couple of events, pushing the file over the cap.
	_ = c.Record(MetricEvent{Version: "v0.20.0", Phase: "scan", Timestamp: time.Unix(1, 0)})
	_ = c.Record(MetricEvent{Version: "v0.20.0", Phase: "report", Timestamp: time.Unix(2, 0)})
	if err := c.Flush(); err != nil {
		t.Fatalf("flush 1: %v", err)
	}
	// Next flush sees an oversized file and rotates it to <path>.1.
	_ = c.Record(MetricEvent{Version: "v0.20.0", Phase: "scan", Timestamp: time.Unix(3, 0)})
	if err := c.Flush(); err != nil {
		t.Fatalf("flush 2: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotated file %s.1: %v", path, err)
	}
}

func TestFromEnvTogglesOnFlag(t *testing.T) {
	t.Setenv(EnvFlag, "")
	if _, ok := FromEnv("").(NoopCollector); !ok {
		t.Error("unset flag should yield NoopCollector")
	}
	t.Setenv(EnvFlag, "true")
	if _, ok := FromEnv(filepath.Join(t.TempDir(), "e.jsonl")).(*FileCollector); !ok {
		t.Error("truthy flag should yield *FileCollector")
	}
	t.Setenv(EnvFlag, "nope")
	if _, ok := FromEnv("").(NoopCollector); !ok {
		t.Error("non-truthy flag should yield NoopCollector")
	}
}

func TestMemoryMB(t *testing.T) {
	if got := MemoryMB(1 << 20); got != 1.0 {
		t.Errorf("MemoryMB(1MiB) = %v, want 1.0", got)
	}
}
