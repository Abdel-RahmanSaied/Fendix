package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadEventsMissingFileIsEmpty(t *testing.T) {
	events, err := LoadEvents(filepath.Join(t.TempDir(), "none.jsonl"))
	if err != nil {
		t.Fatalf("LoadEvents on missing file: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want 0 events, got %d", len(events))
	}
}

func TestLoadEventsRoundTripAndTolerateGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	c := NewFileCollector(path)
	for i := 0; i < 3; i++ {
		_ = c.Record(MetricEvent{Phase: "scan", DurationMs: int64(100 * (i + 1))})
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Append a deliberately-corrupt trailing line; LoadEvents must skip it.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("{not json\n"); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err := LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("want 3 valid events (garbage skipped), got %d", len(events))
	}
}

func TestSummarize(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	var events []MetricEvent
	// Older half slow (200ms), newer half fast (100ms) → improving.
	durs := []int64{200, 200, 100, 100}
	for i, d := range durs {
		events = append(events, MetricEvent{
			Phase: "scan", DurationMs: d, FindingCount: 10, MemoryMB: 100,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	// A non-scan event must be ignored by the summary.
	events = append(events, MetricEvent{Phase: "correlation", DurationMs: 9999})

	s := Summarize(events, 30)
	if s.Count != 4 {
		t.Errorf("Count = %d, want 4 (correlation phase excluded)", s.Count)
	}
	if s.AvgDurationMs != 150 {
		t.Errorf("AvgDurationMs = %v, want 150", s.AvgDurationMs)
	}
	if s.AvgFindings != 10 {
		t.Errorf("AvgFindings = %v, want 10", s.AvgFindings)
	}
	if s.DurationTrend != "improving" {
		t.Errorf("DurationTrend = %q, want improving", s.DurationTrend)
	}
	if !s.LastRun.Equal(base.Add(3 * time.Minute)) {
		t.Errorf("LastRun = %v, want %v", s.LastRun, base.Add(3*time.Minute))
	}
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(nil, 30)
	if s.Count != 0 || s.DurationTrend != "flat" {
		t.Errorf("empty summary = %+v", s)
	}
}

func TestSummarizeCommands(t *testing.T) {
	events := []MetricEvent{
		{Phase: "scan", FindingCount: 3},                          // ignored (not cli)
		{Phase: "cli", Command: "scan", Success: true},            // ok
		{Phase: "cli", Command: "scan", ErrorClass: "scan-error"}, // fail
		{Phase: "cli", Command: "verify", ErrorClass: "usage"},    // fail
		{Phase: "cli", Command: "version", Success: true},         // ok
	}
	s := SummarizeCommands(events, 0)
	if s.Total != 4 {
		t.Fatalf("Total = %d, want 4 (scan-phase event excluded)", s.Total)
	}
	if s.Success != 2 {
		t.Errorf("Success = %d, want 2", s.Success)
	}
	if s.SuccessRate != 0.5 {
		t.Errorf("SuccessRate = %v, want 0.5", s.SuccessRate)
	}
	if s.ByErrorClass["scan-error"] != 1 || s.ByErrorClass["usage"] != 1 {
		t.Errorf("ByErrorClass = %v, want scan-error:1 usage:1", s.ByErrorClass)
	}
}

func TestSummarizeCommandsEmptyRateIsZero(t *testing.T) {
	if s := SummarizeCommands(nil, 0); s.Total != 0 || s.SuccessRate != 0 {
		t.Errorf("empty = %+v, want Total 0 / rate 0 (no divide-by-zero)", s)
	}
}
