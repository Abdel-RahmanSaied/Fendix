package metrics

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// LoadEvents reads all NDJSON metric events from path. A missing file is
// not an error — it returns an empty slice (metrics are opt-in, so "no log
// yet" is the normal first-run state). Malformed lines are skipped rather
// than aborting the whole read, so one bad append can't hide the history.
func LoadEvents(path string) ([]MetricEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening metrics log %s: %w", path, err)
	}
	defer f.Close()

	var events []MetricEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev MetricEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // tolerate a partially-written trailing line
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading metrics log %s: %w", path, err)
	}
	return events, nil
}

// Summary is the aggregate view of recent metric events for `metrics show`.
type Summary struct {
	Count         int
	AvgDurationMs float64
	AvgFindings   float64
	AvgMemoryMB   float64
	LastRun       time.Time
	// DurationTrend is "improving" (getting faster), "worsening" (slower),
	// or "flat", computed by comparing the older vs newer half of the window.
	DurationTrend string
}

// Summarize aggregates the most recent lastN scan-phase events (lastN <= 0
// means all). It ignores non-"scan" phases so the headline numbers describe
// whole scans, not sub-phases.
func Summarize(events []MetricEvent, lastN int) Summary {
	scans := make([]MetricEvent, 0, len(events))
	for _, e := range events {
		if e.Phase == "scan" {
			scans = append(scans, e)
		}
	}
	if lastN > 0 && len(scans) > lastN {
		scans = scans[len(scans)-lastN:]
	}
	s := Summary{Count: len(scans), DurationTrend: "flat"}
	if len(scans) == 0 {
		return s
	}
	var sumDur, sumFind, sumMem float64
	for _, e := range scans {
		sumDur += float64(e.DurationMs)
		sumFind += float64(e.FindingCount)
		sumMem += e.MemoryMB
		if e.Timestamp.After(s.LastRun) {
			s.LastRun = e.Timestamp
		}
	}
	n := float64(len(scans))
	s.AvgDurationMs = sumDur / n
	s.AvgFindings = sumFind / n
	s.AvgMemoryMB = sumMem / n
	s.DurationTrend = durationTrend(scans)
	return s
}

// CommandSummary is the aggregate view of CLI-invocation events (phase
// "cli") behind the "metrics show" success-rate line. Unlike Summarize it
// does NOT filter to scans — it counts every recorded invocation so the rate
// reflects real first-try success across all commands (the v0.25 metric).
type CommandSummary struct {
	Total       int
	Success     int
	SuccessRate float64 // Success/Total in [0,1]; 0 when Total == 0
	// ByErrorClass counts FAILURES grouped by coarse class ("usage",
	// "scan-error", …). Successes are not included.
	ByErrorClass map[string]int
}

// SummarizeCommands aggregates the most recent lastN CLI-invocation events
// (lastN <= 0 means all). It reads phase "cli" events only — never scans, so
// a scan that also emits a "scan" event is counted once here.
func SummarizeCommands(events []MetricEvent, lastN int) CommandSummary {
	cli := make([]MetricEvent, 0, len(events))
	for _, e := range events {
		if e.Phase == "cli" {
			cli = append(cli, e)
		}
	}
	if lastN > 0 && len(cli) > lastN {
		cli = cli[len(cli)-lastN:]
	}
	s := CommandSummary{Total: len(cli), ByErrorClass: map[string]int{}}
	for _, e := range cli {
		if e.Success {
			s.Success++
			continue
		}
		class := e.ErrorClass
		if class == "" {
			class = "unknown"
		}
		s.ByErrorClass[class]++
	}
	if s.Total > 0 {
		s.SuccessRate = float64(s.Success) / float64(s.Total)
	}
	return s
}

// durationTrend compares the mean duration of the older half of the window
// against the newer half. Needs at least 4 points to be meaningful.
func durationTrend(scans []MetricEvent) string {
	if len(scans) < 4 {
		return "flat"
	}
	mid := len(scans) / 2
	older := meanDuration(scans[:mid])
	newer := meanDuration(scans[mid:])
	switch {
	case newer < older*0.95:
		return "improving"
	case newer > older*1.05:
		return "worsening"
	default:
		return "flat"
	}
}

func meanDuration(scans []MetricEvent) float64 {
	if len(scans) == 0 {
		return 0
	}
	var sum float64
	for _, e := range scans {
		sum += float64(e.DurationMs)
	}
	return sum / float64(len(scans))
}
