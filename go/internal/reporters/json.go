package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ScanMetadata contains metadata about the scan run for report output.
type ScanMetadata struct {
	Target         string    `json:"target"`
	StartedAt      time.Time `json:"started_at"`
	Duration       string    `json:"duration"`
	Version        string    `json:"version"`
	Mode           string    `json:"mode"`
	EndpointsCount int       `json:"endpoints_scanned"`
	// EndpointsDiscovered is the number of endpoints found BEFORE the
	// --max-endpoints cap truncated the list; EndpointsTruncated is true when
	// the cap actually dropped some. Without these, endpoints_scanned=500 is
	// indistinguishable from "found exactly 500" vs "found 801, capped to
	// 500" — a silent coverage gap a CI gate can't detect. When no cap fires,
	// EndpointsDiscovered == EndpointsCount and EndpointsTruncated is false.
	EndpointsDiscovered int      `json:"endpoints_discovered,omitempty"`
	EndpointsTruncated  bool     `json:"endpoints_truncated,omitempty"`
	ActiveProbes        bool     `json:"active_probes"`
	ChecksRun           []string `json:"checks_run,omitempty"`
	// ScannerStatus records the per-scanner outcome for the dep-CVE,
	// secrets, semgrep, and textscan passes (F-L7/F-L13/F-L14). It ends
	// the historical fail-open behaviour where a scanner crash was logged
	// at WARN and silently dropped: every failure is now recorded here,
	// surfaced in a scan-end summary line, and (with --fail-on-scanner-error)
	// can force a non-zero exit. SARIF derives invocations[].executionSuccessful
	// from it. Empty for pure black-box scans that run no code scanners.
	ScannerStatus []ScannerStatus `json:"scanner_status,omitempty"`
}

// ScannerStatusState enumerates the terminal state of one scanner pass.
type ScannerStatusState string

const (
	// ScannerOK means the scanner ran to completion without error.
	ScannerOK ScannerStatusState = "ok"
	// ScannerSkipped means the scanner did not run because its
	// precondition was absent (no manifest, tool not installed) or it
	// cannot run in the current mode (e.g. govulncheck in --offline,
	// which needs vuln.go.dev). A skip is not a failure.
	ScannerSkipped ScannerStatusState = "skipped"
	// ScannerFailed means the scanner ran but errored (network blip,
	// malformed output, parse failure). Counts as a failure for
	// --fail-on-scanner-error and for SARIF executionSuccessful.
	ScannerFailed ScannerStatusState = "failed"
)

// ScannerStatus is the recorded outcome of a single scanner pass. Name
// is the scanner identity ("govulncheck", "pip", "npm", "secrets",
// "semgrep", "textscan"); Detail is a short human-readable reason
// (skip cause or error excerpt).
type ScannerStatus struct {
	Name   string             `json:"name"`
	State  ScannerStatusState `json:"state"`
	Detail string             `json:"detail,omitempty"`
}

// Failed reports whether this scanner ran and errored. Skips and OK
// states return false.
func (s ScannerStatus) Failed() bool { return s.State == ScannerFailed }

// SeverityCounts holds the count of findings per severity level.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// SourceCounts holds the count of findings per source type.
type SourceCounts struct {
	Blackbox   int `json:"blackbox"`
	Whitebox   int `json:"whitebox"`
	Correlated int `json:"correlated"`
}

// StatusCounts is the v0.24 decision summary: a wall of findings reduced to
// "what needs action". Confirmed counts HIGH-confidence findings (the v0.23
// score axis), kept deliberately distinct from sources.correlated (cross-engine
// agreement) so the two signals aren't conflated.
type StatusCounts struct {
	Total         int `json:"total"`         // == len(findings)
	Confirmed     int `json:"confirmed"`     // confidence_band == HIGH
	Blocking      int `json:"blocking"`      // status == BLOCK
	Warning       int `json:"warning"`       // status == WARN
	Informational int `json:"informational"` // status == INFO
}

// JSONReport is the top-level structure for JSON report output.
type JSONReport struct {
	Metadata  ScanMetadata     `json:"metadata"`
	Summary   SeverityCounts   `json:"summary"`
	Sources   SourceCounts     `json:"sources"`
	Total     int              `json:"total"`
	Decisions StatusCounts     `json:"decisions"` // v0.24 (additive)
	Findings  []models.Finding `json:"findings"`
}

// CountSeverities tallies findings by severity level.
func CountSeverities(findings []models.Finding) SeverityCounts {
	var counts SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			counts.Critical++
		case models.SeverityHigh:
			counts.High++
		case models.SeverityMedium:
			counts.Medium++
		case models.SeverityLow:
			counts.Low++
		case models.SeverityInfo:
			counts.Info++
		}
	}
	return counts
}

// CountSources tallies findings by source type.
func CountSources(findings []models.Finding) SourceCounts {
	var counts SourceCounts
	for _, f := range findings {
		switch f.Source {
		case models.SourceBlackbox:
			counts.Blackbox++
		case models.SourceWhitebox:
			counts.Whitebox++
		case models.SourceCorrelated:
			counts.Correlated++
		}
	}
	return counts
}

// CountStatuses tallies the v0.24 decision summary from the per-finding
// status + confidence band stamped by the orchestrator. When findings carry
// no decision fields (reporter called without the orchestrator pass), only
// Total is non-zero — additive and harmless.
func CountStatuses(findings []models.Finding) StatusCounts {
	counts := StatusCounts{Total: len(findings)}
	for _, f := range findings {
		switch f.Status {
		case "BLOCK":
			counts.Blocking++
		case "WARN":
			counts.Warning++
		case "INFO":
			counts.Informational++
		}
		if f.ConfidenceBand == string(models.ConfidenceHigh) {
			counts.Confirmed++
		}
	}
	return counts
}

// RenderJSON writes a full JSON report to the writer.
//
// The `findings` field is always serialised as a JSON array (`[]` when the
// input is nil or empty) — never `null` — so consumers can iterate without
// a null-check. This is part of the public schema (docs/schema.md).
func RenderJSON(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	if findings == nil {
		findings = []models.Finding{}
	}
	report := JSONReport{
		Metadata:  meta,
		Summary:   CountSeverities(findings),
		Sources:   CountSources(findings),
		Total:     len(findings),
		Decisions: CountStatuses(findings),
		Findings:  findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}
