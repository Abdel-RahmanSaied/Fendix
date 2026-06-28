package targets

import (
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func ptr(s string) *string { return &s }

func TestByName(t *testing.T) {
	for _, name := range []string{"owasp", "dvwa", "juiceshop"} {
		got, err := ByName(name)
		if err != nil {
			t.Fatalf("ByName(%q): %v", name, err)
		}
		if got.Name() != name {
			t.Errorf("ByName(%q).Name() = %q", name, got.Name())
		}
	}
	if _, err := ByName("nope"); err == nil {
		t.Error("ByName(nope): want error, got nil")
	}
}

func TestFindingMatches(t *testing.T) {
	header := models.Finding{Category: "headers", Title: "Missing Content-Security-Policy header", Endpoint: "http://x/"}
	tests := []struct {
		name string
		want ExpectedVuln
		f    models.Finding
		ok   bool
	}{
		{"type+title", ExpectedVuln{Type: "headers", Location: "Content-Security-Policy"}, header, true},
		{"type only", ExpectedVuln{Type: "headers"}, header, true},
		{"wrong type", ExpectedVuln{Type: "cors", Location: "Content-Security-Policy"}, header, false},
		{"title miss", ExpectedVuln{Type: "headers", Location: "X-Frame-Options"}, header, false},
		{"line match", ExpectedVuln{Type: "secrets", Location: "config.py"}, models.Finding{Category: "secrets", Line: ptr("config.py:14")}, true},
	}
	for _, tt := range tests {
		if got := findingMatches(tt.want, tt.f); got != tt.ok {
			t.Errorf("%s: findingMatches = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

func TestScore(t *testing.T) {
	ks := &KnownSet{
		Target: "t",
		Vulnerabilities: []ExpectedVuln{
			{ID: "A", Type: "headers", Location: "Content-Security-Policy"},
			{ID: "B", Type: "headers", Location: "X-Frame-Options"},
			{ID: "C", Type: "cors"},
		},
	}
	findings := []models.Finding{
		{Category: "headers", Title: "Missing Content-Security-Policy header"}, // hits A
		{Category: "data_exposure", Title: "Stack trace leaked"},               // matches nothing → FP
	}
	got := score("t", ks, findings, 5*time.Second, time.Unix(0, 0))
	if got.TruePos != 1 { // only A matched
		t.Errorf("TruePos = %d, want 1", got.TruePos)
	}
	if got.FalseNeg != 2 { // B and C unmatched
		t.Errorf("FalseNeg = %d, want 2", got.FalseNeg)
	}
	if got.FalsePos != 1 { // the data_exposure finding
		t.Errorf("FalsePos = %d, want 1", got.FalsePos)
	}
	if got.ScanDuration != 5*time.Second {
		t.Errorf("ScanDuration = %v, want 5s", got.ScanDuration)
	}
}

func TestCommittedGroundTruthFilesParse(t *testing.T) {
	// The committed JSON files must load and be non-empty — they are the
	// ground truth the baseline depends on. Paths are relative to this
	// package, so walk up to the repo root.
	for _, rel := range []string{
		"../../../../benchmarks/targets/dvwa-known.json",
		"../../../../benchmarks/targets/juiceshop-known.json",
	} {
		ks, err := loadKnownSet(rel)
		if err != nil {
			t.Fatalf("loadKnownSet(%s): %v", rel, err)
		}
		if len(ks.Vulnerabilities) == 0 {
			t.Errorf("%s: no vulnerabilities defined", rel)
		}
		for _, v := range ks.Vulnerabilities {
			if v.Type == "" {
				t.Errorf("%s: vuln %q has empty type", rel, v.ID)
			}
		}
	}
}
