package engine

import (
	"reflect"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// The report's `checks_run` list is read by consumers as "these checks ran".
// It used to hand-append "secrets", "semgrep" and "deps" whenever a code path
// was configured, regardless of whether those passes actually executed — so a
// scan whose semgrep binary was missing reported semgrep as skipped in
// scanner_status AND as run in checks_run, in the same document.
//
// The comment directly above that code promised metadata "can't drift from
// what actually ran". These tests hold it to that promise.
func TestCodeScannerLabelsOnlyReportsPassesThatRan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status scannerStatusList
		want   []string
	}{
		{
			name: "semgrep binary absent is not reported as run",
			status: scannerStatusList{
				{Name: "secrets", State: reporters.ScannerOK},
				{Name: "semgrep", State: reporters.ScannerSkipped, Detail: "semgrep binary not installed"},
			},
			want: []string{"secrets"},
		},
		{
			name: "a failed pass is not reported as run",
			status: scannerStatusList{
				{Name: "secrets", State: reporters.ScannerFailed, Detail: "boom"},
				{Name: "semgrep", State: reporters.ScannerOK},
			},
			want: []string{"semgrep"},
		},
		{
			name: "deps is one coarse label covering the three dep scanners",
			status: scannerStatusList{
				{Name: "govulncheck", State: reporters.ScannerOK},
				{Name: "pip", State: reporters.ScannerSkipped, Detail: "no python manifest"},
			},
			want: []string{"deps"},
		},
		{
			name: "every dep scanner skipped means no deps label",
			status: scannerStatusList{
				{Name: "govulncheck", State: reporters.ScannerSkipped, Detail: "no go.mod at code path"},
				{Name: "npm", State: reporters.ScannerSkipped, Detail: "no package-lock.json at code path"},
			},
			want: nil,
		},
		{
			name: "all three ran",
			status: scannerStatusList{
				{Name: "secrets", State: reporters.ScannerOK},
				{Name: "semgrep", State: reporters.ScannerOK},
				{Name: "npm", State: reporters.ScannerOK},
			},
			want: []string{"secrets", "semgrep", "deps"},
		},
		{
			name:   "nothing recorded yields nothing claimed",
			status: scannerStatusList{},
			want:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codeScannerLabels(tc.status)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("codeScannerLabels() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The label order must be stable so two identical scans produce byte-identical
// reports — the determinism the release decision is built on.
func TestCodeScannerLabelsAreDeterministicallyOrdered(t *testing.T) {
	status := scannerStatusList{
		{Name: "npm", State: reporters.ScannerOK},
		{Name: "semgrep", State: reporters.ScannerOK},
		{Name: "secrets", State: reporters.ScannerOK},
	}
	want := []string{"secrets", "semgrep", "deps"}
	for i := 0; i < 5; i++ {
		if got := codeScannerLabels(status); !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d: got %v, want %v", i, got, want)
		}
	}
}
