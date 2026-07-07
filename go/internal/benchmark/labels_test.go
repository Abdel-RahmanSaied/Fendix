package benchmark

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestFPClassValid(t *testing.T) {
	valid := []string{
		"constant-authority", "receiver-confusion", "safe-api-misread",
		"const-fold-miss", "guard-dominance", "test-fixture",
		"http-4xx-context", "static-asset-context", "double-sanitize",
		"heuristic-overfire", "version-range-floor", "fabricated-chain",
	}
	for _, c := range valid {
		if !FPClass(c).Valid() {
			t.Errorf("FPClass(%q).Valid() = false, want true", c)
		}
	}
	if FPClass("made-up").Valid() {
		t.Error(`FPClass("made-up").Valid() = true, want false`)
	}
	if FPClass("").Valid() {
		t.Error(`FPClass("").Valid() = true, want false`)
	}
}

func TestLoadLabelSet(t *testing.T) {
	dir := t.TempDir()
	yaml := `- rule: PY_SSRF
  file: app/services/fetch.py
  line: 142
  verdict: fp
  fp_class: constant-authority
  note: host is settings.BASE_URL
- rule: PY_SSRF
  file: ./views.py
  line: 597
  verdict: tp
`
	p := filepath.Join(dir, "labels.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	ls, err := LoadLabelSet(p)
	if err != nil {
		t.Fatalf("LoadLabelSet: %v", err)
	}
	if len(ls.Labels) != 2 {
		t.Fatalf("got %d labels, want 2", len(ls.Labels))
	}
	// Path normalization: leading "./" stripped, backslashes → forward.
	if ls.Labels[1].File != "views.py" {
		t.Errorf("File not normalized: %q", ls.Labels[1].File)
	}
	if ls.Labels[0].Verdict != VerdictFP || ls.Labels[0].FPClass != FPConstantAuthority {
		t.Errorf("bad label[0]: %+v", ls.Labels[0])
	}
}

func TestLoadLabelSetRejectsFPWithoutClass(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "labels.yaml")
	os.WriteFile(p, []byte("- rule: PY_SSRF\n  file: a.py\n  line: 1\n  verdict: fp\n"), 0o644)
	if _, err := LoadLabelSet(p); err == nil {
		t.Fatal("want error for verdict:fp with no fp_class, got nil")
	}
}

func TestLoadLabelSetRejectsBadClass(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "labels.yaml")
	os.WriteFile(p, []byte("- rule: PY_SSRF\n  file: a.py\n  line: 1\n  verdict: fp\n  fp_class: nope\n"), 0o644)
	if _, err := LoadLabelSet(p); err == nil {
		t.Fatal("want error for unknown fp_class, got nil")
	}
}

func fPtr(s string) *string { return &s }

func TestMatchFinding(t *testing.T) {
	label := Label{Rule: "PY_SSRF", File: "app/fetch.py", Line: 142, Verdict: VerdictFP, FPClass: FPConstantAuthority}
	tests := []struct {
		name string
		f    models.Finding
		want bool
	}{
		{"exact", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "app/fetch.py:142"}, true},
		{"within +3", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "app/fetch.py:145"}, true},
		{"within -3", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "app/fetch.py:139"}, true},
		{"outside +4", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "app/fetch.py:146"}, false},
		{"wrong file", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "app/other.py:142"}, false},
		{"wrong rule", models.Finding{ID: "SEC-PY_SQL_INJECTION", Endpoint: "app/fetch.py:142"}, false},
		{"normalized endpoint", models.Finding{ID: "SEC-PY_SSRF", Endpoint: "./app/fetch.py:142"}, true},
	}
	for _, tt := range tests {
		if got := MatchFinding(label, tt.f); got != tt.want {
			t.Errorf("%s: MatchFinding = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestScoreRealWorld(t *testing.T) {
	ls := &LabelSet{Labels: []Label{
		{Rule: "PY_SSRF", File: "a.py", Line: 10, Verdict: VerdictTP},
		{Rule: "PY_SSRF", File: "b.py", Line: 20, Verdict: VerdictFP, FPClass: FPConstantAuthority},
		{Rule: "PY_SQL_INJECTION", File: "c.py", Line: 30, Verdict: VerdictTP}, // no finding → FN
	}}
	findings := []models.Finding{
		{ID: "SEC-PY_SSRF", Endpoint: "a.py:10"},          // matches tp
		{ID: "SEC-PY_SSRF", Endpoint: "b.py:21"},          // matches fp (within ±3)
		{ID: "SEC-PY_PATH_TRAVERSAL", Endpoint: "d.py:5"}, // no label → unknown
	}
	r := ScoreRealWorld("mini", ls, findings, 1000)
	if r.TruePos != 1 || r.FalsePos != 1 || r.Unknown != 1 || r.FalseNeg != 1 {
		t.Fatalf("counts: tp=%d fp=%d unknown=%d fn=%d", r.TruePos, r.FalsePos, r.Unknown, r.FalseNeg)
	}
	if r.PerClass[FPConstantAuthority] != 1 {
		t.Errorf("per-class constant-authority = %d, want 1", r.PerClass[FPConstantAuthority])
	}
	// Precision over LABELED findings only: tp/(tp+fp) = 1/2.
	if got := r.Precision(); got != 0.5 {
		t.Errorf("Precision = %v, want 0.5", got)
	}
	// 1000 LOC → 2 real findings (tp+fp, unknowns excluded) per KLOC = 2.0.
	if got := r.FindingsPerKLOC(); got != 2.0 {
		t.Errorf("FindingsPerKLOC = %v, want 2.0", got)
	}
	if len(r.Unknowns) != 1 || r.Unknowns[0].Endpoint != "d.py:5" {
		t.Errorf("unknowns triage list wrong: %+v", r.Unknowns)
	}
}
