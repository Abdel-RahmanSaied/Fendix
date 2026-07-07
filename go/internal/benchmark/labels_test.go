package benchmark

import (
	"os"
	"path/filepath"
	"testing"
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
