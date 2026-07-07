package benchmark

import "testing"

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
