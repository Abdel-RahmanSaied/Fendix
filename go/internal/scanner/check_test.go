package scanner

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestDefaultChecks_OrderAndConfigleakFirst(t *testing.T) {
	got := DefaultChecks()
	if len(got) == 0 || got[0].Name() != "configleak" {
		t.Fatalf("expected configleak first, got %v", names(got))
	}
}

func TestChecks_EnabledMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *models.ScanConfig
		enabled []string // expected enabled check names
	}{
		{"bare", &models.ScanConfig{}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags"}},
		{"active", &models.ScanConfig{EnableActive: true}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "injection", "open-redirect"}},
		{"auth", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "auth"}},
		{"auth2", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}, AuthUser2: &models.AuthContext{Value: "y"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "auth", "idor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var enabled []string
			for _, c := range DefaultChecks() {
				if c.Enabled(tc.cfg) {
					enabled = append(enabled, c.Name())
				}
			}
			if !subsetEqual(enabled, tc.enabled) {
				t.Errorf("cfg %s: enabled=%v want superset-ordered %v", tc.name, enabled, tc.enabled)
			}
		})
	}
}

func names(cs []Check) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name())
	}
	return out
}

func subsetEqual(got, want []string) bool {
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
	}
	for _, g := range got {
		if !w[g] {
			return false
		}
	}
	return len(got) == len(want)
}
