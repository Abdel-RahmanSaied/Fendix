package secrets

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// secretKeys reduces findings in files under prefix to "id @ endpoint".
func secretKeys(fs []evidence.Evidence, prefix string) []string {
	var out []string
	for _, f := range fs {
		if strings.HasPrefix(f.Endpoint, prefix) {
			out = append(out, f.ID+" @ "+f.Endpoint)
		}
	}
	sort.Strings(out)
	return out
}

// Regression guard: the secrets scanner already resolves its root before
// diff-aware filtering, so `code: "."`, `"./"` and an absolute root report the
// changed file's findings at the same endpoints as the full walk. It must stay
// that way.
func TestScanWithAllowlist_RelativeRootMatchesAbsoluteRoot(t *testing.T) {
	abs, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed(t, abs, "config/settings.py")
	seed(t, abs, "unchanged.py")
	t.Chdir(abs)

	full, err := Scan(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	want := secretKeys(full, "config/settings.py")
	if len(want) == 0 {
		t.Fatalf("seed produced no finding in config/settings.py: %v", secretKeys(full, ""))
	}
	for _, codePath := range []string{".", "./", abs} {
		got, err := ScanWithAllowlist(context.Background(), codePath, gitdiff.NewAllowlist(codePath, []string{"config/settings.py"}))
		if err != nil {
			t.Fatalf("code %q: %v", codePath, err)
		}
		if keys := secretKeys(got, ""); !reflect.DeepEqual(keys, want) {
			t.Errorf("code %q: diff scan reported %v, want %v", codePath, keys, want)
		}
	}
}
