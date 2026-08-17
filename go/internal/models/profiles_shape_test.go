package models

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/fendix-yaml.md showed a FLAT profile shape (`type:` / `value:` at the
// top level) that the parser cannot read. It unmarshalled cleanly into a
// zero-valued struct, so LoadProfileFrom returned (nil, nil) and the scan ran
// completely unauthenticated with no diagnostic — a security control failing
// silently. The doc is fixed; these lock the parser's half.

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProfileFrom_FlatShapeIsALoudError(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"type and value", "type: bearer\nvalue: secret-token\n"},
		{"value only", "value: secret-token\n"},
		{"with header", "type: apikey\nvalue: k\nheader: X-API-Key\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := LoadProfileFrom(writeProfile(t, tc.body))
			if err == nil {
				t.Fatalf("flat profile parsed silently to %+v — a mis-nested credential must\n"+
					"be an error, not an unauthenticated scan", auth)
			}
			if auth != nil {
				t.Errorf("expected nil auth alongside the error, got %+v", auth)
			}
			// The message has to carry the correction, not just the complaint.
			for _, want := range []string{"auth:", "nested"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should mention %q: %v", want, err)
				}
			}
			// It must never echo the credential itself.
			if strings.Contains(err.Error(), "secret-token") {
				t.Errorf("error leaked the credential value: %v", err)
			}
		})
	}
}

func TestLoadProfileFrom_NestedShapeStillWorks(t *testing.T) {
	auth, err := LoadProfileFrom(writeProfile(t,
		"auth:\n  type: bearer\n  value: tok\n  header: Authorization\n"))
	if err != nil {
		t.Fatalf("canonical nested profile failed: %v", err)
	}
	if auth == nil || auth.Value != "tok" || auth.Type != "bearer" {
		t.Fatalf("unexpected auth: %+v", auth)
	}
}

// An genuinely empty profile is still a legitimate no-op, not an error — only
// a credential at the WRONG depth is a mistake worth failing on.
func TestLoadProfileFrom_EmptyProfileIsNotAnError(t *testing.T) {
	for _, body := range []string{"", "auth:\n", "# just a comment\n"} {
		auth, err := LoadProfileFrom(writeProfile(t, body))
		if err != nil {
			t.Errorf("empty profile %q should not error: %v", body, err)
		}
		if auth != nil {
			t.Errorf("empty profile %q should yield nil auth, got %+v", body, auth)
		}
	}
}

func TestLoadProfileFrom_MissingFileIsNotAnError(t *testing.T) {
	auth, err := LoadProfileFrom(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || auth != nil {
		t.Errorf("missing profile should be (nil, nil), got (%+v, %v)", auth, err)
	}
}
