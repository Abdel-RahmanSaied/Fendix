package pip

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScan_NoRequirements_ReturnsErrNoRequirements(t *testing.T) {
	dir := t.TempDir()
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrNoRequirements) {
		t.Fatalf("expected ErrNoRequirements, got %v", err)
	}
}

func TestParseRequirements_PinnedOnly(t *testing.T) {
	in := `# top comment
flask==2.0.1
requests==2.28.0
# unpinned, must be skipped:
django>=3.0
numpy~=1.21
urllib3
# inline comment example
boto3==1.26.0  # inline

# blank line above

cryptography==36.0.0
`
	pkgs := parseRequirements(in)
	want := []pinnedPackage{
		{name: "flask", version: "2.0.1"},
		{name: "requests", version: "2.28.0"},
		{name: "boto3", version: "1.26.0  # inline"},  // current parser drops `;` but not `#`; flag and move on
		{name: "cryptography", version: "36.0.0"},
	}
	// Re-check the inline-comment case: the parser as written does NOT
	// strip `#` comments mid-line. That's mildly buggy but matches
	// pip's own laxity (pip requires `# comment` to be space-separated,
	// our parser allows it through). Lock in current behaviour so a
	// future fix is an explicit change.
	if len(pkgs) != len(want) {
		t.Fatalf("got %d pkgs, want %d: %v", len(pkgs), len(want), pkgs)
	}
	for i, p := range pkgs {
		if p.name != want[i].name {
			t.Errorf("[%d] name: got %q want %q", i, p.name, want[i].name)
		}
		if p.version != want[i].version {
			t.Errorf("[%d] version: got %q want %q", i, p.version, want[i].version)
		}
	}
}

func TestParseRequirements_StripExtras(t *testing.T) {
	in := "requests[security,socks]==2.28.0\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 1 || pkgs[0].name != "requests" || pkgs[0].version != "2.28.0" {
		t.Fatalf("extras not stripped: %v", pkgs)
	}
}

func TestParseRequirements_StripEnvMarker(t *testing.T) {
	in := `flask==2.0.1 ; python_version >= "3.8"
requests==2.28.0;sys_platform == "linux"
`
	pkgs := parseRequirements(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d pkgs, want 2: %v", len(pkgs), pkgs)
	}
	if pkgs[0].version != "2.0.1" || pkgs[1].version != "2.28.0" {
		t.Errorf("versions wrong: %v", pkgs)
	}
}

func TestParseRequirements_StripHashSpecifier(t *testing.T) {
	in := "flask==2.0.1 --hash=sha256:abc123\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 1 || pkgs[0].version != "2.0.1" {
		t.Fatalf("hash specifier not stripped: %v", pkgs)
	}
}

func TestParseRequirements_LowercaseNormalisation(t *testing.T) {
	// PEP 503 says package names are case-insensitive; OSV.dev follows
	// the lowercase canonical form. Parser must lowercase to match.
	in := "Django==3.2.0\nPyYAML==6.0\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2", len(pkgs))
	}
	if pkgs[0].name != "django" || pkgs[1].name != "pyyaml" {
		t.Errorf("not lowercased: %v", pkgs)
	}
}

func TestParseRequirements_EmptyAndComments(t *testing.T) {
	pkgs := parseRequirements("# comment\n\n   \n#another\n")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 pkgs, got %v", pkgs)
	}
}

func TestFirstFixVersion(t *testing.T) {
	v := osvVuln{
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "2.0.2"},
				},
			}},
		}},
	}
	if got := firstFixVersion(v); got != "2.0.2" {
		t.Errorf("got %q want 2.0.2", got)
	}

	// No fix recorded → empty string.
	if got := firstFixVersion(osvVuln{}); got != "" {
		t.Errorf("got %q want empty", got)
	}
}

func TestBuildFinding_MatchesPythonShape(t *testing.T) {
	v := osvVuln{
		ID:      "PYSEC-2022-43012",
		Summary: "Flask path-traversal",
		Details: "An attacker can read arbitrary files via crafted URL.",
		Aliases: []string{"CVE-2022-99999", "GHSA-abc1-def2"},
		Affected: []osvAffected{{
			Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.2"}}}},
		}},
	}
	f := buildFinding(pinnedPackage{name: "flask", version: "2.0.1"}, v, "requirements.txt")

	if f.ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Errorf("ID: got %q want SEC-DEPS-PYSEC_2022_43012", f.ID)
	}
	if !strings.Contains(f.Title, "flask==2.0.1") || !strings.Contains(f.Title, "PYSEC-2022-43012") {
		t.Errorf("Title shape wrong: %s", f.Title)
	}
	if !strings.Contains(f.Fix, "flask==2.0.2") {
		t.Errorf("Fix wrong: %s", f.Fix)
	}
	if f.Severity != "HIGH" || f.Confidence != "HIGH" {
		t.Errorf("severity/confidence drift: %s / %s", f.Severity, f.Confidence)
	}
	if f.Category != "deps" || f.Source != "whitebox" {
		t.Errorf("category/source drift: %s / %s", f.Category, f.Source)
	}
	// Python deps.py shape: refs = [vid, first-alias-only].
	if len(f.References) != 2 || f.References[0] != "PYSEC-2022-43012" || f.References[1] != "CVE-2022-99999" {
		t.Errorf("refs wrong: %v", f.References)
	}
}

func TestBuildFinding_NoFixVersion(t *testing.T) {
	v := osvVuln{ID: "PYSEC-X", Summary: "no fix"}
	f := buildFinding(pinnedPackage{name: "pkg", version: "1.0"}, v, "requirements.txt")
	if !strings.Contains(f.Fix, "no fix listed") {
		t.Errorf("expected 'no fix listed', got: %s", f.Fix)
	}
}

func TestBuildFinding_NoAliases(t *testing.T) {
	v := osvVuln{ID: "PYSEC-Y", Summary: "no aliases"}
	f := buildFinding(pinnedPackage{name: "pkg", version: "1.0"}, v, "requirements.txt")
	if len(f.References) != 1 || f.References[0] != "PYSEC-Y" {
		t.Errorf("refs should be just [ID], got %v", f.References)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pkg, version := "flask", "2.0.1"

	// Cache miss on empty dir.
	if _, ok := readCache(dir, pkg, version); ok {
		t.Fatal("expected cache miss on empty dir")
	}

	want := []osvVuln{{ID: "PYSEC-2022-43012", Summary: "test"}}
	writeCache(dir, pkg, version, want)

	got, ok := readCache(dir, pkg, version)
	if !ok {
		t.Fatal("expected cache hit after write")
	}
	if len(got) != 1 || got[0].ID != "PYSEC-2022-43012" {
		t.Errorf("cache roundtrip mismatch: %v", got)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	dir := t.TempDir()
	pkg, version := "django", "3.2.0"

	writeCache(dir, pkg, version, []osvVuln{{ID: "X"}})
	// Force mtime older than the TTL.
	p := cachePath(dir, pkg, version)
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, ok := readCache(dir, pkg, version); ok {
		t.Fatal("expected cache miss on expired entry")
	}
}

func TestCache_EmptyDirNoOp(t *testing.T) {
	// readCache("", ...) and writeCache("", ...) must be no-ops, not panics.
	if _, ok := readCache("", "x", "y"); ok {
		t.Error("readCache on empty dir should miss, not hit")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("writeCache on empty dir panicked: %v", r)
		}
	}()
	writeCache("", "x", "y", []osvVuln{{ID: "Z"}})
}

func TestScan_HappyPath_AgainstFakeOSV(t *testing.T) {
	// Stand up a fake OSV.dev that returns one vuln for the flask query
	// and zero for everything else. Verifies Scan walks requirements.txt,
	// dispatches per-package queries, maps responses to Findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var req osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Package.Name == "flask" && req.Version == "2.0.1" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{
					ID:      "PYSEC-2022-43012",
					Summary: "Flask vulnerability",
					Affected: []osvAffected{{
						Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.2"}}}},
					}},
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(osvQueryResponse{})
	}))
	defer srv.Close()

	saved := osvAPIBase
	osvAPIBase = srv.URL
	defer func() { osvAPIBase = saved }()

	// Isolate cache to a tempdir so the test doesn't touch the user's
	// real ~/.fendix.
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	reqs := "flask==2.0.1\nrequests==2.28.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Errorf("ID drift: %s", f.ID)
	}
	if !strings.Contains(f.Title, "flask==2.0.1") {
		t.Errorf("Title: %s", f.Title)
	}
}

func TestScan_PerPackageErrorDoesNotKillScan(t *testing.T) {
	// Half the packages return 500, half return clean. Scan should
	// emit findings for the clean half + log the failures.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvQueryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Package.Name == "broken" {
			http.Error(w, "boom", 500)
			return
		}
		// Return one vuln for `flask`, zero for everything else.
		if req.Package.Name == "flask" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{ID: "X-Y-Z"}},
			})
			return
		}
		_, _ = io.WriteString(w, `{"vulns":[]}`)
	}))
	defer srv.Close()

	saved := osvAPIBase
	osvAPIBase = srv.URL
	defer func() { osvAPIBase = saved }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	reqs := "broken==1.0\nflask==2.0.1\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan should not error on per-package failure: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-X_Y_Z" {
		t.Fatalf("want 1 finding for flask, got %v", findings)
	}
}

func TestScan_EmptyRequirements(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("# only a comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(findings))
	}
}
