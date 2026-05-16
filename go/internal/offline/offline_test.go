package offline

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleAdvisories() []Advisory {
	return []Advisory{
		{
			ID:      "GHSA-aaaa-bbbb-cccc",
			Aliases: []string{"CVE-2026-0001"},
			Package: PackageRef{Ecosystem: "PyPI", Name: "flask"},
			Ranges:  []Range{{Introduced: "0.0.0", Fixed: "2.3.0"}},
			Summary: "Flask SSRF",
		},
		{
			ID:      "GHSA-zzzz-yyyy-xxxx",
			Aliases: []string{"CVE-2026-0002"},
			Package: PackageRef{Ecosystem: "npm", Name: "lodash"},
			Ranges:  []Range{{Introduced: "0.0.0", Fixed: "4.17.21"}},
			Summary: "Lodash prototype pollution",
		},
	}
}

func TestWriteAndReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "offline-db.json")
	snap := FromOSVExport(sampleAdvisories(), []string{"osv.dev"})
	if err := Write(path, snap); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Advisories) != 2 {
		t.Errorf("got %d advisories; want 2", len(got.Advisories))
	}
	if got.Schema != SchemaVersion {
		t.Errorf("schema = %d; want %d", got.Schema, SchemaVersion)
	}
	if got.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt should be set after Write")
	}
}

func TestRead_MissingReturnsSentinel(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, ErrSnapshotMissing) {
		t.Errorf("err = %v; want ErrSnapshotMissing", err)
	}
}

func TestDecode_SchemaMismatch(t *testing.T) {
	data := []byte(`{"schema": 999, "advisories": []}`)
	_, err := Decode(data)
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("err = %v; want ErrSchemaMismatch", err)
	}
}

func TestVerify_StableHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "offline-db.json")
	snap := FromOSVExport(sampleAdvisories(), []string{"osv.dev"})
	// Pin GeneratedAt so the hash is stable across runs of this test.
	snap.GeneratedAt = time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if err := Write(path, snap); err != nil {
		t.Fatal(err)
	}
	h1, _, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if h1 == "" || len(h1) != 64 {
		t.Errorf("hash %q does not look like SHA-256 hex", h1)
	}
	h2, _, _ := Verify(path)
	if h1 != h2 {
		t.Errorf("hash not stable across reads: %q vs %q", h1, h2)
	}
}

func TestLookupByPackage_CaseInsensitiveEcosystem(t *testing.T) {
	snap := FromOSVExport(sampleAdvisories(), nil)
	got := snap.LookupByPackage("pypi", "flask") // lowercased ecosystem
	if len(got) != 1 {
		t.Fatalf("got %d advisories; want 1", len(got))
	}
	if got[0].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("wrong advisory matched: %q", got[0].ID)
	}
	// Wrong package name returns empty (no fuzzy match).
	if got := snap.LookupByPackage("PyPI", "FLASK"); len(got) != 0 {
		t.Errorf("case-sensitive name should NOT match: got %d", len(got))
	}
}

func TestLookupByPackage_NoMatches(t *testing.T) {
	snap := FromOSVExport(sampleAdvisories(), nil)
	if got := snap.LookupByPackage("Crates", "tokio"); len(got) != 0 {
		t.Errorf("unexpected matches: %v", got)
	}
}

func TestSummary_ContainsKeyFields(t *testing.T) {
	snap := FromOSVExport(sampleAdvisories(), []string{"osv.dev"})
	snap.GeneratedAt = time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	summary := snap.Summary()
	for _, want := range []string{"schema=1", "advisories=2", "osv.dev", "2026-05-15"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q: %s", want, summary)
		}
	}
}

func TestWrite_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "offline-db.json")
	snap := FromOSVExport(sampleAdvisories(), nil)
	if err := Write(path, snap); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created at %s: %v", path, err)
	}
}
