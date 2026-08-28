package pip

import "testing"

// The v2 fingerprint keys a dependency finding on its DependencyRef. A
// scanner that leaves the ref nil pushes identity back onto the endpoint and
// the rendered title, which is the RC-5 defect it was built to fix — so the
// wiring is asserted here, at the emitter, not only in models.
func TestBuildFindingCarriesTheDependencyIdentity(t *testing.T) {
	ev := buildFinding(
		pinnedPackage{name: "requests", version: "2.28.0"},
		osvVuln{ID: "CVE-2026-69247", Summary: "SSRF in requests"},
		"requirements.txt",
	)

	if ev.Dependency == nil {
		t.Fatal("Dependency is nil — the v2 fingerprint has no package identity to key on")
	}
	if got := ev.Dependency.Ecosystem; got != "PyPI" {
		t.Errorf("Ecosystem = %q, want PyPI", got)
	}
	if got := ev.Dependency.Package; got != "requests" {
		t.Errorf("Package = %q, want requests", got)
	}
	if got := ev.Dependency.Version; got != "2.28.0" {
		t.Errorf("Version = %q, want 2.28.0", got)
	}
	if got := ev.Dependency.Manifest; got != "requirements.txt" {
		t.Errorf("Manifest = %q, want requirements.txt", got)
	}
}
