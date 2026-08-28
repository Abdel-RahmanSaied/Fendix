package applicability

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func treeWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func djangoGisFinding() evidence.Evidence {
	return evidence.Evidence{
		Title:      "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
		Evidence:   "django==5.2.16: GeoDjango GEOSGeometry denial of service via contrib.gis",
		References: []string{"CVE-2026-15830"},
		// componentsFor scopes an advisory via (deps.ecosystem, deps.package)
		// plus a match on the advisory's own text — the metadata the dep
		// scanners stamp.
		Metadata: map[string]string{"deps.ecosystem": "PyPI", "deps.package": "django"},
	}
}

// The affected component is NOT imported anywhere → evidence against
// applicability. This is the state that must materially change the decision.
func TestResolveMarksEvidenceAgainstWhenComponentIsAbsent(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/views.py": "from django.http import JsonResponse\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q, want %q", got, models.ApplicabilityEvidenceAgainst)
	}
}

// The affected component IS imported → evidence FOR applicability. This is the
// state the old bool could not express: it left the field false, identical to
// "never evaluated", so a downstream reader could not tell a cleared check from
// one that never ran.
func TestResolveMarksApplicableWhenComponentIsImported(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/geo.py": "from django.contrib.gis.geos import GEOSGeometry\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityApplicable {
		t.Errorf("Applicability = %q, want %q — the component is imported, which is a positive "+
			"claim the old ComponentNotImported bool could not make", got, models.ApplicabilityApplicable)
	}
	if out[0].ComponentNotImported {
		t.Error("ComponentNotImported = true for an imported component")
	}
}

// An advisory with no importable component known to the catalog was never
// evaluated. That must stay UNKNOWN — not Applicable, not EvidenceAgainst.
func TestResolveLeavesUnknownWhenNoComponentIsKnown(t *testing.T) {
	root := treeWith(t, map[string]string{"app/views.py": "print('hi')\n"})

	ev := evidence.Evidence{
		Title:      "Vulnerable dependency: leftpad==1.0.0 (CVE-2026-00000)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
	}
	out := Resolve(root, []evidence.Evidence{ev})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityUnknown {
		t.Errorf("Applicability = %q, want unknown — no component was evaluated", got)
	}
}

// Dynamic/ambiguous loading. A tree that reaches the component only through
// importlib must NOT be reported as evidence-against on the strength of a
// missing static import — but the static grep genuinely cannot see it, so the
// honest outcome is that Fendix's claim stays as weak as its evidence.
//
// This test documents the KNOWN LIMIT rather than asserting a capability
// Fendix does not have: the string "django.contrib.gis" appearing in an
// importlib call is still matched by the import grep, so this case resolves to
// Applicable. A truly obfuscated dynamic import (assembled at runtime from
// fragments) is a documented false-negative of the applicability analyzer, and
// is why EvidenceAgainst de-escalates rather than suppresses.
func TestResolveSeesDynamicImportsThatNameTheComponentLiterally(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/dyn.py": "import importlib\nm = importlib.import_module('django.contrib.gis.geos')\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got == models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q — a dynamic import that names the component literally was "+
			"reported as evidence of NON-applicability, which would silence a real risk", got)
	}
}
