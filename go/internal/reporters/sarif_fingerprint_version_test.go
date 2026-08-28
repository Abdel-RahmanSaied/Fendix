package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// §8 — the fingerprint SCHEME is versioned in the key, so a consumer that
// baselined on v1 hashes never silently matches them against v2 hashes. The
// key must name the algorithm this build actually produces.
func TestPartialFingerprintKeyNamesTheAlgorithmInUse(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "a1b2c3", Title: "Missing auth",
		Severity: models.SeverityHigh, Source: models.SourceBlackbox,
		Category: "auth", Endpoint: "GET /api/users",
	}
	if err := RenderSARIF(&buf, []models.Finding{f}, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	fps := log.Runs[0].Results[0].PartialFingerprints
	if _, ok := fps[models.FingerprintAlgorithm]; !ok {
		t.Errorf("no key for the algorithm this build produces (%s); got %v",
			models.FingerprintAlgorithm, fps)
	}
	if _, ok := fps["fendix/v1"]; ok {
		t.Error("v2 identities are still published under the v1 key — a v1 baseline would match them by mistake")
	}
}

// SARIF distinguishes `fingerprints` (the tool asserts these are THE identity)
// from `partialFingerprints` (inputs a consumer may combine for baseline
// matching). Fendix's is a complete, self-sufficient identity, but GitHub Code
// Scanning consumes partialFingerprints for alert matching and ignores
// fingerprints — so partialFingerprints is where it has to be to do its job.
func TestFingerprintUsesThePartialFingerprintsMechanism(t *testing.T) {
	var buf bytes.Buffer
	f := models.Finding{
		ID: "SEC-001", Fingerprint: "a1b2c3", Title: "x",
		Severity: models.SeverityLow, Category: "auth", Endpoint: "GET /x",
	}
	if err := RenderSARIF(&buf, []models.Finding{f}, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	res := raw["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	if _, ok := res["partialFingerprints"]; !ok {
		t.Error("identity is not published where GitHub reads it")
	}
}
