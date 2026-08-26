package evidence

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// fullyPopulatedFinding returns a Finding with EVERY exported field set to a
// distinctive non-zero value. The drift guard below asserts no field is zero,
// so if someone adds a field to models.Finding this sample (and therefore the
// adapter) must be updated — the round-trip identity can't silently drop it.
func fullyPopulatedFinding() models.Finding {
	line := "src/app.py:42"
	return models.Finding{
		ID:                "SEC-001",
		Fingerprint:       "abc123",
		Title:             "SQL injection",
		Severity:          models.SeverityCritical,
		Source:            models.SourceCorrelated,
		Category:          "injection",
		Endpoint:          "/api/users",
		AffectedEndpoints: []string{"/api/users", "/api/admin"},
		Evidence:          "param id reaches cursor.execute | Code: src/app.py:42",
		Fix:               "Use parameterized queries",
		References:        []string{"CWE-89"},
		Confidence:        models.ConfidenceHigh,
		Line:              &line,
		TaintChain:        []models.TaintLink{{File: "src/app.py", Line: 42, Expr: "request.args.get('id')"}},
		Reachable:         true,
		SourceTier:        models.TierTreeSitter,
		Route:             &models.Route{Method: "GET", Pattern: "/api/users", Handler: "views.list_users", File: "urls.py", Line: 7},
		RouteConfirmed:    true,
		ProvenPath:        true,
		Status:            "BLOCK",
		ConfidenceScore:   100,
		ConfidenceBand:    "HIGH",
		ConfidenceReasons: []string{"+35 base", "+25 cross-engine agreement"},
	}
}

// notRoundTripped names the Finding fields that are DELIBERATELY absent from
// the Evidence↔Finding adapter, and therefore exempt from the sample-
// completeness guard below.
//
// Only the cross-tool corroboration pair qualifies. Those two are stamped by
// engine.stampDecisions from the POST-Restore evidence, so the published
// value is the proof-union over the dedup group. Mapping them through
// ToFinding would put a pre-dedup value on the projection, and mapping them
// through FromFinding would let a pre-set value block ProvenanceIndex.Restore
// (it only fills what is empty) — either way reintroducing the erasure the
// proof-union fold exists to prevent, on a public surface.
//
// TestExemptFieldsAreGenuinelyNotMapped keeps this list honest: an entry here
// must actually fail to round-trip, so a field cannot be parked here to
// silence the guard while quietly being mapped.
var notRoundTripped = map[string]string{
	"CrossToolCorroborated": "stamped by engine.stampDecisions from restored evidence",
	"CorroboratingTools":    "stamped by engine.stampDecisions from restored evidence",
}

// TestFindingSampleExercisesEveryField is the drift guard: it fails if any
// exported field of the sample Finding is the zero value, forcing the sample
// (and the adapter it backs) to stay complete as models.Finding evolves.
func TestFindingSampleExercisesEveryField(t *testing.T) {
	v := reflect.ValueOf(fullyPopulatedFinding())
	tp := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name := tp.Field(i).Name
		if !tp.Field(i).IsExported() {
			continue
		}
		if _, exempt := notRoundTripped[name]; exempt {
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("Finding.%s is zero in the round-trip sample — populate it AND map it in From/ToFinding", name)
		}
	}
}

// TestExemptFieldsAreGenuinelyNotMapped turns the exemption list from a hole
// into a positive assertion: each exempt field, when populated on a Finding,
// must come back ZERO from a FromFinding→ToFinding round trip. If someone
// later maps one through the adapter, this fails and the exemption has to be
// removed rather than quietly becoming a lie.
func TestExemptFieldsAreGenuinelyNotMapped(t *testing.T) {
	f := fullyPopulatedFinding()
	f.CrossToolCorroborated = true
	f.CorroboratingTools = []string{"codeql"}

	got := FromFinding(f).ToFinding()

	v := reflect.ValueOf(got)
	for name, why := range notRoundTripped {
		field := v.FieldByName(name)
		if !field.IsValid() {
			t.Fatalf("notRoundTripped names %q, which is not a Finding field", name)
		}
		if !field.IsZero() {
			t.Errorf("Finding.%s survived the round trip but is listed as not mapped (%s) — "+
				"either stop mapping it or drop it from notRoundTripped", name, why)
		}
	}
}

// TestRoundTripIdentity is the core v0.22 invariant: lifting a Finding into
// Evidence and projecting it back must reproduce the Finding exactly.
func TestRoundTripIdentity(t *testing.T) {
	orig := fullyPopulatedFinding()
	got := FromFinding(orig).ToFinding()
	if !reflect.DeepEqual(orig, got) {
		t.Errorf("round-trip changed the Finding:\n orig=%+v\n got =%+v", orig, got)
	}
}

// TestRoundTripJSONByteIdentical proves the PUBLIC contract is preserved: the
// marshaled JSON of a round-tripped Finding is byte-identical to the original.
func TestRoundTripJSONByteIdentical(t *testing.T) {
	orig := fullyPopulatedFinding()
	want, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(FromFinding(orig).ToFinding())
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Errorf("JSON drifted after round-trip:\n want %s\n got  %s", want, got)
	}
}

// TestProvenanceIsInternal confirms the new v0.22 fields live on Evidence but
// do NOT leak into the projected Finding (and thus not into the JSON).
func TestProvenanceIsInternal(t *testing.T) {
	e := FromFinding(fullyPopulatedFinding())
	e.RuleID = "python.sqli.cursor-execute"
	e.Payload = "id=1' OR '1'='1"
	e.Response = "HTTP 500 ... SQL syntax error"
	e.DetectedAt = time.Unix(1700000000, 0)
	e.Metadata = map[string]string{"scanner": "ast"}
	e.Lineage = []Evidence{{Source: models.SourceBlackbox}, {Source: models.SourceWhitebox}}

	f := e.ToFinding()
	blob, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"python.sqli.cursor-execute", "OR '1'='1", "SQL syntax error", "1700000000"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("internal provenance %q leaked into Finding JSON: %s", leak, blob)
		}
	}
}

func TestSliceHelpersAndNil(t *testing.T) {
	if FromFindings(nil) != nil {
		t.Error("FromFindings(nil) should be nil")
	}
	if ToFindings(nil) != nil {
		t.Error("ToFindings(nil) should be nil")
	}
	fs := []models.Finding{fullyPopulatedFinding(), {ID: "SEC-002", Title: "x"}}
	got := ToFindings(FromFindings(fs))
	if !reflect.DeepEqual(fs, got) {
		t.Errorf("slice round-trip changed findings")
	}
}
