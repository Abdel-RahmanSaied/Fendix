package semgrep

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The v3.6.2 flask-route-no-auth-decorator message told users the auth
// decorator belongs "directly above the @app.route(...) line". Flask's route()
// must be the outermost decorator, so following that advice registered the
// unwrapped view and left the route unauthenticated. v3.6.3 corrects the
// message from "above" onwards only.
//
// A finding's Title is the first 120 bytes of the message (titleMaxLen) and
// feeds dedupKey, the v1 fingerprint and the backend's title-keyed fallbacks,
// so the correction must leave every Title byte-identical. These tests run the
// real embedded message, as Semgrep would fill it in, through mapResult.

// v362FlaskNoAuthMessage is the message as released in v3.6.2, with $FUNC
// still in place, kept to prove the corrected one files findings identically.
const v362FlaskNoAuthMessage = "Flask route '$FUNC' has no auth-style decorator (@login_required, @requires_auth, @jwt_required, or @auth.login_required) directly above the @app.route(...) line. Confirm authentication is enforced."

// Titles the v3.6.2 message produced, pinned byte for byte, for function names
// short and long enough to move where the 120-byte cut falls.
var v362FlaskNoAuthTitles = map[string]string{
	"x":                         "Flask route 'x' has no auth-style decorator (@login_required, @requires_auth, @jwt_required, or @auth.login_required) di",
	"view":                      "Flask route 'view' has no auth-style decorator (@login_required, @requires_auth, @jwt_required, or @auth.login_required)",
	"admin_view":                "Flask route 'admin_view' has no auth-style decorator (@login_required, @requires_auth, @jwt_required, or @auth.login_req",
	"download_quarterly_report": "Flask route 'download_quarterly_report' has no auth-style decorator (@login_required, @requires_auth, @jwt_required, or ",
}

func flaskNoAuthResult(message, fn string) *semgrepResult {
	return &semgrepResult{
		CheckID: "tmp.fendix-semgrep-rules-123.flask-route-no-auth-decorator",
		Path:    "app/views.py",
		Start:   semgrepLineCol{Line: 12},
		Extra: semgrepExtra{
			Message:  strings.ReplaceAll(message, "$FUNC", fn),
			Severity: "WARNING",
			Lines:    "@app.route(\"/admin\")",
			Metadata: map[string]interface{}{"category": "auth", "cwe": "CWE-306", "confidence": "LOW", "fendix_severity": "MEDIUM"},
			Metavars: map[string]semgrepMetavar{"$APP": {AbstractContent: "app"}, "$FUNC": {AbstractContent: fn}},
		},
	}
}

func TestFlaskNoAuthMessage_CorrectionKeepsEveryFindingIdentity(t *testing.T) {
	rule, ok := loadAllRules(t)["flask-route-no-auth-decorator"]
	if !ok {
		t.Fatal("flask-route-no-auth-decorator is not in the rule pack")
	}
	for fn, wantTitle := range v362FlaskNoAuthTitles {
		corrected, ok := mapResult(flaskNoAuthResult(rule.Message, fn), "")
		if !ok {
			t.Fatalf("%s: corrected message produced no finding", fn)
		}
		released, _ := mapResult(flaskNoAuthResult(v362FlaskNoAuthMessage, fn), "")
		got, was := corrected.ToFinding(), released.ToFinding()

		if got.Title != wantTitle {
			t.Errorf("%s: Title changed:\n got %q\nwant %q", fn, got.Title, wantTitle)
		}
		if models.Fingerprint(got) != models.Fingerprint(was) {
			t.Errorf("%s: fendix/v2 fingerprint changed with the message", fn)
		}
		if models.FingerprintV1(got) != models.FingerprintV1(was) {
			t.Errorf("%s: v1 fingerprint (category|endpoint|title) changed with the message", fn)
		}
		if dedupKeyOf(got) != dedupKeyOf(was) {
			t.Errorf("%s: grouping key changed with the message", fn)
		}
	}
}

func TestFlaskNoAuthMessage_FixPlacesTheDecoratorBelowTheRoute(t *testing.T) {
	rule := loadAllRules(t)["flask-route-no-auth-decorator"]
	ev, ok := mapResult(flaskNoAuthResult(rule.Message, "admin_view"), "")
	if !ok {
		t.Fatal("no finding")
	}
	fix := ev.ToFinding().Fix
	if strings.Contains(fix, "directly above") {
		t.Errorf("Fix still tells users to put the auth decorator above @app.route: %q", fix)
	}
	for _, want := range []string{"directly below the @app.route(...) line", "route() must be the outermost decorator", "does not protect the route"} {
		if !strings.Contains(fix, want) {
			t.Errorf("Fix is missing %q: %q", want, fix)
		}
	}
	if strings.Contains(fix, "\n") {
		t.Errorf("message must stay one folded line or the Title cut moves: %q", fix)
	}
}

// dedupKeyOf mirrors engine.dedupKey (Severity|Category|Title) for a
// non-imported finding; the semgrep package cannot import engine.
func dedupKeyOf(f models.Finding) string {
	return string(f.Severity) + "|" + f.Category + "|" + f.Title
}
