package scanner

import (
	"strings"
	"testing"
)

// §16 — the check bursts each operation independently and looks for a 429 or a
// rate-limit header. That design cannot distinguish an operation-level limiter
// from a shared gateway one: it observes only whether THIS operation answered
// with a limit inside the burst.
//
// So the finding must not imply per-operation granularity it never measured.
// A sweep reporting 883 independent "this operation is unlimited" facts is
// overclaiming when all 883 may sit behind one perimeter that simply was not
// reached within 20 requests.
func TestFindingScopesItsClaimToWhatTheProbeEstablished(t *testing.T) {
	r := newMethodRecorder(t)
	found := runRateLimit(t, r, r.endpoint("GET", "/api/items"), false)
	if len(found) != 1 {
		t.Fatalf("expected one finding, got %d", len(found))
	}
	ev := found[0].Evidence

	if !strings.Contains(ev, "cannot prove the absence") {
		t.Errorf("the bounded-burst caveat is missing: %q", ev)
	}
	if !strings.Contains(strings.ToLower(ev), "per-operation") {
		t.Errorf("the finding does not disclaim per-operation granularity it never measured: %q", ev)
	}
	if !strings.Contains(strings.ToLower(ev), "gateway") {
		t.Errorf("the finding does not name the shared-limiter alternative it cannot rule out: %q", ev)
	}
}
