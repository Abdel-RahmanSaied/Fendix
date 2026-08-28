package models

import "testing"

// RC-5 reproduction: a finding's fingerprint is its LONG-LIVED IDENTITY. It
// must survive everything that changes where a vulnerability sits without
// changing what the vulnerability is — line shifts, inserted comments,
// reformatting — and it must still separate genuinely distinct vulnerabilities.
//
// These tests are written against the semantic-identity contract, not against
// sha1(Category|Endpoint|Title). Under the v1 scheme the location-invariance
// cases fail, which is exactly the defect.

// whiteboxSSRF is one logical source→sink SSRF finding in one symbol. Helpers
// take the location so a test can move the SAME finding around a file.
func whiteboxSSRF(file string, line int) Finding {
	return Finding{
		Category:   "ssrf",
		RuleID:     "python.ssrf.taint",
		Source:     SourceWhitebox,
		SourceTier: TierTreeSitter,
		Title:      "SSRF — user-controlled URL reaches HTTP client",
		Endpoint:   fileLine(file, line),
		Line:       strptr(fileLine(file, line)),
		Route:      &Route{Handler: "fetch_image"},
		TaintChain: []TaintLink{
			{File: file, Line: line - 2, Expr: "request.query_params.get('url')"},
			{File: file, Line: line, Expr: "requests.get(url)"},
		},
	}
}

func TestFingerprintIsStableForTheSameFindingInTheSameSource(t *testing.T) {
	f := whiteboxSSRF("app/views.py", 100)
	if Fingerprint(f) != Fingerprint(f) {
		t.Fatal("fingerprint is not deterministic for identical input")
	}
}

// The RC-5 headline: one unrelated line inserted above the vulnerability
// shifts every line number by one. The vulnerability did not change.
func TestFingerprintSurvivesALineShift(t *testing.T) {
	at100 := Fingerprint(whiteboxSSRF("app/views.py", 100))
	at101 := Fingerprint(whiteboxSSRF("app/views.py", 101))
	if at100 != at101 {
		t.Errorf("line shift changed identity:\n  line 100 = %s\n  line 101 = %s\n"+
			"a vulnerability that moved down one line is the same vulnerability", at100, at101)
	}
}

// Comments added above the finding are a line shift plus nothing. Same
// invariant, stated separately because this is the case users actually hit.
func TestFingerprintSurvivesCommentsInsertedAbove(t *testing.T) {
	before := Fingerprint(whiteboxSSRF("app/views.py", 42))
	after := Fingerprint(whiteboxSSRF("app/views.py", 55)) // 13 comment lines added
	if before != after {
		t.Errorf("inserting comments above the finding changed identity: %s != %s", before, after)
	}
}

// Reformatting moves a call across lines and re-spaces the expression. The
// normalized vulnerable operation is unchanged.
func TestFingerprintSurvivesReformatting(t *testing.T) {
	original := whiteboxSSRF("app/views.py", 100)

	reformatted := whiteboxSSRF("app/views.py", 118)
	reformatted.TaintChain = []TaintLink{
		{File: "app/views.py", Line: 114, Expr: "request.query_params.get( 'url' )"},
		{File: "app/views.py", Line: 118, Expr: "requests.get( url )"},
	}

	if Fingerprint(original) != Fingerprint(reformatted) {
		t.Errorf("reformatting changed identity:\n  original    = %s\n  reformatted = %s",
			Fingerprint(original), Fingerprint(reformatted))
	}
}

// Collision guard: two distinct vulnerable operations under the same rule in
// the same file are two vulnerabilities. Dropping the line number must not
// merge them.
func TestFingerprintSeparatesDistinctOperationsInOneFile(t *testing.T) {
	first := whiteboxSSRF("app/views.py", 100)
	first.Route = &Route{Handler: "first"}

	second := whiteboxSSRF("app/views.py", 200)
	second.Route = &Route{Handler: "second"}
	second.TaintChain = []TaintLink{
		{File: "app/views.py", Line: 198, Expr: "request.query_params.get('target')"},
		{File: "app/views.py", Line: 200, Expr: "requests.get(other_url)"},
	}

	if Fingerprint(first) == Fingerprint(second) {
		t.Errorf("two distinct vulnerable operations collapsed to one identity: %s", Fingerprint(first))
	}
}

// Two sinks inside ONE symbol are still two vulnerable operations.
func TestFingerprintSeparatesTwoSinksInOneSymbol(t *testing.T) {
	base := whiteboxSSRF("app/views.py", 100)

	sibling := whiteboxSSRF("app/views.py", 101)
	sibling.TaintChain = []TaintLink{
		{File: "app/views.py", Line: 98, Expr: "request.query_params.get('url')"},
		{File: "app/views.py", Line: 101, Expr: "urllib.request.urlopen(url_b)"},
	}

	if Fingerprint(base) == Fingerprint(sibling) {
		t.Errorf("two sinks in one symbol collapsed to one identity: %s", Fingerprint(base))
	}
}

func TestFingerprintSeparatesTheSameRuleInDifferentFiles(t *testing.T) {
	a := whiteboxSSRF("app/views.py", 100)
	b := whiteboxSSRF("app/admin.py", 100)
	if Fingerprint(a) == Fingerprint(b) {
		t.Errorf("the same rule in two files collapsed to one identity: %s", Fingerprint(a))
	}
}

// --- dependencies -------------------------------------------------------

func depFinding(advisory, ecosystem, pkg, version, manifest string) Finding {
	return Finding{
		Category:   "deps",
		RuleID:     advisory,
		Source:     SourceWhitebox,
		Title:      "Vulnerable dependency: " + pkg + "==" + version + " (" + advisory + ")",
		Endpoint:   manifest,
		Line:       strptr(manifest),
		Dependency: &DependencyRef{Ecosystem: ecosystem, Package: pkg, Version: version, Manifest: manifest},
	}
}

func TestFingerprintIsStableForTheSameAdvisoryAndPackage(t *testing.T) {
	a := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	b := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("identical dependency findings disagree: %s != %s", Fingerprint(a), Fingerprint(b))
	}
}

func TestFingerprintSeparatesTheSameAdvisoryAcrossPackages(t *testing.T) {
	a := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	b := depFinding("CVE-2026-69247", "PyPI", "urllib3", "1.26.0", "requirements.txt")
	if Fingerprint(a) == Fingerprint(b) {
		t.Errorf("one advisory affecting two packages collapsed to one identity: %s", Fingerprint(a))
	}
}

// A vulnerable package upgraded to another STILL-vulnerable version is the
// same unresolved vulnerability. The version rides in the title today, which
// is why the v1 scheme churns here.
func TestFingerprintSurvivesAStillVulnerableVersionBump(t *testing.T) {
	before := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	after := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.1", "requirements.txt")
	if Fingerprint(before) != Fingerprint(after) {
		t.Errorf("a still-vulnerable version bump changed identity: %s != %s",
			Fingerprint(before), Fingerprint(after))
	}
}

// --- blackbox -----------------------------------------------------------

func TestFingerprintSeparatesMethodsOnOneRoute(t *testing.T) {
	get := Finding{
		Category: "auth", RuleID: "auth.missing", Source: SourceBlackbox,
		Title: "Endpoint served without authentication", Endpoint: "GET /api/users/{id}",
	}
	del := get
	del.Endpoint = "DELETE /api/users/{id}"
	if Fingerprint(get) == Fingerprint(del) {
		t.Errorf("GET and DELETE on one route collapsed to one identity: %s", Fingerprint(get))
	}
}

// The same endpoint issue observed on a later scan is the same issue.
func TestFingerprintIsStableForAnEndpointAcrossScans(t *testing.T) {
	scan1 := Finding{
		Category: "cors", RuleID: "cors.wildcard", Source: SourceBlackbox,
		Title: "Wildcard CORS origin", Endpoint: "GET /api/data",
		Evidence: "Access-Control-Allow-Origin: * (observed 2026-08-01)",
	}
	scan2 := scan1
	scan2.Evidence = "Access-Control-Allow-Origin: * (observed 2026-08-28)"
	if Fingerprint(scan1) != Fingerprint(scan2) {
		t.Errorf("the same endpoint issue re-observed changed identity: %s != %s",
			Fingerprint(scan1), Fingerprint(scan2))
	}
}

func strptr(s string) *string { return &s }

// fileLine renders the "path:line" endpoint form the whitebox scanners emit.
func fileLine(file string, line int) string {
	return file + ":" + itoa(line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
