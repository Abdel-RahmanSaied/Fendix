package models

import "testing"

// §11 — identity must be structural, never presentational. The v1 scheme
// hashes Title, so retitling a finding as its evidence strengthens (RC-6)
// would silently re-file it as a brand-new vulnerability. These lock the
// separation between what a finding IS and how it is currently described,
// scored, or acted on.

func TestFingerprintIgnoresTheTitle(t *testing.T) {
	potential := whiteboxSSRF("app/views.py", 100)
	potential.Title = "Potential SSRF — dynamic URL reaches HTTP client"

	confirmed := whiteboxSSRF("app/views.py", 100)
	confirmed.Title = "SSRF — user-controlled URL reaches HTTP client"

	if Fingerprint(potential) != Fingerprint(confirmed) {
		t.Errorf("re-titling as evidence strengthened changed identity:\n  %s\n  %s",
			Fingerprint(potential), Fingerprint(confirmed))
	}
}

func TestFingerprintIgnoresTheDecision(t *testing.T) {
	warn := whiteboxSSRF("app/views.py", 100)
	warn.Status = "WARN"
	warn.DecisionReason = "no independent corroboration"

	block := whiteboxSSRF("app/views.py", 100)
	block.Status = "BLOCK"
	block.DecisionReason = "reachable taint path corroborated by active probe"

	if Fingerprint(warn) != Fingerprint(block) {
		t.Errorf("WARN→BLOCK changed identity: %s != %s", Fingerprint(warn), Fingerprint(block))
	}
}

func TestFingerprintIgnoresConfidence(t *testing.T) {
	low := whiteboxSSRF("app/views.py", 100)
	low.ConfidenceScore, low.ConfidenceBand, low.Confidence = 50, "MEDIUM", ConfidenceMedium

	high := whiteboxSSRF("app/views.py", 100)
	high.ConfidenceScore, high.ConfidenceBand, high.Confidence = 75, "HIGH", ConfidenceHigh

	if Fingerprint(low) != Fingerprint(high) {
		t.Errorf("a confidence change re-identified the finding: %s != %s",
			Fingerprint(low), Fingerprint(high))
	}
}

func TestFingerprintIgnoresSeverity(t *testing.T) {
	med := whiteboxSSRF("app/views.py", 100)
	med.Severity = SeverityMedium
	crit := whiteboxSSRF("app/views.py", 100)
	crit.Severity = SeverityCritical
	if Fingerprint(med) != Fingerprint(crit) {
		t.Errorf("a re-ranked finding changed identity: %s != %s", Fingerprint(med), Fingerprint(crit))
	}
}

// §6 — applicability is an evolving verdict ABOUT a vulnerability, not part of
// which vulnerability it is.
func TestFingerprintIgnoresApplicability(t *testing.T) {
	unknown := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	against := depFinding("CVE-2026-69247", "PyPI", "requests", "2.28.0", "requirements.txt")
	against.Applicability = ApplicabilityEvidenceAgainst

	if Fingerprint(unknown) != Fingerprint(against) {
		t.Errorf("applicability unknown→evidence_against created a new vulnerability: %s != %s",
			Fingerprint(unknown), Fingerprint(against))
	}
}

// §9 — evidence enrichment. A sink-only observation that later gains a proven
// source→sink path is the SAME vulnerability, better understood.
//
// The sink-only half is modelled the way a real chainless finding arrives: NO
// TaintChain, and evidence that is the raw source line. An earlier version of
// this test gave it a chain, which put both halves on the same code path and
// hid a genuine defect — when a chain appeared the operation switched from the
// evidence text to the chain's sink, and those are different strings. The
// end-to-end fixture caught what this test missed.
func TestFingerprintSurvivesEvidenceEnrichment(t *testing.T) {
	sinkOnly := whiteboxSSRF("app/views.py", 100)
	sinkOnly.Title = "Potential SSRF — dynamic URL reaches HTTP client"
	sinkOnly.TaintChain = nil // a real chainless finding has NO chain at all
	sinkOnly.Reachable = false
	sinkOnly.Evidence = "    return requests.get(url).content"
	sinkOnly.Sink = "requests.get(url)"

	proven := whiteboxSSRF("app/views.py", 100)
	proven.Reachable = true
	proven.Evidence = "    return requests.get(url).content"
	proven.Sink = "requests.get(url)"

	if Fingerprint(sinkOnly) != Fingerprint(proven) {
		t.Errorf("proving the source→sink path re-identified the finding:\n  sink-only = %s\n  proven    = %s",
			Fingerprint(sinkOnly), Fingerprint(proven))
	}
}

// §7 — a fingerprint is published in SARIF, baselines and ignore files. It
// must never be derived from credential material.
func TestFingerprintNeverConsumesRawSecretMaterial(t *testing.T) {
	const credential = "AKIAIOSFODNN7EXAMPLE"

	withSecret := Finding{
		Category: "secrets", RuleID: "secrets/aws-access-key", Source: SourceWhitebox,
		Title: "AWS access key committed to source", Endpoint: "config/settings.py:12",
		Evidence: `AWS_KEY = "` + credential + `"`,
		Secret:   &SecretRef{Identifier: "AWS_KEY", File: "config/settings.py"},
	}
	redacted := withSecret
	redacted.Evidence = `AWS_KEY = "[REDACTED len=20 sha256:1a2b3c4d...]"`

	if Fingerprint(withSecret) != Fingerprint(redacted) {
		t.Error("the fingerprint moved when the credential bytes changed — it is reading the credential")
	}
}

func TestSecretIdentityIsStableUnderLineMovement(t *testing.T) {
	at12 := Finding{
		Category: "secrets", RuleID: "secrets/aws-access-key", Source: SourceWhitebox,
		Title: "AWS access key committed to source", Endpoint: "config/settings.py:12",
		Secret: &SecretRef{Identifier: "AWS_KEY", File: "config/settings.py"},
	}
	at40 := at12
	at40.Endpoint = "config/settings.py:40"

	if Fingerprint(at12) != Fingerprint(at40) {
		t.Errorf("a committed secret that moved down the file changed identity: %s != %s",
			Fingerprint(at12), Fingerprint(at40))
	}
}

func TestTwoDistinctSecretsInOneFileStaySeparate(t *testing.T) {
	aws := Finding{
		Category: "secrets", RuleID: "secrets/aws-access-key", Source: SourceWhitebox,
		Title: "AWS access key committed to source", Endpoint: "config/settings.py:12",
		Secret: &SecretRef{Identifier: "AWS_KEY", File: "config/settings.py"},
	}
	stripe := aws
	stripe.Endpoint = "config/settings.py:13"
	stripe.Secret = &SecretRef{Identifier: "STRIPE_KEY", File: "config/settings.py"}

	if Fingerprint(aws) == Fingerprint(stripe) {
		t.Errorf("two different secrets in one file collapsed to one identity: %s", Fingerprint(aws))
	}
}

// The same invariant over the ANALYZER's real output shape: a chainless
// finding carries a Sink and no chain, a proven one carries both. Identity has
// to read the sink either way, or an analyzer that gets better at proving
// flows re-files every finding it newly proves.
func TestSinkIdentityIsReadTheSameWayWithAndWithoutAChain(t *testing.T) {
	// Modelled on the analyzer's REAL output. The chainless half has no
	// Route: the analyzer binds one only when it proved a chain, so route
	// availability tracks proof rather than tracking the code. Identity must
	// not inherit that dependency — the enclosing symbol is the same symbol
	// either way.
	chainless := Finding{
		Category: "injection", RuleID: "python.ast/PY_SSRF", Source: SourceWhitebox,
		Title:    "Potential SSRF — dynamic URL passed to HTTP client",
		Endpoint: "svc.py:11",
		Symbol:   "make_thumb",
		Evidence: "    return requests.get(src).content",
		Sink:     "requests.get(src)",
	}
	proven := chainless
	proven.Title = "SSRF — user-controlled URL reaches HTTP client"
	proven.Reachable = true
	proven.Route = &Route{Method: "GET", Pattern: "/thumb", Handler: "make_thumb", File: "svc.py"}
	proven.TaintChain = []TaintLink{
		{File: "svc.py", Line: 10, Expr: `request.args.get("src")`},
		{File: "svc.py", Line: 11, Expr: "requests.get(src)"},
	}

	if Fingerprint(chainless) != Fingerprint(proven) {
		t.Errorf("an analyzer that learned to prove the flow re-identified the finding:\n  before = %s\n  after  = %s",
			Fingerprint(chainless), Fingerprint(proven))
	}
}
