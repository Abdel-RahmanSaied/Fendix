package models

import (
	"fmt"
	"strings"
	"testing"
)

// §9 — the identity scheme's guarantees stated as properties over a generated
// corpus rather than as hand-picked examples, because the failure mode that
// matters (two unrelated vulnerabilities quietly sharing one record) only
// shows up at volume.

// corpusFinding is one generated finding plus the LOGICAL key that says which
// vulnerability it is meant to be. Two findings share a logical key exactly
// when they are the same vulnerability seen under different circumstances, so
// the properties below reduce to "fingerprint agrees with logical key".
type corpusFinding struct {
	f       Finding
	logical string
}

// buildCorpus generates findings across all four families, then for each one
// emits variants that change only things identity must ignore: where it sits,
// how it is described, how confident Fendix is, and what it decided.
func buildCorpus() []corpusFinding {
	var out []corpusFinding

	files := []string{"app/views.py", "app/admin.py", "svc/handlers/orders.py", "lib/net/client.go"}
	syms := []string{"fetch_image", "list_orders", "proxy"}
	sinks := []string{"requests.get(url)", "urllib.request.urlopen(target)", "http.Get(u)", "os.open(path)"}
	rules := []string{"python.ssrf.taint", "python.pathtraversal.taint", "go.ssrf.taint"}

	// --- whitebox ---
	for _, file := range files {
		for _, sym := range syms {
			for _, sink := range sinks {
				for _, rule := range rules {
					logical := "wb|" + rule + "|" + file + "|" + sym + "|" + sink
					for variant, line := range []int{10, 137, 4021} {
						f := Finding{
							Category: "injection", RuleID: rule,
							Source: SourceWhitebox, SourceTier: TierTreeSitter,
							Title:    fmt.Sprintf("Finding variant %d", variant),
							Endpoint: fmt.Sprintf("%s:%d", file, line),
							Route:    &Route{Handler: sym, File: file},
							TaintChain: []TaintLink{
								{File: file, Line: line - 3, Expr: "request.args.get('q')"},
								{File: file, Line: line, Expr: sink},
							},
							Severity:        severityVariant(variant),
							ConfidenceScore: 25 + variant*30,
							Status:          statusVariant(variant),
						}
						out = append(out, corpusFinding{f, logical})
					}
				}
			}
		}
	}

	// --- dependencies ---
	advisories := []string{"CVE-2026-69247", "GHSA-xxxx-yyyy-zzzz", "CVE-2025-11111"}
	pkgs := []struct{ eco, name string }{
		{"PyPI", "requests"}, {"PyPI", "urllib3"}, {"npm", "lodash"}, {"Go", "golang.org/x/net"},
	}
	for _, adv := range advisories {
		for _, p := range pkgs {
			logical := "dep|" + adv + "|" + p.eco + "|" + p.name
			for variant, version := range []string{"1.0.0", "1.0.1", "2.3.4"} {
				f := Finding{
					Category: "deps", RuleID: adv, Source: SourceWhitebox,
					Title:    fmt.Sprintf("Vulnerable dependency: %s==%s (%s)", p.name, version, adv),
					Endpoint: "requirements.txt",
					Dependency: &DependencyRef{
						Ecosystem: p.eco, Package: p.name, Version: version,
						Manifest: "requirements.txt",
					},
					Applicability: applicabilityVariant(variant),
					Status:        statusVariant(variant),
				}
				out = append(out, corpusFinding{f, logical})
			}
		}
	}

	// --- secrets ---
	idents := []string{"AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN"}
	secretRules := []string{"secrets/aws-secret-key", "secrets/stripe-live-key", "secrets/generic-api-key"}
	for _, file := range files {
		for _, ident := range idents {
			for _, rule := range secretRules {
				logical := "sec|" + rule + "|" + file + "|" + ident
				for variant, line := range []int{3, 88, 500} {
					f := Finding{
						Category: "secrets", RuleID: rule, Source: SourceWhitebox,
						Title:    fmt.Sprintf("Credential committed (variant %d)", variant),
						Endpoint: fmt.Sprintf("%s:%d", file, line),
						Evidence: fmt.Sprintf("%s = \"[REDACTED len=%d sha256:%08x...]\"", ident, 20+variant, variant*7919),
						Secret:   &SecretRef{Identifier: ident, File: file},
					}
					out = append(out, corpusFinding{f, logical})
				}
			}
		}
	}

	// --- blackbox ---
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	paths := []string{"/api/users/{id}", "/api/orders", "/admin/settings"}
	bbRules := []string{"auth.missing", "cors.wildcard", "headers.missing-csp", "ratelimit.absent"}
	for _, m := range methods {
		for _, path := range paths {
			for _, rule := range bbRules {
				logical := "bb|" + rule + "|" + m + " " + path
				for variant := range 3 {
					f := Finding{
						Category: "auth", RuleID: rule, Source: SourceBlackbox,
						Title:    fmt.Sprintf("Observed issue (variant %d)", variant),
						Endpoint: m + " " + path,
						Evidence: fmt.Sprintf("observed on attempt %d", variant),
						Severity: severityVariant(variant),
						Status:   statusVariant(variant),
					}
					out = append(out, corpusFinding{f, logical})
				}
			}
		}
	}

	return out
}

func severityVariant(i int) Severity {
	return []Severity{SeverityLow, SeverityHigh, SeverityCritical}[i%3]
}
func statusVariant(i int) string { return []string{"INFO", "WARN", "BLOCK"}[i%3] }
func applicabilityVariant(i int) Applicability {
	return []Applicability{ApplicabilityUnknown, ApplicabilityApplicable, ApplicabilityEvidenceAgainst}[i%3]
}

func TestFingerprintIsDeterministicAcrossRepeatedRuns(t *testing.T) {
	corpus := buildCorpus()
	first := make([]string, len(corpus))
	for i, c := range corpus {
		first[i] = Fingerprint(c.f)
	}
	for run := 2; run <= 5; run++ {
		for i, c := range corpus {
			if got := Fingerprint(c.f); got != first[i] {
				t.Fatalf("run %d disagreed on corpus[%d]: %s != %s", run, i, got, first[i])
			}
		}
	}
	t.Logf("determinism: %d findings, 5 runs, 0 disagreements", len(corpus))
}

// The headline property. Every corpus entry carries the logical vulnerability
// it represents; identity must partition the corpus exactly the same way.
//
// A SPLIT is one logical vulnerability wearing more than one fingerprint —
// the RC-5 defect, which files the same issue as new after every edit.
// A COLLISION is one fingerprint worn by more than one logical vulnerability
// — the failure the location component used to prevent for free, and the one
// that matters most: suppressing one finding would silently suppress another.
func TestFingerprintPartitionsTheCorpusByLogicalVulnerability(t *testing.T) {
	corpus := buildCorpus()

	fpsPerLogical := map[string]map[string]bool{}
	logicalsPerFP := map[string]map[string]bool{}
	for _, c := range corpus {
		fp := Fingerprint(c.f)
		if fpsPerLogical[c.logical] == nil {
			fpsPerLogical[c.logical] = map[string]bool{}
		}
		fpsPerLogical[c.logical][fp] = true
		if logicalsPerFP[fp] == nil {
			logicalsPerFP[fp] = map[string]bool{}
		}
		logicalsPerFP[fp][c.logical] = true
	}

	splits := 0
	for logical, fps := range fpsPerLogical {
		if len(fps) > 1 {
			splits++
			if splits <= 5 {
				t.Errorf("SPLIT: logical vulnerability %q has %d identities %v", logical, len(fps), keys(fps))
			}
		}
	}
	collisions := 0
	for fp, logicals := range logicalsPerFP {
		if len(logicals) > 1 {
			collisions++
			if collisions <= 5 {
				t.Errorf("COLLISION: fingerprint %s covers %d vulnerabilities:\n  %s",
					fp, len(logicals), strings.Join(keys(logicals), "\n  "))
			}
		}
	}

	t.Logf("corpus=%d logical=%d identities=%d splits=%d collisions=%d",
		len(corpus), len(fpsPerLogical), len(logicalsPerFP), splits, collisions)
	if splits > 0 || collisions > 0 {
		t.Errorf("expected a clean partition, got %d splits and %d collisions", splits, collisions)
	}
}

// The v1 scheme measured against the same corpus, so the improvement is a
// number rather than a claim. This test asserts the DEFECT still reproduces
// under v1 — if it ever stops, the corpus stopped exercising the bug and the
// comparison above is worthless.
func TestV1SchemeSplitsTheSameCorpus(t *testing.T) {
	corpus := buildCorpus()
	fpsPerLogical := map[string]map[string]bool{}
	for _, c := range corpus {
		fp := FingerprintV1(c.f)
		if fpsPerLogical[c.logical] == nil {
			fpsPerLogical[c.logical] = map[string]bool{}
		}
		fpsPerLogical[c.logical][fp] = true
	}
	split := 0
	for _, fps := range fpsPerLogical {
		if len(fps) > 1 {
			split++
		}
	}
	if split == 0 {
		t.Fatal("v1 split nothing — the corpus no longer exercises RC-5, so the v2 result proves nothing")
	}
	t.Logf("v1 baseline: %d of %d logical vulnerabilities carried more than one identity (%.1f%%)",
		split, len(fpsPerLogical), 100*float64(split)/float64(len(fpsPerLogical)))
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
