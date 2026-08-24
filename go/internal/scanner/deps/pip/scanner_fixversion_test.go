package pip

import (
	"strings"
	"testing"
)

// gitSHA is a realistic commit SHA — the exact thing that must never reach
// an "Upgrade to X" message. OSV genuinely ships GIT ranges alongside
// ECOSYSTEM ones (pillow==9.0.0's advisory set carries ECOSYSTEM 50 /
// SEMVER 11 / GIT 3), so this is a reachable production shape, not a
// hypothetical.
const gitSHA = "8f1d2c3b4a59607e6c1f0dd0d2a1b9e77c3d4a51"

// djangoPYSEC mirrors the verified live-OSV record for django==5.2.16:
// ONE advisory that patches TWO release branches. It is the reason
// fixCandidate exists — "first fixed event" picks whichever the JSON
// happens to list first, and "max fixed event" tells a 5.2.16 user to
// jump a major version.
func djangoPYSEC() osvVuln {
	return osvVuln{
		ID:      "PYSEC-2026-3717",
		Summary: "Django DoS",
		Aliases: []string{"BIT-django-2026-15830", "CVE-2026-15830"},
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Type: "ECOSYSTEM",
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "5.2.17"},
					{Introduced: "6.0"},
					{Fixed: "6.0.8"},
				},
			}},
		}},
	}
}

func TestFixCandidate_DjangoPicksMinimalInBranch(t *testing.T) {
	if got := fixCandidate(djangoPYSEC(), "5.2.16"); got != "5.2.17" {
		t.Errorf("fixCandidate = %q; want 5.2.17 — the minimal in-branch upgrade, not the 6.0.x jump", got)
	}
	// A user already on the 6.0 branch gets the 6.0 patch, from the very
	// same advisory. Same rule, different pin — which is the whole point
	// of ranking against the installed version.
	if got := fixCandidate(djangoPYSEC(), "6.0.7"); got != "6.0.8" {
		t.Errorf("fixCandidate(6.0.7) = %q; want 6.0.8", got)
	}
}

func TestFixCandidate_IgnoresGitRanges(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-pillow-git",
		Affected: []osvAffected{{
			Ranges: []osvRange{
				{Type: "GIT", Events: []osvEvent{{Introduced: "0"}, {Fixed: gitSHA}}},
				{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "9.0.1"}}},
			},
		}},
	}
	if got := fixCandidate(v, "9.0.0"); got != "9.0.1" {
		t.Errorf("fixCandidate = %q; want 9.0.1", got)
	}
	if got := firstFixVersion(v); got != "9.0.1" {
		t.Errorf("firstFixVersion = %q; want 9.0.1 — a GIT range must never win by document order", got)
	}
	f := buildFinding(pinnedPackage{name: "pillow", version: "9.0.0"}, v, "requirements.txt")
	if strings.Contains(f.Fix, gitSHA) {
		t.Errorf("a commit SHA reached the upgrade message: %s", f.Fix)
	}
	if !strings.Contains(f.Fix, "pillow==9.0.1") {
		t.Errorf("Fix = %q; want the ecosystem version", f.Fix)
	}
}

func TestFixCandidate_GitOnlyMeansNoFix(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-git-only",
		Affected: []osvAffected{{
			Ranges: []osvRange{{Type: "GIT", Events: []osvEvent{{Fixed: gitSHA}}}},
		}},
	}
	if got := fixCandidate(v, "1.0.0"); got != "" {
		t.Errorf("fixCandidate = %q; want empty — a GIT-only advisory names no VERSION", got)
	}
	f := buildFinding(pinnedPackage{name: "pkg", version: "1.0.0"}, v, "requirements.txt")
	if !strings.Contains(f.Fix, "no fix listed") {
		t.Errorf("Fix = %q; want the honest no-fix sentinel", f.Fix)
	}
	if strings.Contains(f.Fix, gitSHA) {
		t.Errorf("a commit SHA reached the upgrade message: %s", f.Fix)
	}
}

// TestFixCandidate_EmptyTypeTreatedAsEcosystem locks the adapter contract:
// the offline snapshot and the pip-audit converter both synthesise ranges,
// and a cache entry written by a pre-FIX-06 binary has no type either.
// Treating "" as GIT would silently blank the fix line on all three.
func TestFixCandidate_EmptyTypeTreatedAsEcosystem(t *testing.T) {
	v := osvVuln{
		ID:       "PYSEC-untyped",
		Affected: []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.2"}}}}}},
	}
	if got := fixCandidate(v, "2.0.1"); got != "2.0.2" {
		t.Errorf("fixCandidate = %q; want 2.0.2", got)
	}
}

// TestFixCandidate_FallbackWhenNothingRanksAbove is ladder rung 2. The
// comparator collapses "2.0.1rc1"-style pins onto their release core, so
// "strictly greater" can come back empty for an advisory that plainly
// names a fix. Reporting "no fix listed in OSV" there would be a lie.
func TestFixCandidate_FallbackWhenNothingRanksAbove(t *testing.T) {
	v := osvVuln{
		ID: "PYSEC-below-pin",
		Affected: []osvAffected{{
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "1.5.0"}, {Fixed: "1.4.0"}}}},
		}},
	}
	if got := fixCandidate(v, "9.9.9"); got != "1.4.0" {
		t.Errorf("fixCandidate = %q; want the lowest listed fix (1.4.0), never an invented version", got)
	}
}

// TestMergedFixVersion_MaxAcrossMembers is level (b). Two advisories that
// FIX-05 merges into one finding are only both fixed by the HIGHER of
// their per-advisory candidates.
func TestMergedFixVersion_MaxAcrossMembers(t *testing.T) {
	a := osvVuln{ID: "GHSA-a", Affected: []osvAffected{{
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "49.0.0"}}}}}}}
	b := osvVuln{ID: "GHSA-b", Affected: []osvAffected{{
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "50.0.0"}}}}}}}

	if got := mergedFixVersion([]osvVuln{a, b}, "48.0.1"); got != "50.0.0" {
		t.Errorf("mergedFixVersion = %q; want 50.0.0", got)
	}
	// Order-independent (Rule 8).
	if got := mergedFixVersion([]osvVuln{b, a}, "48.0.1"); got != "50.0.0" {
		t.Errorf("mergedFixVersion reversed = %q; want 50.0.0", got)
	}
	// A member with no usable fix contributes nothing rather than
	// dragging the answer back to "".
	noFix := osvVuln{ID: "GHSA-c"}
	if got := mergedFixVersion([]osvVuln{a, noFix}, "48.0.1"); got != "49.0.0" {
		t.Errorf("mergedFixVersion with a no-fix member = %q; want 49.0.0", got)
	}
	if got := mergedFixVersion([]osvVuln{noFix}, "48.0.1"); got != "" {
		t.Errorf("mergedFixVersion of a no-fix-only component = %q; want empty", got)
	}
}

// TestFixVersion_DeterministicUnderComparatorTies guards the lexicographic
// tie-break. offline.CompareVersions collapses a pre-release onto its
// release core, so "1.0.0-rc.1" and "1.0.0" compare EQUAL; without the
// tie-break the winner would depend on slice order.
func TestFixVersion_DeterministicUnderComparatorTies(t *testing.T) {
	fwd := lowerVersion("1.0.0", "1.0.0-rc.1")
	rev := lowerVersion("1.0.0-rc.1", "1.0.0")
	if fwd != rev {
		t.Errorf("lowerVersion is order-dependent: %q vs %q", fwd, rev)
	}
	if fwd := higherVersion("1.0.0", "1.0.0-rc.1"); fwd != higherVersion("1.0.0-rc.1", "1.0.0") {
		t.Errorf("higherVersion is order-dependent")
	}
}
