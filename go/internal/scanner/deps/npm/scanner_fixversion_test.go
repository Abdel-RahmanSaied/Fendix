package npm

import (
	"strings"
	"testing"
)

// gitSHA is a realistic commit SHA — the exact thing that must never reach
// an "Upgrade to X" message. OSV genuinely ships GIT ranges alongside
// ECOSYSTEM ones, so this is a reachable production shape.
const gitSHA = "8f1d2c3b4a59607e6c1f0dd0d2a1b9e77c3d4a51"

// TestFixCandidate_PicksMinimalInBranch is the npm half of FIX-06's level
// (a): one advisory patching two release branches must recommend the patch
// on the branch the user is actually pinned to.
func TestFixCandidate_PicksMinimalInBranch(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-two-branch",
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Type: "ECOSYSTEM",
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "4.17.21"},
					{Introduced: "5.0.0"},
					{Fixed: "5.1.2"},
				},
			}},
		}},
	}
	if got := fixCandidate(v, "4.17.15"); got != "4.17.21" {
		t.Errorf("fixCandidate = %q; want 4.17.21, not the 5.x jump", got)
	}
	if got := fixCandidate(v, "5.1.0"); got != "5.1.2" {
		t.Errorf("fixCandidate(5.1.0) = %q; want 5.1.2", got)
	}
}

func TestFixCandidate_IgnoresGitRanges(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-git-and-ecosystem",
		Affected: []osvAffected{{
			Ranges: []osvRange{
				{Type: "GIT", Events: []osvEvent{{Introduced: "0"}, {Fixed: gitSHA}}},
				{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "4.17.21"}}},
			},
		}},
	}
	if got := fixCandidate(v, "4.17.20"); got != "4.17.21" {
		t.Errorf("fixCandidate = %q; want 4.17.21", got)
	}
	f := buildFinding(resolvedPackage{name: "lodash", version: "4.17.20"}, v, "package-lock.json")
	if strings.Contains(f.Fix, gitSHA) {
		t.Errorf("a commit SHA reached the upgrade message: %s", f.Fix)
	}
	if !strings.Contains(f.Fix, "lodash@4.17.21") {
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
	f := buildFinding(resolvedPackage{name: "pkg", version: "1.0.0"}, v, "package-lock.json")
	if !strings.Contains(f.Fix, "no fix listed") {
		t.Errorf("Fix = %q; want the honest no-fix sentinel", f.Fix)
	}
	if strings.Contains(f.Fix, gitSHA) {
		t.Errorf("a commit SHA reached the upgrade message: %s", f.Fix)
	}
}

// TestFixCandidate_EmptyTypeTreatedAsEcosystem locks the adapter contract:
// the offline snapshot synthesises ranges with no type, and so does every
// cache entry written by a pre-FIX-06 binary.
func TestFixCandidate_EmptyTypeTreatedAsEcosystem(t *testing.T) {
	v := osvVuln{
		ID:       "GHSA-untyped",
		Affected: []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{{Fixed: "4.17.21"}}}}}},
	}
	if got := fixCandidate(v, "4.17.20"); got != "4.17.21" {
		t.Errorf("fixCandidate = %q; want 4.17.21", got)
	}
}

func TestMergedFixVersion_MaxAcrossMembers(t *testing.T) {
	a := osvVuln{ID: "GHSA-a", Affected: []osvAffected{{
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "4.17.20"}}}}}}}
	b := osvVuln{ID: "GHSA-b", Affected: []osvAffected{{
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "4.17.21"}}}}}}}

	if got := mergedFixVersion([]osvVuln{a, b}, "4.17.15"); got != "4.17.21" {
		t.Errorf("mergedFixVersion = %q; want 4.17.21", got)
	}
	if got := mergedFixVersion([]osvVuln{b, a}, "4.17.15"); got != "4.17.21" {
		t.Errorf("mergedFixVersion reversed = %q; want 4.17.21 (order independence, Rule 8)", got)
	}
}
