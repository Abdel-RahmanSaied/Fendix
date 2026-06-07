package offline

import "testing"

func TestLookupVulnerable_InRange(t *testing.T) {
	snap := FromOSVExport(sampleAdvisories(), nil)

	// flask 2.2.0 < fixed 2.3.0 → vulnerable.
	if got := snap.LookupVulnerable("PyPI", "flask", "2.2.0"); len(got) != 1 {
		t.Fatalf("flask 2.2.0: got %d advisories; want 1", len(got))
	}
	// flask 2.3.0 == fixed → NOT vulnerable (fixed is exclusive upper).
	if got := snap.LookupVulnerable("PyPI", "flask", "2.3.0"); len(got) != 0 {
		t.Errorf("flask 2.3.0 should be patched; got %d advisories", len(got))
	}
	// flask 2.4.1 > fixed → NOT vulnerable.
	if got := snap.LookupVulnerable("PyPI", "flask", "2.4.1"); len(got) != 0 {
		t.Errorf("flask 2.4.1 should be patched; got %d advisories", len(got))
	}
	// lodash 4.17.20 < fixed 4.17.21 → vulnerable (case-insensitive ecosystem).
	if got := snap.LookupVulnerable("npm", "lodash", "4.17.20"); len(got) != 1 {
		t.Errorf("lodash 4.17.20: got %d advisories; want 1", len(got))
	}
}

func TestLookupVulnerable_BelowIntroduced(t *testing.T) {
	snap := FromOSVExport([]Advisory{{
		ID:      "GHSA-intro",
		Package: PackageRef{Ecosystem: "PyPI", Name: "requests"},
		Ranges:  []Range{{Introduced: "2.0.0", Fixed: "2.5.0"}},
	}}, nil)

	if got := snap.LookupVulnerable("PyPI", "requests", "1.9.0"); len(got) != 0 {
		t.Errorf("requests 1.9.0 is below introduced 2.0.0; got %d advisories", len(got))
	}
	if got := snap.LookupVulnerable("PyPI", "requests", "2.0.0"); len(got) != 1 {
		t.Errorf("requests 2.0.0 == introduced should be vulnerable; got %d advisories", len(got))
	}
	if got := snap.LookupVulnerable("PyPI", "requests", "2.4.9"); len(got) != 1 {
		t.Errorf("requests 2.4.9 in range; got %d advisories", len(got))
	}
}

func TestLookupVulnerable_NoRangesMatchesAll(t *testing.T) {
	snap := FromOSVExport([]Advisory{{
		ID:      "GHSA-allver",
		Package: PackageRef{Ecosystem: "npm", Name: "left-pad"},
	}}, nil)

	for _, v := range []string{"0.0.1", "1.0.0", "99.99.99"} {
		if got := snap.LookupVulnerable("npm", "left-pad", v); len(got) != 1 {
			t.Errorf("left-pad %s with no ranges should match; got %d", v, len(got))
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.0", "1.10.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.1", -1},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3-rc1", "1.2.3", 0}, // pre-release suffix stripped to release core
		{"1.0.0+build5", "1.0.0", 0},
		{"10", "9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFirstFixedVersionAndPrimaryAlias(t *testing.T) {
	a := Advisory{
		Aliases: []string{"CVE-2026-9999", "GHSA-extra"},
		Ranges:  []Range{{Introduced: "1.0.0"}, {Introduced: "2.0.0", Fixed: "2.1.0"}},
	}
	if got := a.FirstFixedVersion(); got != "2.1.0" {
		t.Errorf("FirstFixedVersion = %q; want 2.1.0", got)
	}
	if got := a.PrimaryAlias(); got != "CVE-2026-9999" {
		t.Errorf("PrimaryAlias = %q; want CVE-2026-9999", got)
	}
	if got := (Advisory{}).FirstFixedVersion(); got != "" {
		t.Errorf("FirstFixedVersion on empty = %q; want empty", got)
	}
	if got := (Advisory{}).PrimaryAlias(); got != "" {
		t.Errorf("PrimaryAlias on empty = %q; want empty", got)
	}
}
