package models

import "testing"

// TestIsTestPathMatchesPythonMarkers locks the marker set against the Python
// analyzer's `_is_test_path` (python/analyzers/ast_analyzer.py). Deriving test
// context in Go from the endpoint only works because the two agree; if the
// Python side grows a marker, this table is where the drift shows up.
func TestIsTestPathMatchesPythonMarkers(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		// --- the five Python markers -----------------------------------
		{"tests dir", "tests/test_login.py:10", true},
		{"test dir singular", "test/helpers.py:3", true},
		{"testing dir", "app/testing/factory.py:8", true},
		{"conftest", "app/conftest.py:1", true},
		{"test_ prefix file", "app/test_views.py:42", true},
		{"_test suffix file", "app/views_test.py:42", true},
		{"fixtures dir", "app/fixtures/users.py:5", true},
		{"fixture dir singular", "app/fixture/users.py:5", true},

		// --- production paths -------------------------------------------
		{"plain module", "app/views.py:10", false},
		{"nested module", "src/api/handlers/login.py:22", false},
		{"substring not a segment", "app/latest/mod.py:1", false},
		{"contest is not conftest", "app/contest.py:1", false},

		// --- shapes that are not source paths at all ---------------------
		{"empty", "", false},
		{"url endpoint", "GET /api/users", false},
		{"absolute url", "https://api.example.com/tests", false},

		// --- LIVE ROUTES THAT MERELY LOOK LIKE TEST PATHS ------------------
		// Regression gate. The marker regex matches a `tests?`/`testing`/
		// `fixtures` segment anywhere, so without the URL guard every one of
		// these deployed routes classified as test code and had its DAST
		// findings de-escalated to INFO. A route is attack surface no matter
		// what it is named; only a source FILE can be test code.
		{"route named test", "GET /api/test", false},
		{"route named tests", "GET /tests", false},
		{"route under testing", "GET /api/testing/run", false},
		{"route with .json suffix", "POST /v1/test.json", false},
		{"route under fixtures", "GET /fixtures/team-roster", false},
		{"bare path route", "/test/echo", false},
		{"lowercase method", "get /tests", false},
		{"absolute url with test segment", "https://api.example.com/api/testing/run", false},

		// --- normalisation ------------------------------------------------
		{"windows separators", `app\tests\test_login.py:10`, true},
		{"no line suffix", "tests/test_login.py", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTestPath(tc.endpoint); got != tc.want {
				t.Errorf("IsTestPath(%q) = %v, want %v", tc.endpoint, got, tc.want)
			}
		})
	}
}

// TestIsTestPathIsDeterministic guards the reproducibility contract: the
// classifier feeds the confidence/decision layer, so it must be a pure
// function with no filesystem or environment dependence.
func TestIsTestPathIsDeterministic(t *testing.T) {
	const ep = "app/tests/test_views.py:42"
	first := IsTestPath(ep)
	for i := 0; i < 100; i++ {
		if got := IsTestPath(ep); got != first {
			t.Fatalf("IsTestPath is not deterministic: iteration %d returned %v, want %v", i, got, first)
		}
	}
}
