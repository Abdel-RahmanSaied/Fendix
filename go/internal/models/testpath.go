package models

import (
	"regexp"
	"strings"
)

// testPathRe recognises the file-path conventions that mark test / fixture
// code. It mirrors the Python analyzer's `_is_test_path` markers
// (python/analyzers/ast_analyzer.py) EXACTLY, so the Go decision layer and the
// Python emitter agree on what "test code" means: a tests/ or testing/ dir, a
// conftest, a test_*.py / *_test.py file, or a fixtures/ dir.
//
// Keeping the two in lockstep is what lets Fendix derive test context in Go
// from the finding's endpoint instead of threading a flag across the NDJSON
// IPC boundary — the endpoint for a whitebox finding IS the `<rel path>:<line>`
// the Python analyzer classified. TestIsTestPathMatchesPythonMarkers locks the
// marker set.
var testPathRe = regexp.MustCompile(
	`(^|/)(tests?|testing|conftest)([_/.]|$)|(^|/)test_[^/]*\.py$|_test\.py$|/fixtures?/`,
)

// methodPrefixRe matches the leading HTTP method token that black-box emitters
// put on an endpoint ("GET /users/42"). Mirrors the correlator's regex of the
// same name; duplicated rather than shared because `models` must stay free of
// internal dependencies (every other package imports IT).
var methodPrefixRe = regexp.MustCompile(
	`(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+`,
)

// isURLEndpoint reports whether an endpoint denotes a live HTTP route rather
// than a source location. Black-box findings are "<METHOD> /path", a bare
// "/path", or an absolute URL; white-box findings are "relative/file.py:42".
func isURLEndpoint(ep string) bool {
	ep = methodPrefixRe.ReplaceAllString(ep, "")
	return strings.HasPrefix(ep, "/") || strings.Contains(ep, "://")
}

// IsTestPath reports whether a finding endpoint points at test / fixture code.
//
// The endpoint may be a bare path ("tests/test_auth.py"), a path with a line
// suffix ("tests/test_auth.py:42"), or a Windows-separated path — all three
// normalise to the same answer.
//
// URL-SHAPED ENDPOINTS ARE NEVER TEST CODE, and the guard for that is load
// bearing rather than cosmetic. The marker regex matches a `tests?` or
// `testing` path segment anywhere, so without the guard a perfectly real live
// route — `GET /tests`, `GET /api/test`, `GET /api/testing/run`,
// `GET /fixtures/team` — classifies as test code and its DAST findings get
// de-escalated to INFO. A route is a deployed attack surface no matter what it
// is named; only a *source file* can be test code.
//
// Pure and deterministic: the same endpoint always yields the same answer, with
// no filesystem access. That matters because this feeds the confidence /
// decision layer, which must be reproducible (Constitution Rule 8).
func IsTestPath(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	ep := strings.ReplaceAll(endpoint, "\\", "/")
	if isURLEndpoint(ep) {
		return false
	}
	// Strip a trailing ":<line>" suffix. LastIndex(">0") avoids mangling a
	// leading-colon oddity; absolute URLs are already excluded above.
	if i := strings.LastIndex(ep, ":"); i > 0 {
		ep = ep[:i]
	}
	return testPathRe.MatchString(ep)
}
