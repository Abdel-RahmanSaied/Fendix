package scanner

import "regexp"

// ── B4 response-context classification ──────────────────────────────────────
//
// Some DAST observations are real but low-trust because of the CONTEXT they
// fired in, not because the observation is wrong. Fendix's posture (Rule 3) is
// to preserve that evidence and let the confidence scorer de-escalate it,
// rather than delete the finding. A check tags the finding with a context
// string; internal/confidence applies a fixed penalty and prints the reason.
//
// The two contexts are deliberately narrow. Anything broader belongs in a
// check's own "there is no signal here" skip, not in a de-escalation tag —
// de-escalating noise that was never a security signal just moves the noise
// into the report at a lower score.

// staticFilePathRe matches endpoints that serve a static file rather than an
// API route. Findings on these are lower-trust: the file is typically served
// by a CDN or static-file middleware, so an app-layer security expectation
// (a CSP header, a CORS policy) is a weaker signal there than on an API route.
//
// TASK-123 / FP corpus pattern P3 introduced this regex for the rate-limit
// check; v1.1 promoted it to the shared classifier below so header/CORS
// findings get the same treatment instead of each check growing its own
// (divergent) notion of "static".
//
// Conservative match: only common static-asset extensions and a handful of
// well-known dotfiles. Misses are fine — the finding emits untagged and the
// rate-limit check still probes, exactly as if the path were an API route; an
// overly-permissive regex would silently de-escalate real API findings, which
// is the failure mode worth avoiding.
//
// DELIBERATELY EXCLUDED: `pdf`, `zip`, `gz`, `tar` and `wasm`, which the
// original TASK-123 regex carried. Those extensions overwhelmingly appear on
// GENERATED endpoints — `/api/v1/reports/export.pdf`,
// `/api/invoices/2024.zip`, `/api/backup.tar.gz` — not on CDN-served files. On
// a generated route both behaviours keyed off this predicate are wrong: rate
// limiting an expensive export endpoint is exactly the CWE-770 control the
// check exists to find, and its missing security headers are a normal API
// finding, not a low-trust one. Static `.pdf` downloads simply get probed and
// reported like any other route, which is the safe direction to err.
var staticFilePathRe = regexp.MustCompile(
	`(?i)(?:` +
		`\.(?:DS_Store|map|ico|woff2?|ttf|otf|css|js|mjs|png|jpe?g|gif|svg|webp|avif|bmp)$` +
		`|/(?:robots|humans|security|favicon|sitemap)\.(?:txt|xml)$` +
		`)`,
)

// isStaticAssetPath reports whether an endpoint path serves a static asset.
// Pure and deterministic — the same path always yields the same answer.
func isStaticAssetPath(path string) bool {
	return staticFilePathRe.MatchString(path)
}

// httpResponseContext maps a response status to a confidence de-escalation
// context for B4. The 404/410/5xx codes are already skipped upstream; the
// 4xx codes that still emit (401/403/405/406/429) are auth-gated / client
// errors whose header findings are lower-signal.
func httpResponseContext(status int) string {
	switch status {
	case 401, 403, 405, 406, 429:
		return "4xx"
	}
	return ""
}

// responseContextFor resolves the single de-escalation context for a finding
// observed at `path` with response `status`. Returns "" when neither applies,
// which leaves the finding at full confidence.
//
// The response status is checked FIRST so the pre-existing "4xx" behaviour is
// bit-for-bit unchanged: an auth-gated response on a static path still reports
// "4xx". Both contexts carry the same penalty, so the ordering only decides
// which reason line the report prints — and "this was auth-gated" is the more
// specific, more actionable explanation of the two.
func responseContextFor(status int, path string) string {
	if c := httpResponseContext(status); c != "" {
		return c
	}
	if isStaticAssetPath(path) {
		return "static-asset"
	}
	return ""
}

// ── document-rendering classification ───────────────────────────────────────
//
// A second, orthogonal axis to the B4 contexts above. Those grade how much to
// TRUST an observation; this one grades whether the observation describes a
// control that could have applied at all.
//
// Content-Security-Policy, X-Frame-Options, Cross-Origin-Opener-Policy,
// Cross-Origin-Embedder-Policy and Permissions-Policy are instructions to a
// browser that is RENDERING A DOCUMENT. A JSON payload is parsed by a fetch
// caller, never rendered: it has no DOM to inject into, no frame to be nested
// in, no browsing-context group to isolate, and no feature-permission surface.
// Reporting those headers as missing on an API response describes a control
// that had nothing to control.
//
// Transport and sniffing headers are NOT part of this set and are deliberately
// unaffected: Strict-Transport-Security governs the connection, and
// X-Content-Type-Options: nosniff genuinely matters for a JSON response — it is
// what stops a browser MIME-sniffing that body into something executable.

// documentContentTypeRe matches media types a browser renders as a document.
// XHTML and SVG are included: both are parsed into a DOM and can execute
// script, which is exactly what CSP and frame-ancestors constrain.
var documentContentTypeRe = regexp.MustCompile(`(?i)^(?:text/html|application/xhtml\+xml|image/svg\+xml)\b`)

// apiContentTypeRe matches media types that are parsed as DATA. Deliberately a
// closed list of shapes rather than "anything not a document": that inversion
// would classify an unknown or novel media type as an API response and silently
// de-escalate a real finding, which is the reading this file exists to avoid.
//
// The `+json`/`+xml` suffix forms cover the structured-syntax families
// (application/problem+json, application/vnd.api+json, application/hal+json …)
// that RFC 6839 defines, so a vendor media type does not fall through to
// "unknown" merely for being vendor-specific.
var apiContentTypeRe = regexp.MustCompile(`(?i)^(?:application/(?:json|xml|[\w.+-]*\+json|[\w.+-]*\+xml)|text/csv)\b`)

// classifyDocumentRendering reports whether a response is browser-rendered.
//
// THREE-STATE ON PURPOSE, and the third state is the point. `known` is false
// when the Content-Type is absent, empty, or simply not one this function
// recognises — and in that case the caller must change NOTHING. Collapsing
// unknown into "not a document" would de-escalate every response whose media
// type the engine has not enumerated, turning a gap in Fendix's knowledge into
// a silent claim about the target. That is the same "absence of evidence read
// as evidence" failure the decision layer refuses everywhere else.
func classifyDocumentRendering(contentType string) (isDocument bool, known bool) {
	if contentType == "" {
		return false, false
	}
	switch {
	case documentContentTypeRe.MatchString(contentType):
		return true, true
	case apiContentTypeRe.MatchString(contentType):
		return false, true
	default:
		return false, false
	}
}
