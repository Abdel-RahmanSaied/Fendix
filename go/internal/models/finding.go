// Package models defines the core data types shared across Fendix.
// Finding, Severity, Confidence, and Source are the primary types
// used by both Go and Python engines via the IPC contract.
package models

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents how certain we are about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Source indicates which engine produced the finding.
type Source string

const (
	SourceBlackbox   Source = "blackbox"
	SourceWhitebox   Source = "whitebox"
	SourceCorrelated Source = "correlated"
)

// SourceTier records WHICH analysis engine tier produced a whitebox
// finding (Proven Path v1 / roadmap "Tier provenance enforcement"). The
// correlator weights tiers differently when escalating confidence: a
// CRITICAL driven by a Tier-3 semgrep regex that never cleared the
// F1≥0.95 gate must not escalate to CRITICAL via correlation. Preserved
// end-to-end through NDJSON IPC → correlator → ScanFinding → UI so the
// F1 gate can't be silently bypassed by the correlation moat.
//
// Empty for blackbox findings (no code tier produced them) and for
// pre-existing findings emitted before the field existed — treat empty
// as "unknown tier", which the correlator scores most conservatively.
type SourceTier string

const (
	// TierNativeGo: in-binary Go analysis (textscan today; gosast later).
	TierNativeGo SourceTier = "native_go"
	// TierTreeSitter: the Python/tree-sitter sidecar (the AST taint
	// analyzer that emits taint chains — the highest-trust SAST tier).
	TierTreeSitter SourceTier = "tree_sitter_sidecar"
	// TierSemgrepShim: shelled-out semgrep (breadth, lowest trust until a
	// rule pack clears the F1 gate).
	TierSemgrepShim SourceTier = "semgrep_shim"
)

// Route binds a finding to the HTTP route that reaches its sink (Proven
// Path v1). Populated by the Python route extractor for whitebox findings
// whose enclosing function is a registered Django/Flask/FastAPI handler;
// the correlator uses it to bind a blackbox endpoint to the exact handler
// + taint chain instead of fuzzy path matching. Empty when no route could
// be bound (e.g. a finding in a helper not directly wired to a URL).
type Route struct {
	Method  string `json:"method,omitempty"`  // GET, POST, … ("" = any/unknown)
	Pattern string `json:"pattern,omitempty"` // URL pattern, e.g. /users/<id>
	Handler string `json:"handler,omitempty"` // handler symbol, e.g. views.get_user
	File    string `json:"file,omitempty"`    // file the route is declared in
	Line    int    `json:"line,omitempty"`    // line of the route declaration
}

// TaintLink is one step in a dataflow chain from a source (e.g.
// request.args.get) to a sink (e.g. cursor.execute). The Python AST
// analyzer records these chains for SQLi, SSRF, and open-redirect
// findings (TASK-114) so the correlator and reporters can prove
// "this is reachable" rather than "this looks dangerous."
type TaintLink struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Expr string `json:"expr"`
}

// Finding represents a single security finding produced by either engine.
// This struct is the shared data contract between Go and Python.
//
// AffectedEndpoints is populated by the orchestrator's deduplication pass
// (TASK-088) when N findings of the same (Title, Category, Severity)
// collapse into one. The slice contains every affected endpoint including
// the primary one in `Endpoint`. When the finding represents a single
// occurrence, AffectedEndpoints is nil (omitted from JSON via omitempty).
//
// TaintChain and Reachable are populated by the white-box AST analyzer
// when it can prove an intra-function dataflow path from a request-input
// source to a dangerous sink (TASK-114). The correlator promotes a
// blackbox+whitebox match to Source=correlated AND Reachable=true when
// the whitebox half carries a chain — that's the "DAST + SAST agree
// AND we can show the path" case worth a build-failing exit code.
type Finding struct {
	ID                string      `json:"id"`
	Title             string      `json:"title"`
	Severity          Severity    `json:"severity"`
	Source            Source      `json:"source"`
	Category          string      `json:"category"`
	Endpoint          string      `json:"endpoint"`
	AffectedEndpoints []string    `json:"affected_endpoints,omitempty"`
	Evidence          string      `json:"evidence"`
	Fix               string      `json:"fix"`
	References        []string    `json:"references"`
	Confidence        Confidence  `json:"confidence"`
	Line              *string     `json:"line"`
	TaintChain        []TaintLink `json:"taint_chain,omitempty"`
	Reachable         bool        `json:"reachable,omitempty"`
	// SourceTier records the analysis engine tier (Proven Path v1). Empty
	// for blackbox / pre-field findings. See SourceTier doc.
	SourceTier SourceTier `json:"source_tier,omitempty"`
	// Route binds the finding to its HTTP route (Proven Path v1). Empty
	// when unbound. A non-empty Route + a TaintChain is the v1 "proof":
	// route → handler → source→sink taint path.
	Route *Route `json:"route,omitempty"`
}

// SeverityRank returns a numeric rank for severity comparison.
// Higher values indicate more severe findings.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
