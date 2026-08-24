package applicability

import "regexp"

// Lang selects which source-file matcher a component token uses. A Python
// token can only ever match inside a Python file and a JS token inside a
// JS/TS file — a plain substring search would cross-match constantly
// (`lodash/template` appears in a .py comment; `django.contrib.gis` in a
// .ts string) and every cross-match is a MISSED de-escalation, so the
// routing is about precision rather than speed.
type Lang int

const (
	// LangPython covers .py / .pyi.
	LangPython Lang = iota
	// LangJS covers .js .jsx .ts .tsx .mjs .cjs .mts .cts.
	LangJS
)

func (l Lang) String() string {
	if l == LangJS {
		return "js"
	}
	return "python"
}

// Component is one importable unit an advisory is scoped to.
type Component struct {
	// Import is the dotted Python module path ("django.contrib.gis") or the
	// JS specifier ("lodash/template") the scanned tree would import.
	Import string
	Lang   Lang
}

// ── The curated catalog ─────────────────────────────────────────────────
//
// Both tables are plain Go literals rather than an embedded YAML rule pack,
// matching textscan/rules.go — the closest analogue in this codebase and
// itself a curated detection table. The regexes are compile-checked, the
// table is diff-reviewable, and a malformed entry is a build failure rather
// than a runtime parse error. (The go:embed-YAML pattern in
// scanner/semgrep exists for rule packs that ship independently of the
// binary; this catalog does not.)
//
// The catalog is deliberately SMALL. A wrong entry here de-escalates a real
// risk, so every entry has to be one a human has actually checked. When a
// package or advisory is not in the catalog, nothing happens at all — the
// finding keeps its full confidence, which is the safe direction.

// byAdvisory maps an OSV id OR any of its aliases to the components the
// advisory touches. It is the highest-precision tier and is consulted
// first, and it is the ONLY way to scope an advisory whose own text never
// names its component.
//
// It ships empty on purpose. An entry is an assertion about a specific
// published advisory, and asserting one without having read that advisory
// would silently reduce the confidence of a finding that deserves full
// weight. Add entries as advisories are curated; the byPackage tier below
// carries the general case in the meantime because it is self-evidencing —
// it only fires when the advisory's own summary says which component it
// touches.
var byAdvisory = map[string][]Component{}

// packageRule scopes an advisory to components only when the advisory's own
// summary/details match Pattern. Deterministic regex, no model and no
// randomness (Rule 8) — and self-evidencing: the advisory text is what
// justifies the claim, so a rule cannot mis-scope an advisory that never
// mentions the component.
type packageRule struct {
	Pattern    *regexp.Regexp
	Components []Component
}

// byPackage is keyed "<ecosystem>/<lowercased package>", matching the
// (deps.ecosystem, deps.package) metadata the dep scanners stamp.
var byPackage = map[string][]packageRule{
	"PyPI/django": {
		{
			// GeoDjango is an optional stack: it needs GDAL/GEOS installed
			// and a spatial database backend, and the overwhelming majority
			// of Django projects never import it.
			Pattern: regexp.MustCompile(`(?i)\bcontrib\.gis\b|\bgeodjango\b`),
			Components: []Component{
				{Import: "django.contrib.gis", Lang: LangPython},
			},
		},
		{
			// django.contrib.postgres is Postgres-only and opt-in.
			Pattern: regexp.MustCompile(`(?i)\bcontrib\.postgres\b`),
			Components: []Component{
				{Import: "django.contrib.postgres", Lang: LangPython},
			},
		},
		{
			// The bundled admin site is frequently removed from
			// API-only deployments.
			Pattern: regexp.MustCompile(`(?i)\bcontrib\.admin\b|\bdjango admin\b|\badmin site\b`),
			Components: []Component{
				{Import: "django.contrib.admin", Lang: LangPython},
			},
		},
	},
	"npm/lodash": {
		{
			// lodash's template-injection advisories name `_.template`
			// explicitly. The per-method entry point is importable on its
			// own, and a project using only `_.get`/`_.merge` never reaches
			// it. The pattern requires the METHOD to be named — a bare
			// "template" would match far too much prose.
			Pattern: regexp.MustCompile(`(?i)_\.template\b|\blodash/template\b`),
			Components: []Component{
				{Import: "lodash/template", Lang: LangJS},
			},
		},
	},
}
