// Package initcmd implements `fendix init` — zero-config workflow
// generator. It detects the project's stack and writes a default
// CI workflow plus a `.fendix-ignore` starter file.
package initcmd

import (
	"os"
	"path/filepath"
	"strings"
)

// Stack represents a detected primary language/framework. The detection
// is deliberately coarse — `init` doesn't currently customize output
// per stack (the workflow template is generic), but the detected stack
// is reported to the user so they can sanity-check that fendix found
// the right project.
type Stack struct {
	Name   string // e.g. "Python", "Node.js", "Go", "Generic"
	Marker string // file that triggered the detection, e.g. "go.mod"
}

// SpecLocation is a discovered OpenAPI spec path, relative to the
// project root.
type SpecLocation struct {
	Path string // e.g. "openapi.yaml", "api/openapi.json"
}

// Detection bundles everything `init` figures out about the project.
type Detection struct {
	Stacks []Stack        // all detected stacks (a polyglot repo has multiple)
	Specs  []SpecLocation // OpenAPI specs found at common paths
}

// stackMarkers maps a marker filename to a friendly stack name. Order
// matters only for the "primary" pick when reporting; all matches are
// returned.
var stackMarkers = []struct {
	Marker string
	Name   string
}{
	// Go is checked first since `go.mod` is unambiguous.
	{"go.mod", "Go"},
	// Python: pyproject.toml is the modern standard; requirements.txt
	// is the legacy/widespread one. setup.py covers older projects.
	{"pyproject.toml", "Python"},
	{"requirements.txt", "Python"},
	{"setup.py", "Python"},
	{"Pipfile", "Python"},
	// Node.js: package.json is canonical.
	{"package.json", "Node.js"},
	// Ruby
	{"Gemfile", "Ruby"},
	// Rust
	{"Cargo.toml", "Rust"},
	// Java/Kotlin (Maven, Gradle)
	{"pom.xml", "Java"},
	{"build.gradle", "Java"},
	{"build.gradle.kts", "Kotlin"},
	// PHP
	{"composer.json", "PHP"},
}

// specCandidates is the list of paths checked for an OpenAPI/Swagger
// spec, in order of preference. Both YAML and JSON are common.
var specCandidates = []string{
	"openapi.yaml",
	"openapi.yml",
	"openapi.json",
	"swagger.yaml",
	"swagger.yml",
	"swagger.json",
	"api/openapi.yaml",
	"api/openapi.yml",
	"api/openapi.json",
	"docs/openapi.yaml",
	"docs/openapi.yml",
	"docs/openapi.json",
	"spec/openapi.yaml",
	"spec/openapi.json",
}

// Detect inspects rootDir and returns a Detection summarizing what was
// found. It does not error on a missing directory or unreadable files;
// callers get an empty Detection instead. Callers should treat an empty
// Detection.Stacks as "unknown / generic".
func Detect(rootDir string) Detection {
	d := Detection{}
	seenStacks := make(map[string]bool)

	for _, m := range stackMarkers {
		path := filepath.Join(rootDir, m.Marker)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		// De-dup by stack name — a Python project can have both
		// pyproject.toml and requirements.txt; report Python once
		// but keep the first marker we found for accurate reporting.
		if seenStacks[m.Name] {
			continue
		}
		seenStacks[m.Name] = true
		d.Stacks = append(d.Stacks, Stack{Name: m.Name, Marker: m.Marker})
	}

	for _, c := range specCandidates {
		path := filepath.Join(rootDir, c)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		d.Specs = append(d.Specs, SpecLocation{Path: c})
	}

	return d
}

// PrimaryStack returns the first detected stack, or a "Generic" stack
// when none were detected. Used in the user-facing summary line.
func (d Detection) PrimaryStack() Stack {
	if len(d.Stacks) > 0 {
		return d.Stacks[0]
	}
	return Stack{Name: "Generic", Marker: ""}
}

// SummaryLine returns a one-line human-readable description of what was
// detected, suitable for the init command's "✓ Detected: ..." line.
func (d Detection) SummaryLine() string {
	stackPart := d.PrimaryStack().Name
	if len(d.Stacks) > 1 {
		extras := make([]string, 0, len(d.Stacks)-1)
		for _, s := range d.Stacks[1:] {
			extras = append(extras, s.Name)
		}
		stackPart += " (also: " + strings.Join(extras, ", ") + ")"
	}

	if len(d.Specs) == 0 {
		return stackPart + " — no OpenAPI spec found at common paths"
	}
	specPart := d.Specs[0].Path
	if len(d.Specs) > 1 {
		specPart += " (and " + plural(len(d.Specs)-1, "other", "others") + ")"
	}
	return stackPart + ", OpenAPI spec at " + specPart
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return "1 " + singular
	}
	return itoa(n) + " " + pluralForm
}

// itoa is a tiny strconv.Itoa to avoid importing strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
