package initcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, rel string, content string) {
	t.Helper()
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDetect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	d := Detect(dir)
	if len(d.Stacks) != 0 {
		t.Errorf("empty dir: want no stacks, got %v", d.Stacks)
	}
	if len(d.Specs) != 0 {
		t.Errorf("empty dir: want no specs, got %v", d.Specs)
	}
	if d.PrimaryStack().Name != "Generic" {
		t.Errorf("PrimaryStack on empty: want Generic, got %s", d.PrimaryStack().Name)
	}
}

func TestDetect_GoProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/foo\n")
	d := Detect(dir)
	if len(d.Stacks) != 1 || d.Stacks[0].Name != "Go" {
		t.Errorf("want Go stack, got %v", d.Stacks)
	}
	if d.Stacks[0].Marker != "go.mod" {
		t.Errorf("want marker go.mod, got %s", d.Stacks[0].Marker)
	}
}

func TestDetect_PythonProject_DedupsStackName(t *testing.T) {
	dir := t.TempDir()
	// Both pyproject.toml AND requirements.txt are common in modern
	// Python repos. The detector should report Python ONCE, not twice.
	writeFile(t, dir, "pyproject.toml", "[project]\nname='foo'\n")
	writeFile(t, dir, "requirements.txt", "requests==2.31.0\n")
	d := Detect(dir)
	if len(d.Stacks) != 1 {
		t.Fatalf("want 1 stack (deduped), got %d: %v", len(d.Stacks), d.Stacks)
	}
	if d.Stacks[0].Name != "Python" {
		t.Errorf("want Python, got %s", d.Stacks[0].Name)
	}
	// pyproject.toml is checked before requirements.txt in stackMarkers,
	// so it should be the recorded marker.
	if d.Stacks[0].Marker != "pyproject.toml" {
		t.Errorf("want pyproject.toml marker (preferred over requirements.txt), got %s", d.Stacks[0].Marker)
	}
}

func TestDetect_Polyglot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/foo\n")
	writeFile(t, dir, "package.json", "{}\n")
	writeFile(t, dir, "pyproject.toml", "[project]\n")
	d := Detect(dir)
	if len(d.Stacks) != 3 {
		t.Fatalf("want 3 stacks, got %d: %v", len(d.Stacks), d.Stacks)
	}
	// Order in stackMarkers is Go → Python → Node.js, so primary
	// should be Go.
	if d.PrimaryStack().Name != "Go" {
		t.Errorf("polyglot primary: want Go, got %s", d.PrimaryStack().Name)
	}
}

func TestDetect_OpenAPISpec_RootLevel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", "openapi: 3.0.0\n")
	d := Detect(dir)
	if len(d.Specs) != 1 || d.Specs[0].Path != "openapi.yaml" {
		t.Errorf("want openapi.yaml, got %v", d.Specs)
	}
}

func TestDetect_OpenAPISpec_NestedPaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api/openapi.json", "{}")
	writeFile(t, dir, "docs/openapi.yaml", "openapi: 3.0.0\n")
	d := Detect(dir)
	if len(d.Specs) != 2 {
		t.Fatalf("want 2 specs, got %d: %v", len(d.Specs), d.Specs)
	}
}

func TestDetect_OpenAPISpec_NotFoundOnUnusualPath(t *testing.T) {
	dir := t.TempDir()
	// We deliberately do NOT scan arbitrary paths — only known
	// conventional locations. A spec at custom-dir/openapi.yaml
	// won't be auto-detected, and that's the documented behavior.
	writeFile(t, dir, "custom-dir/openapi.yaml", "openapi: 3.0.0\n")
	d := Detect(dir)
	if len(d.Specs) != 0 {
		t.Errorf("want no specs at unconventional path, got %v", d.Specs)
	}
}

func TestSummaryLine_GoWithSpec(t *testing.T) {
	d := Detection{
		Stacks: []Stack{{Name: "Go", Marker: "go.mod"}},
		Specs:  []SpecLocation{{Path: "openapi.yaml"}},
	}
	got := d.SummaryLine()
	want := "Go, OpenAPI spec at openapi.yaml"
	if got != want {
		t.Errorf("SummaryLine: got %q, want %q", got, want)
	}
}

func TestSummaryLine_PolyglotWithoutSpec(t *testing.T) {
	d := Detection{
		Stacks: []Stack{
			{Name: "Go", Marker: "go.mod"},
			{Name: "Python", Marker: "pyproject.toml"},
		},
	}
	got := d.SummaryLine()
	want := "Go (also: Python) — no OpenAPI spec found at common paths"
	if got != want {
		t.Errorf("SummaryLine: got %q, want %q", got, want)
	}
}

func TestSummaryLine_GenericNoSpec(t *testing.T) {
	d := Detection{}
	got := d.SummaryLine()
	want := "Generic — no OpenAPI spec found at common paths"
	if got != want {
		t.Errorf("SummaryLine: got %q, want %q", got, want)
	}
}
