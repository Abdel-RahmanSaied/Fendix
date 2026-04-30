package initcmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_WritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	err := Run(Options{RootDir: dir, Out: &out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, rel := range []string{".github/workflows/fendix.yml", ".fendix.yaml", ".fendix-ignore"} {
		abs := filepath.Join(dir, rel)
		info, err := os.Stat(abs)
		if err != nil {
			t.Errorf("%s not written: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", rel)
		}
	}

	got := out.String()
	for _, want := range []string{
		"✓ Detected:",
		"✓ Wrote .github/workflows/fendix.yml",
		"✓ Wrote .fendix.yaml",
		"✓ Wrote .fendix-ignore",
		"Next steps:",
		"git add .github/workflows/fendix.yml .fendix.yaml .fendix-ignore",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRun_RefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	// Pre-existing workflow — Run should refuse without --force.
	if err := os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github/workflows/fendix.yml"), []byte("# user's existing workflow\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Run(Options{RootDir: dir, Out: &out})
	if err == nil {
		t.Fatalf("want ErrFileExists, got nil")
	}
	var fileErr *ErrFileExists
	if !errors.As(err, &fileErr) {
		t.Fatalf("want *ErrFileExists, got %T: %v", err, err)
	}
	if fileErr.Path != ".github/workflows/fendix.yml" {
		t.Errorf("want path .github/workflows/fendix.yml, got %s", fileErr.Path)
	}

	// And critically — the existing file MUST be untouched. The
	// pre-flight check that prevents clobbering should run before
	// any write happens.
	got, err := os.ReadFile(filepath.Join(dir, ".github/workflows/fendix.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# user's existing workflow\n" {
		t.Errorf("user's file was clobbered despite refuse-to-clobber: %q", got)
	}

	// AND no other init file should have been created (atomicity in
	// spirit — either everything writes or nothing does).
	if _, err := os.Stat(filepath.Join(dir, ".fendix-ignore")); err == nil {
		t.Errorf(".fendix-ignore was written despite Run aborting on conflict")
	}
	if _, err := os.Stat(filepath.Join(dir, ".fendix.yaml")); err == nil {
		t.Errorf(".fendix.yaml was written despite Run aborting on conflict")
	}
}

func TestRun_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github/workflows/fendix.yml"), []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, Force: true, Out: &out}); err != nil {
		t.Fatalf("Run --force: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, ".github/workflows/fendix.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "# old\n" {
		t.Errorf("--force did not overwrite the existing file")
	}
	if !bytes.Contains(got, []byte("Fendix")) {
		t.Errorf("written workflow doesn't contain 'Fendix' — wrong template? got: %q", got)
	}
}

func TestRun_PrintDoesNotWriteFiles(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, Print: true, Out: &out}); err != nil {
		t.Fatalf("Run --print: %v", err)
	}

	// No files should be on disk after a --print run.
	if _, err := os.Stat(filepath.Join(dir, ".github/workflows/fendix.yml")); err == nil {
		t.Errorf("--print wrote a file to disk")
	}
	if _, err := os.Stat(filepath.Join(dir, ".fendix-ignore")); err == nil {
		t.Errorf("--print wrote .fendix-ignore to disk")
	}
	if _, err := os.Stat(filepath.Join(dir, ".fendix.yaml")); err == nil {
		t.Errorf("--print wrote .fendix.yaml to disk")
	}

	got := out.String()
	for _, want := range []string{
		"──── .github/workflows/fendix.yml ────",
		"──── .fendix.yaml ────",
		"──── .fendix-ignore ────",
		"Fendix",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--print output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRun_DetectionEchoedToOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, Out: &out}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(out.String(), "✓ Detected: Go") {
		t.Errorf("detection line missing or wrong stack:\n%s", out.String())
	}
}
