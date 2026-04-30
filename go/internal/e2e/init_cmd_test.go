//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInit_WritesFilesInProjectDir runs `fendix init` in a tempdir
// configured to look like a Python+OpenAPI project and asserts the
// init writes both expected files plus the detection echo line.
//
// This guards the wiring between the cobra command and the initcmd
// package — a regression where the flag binding broke would still pass
// the unit tests but fail this e2e (the same class of bug TASK-079
// surfaced in a different command).
func TestInit_WritesFilesInProjectDir(t *testing.T) {
	bin := fendixBinary(t)

	// Set up a fake project: pyproject.toml + an OpenAPI spec in the
	// `api/` subdir. The detection should echo "Python, OpenAPI spec
	// at api/openapi.yaml" in the init output.
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte("[project]\nname='example'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "api/openapi.yaml"), []byte("openapi: 3.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "init")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fendix init failed: %v\n%s", err, out)
	}

	got := string(out)
	for _, want := range []string{
		"✓ Detected: Python",
		"api/openapi.yaml",
		"✓ Wrote .github/workflows/fendix.yml",
		"✓ Wrote .fendix-ignore",
		"Next steps:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("init output missing %q\nfull output:\n%s", want, got)
		}
	}

	// The two files must exist on disk after init returns.
	for _, rel := range []string{".github/workflows/fendix.yml", ".fendix-ignore"} {
		info, err := os.Stat(filepath.Join(tmp, rel))
		if err != nil {
			t.Errorf("%s not on disk after init: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s on disk but empty", rel)
		}
	}

	// Sanity-check the workflow content — it should reference fendix
	// and the get.fendix.dev install URL we ship with the CLI.
	wf, err := os.ReadFile(filepath.Join(tmp, ".github/workflows/fendix.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wf, []byte("fendix")) {
		t.Errorf("workflow doesn't mention fendix")
	}
}

// TestInit_RefusesToClobber confirms the cobra flag wiring honors the
// initcmd package's pre-flight clobber-check. The exit code from a
// clobber failure should be non-zero (cobra wraps the *ErrFileExists
// the package returns).
func TestInit_RefusesToClobber(t *testing.T) {
	bin := fendixBinary(t)
	tmp := t.TempDir()

	// Pre-existing workflow at the path init would write to.
	if err := os.MkdirAll(filepath.Join(tmp, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("# user's existing workflow — do not touch\n")
	if err := os.WriteFile(filepath.Join(tmp, ".github/workflows/fendix.yml"), original, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "init")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("init should have failed on existing file, but exited 0\noutput: %s", out)
	}

	got := string(out)
	if !strings.Contains(got, "refusing to overwrite") {
		t.Errorf("expected 'refusing to overwrite' in error output, got:\n%s", got)
	}

	// The user's file MUST be exactly preserved.
	gotFile, err := os.ReadFile(filepath.Join(tmp, ".github/workflows/fendix.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotFile, original) {
		t.Errorf("user's workflow was modified despite refuse-to-clobber:\ngot:  %q\nwant: %q", gotFile, original)
	}

	// And no .fendix-ignore should exist either (atomicity in spirit).
	if _, err := os.Stat(filepath.Join(tmp, ".fendix-ignore")); err == nil {
		t.Errorf(".fendix-ignore was written despite init aborting on conflict")
	}
}

// TestInit_PrintFlagDryRuns verifies --print writes the templates to
// stdout without touching the filesystem.
func TestInit_PrintFlagDryRuns(t *testing.T) {
	bin := fendixBinary(t)
	tmp := t.TempDir()

	cmd := exec.Command(bin, "init", "--print")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fendix init --print failed: %v\n%s", err, out)
	}

	got := string(out)
	for _, want := range []string{
		"──── .github/workflows/fendix.yml ────",
		"──── .fendix-ignore ────",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--print output missing %q", want)
		}
	}

	if _, err := os.Stat(filepath.Join(tmp, ".github/workflows/fendix.yml")); err == nil {
		t.Errorf("--print wrote a workflow to disk")
	}
	if _, err := os.Stat(filepath.Join(tmp, ".fendix-ignore")); err == nil {
		t.Errorf("--print wrote .fendix-ignore to disk")
	}
}
