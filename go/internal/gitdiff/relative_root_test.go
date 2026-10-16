package gitdiff

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The composite Action passes --code "." by default, and diff mode is on for
// every pull request, so a relative root must scope the diff-aware scanners
// exactly as its absolute form does. Through v3.6.1 it did not: RelPaths fell
// back to absolute paths (semgrep's --include matched nothing) and
// TraversesSymlink refused every file (textscan skipped them), while both
// scanners still reported a clean, complete run.

// chdirTempRepo creates the given files under a fresh directory, changes the
// process working directory into it for the rest of the test, and returns its
// absolute path with symlinks resolved (macOS temp dirs live under a /var
// symlink).
func chdirTempRepo(t *testing.T, files ...string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	return root
}

// rootSpellings is every way a caller may name the same scan root.
func rootSpellings(abs string) []string {
	return []string{".", "./", abs}
}

// relPathsE wraps the RelPaths call so the assertions below do not depend on
// its signature.
func relPathsE(a *Allowlist, root string) ([]string, error) {
	return a.RelPaths(root), nil
}

func relPaths(t *testing.T, a *Allowlist, root string) []string {
	t.Helper()
	got, err := relPathsE(a, root)
	if err != nil {
		t.Fatalf("RelPaths(%q): %v", root, err)
	}
	return got
}

func TestRelPaths_RelativeAndAbsoluteRootsAgree(t *testing.T) {
	changed := []string{"server.py", "deploy/k8s/worker.yaml"}
	abs := chdirTempRepo(t, changed...)
	want := []string{"deploy/k8s/worker.yaml", "server.py"}
	for _, root := range rootSpellings(abs) {
		got := relPaths(t, NewAllowlist(root, changed), root)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("RelPaths(%q) = %v, want %v", root, got, want)
		}
		for _, p := range got {
			if filepath.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") {
				t.Errorf("RelPaths(%q) produced %q, which is not a root-relative path", root, p)
			}
		}
	}
}

func TestRelPaths_EmptyAllowlistWithRelativeRoot(t *testing.T) {
	chdirTempRepo(t)
	for _, root := range []string{".", "./"} {
		if got := relPaths(t, NewAllowlist(root, nil), root); len(got) != 0 {
			t.Errorf("RelPaths(%q) of an empty allowlist = %v, want none", root, got)
		}
	}
}

func TestTraversesSymlink_RelativeRootAcceptsContainedFile(t *testing.T) {
	abs := chdirTempRepo(t, "deploy/k8s/worker.yaml", "top.go")
	for _, file := range []string{
		filepath.Join(abs, "deploy", "k8s", "worker.yaml"),
		filepath.Join(abs, "top.go"),
	} {
		for _, root := range rootSpellings(abs) {
			if TraversesSymlink(root, file) {
				t.Errorf("TraversesSymlink(%q, %q) = true; a regular file under the root must be accepted", root, file)
			}
		}
	}
}

func TestTraversesSymlink_RelativeRootStillRefusesSymlinkAndEscape(t *testing.T) {
	abs := chdirTempRepo(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(abs, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	for _, root := range rootSpellings(abs) {
		if !TraversesSymlink(root, filepath.Join(abs, "link", "f.go")) {
			t.Errorf("TraversesSymlink(%q, …/link/f.go) = false; a symlinked parent must be refused", root)
		}
		if !TraversesSymlink(root, filepath.Join(outside, "f.go")) {
			t.Errorf("TraversesSymlink(%q, outside) = false; a path outside the root must be refused", root)
		}
	}
}

// An entry that cannot be expressed under the root must be an error, never an
// absolute or ../ path handed to a scanner as a filter.
func TestRelPaths_EntryOutsideRootIsAnError(t *testing.T) {
	abs := chdirTempRepo(t, "app/server.py")
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	al := NewAllowlist(elsewhere, []string{"other.py"})
	for _, root := range rootSpellings(abs) {
		got, err := relPathsE(al, root)
		if err == nil {
			t.Errorf("RelPaths(%q) of an entry outside the root returned %v and no error", root, got)
		}
	}
}
