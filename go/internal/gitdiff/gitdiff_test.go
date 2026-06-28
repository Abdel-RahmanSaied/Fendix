package gitdiff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// withFakeGit swaps execCommand for a stub that echoes the given NUL-joined
// path list (or fails, when failMsg is set) and records the args git was
// called with. Restores the real execCommand on cleanup.
func withFakeGit(t *testing.T, nulOutput string, failMsg string, gotArgs *[]string) {
	t.Helper()
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if gotArgs != nil {
			*gotArgs = args
		}
		// Build a real *exec.Cmd that runs /bin/sh to reproduce the canned
		// stdout/stderr+exit without depending on a git repo. NUL bytes
		// can't ride through an env var (Go's exec rejects them), so encode
		// the output as a printf format string with \0 for separators.
		c := exec.CommandContext(ctx, "/bin/sh", "-c", scriptFor(nulOutput, failMsg))
		c.Env = os.Environ()
		return c
	}
}

func TestChangedFiles_ParsesNulDelimitedAndSorts(t *testing.T) {
	var args []string
	// Intentionally unsorted, with a trailing NUL and an empty token.
	withFakeGit(t, "src/b.py\x00src/a.go\x00", "", &args)

	got, err := ChangedFiles(context.Background(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"src/a.go", "src/b.py"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Always name-only, NUL-delimited, deletions filtered out.
	joined := strings.Join(args, " ")
	for _, must := range []string{"diff", "--name-only", "-z", "--diff-filter=d"} {
		if !strings.Contains(joined, must) {
			t.Errorf("git args %q missing %q", joined, must)
		}
	}
}

func TestChangedFiles_StagedAddsCached(t *testing.T) {
	var args []string
	withFakeGit(t, "", "", &args)
	if _, err := ChangedFiles(context.Background(), Options{Staged: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(args, "--cached") {
		t.Errorf("staged scan must pass --cached; got %v", args)
	}
}

func TestChangedFiles_RefIsPassedThrough(t *testing.T) {
	var args []string
	withFakeGit(t, "", "", &args)
	if _, err := ChangedFiles(context.Background(), Options{Ref: "origin/main"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(args, "origin/main") {
		t.Errorf("ref must be forwarded to git; got %v", args)
	}
}

func TestChangedFiles_CleanTreeReturnsEmptyNotNil(t *testing.T) {
	withFakeGit(t, "", "", nil)
	got, err := ChangedFiles(context.Background(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("clean tree must return a non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("clean tree must return zero files, got %v", got)
	}
}

func TestChangedFiles_GitErrorSurfacesStderr(t *testing.T) {
	withFakeGit(t, "", "fatal: not a git repository", nil)
	_, err := ChangedFiles(context.Background(), Options{})
	if err == nil {
		t.Fatal("expected error when git fails")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("error should surface git stderr, got: %v", err)
	}
}

func TestAllowlist_NilAllowsEverything(t *testing.T) {
	var al *Allowlist
	if !al.Allows("/any/path.go") {
		t.Error("nil allowlist must allow every path (full-scan semantics)")
	}
	if al.Empty() {
		t.Error("nil allowlist is not Empty (it is full-scan, not zero-scope)")
	}
	if !al.ContainsBase("go.mod") {
		t.Error("nil allowlist must report every manifest in scope")
	}
	if al.Len() != 0 {
		t.Errorf("nil allowlist Len should be 0, got %d", al.Len())
	}
}

func TestAllowlist_AllowsOnlyListedFiles(t *testing.T) {
	root := t.TempDir()
	al := NewAllowlist(root, []string{"a.go", "sub/b.py"})

	if !al.Allows(filepath.Join(root, "a.go")) {
		t.Error("a.go should be allowed (absolute)")
	}
	if !al.Allows(filepath.Join(root, "sub", "b.py")) {
		t.Error("sub/b.py should be allowed")
	}
	if al.Allows(filepath.Join(root, "c.go")) {
		t.Error("c.go is not in the diff and must be rejected")
	}
}

func TestAllowlist_EmptyMatchesNothing(t *testing.T) {
	al := NewAllowlist(t.TempDir(), nil)
	if !al.Empty() {
		t.Error("allowlist built from zero paths must be Empty")
	}
	if al.Allows("/anything.go") {
		t.Error("empty (non-nil) allowlist must reject every path")
	}
}

func TestAllowlist_ContainsBaseMatchesNestedManifest(t *testing.T) {
	root := t.TempDir()
	al := NewAllowlist(root, []string{"services/api/requirements.txt", "README.md"})

	if !al.ContainsBase("requirements.txt") {
		t.Error("nested requirements.txt must satisfy the SCA gate")
	}
	if al.ContainsBase("go.mod", "package-lock.json") {
		t.Error("no go.mod / package-lock.json changed; gate must be closed")
	}
}

func TestAllowlist_RelPathsRoundTrips(t *testing.T) {
	root := t.TempDir()
	al := NewAllowlist(root, []string{"z.go", "a/b.py"})
	rel := al.RelPaths(root)
	want := []string{"a/b.py", "z.go"}
	if !reflect.DeepEqual(rel, want) {
		t.Fatalf("RelPaths got %v, want %v", rel, want)
	}
}

// scriptFor builds a /bin/sh snippet that reproduces a git invocation's
// output. On failure it writes failMsg to stderr and exits 1. On success it
// emits nulOutput verbatim, translating the literal "\x00" placeholders the
// caller uses for separators into real NUL bytes via printf's \0 escape.
func scriptFor(nulOutput, failMsg string) string {
	if failMsg != "" {
		return "printf '%s' " + shQuote(failMsg) + " >&2; exit 1"
	}
	// Replace NUL with printf's \0, then feed through a single printf so the
	// separators become genuine NUL bytes in stdout.
	fmtStr := strings.ReplaceAll(nulOutput, "\x00", `\0`)
	return "printf '" + fmtStr + "'"
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestTraversesSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "real", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	// A normal in-repo file: no symlink in its path → allowed.
	if TraversesSymlink(root, filepath.Join(root, "real", "sub", "f.go")) {
		t.Error("real path wrongly flagged as traversing a symlink")
	}
	// A file reached through the symlinked dir → refused (scope escape).
	if !TraversesSymlink(root, filepath.Join(root, "link", "f.go")) {
		t.Error("path through a symlinked parent must be refused")
	}
	// A path entirely outside root → refused.
	if !TraversesSymlink(root, filepath.Join(outside, "f.go")) {
		t.Error("path outside root must be refused")
	}
}
