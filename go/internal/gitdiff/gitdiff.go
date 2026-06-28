// Package gitdiff resolves the set of files changed in a working tree and
// exposes a path Allowlist that the whitebox scanners consult to scope a
// scan to only those files — the engine half of "diff-aware scanning"
// (`fendix scan --diff[=ref] --staged`), the single most important
// developer-workflow feature in the 90-day cut.
//
// Why os/exec git instead of go-git: the codebase deliberately avoids the
// go-git dependency (it is large and has surprising defaults — see
// internal/pluginscmd). Resolving a changed-file list is a one-shot
// `git diff --name-only` shell-out; the heavyweight library buys us
// nothing here. The only git feature we need is name-only diff output,
// which every git since 1.x prints identically.
//
// The Allowlist is intentionally a separate, scanner-agnostic type so the
// secrets / textscan / semgrep packages can filter against it without
// importing each other or the orchestrator. A nil *Allowlist means
// "no diff scoping" and every scanner behaves exactly as it does in a
// full scan — diff mode can only ever *narrow* the file set, never change
// detection logic, so it cannot move the heavy-eval F1 score.
package gitdiff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// execCommand is a seam for tests to stub the git subprocess. Production
// code always uses exec.CommandContext; tests swap in a fake that returns
// canned name-only output without needing a real repository.
var execCommand = exec.CommandContext

// Options selects which changed-file set git should report.
type Options struct {
	// RepoRoot is the directory the git command runs in. Empty means the
	// process working directory. The resolved Allowlist paths are made
	// absolute against this root.
	RepoRoot string
	// Ref, when non-empty, diffs the working tree (or the index, if
	// Staged) against this git ref — a branch, tag, or commit-ish such as
	// "origin/main" or "HEAD~1". Empty Ref diffs against HEAD.
	Ref string
	// Staged restricts the diff to changes staged in the index
	// (`git diff --cached`) — the set a pre-commit hook must scan. When
	// false, unstaged working-tree changes are included too.
	Staged bool
}

// ChangedFiles returns the repo-relative paths of files changed under the
// given options, in sorted order, with deletions excluded (a deleted file
// has nothing left to scan). The returned slice is empty (not nil) when
// the tree is clean, so callers can distinguish "nothing changed" from an
// error.
//
// Renames are reported as their new path (--diff-filter excludes the old
// side via D). Paths git would quote (those containing unusual bytes) are
// returned verbatim from `-z` NUL-delimited output, so no shell unquoting
// is needed.
func ChangedFiles(ctx context.Context, opts Options) ([]string, error) {
	args := []string{"diff", "--name-only", "-z",
		// Drop deletions: scanning a path that no longer exists is a no-op
		// at best and a stat error at worst. A (D)eleted file cannot carry
		// a new finding.
		"--diff-filter=d"}
	if opts.Staged {
		args = append(args, "--cached")
	}
	if opts.Ref != "" {
		args = append(args, opts.Ref)
	}

	cmd := execCommand(ctx, "git", args...)
	if opts.RepoRoot != "" {
		cmd.Dir = opts.RepoRoot
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git diff failed: %s", msg)
	}

	// -z yields NUL-separated, unquoted paths with a trailing NUL.
	raw := strings.Split(strings.TrimRight(stdout.String(), "\x00"), "\x00")
	files := make([]string, 0, len(raw))
	for _, p := range raw {
		if p == "" {
			continue
		}
		files = append(files, p)
	}
	sort.Strings(files)
	return files, nil
}

// Allowlist is a set of absolute file paths a diff-aware scan is restricted
// to. A nil *Allowlist means "no scoping" — see the package doc. Methods are
// nil-safe so callers can hold a *Allowlist field that is nil in full-scan
// mode and pass it straight to scanners.
type Allowlist struct {
	abs map[string]struct{}
}

// NewAllowlist builds an Allowlist from repo-relative paths resolved against
// root. Paths are cleaned and made absolute so a scanner walking an absolute
// tree (secrets/textscan call filepath.Abs on their root) can match entries
// directly. An empty paths slice yields a non-nil, empty Allowlist that
// matches nothing — the correct behaviour for "diff requested, zero files
// changed" (scan nothing, not everything).
func NewAllowlist(root string, paths []string) *Allowlist {
	al := &Allowlist{abs: make(map[string]struct{}, len(paths))}
	for _, p := range paths {
		joined := p
		if !filepath.IsAbs(p) {
			joined = filepath.Join(root, p)
		}
		if abs, err := filepath.Abs(joined); err == nil {
			al.abs[filepath.Clean(abs)] = struct{}{}
		} else {
			al.abs[filepath.Clean(joined)] = struct{}{}
		}
	}
	return al
}

// Allows reports whether the given path is in the allowlist. A nil
// Allowlist allows everything (full-scan semantics). The path is cleaned
// and absolutised before lookup so callers may pass either absolute or
// root-relative paths.
func (a *Allowlist) Allows(path string) bool {
	if a == nil {
		return true
	}
	abs := path
	if !filepath.IsAbs(path) {
		if resolved, err := filepath.Abs(path); err == nil {
			abs = resolved
		}
	}
	_, ok := a.abs[filepath.Clean(abs)]
	return ok
}

// Empty reports whether the allowlist scopes the scan to zero files. Always
// false for a nil Allowlist (full scan). Lets the orchestrator short-circuit
// the expensive whitebox walk when a diff matched nothing scannable.
func (a *Allowlist) Empty() bool {
	return a != nil && len(a.abs) == 0
}

// Len returns the number of files in the allowlist (0 for nil).
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.abs)
}

// AbsPaths returns the allowlist entries as cleaned absolute paths, sorted.
// The diff-aware scanners use it to scan only the changed files directly —
// O(changed files) — instead of walking the whole tree to filter down to
// them. A nil/empty allowlist yields nil.
func (a *Allowlist) AbsPaths() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.abs))
	for abs := range a.abs {
		out = append(out, abs)
	}
	sort.Strings(out)
	return out
}

// RelPaths returns the allowlist entries relative to root, sorted. Used to
// build the semgrep `--include` glob set and for diagnostic logging. A nil
// or empty allowlist yields an empty slice.
func (a *Allowlist) RelPaths(root string) []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.abs))
	for abs := range a.abs {
		if rel, err := filepath.Rel(root, abs); err == nil {
			out = append(out, filepath.ToSlash(rel))
		} else {
			out = append(out, filepath.ToSlash(abs))
		}
	}
	sort.Strings(out)
	return out
}

// ContainsBase reports whether any allowlisted file has the given base name
// (e.g. "go.mod", "package-lock.json", "poetry.lock"). The SCA gate uses
// this to decide whether a dependency manifest changed and the ecosystem's
// dep-CVE scan must run. Matching is on the final path element only, so a
// nested service's manifest (services/api/requirements.txt) still triggers.
func (a *Allowlist) ContainsBase(names ...string) bool {
	if a == nil {
		// No scoping → behave as a full scan: every manifest is "in scope".
		return true
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	for abs := range a.abs {
		if _, ok := want[filepath.Base(abs)]; ok {
			return true
		}
	}
	return false
}
