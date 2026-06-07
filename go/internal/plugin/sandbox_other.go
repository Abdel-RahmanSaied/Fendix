//go:build !unix

package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkEntrypointSafe is the best-effort portable variant of the Unix
// pre-exec check (F-H2). Non-Unix platforms (Windows) don't expose the
// POSIX uid / mode bits the full check relies on, so we enforce only
// the portable invariants: the entrypoint must stay under the plugin
// dir, and no component within the dir may be a symlink that escapes
// it. Ownership and group/other-writability are not checked here —
// documented as a known gap; the primary deployment target is Unix CI.
func checkEntrypointSafe(dir, entrypoint string) error {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve plugin dir: %w", err)
	}
	entAbs, err := filepath.Abs(entrypoint)
	if err != nil {
		return fmt.Errorf("resolve entrypoint: %w", err)
	}

	rel, err := filepath.Rel(dirAbs, entAbs)
	if err != nil {
		return fmt.Errorf("entrypoint %q is not under plugin dir %q: %w", entAbs, dirAbs, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("entrypoint %q escapes plugin dir %q", entAbs, dirAbs)
	}

	cur := dirAbs
	parts := []string{}
	if rel != "." {
		parts = strings.Split(rel, string(os.PathSeparator))
	}
	chain := []string{dirAbs}
	for _, part := range parts {
		cur = filepath.Join(cur, part)
		chain = append(chain, cur)
	}

	for _, path := range chain {
		fi, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("lstat %q: %w", path, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("resolve symlink %q: %w", path, err)
		}
		within, err := pathWithin(dirAbs, target)
		if err != nil {
			return fmt.Errorf("evaluate symlink target %q: %w", target, err)
		}
		if !within {
			return fmt.Errorf("entrypoint chain component %q is a symlink escaping the plugin dir (target %q)", path, target)
		}
	}
	return nil
}

// pathWithin reports whether target is the directory root itself or a
// path nested under it. Both arguments must be absolute.
func pathWithin(root, target string) (bool, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false, err
	}
	if rel == "." {
		return true, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}
	return true, nil
}
