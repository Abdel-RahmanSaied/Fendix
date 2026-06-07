//go:build unix

package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// checkEntrypointSafe validates that the resolved entrypoint and every
// directory between the plugin root (inclusive) and the entrypoint is
// safe to execute without a second party having been able to tamper
// with it (F-H2):
//
//   - No component within the plugin dir may be a symlink that escapes
//     the plugin dir (a symlink staying inside the dir is fine — it
//     can't point at code the operator didn't already trust).
//   - No component may be group- or other-writable: a writable parent
//     lets another local user replace the entrypoint between this check
//     and exec, or swap a directory for a symlink.
//   - No component may be owned by a uid other than the invoking user
//     (or root): foreign ownership means someone else controls the
//     bytes we're about to run.
//
// dir is the absolute plugin directory; entrypoint is the resolved
// absolute path to the executable (filepath.Join(dir, spec.Entrypoint)).
// The manifest parser already rejected `..` and absolute entrypoints;
// this is the on-disk, just-before-exec second line of defence.
func checkEntrypointSafe(dir, entrypoint string) error {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve plugin dir: %w", err)
	}
	entAbs, err := filepath.Abs(entrypoint)
	if err != nil {
		return fmt.Errorf("resolve entrypoint: %w", err)
	}

	// Build the chain of paths to inspect: the plugin dir itself, then
	// each component down to and including the entrypoint. We stop at
	// the plugin dir — the operator chose where to place the plugin
	// root, so its parents are out of scope (and on a normal install the
	// root sits under ~/.fendix/plugins, which the operator owns).
	rel, err := filepath.Rel(dirAbs, entAbs)
	if err != nil {
		return fmt.Errorf("entrypoint %q is not under plugin dir %q: %w", entAbs, dirAbs, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("entrypoint %q escapes plugin dir %q", entAbs, dirAbs)
	}

	uid := os.Getuid()
	chain := []string{dirAbs}
	cur := dirAbs
	if rel != "." {
		for _, part := range strings.Split(rel, string(os.PathSeparator)) {
			cur = filepath.Join(cur, part)
			chain = append(chain, cur)
		}
	}

	for _, path := range chain {
		fi, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("lstat %q: %w", path, err)
		}

		// A symlink anywhere in the in-dir chain is rejected if it
		// escapes the plugin dir; an in-dir symlink is tolerated.
		if fi.Mode()&os.ModeSymlink != 0 {
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
			// Re-stat through the link so the perm/owner checks below
			// apply to the real on-disk object.
			fi, err = os.Stat(path)
			if err != nil {
				return fmt.Errorf("stat symlink target for %q: %w", path, err)
			}
		}

		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("entrypoint chain component %q is group/other-writable (%o); refusing to exec a tamperable plugin", path, fi.Mode().Perm())
		}

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			// Best-effort: if the platform doesn't expose Stat_t we've
			// already enforced the symlink + writability checks above.
			continue
		}
		if int(st.Uid) != uid && st.Uid != 0 {
			return fmt.Errorf("entrypoint chain component %q is owned by uid %d, not the invoking user (%d) or root; refusing to exec", path, st.Uid, uid)
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
