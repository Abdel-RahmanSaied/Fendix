package pluginscmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/plugin"
)

// ---------------------------------------------------------------------------
// deriveName — URL-to-directory-name unit cases
// ---------------------------------------------------------------------------

func TestDeriveName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://github.com/you/my-plugin", "my-plugin"},
		{"https://github.com/you/my-plugin.git", "my-plugin"},
		{"https://github.com/you/my-plugin/", "my-plugin"},
		{"https://github.com/you/my-plugin.git/", "my-plugin"},
		{"git@github.com:you/my-plugin.git", "my-plugin"},
		{"git@gitlab.com:org/sub/my-plugin.git", "my-plugin"},
		{"https://example.com/path/to/plugin?ref=main", "plugin"},
		{"https://example.com/path/to/plugin#fragment", "plugin"},
		{"file:///tmp/foo", "foo"},
		{"file:///tmp/foo/", "foo"},
	}
	for _, c := range cases {
		got := deriveName(c.in)
		if got != c.want {
			t.Errorf("deriveName(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestDeriveName_RejectsTraversal(t *testing.T) {
	// validInstallNameRe should refuse anything that came out looking dangerous.
	bad := []string{"..", ".hidden", "with/slash", "with space", "with\nnewline", ""}
	for _, name := range bad {
		if validInstallNameRe.MatchString(name) {
			t.Errorf("validInstallNameRe accepted unsafe name %q", name)
		}
	}
	good := []string{"my-plugin", "my_plugin", "my.plugin", "MyPlugin", "p1"}
	for _, name := range good {
		if !validInstallNameRe.MatchString(name) {
			t.Errorf("validInstallNameRe rejected reasonable name %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// install — happy path with stubbed gitClone + loadPluginFn
// ---------------------------------------------------------------------------

// writeFakePluginDir writes a minimal valid plugin.yaml + executable
// entrypoint into dir. Used to simulate what gitClone would land.
func writeFakePluginDir(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest := fmt.Sprintf(`name: %s
version: 0.1.0
entrypoint: ./run.sh
mode: whitebox
timeout: 30s
`, name)
	if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho done"), 0o755); err != nil {
		t.Fatalf("write entrypoint: %v", err)
	}
}

// withTempRoot redirects userPluginsRoot at a t.TempDir() so install
// can't touch a real ~/.fendix/plugins/. Returns the path it points at.
func withTempRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	orig := userPluginsRoot
	userPluginsRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { userPluginsRoot = orig })
	return root
}

func TestRunInstall_HappyPath(t *testing.T) {
	root := withTempRoot(t)
	cloneTarget := ""
	origClone := gitClone
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		cloneTarget = destDir
		writeFakePluginDir(t, destDir, "my-plugin")
		return nil, nil
	}
	t.Cleanup(func() { gitClone = origClone })

	var out, errOut bytes.Buffer
	if err := runInstall(&out, &errOut, "https://github.com/me/my-plugin.git", ""); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	wantDir := filepath.Join(root, "my-plugin")
	if cloneTarget != wantDir {
		t.Errorf("git clone target = %q; want %q", cloneTarget, wantDir)
	}
	got := out.String()
	if !strings.Contains(got, "Installed plugin my-plugin") {
		t.Errorf("stdout missing success line: %q", got)
	}
}

func TestRunInstall_RefusesPreexisting(t *testing.T) {
	root := withTempRoot(t)
	existing := filepath.Join(root, "my-plugin")
	writeFakePluginDir(t, existing, "my-plugin")

	called := false
	origClone := gitClone
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		called = true
		return nil, nil
	}
	t.Cleanup(func() { gitClone = origClone })

	var out, errOut bytes.Buffer
	err := runInstall(&out, &errOut, "https://github.com/me/my-plugin.git", "")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v; want 'already exists'", err)
	}
	if called {
		t.Errorf("git clone called despite preexisting dest")
	}
}

func TestRunInstall_GitCloneError_BubblesStderr(t *testing.T) {
	_ = withTempRoot(t)
	origClone := gitClone
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		return []byte("fatal: Authentication failed"), errors.New("exit status 128")
	}
	t.Cleanup(func() { gitClone = origClone })

	var out, errOut bytes.Buffer
	err := runInstall(&out, &errOut, "https://example.com/private.git", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Authentication failed") {
		t.Errorf("err = %v; want stderr context", err)
	}
}

func TestRunInstall_CleansUpOnInvalidPlugin(t *testing.T) {
	_ = withTempRoot(t)
	cloneTarget := ""
	origClone := gitClone
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		cloneTarget = destDir
		// Clone but DON'T write plugin.yaml — the post-clone validation
		// should remove the directory.
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return nil, err
		}
		return nil, nil
	}
	t.Cleanup(func() { gitClone = origClone })

	var out, errOut bytes.Buffer
	err := runInstall(&out, &errOut, "https://github.com/me/not-a-plugin.git", "")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if _, statErr := os.Stat(cloneTarget); statErr == nil {
		t.Errorf("clone dir %s should be removed after validation failure", cloneTarget)
	}
}

func TestRunInstall_NameOverride(t *testing.T) {
	root := withTempRoot(t)
	origClone := gitClone
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		writeFakePluginDir(t, destDir, "my-plugin")
		return nil, nil
	}
	t.Cleanup(func() { gitClone = origClone })

	var out, errOut bytes.Buffer
	if err := runInstall(&out, &errOut, "https://github.com/me/my-plugin.git", "custom-name"); err != nil {
		t.Fatalf("runInstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "custom-name")); err != nil {
		t.Errorf("expected custom-name dir to exist: %v", err)
	}
}

func TestRunInstall_RejectsUnsafeDerivedName(t *testing.T) {
	withTempRoot(t)
	// "../etc/passwd" → after stripping etc., derived = "passwd" — fine.
	// But "" (the empty derived from "" URL) is what we want to catch.
	var out, errOut bytes.Buffer
	err := runInstall(&out, &errOut, "", "")
	if err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("err = %v; want 'invalid characters'", err)
	}
}

// ---------------------------------------------------------------------------
// list — table render against a populated DiscoveryRoot
// ---------------------------------------------------------------------------

// withTempCwd cd's into t.TempDir() so DefaultRoots' first root
// (cwd/.fendix/plugins) points at the test's tmpdir.
func withTempCwd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

func TestListCmd_EmptyDiscovery(t *testing.T) {
	withTempCwd(t)
	cmd := newListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "no plugins found") {
		t.Errorf("expected 'no plugins found' in output: %q", got)
	}
	if !strings.Contains(got, "fendix plugins install") {
		t.Errorf("expected install hint in output: %q", got)
	}
}

func TestListCmd_WithPlugins(t *testing.T) {
	cwd := withTempCwd(t)
	repoLocalRoot := filepath.Join(cwd, ".fendix", "plugins")
	writeFakePluginDir(t, filepath.Join(repoLocalRoot, "plugin-a"), "plugin-a")
	writeFakePluginDir(t, filepath.Join(repoLocalRoot, "plugin-b"), "plugin-b")

	cmd := newListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "NAME") {
		t.Errorf("expected header row, got: %q", got)
	}
	if !strings.Contains(got, "plugin-a") || !strings.Contains(got, "plugin-b") {
		t.Errorf("expected both plugin names in output: %q", got)
	}
	// Sorted alphabetically — plugin-a before plugin-b.
	if strings.Index(got, "plugin-a") > strings.Index(got, "plugin-b") {
		t.Errorf("plugins not sorted alphabetically: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Regression test for the symlink-discovery fix folded in from TASK-127.
// ---------------------------------------------------------------------------

func TestDiscover_FollowsSymlinkedPluginDirs(t *testing.T) {
	rootDir := t.TempDir()
	// Real plugin dir lives in a separate location...
	realPluginDir := filepath.Join(t.TempDir(), "the-real-plugin")
	writeFakePluginDir(t, realPluginDir, "symlinked-plugin")

	// ...and is symlinked into the discovery root.
	pluginsRoot := filepath.Join(rootDir, ".fendix", "plugins")
	if err := os.MkdirAll(pluginsRoot, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(realPluginDir, filepath.Join(pluginsRoot, "symlinked-plugin")); err != nil {
		t.Skipf("symlink creation not supported in test env: %v", err)
	}

	plugins, err := plugin.Discover([]string{pluginsRoot})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin discovered via symlink, got %d", len(plugins))
	}
	if plugins[0].Name != "symlinked-plugin" {
		t.Errorf("plugin name = %q; want symlinked-plugin", plugins[0].Name)
	}
}
