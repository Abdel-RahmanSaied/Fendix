package hookcmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newRepo creates a real git repo in a temp dir and returns its path. Real
// git (not a stub) is used because hooksDir() exercises rev-parse / config
// resolution that a stub would have to reimplement anyway.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@t.t"},
		{"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// inDir runs fn with the process cwd set to dir, restoring it after. The
// hook commands operate on the cwd's repo, matching how a user invokes them.
func inDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()
	fn()
}

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := NewCmd()
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(&buf)
	c.SetArgs(args)
	err := c.Execute()
	return buf.String(), err
}

func TestInstall_WritesExecutableHookWithSentinel(t *testing.T) {
	repo := newRepo(t)
	inDir(t, repo, func() {
		out, err := runCmd(t, "install")
		if err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
		hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
		info, serr := os.Stat(hook)
		if serr != nil {
			t.Fatalf("hook not written: %v", serr)
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("hook is not executable: mode %v", info.Mode())
		}
		body, _ := os.ReadFile(hook)
		s := string(body)
		if !strings.Contains(s, hookSentinel) {
			t.Error("hook missing fendix sentinel comment")
		}
		for _, want := range []string{"--staged", "--fast", "--fail-on HIGH", "scan --code ."} {
			if !strings.Contains(s, want) {
				t.Errorf("hook script missing %q\n%s", want, s)
			}
		}
	})
}

func TestInstall_CustomFailOn(t *testing.T) {
	repo := newRepo(t)
	inDir(t, repo, func() {
		if _, err := runCmd(t, "install", "--fail-on", "CRITICAL"); err != nil {
			t.Fatal(err)
		}
		body, _ := os.ReadFile(filepath.Join(repo, ".git", "hooks", "pre-commit"))
		if !strings.Contains(string(body), "--fail-on CRITICAL") {
			t.Errorf("custom --fail-on not honoured:\n%s", body)
		}
	})
}

func TestInstall_RefusesToClobberForeignHook(t *testing.T) {
	repo := newRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	inDir(t, repo, func() {
		_, err := runCmd(t, "install")
		if err == nil {
			t.Fatal("install should refuse to overwrite a non-fendix hook without --force")
		}
		// The foreign hook must be untouched.
		body, _ := os.ReadFile(hookPath)
		if !strings.Contains(string(body), "echo mine") {
			t.Error("foreign hook was modified despite the refusal")
		}
	})
}

func TestInstall_ForceReplacesForeignHook(t *testing.T) {
	repo := newRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	_ = os.MkdirAll(filepath.Dir(hookPath), 0o755)
	_ = os.WriteFile(hookPath, []byte("#!/bin/sh\necho mine\n"), 0o755)
	inDir(t, repo, func() {
		if _, err := runCmd(t, "install", "--force"); err != nil {
			t.Fatalf("force install failed: %v", err)
		}
		body, _ := os.ReadFile(hookPath)
		if !strings.Contains(string(body), hookSentinel) {
			t.Error("force install did not replace the foreign hook")
		}
	})
}

func TestInstall_ReinstallOverFendixHookSucceeds(t *testing.T) {
	repo := newRepo(t)
	inDir(t, repo, func() {
		if _, err := runCmd(t, "install"); err != nil {
			t.Fatal(err)
		}
		// A second install (e.g. to change --fail-on) must not need --force.
		if _, err := runCmd(t, "install", "--fail-on", "MEDIUM"); err != nil {
			t.Fatalf("reinstall over a fendix hook should succeed: %v", err)
		}
		body, _ := os.ReadFile(filepath.Join(repo, ".git", "hooks", "pre-commit"))
		if !strings.Contains(string(body), "--fail-on MEDIUM") {
			t.Error("reinstall did not update --fail-on")
		}
	})
}

func TestStatus_ReportsInstalledState(t *testing.T) {
	repo := newRepo(t)
	inDir(t, repo, func() {
		out, _ := runCmd(t, "status")
		if !strings.Contains(out, "not installed") {
			t.Errorf("status before install should say not installed, got: %s", out)
		}
		_, _ = runCmd(t, "install")
		out, _ = runCmd(t, "status")
		if !strings.Contains(out, "installed at") {
			t.Errorf("status after install should report the path, got: %s", out)
		}
	})
}

func TestUninstall_RemovesOnlyFendixHook(t *testing.T) {
	repo := newRepo(t)
	inDir(t, repo, func() {
		_, _ = runCmd(t, "install")
		hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
		if _, err := os.Stat(hook); err != nil {
			t.Fatal("precondition: hook should exist")
		}
		if _, err := runCmd(t, "uninstall"); err != nil {
			t.Fatalf("uninstall failed: %v", err)
		}
		if _, err := os.Stat(hook); !os.IsNotExist(err) {
			t.Error("uninstall did not remove the hook")
		}
	})
}

func TestUninstall_LeavesForeignHookAlone(t *testing.T) {
	repo := newRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	_ = os.MkdirAll(filepath.Dir(hookPath), 0o755)
	_ = os.WriteFile(hookPath, []byte("#!/bin/sh\necho mine\n"), 0o755)
	inDir(t, repo, func() {
		if _, err := runCmd(t, "uninstall"); err == nil {
			t.Error("uninstall should refuse to remove a non-fendix hook")
		}
		if _, err := os.Stat(hookPath); err != nil {
			t.Error("foreign hook was removed despite the refusal")
		}
	})
}

func TestHooksDir_HonoursCoreHooksPath(t *testing.T) {
	repo := newRepo(t)
	custom := filepath.Join(repo, "myhooks")
	cmd := exec.Command("git", "config", "core.hooksPath", "myhooks")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set hooksPath: %v\n%s", err, out)
	}
	inDir(t, repo, func() {
		if _, err := runCmd(t, "install"); err != nil {
			t.Fatalf("install with core.hooksPath failed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(custom, "pre-commit")); err != nil {
			t.Errorf("hook not written into core.hooksPath dir: %v", err)
		}
	})
}

func TestInstall_NotAGitRepoErrors(t *testing.T) {
	dir := t.TempDir() // plain dir, no git init
	inDir(t, dir, func() {
		if _, err := runCmd(t, "install"); err == nil {
			t.Error("install outside a git repo should error")
		}
	})
}
