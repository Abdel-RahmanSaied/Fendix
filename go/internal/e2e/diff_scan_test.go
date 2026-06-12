//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitInit sets up a throwaway repo in dir with an identity so commits work
// in CI (which has no global git config).
func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "e2e@fendix.test"},
		{"config", "user.name", "fendix-e2e"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

type jsonReport struct {
	Total    int `json:"total"`
	Findings []struct {
		Endpoint string `json:"endpoint"`
		Title    string `json:"title"`
	} `json:"findings"`
}

// TestDiffStagedScan_E2E proves `fendix scan --code <repo> --staged --fast`:
//  1. scopes the whitebox scan to the files git reports as staged, and
//  2. completes well under the sub-1s budget on a non-trivial tree.
//
// We plant the SAME secret in a staged file and an unstaged file. A staged
// diff scan must report the staged one and NOT the unstaged one — that is
// the whole value of diff-aware scanning for a pre-commit hook.
func TestDiffStagedScan_E2E(t *testing.T) {
	bin := fendixBinary(t)
	repo := t.TempDir()
	gitInit(t, repo)

	// A realistic tree so the timing claim isn't trivially true.
	for _, d := range []string{"src/a", "src/b", "src/c"} {
		for i := 0; i < 30; i++ {
			write(t, filepath.Join(repo, d, "m.go"), "package x\n")
			write(t, filepath.Join(repo, d, fmt.Sprintf("f%d.py", i)), "x = 1\n")
		}
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "baseline")

	const secret = "GITHUB_TOKEN = \"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\"\n"
	staged := filepath.Join(repo, "src/a/changed.py")
	unstaged := filepath.Join(repo, "src/b/other.py")
	write(t, staged, secret)
	write(t, unstaged, secret)
	git(t, repo, "add", "src/a/changed.py") // stage ONLY the first

	start := time.Now()
	cmd := exec.Command(bin, "scan", "--code", repo, "--staged", "--fast", "--format", "json")
	out, err := cmd.Output()
	elapsed := time.Since(start)
	// Exit 1 (findings present) is expected and fine; only a >1 exit is a
	// hard failure. cmd.Output returns *ExitError for non-zero exits.
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 1 {
			t.Fatalf("scan failed (exit>1): %v\nstderr:\n%s", err, exitStderr(err))
		}
	}

	var rep jsonReport
	if jerr := json.Unmarshal(out, &rep); jerr != nil {
		t.Fatalf("report not valid JSON: %v\n%s", jerr, out)
	}

	// The staged secret must be reported.
	if !hasEndpointContaining(rep, "changed.py") {
		t.Errorf("staged diff scan missed the secret in the staged file; findings=%+v", rep.Findings)
	}
	// The unstaged secret must NOT be reported — that's the scoping guarantee.
	if hasEndpointContaining(rep, "other.py") {
		t.Errorf("staged diff scan leaked a finding from an UNSTAGED file; findings=%+v", rep.Findings)
	}

	// Budget: fast staged scan on ~180 files must be comfortably sub-second.
	// Generous 2s ceiling absorbs CI cold-cache + binary spawn; the steady
	// state is tens of ms.
	if elapsed > 2*time.Second {
		t.Errorf("diff scan took %v, expected sub-second budget", elapsed)
	}
	t.Logf("staged --fast diff scan of repo completed in %v", elapsed)
}

// TestDiffRefScan_E2E proves `--diff=<ref>` scopes to files changed since a
// ref (not just the index), the CI-PR-comment use case.
func TestDiffRefScan_E2E(t *testing.T) {
	bin := fendixBinary(t)
	repo := t.TempDir()
	gitInit(t, repo)
	write(t, filepath.Join(repo, "keep.py"), "x = 1\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "base")

	const secret = "AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\"\n"
	write(t, filepath.Join(repo, "new.py"), secret)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "add new.py with secret")

	// Diff against the first commit: new.py is changed, keep.py is not.
	cmd := exec.Command(bin, "scan", "--code", repo, "--diff=HEAD~1", "--fast", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 1 {
			t.Fatalf("scan failed: %v\n%s", err, exitStderr(err))
		}
	}
	var rep jsonReport
	if jerr := json.Unmarshal(out, &rep); jerr != nil {
		t.Fatalf("report not valid JSON: %v\n%s", jerr, out)
	}
	if !hasEndpointContaining(rep, "new.py") {
		t.Errorf("--diff=HEAD~1 missed the secret in the changed file; %+v", rep.Findings)
	}
}

func hasEndpointContaining(rep jsonReport, sub string) bool {
	for _, f := range rep.Findings {
		if strings.Contains(f.Endpoint, sub) {
			return true
		}
	}
	return false
}

func exitStderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return string(ee.Stderr)
	}
	return ""
}
