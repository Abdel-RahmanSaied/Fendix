package ghapp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeBin writes an executable shell script at <dir>/<name>
// that records its argv into a sidecar file and emits the supplied
// stdout/stderr + exit code. Used to replace `git` and `fendix` on
// PATH for scanner tests so they run hermetically.
func writeFakeBin(t *testing.T, dir, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake bin uses POSIX shell; skipping on windows")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return path
}

func TestInjectInstallationToken(t *testing.T) {
	cases := []struct {
		in    string
		token string
		want  string
	}{
		{"https://github.com/owner/repo.git", "abc123",
			"https://x-access-token:abc123@github.com/owner/repo.git"},
		{"https://github.com/owner/repo", "tok",
			"https://x-access-token:tok@github.com/owner/repo"},
	}
	for _, c := range cases {
		got, err := injectInstallationToken(c.in, c.token)
		if err != nil {
			t.Fatalf("injectInstallationToken(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("injectInstallationToken(%q): got %q want %q", c.in, got, c.want)
		}
	}
}

func TestInjectInstallationToken_RejectsNonHTTPS(t *testing.T) {
	_, err := injectInstallationToken("git@github.com:owner/repo.git", "tok")
	if err == nil {
		t.Fatal("expected error for non-https URL")
	}
}

func TestRedactToken(t *testing.T) {
	got := redactToken("git fetch https://x-access-token:secret@github.com/o/r.git", "secret")
	if !strings.Contains(got, "[REDACTED]") || strings.Contains(got, "secret") {
		t.Errorf("redactToken did not redact: %q", got)
	}
}

func TestFendixScanner_Run_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX fake bins")
	}
	binDir := t.TempDir()
	// Track that each git invocation succeeds and that fendix is
	// invoked twice (scan, then report). Each fake records its argv
	// to a log file we can read back for assertions.
	gitLog := filepath.Join(binDir, "git.log")
	fendixLog := filepath.Join(binDir, "fendix.log")
	gitScript := `echo "$@" >> "` + gitLog + `"; exit 0`
	fendixScript := `echo "$@" >> "` + fendixLog + `"
# Find --output value and write the right blob to it.
prev=""; out=""
for a in "$@"; do
  if [ "$prev" = "--output" ]; then out="$a"; fi
  prev="$a"
done
case "$1" in
  scan)
    cat > "$out" <<'JSON'
{"metadata":{"mode":"whitebox","endpoints_scanned":0,"duration":"0.1s"},
 "summary":{"critical":0,"high":1,"medium":0,"low":0,"info":0},
 "sources":{"blackbox":0,"whitebox":1,"correlated":0},
 "total":1,
 "findings":[{"severity":"HIGH","title":"hardcoded secret","endpoint":"src/x.py:1","line":"src/x.py:1"}]}
JSON
    ;;
  report)
    printf '{"runs":[{"results":[{"ruleId":"x"}]}]}' > "$out"
    ;;
esac
exit 0`

	gitBin := writeFakeBin(t, binDir, "fakegit", gitScript)
	fendixBin := writeFakeBin(t, binDir, "fakefendix", fendixScript)

	s := &FendixScanner{GitBinary: gitBin, FendixBinary: fendixBin, WorkDir: t.TempDir()}
	res, err := s.Run(context.Background(), ScanRequest{
		CloneURL:          "https://github.com/owner/repo.git",
		HeadSHA:           "deadbeef",
		InstallationToken: "ghs_test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(res.FindingsJSON), `"total":1`) {
		t.Errorf("findings not captured: %s", res.FindingsJSON)
	}
	if !strings.Contains(string(res.SARIF), `"runs"`) {
		t.Errorf("sarif not captured: %s", res.SARIF)
	}

	gitLogBytes, _ := os.ReadFile(gitLog)
	gitOutput := string(gitLogBytes)
	if !strings.Contains(gitOutput, "init") {
		t.Errorf("git init not invoked, log: %s", gitOutput)
	}
	if !strings.Contains(gitOutput, "x-access-token:ghs_test@github.com") {
		t.Errorf("clone URL not authed, log: %s", gitOutput)
	}
	if !strings.Contains(gitOutput, "deadbeef") {
		t.Errorf("head SHA not fetched, log: %s", gitOutput)
	}

	fendixLogBytes, _ := os.ReadFile(fendixLog)
	fendixOutput := string(fendixLogBytes)
	if !strings.Contains(fendixOutput, "scan") {
		t.Errorf("fendix scan not invoked, log: %s", fendixOutput)
	}
	if !strings.Contains(fendixOutput, "report") {
		t.Errorf("fendix report not invoked, log: %s", fendixOutput)
	}
	if !strings.Contains(fendixOutput, "--format json") {
		t.Errorf("fendix scan not in json mode, log: %s", fendixOutput)
	}
	if !strings.Contains(fendixOutput, "--format sarif") {
		t.Errorf("fendix report not in sarif mode, log: %s", fendixOutput)
	}
}

func TestFendixScanner_Run_GitFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX fake bins")
	}
	binDir := t.TempDir()
	gitBin := writeFakeBin(t, binDir, "fakegit",
		`echo "fake git failure" 1>&2; exit 5`)
	fendixBin := writeFakeBin(t, binDir, "fakefendix", `exit 0`)

	s := &FendixScanner{GitBinary: gitBin, FendixBinary: fendixBin, WorkDir: t.TempDir()}
	_, err := s.Run(context.Background(), ScanRequest{
		CloneURL:          "https://github.com/o/r.git",
		HeadSHA:           "deadbeef",
		InstallationToken: "tok",
	})
	if err == nil {
		t.Fatal("expected error from git failure")
	}
	if strings.Contains(err.Error(), "tok") {
		t.Errorf("err should redact token, got: %v", err)
	}
}

func TestFendixScanner_Run_FendixScanFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX fake bins")
	}
	binDir := t.TempDir()
	gitBin := writeFakeBin(t, binDir, "fakegit", `exit 0`)
	fendixBin := writeFakeBin(t, binDir, "fakefendix",
		`echo "scan blew up" 1>&2; exit 2`)

	s := &FendixScanner{GitBinary: gitBin, FendixBinary: fendixBin, WorkDir: t.TempDir()}
	_, err := s.Run(context.Background(), ScanRequest{
		CloneURL:          "https://github.com/o/r.git",
		HeadSHA:           "deadbeef",
		InstallationToken: "tok",
	})
	if err == nil {
		t.Fatal("expected error from fendix scan failure")
	}
	if !strings.Contains(err.Error(), "fendix scan failed") {
		t.Errorf("expected fendix-scan-failed error, got: %v", err)
	}
}

func TestFendixScanner_Run_ValidatesInputs(t *testing.T) {
	s := &FendixScanner{}
	cases := []ScanRequest{
		{CloneURL: "", HeadSHA: "x", InstallationToken: "t"},
		{CloneURL: "https://x", HeadSHA: "", InstallationToken: "t"},
		{CloneURL: "https://x", HeadSHA: "x", InstallationToken: ""},
	}
	for _, c := range cases {
		_, err := s.Run(context.Background(), c)
		if err == nil {
			t.Errorf("expected validation error for %+v", c)
		}
	}
}
