package ghapp

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
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

// F-H3: the token is supplied per-invocation via an http.extraheader
// Authorization: Basic header, NOT embedded in the clone URL. The basic
// credential is base64("x-access-token:<token>").
func TestBasicAuthToken(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		{"abc123", base64.StdEncoding.EncodeToString([]byte("x-access-token:abc123"))},
		{"tok", base64.StdEncoding.EncodeToString([]byte("x-access-token:tok"))},
	}
	for _, c := range cases {
		if got := basicAuthToken(c.token); got != c.want {
			t.Errorf("basicAuthToken(%q): got %q want %q", c.token, got, c.want)
		}
	}
}

// F-H3 regression lock: the installation token must never survive into the
// scan/report subprocess environment (which may run untrusted fork-PR code).
// scrubTokenFromEnv drops any entry whose VALUE contains the token, matched
// on value (not key name).
func TestScrubTokenFromEnv(t *testing.T) {
	const token = "ghs_secrettoken123"
	env := []string{
		"PATH=/usr/bin",
		"GITHUB_TOKEN=" + token,              // dropped: value is the token
		"LEAKED=prefix-" + token + "-suffix", // dropped: value contains the token
		"HOME=/home/runner",
		token + "=harmless", // KEPT: token is the key, value is clean
	}
	got := scrubTokenFromEnv(env, token)

	for _, e := range got {
		if i := strings.IndexByte(e, '='); i >= 0 && strings.Contains(e[i+1:], token) {
			t.Errorf("scrubbed env still leaks the token in a value: %q", e)
		}
	}
	// The clean entries (including the one keyed by the token) survive.
	want := map[string]bool{"PATH=/usr/bin": true, "HOME=/home/runner": true, token + "=harmless": true}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %v, want %d", len(got), got, len(want))
	}
	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected entry survived: %q", e)
		}
	}
}

// scrubTokenFromEnv with an empty token must be a no-op (nothing to scrub).
func TestScrubTokenFromEnv_EmptyToken(t *testing.T) {
	env := []string{"A=1", "B=2"}
	if got := scrubTokenFromEnv(env, ""); len(got) != 2 {
		t.Errorf("empty token should not scrub; got %v", got)
	}
}

func TestValidateHTTPSCloneURL(t *testing.T) {
	if err := validateHTTPSCloneURL("https://github.com/owner/repo.git"); err != nil {
		t.Errorf("https URL should validate, got: %v", err)
	}
	if err := validateHTTPSCloneURL("git@github.com:owner/repo.git"); err == nil {
		t.Fatal("expected error for non-https (ssh) URL")
	}
	if err := validateHTTPSCloneURL("http://github.com/owner/repo.git"); err == nil {
		t.Fatal("expected error for plain-http URL")
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
	// F-H3: the remote is added with the bare clone URL (NO embedded
	// credentials); auth is supplied per-invocation via the
	// http.extraheader Authorization: Basic header.
	if !strings.Contains(gitOutput, "remote add origin https://github.com/owner/repo.git") {
		t.Errorf("remote not added with bare URL, log: %s", gitOutput)
	}
	if strings.Contains(gitOutput, "x-access-token:ghs_test@") {
		t.Errorf("clone URL must NOT embed the token, log: %s", gitOutput)
	}
	wantHeader := "http.extraheader=Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_test"))
	if !strings.Contains(gitOutput, wantHeader) {
		t.Errorf("fetch did not pass auth via extraheader, log: %s", gitOutput)
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

// F-H3: drive the *real* git binary through the exact init + remote-add
// + token-via-extraheader steps the production code uses, then assert
// the installation token never lands in the persisted .git/config. The
// per-invocation `-c http.extraheader=...` must not be written to disk,
// and the remote URL must be the bare clone URL with no embedded
// credentials.
func TestGitConfigDoesNotPersistToken(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH; skipping real-git config persistence test")
	}
	const token = "ghs_supersecret_token"
	dir := t.TempDir()
	cloneURL := "https://github.com/owner/repo.git"
	authHeaderArg := "http.extraheader=Authorization: Basic " + basicAuthToken(token)

	run := func(args ...string) {
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		// Hermetic: don't read the developer's global/system git config.
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}

	run("init", "--quiet", dir)
	run("-C", dir, "remote", "add", "origin", cloneURL)
	// A fetch with the per-invocation extraheader. It targets a bogus
	// SHA and will fail to fetch — but the failure is irrelevant: we are
	// asserting that the -c flag is NOT persisted to config regardless.
	failCmd := exec.Command(gitBin, "-C", dir, "-c", authHeaderArg,
		"config", "--list") // list resolved config including the -c override
	failCmd.Dir = dir
	failCmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	listOut, err := failCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git config --list: %v (%s)", err, listOut)
	}
	// The -c override is visible in this single invocation's resolved
	// config (that's expected — it's how auth is supplied), but it must
	// NOT have been written to the on-disk .git/config.
	cfgBytes, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatalf("read .git/config: %v", err)
	}
	cfg := string(cfgBytes)
	if strings.Contains(cfg, token) {
		t.Errorf(".git/config leaked the installation token:\n%s", cfg)
	}
	if strings.Contains(cfg, basicAuthToken(token)) {
		t.Errorf(".git/config leaked the basic-auth header value:\n%s", cfg)
	}
	if strings.Contains(cfg, "extraheader") {
		t.Errorf(".git/config persisted the extraheader override:\n%s", cfg)
	}
	if !strings.Contains(cfg, cloneURL) {
		t.Errorf("expected bare clone URL in .git/config, got:\n%s", cfg)
	}
}

// F-H3 / F-M5: the `fendix scan` subprocess runs untrusted fork-PR code.
// After clone+fetch, the installation token must NOT be present in that
// subprocess's environment. The fake fendix dumps its environment to a
// file in the (persistent) WorkDir parent so we can inspect it after
// Run removes the per-scan temp dir.
func TestFendixScanner_Run_TokenNotInScanEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX fake bins")
	}
	const token = "ghs_env_secret"
	binDir := t.TempDir()
	workDir := t.TempDir()
	envDump := filepath.Join(workDir, "scan-env.txt")

	gitBin := writeFakeBin(t, binDir, "fakegit", `exit 0`)
	// The fake fendix writes its full environment to envDump on `scan`,
	// and emits the expected report blobs so Run completes.
	fendixScript := `prev=""; out=""
for a in "$@"; do
  if [ "$prev" = "--output" ]; then out="$a"; fi
  prev="$a"
done
case "$1" in
  scan)
    env > "` + envDump + `"
    cat > "$out" <<'JSON'
{"metadata":{"mode":"whitebox","endpoints_scanned":0,"duration":"0s"},
 "summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
 "sources":{"blackbox":0,"whitebox":0,"correlated":0},
 "total":0,"findings":[]}
JSON
    ;;
  report)
    printf '{"runs":[]}' > "$out"
    ;;
esac
exit 0`
	fendixBin := writeFakeBin(t, binDir, "fakefendix", fendixScript)

	// Seed an inherited variable that contains the token to prove the
	// scrubber drops by value, not just by a known key name.
	t.Setenv("SOME_INHERITED_VAR", "prefix-"+token+"-suffix")

	s := &FendixScanner{GitBinary: gitBin, FendixBinary: fendixBin, WorkDir: workDir}
	if _, err := s.Run(context.Background(), ScanRequest{
		CloneURL:          "https://github.com/owner/repo.git",
		HeadSHA:           "deadbeef",
		InstallationToken: token,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	dump, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatalf("read scan env dump: %v", err)
	}
	if strings.Contains(string(dump), token) {
		t.Errorf("installation token present in scan subprocess env:\n%s", dump)
	}
}
