//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDebugBundle_WrittenAndRedacted is the regression test for TASK-102.
// Runs a real fendix scan with --debug-bundle and an --auth value, and
// asserts that (a) the tarball file is produced, (b) it contains the
// expected entries, (c) the auth credential never appears in cleartext
// anywhere inside the archive — including the buffered slog stream.
func TestDebugBundle_WrittenAndRedacted(t *testing.T) {
	bin := fendixBinary(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	reportPath := filepath.Join(dir, "report.json")

	const secret = "Bearer e2e-debug-bundle-token-12345"

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--auth", secret,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--debug-bundle", bundlePath,
		"--output", reportPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 1 is allowed: --fail-on may emit, but the bundle
		// should still be written. Exit code >=2 is a real failure.
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("debug bundle not produced at %s: %v\noutput:\n%s", bundlePath, err, out)
	}

	entries := readBundleEntries(t, bundlePath)

	requiredNames := []string{"README.md", "config.json", "environment.json", "metadata.json", "findings.json", "debug.log"}
	for _, name := range requiredNames {
		body, ok := entries[name]
		if !ok {
			t.Errorf("bundle missing entry %q; got %v", name, bundleKeys(entries))
			continue
		}
		if len(body) == 0 && name != "debug.log" {
			t.Errorf("bundle entry %q is empty", name)
		}
	}

	// No entry should contain the auth value or its bare-token form.
	const bare = "e2e-debug-bundle-token-12345"
	for name, body := range entries {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("bundle entry %q leaked the full Bearer token", name)
		}
		if bytes.Contains(body, []byte(bare)) {
			t.Errorf("bundle entry %q leaked the bare token", name)
		}
	}

	// config.json must explicitly mark auth.value as [REDACTED].
	var cfg map[string]any
	if err := json.Unmarshal(entries["config.json"], &cfg); err != nil {
		t.Fatalf("config.json invalid: %v\nbody:\n%s", err, entries["config.json"])
	}
	auth, ok := cfg["auth"].(map[string]any)
	if !ok {
		t.Fatalf("config.json missing auth object: %v", cfg)
	}
	if got, _ := auth["value"].(string); got != "[REDACTED]" {
		t.Errorf("config.json auth.value not redacted; got %q", got)
	}

	// environment.json should record runtime versions.
	var env map[string]string
	if err := json.Unmarshal(entries["environment.json"], &env); err != nil {
		t.Fatalf("environment.json invalid: %v", err)
	}
	for _, key := range []string{"go_version", "goos", "goarch"} {
		if env[key] == "" {
			t.Errorf("environment.json missing %q", key)
		}
	}

	// probes.jsonl should NOT exist when --enable-active was off.
	if _, ok := entries["probes.jsonl"]; ok {
		t.Error("probes.jsonl present despite --enable-active not being set")
	}

	// debug.log should be non-trivial (the scan emits at least info-level
	// records). If empty, the slog tee never fired.
	if !strings.Contains(string(entries["debug.log"]), "level=") {
		t.Errorf("debug.log missing slog text-format records; got first 200 bytes:\n%.200s", entries["debug.log"])
	}
}

func readBundleEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			t.Fatalf("tar body for %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = buf.Bytes()
	}
	return out
}

func bundleKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
