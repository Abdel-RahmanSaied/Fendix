//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicy_FailOnFromConfigFile verifies the .fendix.yaml `fail_on`
// value is honored by `fendix scan` when no --fail-on flag is passed.
// Catches the same class of bug TASK-079 caught for --save-baseline:
// the policy field is declared but not actually read into ScanConfig.
func TestPolicy_FailOnFromConfigFile(t *testing.T) {
	bin := fendixBinary(t)
	tmp := t.TempDir()
	wordlist := tinyWordlist(t)

	// Write a policy file with fail_on: HIGH.
	policy := `version: 1
fail_on: HIGH
`
	policyPath := filepath.Join(tmp, ".fendix.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run a code-only scan against the badcode fixture. The fixture
	// reliably produces HIGH-severity findings, so fail_on: HIGH should
	// trigger exit code 1 — proving the policy file's value reached
	// the orchestrator. Without policy support, exit code would be 0.
	root := repoRoot(t)
	badcode := filepath.Join(root, "..", "fendix-test-fixtures", "badcode")
	if _, err := os.Stat(badcode); os.IsNotExist(err) {
		t.Skip("badcode fixture not present at /tmp/fendix-test/badcode; skipping")
	}

	cmd := exec.Command(bin,
		"scan",
		"--code", badcode,
		"--wordlist", wordlist,
		"--config", policyPath,
		"--format", "json",
		"--output", filepath.Join(tmp, "out.json"),
	)
	cmd.Dir = tmp
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()

	// Any exit-1 is the success signal here — the gate fired because
	// the policy's fail_on resolved into the ScanConfig.
	if err == nil {
		t.Fatalf("expected exit 1 from --fail-on=HIGH gating (via .fendix.yaml), got exit 0\noutput:\n%s", out.String())
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got %d\noutput:\n%s", exitErr.ExitCode(), out.String())
		}
	}

	// Policy summary log line should mention the policy was applied
	// (so users can debug precedence). Exact field count varies as
	// the schema grows — we just assert the line is present.
	if !strings.Contains(out.String(), "policy applied") {
		t.Errorf("expected 'policy applied' log line on stderr, got:\n%s", out.String())
	}
}

// TestPolicy_MissingExplicitConfigFails verifies that pointing
// --config at a nonexistent file is a hard error, not a silent
// fallback to flag-only mode. Silent fallback would mask typos.
func TestPolicy_MissingExplicitConfigFails(t *testing.T) {
	bin := fendixBinary(t)
	tmp := t.TempDir()

	cmd := exec.Command(bin,
		"scan",
		"--url", "http://example.invalid",
		"--config", filepath.Join(tmp, "does-not-exist.yaml"),
	)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error when --config points at nonexistent file, got exit 0\n%s", out)
	}
	if !bytes.Contains(out, []byte("policy file not found")) {
		t.Errorf("expected 'policy file not found' in error, got:\n%s", out)
	}
}

// TestPolicy_UnknownFieldRejected verifies KnownFields(true) on the
// YAML decoder catches typos in policy keys (the most common
// "I set this but it didn't take" failure mode).
func TestPolicy_UnknownFieldRejected(t *testing.T) {
	bin := fendixBinary(t)
	tmp := t.TempDir()

	policy := `version: 1
fial_on: HIGH
`
	policyPath := filepath.Join(tmp, ".fendix.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin,
		"scan",
		"--url", "http://example.invalid",
		"--config", policyPath,
	)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error on unknown policy field, got exit 0\n%s", out)
	}
	got := string(out)
	if !strings.Contains(got, "fial_on") && !strings.Contains(got, "field") {
		t.Errorf("expected unknown-field error mentioning the typo, got:\n%s", got)
	}
}
