//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDemo_HelpListsFlags is a smoke test for the `fendix demo` cobra
// wiring. It deliberately does NOT spin up Docker — that would make
// the e2e suite require Docker on every CI runner, which the rest of
// the suite doesn't. Instead, it asserts:
//
//   - `fendix demo` appears in `fendix --help` output.
//   - `fendix demo --help` shows the four flags we declared (--open,
//     --port, --output, --image).
//
// Catches cobra-wiring regressions (the flag declared but not bound,
// or the subcommand declared but not registered with root) — the same
// class of bug TASK-079 caught for --save-baseline.
func TestDemo_HelpListsFlags(t *testing.T) {
	bin := fendixBinary(t)

	rootHelp, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("fendix --help failed: %v\n%s", err, rootHelp)
	}
	if !strings.Contains(string(rootHelp), "demo") {
		t.Errorf("`demo` should appear in `fendix --help`, got:\n%s", rootHelp)
	}

	demoHelp, err := exec.Command(bin, "demo", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("fendix demo --help failed: %v\n%s", err, demoHelp)
	}
	got := string(demoHelp)
	for _, want := range []string{
		"--open",
		"--port",
		"--output",
		"--image",
		"juice-shop", // referenced in long-help description
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in demo --help output, got:\n%s", want, got)
		}
	}
}
