package engine

import (
	"strings"
	"testing"
)

func TestCheckPython_DefaultBinary(t *testing.T) {
	status := CheckPython("")
	// On most dev machines, python3 is available.
	// This test verifies the function runs without panic.
	if status.Available {
		if status.Binary == "" {
			t.Error("Available=true but Binary is empty")
		}
		if status.Version == "" {
			t.Error("Available=true but Version is empty")
		}
		if !strings.HasPrefix(status.Version, "3.") {
			t.Errorf("expected version starting with 3., got %s", status.Version)
		}
	}
}

func TestCheckPython_NonexistentBinary(t *testing.T) {
	status := CheckPython("python-nonexistent-binary-xyz")
	if status.Available {
		t.Fatal("expected Available=false for nonexistent binary")
	}
}

func TestCheckPython_ExplicitBinary(t *testing.T) {
	// Test with an explicit path — use the system python3 if available
	status := CheckPython("python3")
	if status.Available {
		if status.Version == "" {
			t.Error("expected version string when python3 is available")
		}
	}
}

func TestPythonRequiredMessage(t *testing.T) {
	msg := PythonRequiredMessage()
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	if !strings.Contains(msg, "Python 3") {
		t.Error("message should mention Python 3")
	}
	if !strings.Contains(msg, "blackbox") {
		t.Error("message should mention blackbox fallback")
	}
}
