package engine

import (
	"fmt"
	"os/exec"
	"strings"
)

// PythonStatus describes the availability and version of the Python runtime.
type PythonStatus struct {
	Available bool
	Binary    string // resolved path to python3
	Version   string // e.g. "3.11.5"
}

// CheckPython verifies that a Python 3 interpreter is available on the system.
// It tries the given binary name (default "python3"), checks it runs, and
// captures the version string.
func CheckPython(pythonBin string) PythonStatus {
	if pythonBin == "" {
		pythonBin = "python3"
	}

	// Resolve the full path
	resolved, err := exec.LookPath(pythonBin)
	if err != nil {
		return PythonStatus{Available: false, Binary: pythonBin}
	}

	// Run python3 --version to verify it actually works
	cmd := exec.Command(resolved, "--version")
	output, err := cmd.Output()
	if err != nil {
		return PythonStatus{Available: false, Binary: resolved}
	}

	version := strings.TrimSpace(string(output))
	// "Python 3.11.5" → "3.11.5"
	version = strings.TrimPrefix(version, "Python ")

	return PythonStatus{
		Available: true,
		Binary:    resolved,
		Version:   version,
	}
}

// PythonRequiredMessage returns a user-friendly message explaining that
// Python is needed for whitebox scanning.
func PythonRequiredMessage() string {
	return fmt.Sprintf(
		"Python 3 is required for whitebox analysis (secrets, semgrep, AST checks).\n"+
			"Install Python 3: https://www.python.org/downloads/\n"+
			"The scan will continue with blackbox checks only.",
	)
}
