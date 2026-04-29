package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ScanRequest is the JSON payload sent to the Python engine via stdin.
type ScanRequest struct {
	Mode     string   `json:"mode"`
	Spec     string   `json:"spec,omitempty"`
	CodePath string   `json:"code_path,omitempty"`
	Language string   `json:"language,omitempty"`
	Checks   []string `json:"checks"`
	Verbose  bool     `json:"verbose"`
}

// DoneMessage is the terminal JSON line from the Python engine.
type DoneMessage struct {
	Done  bool   `json:"done"`
	Total int    `json:"total"`
	Error string `json:"error,omitempty"`
}

// PythonSpawner manages the lifecycle of the Python engine subprocess.
type PythonSpawner struct {
	pythonBin string // path to python3 binary
	engineDir string // directory containing engine.py
}

// NewPythonSpawner creates a spawner that will invoke the Python engine.
// pythonBin defaults to "python3" if empty.
// engineDir defaults to "python" relative to CWD if empty.
func NewPythonSpawner(pythonBin, engineDir string) *PythonSpawner {
	if pythonBin == "" {
		pythonBin = "python3"
	}
	if engineDir == "" {
		engineDir = "python"
	}
	return &PythonSpawner{
		pythonBin: pythonBin,
		engineDir: engineDir,
	}
}

// SpawnResult holds the findings and any error from the Python engine.
type SpawnResult struct {
	Findings []models.Finding
	Total    int
	Err      error
}

// Run spawns the Python engine, sends the ScanRequest, and collects findings.
// It respects context cancellation and kills the subprocess if cancelled.
func (ps *PythonSpawner) Run(ctx context.Context, req ScanRequest) SpawnResult {
	enginePath := filepath.Join(ps.engineDir, "engine.py")

	cmd := exec.CommandContext(ctx, ps.pythonBin, enginePath)
	cmd.Dir = ps.engineDir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return SpawnResult{Err: fmt.Errorf("creating stdin pipe: %w", err)}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SpawnResult{Err: fmt.Errorf("creating stdout pipe: %w", err)}
	}

	// Capture stderr for diagnostics
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	slog.Info("spawning python engine", "bin", ps.pythonBin, "engine", enginePath)
	startTime := time.Now()

	if err := cmd.Start(); err != nil {
		return SpawnResult{Err: fmt.Errorf("starting python engine: %w", err)}
	}

	// Send ScanRequest and close stdin
	reqJSON, err := json.Marshal(req)
	if err != nil {
		cmd.Process.Kill()
		return SpawnResult{Err: fmt.Errorf("marshaling scan request: %w", err)}
	}

	if _, err := stdin.Write(reqJSON); err != nil {
		cmd.Process.Kill()
		return SpawnResult{Err: fmt.Errorf("writing scan request to stdin: %w", err)}
	}
	stdin.Close()

	// Read streaming findings from stdout
	findings, total, readErr := readFindings(stdout)

	// Wait for process to exit
	waitErr := cmd.Wait()

	duration := time.Since(startTime)
	slog.Info("python engine finished",
		"duration", duration.Round(time.Millisecond),
		"findings", len(findings),
		"exit_code", cmd.ProcessState.ExitCode(),
	)

	// Log stderr if non-empty
	if stderrStr := stderrBuf.String(); stderrStr != "" {
		for _, line := range strings.Split(strings.TrimSpace(stderrStr), "\n") {
			slog.Debug("python engine stderr", "line", line)
		}
	}

	if readErr != nil {
		return SpawnResult{Findings: findings, Total: total, Err: fmt.Errorf("reading python output: %w", readErr)}
	}

	if waitErr != nil {
		// Context cancellation is not an error — it means the user cancelled
		if ctx.Err() != nil {
			return SpawnResult{Findings: findings, Total: total, Err: ctx.Err()}
		}
		return SpawnResult{Findings: findings, Total: total, Err: fmt.Errorf("python engine exited with error: %w", waitErr)}
	}

	return SpawnResult{Findings: findings, Total: total}
}

// readFindings reads newline-delimited JSON from the Python engine stdout.
// It returns collected findings and the total from the done message.
func readFindings(r io.Reader) ([]models.Finding, int, error) {
	var findings []models.Finding
	scanner := bufio.NewScanner(r)

	// Increase buffer size for potentially large finding JSON
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if this is the done message
		var done DoneMessage
		if err := json.Unmarshal([]byte(line), &done); err == nil && done.Done {
			if done.Error != "" {
				return findings, done.Total, fmt.Errorf("python engine error: %s", done.Error)
			}
			return findings, done.Total, nil
		}

		// Parse as a Finding
		var finding models.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			logagg.Warn("python_engine", "skipping malformed finding JSON from python", "error", err, "line", line)
			continue
		}

		// Only accept findings with required fields
		if finding.Title == "" || finding.Severity == "" {
			logagg.Warn("python_engine", "skipping finding with missing required fields", "line", line)
			continue
		}

		// Mark source as whitebox
		if finding.Source == "" {
			finding.Source = models.SourceWhitebox
		}

		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return findings, 0, fmt.Errorf("scanning stdout: %w", err)
	}

	// If we got here without a done message, it means the stream ended unexpectedly
	if len(findings) > 0 {
		slog.Warn("python engine stream ended without done message", "findings_collected", len(findings))
	}

	return findings, len(findings), nil
}
