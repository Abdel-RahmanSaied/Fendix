// Package plugin discovers and runs out-of-tree Fendix plugins.
//
// A plugin is a directory containing a plugin.yaml manifest and an
// executable entrypoint. The engine invokes the entrypoint with a
// JSON ScanRequest on stdin; the entrypoint emits zero or more
// newline-delimited Finding JSON objects on stdout, terminated by
// {"done": true, "total": N}. This is the same NDJSON contract the
// embedded Python engine speaks (ADR-002), so plugin authors writing
// a Python plugin can share most of the engine.py scaffolding.
//
// Discovery walks two roots in order:
//
//  1. <repo>/.fendix/plugins/    (repo-local; takes precedence)
//  2. ~/.fendix/plugins/         (user-global)
//
// On collision (same plugin name in both roots) the repo-local
// version wins, so a project can pin a specific plugin version
// without affecting the developer's other repos.
package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// DefaultTimeout caps a single plugin invocation when the manifest
// does not specify a Timeout.
const DefaultTimeout = 30 * time.Second

// MaxTimeout is the upper bound on plugin runtime regardless of what
// the manifest claims. A plugin that wants longer scans should run
// async and emit findings incrementally; the engine cannot wait
// forever on a single subprocess.
const MaxTimeout = 5 * time.Minute

// Mode declares whether a plugin sees blackbox (URL/spec/auth) or
// whitebox (code path) inputs. Plugins that need both can declare
// Mode="hybrid"; the orchestrator will run them once with all fields
// populated.
type Mode string

const (
	ModeBlackbox Mode = "blackbox"
	ModeWhitebox Mode = "whitebox"
	ModeHybrid   Mode = "hybrid"
)

// Spec is the on-disk plugin.yaml schema. Unknown fields are
// rejected (yaml.Decoder.KnownFields(true)) so typos surface as
// errors rather than silently-ignored config — same posture as
// .fendix.yaml in policy.Load.
type Spec struct {
	Name        string        `yaml:"name"`
	Version     string        `yaml:"version,omitempty"`
	Description string        `yaml:"description,omitempty"`
	Entrypoint  string        `yaml:"entrypoint"`
	Mode        Mode          `yaml:"mode"`
	Categories  []string      `yaml:"categories,omitempty"`
	Timeout     time.Duration `yaml:"timeout,omitempty"`
}

// Plugin is a discovered, validated plugin ready to run.
type Plugin struct {
	Spec
	// Dir is the absolute path to the plugin directory. Entrypoint
	// is resolved relative to Dir.
	Dir string
}

// ScanRequest is the JSON payload the engine sends to a plugin's
// stdin. It mirrors the embedded engine's ScanRequest plus a
// Categories field so plugins can filter to relevant work without
// re-walking the source tree. Field names are stable — adding new
// fields is fine, removing or renaming them is a breaking change.
type ScanRequest struct {
	Mode       Mode     `json:"mode"`
	URL        string   `json:"url,omitempty"`
	Spec       string   `json:"spec,omitempty"`
	CodePath   string   `json:"code_path,omitempty"`
	Auth       string   `json:"auth,omitempty"`
	AuthType   string   `json:"auth_type,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Verbose    bool     `json:"verbose"`
}

// doneMessage matches the engine's terminator format so plugin
// authors with an existing engine.py-shaped plugin work unchanged.
type doneMessage struct {
	Done  bool   `json:"done"`
	Total int    `json:"total"`
	Error string `json:"error,omitempty"`
}

// Discover walks the given roots in order, parses every plugin.yaml
// it finds, and returns the resulting Plugin list deduplicated by
// Name (earlier roots win — pass repo-local first, user-global
// second). A malformed plugin.yaml in one directory does not stop
// discovery in others; the error for that directory is logged at
// WARN level and the plugin is skipped.
//
// Discover is intentionally tolerant of missing roots: a fresh
// install with no plugin directories returns ([], nil), not an error.
func Discover(roots []string) ([]Plugin, error) {
	seen := make(map[string]struct{})
	var out []Plugin
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			slog.Warn("plugin discovery: cannot read root", "root", root, "err", err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, e.Name())
			p, err := loadPlugin(dir)
			if err != nil {
				slog.Warn("plugin skipped", "dir", dir, "err", err)
				continue
			}
			if _, dup := seen[p.Name]; dup {
				slog.Debug("plugin shadowed by earlier root", "name", p.Name, "dir", dir)
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

// loadPlugin parses plugin.yaml under dir and validates the result.
func loadPlugin(dir string) (Plugin, error) {
	manifest := filepath.Join(dir, "plugin.yaml")
	f, err := os.Open(manifest)
	if err != nil {
		return Plugin{}, fmt.Errorf("open plugin.yaml: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return Plugin{}, fmt.Errorf("parse plugin.yaml: %w", err)
	}

	if err := validate(&s); err != nil {
		return Plugin{}, err
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return Plugin{}, fmt.Errorf("absolute path: %w", err)
	}
	return Plugin{Spec: s, Dir: abs}, nil
}

func validate(s *Spec) error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("plugin.yaml: name is required")
	}
	if strings.ContainsAny(s.Name, "/\\") {
		return fmt.Errorf("plugin.yaml: name %q must not contain path separators", s.Name)
	}
	if strings.TrimSpace(s.Entrypoint) == "" {
		return errors.New("plugin.yaml: entrypoint is required")
	}
	if filepath.IsAbs(s.Entrypoint) {
		return fmt.Errorf("plugin.yaml: entrypoint %q must be relative to the plugin directory", s.Entrypoint)
	}
	if strings.Contains(s.Entrypoint, "..") {
		return fmt.Errorf("plugin.yaml: entrypoint %q must not traverse with '..'", s.Entrypoint)
	}
	switch s.Mode {
	case ModeBlackbox, ModeWhitebox, ModeHybrid:
	case "":
		return errors.New("plugin.yaml: mode is required (blackbox, whitebox, or hybrid)")
	default:
		return fmt.Errorf("plugin.yaml: mode %q is not one of blackbox, whitebox, hybrid", s.Mode)
	}
	if s.Timeout < 0 {
		return fmt.Errorf("plugin.yaml: timeout %s must not be negative", s.Timeout)
	}
	if s.Timeout > MaxTimeout {
		return fmt.Errorf("plugin.yaml: timeout %s exceeds engine cap of %s", s.Timeout, MaxTimeout)
	}
	return nil
}

// Run invokes the plugin entrypoint and returns the findings it
// emitted. A plugin that exits with non-zero status, takes longer
// than its timeout, or emits a {"error": ...} terminator returns
// an error; partial findings collected before the failure are
// preserved in the slice.
//
// Findings emitted without a Source field are tagged with the
// plugin's Mode so downstream correlation/dedup treats them
// consistently with the embedded engines.
func (p Plugin) Run(ctx context.Context, req ScanRequest) ([]models.Finding, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, filepath.Join(p.Dir, p.Entrypoint))
	cmd.Dir = p.Dir
	cmd.Env = append(os.Environ(),
		"FENDIX_PLUGIN_NAME="+p.Name,
		"FENDIX_PLUGIN_DIR="+p.Dir,
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %s: stdin pipe: %w", p.Name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("plugin %s: stdout pipe: %w", p.Name, err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("plugin %s: start: %w", p.Name, err)
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("plugin %s: marshal request: %w", p.Name, err)
	}
	if _, err := stdin.Write(append(reqJSON, '\n')); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("plugin %s: write request: %w", p.Name, err)
	}
	_ = stdin.Close()

	findings, readErr := readPluginFindings(stdout, p)
	waitErr := cmd.Wait()

	if stderrBuf.Len() > 0 {
		slog.Debug("plugin stderr", "plugin", p.Name, "stderr", strings.TrimSpace(stderrBuf.String()))
	}

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return findings, fmt.Errorf("plugin %s: timeout after %s", p.Name, timeout)
	}
	if readErr != nil {
		return findings, fmt.Errorf("plugin %s: %w", p.Name, readErr)
	}
	if waitErr != nil {
		return findings, fmt.Errorf("plugin %s: exit: %w", p.Name, waitErr)
	}
	return findings, nil
}

// readPluginFindings drains the plugin's stdout, returning the
// findings array and any terminator error (e.g. plugin emitted
// {"error": "..."}). Malformed lines are skipped at DEBUG level
// rather than raising — a single junk line on stdout shouldn't
// fail the whole scan.
func readPluginFindings(r io.Reader, p Plugin) ([]models.Finding, error) {
	var out []models.Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var done doneMessage
		if err := json.Unmarshal([]byte(line), &done); err == nil && done.Done {
			if done.Error != "" {
				return out, fmt.Errorf("plugin reported error: %s", done.Error)
			}
			return out, nil
		}

		var f models.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			slog.Debug("plugin emitted malformed JSON", "plugin", p.Name, "line", line, "err", err)
			continue
		}
		if f.Title == "" || f.Severity == "" {
			slog.Debug("plugin finding missing required fields", "plugin", p.Name, "line", line)
			continue
		}
		if f.Source == "" {
			f.Source = sourceForMode(p.Mode)
		}
		// Tag the finding with the plugin name so reports/dedup can
		// trace provenance. We piggy-back on References because
		// adding a new top-level field would break the IPC contract.
		f.References = append(f.References, "fendix-plugin:"+p.Name)
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scan plugin stdout: %w", err)
	}
	return out, nil
}

func sourceForMode(m Mode) models.Source {
	switch m {
	case ModeBlackbox:
		return models.SourceBlackbox
	case ModeWhitebox, ModeHybrid:
		return models.SourceWhitebox
	default:
		return models.SourceWhitebox
	}
}

// DefaultRoots returns the canonical plugin search path: repo-local
// first, then user-global. cwd is the working directory whose
// .fendix/plugins should be searched (typically the scan root). If
// cwd is empty, only the user-global root is returned.
//
// On systems where os.UserHomeDir fails (very rare) the user-global
// root is silently omitted.
func DefaultRoots(cwd string) []string {
	var roots []string
	if cwd != "" {
		roots = append(roots, filepath.Join(cwd, ".fendix", "plugins"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".fendix", "plugins"))
	}
	return roots
}
