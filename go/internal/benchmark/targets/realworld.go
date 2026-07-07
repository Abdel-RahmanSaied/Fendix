package targets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Abdel-RahmanSaied/Fendix/internal/benchmark"
	"gopkg.in/yaml.v3"
)

// realWorldManifest is a committed corpus entry descriptor. A public entry
// pins a repo URL + SHA; a seed entry sets local:true and resolves its path
// from the git-ignored benchmarks/realworld/local.yaml.
type realWorldManifest struct {
	Name    string `yaml:"name"`
	Repo    string `yaml:"repo,omitempty"`
	SHA     string `yaml:"sha,omitempty"`
	License string `yaml:"license,omitempty"`
	Local   bool   `yaml:"local,omitempty"`
}

// RealWorld is a SAST corpus target: a source tree at a pinned revision plus a
// committed labels.yaml. It reuses the scan-production + scoring split of the
// other targets but scores against labels, not a known-vuln set.
type RealWorld struct {
	root      string // repo root (holds benchmarks/realworld/…); "" = cwd
	entryName string // corpus entry directory name under benchmarks/realworld/
}

// NewRealWorld returns a RealWorld target for one corpus entry.
func NewRealWorld(entryName string) *RealWorld {
	return &RealWorld{entryName: entryName}
}

// Name implements benchmark.BenchmarkTarget: "realworld/<entry>".
func (r *RealWorld) Name() string { return "realworld/" + r.entryName }

func (r *RealWorld) entryDir() string {
	root := r.root
	return filepath.Join(root, "benchmarks", "realworld", r.entryName)
}

func (r *RealWorld) loadManifest() (*realWorldManifest, error) {
	data, err := os.ReadFile(filepath.Join(r.entryDir(), "manifest.yaml"))
	if err != nil {
		return nil, fmt.Errorf("realworld %s: %w", r.entryName, err)
	}
	var m realWorldManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("realworld %s: parse manifest: %w", r.entryName, err)
	}
	return &m, nil
}

// resolveSourcePath returns the local source tree for the entry, or
// ErrTargetSkipped when a local-only entry has no configured path.
func (r *RealWorld) resolveSourcePath(m *realWorldManifest) (string, error) {
	if m.Local {
		p, err := lookupLocalPath(r.root, m.Name)
		if err != nil || p == "" {
			return "", fmt.Errorf("realworld %s: %w — no local path configured (add it to benchmarks/realworld/local.yaml); seed tier is intentionally private", r.entryName, ErrTargetSkipped)
		}
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("realworld %s: %w — configured local path %q does not exist", r.entryName, ErrTargetSkipped, p)
		}
		return p, nil
	}
	return "", fmt.Errorf("realworld %s: public-tier clone not implemented in this task", r.entryName)
}

// lookupLocalPath reads benchmarks/realworld/local.yaml (name → abs path).
func lookupLocalPath(root, name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "benchmarks", "realworld", "local.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var paths map[string]string
	if err := yaml.Unmarshal(data, &paths); err != nil {
		return "", err
	}
	return paths[name], nil
}

// Scan resolves the source tree and runs fendix; loud-SKIPs a local entry with
// no path.
func (r *RealWorld) Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error) {
	m, err := r.loadManifest()
	if err != nil {
		return nil, err
	}
	src, err := r.resolveSourcePath(m)
	if err != nil {
		return nil, err
	}
	findings, dur, err := runFendixScan(ctx, fendixBin, []string{"--code", src, "--python-engine"})
	if err != nil {
		return nil, fmt.Errorf("realworld %s: %w", r.entryName, err)
	}
	return &benchmark.ScanResult{Findings: findings, ScanDuration: dur}, nil
}
