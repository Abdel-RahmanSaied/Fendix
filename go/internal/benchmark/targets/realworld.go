package targets

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	src       string // resolved source tree (set by Scan); the KLOC denominator
	cacheRoot string // public-tier clone cache; "" = ~/.fendix/cache/bench-realworld
	// Result is the rich scored outcome attached by Run for the CLI's
	// per-class + triage output. BenchmarkResult (Run's return) is the
	// compact shape the baseline stores.
	Result *benchmark.RealWorldResult
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
// ErrTargetSkipped when a local-only entry has no configured path. Public
// entries clone the pinned repo@sha into the bench cache (reused if present).
func (r *RealWorld) resolveSourcePath(ctx context.Context, m *realWorldManifest) (string, error) {
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
	// Public tier: clone at pinned SHA into the bench cache (reuse if present).
	if m.Repo == "" || m.SHA == "" {
		return "", fmt.Errorf("realworld %s: public entry needs repo+sha in manifest.yaml", r.entryName)
	}
	cacheRoot := r.cacheRoot
	if cacheRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cacheRoot = filepath.Join(home, ".fendix", "cache", "bench-realworld")
	}
	dest := filepath.Join(cacheRoot, m.Name+"@"+m.SHA)
	if _, err := os.Stat(dest); err == nil {
		return dest, nil // cache hit — pinned SHA is immutable
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	// Shallow init + fetch the exact SHA (depth 1) for reproducibility.
	steps := [][]string{
		{"-C", dest, "init", "-q"},
		{"-C", dest, "remote", "add", "origin", m.Repo},
		{"-C", dest, "fetch", "-q", "--depth", "1", "origin", m.SHA},
		{"-C", dest, "checkout", "-q", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if err := runProcess(ctx, "git", args...); err != nil {
			os.RemoveAll(dest)
			return "", fmt.Errorf("realworld %s: git %v: %w", r.entryName, args, err)
		}
	}
	return dest, nil
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
	src, err := r.resolveSourcePath(ctx, m)
	if err != nil {
		return nil, err
	}
	r.src = src // scored LOC comes from the resolved source tree
	findings, dur, err := runFendixScan(ctx, fendixBin, []string{"--code", src, "--python-engine"})
	if err != nil {
		return nil, fmt.Errorf("realworld %s: %w", r.entryName, err)
	}
	return &benchmark.ScanResult{Findings: findings, ScanDuration: dur}, nil
}

// countLOC counts non-blank lines across .py/.go files under root — a coarse
// but deterministic KLOC denominator for noise density.
func countLOC(root string) int {
	total := 0
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".py") && !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 1024*1024), 1024*1024)
		for s.Scan() {
			if strings.TrimSpace(s.Text()) != "" {
				total++
			}
		}
		return nil
	})
	return total
}

// Run scores result against the entry's labels. It attaches the rich
// RealWorldResult to the target (for the CLI's per-class + triage output) and
// returns the compact BenchmarkResult the baseline stores.
func (r *RealWorld) Run(ctx context.Context, result *benchmark.ScanResult) (*benchmark.BenchmarkResult, error) {
	ls, err := benchmark.LoadLabelSet(filepath.Join(r.entryDir(), "labels.yaml"))
	if err != nil {
		return nil, fmt.Errorf("realworld %s: %w", r.entryName, err)
	}
	loc := 0
	if r.src != "" {
		loc = countLOC(r.src)
	}
	rw := benchmark.ScoreRealWorld(r.Name(), ls, result.Findings, loc)
	r.Result = rw
	return &benchmark.BenchmarkResult{
		Target:       r.Name(),
		TruePos:      rw.TruePos,
		FalsePos:     rw.FalsePos,
		TrueNeg:      0,
		FalseNeg:     rw.FalseNeg,
		ScanDuration: result.ScanDuration,
		Timestamp:    time.Now(),
	}, nil
}

// TriageReport renders the unknown findings + per-class FP breakdown for one
// entry, so labeling is incremental and the number stays defensible.
func (r *RealWorld) TriageReport() string {
	if r.Result == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "realworld/%s: precision %.1f%% over %d labeled (%d tp, %d fp), %d unknown, %.2f findings/KLOC\n",
		r.entryName, r.Result.Precision()*100, r.Result.TruePos+r.Result.FalsePos,
		r.Result.TruePos, r.Result.FalsePos, r.Result.Unknown, r.Result.FindingsPerKLOC())
	if len(r.Result.PerClass) > 0 {
		b.WriteString("  FP classes: ")
		classes := make([]benchmark.FPClass, 0, len(r.Result.PerClass))
		for c := range r.Result.PerClass {
			classes = append(classes, c)
		}
		sort.Slice(classes, func(i, j int) bool { return string(classes[i]) < string(classes[j]) })
		for _, c := range classes {
			fmt.Fprintf(&b, "%s=%d ", c, r.Result.PerClass[c])
		}
		b.WriteString("\n")
	}
	for _, f := range r.Result.Unknowns {
		fmt.Fprintf(&b, "  UNKNOWN  %s  %s\n", f.ID, f.Endpoint)
	}
	return b.String()
}
