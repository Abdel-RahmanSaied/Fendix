package targets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/benchmark"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestRealWorldLoudSkipWhenLocalPathAbsent(t *testing.T) {
	dir := t.TempDir()
	// A committed manifest that is local-only, with no local.yaml → SKIP.
	entry := filepath.Join(dir, "benchmarks", "realworld", "seed")
	os.MkdirAll(entry, 0o755)
	os.WriteFile(filepath.Join(entry, "manifest.yaml"),
		[]byte("name: seed\nlocal: true\n"), 0o644)
	os.WriteFile(filepath.Join(entry, "labels.yaml"), []byte("[]\n"), 0o644)

	rw := &RealWorld{root: dir, entryName: "seed"}
	_, err := rw.Scan(context.Background(), "fendix")
	if !errors.Is(err, ErrTargetSkipped) {
		t.Fatalf("Scan() should loud-SKIP when local path absent, got %v", err)
	}
}

func TestRealWorldRunScoresAndCountsLOC(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "benchmarks", "realworld", "mini")
	os.MkdirAll(entry, 0o755)
	os.WriteFile(filepath.Join(entry, "manifest.yaml"), []byte("name: mini\nlocal: true\n"), 0o644)
	os.WriteFile(filepath.Join(entry, "labels.yaml"),
		[]byte("- rule: PY_SSRF\n  file: app.py\n  line: 5\n  verdict: tp\n"), 0o644)
	// A source tree so LOC>0.
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "app.py"), []byte("import requests\nx=1\ny=2\nz=3\nrequests.get(u)\n"), 0o644)

	rw := &RealWorld{root: dir, entryName: "mini"}
	sr := &benchmark.ScanResult{Findings: []models.Finding{
		{ID: "SEC-PY_SSRF", Endpoint: "app.py:5"},
	}}
	rw.src = src // scored LOC comes from the resolved src
	res, err := rw.Run(context.Background(), sr)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TruePos != 1 || res.FalsePos != 0 {
		t.Errorf("BenchmarkResult tp/fp = %d/%d, want 1/0", res.TruePos, res.FalsePos)
	}
	if rw.Result == nil || rw.Result.LOC == 0 {
		t.Fatalf("RealWorldResult not attached or LOC=0: %+v", rw.Result)
	}
}
