package targets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
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
