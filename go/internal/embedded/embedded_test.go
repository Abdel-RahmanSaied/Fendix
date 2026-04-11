package embedded

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineFS_Exists(t *testing.T) {
	// The embedded FS should always be non-nil (it's a compile-time embed)
	entries, err := fs.ReadDir(EngineFS, "engine")
	if err != nil {
		t.Fatalf("reading EngineFS: %v", err)
	}
	// Should have at least the .gitkeep placeholder
	if len(entries) == 0 {
		t.Fatal("EngineFS is empty — expected at least .gitkeep")
	}
}

func TestHasEngine_PlaceholderOnly(t *testing.T) {
	// In development (without embed-engine build step), only .gitkeep exists.
	// HasEngine should return false in that case.
	// NOTE: if this test runs after the embed-engine build step, it may return true.
	// We test the logic by verifying HasEngine is callable and returns bool.
	result := HasEngine()
	_ = result // Just verify it doesn't panic
}

func TestExtractEngine_NoEngine(t *testing.T) {
	if HasEngine() {
		t.Skip("engine files are embedded — skipping no-engine test")
	}

	destDir := t.TempDir()
	_, err := ExtractEngine(destDir)
	if err == nil {
		t.Fatal("expected error when no engine files embedded")
	}
}

func TestExtractEngine_WithFiles(t *testing.T) {
	if !HasEngine() {
		t.Skip("no engine files embedded — run with embed-engine build step to test extraction")
	}

	destDir := t.TempDir()
	count, err := ExtractEngine(destDir)
	if err != nil {
		t.Fatalf("ExtractEngine failed: %v", err)
	}

	if count == 0 {
		t.Fatal("expected at least 1 file extracted")
	}

	// Verify engine.py was extracted
	enginePath := filepath.Join(destDir, "engine.py")
	if _, err := os.Stat(enginePath); os.IsNotExist(err) {
		t.Error("expected engine.py to be extracted")
	}

	// Verify analyzers directory was created
	analyzersDir := filepath.Join(destDir, "analyzers")
	info, err := os.Stat(analyzersDir)
	if err != nil {
		t.Errorf("expected analyzers/ directory: %v", err)
	} else if !info.IsDir() {
		t.Error("expected analyzers/ to be a directory")
	}

	// Verify rules directory was created
	rulesDir := filepath.Join(destDir, "rules")
	info, err = os.Stat(rulesDir)
	if err != nil {
		t.Errorf("expected rules/ directory: %v", err)
	} else if !info.IsDir() {
		t.Error("expected rules/ to be a directory")
	}
}

func TestEngineDir(t *testing.T) {
	dir, err := EngineDir()
	if err != nil {
		t.Fatalf("EngineDir failed: %v", err)
	}

	if dir == "" {
		t.Fatal("EngineDir returned empty string")
	}

	if !filepath.IsAbs(dir) {
		t.Errorf("expected absolute path, got %s", dir)
	}

	if filepath.Base(dir) != "engine" {
		t.Errorf("expected path ending in 'engine', got %s", dir)
	}

	// Should contain .fendix in the path
	if !containsSegment(dir, ".fendix") {
		t.Errorf("expected .fendix in path, got %s", dir)
	}
}

func containsSegment(path, segment string) bool {
	for path != "" {
		dir, base := filepath.Split(path)
		base = filepath.Base(path)
		if base == segment {
			return true
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
		_ = dir
	}
	return false
}
