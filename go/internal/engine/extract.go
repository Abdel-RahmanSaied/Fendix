package engine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Abdel-RahmanSaied/Fendix/internal/embedded"
)

// VersionFile is written to the engine directory after extraction.
// On upgrade, if the binary version differs, re-extract.
const VersionFile = ".fendix-version"

// EnsureEngine returns a path to a usable Python engine directory.
// Resolution order:
//  1. If engineDir is set (dev mode / explicit config), use it directly.
//  2. If FENDIX_ENGINE env var is set, use that (matches the --help and
//     package doc promise; lets CI / E2E tests point at the repo's
//     python/ tree without changing CWD).
//  3. If embedded FS has engine files, extract to ~/.fendix/engine/ and return that.
//  4. Fall back to "python" relative to CWD (source tree development).
//
// The version parameter is the Go binary version (e.g. "1.0.0" or "dev").
// If the extracted engine has a different version stamp, it is re-extracted.
func EnsureEngine(engineDir, version string) (string, error) {
	// 1. Explicit engine directory — use directly
	if engineDir != "" {
		if _, err := os.Stat(filepath.Join(engineDir, "engine.py")); err == nil {
			slog.Debug("using explicit engine directory", "dir", engineDir)
			return engineDir, nil
		}
		return "", fmt.Errorf("engine directory %s does not contain engine.py", engineDir)
	}

	// 2. FENDIX_ENGINE env override — documented in --python-engine's
	// flag description. Lets CI / tests point at an absolute path
	// without depending on the binary's CWD.
	if envDir := os.Getenv("FENDIX_ENGINE"); envDir != "" {
		if _, err := os.Stat(filepath.Join(envDir, "engine.py")); err == nil {
			slog.Debug("using FENDIX_ENGINE directory", "dir", envDir)
			return envDir, nil
		}
		return "", fmt.Errorf("FENDIX_ENGINE=%s does not contain engine.py", envDir)
	}

	// 3. Try embedded extraction
	if embedded.HasEngine() {
		destDir, err := embedded.EngineDir()
		if err != nil {
			return "", fmt.Errorf("determining engine directory: %w", err)
		}

		if needsExtraction(destDir, version) {
			slog.Info("extracting embedded python engine", "dest", destDir)
			count, err := embedded.ExtractEngine(destDir)
			if err != nil {
				return "", fmt.Errorf("extracting engine: %w", err)
			}
			slog.Info("python engine extracted", "files", count, "dest", destDir)

			// Write version stamp
			if err := writeVersionStamp(destDir, version); err != nil {
				slog.Warn("failed to write version stamp", "error", err)
			}
		} else {
			slog.Debug("embedded engine already extracted", "dir", destDir)
		}

		return destDir, nil
	}

	// 4. Fall back to local "python" directory (development mode)
	localDir := "python"
	if _, err := os.Stat(filepath.Join(localDir, "engine.py")); err == nil {
		slog.Debug("using local python engine directory", "dir", localDir)
		return localDir, nil
	}

	return "", fmt.Errorf("no python engine found: no embedded engine, no local python/ directory")
}

// needsExtraction returns true if the engine needs to be extracted or re-extracted.
func needsExtraction(destDir, version string) bool {
	// Check if engine.py exists
	if _, err := os.Stat(filepath.Join(destDir, "engine.py")); os.IsNotExist(err) {
		return true
	}

	// Check version stamp
	stampPath := filepath.Join(destDir, VersionFile)
	stamp, err := os.ReadFile(stampPath)
	if err != nil {
		return true // No stamp — re-extract
	}

	// Dev builds always re-extract (version changes frequently during development)
	if version == "dev" || version == "" {
		return false // Don't re-extract in dev mode — wastes time
	}

	return string(stamp) != version
}

// writeVersionStamp writes the version to the engine directory.
func writeVersionStamp(destDir, version string) error {
	stampPath := filepath.Join(destDir, VersionFile)
	return os.WriteFile(stampPath, []byte(version), 0o644)
}
