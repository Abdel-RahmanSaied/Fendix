// Subcommand: `fendix engine` — inspect and refresh the Python whitebox
// engine that backs the AST analyzer (injection / SSTI / pickle / yaml-load
// / path-traversal). Resolution mirrors engine.EnsureEngine:
//
//	1. --dir flag (explicit override)
//	2. FENDIX_ENGINE env var
//	3. embedded payload extracted to ~/.fendix/engine
//	4. ./python relative to CWD (dev mode)
//
// Two operations:
//   - `fendix engine info` — show which engine path resolves and from where,
//     plus the Version stamp on disk. Useful for "why is this scan missing
//     findings" support questions.
//   - `fendix engine sync` — force re-extraction of the embedded engine even
//     if the Version stamp matches the binary. Lets users recover from a
//     hand-edited / partially-deleted ~/.fendix/engine without uninstalling
//     and reinstalling.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Abdel-RahmanSaied/Fendix/internal/embedded"
	"github.com/Abdel-RahmanSaied/Fendix/internal/engine"
	"github.com/spf13/cobra"
)

func newEngineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine",
		Short: "Inspect or refresh the Python whitebox engine",
		Long: `Manage the Python engine that backs the AST analyzer (taint chains for
SQL injection / SSTI / pickle / yaml.load / path traversal). The engine
is normally bundled with the binary and extracted on first scan; this
command lets you check what's installed and force a clean refresh.`,
	}
	cmd.AddCommand(newEngineInfoCmd())
	cmd.AddCommand(newEngineSyncCmd())
	return cmd
}

func newEngineInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show where the Python engine is loaded from",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Binary Version: %s\n", Version)
			if env := os.Getenv("FENDIX_ENGINE"); env != "" {
				fmt.Fprintf(out, "FENDIX_ENGINE:  %s\n", env)
			} else {
				fmt.Fprintln(out, "FENDIX_ENGINE:  (unset)")
			}
			fmt.Fprintf(out, "Embedded:       %v\n", embedded.HasEngine())

			path, err := engine.EnsureEngine("", Version)
			if err != nil {
				fmt.Fprintf(out, "Resolved:       (none — %s)\n", err)
				return nil
			}
			fmt.Fprintf(out, "Resolved:       %s\n", path)
			stampPath := filepath.Join(path, engine.VersionFile)
			if data, err := os.ReadFile(stampPath); err == nil {
				fmt.Fprintf(out, "Version stamp:  %s\n", string(data))
			} else {
				fmt.Fprintln(out, "Version stamp:  (not present)")
			}
			return nil
		},
	}
}

func newEngineSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Force re-extraction of the embedded engine to ~/.fendix/engine",
		Long: `Re-extract the bundled engine even when the Version stamp already
matches this binary. Use after manually editing files in ~/.fendix/engine
to reset to a known-good state, or when troubleshooting why scans return
fewer findings than expected.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !embedded.HasEngine() {
				return fmt.Errorf("this binary has no embedded engine — install a release binary or set FENDIX_ENGINE to point at a source tree")
			}
			dest, err := embedded.EngineDir()
			if err != nil {
				return fmt.Errorf("resolving engine destination: %w", err)
			}
			// Remove the existing tree so we don't leave orphan files
			// from a previous engine Version that this binary doesn't
			// know about. Safe — embedded.ExtractEngine repopulates.
			if err := os.RemoveAll(dest); err != nil {
				return fmt.Errorf("clearing %s: %w", dest, err)
			}
			count, err := embedded.ExtractEngine(dest)
			if err != nil {
				return fmt.Errorf("extracting engine: %w", err)
			}
			// Re-stamp so future binary-Version checks see the fresh extraction.
			if err := os.WriteFile(filepath.Join(dest, engine.VersionFile), []byte(Version), 0644); err != nil {
				return fmt.Errorf("writing Version stamp: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Re-extracted %d files to %s (stamped %s)\n", count, dest, Version)
			return nil
		},
	}
	return cmd
}
