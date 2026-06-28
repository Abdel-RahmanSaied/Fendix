package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/metrics"
	"github.com/spf13/cobra"
)

// newMetricsCmd is the `fendix metrics` command group (v0.20). It reads the
// opt-in local event log (FENDIX_METRICS) and never makes a network call.
func newMetricsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Inspect local product metrics (opt-in via FENDIX_METRICS)",
		Long: `Show, export, or clear the local metrics event log written when
FENDIX_METRICS is set. All data stays on disk (` + metrics.DefaultPath + `);
nothing is ever sent anywhere.`,
	}
	cmd.AddCommand(newMetricsShowCmd(), newMetricsExportCmd(), newMetricsClearCmd())
	return cmd
}

func newMetricsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print a summary of the last 30 scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			events, err := metrics.LoadEvents(metrics.DefaultPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(events) == 0 {
				fmt.Fprintf(out, "No metrics recorded yet. Enable with FENDIX_METRICS=true and run a scan.\n")
				return nil
			}
			s := metrics.Summarize(events, 30)
			arrow := map[string]string{"improving": "↓ improving", "worsening": "↑ worsening", "flat": "→ flat"}[s.DurationTrend]
			fmt.Fprintf(out, "Fendix metrics — last %d scans\n", s.Count)
			fmt.Fprintln(out, "─────────────────────────────")
			fmt.Fprintf(out, "Total scans:        %d\n", s.Count)
			fmt.Fprintf(out, "Avg duration:       %.1fs\n", s.AvgDurationMs/1000)
			fmt.Fprintf(out, "Avg findings:       %.1f\n", s.AvgFindings)
			fmt.Fprintf(out, "Avg memory:         %.0fMB\n", s.AvgMemoryMB)
			fmt.Fprintf(out, "Last run:           %s\n", s.LastRun.Format("2006-01-02 15:04 MST"))
			fmt.Fprintf(out, "Trend (duration):   %s\n", arrow)
			return nil
		},
	}
}

func newMetricsExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Dump all recorded events",
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, _ := cmd.Flags().GetBool("json")
			events, err := metrics.LoadEvents(metrics.DefaultPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(events)
			}
			// Default: re-emit the raw NDJSON.
			enc := json.NewEncoder(out)
			for _, e := range events {
				if err := enc.Encode(e); err != nil {
					return fmt.Errorf("encoding event: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "Emit a single indented JSON array instead of NDJSON")
	return cmd
}

func newMetricsClearCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete the local metrics event log",
		RunE: func(cmd *cobra.Command, args []string) error {
			yes, _ := cmd.Flags().GetBool("yes")
			out := cmd.OutOrStdout()
			if _, err := os.Stat(metrics.DefaultPath); os.IsNotExist(err) {
				fmt.Fprintln(out, "Nothing to clear — no metrics log exists.")
				return nil
			}
			if !yes {
				fmt.Fprintf(out, "Delete %s? [y/N] ", metrics.DefaultPath)
				reader := bufio.NewReader(cmd.InOrStdin())
				line, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(line)) != "y" {
					fmt.Fprintln(out, "Aborted.")
					return nil
				}
			}
			if err := os.Remove(metrics.DefaultPath); err != nil {
				return fmt.Errorf("removing metrics log: %w", err)
			}
			fmt.Fprintf(out, "Removed %s\n", metrics.DefaultPath)
			return nil
		},
	}
	cmd.Flags().Bool("yes", false, "Skip the confirmation prompt")
	return cmd
}
