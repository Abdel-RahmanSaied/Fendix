// Package main is the entrypoint for the Fendix CLI.
// Fendix is a hybrid API and code security scanner that combines
// black-box HTTP probing (Go) with white-box static analysis (Python).
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "fendix",
		Short: "Fendix — hybrid API and code security scanner",
		Long: `Fendix finds vulnerabilities before attackers do.

It combines black-box HTTP scanning with white-box static analysis
to produce high-confidence security findings with evidence.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newVerifyCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fendix version %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a security scan",
		Long:  "Scan an API endpoint, source code, or both for security vulnerabilities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("scan: not yet implemented (Phase 1)")
			return nil
		},
	}

	// All scan flags per spec — wired to variables in later tasks.
	flags := cmd.Flags()
	flags.String("url", "", "Target API base URL (black-box scanning)")
	flags.String("spec", "", "Path to OpenAPI/Swagger YAML or JSON spec")
	flags.String("code", "", "Path to source code directory (white-box scanning)")
	flags.String("auth", "", `Auth header value, e.g. "Bearer token123"`)
	flags.String("auth-type", "", "Auth type: bearer, apikey, basic, cookie (default: auto-detect)")
	flags.String("auth-header", "Authorization", "Custom auth header name")
	flags.StringP("output", "o", "", "Output file path (default: stdout)")
	flags.StringP("format", "f", "json", "Output format: json, html, sarif")
	flags.String("fail-on", "", "Exit 1 if findings at this severity: CRITICAL, HIGH, MEDIUM")
	flags.String("baseline", "", "Path to previous findings JSON for diff mode")
	flags.String("save-baseline", "", "Save current findings to this path")
	flags.Bool("enable-active", false, "Enable active injection probes (default: false)")
	flags.IntP("workers", "w", 10, "Concurrent HTTP workers")
	flags.Int("timeout", 10, "HTTP timeout in seconds")
	flags.Int("delay", 100, "Milliseconds between HTTP requests")
	flags.String("ignore", "", "Path to .fendix-ignore file")
	flags.BoolP("verbose", "v", false, "Print all requests and raw findings")

	return cmd
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render a saved findings file",
		Long:  "Convert a previously saved JSON findings file to HTML or SARIF format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("report: not yet implemented (Phase 6)")
			return nil
		},
	}

	flags := cmd.Flags()
	flags.String("input", "", "Path to findings JSON file")
	flags.StringP("format", "f", "html", "Output format: json, html, sarif")
	flags.StringP("output", "o", "", "Output file path (default: stdout)")

	return cmd
}

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify [finding-id]",
		Short: "Re-run a single finding by ID",
		Long:  "Re-test a specific finding to verify it still exists.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("verify: not yet implemented (Phase 4) — finding %s\n", args[0])
			return nil
		},
	}
}
