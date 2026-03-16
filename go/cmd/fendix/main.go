// Package main is the entrypoint for the Fendix CLI.
// Fendix is a hybrid API and code security scanner that combines
// black-box HTTP probing (Go) with white-box static analysis (Python).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/fendix/fendix/internal/engine"
	"github.com/fendix/fendix/internal/models"
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
			flags := cmd.Flags()

			urlFlag, _ := flags.GetString("url")
			specFlag, _ := flags.GetString("spec")
			codeFlag, _ := flags.GetString("code")
			authFlag, _ := flags.GetString("auth")
			authTypeFlag, _ := flags.GetString("auth-type")
			authHeaderFlag, _ := flags.GetString("auth-header")
			authUser2Flag, _ := flags.GetString("auth-user2")
			profileFlag, _ := flags.GetString("profile")
			outputFlag, _ := flags.GetString("output")
			formatFlag, _ := flags.GetString("format")
			failOnFlag, _ := flags.GetString("fail-on")
			baselineFlag, _ := flags.GetString("baseline")
			enableActive, _ := flags.GetBool("enable-active")
			workers, _ := flags.GetInt("workers")
			timeout, _ := flags.GetInt("timeout")
			delay, _ := flags.GetInt("delay")
			ignoreFlag, _ := flags.GetString("ignore")
			verbose, _ := flags.GetBool("verbose")

			if urlFlag == "" && specFlag == "" && codeFlag == "" {
				return fmt.Errorf("at least one of --url, --spec, or --code is required")
			}

			cfg := &models.ScanConfig{
				URL:          urlFlag,
				SpecPath:     specFlag,
				CodePath:     codeFlag,
				EnableActive: enableActive,
				Workers:      workers,
				Timeout:      timeout,
				DelayMs:      delay,
				Verbose:      verbose,
				IgnorePath:   ignoreFlag,
				BaselinePath: baselineFlag,
				OutputPath:   outputFlag,
				Format:       formatFlag,
				FailOn:       failOnFlag,
			}

			var flagAuth *models.AuthContext
			if authFlag != "" {
				flagAuth = &models.AuthContext{
					Type:   authTypeFlag,
					Value:  authFlag,
					Header: authHeaderFlag,
				}
			}
			cfg.Auth = models.ResolveAuth(flagAuth, models.ProfileLoader(profileFlag))

			if authUser2Flag != "" {
				cfg.AuthUser2 = models.NormalizeAuth(&models.AuthContext{
					Value:  authUser2Flag,
					Header: authHeaderFlag,
				})
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			orch := engine.NewOrchestrator(cfg)
			exitCode := orch.Run(ctx)
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.String("url", "", "Target API base URL (black-box scanning)")
	flags.String("spec", "", "Path to OpenAPI/Swagger YAML or JSON spec")
	flags.String("code", "", "Path to source code directory (white-box scanning)")
	flags.String("auth", "", `Auth header value, e.g. "Bearer token123"`)
	flags.String("auth-type", "", "Auth type: bearer, apikey, basic, cookie (default: auto-detect)")
	flags.String("auth-header", "Authorization", "Custom auth header name")
	flags.String("auth-user2", "", `Second user auth for IDOR checks, e.g. "Bearer token-user2"`)
	flags.String("profile", "", "Auth profile name from ~/.fendix/profiles/<name>.yaml")
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
