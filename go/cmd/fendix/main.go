// Package main is the entrypoint for the Fendix CLI.
// Fendix is a hybrid API and code security scanner that combines
// black-box HTTP probing (Go) with white-box static analysis (Python).
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/democmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/engine"
	"github.com/Abdel-RahmanSaied/Fendix/internal/initcmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/policy"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	// Install a real slog default at startup. Without this,
	// `slog.Default()` returns the stdlib's *defaultHandler, which routes
	// through log.Default() → back to slog.Default(). Any code that wraps
	// the existing default (the --debug-bundle slog tee) would create
	// infinite recursion on every log call and deadlock on the log
	// package's mutex. Installing a concrete TextHandler here makes the
	// default a real, wrappable handler for every subcommand.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		// Cobra's SilenceErrors=true on the root command suppresses its
		// built-in error printing (which clutters scan output), so we print
		// the error here ourselves before exiting. Without this, errors
		// from any subcommand vanish silently.
		fmt.Fprintln(os.Stderr, "Error:", err)
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
	root.AddCommand(newInitCmd())
	root.AddCommand(newDemoCmd())

	return root
}

func newDemoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Spin up OWASP Juice Shop locally and run a sample scan",
		Long: `Pull and start bkimminich/juice-shop in Docker on localhost:3000, run
a stock fendix scan against it, render an HTML report, and (with --open) open
the report in the default browser. Useful for first-time evaluators who want
to see a real Fendix scan without pointing it at production.

Cleans up the container on exit (success or failure).`,
		Example: `  fendix demo                       # scan, write report to $TMPDIR/fendix-demo-<unix>.html
  fendix demo --open                # also open the report in your browser
  fendix demo --port 4000           # bind juice-shop on a different port
  fendix demo --output ./demo.html  # write report to an explicit path`,
		RunE: func(cmd *cobra.Command, args []string) error {
			openAfter, _ := cmd.Flags().GetBool("open")
			port, _ := cmd.Flags().GetInt("port")
			output, _ := cmd.Flags().GetString("output")
			image, _ := cmd.Flags().GetString("image")

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()

			path, err := democmd.Run(ctx, democmd.Options{
				ImageRef:   image,
				Port:       port,
				OutputPath: output,
				OpenAfter:  openAfter,
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}
			_ = path // already printed by democmd.Run
			return nil
		},
	}
	cmd.Flags().Bool("open", false, "open the rendered HTML report in your default browser when the scan finishes")
	cmd.Flags().Int("port", democmd.DefaultPort, "local port to bind juice-shop on")
	cmd.Flags().String("output", "", "HTML report output path (default: $TMPDIR/fendix-demo-<unix>.html)")
	cmd.Flags().String("image", democmd.DefaultImageRef, "juice-shop Docker image reference (pinned for reproducibility)")
	return cmd
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a default CI workflow + .fendix-ignore in the current directory",
		Long: `Detect the project stack and write a drop-in GitHub Actions workflow plus a
.fendix-ignore starter file. Refuses to overwrite existing files unless --force is set.

Files written (relative to the working directory):
  .github/workflows/fendix.yml   — PR-gated DAST + SAST scan with SARIF upload
  .fendix-ignore                 — empty starter for finding-level suppressions

Use --print to preview without writing.`,
		Example: `  fendix init                    # write the files
  fendix init --print            # preview the generated content
  fendix init --force            # overwrite existing files`,
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			print, _ := cmd.Flags().GetBool("print")
			return initcmd.Run(initcmd.Options{
				Force: force,
				Print: print,
				Out:   cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().Bool("force", false, "overwrite existing files")
	cmd.Flags().Bool("print", false, "print generated content to stdout instead of writing")
	return cmd
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
			saveBaselineFlag, _ := flags.GetString("save-baseline")
			enableActive, _ := flags.GetBool("enable-active")
			maxProbesPerEndpoint, _ := flags.GetInt("max-probes-per-endpoint")
			workers, _ := flags.GetInt("workers")
			timeout, _ := flags.GetInt("timeout")
			delay, _ := flags.GetInt("delay")
			ignoreFlag, _ := flags.GetString("ignore")
			verbose, _ := flags.GetBool("verbose")
			wordlistFlag, _ := flags.GetString("wordlist")
			crawlDepth, _ := flags.GetInt("crawl-depth")
			maxEndpoints, _ := flags.GetInt("max-endpoints")
			maxRequests, _ := flags.GetInt64("max-requests")
			maxDuration, _ := flags.GetDuration("max-duration")
			respectRobots, _ := flags.GetBool("respect-robots")
			debugBundleFlag, _ := flags.GetString("debug-bundle")
			noPluginsFlag, _ := flags.GetBool("no-plugins")
			noNativeDepsFlag, _ := flags.GetBool("no-native-deps")
			configFlag, _ := flags.GetString("config")

			// Resolve --config: explicit path takes precedence; if
			// absent and a .fendix.yaml exists in the cwd, pick it up
			// silently. Missing files are not errors — user might just
			// be running fendix without a policy.
			policyPath := configFlag
			if policyPath == "" {
				if _, err := os.Stat(policy.DefaultPath); err == nil {
					policyPath = policy.DefaultPath
				}
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fmt.Errorf("loading policy %s: %w", policyPath, err)
			}
			if configFlag != "" && pol == nil {
				// User explicitly pointed at a config file that doesn't
				// exist — refuse to silently fall back to flag-only.
				return fmt.Errorf("policy file not found: %s", configFlag)
			}

			if urlFlag == "" && specFlag == "" && codeFlag == "" {
				return fmt.Errorf("at least one of --url, --spec, or --code is required")
			}

			cfg := &models.ScanConfig{
				URL:                  urlFlag,
				SpecPath:             specFlag,
				CodePath:             codeFlag,
				EnableActive:         enableActive,
				MaxProbesPerEndpoint: maxProbesPerEndpoint,
				Workers:              workers,
				Timeout:              timeout,
				DelayMs:              delay,
				Verbose:              verbose,
				IgnorePath:           ignoreFlag,
				BaselinePath:         baselineFlag,
				SaveBaselinePath:     saveBaselineFlag,
				OutputPath:           outputFlag,
				Format:               formatFlag,
				FailOn:               failOnFlag,
				WordlistPath:         wordlistFlag,
				CrawlDepth:           crawlDepth,
				MaxEndpoints:         maxEndpoints,
				MaxRequests:          maxRequests,
				MaxDuration:          maxDuration,
				RespectRobots:        respectRobots,
				DebugBundlePath:      debugBundleFlag,
				NoPlugins:            noPluginsFlag,
				NoNativeDeps:         noNativeDepsFlag,
			}

			// Apply policy file values to cfg for fields the user did
			// NOT pass on the CLI. Precedence: cobra-default → policy
			// file → explicit CLI flag (CLI wins). The CLISet captures
			// which flags cobra observed as explicitly changed.
			if pol != nil {
				cli := policy.CLISet{}
				flags.Visit(func(f *pflag.Flag) { cli[f.Name] = true })
				appliedProfile := profileFlag
				applied := policy.ApplyTo{
					SetFailOn:        func(v string) { cfg.FailOn = v },
					SetEnableActive:  func(v bool) { cfg.EnableActive = v },
					SetWorkers:       func(v int) { cfg.Workers = v },
					SetTimeoutSec:    func(v int) { cfg.Timeout = v },
					SetDelayMs:       func(v int) { cfg.DelayMs = v },
					SetFormat:        func(v string) { cfg.Format = v },
					SetCrawlDepth:    func(v int) { cfg.CrawlDepth = v },
					SetMaxEndpoints:  func(v int) { cfg.MaxEndpoints = v },
					SetWordlistPath:  func(v string) { cfg.WordlistPath = v },
					SetRespectRobots: func(v bool) { cfg.RespectRobots = v },
					SetMaxRequests:   func(v int64) { cfg.MaxRequests = v },
					SetMaxDuration:   func(v time.Duration) { cfg.MaxDuration = v },
					SetIgnorePath:    func(v string) { cfg.IgnorePath = v },
					SetAuthProfile:   func(v string) { appliedProfile = v },
				}.Run(pol, cli)
				if applied > 0 {
					slog.Info("policy applied", "path", policyPath, "fields", applied)
				}
				profileFlag = appliedProfile
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

			orch := engine.NewOrchestrator(cfg, Version)
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
	flags.Int("max-probes-per-endpoint", 20, "Max active probes per endpoint (only effective with --enable-active)")
	flags.IntP("workers", "w", 10, "Concurrent HTTP workers")
	flags.Int("timeout", 10, "HTTP timeout in seconds")
	flags.Int("delay", 100, "Milliseconds between HTTP requests")
	flags.String("ignore", "", "Path to .fendix-ignore file")
	flags.BoolP("verbose", "v", false, "Print all requests and raw findings")
	flags.String("wordlist", "", "Path to brute-force wordlist (one path per line); overrides built-in CommonPaths")
	flags.Int("crawl-depth", 1, "Recursive HTML link crawl depth (0 disables; 1 = home-page links only)")
	flags.Int("max-endpoints", 500, "Cap total discovered endpoints (0 = no cap)")
	flags.Int64("max-requests", 0, "Soft-cap on total HTTP requests across all checks (0 = no cap)")
	flags.Duration("max-duration", 0, "Soft-cap on total scan wall-clock time, e.g. 5m (0 = no cap)")
	flags.Bool("respect-robots", false, "Treat robots.txt Disallow as a hard restriction (default: queue as discovery hints)")
	flags.String("debug-bundle", "", "Write a redacted diagnostic tarball to this path at scan end (intended for bug reports)")
	flags.Bool("no-plugins", false, "Disable out-of-tree plugin discovery in .fendix/plugins/ + ~/.fendix/plugins/")
	flags.Bool("no-native-deps", false, "Disable the in-process Go dep-CVE scanner (TASK-119). Defer to the Python deps.py path instead.")
	flags.String("config", "", "Path to .fendix.yaml policy file (default: auto-detect .fendix.yaml in cwd)")

	return cmd
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render a saved findings file",
		Long:  "Convert a previously saved JSON findings file to HTML or SARIF format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			inputPath, _ := flags.GetString("input")
			formatFlag, _ := flags.GetString("format")
			outputPath, _ := flags.GetString("output")

			if inputPath == "" {
				return fmt.Errorf("--input is required: path to a findings JSON file")
			}

			data, err := os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("reading input file %s: %w", inputPath, err)
			}

			report, err := reporters.ParseJSONReport(data)
			if err != nil {
				return fmt.Errorf("loading %s: %w", inputPath, err)
			}

			var w io.Writer = os.Stdout
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file %s: %w", outputPath, err)
				}
				defer f.Close()
				w = f
			}

			switch formatFlag {
			case "html":
				return reporters.RenderHTML(w, report.Findings, report.Metadata)
			case "sarif":
				return reporters.RenderSARIF(w, report.Findings, report.Metadata)
			case "json":
				return reporters.RenderJSON(w, report.Findings, report.Metadata)
			default:
				return fmt.Errorf("unsupported format %q — use json, html, or sarif", formatFlag)
			}
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
