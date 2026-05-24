// Package main is the entrypoint for the Fendix CLI.
// Fendix is a hybrid API and code security scanner that combines
// black-box HTTP probing (Go) with white-box static analysis (Python).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/cli"
	"github.com/Abdel-RahmanSaied/Fendix/internal/democmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/engine"
	"github.com/Abdel-RahmanSaied/Fendix/internal/ignorecmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/initcmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/pluginscmd"
	"github.com/Abdel-RahmanSaied/Fendix/internal/policy"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/verifycmd"
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
		// Sprint 03 introduced *cli.ExitError so subcommands (today: just
		// verify) can dictate a specific process exit code that's
		// CI-script-friendly. Catch and translate before falling through
		// to the generic error-prints-then-exit-2 path.
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}

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
	root.AddCommand(newNotifyCmd())
	root.AddCommand(newJiraCmd())
	root.AddCommand(newDBCmd())
	root.AddCommand(newEngineCmd())
	root.AddCommand(pluginscmd.NewCmd())
	root.AddCommand(ignorecmd.NewCmd())

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
		Long: `Detect the project stack and write a drop-in CI workflow plus a
.fendix-ignore starter file. Refuses to overwrite existing files unless --force is set.

Pick a CI system via --ci. Without it, fendix auto-detects from .github/,
.gitlab-ci.yml, or .circleci/ in the project root, defaulting to GitHub when
none of those is present.

Files written (relative to the working directory):
  --ci github (default)  .github/workflows/fendix.yml   — PR-gated DAST+SAST scan
                         .fendix.yaml                   — policy starter
                         .fendix-ignore                 — finding suppressions
  --ci gitlab            .gitlab-ci.fendix.yml          — GitLab CI include file
                         NEXT-STEPS-fendix.md           — wiring instructions
                         .fendix.yaml + .fendix-ignore
  --ci circleci          .circleci/fendix-config.yml    — CircleCI snippet
                         NEXT-STEPS-fendix.md           — wiring instructions
                         .fendix.yaml + .fendix-ignore

Use --print to preview without writing.`,
		Example: `  fendix init                       # auto-detect CI; write the files
  fendix init --ci gitlab           # emit GitLab CI templates
  fendix init --ci circleci         # emit CircleCI templates
  fendix init --print               # preview the generated content
  fendix init --force               # overwrite existing files`,
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			print, _ := cmd.Flags().GetBool("print")
			ci, _ := cmd.Flags().GetString("ci")
			return initcmd.Run(initcmd.Options{
				Force: force,
				Print: print,
				CI:    ci,
				Out:   cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().Bool("force", false, "overwrite existing files")
	cmd.Flags().Bool("print", false, "print generated content to stdout instead of writing")
	cmd.Flags().String("ci", "", "CI system to emit templates for: github, gitlab, circleci (default: auto-detect → github)")
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
			usePipAuditFlag, _ := flags.GetBool("use-pip-audit")
			pythonEngineFlag, _ := flags.GetBool("python-engine")
			// Auto-enable the Python engine for whitebox scans unless the
			// user explicitly disabled it. Without this, `fendix scan --code
			// <path>` runs only the native-Go checks (secrets / semgrep /
			// deps) and silently skips the AST injection / open-redirect /
			// SSTI / path-traversal / pickle / yaml-load analyzer entirely.
			// When the engine isn't discoverable, NewOrchestrator logs a
			// debug-level message and continues with the Go-only checks.
			if codeFlag != "" && !flags.Changed("python-engine") {
				pythonEngineFlag = true
			}
			configFlag, _ := flags.GetString("config")
			langFlag, _ := flags.GetString("lang")

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
				UsePipAudit:          usePipAuditFlag,
				PythonEngine:         pythonEngineFlag,
				Lang:                 resolveLang(langFlag, cmd.ErrOrStderr()),
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
	flags.StringP("format", "f", "json", "Output format: json, html, sarif, pdf")
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
	flags.Bool("use-pip-audit", false, "Shell out to the pip-audit binary for Python dep-CVE scanning instead of the native OSV.dev client. Falls back to OSV.dev with a warning if pip-audit is not on PATH.")
	flags.Bool("python-engine", false, "Spawn the Python whitebox engine for auth/injection/deps checks (TASK-118). Default off — secrets and semgrep are now native Go and the embedded Python distribution is no longer bundled. Requires a local python/ source tree or FENDIX_ENGINE pointing at one.")
	flags.String("config", "", "Path to .fendix.yaml policy file (default: auto-detect .fendix.yaml in cwd)")
	flags.String("lang", "en", "HTML report language: en (default), ar (Arabic, RTL). Other formats stay English.")
	flags.Bool("offline", false, "Air-gapped mode (Sprint 09): consult the local offline-db snapshot for dep CVEs instead of osv.dev/golang.org/x/vuln. Today this is a no-op honest stub — the snapshot is created via `fendix db update`; per-scanner integration is wired sprint-by-sprint (see internal/offline/offline.go).")
	flags.String("offline-db", "", "Path to the offline-db snapshot (default: ~/.fendix/offline-db.json). Only effective with --offline.")

	return cmd
}

// resolveLang validates --lang against the i18n-supported set. Unknown
// values fall back to English with a one-line warning to stderr so the
// user can see their flag didn't take effect.
func resolveLang(lang string, stderr io.Writer) string {
	if lang == "" {
		return "en"
	}
	if reporters.IsSupportedLang(lang) {
		return lang
	}
	fmt.Fprintf(stderr, "warning: --lang=%q is not a supported translation; falling back to English. Supported: en, ar.\n", lang)
	return "en"
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
			langFlag, _ := flags.GetString("lang")
			lang := resolveLang(langFlag, cmd.ErrOrStderr())

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
				return reporters.RenderHTMLOpts(w, report.Findings, report.Metadata, reporters.HTMLOptions{Lang: lang})
			case "sarif":
				return reporters.RenderSARIF(w, report.Findings, report.Metadata)
			case "pdf":
				classification, _ := flags.GetString("classification")
				return reporters.RenderPDF(w, report.Findings, report.Metadata, reporters.PDFOptions{Classification: classification})
			case "json":
				return reporters.RenderJSON(w, report.Findings, report.Metadata)
			default:
				return fmt.Errorf("unsupported format %q — use json, html, sarif, or pdf", formatFlag)
			}
		},
	}

	flags := cmd.Flags()
	flags.String("input", "", "Path to findings JSON file")
	flags.StringP("format", "f", "html", "Output format: json, html, sarif, pdf")
	flags.StringP("output", "o", "", "Output file path (default: stdout)")
	flags.String("lang", "en", "HTML report language: en (default), ar (Arabic, RTL). Other formats stay English.")
	flags.String("classification", "INTERNAL", "PDF classification banner text rendered on every page (empty disables; only used by --format pdf)")

	return cmd
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [finding-id]",
		Short: "Re-run a single finding by ID and report still-present / resolved",
		Long: `Re-test a specific finding from a saved baseline scan report and
report whether it is still present, resolved, or unverifiable.

Supported finding shapes:
  - URL-anchored DAST findings    (source: blackbox)
  - File-anchored SAST findings   (source: whitebox; category:
                                   secrets / injection / headers / ...)
  - Dependency CVE findings       (category: deps)

Not yet supported (returns status "unknown" with an explanatory reason):
  - Correlated findings           (source: correlated)
  - Active injection probe findings (require --enable-active to reproduce)

Exit codes (Sprint 03 of the enterprise-readiness plan):
  0   resolved          — the finding no longer fires
  1   still-present     — the finding still fires; CI should fail the build
  2   unknown OR
      not-found-in-baseline
                        — verify could not produce a confident result;
                          the operator should investigate but CI should
                          NOT auto-fail on this

The user passes --baseline pointing at a previously saved findings.json
from "fendix scan --output ...", plus the same --url and/or --code that
the original scan used.

Output is JSON (machine-readable) when --json is set; otherwise a short
human-readable summary.

Use in CI:

  fendix verify SEC-001-abc --baseline scan.json --url $TARGET_URL
  case $? in
    0) echo "resolved";;
    1) echo "still present"; exit 1;;
    2) echo "verify could not tell — investigate manually";;
  esac
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			baseline, _ := cmd.Flags().GetString("baseline")
			targetURL, _ := cmd.Flags().GetString("url")
			codePath, _ := cmd.Flags().GetString("code")
			auth, _ := cmd.Flags().GetString("auth")
			emitJSON, _ := cmd.Flags().GetBool("json")
			timeoutSec, _ := cmd.Flags().GetInt("timeout")

			if baseline == "" {
				return fmt.Errorf("--baseline <findings.json> is required")
			}
			if targetURL == "" && codePath == "" {
				return fmt.Errorf("at least one of --url or --code must be set (matching the original scan)")
			}

			result, err := verifycmd.Run(cmd.Context(), args[0], verifycmd.Options{
				BaselinePath: baseline,
				URL:          targetURL,
				CodePath:     codePath,
				Auth:         auth,
				Timeout:      time.Duration(timeoutSec) * time.Second,
			})
			if err != nil {
				return err
			}
			if err := verifycmd.Render(os.Stdout, result, emitJSON); err != nil {
				return err
			}

			// Exit-code semantics for CI scripting (Sprint 03).
			// 0 = resolved (default for RunE returning nil)
			// 1 = still-present (CI should fail the build)
			// 2 = unknown / not-found-in-baseline (operator should
			//     investigate but CI should not auto-fail)
			switch result.Status {
			case verifycmd.StatusResolved:
				return nil
			case verifycmd.StatusStillPresent:
				return cli.ExitWithCode(1, "finding still present")
			case verifycmd.StatusUnknown, verifycmd.StatusNotFound:
				return cli.ExitWithCode(2, fmt.Sprintf("verification %s", result.Status))
			default:
				return cli.ExitWithCode(2, fmt.Sprintf("unexpected status %q", result.Status))
			}
		},
	}
	cmd.Flags().String("baseline", "", "Path to the saved findings.json from the original scan (required)")
	cmd.Flags().String("url", "", "Target URL (re-test URL-anchored findings; same as original --url)")
	cmd.Flags().String("code", "", "Source code path (re-test file-anchored / dep findings; same as original --code)")
	cmd.Flags().String("auth", "", "Authorization header value (e.g. \"Bearer ...\")")
	cmd.Flags().Bool("json", false, "Emit JSON instead of the human-readable summary")
	cmd.Flags().Int("timeout", 15, "HTTP timeout in seconds (URL-anchored verify only)")
	return cmd
}
