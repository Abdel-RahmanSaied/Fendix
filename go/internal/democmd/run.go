// Package democmd implements the `fendix demo` subcommand: spin up
// OWASP Juice Shop locally in Docker, run a stock fendix scan against
// it, render an HTML report, and (optionally) open the report in the
// default browser. Removes the cold-start "what does a real scan look
// like?" question for first-time evaluators.
//
// The command shells out to the host's docker CLI rather than using a
// Docker SDK; this avoids a heavy dependency, matches the existing
// scripts/benchmark/run-juice-shop.sh pattern, and works everywhere
// the user's docker setup works (Docker Desktop, Colima, OrbStack,
// etc.).
package democmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Defaults — can be overridden via Options.
const (
	DefaultImageRef       = "bkimminich/juice-shop:v17.1.1"
	DefaultPort           = 3000
	DefaultContainerName  = "fendix-demo"
	DefaultHealthTimeout  = 90 * time.Second
	DefaultScanTimeout    = 5 * time.Minute
	DefaultHealthInterval = 2 * time.Second
)

// Errors returned by Run. Distinguished so the calling cobra command
// can map them to actionable user messages.
var (
	ErrDockerMissing       = errors.New("docker not found on PATH")
	ErrFendixBinaryMissing = errors.New("could not locate fendix binary; pass --fendix-bin")
	ErrPortInUse           = errors.New("local port already in use")
	ErrJuiceShopNotReady   = errors.New("juice-shop did not become healthy within the timeout")
	ErrScanFailed          = errors.New("fendix scan failed")
)

// Options configures Run. Zero-valued fields use the Default* constants
// above. The struct is deliberately public so callers (cobra subcommand,
// future fendix-demo Docker recipe) can wire in their own paths.
type Options struct {
	ImageRef       string
	Port           int
	ContainerName  string
	OutputPath     string // HTML report path. If empty, derived to $TMPDIR/fendix-demo-<unix>.html.
	OpenAfter      bool
	FendixBin      string // Defaults to /proc/self/exe (the running fendix binary).
	HealthTimeout  time.Duration
	ScanTimeout    time.Duration
	HealthInterval time.Duration

	// Stdout, Stderr are where progress and command output stream.
	// Default to os.Stdout / os.Stderr when nil.
	Stdout, Stderr io.Writer

	// docker, exec hooks for tests. See defaultDocker.
	docker dockerCmd
}

// dockerCmd lets tests substitute a fake. Production wires to the
// host's docker CLI.
type dockerCmd interface {
	Run(ctx context.Context, args ...string) error
	Output(ctx context.Context, args ...string) (string, error)
}

type realDocker struct{}

func (realDocker) Run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func (realDocker) Output(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	return string(out), err
}

// resolve fills in defaults on a copy of the input Options.
func (o Options) resolve() Options {
	if o.ImageRef == "" {
		o.ImageRef = DefaultImageRef
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.ContainerName == "" {
		o.ContainerName = DefaultContainerName
	}
	if o.HealthTimeout == 0 {
		o.HealthTimeout = DefaultHealthTimeout
	}
	if o.ScanTimeout == 0 {
		o.ScanTimeout = DefaultScanTimeout
	}
	if o.HealthInterval == 0 {
		o.HealthInterval = DefaultHealthInterval
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.OutputPath == "" {
		o.OutputPath = filepath.Join(os.TempDir(), fmt.Sprintf("fendix-demo-%d.html", time.Now().Unix()))
	}
	if o.docker == nil {
		o.docker = realDocker{}
	}
	return o
}

// Run executes the demo flow. Always cleans up the container on exit.
// Returns the path of the rendered HTML report on success.
func Run(ctx context.Context, opts Options) (reportPath string, err error) {
	opts = opts.resolve()

	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("%w: install Docker Desktop, OrbStack, or Colima and try again", ErrDockerMissing)
	}

	fendixBin := opts.FendixBin
	if fendixBin == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrFendixBinaryMissing, err)
		}
		fendixBin = exe
	}

	// Stop any leftover container from a prior run; ignore "no such
	// container" errors (the common case).
	_ = opts.docker.Run(ctx, "rm", "-f", opts.ContainerName)

	fmt.Fprintf(opts.Stdout, "→ pulling and starting %s on :%d (this may take a minute on first run)\n", opts.ImageRef, opts.Port)
	if err := opts.docker.Run(ctx,
		"run", "-d", "--rm",
		"--name", opts.ContainerName,
		"-p", fmt.Sprintf("%d:3000", opts.Port),
		opts.ImageRef,
	); err != nil {
		return "", fmt.Errorf("docker run: %w", err)
	}

	// Always tear down the container — success or failure.
	defer func() {
		// Use a fresh context so a parent-cancel doesn't prevent
		// cleanup. The 30s budget is generous for a stop+rm.
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = opts.docker.Run(stopCtx, "rm", "-f", opts.ContainerName)
	}()

	fmt.Fprintf(opts.Stdout, "→ waiting up to %s for juice-shop to be ready\n", opts.HealthTimeout)
	if err := waitForJuiceShop(ctx, opts.Port, opts.HealthTimeout, opts.HealthInterval); err != nil {
		return "", err
	}
	fmt.Fprintln(opts.Stdout, "→ juice-shop ready")

	fmt.Fprintf(opts.Stdout, "→ running fendix scan against http://localhost:%d\n", opts.Port)
	scanCtx, cancel := context.WithTimeout(ctx, opts.ScanTimeout)
	defer cancel()

	scanCmd := exec.CommandContext(scanCtx, fendixBin, "scan",
		"--url", fmt.Sprintf("http://localhost:%d", opts.Port),
		"--format", "html",
		"--output", opts.OutputPath,
	)
	scanCmd.Stdout = opts.Stdout
	scanCmd.Stderr = opts.Stderr
	if err := scanCmd.Run(); err != nil {
		// fendix exits non-zero when --fail-on triggers; treat any
		// error here as a scan failure and surface it for triage.
		return "", fmt.Errorf("%w: %v", ErrScanFailed, err)
	}

	fmt.Fprintf(opts.Stdout, "✓ report written to %s\n", opts.OutputPath)
	if opts.OpenAfter {
		if err := openInBrowser(opts.OutputPath); err != nil {
			fmt.Fprintf(opts.Stderr, "! could not open report automatically (%v); open it manually: %s\n", err, opts.OutputPath)
		}
	}
	return opts.OutputPath, nil
}

// waitForJuiceShop polls juice-shop's application-version endpoint
// until it returns 200 OK or the timeout expires.
func waitForJuiceShop(ctx context.Context, port int, timeout, interval time.Duration) error {
	url := "http://localhost:" + strconv.Itoa(port) + "/rest/admin/application-version"
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return fmt.Errorf("%w (after %s)", ErrJuiceShopNotReady, timeout)
}

// openInBrowser launches the OS default browser pointed at path.
// Best-effort; failure is reported to the caller for fall-through
// messaging.
func openInBrowser(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		return fmt.Errorf("don't know how to open a browser on %s", runtime.GOOS)
	}
	return cmd.Start()
}
