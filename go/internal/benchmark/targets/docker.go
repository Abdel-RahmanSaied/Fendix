package targets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ErrDockerMissing is returned by a DAST target when the docker CLI is not
// available — surfaced loudly rather than silently skipped (agent spec).
var ErrDockerMissing = errors.New("docker not found on PATH (required for DVWA/Juice Shop benchmarks)")

// dockerAvailable reports whether the docker CLI is on PATH.
func dockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// runProcess runs bin with args, forwarding stderr for diagnosis and
// honoring ctx cancellation/timeout.
func runProcess(ctx context.Context, bin string, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// container is a deliberately-vulnerable target app run in Docker for the
// duration of one benchmark.
type container struct {
	name          string
	image         string
	hostPort      int
	containerPort int
	// portEnv is the env var an operator sets to move hostPort; named in the
	// ErrHostPortInUse message so the fix is discoverable from the failure.
	portEnv string
}

// ErrHostPortInUse is returned when the port a benchmark target needs is
// already bound. Distinguished so the CLI can print the override hint instead
// of a raw Docker error.
var ErrHostPortInUse = errors.New("benchmark host port already in use")

// hostPortFree reports whether the benchmark can bind hostPort. Checked BEFORE
// `docker run` so the failure is a sentence the operator can act on rather than
// `exit status 125` wrapped around a daemon message. Port 3000 in particular is
// the single most commonly occupied port on a developer machine (every Node dev
// server defaults to it), so a benchmark suite that hard-fails on it is
// unusable exactly where it is most convenient to run.
func hostPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// start removes any stale container of the same name, then launches the
// image detached with the port mapping. The image is pinned by the caller for
// reproducibility. Fails fast with ErrHostPortInUse when the port is bound.
func (c container) start(ctx context.Context) error {
	if !dockerAvailable() {
		return ErrDockerMissing
	}
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", c.name).Run() // best-effort cleanup of a prior run

	if !hostPortFree(c.hostPort) {
		return fmt.Errorf("%w: port %d is bound by another process; free it or set %s=<port>",
			ErrHostPortInUse, c.hostPort, c.portEnv)
	}

	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", c.name,
		"-p", fmt.Sprintf("%d:%d", c.hostPort, c.containerPort),
		c.image,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// `docker run` can fail AFTER creating the container (a port-bind
		// failure does exactly this), leaving a stale `Created` container that
		// the next run has to clean up. Remove it here so a failed benchmark
		// leaves nothing behind.
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", c.name).Run()
		return fmt.Errorf("docker run %s: %w", c.image, err)
	}
	return nil
}

// portFromEnv reads an operator override for a benchmark target's host port,
// falling back to def when unset or unparseable. Env rather than a CLI flag
// because targets are constructed by targets.All() with no plumbed options,
// and it matches the FENDIX_* convention used elsewhere (FENDIX_ENGINE,
// FENDIX_METRICS).
func portFromEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return def
}

// stop force-removes the container. It is meant for `defer` and uses its
// own short timeout so teardown still runs when the parent ctx is
// cancelled.
func (c container) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", c.name).Run()
}

// waitForHTTP polls url until it returns any HTTP response or the timeout
// elapses. Any response (even 4xx/5xx) means the app is up enough to scan.
func waitForHTTP(ctx context.Context, url string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: interval}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("building health-check request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s: %w", timeout, url, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
