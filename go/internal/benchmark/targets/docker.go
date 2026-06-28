package targets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
}

// start removes any stale container of the same name, then launches the
// image detached with the port mapping. The image is pinned by the caller
// for reproducibility.
func (c container) start(ctx context.Context) error {
	if !dockerAvailable() {
		return ErrDockerMissing
	}
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", c.name).Run() // best-effort cleanup of a prior run
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", c.name,
		"-p", fmt.Sprintf("%d:%d", c.hostPort, c.containerPort),
		c.image,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker run %s: %w", c.image, err)
	}
	return nil
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
