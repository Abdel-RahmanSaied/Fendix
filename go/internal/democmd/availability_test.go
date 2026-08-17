package democmd

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests are the regression gate for the incomplete dependency-injection
// seam: Run performed `exec.LookPath("docker")` inline, BEFORE dispatching
// through the injectable opts.docker. Injecting a fake therefore isolated the
// test from docker EXECUTION but not from docker DETECTION, so the suite passed
// on a CI runner with Docker installed and failed on a developer machine
// without it — a host-dependent test, which is the thing DI exists to prevent.

// TestRunUsesInjectedRuntimeOnDockerlessHost is the headline gate: with a fake
// runtime, Run must never consult the host, so the outcome is identical whether
// or not docker is installed on the machine running `go test`.
//
// The host-independence claim is ASSERTED, not merely logged: the test forces
// PATH to a directory containing no docker binary for its duration. On the old
// code — an inline exec.LookPath("docker") ahead of the seam — that alone makes
// this test fail, which is precisely the host coupling being fixed. (Setting
// PATH means this test must not run in parallel with others in the package;
// none of them call t.Parallel.)
func TestRunUsesInjectedRuntimeOnDockerlessHost(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no docker reachable from here
	if _, err := exec.LookPath("docker"); err == nil {
		t.Fatal("test setup failed: docker is still resolvable after emptying PATH")
	}

	port, _, _ := startFakeJuiceShop(t, 0)
	docker := &fakeDocker{} // Available() → nil, without touching PATH
	out := filepath.Join(t.TempDir(), "demo.html")

	var stdout, stderr bytes.Buffer
	report, err := Run(context.Background(), Options{
		Port:           port,
		FendixBin:      fakeFendixBinary(t),
		OutputPath:     out,
		HealthTimeout:  3 * time.Second,
		HealthInterval: 50 * time.Millisecond,
		Stdout:         &stdout,
		Stderr:         &stderr,
		docker:         docker,
	})
	if err != nil {
		t.Fatalf("Run with an injected runtime failed: %v\nstderr: %s", err, stderr.String())
	}
	if report != out {
		t.Errorf("report path = %q, want %q", report, out)
	}
	// The injected runtime — not the (empty) host PATH — is what ran.
	if len(docker.callArgs()) == 0 {
		t.Error("the injected docker runtime was never invoked")
	}
}

// TestRunReportsDockerUnavailable covers the failure path through the seam: an
// unavailable runtime aborts before any docker command is attempted, and the
// user-facing error is the actionable install hint.
func TestRunReportsDockerUnavailable(t *testing.T) {
	docker := &fakeDocker{
		unavailable: errors.New("docker not found on PATH: install Docker Desktop, OrbStack, or Colima and try again"),
	}

	var stdout, stderr bytes.Buffer
	_, err := Run(context.Background(), Options{
		Port:      65500,
		FendixBin: fakeFendixBinary(t),
		Stdout:    &stdout,
		Stderr:    &stderr,
		docker:    docker,
	})
	if err == nil {
		t.Fatal("expected an error when the docker runtime is unavailable")
	}
	if !strings.Contains(err.Error(), "docker not found on PATH") {
		t.Errorf("error = %q, want it to name the missing docker binary", err)
	}
	if !strings.Contains(err.Error(), "Docker Desktop") {
		t.Errorf("error = %q, want the actionable install hint", err)
	}
	// Nothing may be attempted once availability fails — in particular the
	// leftover-container cleanup, which would otherwise shell out to docker.
	if calls := docker.callArgs(); len(calls) != 0 {
		t.Errorf("expected no docker calls after an availability failure, got %v", calls)
	}
}

// TestRunPropagatesErrDockerMissingSentinel keeps the sentinel usable by
// callers that branch on it (the cobra command maps it to an exit hint).
func TestRunPropagatesErrDockerMissingSentinel(t *testing.T) {
	docker := &fakeDocker{unavailable: ErrDockerMissing}

	_, err := Run(context.Background(), Options{
		Port:      65501,
		FendixBin: fakeFendixBinary(t),
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
		docker:    docker,
	})
	if !errors.Is(err, ErrDockerMissing) {
		t.Errorf("errors.Is(err, ErrDockerMissing) = false; got %v", err)
	}
}

// TestRealDockerAvailableMatchesTheHost pins production behaviour: realDocker
// still performs the genuine exec.LookPath probe that Run used to do inline.
// The assertion adapts to the host rather than requiring docker, so it is
// meaningful on a CI runner AND on a docker-less laptop.
func TestRealDockerAvailableMatchesTheHost(t *testing.T) {
	_, lookErr := exec.LookPath("docker")
	err := realDocker{}.Available()

	if lookErr == nil {
		if err != nil {
			t.Errorf("docker IS on PATH but realDocker.Available() returned %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("docker is NOT on PATH but realDocker.Available() returned nil")
	}
	if !errors.Is(err, ErrDockerMissing) {
		t.Errorf("realDocker.Available() = %v, want it to wrap ErrDockerMissing", err)
	}
	if !strings.Contains(err.Error(), "Docker Desktop") {
		t.Errorf("realDocker.Available() = %v, want the actionable install hint", err)
	}
}

// TestResolveDefaultsToRealDocker guards the wiring: an Options with no
// injected runtime must still get the real one, so production is unchanged.
func TestResolveDefaultsToRealDocker(t *testing.T) {
	resolved := Options{}.resolve()
	if _, ok := resolved.docker.(realDocker); !ok {
		t.Fatalf("resolve() did not default docker to realDocker, got %T", resolved.docker)
	}
}
