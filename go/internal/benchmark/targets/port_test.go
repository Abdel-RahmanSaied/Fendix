package targets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// The DAST benchmark targets hardcoded their host ports with no override, so a
// machine already using port 3000 — the default for essentially every Node dev
// server, including Juice Shop's own — could not run the suite at all. It
// failed with a raw daemon message wrapped in `exit status 125` and left a
// stale `Created` container behind. For a harness whose numbers gate releases,
// that made the most convenient place to run it the one place it didn't work.

func TestHostPortFree(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	busy := ln.Addr().(*net.TCPAddr).Port

	if hostPortFree(busy) {
		t.Errorf("hostPortFree(%d) = true while the port is bound", busy)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if !hostPortFree(busy) {
		t.Errorf("hostPortFree(%d) = false after the listener closed", busy)
	}
}

// TestStartFailsFastOnBoundPort is the regression gate: the failure must name
// the port AND the override, and must arrive before Docker is invoked.
func TestStartFailsFastOnBoundPort(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not on PATH")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port

	c := container{
		name:          "fendix-bench-porttest",
		image:         "this-image-is-never-pulled:latest",
		hostPort:      busy,
		containerPort: 3000,
		portEnv:       "FENDIX_BENCH_JUICESHOP_PORT",
	}
	err = c.start(context.Background())
	if err == nil {
		t.Fatal("expected an error when the host port is bound")
	}
	if !errors.Is(err, ErrHostPortInUse) {
		t.Errorf("errors.Is(err, ErrHostPortInUse) = false: %v", err)
	}
	for _, want := range []string{fmt.Sprint(busy), "FENDIX_BENCH_JUICESHOP_PORT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q so the fix is discoverable: %v", want, err)
		}
	}
	// The bogus image proves we never reached `docker run` — a pull attempt
	// would have produced a very different error.
	if strings.Contains(err.Error(), "docker run") {
		t.Errorf("preflight did not short-circuit; docker was invoked: %v", err)
	}
}

func TestPortFromEnv(t *testing.T) {
	const key = "FENDIX_BENCH_TEST_PORT"
	for _, tc := range []struct {
		name, val string
		want      int
	}{
		{"unset", "", 3000},
		{"override", "4100", 4100},
		{"non-numeric falls back", "abc", 3000},
		{"zero falls back", "0", 3000},
		{"out of range falls back", "70000", 3000},
		{"negative falls back", "-1", 3000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.val == "" {
				os.Unsetenv(key)
			} else {
				t.Setenv(key, tc.val)
			}
			if got := portFromEnv(key, 3000); got != tc.want {
				t.Errorf("portFromEnv(%q) = %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}

// Both DAST targets must honour their override, or the escape hatch the error
// message advertises does not exist.
func TestTargetsHonourPortOverride(t *testing.T) {
	t.Setenv("FENDIX_BENCH_JUICESHOP_PORT", "4321")
	t.Setenv("FENDIX_BENCH_DVWA_PORT", "4322")
	if got := NewJuiceShop().hostPort; got != 4321 {
		t.Errorf("juiceshop hostPort = %d, want 4321", got)
	}
	if got := NewDVWA().hostPort; got != 4322 {
		t.Errorf("dvwa hostPort = %d, want 4322", got)
	}
}
