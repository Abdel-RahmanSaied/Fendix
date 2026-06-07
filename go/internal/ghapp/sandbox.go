package ghapp

import (
	"context"
	"log/slog"
	"os/exec"
)

// Sandbox decides how the `fendix scan` of untrusted fork-PR code is
// launched. Fork PRs run code we don't trust — a malicious PR could
// embed a build/scan-time payload that tries to read the installation
// token from the environment or exfiltrate it over the network. The
// Sandbox is the choke point where we (a) confirm the installation
// token is NOT in the child's environment and (b), where the host
// supports it, drop network access and privileges before the scan
// process is exec'd.
//
// The abstraction exists so the isolation choice is explicit and
// testable: a no-op default that still hardens the env, and an
// OS-specific implementation that layers on kernel primitives when
// they're available. Isolation is always best-effort — we never
// hard-break local scanning when primitives are absent (a developer
// running tests on macOS, an unprivileged container without
// CAP_SYS_ADMIN). When isolation can't be applied we log it clearly
// and continue with the token-dropped environment, which is the
// minimum guarantee on every platform.
type Sandbox interface {
	// Command builds the *exec.Cmd that will run the scan. Implementations
	// MUST return a command whose Env does not contain the installation
	// token (callers pass a pre-sanitised env via baseEnv) and SHOULD
	// apply OS-level isolation (network + privilege drop) when the host
	// supports it. name/args are the scan binary and its arguments.
	//
	// baseEnv is the environment to run the child with; it has already
	// had the installation token stripped by the caller. Implementations
	// may append isolation-specific entries but must not re-introduce
	// secrets.
	Command(ctx context.Context, logger *slog.Logger, name string, args, baseEnv []string) *exec.Cmd

	// Isolation returns a short, stable description of the isolation
	// actually applied (e.g. "none", "linux/unshare-net+no-new-privs").
	// Used for logging and tests so the choice is observable.
	Isolation() string
}

// bestEffortSandbox is the default, portable Sandbox. It performs no
// OS-level isolation beyond what the caller already did (dropping the
// token from the environment). It is the fallback on every platform
// where a stronger Sandbox isn't available, and the only Sandbox on
// non-Linux hosts.
type bestEffortSandbox struct{}

func (bestEffortSandbox) Command(ctx context.Context, _ *slog.Logger, name string, args, baseEnv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = baseEnv
	return cmd
}

func (bestEffortSandbox) Isolation() string { return "none" }

// NewSandbox returns the strongest Sandbox available on the current
// host. On Linux it returns an implementation that drops network and
// privileges when the kernel primitives are present (see
// sandbox_linux.go); everywhere else (and on Linux without the
// primitives) it returns the best-effort sandbox. The selection is
// made at construction time via the platform-specific newOSSandbox.
func NewSandbox(logger *slog.Logger) Sandbox {
	if logger == nil {
		logger = slog.Default()
	}
	return newOSSandbox(logger)
}
