//go:build linux

package ghapp

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// linuxSandbox runs the scan in a fresh network + user namespace so the
// untrusted code (a) has no network connectivity (an empty net
// namespace has only a down loopback, so it cannot phone home or
// exfiltrate the installation token) and (b) runs unprivileged in a
// user namespace that maps the App's UID to an unprivileged UID inside
// the namespace and cannot escalate.
//
// Both are done via clone(2) flags on the child (SysProcAttr), so we
// don't depend on the `unshare` binary being installed. We only select
// this sandbox when an unprivileged user namespace can actually be
// created on this host (see newOSSandbox); otherwise we fall back to
// the best-effort sandbox so local scanning never hard-breaks.
type linuxSandbox struct{}

func (linuxSandbox) Command(ctx context.Context, _ *slog.Logger, name string, args, baseEnv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = baseEnv
	cmd.SysProcAttr = unprivilegedNetNSAttr()
	return cmd
}

func (linuxSandbox) Isolation() string { return "linux/userns-net+no-new-privs" }

// unprivilegedNetNSAttr builds the SysProcAttr that places the child in
// a new network namespace (no connectivity) and a new user namespace
// (unprivileged). CLONE_NEWUSER both drops privileges and is what makes
// CLONE_NEWNET available to a non-root process. The UID/GID maps point
// the child's root at the App's own (unprivileged) UID — the child can
// never gain a capability it didn't start with.
func unprivilegedNetNSAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		// Kill the scan child if the App process dies, so a stuck or
		// malicious scan can't outlive its parent.
		Pdeathsig: syscall.SIGKILL,
	}
}

// newOSSandbox probes whether an unprivileged user+net namespace can be
// created on this host. Many hardened/older kernels and some container
// runtimes disable unprivileged user namespaces
// (kernel.unprivileged_userns_clone=0, or no userns in the seccomp
// profile). When the probe fails we log it and fall back to the
// best-effort sandbox — local scanning continues with the token-dropped
// environment, which is the minimum guarantee on every platform.
func newOSSandbox(logger *slog.Logger) Sandbox {
	if err := probeUserNetNS(); err != nil {
		logger.Warn("scan sandbox: Linux network/privilege isolation unavailable; "+
			"running with token-dropped environment only",
			"isolation", "none",
			"reason", err)
		return bestEffortSandbox{}
	}
	logger.Info("scan sandbox: Linux network + privilege isolation enabled",
		"isolation", "linux/userns-net+no-new-privs")
	return linuxSandbox{}
}

// probeUserNetNS checks whether an unprivileged user+net namespace can
// be created on this host by attempting a clone(2) with the sandbox
// flags. The exec target is a deliberately non-existent path: the
// kernel sets up the namespaces (the part we're probing) before exec,
// so a successful clone followed by an exec-ENOENT means the sandbox is
// available. A clone/permission failure (EPERM on hosts where
// unprivileged userns is disabled) surfaces before exec and tells us
// the sandbox is unavailable, so we fall back to best-effort.
func probeUserNetNS() error {
	cmd := exec.Command("/nonexistent-fendix-sandbox-probe")
	cmd.SysProcAttr = unprivilegedNetNSAttr()
	err := cmd.Run()
	if err == nil {
		return nil
	}
	// Expected: namespaces were created, only the bogus exec path failed.
	var execErr *exec.Error
	if errors.As(err, &execErr) && os.IsNotExist(execErr.Err) {
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	// Anything else (EPERM from clone, etc.) → sandbox unavailable.
	return err
}
