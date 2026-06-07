//go:build !linux

package ghapp

import "log/slog"

// newOSSandbox returns the best-effort sandbox on non-Linux hosts. The
// kernel primitives the Linux sandbox relies on (unshare, no-new-privs)
// have no portable equivalent here, so the only guarantee is the
// token-dropped environment the caller already established.
func newOSSandbox(logger *slog.Logger) Sandbox {
	logger.Info("scan sandbox: OS isolation unavailable on this platform; "+
		"running with token-dropped environment only",
		"isolation", "none")
	return bestEffortSandbox{}
}
