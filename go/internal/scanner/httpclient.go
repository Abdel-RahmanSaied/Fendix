package scanner

import (
	"net/http"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/netguard"
)

// allowPrivate returns the effective SSRF-guard policy for a scan: the guard
// is relaxed when the operator opted in with --allow-private-targets
// (cfg.AllowPrivate) OR when the primary --url target itself resolves to a
// private/loopback address. The latter is the auto-allow rule — scanning your
// own internal/staging/localhost target must keep working without an extra
// flag. cfg.URL is the operator's declared target; per-endpoint FullURLs are
// derived from it during discovery, so keying the heuristic off cfg.URL is
// sufficient and avoids per-request DNS lookups.
func allowPrivate(cfg *models.ScanConfig) bool {
	if cfg == nil {
		return false
	}
	if cfg.AllowPrivate {
		return true
	}
	return netguard.TargetIsPrivate(cfg.URL)
}

// guardedClient builds an *http.Client whose transport composes the budget
// counter over the SSRF egress guard, and whose CheckRedirect caps redirect
// hops and re-applies the IP policy on every hop. Every black-box check that
// makes outbound requests builds its client through here so SSRF protection
// (and the auto-allow heuristic) is applied uniformly.
func guardedClient(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	timeout := 0
	if cfg != nil {
		timeout = cfg.Timeout
	}
	return &http.Client{
		Timeout:       time.Duration(timeout) * time.Second,
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: netguard.Config{AllowPrivate: ap}.CheckRedirect(),
	}
}

// guardedClientNoFollow builds a client with the SAME guarded transport as
// guardedClient (budget over netguard SSRF policy) but does NOT follow
// redirects — it returns http.ErrUseLastResponse so the caller observes the
// raw 3xx. Used by checks where a redirect IS the signal (auth, idor,
// open-redirect, host-header). Timeout is 0 because the shared client relies
// on a per-job context deadline (see runCheck).
func guardedClientNoFollow(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	return &http.Client{
		Timeout:       0,
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}
