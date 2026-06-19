// Package netguard provides an SSRF-filtering http transport and dialer.
//
// The scanner makes outbound HTTP requests to operator-supplied targets
// (--url, OpenAPI server URLs, sitemap/robots <loc> entries, links scraped
// from crawled HTML). Any of those can resolve — or be redirected — to an
// address that reaches the host's own loopback interface, the RFC1918
// network the scanner runs in, or the cloud metadata endpoint
// (169.254.169.254). Left unguarded that is a classic SSRF: a hostile target
// could make the scanner exfiltrate IAM credentials or pivot into the
// internal network it is being run from.
//
// The guard validates the *actual dialed IP* after DNS resolution (not just
// the hostname) so DNS-rebinding — a hostname that resolves to a public IP
// on the first lookup and a private IP on the connect — is also refused.
//
// Scanning your own internal/staging/localhost target is a legitimate and
// common use, so the guard is opt-out: AllowPrivate makes DialContext a plain
// passthrough. The scan command wires AllowPrivate from the
// --allow-private-targets flag and from an auto-allow heuristic (a --url that
// itself resolves to a private/loopback IP — see TargetIsPrivate).
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// metadataIP is the cloud instance metadata service address (AWS/GCP/Azure
// all share 169.254.169.254). It falls inside the link-local 169.254.0.0/16
// range that IsBlockedAddr already refuses, but we keep an explicit constant
// and check so the intent is obvious in error messages and so a future change
// to the link-local handling can't silently re-expose it.
var metadataIP = netip.MustParseAddr("169.254.169.254")

// uniqueLocalPrefix is IPv6 unique-local fc00::/7. Go's net.IP.IsPrivate
// covers this, but we check the prefix explicitly so the guard stays correct
// even if the stdlib definition of IsPrivate ever narrows.
var uniqueLocalPrefix = netip.MustParsePrefix("fc00::/7")

// IsBlockedAddr reports whether dialing addr would reach an address the SSRF
// guard refuses. The blocked set is:
//
//   - loopback                127.0.0.0/8, ::1
//   - link-local unicast      169.254.0.0/16, fe80::/10 (incl. metadata IP)
//   - link-local multicast    224.0.0.0/24 et al.
//   - unique-local IPv6       fc00::/7
//   - RFC1918 private         10/8, 172.16/12, 192.168/16
//   - unspecified             0.0.0.0, ::
//   - any multicast           224.0.0.0/4, ff00::/8
//
// It deliberately maps IPv4-in-IPv6 (::ffff:a.b.c.d) down to the v4 form
// first so a private v4 address can't slip through wrapped as v6.
func IsBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		// An unparseable / zero address is never safe to dial.
		return true
	}
	// Normalise IPv4-mapped IPv6 to plain IPv4 so the v4 predicates below
	// (private ranges etc.) apply to addresses like ::ffff:10.0.0.1.
	addr = addr.Unmap()

	if addr == metadataIP {
		return true
	}
	if addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		addr.IsPrivate() { // 10/8, 172.16/12, 192.168/16 + fc00::/7 v6 ULA
		return true
	}
	// netip.Addr.IsPrivate already includes fc00::/7, but check the prefix
	// explicitly as defence-in-depth in case the stdlib definition narrows.
	if uniqueLocalPrefix.Contains(addr) {
		return true
	}
	return false
}

// Config configures the guard. The zero value (AllowPrivate=false) is the
// safe default: private/loopback/metadata addresses are refused.
type Config struct {
	// AllowPrivate disables the guard entirely when true — DialContext and
	// CheckRedirect become passthroughs (the hop cap still applies). Set when
	// the operator is deliberately scanning an internal/staging/localhost
	// target.
	AllowPrivate bool
}

// blockedError is returned when the guard refuses a connection. It carries the
// host and the resolved IP so log lines and test assertions can see both.
type blockedError struct {
	host string
	ip   netip.Addr
}

func (e *blockedError) Error() string {
	return fmt.Sprintf("netguard: refusing connection to %s (%s): private/loopback/metadata address blocked (SSRF guard); pass --allow-private-targets to scan internal hosts", e.host, e.ip)
}

// DialContext returns a net.Dialer-backed DialContext that, after the host
// portion of address is resolved, refuses connections whose dialed IP is in
// the blocked set. When cfg.AllowPrivate is true it returns the underlying
// dialer's DialContext unchanged (a plain passthrough).
//
// The validation happens at connect time on the concrete IP the OS would
// dial, which is what makes it resistant to DNS rebinding: even if a prior
// hostname lookup returned a public IP, the address actually handed to the
// kernel is re-checked here.
func (cfg Config) DialContext(d *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	base := d.DialContext
	if cfg.AllowPrivate {
		return base
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		// If the host is already an IP literal, validate it directly — no
		// lookup, no rebinding window.
		if ip, perr := netip.ParseAddr(host); perr == nil {
			if IsBlockedAddr(ip) {
				return nil, &blockedError{host: host, ip: ip.Unmap()}
			}
			return base(ctx, network, address)
		}

		// Resolve the host and reject if ANY candidate IP is blocked, then
		// dial only the vetted IPs. Pinning to a cleared IP (rather than
		// letting the stdlib dialer re-resolve) closes the DNS-rebinding
		// window where a second lookup could return a private record.
		resolver := d.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsBlockedAddr(ip) {
				return nil, &blockedError{host: host, ip: ip.Unmap()}
			}
		}
		var dialErr error
		for _, ip := range ips {
			conn, derr := base(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			dialErr = derr
		}
		return nil, dialErr
	}
}

// Transport returns an *http.Transport that clones tmpl (or
// http.DefaultTransport when tmpl is nil) and installs the guard's
// DialContext. Other tmpl fields (MaxIdleConnsPerHost, timeouts, …) are
// preserved so callers can compose the guard onto a customised transport —
// e.g. the crawler's keep-alive transport.
func (cfg Config) Transport(tmpl *http.Transport) *http.Transport {
	if tmpl == nil {
		tmpl = http.DefaultTransport.(*http.Transport)
	}
	t := tmpl.Clone()
	// The dialer mirrors http.DefaultTransport's dialer so a nil tmpl behaves
	// like http.DefaultTransport with the guard bolted on.
	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	t.DialContext = cfg.DialContext(d)
	// Installing a custom DialContext disables the stdlib's automatic HTTP/2
	// upgrade (Go only auto-wires h2 when DialContext and DialTLSContext are
	// both nil). Without this, a guarded client speaks only HTTP/1.x, so an
	// h2-preferring gateway (Kong, most modern reverse proxies) negotiates h2
	// over ALPN and the h1 reader chokes on the first h2 frame:
	//   "malformed HTTP response \x00\x00\x12\x04..." (an h2 SETTINGS frame).
	// That broke --spec fetches from a Kong gateway entirely. Re-advertise both
	// protocols so ALPN picks h2 when offered and falls back to h1 otherwise.
	// Go 1.25's Transport.Protocols enables h2 over the custom dialer with no
	// golang.org/x/net/http2 dependency.
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	t.Protocols = protos
	return t
}

// MaxRedirects caps how many redirect hops a guarded client follows. Matches
// the Go stdlib default; named here so CheckRedirect and tests share it.
const MaxRedirects = 10

// CheckRedirect returns a function suitable for http.Client.CheckRedirect. It
// caps redirect hops at MaxRedirects and re-applies the IP policy to each new
// hop's host so a target can't 302 the scanner into a private address even if
// the original host was public. When AllowPrivate is true it only enforces the
// hop cap.
func (cfg Config) CheckRedirect() func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("netguard: stopped after %d redirects", MaxRedirects)
		}
		if cfg.AllowPrivate {
			return nil
		}
		host := req.URL.Hostname()
		// If the redirect target is an IP literal we can validate it without a
		// lookup; otherwise resolve and reject on any blocked candidate. The
		// dialer re-validates on connect too, but checking here gives a clear
		// error and avoids even opening the connection.
		if ip, err := netip.ParseAddr(host); err == nil {
			if IsBlockedAddr(ip) {
				return &blockedError{host: host, ip: ip.Unmap()}
			}
			return nil
		}
		ips, err := net.DefaultResolver.LookupNetIP(req.Context(), "ip", host)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if IsBlockedAddr(ip) {
				return &blockedError{host: host, ip: ip.Unmap()}
			}
		}
		return nil
	}
}

// TargetIsPrivate reports whether rawURL's host resolves to (or is) a blocked
// address. The scan command uses it to auto-allow private scanning when the
// operator's own --url target points at an internal/staging/localhost host —
// so scanning your own target keeps working without --allow-private-targets.
//
// A parse failure or empty host returns false (no auto-allow); the guard then
// applies its normal policy. A resolution failure also returns false — we
// can't prove the target is private, so we don't relax the guard.
func TargetIsPrivate(rawURL string) bool {
	host := hostOf(rawURL)
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return IsBlockedAddr(ip)
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if IsBlockedAddr(ip) {
			return true
		}
	}
	return false
}

// hostOf extracts the bare hostname (no port) from a URL. Returns "" when the
// URL has no host or can't be parsed.
func hostOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
