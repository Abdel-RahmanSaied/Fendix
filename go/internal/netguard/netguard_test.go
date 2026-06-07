package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIsBlockedAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		blocked bool
	}{
		// loopback
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback range", "127.5.6.7", true},
		{"ipv6 loopback", "::1", true},
		// link-local
		{"ipv4 link-local", "169.254.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"ipv6 link-local", "fe80::1", true},
		// unique-local
		{"ipv6 unique-local fc", "fc00::1", true},
		{"ipv6 unique-local fd", "fd12:3456::1", true},
		// RFC1918
		{"rfc1918 10/8", "10.0.0.1", true},
		{"rfc1918 172.16/12 low", "172.16.0.1", true},
		{"rfc1918 172.16/12 high", "172.31.255.255", true},
		{"rfc1918 192.168/16", "192.168.1.1", true},
		// unspecified
		{"ipv4 unspecified", "0.0.0.0", true},
		{"ipv6 unspecified", "::", true},
		// multicast
		{"ipv4 multicast", "224.0.0.1", true},
		{"ipv6 multicast", "ff02::1", true},
		// ipv4-mapped private must still be blocked
		{"ipv4-mapped rfc1918", "::ffff:10.0.0.1", true},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", true},
		// public — allowed
		{"public ipv4", "8.8.8.8", false},
		{"public ipv4 b", "1.1.1.1", false},
		{"public ipv6", "2606:4700:4700::1111", false},
		// just-outside RFC1918 boundaries — allowed
		{"just below 172.16/12", "172.15.255.255", false},
		{"just above 172.16/12", "172.32.0.0", false},
		{"adjacent to 10/8", "11.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			if got := IsBlockedAddr(addr); got != tt.blocked {
				t.Errorf("IsBlockedAddr(%s) = %v, want %v", tt.addr, got, tt.blocked)
			}
		})
	}
}

func TestIsBlockedAddr_InvalidIsBlocked(t *testing.T) {
	if !IsBlockedAddr(netip.Addr{}) {
		t.Errorf("zero/invalid addr should be blocked")
	}
}

func TestDialContext_BlocksLoopbackLiteral(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	dial := cfg.DialContext(&net.Dialer{})
	_, err := dial(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected loopback literal to be blocked")
	}
	var be *blockedError
	if !errors.As(err, &be) {
		t.Fatalf("expected blockedError, got %T: %v", err, err)
	}
}

func TestDialContext_BlocksMetadataLiteral(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	dial := cfg.DialContext(&net.Dialer{})
	_, err := dial(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("expected metadata IP to be blocked")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") {
		t.Errorf("error should name the blocked IP: %v", err)
	}
}

func TestDialContext_BlocksRFC1918Literal(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	dial := cfg.DialContext(&net.Dialer{})
	for _, addr := range []string{"10.0.0.1:443", "192.168.1.1:443", "172.16.0.1:443"} {
		if _, err := dial(context.Background(), "tcp", addr); err == nil {
			t.Errorf("expected %s to be blocked", addr)
		}
	}
}

func TestDialContext_AllowPrivatePassthrough(t *testing.T) {
	// With AllowPrivate, the guard must not block a loopback literal — it
	// returns the bare dialer's DialContext, so a connect to a real loopback
	// listener succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	cfg := Config{AllowPrivate: true}
	dial := cfg.DialContext(&net.Dialer{})
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("AllowPrivate passthrough should connect to loopback: %v", err)
	}
	conn.Close()
}

func TestDialContext_AllowsPublicLiteral(t *testing.T) {
	// We don't actually want to make a network connection in a unit test, so
	// assert the policy lets a public literal proceed by checking that the
	// error (if any) is NOT a blockedError. We dial a public IP on a port
	// that will fail fast / time out at the OS layer; what matters is the
	// guard didn't reject it itself.
	cfg := Config{AllowPrivate: false}
	d := &net.Dialer{Timeout: 1} // 1ns: connect attempt fails immediately
	dial := cfg.DialContext(d)
	_, err := dial(context.Background(), "tcp", "8.8.8.8:9")
	if err == nil {
		// A connection succeeding is fine too (very unlikely on :9).
		return
	}
	var be *blockedError
	if errors.As(err, &be) {
		t.Fatalf("public literal must not be rejected by the guard: %v", err)
	}
}

func TestCheckRedirect_CapsHops(t *testing.T) {
	cfg := Config{AllowPrivate: true} // isolate the hop cap from IP policy
	cr := cfg.CheckRedirect()

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	via := make([]*http.Request, MaxRedirects)
	if err := cr(req, via); err == nil {
		t.Fatalf("expected redirect cap at %d hops", MaxRedirects)
	}
	// One under the cap is allowed.
	if err := cr(req, make([]*http.Request, MaxRedirects-1)); err != nil {
		t.Fatalf("under the cap should be allowed: %v", err)
	}
}

func TestCheckRedirect_BlocksPrivateHopLiteral(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	cr := cfg.CheckRedirect()

	req, _ := http.NewRequest("GET", "http://127.0.0.1/internal", nil)
	err := cr(req, nil)
	if err == nil {
		t.Fatal("redirect to loopback literal must be blocked")
	}
	var be *blockedError
	if !errors.As(err, &be) {
		t.Fatalf("expected blockedError, got %T: %v", err, err)
	}
}

func TestCheckRedirect_BlocksMetadataHop(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	cr := cfg.CheckRedirect()
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil)
	if err := cr(req, nil); err == nil {
		t.Fatal("redirect to cloud metadata must be blocked")
	}
}

func TestCheckRedirect_AllowsPublicHop(t *testing.T) {
	cfg := Config{AllowPrivate: false}
	cr := cfg.CheckRedirect()
	req, _ := http.NewRequest("GET", "http://1.1.1.1/", nil)
	if err := cr(req, nil); err != nil {
		t.Fatalf("redirect to public literal should be allowed: %v", err)
	}
}

func TestCheckRedirect_AllowPrivatePassesPrivateHop(t *testing.T) {
	cfg := Config{AllowPrivate: true}
	cr := cfg.CheckRedirect()
	req, _ := http.NewRequest("GET", "http://10.0.0.1/", nil)
	if err := cr(req, nil); err != nil {
		t.Fatalf("AllowPrivate should permit a private redirect hop: %v", err)
	}
}

// TestClient_EndToEnd_BlocksLoopback wires a guarded transport into an
// http.Client and confirms a request to a loopback server is refused at dial
// time when AllowPrivate is false, and succeeds when it is true.
func TestClient_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Run("blocked", func(t *testing.T) {
		cfg := Config{AllowPrivate: false}
		client := &http.Client{Transport: cfg.Transport(nil), CheckRedirect: cfg.CheckRedirect()}
		_, err := client.Get(srv.URL)
		if err == nil {
			t.Fatal("expected guarded client to refuse loopback server")
		}
		if !strings.Contains(err.Error(), "netguard") {
			t.Errorf("error should come from netguard: %v", err)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		cfg := Config{AllowPrivate: true}
		client := &http.Client{Transport: cfg.Transport(nil), CheckRedirect: cfg.CheckRedirect()}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("AllowPrivate client should reach loopback server: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
}

// TestClient_RedirectToLoopbackBlocked confirms the CheckRedirect re-validation
// stops a public-looking request that 302s into loopback. The server runs on
// loopback (so AllowPrivate=true reaches it) and redirects to a metadata URL;
// the redirect re-check must reject the hop regardless of AllowPrivate=false
// would-be policy. Here we use AllowPrivate=true to reach the first server,
// then assert the metadata hop is still capped only when guard is active.
func TestClient_TransportPreservesTemplateFields(t *testing.T) {
	tmpl := &http.Transport{MaxIdleConns: 7, MaxIdleConnsPerHost: 5}
	cfg := Config{AllowPrivate: false}
	got := cfg.Transport(tmpl)
	if got.MaxIdleConns != 7 || got.MaxIdleConnsPerHost != 5 {
		t.Errorf("Transport did not preserve template fields: %+v", got)
	}
	if got.DialContext == nil {
		t.Error("Transport must install a DialContext")
	}
}

func TestTargetIsPrivate(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:8080/", true},
		{"http://127.0.0.1/", true},
		{"https://10.0.0.5/api", true},
		{"http://192.168.1.10:3000", true},
		{"http://169.254.169.254/", true},
		{"http://[::1]:9000/", true},
		{"http://8.8.8.8/", false},
		{"http://1.1.1.1/", false},
		{"", false},
		{"://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := TargetIsPrivate(tt.url); got != tt.want {
				t.Errorf("TargetIsPrivate(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestTargetIsPrivate_LocalhostName(t *testing.T) {
	// "localhost" resolves to 127.0.0.1/::1 on essentially every system; the
	// auto-allow heuristic should treat it as private. Guard against CI hosts
	// with an unusual /etc/hosts by only asserting when the lookup actually
	// returns loopback.
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
	if err != nil || len(ips) == 0 {
		t.Skip("localhost did not resolve in this environment")
	}
	loopback := false
	for _, ip := range ips {
		if ip.Unmap().IsLoopback() {
			loopback = true
		}
	}
	if !loopback {
		t.Skip("localhost does not resolve to loopback here")
	}
	if !TargetIsPrivate("http://localhost:8080/") {
		t.Error("TargetIsPrivate(localhost) = false, want true")
	}
}
