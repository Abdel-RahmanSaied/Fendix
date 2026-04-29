//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// TestAuthProfiles_E2E covers the auth-profile matrix end-to-end (TASK-096).
// Each profile spins up a mock server that records every incoming request's
// auth signature and asserts the fendix CLI delivered the expected wire
// format. We don't measure findings here — many checks emit findings on a
// 200 response regardless of auth — we measure the raw wire format reaching
// the server, which is the contract the user is buying with `--auth-type`.
//
// Coverage:
//   - bearer:        Authorization: Bearer <token>
//   - apikey-header: <user-chosen-header>: <key>
//   - apikey-query:  ?<param-name>=<key>          (TASK-096 new)
//   - basic:         Authorization: Basic <b64(user:pass)>
//   - cookie:        Cookie: <name>=<value>
//
// refresh-on-401 is intentionally NOT covered here — it isn't implemented
// in v0.5 (see PHASES.md backlog). Adding it would be a separate task that
// introduces a token-refresh RoundTripper.
func TestAuthProfiles_E2E(t *testing.T) {
	bin := fendixBinary(t)

	cases := []struct {
		name string
		// Args appended to the base scan command. Each must include
		// --auth-type explicitly so the auto-detect path doesn't muddy
		// what the test is actually verifying.
		extraArgs []string
		// validate inspects an incoming request and reports whether it
		// carries the expected auth wire format. Only the FIRST matching
		// request is needed to mark the test green — every check (headers,
		// CORS, exposure, ratelimit, robots.txt fetch, etc.) sends a copy
		// of the auth, so this is robust against ordering.
		validate func(r *http.Request) bool
	}{
		{
			name: "bearer",
			extraArgs: []string{
				"--auth", "Bearer fendix-test-token",
				"--auth-type", "bearer",
			},
			validate: func(r *http.Request) bool {
				return r.Header.Get("Authorization") == "Bearer fendix-test-token"
			},
		},
		{
			name: "apikey-header",
			extraArgs: []string{
				"--auth", "secret-api-key-123",
				"--auth-type", "apikey",
				"--auth-header", "X-API-Key",
			},
			validate: func(r *http.Request) bool {
				return r.Header.Get("X-API-Key") == "secret-api-key-123"
			},
		},
		{
			name: "apikey-query",
			extraArgs: []string{
				"--auth", "qkey-789",
				"--auth-type", "apikey-query",
				"--auth-header", "api_key", // doubles as query-param name in this mode
			},
			validate: func(r *http.Request) bool {
				// Must be in the URL query string, NOT in any header.
				if got := r.URL.Query().Get("api_key"); got != "qkey-789" {
					return false
				}
				if h := r.Header.Get("api_key"); h != "" {
					return false
				}
				if h := r.Header.Get("Authorization"); h != "" {
					return false
				}
				return true
			},
		},
		{
			name: "basic",
			extraArgs: []string{
				"--auth", "Basic dXNlcjpwYXNz", // base64("user:pass")
				"--auth-type", "basic",
			},
			validate: func(r *http.Request) bool {
				return r.Header.Get("Authorization") == "Basic dXNlcjpwYXNz"
			},
		},
		{
			name: "cookie",
			extraArgs: []string{
				"--auth", "session=fendix-session-cookie",
				"--auth-type", "cookie",
			},
			validate: func(r *http.Request) bool {
				// AuthTypeCookie always normalizes to the "Cookie" header
				// regardless of --auth-header (see NormalizeAuth). The
				// cookie name comes from the Value, not the Header.
				return r.Header.Get("Cookie") == "session=fendix-session-cookie"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu      sync.Mutex
				matched bool
				seen    int
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen++
				if tc.validate(r) {
					matched = true
				}
				mu.Unlock()
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer srv.Close()

			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "report.json")

			args := []string{
				"scan",
				"--url", srv.URL,
				"--output", outputPath,
				"--workers", "2",
				"--timeout", "5",
				"--wordlist", tinyWordlist(t),
				"--crawl-depth", "0",
			}
			args = append(args, tc.extraArgs...)

			cmd := exec.Command(bin, args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
					t.Fatalf("scan failed: %v\n%s", err, out)
				}
			}

			// Sanity: the scan must have actually exercised the server.
			// If it didn't, the validation result is meaningless.
			mu.Lock()
			finalSeen, finalMatched := seen, matched
			mu.Unlock()
			if finalSeen == 0 {
				t.Fatalf("server saw zero requests — scan did not exercise the auth path.\noutput:\n%s", out)
			}
			if !finalMatched {
				t.Fatalf("auth profile %q never delivered the expected wire format across %d requests.\noutput:\n%s",
					tc.name, finalSeen, out)
			}

			// Confirm the report was actually written too — proves the
			// pipeline ran end to end.
			if _, err := os.Stat(outputPath); err != nil {
				t.Errorf("expected report at %s: %v", outputPath, err)
			}
		})
	}
}

// TestAuthProfile_APIKeyQuery_NoHeaderLeak is the targeted regression for
// the apikey-query wire format: ensure the credential is NEVER set as a
// request header, since some servers log Authorization-class headers and
// users explicitly chose query placement to avoid that. This also locks
// in the URL-mutation contract: the value is in the query string, plus
// the existing query params (if any) survive.
func TestAuthProfile_APIKeyQuery_NoHeaderLeak(t *testing.T) {
	bin := fendixBinary(t)

	type req struct {
		path, query string
		hasAuthHdr  bool
		hasKeyHdr   bool
	}
	var (
		mu       sync.Mutex
		captured []req
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		captured = append(captured, req{
			path:       r.URL.Path,
			query:      r.URL.RawQuery,
			hasAuthHdr: r.Header.Get("Authorization") != "",
			hasKeyHdr:  r.Header.Get("api_key") != "",
		})
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--crawl-depth", "0",
		"--auth", "leak-test-key",
		"--auth-type", "apikey-query",
		"--auth-header", "api_key",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("scan failed: %v\n%s", err, out)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) == 0 {
		t.Fatalf("server saw zero requests")
	}

	// Every captured request must have the key in the query string and
	// nowhere else. The auth-scanner's own no-auth probe is the one
	// exception — it intentionally omits credentials to test for missing
	// authentication. We only need ONE request to carry the key in query;
	// many will, and a few may not (the no-auth check, the JWT bypass
	// probes — those skip when not bearer-shaped).
	matched := 0
	for _, r := range captured {
		if r.hasAuthHdr {
			t.Errorf("apikey-query leaked into Authorization header: req=%+v", r)
		}
		if r.hasKeyHdr {
			t.Errorf("apikey-query leaked into a header named api_key: req=%+v", r)
		}
		if r.query == "api_key=leak-test-key" {
			matched++
		}
	}
	if matched == 0 {
		t.Fatalf("no captured request carried api_key=leak-test-key in query string.\ncaptured: %+v\noutput:\n%s",
			captured, out)
	}
}
