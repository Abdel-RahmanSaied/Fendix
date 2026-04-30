package ghapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// genTestKey produces a small RSA key for tests. 2048-bit so it's fast
// to generate but still RS256-signature-compatible.
func genTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func keyToPKCS1PEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func keyToPKCS8PEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestLoadAppCredentials_PKCS1(t *testing.T) {
	k := genTestKey(t)
	creds, err := LoadAppCredentials(12345, keyToPKCS1PEM(t, k))
	if err != nil {
		t.Fatalf("LoadAppCredentials PKCS1: %v", err)
	}
	if creds.AppID != 12345 {
		t.Errorf("appID mismatch: %d", creds.AppID)
	}
	if creds.PrivateKey.N.Cmp(k.N) != 0 {
		t.Errorf("private key not round-tripped")
	}
}

func TestLoadAppCredentials_PKCS8(t *testing.T) {
	k := genTestKey(t)
	creds, err := LoadAppCredentials(99, keyToPKCS8PEM(t, k))
	if err != nil {
		t.Fatalf("LoadAppCredentials PKCS8: %v", err)
	}
	if creds.PrivateKey.N.Cmp(k.N) != 0 {
		t.Errorf("private key not round-tripped from PKCS8")
	}
}

func TestLoadAppCredentials_NotPEM(t *testing.T) {
	_, err := LoadAppCredentials(1, []byte("not a pem"))
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey on garbage input, got %v", err)
	}
}

func TestLoadAppCredentials_UnknownPEMType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "FOO KEY", Bytes: []byte{0x00}})
	_, err := LoadAppCredentials(1, pemBytes)
	if err == nil {
		t.Fatalf("expected error on unknown PEM type")
	}
}

// verifyJWT parses a compact JWT, asserts header alg=RS256, decodes
// claims, and verifies the signature against the key's public half.
// Returns the decoded claims.
func verifyJWT(t *testing.T, jwt string, pubKey *rsa.PublicKey) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %q", header.Alg)
	}
	if header.Typ != "JWT" {
		t.Errorf("expected typ=JWT, got %q", header.Typ)
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	hashed := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig); err != nil {
		t.Fatalf("RS256 sig verify failed: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	return claims
}

func TestSignAppJWT_StructureAndSignature(t *testing.T) {
	k := genTestKey(t)
	creds := &AppCredentials{AppID: 7777, PrivateKey: k}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	jwt, err := SignAppJWT(creds, now)
	if err != nil {
		t.Fatalf("SignAppJWT: %v", err)
	}

	claims := verifyJWT(t, jwt, &k.PublicKey)

	// iss must be the AppID as a number.
	if got, _ := claims["iss"].(float64); int64(got) != 7777 {
		t.Errorf("iss claim mismatch: %v", claims["iss"])
	}
	// iat is in the past by ~AppJWTLeeway.
	iat, _ := claims["iat"].(float64)
	expectedIAT := now.Add(-AppJWTLeeway).Unix()
	if int64(iat) != expectedIAT {
		t.Errorf("iat mismatch: got %d want %d", int64(iat), expectedIAT)
	}
	// exp is now+AppJWTLifetime.
	exp, _ := claims["exp"].(float64)
	expectedEXP := now.Add(AppJWTLifetime).Unix()
	if int64(exp) != expectedEXP {
		t.Errorf("exp mismatch: got %d want %d", int64(exp), expectedEXP)
	}
}

func TestSignAppJWT_NilCreds(t *testing.T) {
	if _, err := SignAppJWT(nil, time.Now()); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey on nil creds, got %v", err)
	}
}

func TestSignAppJWT_NilKey(t *testing.T) {
	if _, err := SignAppJWT(&AppCredentials{AppID: 1, PrivateKey: nil}, time.Now()); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey on nil key, got %v", err)
	}
}

func TestInstallationToken_IsExpired(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		tok  *InstallationToken
		want bool
	}{
		{"nil token", nil, true},
		{"already expired", &InstallationToken{ExpiresAt: now.Add(-time.Hour)}, true},
		{"30s left — within refresh window", &InstallationToken{ExpiresAt: now.Add(20 * time.Second)}, true},
		{"5min left — fresh", &InstallationToken{ExpiresAt: now.Add(5 * time.Minute)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tok.IsExpired(now); got != tc.want {
				t.Errorf("IsExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

// fakeGitHub returns a 201 with a fixed installation token. Used to test
// FetchInstallationToken and TokenSource without hitting api.github.com.
func fakeGitHub(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		// Echo the path so tests can assert the right installation ID
		// was requested.
		expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"token":"ghs_fake_token_%s","expires_at":%q}`, r.URL.Path, expiry)
	}))
}

func TestFetchInstallationToken_Success(t *testing.T) {
	srv := fakeGitHub(t, nil)
	defer srv.Close()

	tok, err := FetchInstallationToken(context.Background(), srv.Client(), srv.URL, "fake.jwt", 999)
	if err != nil {
		t.Fatalf("FetchInstallationToken: %v", err)
	}
	if !strings.HasPrefix(tok.Token, "ghs_fake_token_") {
		t.Errorf("unexpected token: %q", tok.Token)
	}
	if tok.ExpiresAt.IsZero() {
		t.Errorf("expires_at not parsed")
	}
}

func TestFetchInstallationToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := FetchInstallationToken(context.Background(), srv.Client(), srv.URL, "fake.jwt", 1)
	if !errors.Is(err, ErrInstallationTokenFailed) {
		t.Fatalf("expected ErrInstallationTokenFailed, got %v", err)
	}
}

func TestTokenSource_SingleFlight(t *testing.T) {
	// 50 concurrent Get calls for the same installation should produce
	// exactly one network refresh, not 50.
	var hits atomic.Int32
	srv := fakeGitHub(t, &hits)
	defer srv.Close()

	k := genTestKey(t)
	creds := &AppCredentials{AppID: 1, PrivateKey: k}
	ts := NewTokenSource(creds, srv.Client(), srv.URL)

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	results := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, err := ts.Get(context.Background(), 42)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("expected single network refresh, got %d", got)
	}
}

func TestTokenSource_CacheReuse(t *testing.T) {
	// Sequential Get calls within the cache lifetime should reuse the
	// same token (no new network refresh).
	var hits atomic.Int32
	srv := fakeGitHub(t, &hits)
	defer srv.Close()

	k := genTestKey(t)
	creds := &AppCredentials{AppID: 1, PrivateKey: k}
	ts := NewTokenSource(creds, srv.Client(), srv.URL)

	for i := 0; i < 5; i++ {
		if _, err := ts.Get(context.Background(), 42); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("expected 1 network refresh across 5 cached calls, got %d", got)
	}
}

func TestTokenSource_DifferentInstallationsAreIndependent(t *testing.T) {
	// Tokens for different installation IDs are cached independently —
	// asking for installation A should not return installation B's
	// token.
	var hits atomic.Int32
	srv := fakeGitHub(t, &hits)
	defer srv.Close()
	k := genTestKey(t)
	ts := NewTokenSource(&AppCredentials{AppID: 1, PrivateKey: k}, srv.Client(), srv.URL)

	tokA, err := ts.Get(context.Background(), 100)
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	tokB, err := ts.Get(context.Background(), 200)
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if tokA.Token == tokB.Token {
		t.Errorf("different installations should produce different tokens")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("expected 2 refreshes (one per installation), got %d", got)
	}
}
