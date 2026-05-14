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
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// AppJWTLifetime caps how long an App JWT is valid before re-signing.
// GitHub's documented maximum is 10 minutes; we use 9 minutes to avoid
// clock-skew rejections at the 10-minute boundary.
const AppJWTLifetime = 9 * time.Minute

// AppJWTLeeway dates the JWT's iat claim slightly in the past to absorb
// clock skew between the App server and GitHub. GitHub rejects JWTs
// whose iat is in the future, even by a few seconds.
const AppJWTLeeway = 60 * time.Second

// Errors from the auth layer.
var (
	ErrInvalidPrivateKey       = errors.New("private key is not a valid RSA PEM block")
	ErrInstallationTokenFailed = errors.New("installation token request failed")
)

// AppCredentials is the App-level identity. AppID is the numeric ID
// shown in the App's settings page; PrivateKey is the RSA private key
// downloaded as a .pem when the App was created. Treat the PEM as
// confidential — anyone with the key can mint JWTs that authenticate
// as this App.
type AppCredentials struct {
	AppID      int64
	PrivateKey *rsa.PrivateKey
}

// LoadAppCredentials parses an RSA private key PEM blob (typically read
// from a file or env var) and pairs it with the App's numeric ID. The
// PEM block must be a PKCS#1 RSA private key (the format GitHub hands
// out); PKCS#8 is also accepted as a defensive measure.
func LoadAppCredentials(appID int64, pemBytes []byte) (*AppCredentials, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	return &AppCredentials{AppID: appID, PrivateKey: key}, nil
}

// SignAppJWT mints an RS256-signed JSON Web Token suitable for
// authenticating as the App to GitHub's REST API. The JWT's lifetime is
// AppJWTLifetime; iat is dated AppJWTLeeway in the past. GitHub uses
// the iss claim to look up the App; the JWT is unconditional within
// its validity window (no scopes, no aud).
//
// Returns the compact JWT string ("header.payload.signature").
func SignAppJWT(creds *AppCredentials, now time.Time) (string, error) {
	if creds == nil || creds.PrivateKey == nil {
		return "", ErrInvalidPrivateKey
	}
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "RS256", Typ: "JWT"}
	claims := struct {
		IAT int64 `json:"iat"`
		EXP int64 `json:"exp"`
		ISS int64 `json:"iss"`
	}{
		IAT: now.Add(-AppJWTLeeway).Unix(),
		EXP: now.Add(AppJWTLifetime).Unix(),
		ISS: creds.AppID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64URL(headerJSON) + "." + base64URL(claimsJSON)
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, creds.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signingInput + "." + base64URL(sig), nil
}

// base64URL encodes bytes using base64url-without-padding, the canonical
// JWT segment encoding (RFC 7515 §2).
func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// InstallationToken is GitHub's short-lived OAuth-style token that
// authenticates as the App's installation in a specific account. Lifetime
// is one hour; obtain a fresh one before every operation (or use the
// TokenSource cache below for the single-flight pattern).
type InstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired reports whether the token has expired. Used by TokenSource
// to decide on refresh; conservative — treats tokens with <30s of life
// remaining as expired so we don't pass a soon-to-expire token to a
// downstream call that might take longer than the remaining lifetime.
func (t *InstallationToken) IsExpired(now time.Time) bool {
	return t == nil || !now.Before(t.ExpiresAt.Add(-30*time.Second))
}

// FetchInstallationToken exchanges an App JWT for an installation token
// for a specific installation ID. installationID is the integer ID
// GitHub assigned when the App was installed in an account; the App
// needs to know the ID per-installation to act on the installation's
// behalf. The base URL defaults to https://api.github.com but is
// overrideable for GitHub Enterprise Server (set GITHUB_API_URL).
func FetchInstallationToken(ctx context.Context, httpClient *http.Client, baseURL string, appJWT string, installationID int64) (*InstallationToken, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	url := baseURL + "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInstallationTokenFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrInstallationTokenFailed, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%w: %s: %s", ErrInstallationTokenFailed, resp.Status, string(body))
	}

	var tok InstallationToken
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("%w: parse response: %v", ErrInstallationTokenFailed, err)
	}
	return &tok, nil
}

// TokenSource caches and refreshes InstallationTokens per-installation.
// Concurrent calls to Get for the same installation single-flight to one
// network refresh — preventing thundering-herd refreshes when many
// webhooks for the same installation arrive at once.
type TokenSource struct {
	creds      *AppCredentials
	httpClient *http.Client
	baseURL    string
	now        func() time.Time

	mu      sync.Mutex
	tokens  map[int64]*InstallationToken
	flights map[int64]*tokenFlight
}

type tokenFlight struct {
	done  chan struct{}
	token *InstallationToken
	err   error
}

// NewTokenSource constructs a TokenSource. Pass a nil http.Client to
// use http.DefaultClient (recommended); pass a custom now() for tests.
func NewTokenSource(creds *AppCredentials, httpClient *http.Client, baseURL string) *TokenSource {
	return &TokenSource{
		creds:      creds,
		httpClient: httpClient,
		baseURL:    baseURL,
		now:        time.Now,
		tokens:     make(map[int64]*InstallationToken),
		flights:    make(map[int64]*tokenFlight),
	}
}

// Get returns a fresh installation token for installationID, refreshing
// if the cached one is expired or absent. Safe for concurrent use; one
// network refresh per installation regardless of caller count.
func (ts *TokenSource) Get(ctx context.Context, installationID int64) (*InstallationToken, error) {
	ts.mu.Lock()
	if t, ok := ts.tokens[installationID]; ok && !t.IsExpired(ts.now()) {
		ts.mu.Unlock()
		return t, nil
	}
	if flight, ok := ts.flights[installationID]; ok {
		ts.mu.Unlock()
		select {
		case <-flight.done:
			return flight.token, flight.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	flight := &tokenFlight{done: make(chan struct{})}
	ts.flights[installationID] = flight
	ts.mu.Unlock()

	go func() {
		defer close(flight.done)
		jwt, signErr := SignAppJWT(ts.creds, ts.now())
		if signErr != nil {
			flight.err = signErr
		} else {
			tok, fetchErr := FetchInstallationToken(ctx, ts.httpClient, ts.baseURL, jwt, installationID)
			if fetchErr != nil {
				flight.err = fetchErr
			} else {
				flight.token = tok
			}
		}
		ts.mu.Lock()
		if flight.token != nil {
			ts.tokens[installationID] = flight.token
		}
		delete(ts.flights, installationID)
		ts.mu.Unlock()
	}()

	select {
	case <-flight.done:
		return flight.token, flight.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
