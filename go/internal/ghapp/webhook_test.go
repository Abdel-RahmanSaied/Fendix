package ghapp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// signFor produces a valid X-Hub-Signature-256 value for the given body
// and secret — used by the test helpers to hand the server a request
// the production code will accept.
func signFor(t *testing.T, secret, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature_Valid(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{"zen":"Practicality beats purity"}`)
	sig := signFor(t, secret, body)
	if err := VerifySignature(secret, sig, body); err != nil {
		t.Fatalf("expected valid signature to verify, got %v", err)
	}
}

func TestVerifySignature_Tampered(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{"zen":"Anything added dilutes everything else"}`)
	sig := signFor(t, secret, body)
	tampered := append([]byte{}, body...)
	tampered[0] ^= 0x01 // flip a bit
	err := VerifySignature(secret, sig, tampered)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch on tampered body, got %v", err)
	}
}

func TestVerifySignature_WrongSecret(t *testing.T) {
	body := []byte(`{}`)
	sig := signFor(t, []byte("real"), body)
	err := VerifySignature([]byte("attacker"), sig, body)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch with wrong secret, got %v", err)
	}
}

func TestVerifySignature_MissingHeader(t *testing.T) {
	err := VerifySignature([]byte("s"), "", []byte("x"))
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
}

func TestVerifySignature_LegacySHA1Rejected(t *testing.T) {
	// X-Hub-Signature (sha1=...) is the deprecated legacy header. We
	// require the modern X-Hub-Signature-256 header. A sha1= prefix
	// must be rejected as an unsupported algorithm.
	err := VerifySignature([]byte("s"), "sha1=abcd", []byte("x"))
	if !errors.Is(err, ErrUnsupportedSigAlgo) {
		t.Fatalf("expected ErrUnsupportedSigAlgo on sha1 sig, got %v", err)
	}
}

func TestVerifySignature_MalformedHex(t *testing.T) {
	err := VerifySignature([]byte("s"), "sha256=NOT_HEX", []byte("x"))
	if err == nil || errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected hex-decode error, got %v", err)
	}
}

func TestVerifySignature_PrefixOnlyRejected(t *testing.T) {
	// "sha256=" with no payload should be rejected, not treated as
	// equal to an empty HMAC.
	err := VerifySignature([]byte("s"), "sha256=", []byte("x"))
	if err == nil {
		t.Fatalf("expected error on empty signature payload, got nil")
	}
}

// stubRouter records calls; lets us assert which handler ran.
type stubRouter struct {
	pullRequest int
	push        int
	checkRun    int
	lastEvent   string
	returnErr   error
}

func (s *stubRouter) HandlePullRequest(ctx Context, body []byte) error {
	s.pullRequest++
	s.lastEvent = ctx.Event
	return s.returnErr
}
func (s *stubRouter) HandlePush(ctx Context, body []byte) error {
	s.push++
	s.lastEvent = ctx.Event
	return s.returnErr
}
func (s *stubRouter) HandleCheckRun(ctx Context, body []byte) error {
	s.checkRun++
	s.lastEvent = ctx.Event
	return s.returnErr
}

func newTestServer(t *testing.T, secret []byte) (*Server, *stubRouter) {
	t.Helper()
	r := &stubRouter{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(secret, r, logger), r
}

func makeReq(t *testing.T, method, event string, secret, body []byte, withSig bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "/webhook", bytes.NewReader(body))
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-GitHub-Delivery", "test-delivery-uuid")
	}
	if withSig {
		req.Header.Set("X-Hub-Signature-256", signFor(t, secret, body))
	}
	return req
}

func TestServeHTTP_RoutesPullRequest(t *testing.T) {
	secret := []byte("s")
	srv, router := newTestServer(t, secret)
	body := []byte(`{"action":"opened","number":1,"installation":{"id":42}}`)
	req := makeReq(t, http.MethodPost, "pull_request", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d body=%q", rec.Code, rec.Body.String())
	}
	if router.pullRequest != 1 {
		t.Errorf("expected pullRequest=1, got %d", router.pullRequest)
	}
	if router.lastEvent != "pull_request" {
		t.Errorf("expected event pull_request, got %q", router.lastEvent)
	}
}

func TestServeHTTP_RoutesPing(t *testing.T) {
	// Ping is acknowledged at dispatch level, not routed to the
	// EventRouter — so router counters stay 0 and the response is 200.
	secret := []byte("s")
	srv, router := newTestServer(t, secret)
	body := []byte(`{"zen":"Mind your words","hook_id":1}`)
	req := makeReq(t, http.MethodPost, "ping", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on ping, got %d", rec.Code)
	}
	if router.pullRequest+router.push+router.checkRun != 0 {
		t.Errorf("expected ping not routed to handlers")
	}
}

func TestServeHTTP_UnknownEventDropped(t *testing.T) {
	// Unknown events are 200-OK'd silently — GitHub disables endpoints
	// that 4xx repeatedly. Make sure the router wasn't called.
	secret := []byte("s")
	srv, router := newTestServer(t, secret)
	body := []byte(`{}`)
	req := makeReq(t, http.MethodPost, "issues", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on unknown event, got %d", rec.Code)
	}
	if router.pullRequest+router.push+router.checkRun != 0 {
		t.Errorf("unknown event should not call any handler")
	}
}

func TestServeHTTP_WrongMethod(t *testing.T) {
	secret := []byte("s")
	srv, _ := newTestServer(t, secret)
	body := []byte(`{}`)
	req := makeReq(t, http.MethodGet, "ping", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestServeHTTP_BadSignatureReturns401(t *testing.T) {
	secret := []byte("s")
	srv, router := newTestServer(t, secret)
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad sig, got %d", rec.Code)
	}
	if router.pullRequest != 0 {
		t.Errorf("router should not be called on bad sig")
	}
}

func TestServeHTTP_MissingSignatureReturns401(t *testing.T) {
	secret := []byte("s")
	srv, _ := newTestServer(t, secret)
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	// No X-Hub-Signature-256 header.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing sig, got %d", rec.Code)
	}
}

func TestServeHTTP_BodyTooLargeReturns413(t *testing.T) {
	secret := []byte("s")
	srv, _ := newTestServer(t, secret)
	// Body larger than the cap; signature is computed for the same
	// body so we know the rejection is on the size cap, not the sig.
	body := make([]byte, MaxWebhookBodyBytes+1)
	for i := range body {
		body[i] = 'x'
	}
	req := makeReq(t, http.MethodPost, "pull_request", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on oversize body, got %d", rec.Code)
	}
}

func TestServeHTTP_EmptyBodyReturns400(t *testing.T) {
	secret := []byte("s")
	srv, _ := newTestServer(t, secret)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(""))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", signFor(t, secret, nil))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty body, got %d", rec.Code)
	}
}

func TestServeHTTP_HandlerErrorReturns500(t *testing.T) {
	secret := []byte("s")
	srv, router := newTestServer(t, secret)
	router.returnErr = errors.New("boom")
	body := []byte(`{"action":"opened"}`)
	req := makeReq(t, http.MethodPost, "pull_request", secret, body, true)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on handler error, got %d", rec.Code)
	}
}

func TestDecodePing(t *testing.T) {
	body := []byte(`{"zen":"Approachable is better than simple.","hook_id":12345}`)
	p, err := DecodePing(body)
	if err != nil {
		t.Fatalf("DecodePing: %v", err)
	}
	if p.Zen != "Approachable is better than simple." {
		t.Errorf("zen mismatch: %q", p.Zen)
	}
	if p.HookID != 12345 {
		t.Errorf("hook_id mismatch: %d", p.HookID)
	}
}

func TestDecodePing_Malformed(t *testing.T) {
	if _, err := DecodePing([]byte(`{not json}`)); err == nil {
		t.Fatalf("expected error on malformed JSON")
	}
}
