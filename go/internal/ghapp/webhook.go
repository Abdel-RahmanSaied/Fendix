// Package ghapp implements the Fendix GitHub App: webhook signature
// verification, App-as-bot authentication (App JWT → installation token),
// and event routing. The package is consumed by cmd/fendix-app, the
// long-running HTTP server that GitHub posts webhooks to.
//
// The scan-and-comment workflow that runs on a pull_request event is
// implemented in handler.go (Handler.HandlePullRequest): decode payload
// → filter to scan-worthy actions (opened / synchronize / reopened) →
// acquire installation token → clone HEAD SHA → run scan → post PR
// comment summarising findings → upload SARIF to Code Scanning (best
// effort). HandleCheckRun re-runs the scan when GitHub UI's "Re-run
// check" button is clicked. HandlePush is wired for the eventual
// baseline-refresh flow but is a no-op acknowledgement today.
package ghapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// MaxWebhookBodyBytes caps the request body size the webhook handler will
// read. GitHub's documented webhook payload limit is 25 MB, but Fendix
// only uses a small subset of fields and never needs more than ~2 MB
// (a large pull_request payload). The cap protects the handler from
// memory exhaustion if a misbehaving client floods the endpoint.
const MaxWebhookBodyBytes = 4 << 20 // 4 MiB

// Errors returned by the webhook layer. Distinguished so the HTTP
// handler can map them to the right status codes.
var (
	ErrMissingSignature   = errors.New("missing X-Hub-Signature-256 header")
	ErrSignatureMismatch  = errors.New("webhook signature does not match shared secret")
	ErrUnsupportedSigAlgo = errors.New("only sha256 webhook signatures are supported")
	ErrEmptyBody          = errors.New("webhook body is empty")
	ErrBodyTooLarge       = errors.New("webhook body exceeds size cap")
)

// VerifySignature validates GitHub's X-Hub-Signature-256 header against
// the body using HMAC-SHA256 with the App's webhook secret. Returns nil
// if the signature matches; a sentinel error otherwise.
//
// GitHub's signature header format is "sha256=<hex>". Both the legacy
// "sha1=<hex>" header (X-Hub-Signature) and the missing-header case are
// rejected — Fendix only supports modern signed webhooks.
func VerifySignature(secret []byte, signatureHeader string, body []byte) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	const prefix = "sha256="
	if len(signatureHeader) <= len(prefix) || signatureHeader[:len(prefix)] != prefix {
		return ErrUnsupportedSigAlgo
	}
	want, err := hex.DecodeString(signatureHeader[len(prefix):])
	if err != nil {
		return fmt.Errorf("malformed signature hex: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	got := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return ErrSignatureMismatch
	}
	return nil
}

// EventRouter dispatches a verified webhook event to its handler. The
// router decouples HTTP-layer concerns (sig verify, body read) from
// business logic (handle pull_request, push, check_run). Concrete
// handlers live in handler.go.
type EventRouter interface {
	HandlePullRequest(ctx Context, body []byte) error
	HandlePush(ctx Context, body []byte) error
	HandleCheckRun(ctx Context, body []byte) error
}

// Context carries per-event metadata pulled from request headers.
// Distinct from context.Context — that's part of the http.Request the
// handler is invoked with; this struct holds GitHub-specific event
// metadata.
type Context struct {
	Event    string // X-GitHub-Event header value
	Delivery string // X-GitHub-Delivery — UUID for idempotency
	Logger   *slog.Logger
}

// Server is the HTTP handler that GitHub posts webhooks to. It owns
// the webhook secret and the EventRouter. Construct with NewServer.
type Server struct {
	secret []byte
	router EventRouter
	logger *slog.Logger
}

// NewServer constructs a Server. The webhook secret is the App-level
// shared secret configured during App creation; treat it as confidential
// — anyone with the secret can spoof webhooks. The router receives
// verified events; pass the production handler from handler.go for the
// real implementation.
func NewServer(secret []byte, router EventRouter, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{secret: secret, router: router, logger: logger}
}

// ServeHTTP implements http.Handler. The route is intentionally
// unconditional — register *Server on whatever path the operator wants
// (default: POST /webhook) using http.ServeMux or a third-party router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readBody(r)
	if err != nil {
		s.logger.Warn("webhook body read failed", "err", err)
		statusForReadErr(w, err)
		return
	}

	if err := VerifySignature(s.secret, r.Header.Get("X-Hub-Signature-256"), body); err != nil {
		s.logger.Warn("webhook signature verification failed",
			"err", err,
			"delivery", r.Header.Get("X-GitHub-Delivery"))
		// Always return 401 on sig failure regardless of which sub-error
		// fired. We don't want to leak "header missing" vs "signature
		// mismatch" to a probing attacker.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")
	ctx := Context{
		Event:    event,
		Delivery: delivery,
		Logger:   s.logger.With("event", event, "delivery", delivery),
	}
	ctx.Logger.Info("webhook received", "size_bytes", len(body))

	if err := s.dispatch(ctx, body); err != nil {
		ctx.Logger.Error("event handler failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// dispatch routes verified events to the registered router. Unknown
// events get logged and 200-OK'd — GitHub disables webhook endpoints
// that 4xx repeatedly, and an unknown event isn't an error condition
// (we just don't process it yet).
func (s *Server) dispatch(ctx Context, body []byte) error {
	switch ctx.Event {
	case "pull_request":
		return s.router.HandlePullRequest(ctx, body)
	case "push":
		return s.router.HandlePush(ctx, body)
	case "check_run":
		return s.router.HandleCheckRun(ctx, body)
	case "ping":
		// GitHub sends a ping event on App install / webhook create.
		// Acknowledge silently.
		ctx.Logger.Info("webhook ping ack")
		return nil
	default:
		ctx.Logger.Info("ignoring unsupported event")
		return nil
	}
}

// readBody reads the request body up to MaxWebhookBodyBytes. Returns
// ErrBodyTooLarge if the cap is exceeded; ErrEmptyBody for zero-length
// bodies (which GitHub never sends — empty body indicates a buggy
// client).
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, ErrEmptyBody
	}
	limited := io.LimitReader(r.Body, MaxWebhookBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, ErrEmptyBody
	}
	if len(body) > MaxWebhookBodyBytes {
		return nil, ErrBodyTooLarge
	}
	return body, nil
}

func statusForReadErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEmptyBody):
		http.Error(w, "empty body", http.StatusBadRequest)
	case errors.Is(err, ErrBodyTooLarge):
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

// PingPayload is the minimal subset of GitHub's ping event the App
// inspects. Used for tests and for first-install logging.
type PingPayload struct {
	Zen    string `json:"zen"`
	HookID int64  `json:"hook_id"`
}

// DecodePing parses a ping webhook body. Returns the parsed payload
// and an error on malformed JSON.
func DecodePing(body []byte) (*PingPayload, error) {
	var p PingPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode ping: %w", err)
	}
	return &p, nil
}
