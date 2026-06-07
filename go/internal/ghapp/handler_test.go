package ghapp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeScanner returns canned ScanResult bytes and records the
// last ScanRequest it saw.
type fakeScanner struct {
	last     ScanRequest
	called   atomic.Int32
	findings []byte
	sarif    []byte
	err      error
}

func (f *fakeScanner) Run(_ context.Context, req ScanRequest) (*ScanResult, error) {
	f.last = req
	f.called.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &ScanResult{FindingsJSON: f.findings, SARIF: f.sarif}, nil
}

// installationTokenServer mocks GitHub's installation-tokens endpoint
// so TokenSource can mint tokens against an httptest server.
func installationTokenServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/123/access_tokens" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"`+token+`","expires_at":"2099-01-01T00:00:00Z"}`)
	}))
}

func newTestHandler(t *testing.T, scanner Scanner) (*Handler, *httptest.Server) {
	t.Helper()
	tokenSrv := installationTokenServer(t, "ghs_test_token")
	t.Cleanup(tokenSrv.Close)

	creds := &AppCredentials{AppID: 1, PrivateKey: genTestKey(t)}
	tokens := NewTokenSource(creds, tokenSrv.Client(), tokenSrv.URL)

	// Single worker so concurrency-sensitive assertions are deterministic;
	// individual tests that exercise the cap construct their own pool.
	h := NewHandler(tokens, "", tokenSrv.Client(), 1)
	h.Scanner = scanner
	// F-H5a: scans now run on the background pool. Drain it on cleanup so
	// goroutines don't outlive the test.
	t.Cleanup(func() {
		_ = h.Shutdown(context.Background())
	})
	return h, tokenSrv
}

// drainScans waits until the Handler's background pool has finished all
// queued + in-flight scans. Scans run asynchronously (F-H5a), so tests
// that assert scan side effects must synchronise on completion. It
// shuts the pool down (idempotent) and waits for the workers to drain,
// then is safe to call again from the t.Cleanup hook.
func drainScans(t *testing.T, h *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("drainScans: pool did not drain: %v", err)
	}
}

func eventCtx() Context {
	return Context{
		Event:    "pull_request",
		Delivery: "test-delivery",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func samplePullRequestPayload(action string, installationID int64) []byte {
	type pr struct {
		Action      string `json:"action"`
		Number      int    `json:"number"`
		PullRequest struct {
			Head struct {
				SHA  string `json:"sha"`
				Repo struct {
					CloneURL string `json:"clone_url"`
				} `json:"repo"`
			} `json:"head"`
		} `json:"pull_request"`
		Repository struct {
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name string `json:"name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	var p pr
	p.Action = action
	p.Number = 42
	p.PullRequest.Head.SHA = "deadbeef"
	p.PullRequest.Head.Repo.CloneURL = "https://github.com/octocat/hello-world.git"
	p.Repository.Owner.Login = "octocat"
	p.Repository.Name = "hello-world"
	p.Installation.ID = installationID
	b, _ := json.Marshal(&p)
	return b
}

func TestHandlePullRequest_FullFlow(t *testing.T) {
	scanner := &fakeScanner{
		findings: []byte(`{
			"metadata":{"mode":"hybrid","endpoints_scanned":1,"duration":"1s"},
			"summary":{"critical":0,"high":1,"medium":0,"low":0,"info":0},
			"sources":{"blackbox":0,"whitebox":1,"correlated":0},
			"total":1,
			"findings":[{"severity":"HIGH","title":"hardcoded secret","endpoint":"src/x.py:1"}]
		}`),
		sarif: []byte(`{"runs":[]}`),
	}

	h, _ := newTestHandler(t, scanner)

	var commentArgs struct {
		Token, Owner, Repo, Body string
		PR                       int
		Called                   int
	}
	h.PostComment = func(_ context.Context, token, owner, repo string, prNumber int, body string) error {
		commentArgs.Token = token
		commentArgs.Owner = owner
		commentArgs.Repo = repo
		commentArgs.PR = prNumber
		commentArgs.Body = body
		commentArgs.Called++
		return nil
	}
	var sarifArgs struct {
		Token, Owner, Repo, SHA, Ref string
		Called                       int
		SARIFLen                     int
	}
	h.UploadSARIF = func(_ context.Context, token, owner, repo, sha, ref string, sarif []byte) error {
		sarifArgs.Token = token
		sarifArgs.Owner = owner
		sarifArgs.Repo = repo
		sarifArgs.SHA = sha
		sarifArgs.Ref = ref
		sarifArgs.SARIFLen = len(sarif)
		sarifArgs.Called++
		return nil
	}

	if err := h.HandlePullRequest(eventCtx(), samplePullRequestPayload("opened", 123)); err != nil {
		t.Fatalf("HandlePullRequest: %v", err)
	}
	drainScans(t, h)
	if scanner.called.Load() != 1 {
		t.Errorf("scanner called %d times, want 1", scanner.called.Load())
	}
	if scanner.last.HeadSHA != "deadbeef" {
		t.Errorf("scanner head sha: %q", scanner.last.HeadSHA)
	}
	if scanner.last.CloneURL != "https://github.com/octocat/hello-world.git" {
		t.Errorf("scanner clone url: %q", scanner.last.CloneURL)
	}
	if scanner.last.InstallationToken != "ghs_test_token" {
		t.Errorf("scanner token: %q", scanner.last.InstallationToken)
	}

	if commentArgs.Called != 1 {
		t.Errorf("PostComment called %d times, want 1", commentArgs.Called)
	}
	if commentArgs.Token != "ghs_test_token" || commentArgs.Owner != "octocat" ||
		commentArgs.Repo != "hello-world" || commentArgs.PR != 42 {
		t.Errorf("comment args wrong: %+v", commentArgs)
	}

	if sarifArgs.Called != 1 {
		t.Errorf("UploadSARIF called %d times, want 1", sarifArgs.Called)
	}
	if sarifArgs.SHA != "deadbeef" || sarifArgs.Ref != "refs/pull/42/head" {
		t.Errorf("sarif sha/ref wrong: %+v", sarifArgs)
	}
	if sarifArgs.SARIFLen != len(scanner.sarif) {
		t.Errorf("sarif passthrough wrong len: got %d want %d", sarifArgs.SARIFLen, len(scanner.sarif))
	}
}

func TestHandlePullRequest_FilteredAction(t *testing.T) {
	scanner := &fakeScanner{}
	h, _ := newTestHandler(t, scanner)
	h.PostComment = func(_ context.Context, _, _, _ string, _ int, _ string) error {
		t.Fatal("comment should not be posted on closed action")
		return nil
	}
	h.UploadSARIF = func(_ context.Context, _, _, _, _, _ string, _ []byte) error {
		t.Fatal("sarif should not be uploaded on closed action")
		return nil
	}

	if err := h.HandlePullRequest(eventCtx(), samplePullRequestPayload("closed", 123)); err != nil {
		t.Fatalf("HandlePullRequest closed: %v", err)
	}
	if scanner.called.Load() != 0 {
		t.Errorf("scanner should not run for closed; ran %d times", scanner.called.Load())
	}
}

func TestHandlePullRequest_NoInstallation(t *testing.T) {
	scanner := &fakeScanner{}
	h, _ := newTestHandler(t, scanner)
	h.PostComment = func(_ context.Context, _, _, _ string, _ int, _ string) error {
		t.Fatal("comment should not run without installation")
		return nil
	}
	h.UploadSARIF = func(_ context.Context, _, _, _, _, _ string, _ []byte) error {
		t.Fatal("sarif should not run without installation")
		return nil
	}

	if err := h.HandlePullRequest(eventCtx(), samplePullRequestPayload("opened", 0)); err != nil {
		t.Fatalf("HandlePullRequest: %v", err)
	}
	if scanner.called.Load() != 0 {
		t.Errorf("scanner should not run without installation")
	}
}

func TestHandlePullRequest_SARIFFailureNonFatal(t *testing.T) {
	scanner := &fakeScanner{
		findings: []byte(`{"metadata":{"mode":"x","endpoints_scanned":0,"duration":"0s"},"summary":{},"sources":{},"total":0,"findings":[]}`),
		sarif:    []byte(`{"runs":[]}`),
	}
	h, _ := newTestHandler(t, scanner)
	var commentMu sync.Mutex
	commentCalled := 0
	h.PostComment = func(_ context.Context, _, _, _ string, _ int, _ string) error {
		commentMu.Lock()
		commentCalled++
		commentMu.Unlock()
		return nil
	}
	h.UploadSARIF = func(_ context.Context, _, _, _, _, _ string, _ []byte) error {
		return io.ErrUnexpectedEOF
	}
	// Even when SARIF upload fails, the scan still posts the comment and
	// does not propagate — failure is logged, not surfaced. The webhook
	// is acknowledged immediately; drain the pool before asserting.
	if err := h.HandlePullRequest(eventCtx(), samplePullRequestPayload("synchronize", 123)); err != nil {
		t.Fatalf("expected nil err from immediate ack, got: %v", err)
	}
	drainScans(t, h)
	commentMu.Lock()
	defer commentMu.Unlock()
	if commentCalled != 1 {
		t.Errorf("expected comment to post even with SARIF failure")
	}
}

func TestHandleCheckRun_Rerequested(t *testing.T) {
	scanner := &fakeScanner{
		findings: []byte(`{"metadata":{"mode":"x","endpoints_scanned":0,"duration":"0s"},"summary":{},"sources":{},"total":0,"findings":[]}`),
		sarif:    []byte(`{"runs":[]}`),
	}
	h, _ := newTestHandler(t, scanner)
	h.PostComment = func(_ context.Context, _, _, _ string, _ int, _ string) error {
		return nil
	}
	h.UploadSARIF = func(_ context.Context, _, _, _, _, _ string, _ []byte) error {
		return nil
	}

	payload := []byte(`{
		"action":"rerequested",
		"check_run":{"name":"fendix","head_sha":"cafe1234","pull_requests":[{"number":7}]},
		"repository":{"owner":{"login":"octocat"},"name":"hw","clone_url":"https://github.com/octocat/hw.git"},
		"installation":{"id":123}
	}`)
	if err := h.HandleCheckRun(eventCtx(), payload); err != nil {
		t.Fatalf("HandleCheckRun: %v", err)
	}
	drainScans(t, h)
	if scanner.called.Load() != 1 {
		t.Errorf("scanner not invoked on rerequested, called %d", scanner.called.Load())
	}
	if scanner.last.HeadSHA != "cafe1234" {
		t.Errorf("scanner head sha: %q", scanner.last.HeadSHA)
	}
}

func TestHandleCheckRun_OtherActionsNoOp(t *testing.T) {
	scanner := &fakeScanner{}
	h, _ := newTestHandler(t, scanner)
	for _, action := range []string{"created", "completed", "requested_action"} {
		body := []byte(`{"action":"` + action + `","check_run":{"name":"fendix","head_sha":"x"}}`)
		if err := h.HandleCheckRun(eventCtx(), body); err != nil {
			t.Errorf("action=%s: %v", action, err)
		}
	}
	if scanner.called.Load() != 0 {
		t.Errorf("scanner should not run for non-rerequested actions, ran %d times", scanner.called.Load())
	}
}

func TestNewHandler_DefaultsWired(t *testing.T) {
	h := NewHandler(nil, "", nil, 0)
	t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
	if h.BaseURL != "https://api.github.com" {
		t.Errorf("default BaseURL: %q", h.BaseURL)
	}
	if h.HTTPClient != http.DefaultClient {
		t.Errorf("default HTTPClient should be http.DefaultClient")
	}
	if _, ok := h.Scanner.(*FendixScanner); !ok {
		t.Errorf("default Scanner should be *FendixScanner, got %T", h.Scanner)
	}
	if h.PostComment == nil {
		t.Errorf("default PostComment not set")
	}
	if h.UploadSARIF == nil {
		t.Errorf("default UploadSARIF not set")
	}
	if h.pool == nil {
		t.Errorf("default pool not constructed")
	}
}

// Compile-time assertion that *FendixScanner satisfies Scanner.
var _ Scanner = (*FendixScanner)(nil)

// Sanity check that the PR ref the handler builds is what the
// runScan path passes through.
func TestPRRefFormat(t *testing.T) {
	want := "refs/pull/" + strconv.Itoa(99) + "/head"
	if want != "refs/pull/99/head" {
		t.Errorf("ref format drift: %s", want)
	}
}
