package ghapp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadSARIF_Success(t *testing.T) {
	sarifIn := []byte(`{"runs":[{"results":[{"ruleId":"fendix.headers.csp","message":{"text":"missing CSP"}}]}]}`)

	var captured struct {
		Auth       string
		Accept     string
		APIVersion string
		Path       string
		Decoded    []byte
		Payload    struct {
			CommitSHA string `json:"commit_sha"`
			Ref       string `json:"ref"`
			SARIF     string `json:"sarif"`
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Auth = r.Header.Get("Authorization")
		captured.Accept = r.Header.Get("Accept")
		captured.APIVersion = r.Header.Get("X-GitHub-Api-Version")
		captured.Path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.Payload)

		// Round-trip the encoded sarif: base64-decode, gunzip, must
		// equal sarifIn — proves we sent the right format.
		gzipped, err := base64.StdEncoding.DecodeString(captured.Payload.SARIF)
		if err == nil {
			r, _ := gzip.NewReader(bytes.NewReader(gzipped))
			if r != nil {
				captured.Decoded, _ = io.ReadAll(r)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	err := UploadSARIF(context.Background(), srv.Client(), srv.URL,
		"ghs_xx", "octocat", "Hello-World",
		"deadbeef", "refs/pull/42/head", sarifIn)
	if err != nil {
		t.Fatalf("UploadSARIF: %v", err)
	}
	if captured.Auth != "Bearer ghs_xx" {
		t.Errorf("auth: %q", captured.Auth)
	}
	if captured.Accept != "application/vnd.github+json" {
		t.Errorf("accept: %q", captured.Accept)
	}
	if captured.APIVersion != "2022-11-28" {
		t.Errorf("api-version: %q", captured.APIVersion)
	}
	if captured.Path != "/repos/octocat/Hello-World/code-scanning/sarifs" {
		t.Errorf("path: %q", captured.Path)
	}
	if captured.Payload.CommitSHA != "deadbeef" || captured.Payload.Ref != "refs/pull/42/head" {
		t.Errorf("payload sha/ref: %+v", captured.Payload)
	}
	if !bytes.Equal(captured.Decoded, sarifIn) {
		t.Errorf("decoded sarif mismatch: got %q want %q", captured.Decoded, sarifIn)
	}
}

func TestUploadSARIF_Non202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"message":"invalid sarif"}`)
	}))
	defer srv.Close()

	err := UploadSARIF(context.Background(), srv.Client(), srv.URL,
		"tok", "o", "r", "sha", "refs/heads/main", []byte(`{"runs":[]}`))
	if err == nil {
		t.Fatal("expected error on 422")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("expected 422 in err: %v", err)
	}
}

func TestUploadSARIF_EmptyPayload(t *testing.T) {
	err := UploadSARIF(context.Background(), nil, "https://api.github.com",
		"tok", "o", "r", "sha", "ref", nil)
	if err == nil {
		t.Fatal("expected error on empty sarif")
	}
}

func TestEncodeSARIF_RoundTrip(t *testing.T) {
	in := []byte(`{"runs":[{"results":[]}]}`)
	encoded, err := encodeSARIF(in)
	if err != nil {
		t.Fatalf("encodeSARIF: %v", err)
	}
	gzipped, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round-trip mismatch: %q vs %q", out, in)
	}
}
