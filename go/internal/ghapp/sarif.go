package ghapp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// UploadSARIF uploads a SARIF blob to GitHub's Code Scanning API. The
// API accepts gzip+base64-encoded SARIF; the Server stores the
// findings against the given commit SHA and ref, then makes them
// available in the repo's Security tab.
//
// commitSHA is the SHA the findings apply to (the PR head SHA for
// PR scans). ref identifies which scan target this is — for PR
// scans, "refs/pull/<pr_number>/head" is the conventional value
// (it always exists, unlike refs/pull/.../merge which doesn't if
// the PR has conflicts).
//
// The 202 Accepted response means GitHub queued the SARIF for
// processing — actual visibility in the Security tab is deferred
// (typically a few seconds). This function does not poll for
// completion; the operator path is fire-and-forget.
func UploadSARIF(ctx context.Context, httpClient *http.Client, baseURL, installationToken, owner, repo, commitSHA, ref string, sarif []byte) error {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	if len(sarif) == 0 {
		return fmt.Errorf("sarif: empty payload")
	}

	encoded, err := encodeSARIF(sarif)
	if err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}

	payload, err := json.Marshal(struct {
		CommitSHA string `json:"commit_sha"`
		Ref       string `json:"ref"`
		SARIF     string `json:"sarif"`
	}{CommitSHA: commitSHA, Ref: ref, SARIF: encoded})
	if err != nil {
		return fmt.Errorf("sarif: encode payload: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") +
		"/repos/" + owner + "/" + repo + "/code-scanning/sarifs"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sarif: upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("sarif: upload: %s: %s", resp.Status, string(responseBody))
	}
	return nil
}

// encodeSARIF gzip-compresses then base64-encodes a SARIF JSON blob,
// the format GitHub's Code Scanning API requires for the `sarif`
// field of POST /repos/{owner}/{repo}/code-scanning/sarifs.
func encodeSARIF(sarif []byte) (string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(sarif); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
