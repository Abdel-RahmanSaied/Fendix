package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const idorMaxBodySize = 64 * 1024 // 64KB for response comparison

// CheckIDOR performs Insecure Direct Object Reference detection using two
// authenticated accounts. It sends the same request with user1 and user2
// credentials and flags endpoints where both users get identical 200 responses,
// which suggests missing object-level authorization.
// Requires cfg.AuthUser2 to be set (--auth-user2 flag).
func CheckIDOR(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	if cfg.Auth == nil || cfg.AuthUser2 == nil {
		return nil
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: budget.Transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)

	resp1Body, resp1Status, err := doAuthRequest(ctx, client, endpoint, cfg.Auth)
	if err != nil || resp1Status < 200 || resp1Status >= 300 {
		return nil
	}

	resp2Body, resp2Status, err := doAuthRequest(ctx, client, endpoint, cfg.AuthUser2)
	if err != nil || resp2Status < 200 || resp2Status >= 300 {
		return nil
	}

	if resp1Status == resp2Status && resp1Body == resp2Body && resp1Body != "" {
		evidence := fmt.Sprintf("Both users received identical HTTP %d responses (%d bytes)",
			resp1Status, len(resp1Body))
		if len(resp1Body) > 200 {
			evidence += fmt.Sprintf("; body preview: %s...", resp1Body[:200])
		}

		return []models.Finding{
			{
				Title:      "Potential IDOR — identical responses for different users",
				Severity:   models.SeverityHigh,
				Source:     models.SourceBlackbox,
				Category:   "idor",
				Endpoint:   epLabel,
				Evidence:   truncateEvidence(evidence, 500),
				Fix:        "Implement object-level authorization. Ensure each user can only access their own resources.",
				References: []string{"CWE-639", "OWASP-A01"},
				Confidence: models.ConfidenceMedium,
			},
		}
	}

	slog.Debug("IDOR check: responses differ", "endpoint", epLabel)
	return nil
}

func doAuthRequest(ctx context.Context, client *http.Client, endpoint Endpoint, auth *models.AuthContext) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("creating request: %w", err)
	}

	auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, idorMaxBodySize))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("reading body: %w", err)
	}

	return string(body), resp.StatusCode, nil
}

func truncateEvidence(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
