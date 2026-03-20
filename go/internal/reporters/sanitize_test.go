package reporters

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestSanitizeFindings_RedactsAuthValues(t *testing.T) {
	auth := &models.AuthContext{
		Value:  "Bearer sk-live-abc123def456",
		Header: "Authorization",
		Type:   models.AuthTypeBearer,
	}

	findings := []models.Finding{
		{
			Title:    "Test finding",
			Evidence: "Request sent with Bearer sk-live-abc123def456 got 200",
			Fix:      "Remove Bearer sk-live-abc123def456 from response",
		},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Evidence, "sk-live-abc123def456") {
		t.Errorf("evidence still contains secret: %s", sanitized[0].Evidence)
	}
	if !strings.Contains(sanitized[0].Evidence, "[REDACTED]") {
		t.Error("evidence should contain [REDACTED]")
	}
	if strings.Contains(sanitized[0].Fix, "sk-live-abc123def456") {
		t.Errorf("fix still contains secret: %s", sanitized[0].Fix)
	}
}

func TestSanitizeFindings_RedactsBareToken(t *testing.T) {
	auth := &models.AuthContext{
		Value: "Bearer eyJhbGciOiJIUzI1NiJ9.longpayload.signature",
	}

	findings := []models.Finding{
		{
			Title:    "JWT exposed",
			Evidence: "Token eyJhbGciOiJIUzI1NiJ9.longpayload.signature found in response",
		},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Evidence, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("bare token should be redacted: %s", sanitized[0].Evidence)
	}
}

func TestSanitizeFindings_NilAuth(t *testing.T) {
	findings := []models.Finding{
		{Title: "Test", Evidence: "some evidence"},
	}

	sanitized := SanitizeFindings(findings, nil)

	if sanitized[0].Evidence != "some evidence" {
		t.Errorf("nil auth should not modify findings")
	}
}

func TestSanitizeFindings_MultipleAuthContexts(t *testing.T) {
	auth1 := &models.AuthContext{Value: "Bearer token-user1"}
	auth2 := &models.AuthContext{Value: "Bearer token-user2"}

	findings := []models.Finding{
		{
			Evidence: "user1=Bearer token-user1, user2=Bearer token-user2",
		},
	}

	sanitized := SanitizeFindings(findings, auth1, auth2)

	if strings.Contains(sanitized[0].Evidence, "token-user1") {
		t.Error("user1 token should be redacted")
	}
	if strings.Contains(sanitized[0].Evidence, "token-user2") {
		t.Error("user2 token should be redacted")
	}
}

func TestSanitizeFindings_DoesNotMutateOriginal(t *testing.T) {
	auth := &models.AuthContext{Value: "Bearer secret-tok"}

	original := []models.Finding{
		{Evidence: "includes Bearer secret-tok value"},
	}

	_ = SanitizeFindings(original, auth)

	if !strings.Contains(original[0].Evidence, "secret-tok") {
		t.Error("original findings should not be mutated")
	}
}

func TestSanitizeFindings_EmptySecrets(t *testing.T) {
	auth := &models.AuthContext{Value: ""}

	findings := []models.Finding{
		{Evidence: "no secrets here"},
	}

	sanitized := SanitizeFindings(findings, auth)
	if sanitized[0].Evidence != "no secrets here" {
		t.Error("empty auth should not modify findings")
	}
}

func TestSanitizeFindings_RedactsInTitle(t *testing.T) {
	auth := &models.AuthContext{Value: "Bearer my-secret-token"}

	findings := []models.Finding{
		{Title: "Leak found: Bearer my-secret-token"},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Title, "my-secret-token") {
		t.Errorf("title should be redacted: %s", sanitized[0].Title)
	}
}
