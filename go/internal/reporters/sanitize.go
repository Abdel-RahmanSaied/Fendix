package reporters

import (
	"strings"

	"github.com/fendix/fendix/internal/models"
)

// SanitizeFindings replaces any occurrence of auth credential values
// in finding evidence and fix text with [REDACTED].
// This is a defense-in-depth measure: auth values must never appear in reports.
func SanitizeFindings(findings []models.Finding, authContexts ...*models.AuthContext) []models.Finding {
	var secrets []string
	for _, auth := range authContexts {
		if auth == nil || auth.Value == "" {
			continue
		}
		secrets = append(secrets, auth.Value)

		// Also add the bare token (without "Bearer " prefix) as a secret
		if stripped := strings.TrimPrefix(auth.Value, "Bearer "); stripped != auth.Value {
			secrets = append(secrets, stripped)
		}
		if stripped := strings.TrimPrefix(auth.Value, "Basic "); stripped != auth.Value {
			secrets = append(secrets, stripped)
		}
	}

	if len(secrets) == 0 {
		return findings
	}

	sanitized := make([]models.Finding, len(findings))
	copy(sanitized, findings)

	for i := range sanitized {
		sanitized[i].Evidence = redactSecrets(sanitized[i].Evidence, secrets)
		sanitized[i].Fix = redactSecrets(sanitized[i].Fix, secrets)
		sanitized[i].Title = redactSecrets(sanitized[i].Title, secrets)
	}

	return sanitized
}

func redactSecrets(text string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	return text
}
