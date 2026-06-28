// Package scanner implements HTTP-based black-box security checks.
// Each check is a function that takes a scan config and endpoint,
// sends HTTP requests, and returns findings based on the responses.
package scanner

import (
	"context"

	ev "github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Endpoint represents a discovered API endpoint to scan.
//
// Params holds query and path parameter names (covered by TASK-081).
// Headers holds OpenAPI `in: header` parameter names with standard auth
// headers (Authorization, Cookie, X-Api-Key, ...) filtered out — those are
// the auth scanner's job, and probing them with malicious payloads risks
// breaking the test session for downstream endpoints.
// BodyParams holds JSON body field names extracted from `requestBody`
// (OpenAPI 3) or `in: body` schema (Swagger 2). Probing them requires
// emitting a JSON body on POST/PUT/PATCH; see CheckInjectionWithAudit.
type Endpoint struct {
	Method     string
	Path       string
	FullURL    string
	Params     []string
	Headers    []string
	BodyParams []string
}

// CheckFn is the signature for all scanner check functions.
// Each check receives a context, config, and endpoint, and returns findings.
type CheckFn func(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence
