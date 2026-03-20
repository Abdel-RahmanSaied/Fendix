// Package scanner implements HTTP-based black-box security checks.
// Each check is a function that takes a scan config and endpoint,
// sends HTTP requests, and returns findings based on the responses.
package scanner

import "context"

import "github.com/Abdel-RahmanSaied/Fendix/internal/models"

// Endpoint represents a discovered API endpoint to scan.
type Endpoint struct {
	Method  string
	Path    string
	FullURL string
	Params  []string
}

// CheckFn is the signature for all scanner check functions.
// Each check receives a context, config, and endpoint, and returns findings.
type CheckFn func(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding
