package models

import (
	"crypto/sha1"
	"encoding/hex"
)

// Fingerprint returns a content-derived, run-stable identity for a finding:
// the hex sha1 of Category|Endpoint|Title. It deliberately excludes ID (which
// is a positional SEC-NNN reassigned every run), Severity (so a re-ranked
// finding keeps the same identity), and Evidence/Line specifics (so cosmetic
// changes don't churn it). This is the key suppressions and baselines should
// pin to instead of the drifting positional ID.
//
// It mirrors the (Title, Endpoint, Category) trio the baseline diff already
// uses for cross-run identity — here folded into a single stable token that
// can also be emitted on the finding and matched by an ignore rule.
func Fingerprint(f Finding) string {
	h := sha1.Sum([]byte(f.Category + "|" + f.Endpoint + "|" + f.Title))
	return hex.EncodeToString(h[:])
}
