// Package offline ships an air-gapped CVE database snapshot format
// and a thin "fendix db" CLI surface around it. Sprint 09 (Phase
// 4.1) — for customers whose CI runners can't reach
// osv.dev / proxy.golang.org / index.golang.org.
//
// Snapshot file format (v1):
//
//	{
//	  "schema": 1,
//	  "generated_at": "2026-05-15T12:00:00Z",
//	  "generator": "fendix vX.Y.Z db update --source ...",
//	  "sources": ["osv.dev", "golang.org/x/vuln"],
//	  "advisories": [
//	    {
//	      "id": "GHSA-...",
//	      "aliases": ["CVE-..."],
//	      "package": {"ecosystem": "PyPI", "name": "..."},
//	      "ranges": [{"introduced": "1.0.0", "fixed": "1.0.3"}],
//	      "summary": "...",
//	      "references": ["https://..."]
//	    },
//	    ...
//	  ]
//	}
//
// The format is deliberately a subset of OSV's wire schema so we can
// hydrate it directly from an OSV.dev mirror without an intermediate
// translation step. Future versions can add fields without bumping
// `schema` as long as readers ignore unknowns (which the Go json
// decoder does by default).
//
// The package itself ships the snapshot read/write + verify path.
// Sprint 09 deliberately leaves the *integration* with the per-
// ecosystem scanners (pip / npm / govulncheck) as follow-ups — the
// shape is set, but rewiring each scanner's HTTP path through a
// snapshot index is genuinely 2-3 days each. See the per-scanner
// TODO comments + the Sprint 09 Status section.
package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// SchemaVersion is the on-disk format version. Bump when the format
// changes in a non-backward-compatible way.
const SchemaVersion = 1

// DefaultDBPath is where `fendix db update` writes by default.
// Honours the XDG/fendix conventions used elsewhere in the codebase.
func DefaultDBPath() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".fendix", "offline-db.json")
}

// Snapshot is the in-memory shape of an on-disk DB.
type Snapshot struct {
	Schema      int         `json:"schema"`
	GeneratedAt time.Time   `json:"generated_at"`
	Generator   string      `json:"generator"`
	Sources     []string    `json:"sources"`
	Advisories  []Advisory  `json:"advisories"`
}

// Advisory mirrors the OSV.dev wire shape, but only the subset we
// actually consume. Unknown fields in real OSV data are silently
// dropped on decode.
type Advisory struct {
	ID         string      `json:"id"`
	Aliases    []string    `json:"aliases,omitempty"`
	Package    PackageRef  `json:"package"`
	Ranges     []Range     `json:"ranges,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	References []string    `json:"references,omitempty"`
}

type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// ErrSnapshotMissing is returned by Read when the path doesn't exist.
// Scan paths can errors.Is-check this to emit a clear "run `fendix db
// update` first" error.
var ErrSnapshotMissing = errors.New("offline: snapshot file not found")

// ErrSchemaMismatch is returned when the on-disk schema doesn't match
// SchemaVersion.
var ErrSchemaMismatch = errors.New("offline: snapshot schema version mismatch")

// Read loads a snapshot from disk. Returns ErrSnapshotMissing when
// the path doesn't exist (a normal "user hasn't run update yet"
// outcome).
func Read(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrSnapshotMissing, path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Decode(data)
}

// Decode parses snapshot JSON bytes into a Snapshot, validating the
// schema version.
func Decode(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchemaMismatch, s.Schema, SchemaVersion)
	}
	return &s, nil
}

// Write encodes the snapshot as pretty JSON to the given path,
// creating parent directories. The file ends with a trailing newline
// so it round-trips through line-oriented tooling (jq, less, diff).
func Write(path string, snap *Snapshot) error {
	if snap == nil {
		return errors.New("offline: cannot write nil snapshot")
	}
	if snap.Schema == 0 {
		snap.Schema = SchemaVersion
	}
	if snap.GeneratedAt.IsZero() {
		snap.GeneratedAt = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	out, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Verify computes a SHA-256 hash of the snapshot file and returns
// hex-encoded. Callers can compare to a published checksum to catch
// integrity-corrupting transfers (especially over air-gapped
// sneakernet).
func Verify(path string) (string, *Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, fmt.Errorf("%w: %s", ErrSnapshotMissing, path)
		}
		return "", nil, err
	}
	snap, err := Decode(data)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), snap, nil
}

// FromOSVExport hydrates a Snapshot from a list of OSV advisory JSON
// objects. Used by `fendix db update --source` to ingest an OSV.dev
// `vulns.zip` extract.
func FromOSVExport(advisories []Advisory, sources []string) *Snapshot {
	return &Snapshot{
		Schema:      SchemaVersion,
		GeneratedAt: time.Now().UTC(),
		Generator:   fmt.Sprintf("fendix offline.FromOSVExport (runtime %s)", runtime.Version()),
		Sources:     sources,
		Advisories:  advisories,
	}
}

// Summary returns a human-readable one-line description of the
// snapshot for `fendix db list` output.
func (s *Snapshot) Summary() string {
	return fmt.Sprintf("schema=%d advisories=%d sources=%v generated=%s",
		s.Schema, len(s.Advisories), s.Sources,
		s.GeneratedAt.UTC().Format(time.RFC3339))
}

// LookupByPackage returns every advisory matching (ecosystem, name).
// Ecosystem comparison is case-insensitive (OSV uses "PyPI", we
// might receive "pypi"); name comparison is case-sensitive (per OSV
// convention).
func (s *Snapshot) LookupByPackage(ecosystem, name string) []Advisory {
	out := make([]Advisory, 0)
	if s == nil {
		return out
	}
	for _, a := range s.Advisories {
		if equalFold(a.Package.Ecosystem, ecosystem) && a.Package.Name == name {
			out = append(out, a)
		}
	}
	return out
}

// equalFold is a tiny ASCII case-insensitive compare to avoid pulling
// in `strings` for this one call.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// ReadFrom is a streaming variant for very large snapshots. Not used
// today (~few MB of advisories fits in memory comfortably), but
// available for the millions-of-advisories future.
func ReadFrom(r io.Reader) (*Snapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Decode(data)
}
