package benchmark

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"gopkg.in/yaml.v3"
)

// FPClass is the false-positive taxonomy (design §5). It is also the enum
// used in a label's `fp_class:` field, so a labels file can never name a
// class the fixes don't track.
type FPClass string

const (
	FPConstantAuthority FPClass = "constant-authority"
	FPReceiverConfusion FPClass = "receiver-confusion"
	FPSafeAPIMisread    FPClass = "safe-api-misread"
	FPConstFoldMiss     FPClass = "const-fold-miss"
	FPGuardDominance    FPClass = "guard-dominance"
	FPTestFixture       FPClass = "test-fixture"
	FPHTTP4xxContext    FPClass = "http-4xx-context"
	FPStaticAssetCtx    FPClass = "static-asset-context"
	FPDoubleSanitize    FPClass = "double-sanitize"
	FPHeuristicOverfire FPClass = "heuristic-overfire"
	FPVersionRangeFloor FPClass = "version-range-floor"
	FPFabricatedChain   FPClass = "fabricated-chain"
)

var validFPClasses = map[FPClass]bool{
	FPConstantAuthority: true, FPReceiverConfusion: true, FPSafeAPIMisread: true,
	FPConstFoldMiss: true, FPGuardDominance: true, FPTestFixture: true,
	FPHTTP4xxContext: true, FPStaticAssetCtx: true, FPDoubleSanitize: true,
	FPHeuristicOverfire: true, FPVersionRangeFloor: true, FPFabricatedChain: true,
}

// Valid reports whether c is a recognized FP class.
func (c FPClass) Valid() bool { return validFPClasses[c] }

// Verdict is a label's ground-truth call for a matched finding.
type Verdict string

const (
	VerdictTP      Verdict = "tp"
	VerdictFP      Verdict = "fp"
	VerdictUnknown Verdict = "unknown" // never in a file; the scorer's bucket for unlabeled findings
)

// Label is one ground-truth entry keyed by a STABLE (rule+file+line) tuple,
// not a fingerprint — fingerprints embed evidence text that legitimate fixes
// change, silently orphaning labels (design §4.3).
type Label struct {
	Rule    string  `yaml:"rule"`
	File    string  `yaml:"file"`
	Line    int     `yaml:"line"`
	Verdict Verdict `yaml:"verdict"`
	FPClass FPClass `yaml:"fp_class,omitempty"`
	Note    string  `yaml:"note,omitempty"`
}

// LabelSet is the parsed labels.yaml for one corpus entry.
type LabelSet struct {
	Labels []Label
}

// NormalizePath makes a repo-relative path stable for matching: forward
// slashes, no leading "./".
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return p
}

// LoadLabelSet reads and validates a labels.yaml. verdict:fp requires a valid
// fp_class; any verdict other than tp/fp is rejected.
func LoadLabelSet(path string) (*LabelSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading labels %s: %w", path, err)
	}
	var labels []Label
	if err := yaml.Unmarshal(data, &labels); err != nil {
		return nil, fmt.Errorf("parsing labels %s: %w", path, err)
	}
	for i := range labels {
		labels[i].File = NormalizePath(labels[i].File)
		switch labels[i].Verdict {
		case VerdictTP:
		case VerdictFP:
			if !labels[i].FPClass.Valid() {
				return nil, fmt.Errorf("labels %s: entry %d verdict:fp needs a valid fp_class (got %q)", path, i, labels[i].FPClass)
			}
		default:
			return nil, fmt.Errorf("labels %s: entry %d has invalid verdict %q (want tp|fp)", path, i, labels[i].Verdict)
		}
	}
	return &LabelSet{Labels: labels}, nil
}

const lineTolerance = 3

// MatchFinding reports whether f corresponds to label l: same rule (label.Rule
// is the finding ID's suffix after "SEC-"), same normalized file, and line
// within ±3 of the anchor.
func MatchFinding(l Label, f models.Finding) bool {
	if ruleOf(f.ID) != l.Rule {
		return false
	}
	file, line, ok := splitEndpoint(f.Endpoint)
	if !ok {
		return false
	}
	if NormalizePath(file) != l.File {
		return false
	}
	d := line - l.Line
	if d < 0 {
		d = -d
	}
	return d <= lineTolerance
}

// ruleOf strips the "SEC-" prefix so "SEC-PY_SSRF" → "PY_SSRF".
func ruleOf(id string) string { return strings.TrimPrefix(id, "SEC-") }

// splitEndpoint splits "path/to/file.py:42" into ("path/to/file.py", 42, true).
func splitEndpoint(ep string) (string, int, bool) {
	i := strings.LastIndex(ep, ":")
	if i <= 0 {
		return "", 0, false
	}
	line, err := strconv.Atoi(ep[i+1:])
	if err != nil {
		return "", 0, false
	}
	return ep[:i], line, true
}
