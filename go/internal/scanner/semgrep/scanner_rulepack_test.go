package semgrep

import (
	"io/fs"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// rulepackTotalCount is the count of bundled rules Sprint 18 ships with.
// When you add or remove a rule, update this constant in the same commit
// so the catalog test catches accidental rule deletion.
const rulepackTotalCount = 24

// rulepackFiles is the canonical list of embedded YAML rule files. The
// extraction tests (TestEnsureRules_ExtractsAllBundledFiles) assert this
// matches the disk layout. Add a new file here when you create one.
var rulepackFiles = []string{
	"auth.yaml",
	"injection.yaml",
	"secrets.yaml",
	"crypto.yaml",
}

// validFendixSeverityKeys is the set of values accepted in the
// metadata.fendix_severity rule field. Mirrors validFendixSeverities in
// scanner.go but as a string-only set since the YAML still holds strings.
var validFendixSeverityKeys = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"INFO":     true,
}

// validConfidenceKeys mirrors the values resolveConfidence in scanner.go
// recognises. A rule that ships a string outside this set silently
// defaults to MEDIUM, which is the wrong shape for a rule audit.
var validConfidenceKeys = map[string]bool{
	"HIGH":   true,
	"MEDIUM": true,
	"LOW":    true,
}

// ruleYAML is the subset of each rule's YAML we assert on. Unknown fields
// in real semgrep YAML (e.g. patterns, message) are ignored — this is a
// catalog audit, not a semgrep parser.
type ruleYAML struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Languages []any  `yaml:"languages"`
	Metadata  struct {
		Category       string `yaml:"category"`
		CWE            any    `yaml:"cwe"` // string or []string per resolveCWE
		Confidence     string `yaml:"confidence"`
		FendixSeverity string `yaml:"fendix_severity"`
	} `yaml:"metadata"`
}

type ruleFileYAML struct {
	Rules []ruleYAML `yaml:"rules"`
}

// loadAllRules walks the embedded FS, parses every YAML file, and returns
// every rule it finds keyed by ID. Duplicate IDs across files (or within
// one file) are reported as an error — semgrep merges rule packs by ID,
// so a duplicate is a silent override.
func loadAllRules(t *testing.T) map[string]ruleYAML {
	t.Helper()
	out := make(map[string]ruleYAML)
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var doc ruleFileYAML
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, r := range doc.Rules {
			if r.ID == "" {
				t.Errorf("%s: rule with empty id", path)
				continue
			}
			if existing, ok := out[r.ID]; ok {
				t.Errorf("duplicate rule id %q (also in %v)", r.ID, existing)
				continue
			}
			out[r.ID] = r
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func TestRulepack_TotalCountMatchesConstant(t *testing.T) {
	rules := loadAllRules(t)
	if len(rules) != rulepackTotalCount {
		ids := make([]string, 0, len(rules))
		for id := range rules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("rulepack has %d rules; rulepackTotalCount = %d. IDs: %s",
			len(rules), rulepackTotalCount, strings.Join(ids, ", "))
	}
}

func TestRulepack_EveryRuleHasFendixSeverity(t *testing.T) {
	for id, r := range loadAllRules(t) {
		got := strings.ToUpper(r.Metadata.FendixSeverity)
		if !validFendixSeverityKeys[got] {
			t.Errorf("rule %q: metadata.fendix_severity = %q; want one of CRITICAL/HIGH/MEDIUM/LOW/INFO",
				id, r.Metadata.FendixSeverity)
		}
	}
}

func TestRulepack_EveryRuleHasCategory(t *testing.T) {
	for id, r := range loadAllRules(t) {
		if strings.TrimSpace(r.Metadata.Category) == "" {
			t.Errorf("rule %q: metadata.category is empty", id)
		}
	}
}

func TestRulepack_EveryRuleHasCWE(t *testing.T) {
	for id, r := range loadAllRules(t) {
		switch v := r.Metadata.CWE.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				t.Errorf("rule %q: metadata.cwe is empty string", id)
			}
		case []any:
			if len(v) == 0 {
				t.Errorf("rule %q: metadata.cwe is empty list", id)
			}
		case nil:
			t.Errorf("rule %q: metadata.cwe is absent", id)
		default:
			t.Errorf("rule %q: metadata.cwe has unexpected type %T", id, v)
		}
	}
}

func TestRulepack_EveryRuleHasValidConfidence(t *testing.T) {
	for id, r := range loadAllRules(t) {
		got := strings.ToUpper(r.Metadata.Confidence)
		if !validConfidenceKeys[got] {
			t.Errorf("rule %q: metadata.confidence = %q; want HIGH/MEDIUM/LOW",
				id, r.Metadata.Confidence)
		}
	}
}

func TestRulepack_EveryRuleHasLanguage(t *testing.T) {
	for id, r := range loadAllRules(t) {
		if len(r.Languages) == 0 {
			t.Errorf("rule %q: languages list is empty", id)
		}
	}
}

func TestRulepack_LowConfidenceCappedAtMediumSeverity(t *testing.T) {
	// Mirrors the consistency rule in docs/semgrep-rules.md:
	// "a finding with confidence: LOW cannot have severity higher than
	// MEDIUM. The orchestrator will downgrade and warn."
	// At write time the rule is enforced at the orchestrator layer, not in
	// the rule pack — but a rule that ships with LOW+HIGH is shipping a
	// finding that will be silently downgraded, which is a docs-drift bug
	// of its own. Catch it here.
	rank := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for id, r := range loadAllRules(t) {
		conf := strings.ToUpper(r.Metadata.Confidence)
		sev := strings.ToUpper(r.Metadata.FendixSeverity)
		if conf == "LOW" && rank[sev] > rank["MEDIUM"] {
			t.Errorf("rule %q: confidence=LOW but fendix_severity=%s. "+
				"Downgrade severity or raise confidence — the orchestrator "+
				"will downgrade this to MEDIUM anyway.", id, sev)
		}
	}
}

// TestRulepack_ValidatesViaSemgrepCLI invokes `semgrep --validate` against
// the bundled rules. Skipped when semgrep is not on PATH (the common dev
// case + CI runners without semgrep installed). Catches pattern-syntax
// errors the YAML-only catalog tests above can't see — e.g. a malformed
// pattern-either body or a metavariable-regex with invalid Go regex syntax.
func TestRulepack_ValidatesViaSemgrepCLI(t *testing.T) {
	bin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not on PATH; skipping --validate check")
	}
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	for _, name := range rulepackFiles {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(bin, "--validate", "--config", filepath.Join(dir, name))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("semgrep --validate %s failed: %v\noutput:\n%s",
					name, err, string(out))
			}
		})
	}
}
