package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// writePythonScript creates a temporary Python script that simulates the engine.
func writePythonScript(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("writing python script: %v", err)
	}
	return path
}

func TestReadFindings_ValidStream(t *testing.T) {
	input := `{"id":"","title":"Hardcoded secret","severity":"HIGH","source":"whitebox","category":"secrets","endpoint":"config.py:14","evidence":"API_KEY = sk-...","fix":"Use env var","references":["CWE-798"],"confidence":"HIGH","line":"config.py:14"}
{"id":"","title":"SQL injection","severity":"CRITICAL","source":"whitebox","category":"injection","endpoint":"db.py:42","evidence":"cursor.execute(f\"...\")","fix":"Use parameterized queries","references":["CWE-89"],"confidence":"HIGH","line":"db.py:42"}
{"done":true,"total":2}
`
	findings, total, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Title != "Hardcoded secret" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	if findings[1].Severity != models.SeverityCritical {
		t.Errorf("unexpected severity: %s", findings[1].Severity)
	}
}

func TestReadFindings_EmptyStream(t *testing.T) {
	input := `{"done":true,"total":0}
`
	findings, total, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestReadFindings_MalformedLine(t *testing.T) {
	input := `not valid json
{"id":"","title":"Valid finding","severity":"HIGH","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"HIGH","line":null}
{"done":true,"total":1}
`
	findings, total, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (malformed skipped), got %d", len(findings))
	}
}

func TestReadFindings_MissingRequiredFields(t *testing.T) {
	input := `{"id":"","title":"","severity":"","source":"","category":"","endpoint":"","evidence":"","fix":"","references":[],"confidence":"","line":null}
{"done":true,"total":0}
`
	findings, _, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (empty title/severity skipped), got %d", len(findings))
	}
}

func TestReadFindings_DoneWithError(t *testing.T) {
	input := `{"done":true,"total":0,"error":"invalid ScanRequest JSON: Expecting value"}
`
	_, _, err := readFindings(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error from done message with error field")
	}
	if !strings.Contains(err.Error(), "invalid ScanRequest JSON") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadFindings_NoTerminator(t *testing.T) {
	input := `{"id":"","title":"Orphan finding","severity":"MEDIUM","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"MEDIUM","line":null}
`
	findings, total, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if total != 1 {
		t.Errorf("expected total 1 (fallback), got %d", total)
	}
}

func TestReadFindings_BlankLines(t *testing.T) {
	input := `
{"id":"","title":"Finding","severity":"LOW","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"LOW","line":null}

{"done":true,"total":1}
`
	findings, total, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestReadFindings_WhiteboxSourceDefault(t *testing.T) {
	input := `{"id":"","title":"No source","severity":"HIGH","source":"","category":"test","endpoint":"a.py","evidence":"x","fix":"y","references":[],"confidence":"HIGH","line":null}
{"done":true,"total":1}
`
	findings, _, err := readFindings(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Source != models.SourceWhitebox {
		t.Errorf("expected source whitebox, got %s", findings[0].Source)
	}
}

func TestPythonSpawner_RunWithMockEngine(t *testing.T) {
	dir := t.TempDir()

	// Write a minimal mock engine.py that emits one finding and done
	script := `import json, sys
finding = {
    "id": "",
    "title": "Mock finding",
    "severity": "HIGH",
    "source": "whitebox",
    "category": "secrets",
    "endpoint": "mock.py:1",
    "evidence": "MOCK_KEY = 'abc'",
    "fix": "Remove it",
    "references": ["CWE-798"],
    "confidence": "HIGH",
    "line": "mock.py:1"
}
print(json.dumps(finding), flush=True)
print(json.dumps({"done": True, "total": 1}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{
		Mode:     "whitebox",
		CodePath: dir,
		Checks:   []string{"secrets"},
	}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Title != "Mock finding" {
		t.Errorf("unexpected title: %s", result.Findings[0].Title)
	}
}

func TestPythonSpawner_RunEmptyEngine(t *testing.T) {
	dir := t.TempDir()

	script := `import json, sys
request = json.loads(sys.stdin.read())
print(json.dumps({"done": True, "total": 0}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{
		Mode:   "whitebox",
		Checks: []string{},
	}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Script that sleeps long enough to be cancelled
	script := `import time, json, sys
sys.stdin.read()
time.sleep(30)
print(json.dumps({"done": True, "total": 0}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{}}

	result := spawner.Run(ctx, req)
	if result.Err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestPythonSpawner_BadPythonBin(t *testing.T) {
	spawner := NewPythonSpawner("/nonexistent/python3", ".")
	req := ScanRequest{Mode: "whitebox", Checks: []string{}}

	result := spawner.Run(context.Background(), req)
	if result.Err == nil {
		t.Fatal("expected error from bad python binary")
	}
}

func TestPythonSpawner_MultipleFindings(t *testing.T) {
	dir := t.TempDir()

	script := `import json, sys
sys.stdin.read()
for i in range(5):
    finding = {
        "id": "",
        "title": f"Finding {i+1}",
        "severity": "MEDIUM",
        "source": "whitebox",
        "category": "test",
        "endpoint": f"file{i}.py:1",
        "evidence": f"issue {i+1}",
        "fix": "Fix it",
        "references": [],
        "confidence": "MEDIUM",
        "line": f"file{i}.py:1"
    }
    print(json.dumps(finding), flush=True)
print(json.dumps({"done": True, "total": 5}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(result.Findings))
	}
	for i, f := range result.Findings {
		expected := "Finding " + string(rune('1'+i))
		if f.Title != expected {
			// Just check they're all present
			if f.Source != models.SourceWhitebox {
				t.Errorf("finding %d: expected source whitebox, got %s", i, f.Source)
			}
		}
	}
}

func TestPythonSpawner_StderrLogging(t *testing.T) {
	dir := t.TempDir()

	// Script that writes to stderr (diagnostics) and stdout (findings)
	script := `import json, sys
sys.stdin.read()
print("[fendix-engine] starting check: secrets", file=sys.stderr, flush=True)
finding = {
    "id": "",
    "title": "Secret found",
    "severity": "CRITICAL",
    "source": "whitebox",
    "category": "secrets",
    "endpoint": "env.py:3",
    "evidence": "AWS_KEY = AKIA...",
    "fix": "Rotate key",
    "references": ["CWE-798"],
    "confidence": "HIGH",
    "line": "env.py:3"
}
print(json.dumps(finding), flush=True)
print("[fendix-engine] finished check: secrets", file=sys.stderr, flush=True)
print(json.dumps({"done": True, "total": 1}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}, Verbose: true}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_EngineCrash(t *testing.T) {
	dir := t.TempDir()

	// Script that crashes with exit code 1
	script := `import sys
sys.stdin.read()
sys.exit(1)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}}

	result := spawner.Run(context.Background(), req)
	if result.Err == nil {
		t.Fatal("expected error from engine crash")
	}
	// Should not have any findings
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings from crashed engine, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_DefaultValues(t *testing.T) {
	spawner := NewPythonSpawner("", "")
	if spawner.pythonBin != "python3" {
		t.Errorf("expected default pythonBin 'python3', got '%s'", spawner.pythonBin)
	}
	if spawner.engineDir != "python" {
		t.Errorf("expected default engineDir 'python', got '%s'", spawner.engineDir)
	}
}

func TestScanRequest_JSONSerialization(t *testing.T) {
	req := ScanRequest{
		Mode:     "whitebox",
		Spec:     "./openapi.yaml",
		CodePath: "./src",
		Language: "python",
		Checks:   []string{"secrets", "auth", "semgrep"},
		Verbose:  true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)
	for _, expected := range []string{`"mode":"whitebox"`, `"spec":"./openapi.yaml"`, `"code_path":"./src"`, `"checks":["secrets","auth","semgrep"]`} {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("JSON missing expected field: %s\ngot: %s", expected, jsonStr)
		}
	}
}

func TestScanRequest_OmitEmpty(t *testing.T) {
	req := ScanRequest{
		Mode:   "whitebox",
		Checks: []string{"secrets"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, `"spec"`) {
		t.Errorf("expected spec to be omitted when empty, got: %s", jsonStr)
	}
	if strings.Contains(jsonStr, `"code_path"`) {
		t.Errorf("expected code_path to be omitted when empty, got: %s", jsonStr)
	}
}
