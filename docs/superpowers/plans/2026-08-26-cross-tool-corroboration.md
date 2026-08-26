# Cross-Tool Corroboration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SARIF cross-tool corroboration reachable in the hosted product (attach SARIF at scan launch) and visible to users (public fields, badge, filter, collapse count).

**Architecture:** The engine's correlation predicate and proof-union fold are already hardened and are NOT re-opened. This cycle adds: per-tool collapsed counts folded into report metadata, two additive public `Finding` fields stamped from *restored* evidence, backend scan attachments with two-phase upload, persistence of the import accounting on `Scan`, and four UI surfaces.

**Tech Stack:** Go 1.x (engine), Django 5.2 + DRF (backend), Next.js 16 + TypeScript (frontend), Postgres 16, pytest, vitest.

**Spec:** [docs/superpowers/specs/2026-08-26-cross-tool-corroboration-design.md](../specs/2026-08-26-cross-tool-corroboration-design.md)

## Global Constraints

- Three repos: engine `Fendix/`, backend `fendix-backend/`, frontend `fendix_frontend/`. All work on `main`; never push `PreProduction`.
- `schema_version` stays `1`. Every new report key is `omitempty` / additive.
- The correlation predicate (`classify`, `independent`, `locationClose`) and the proof-union fold (`mergeScoringProvenance`) are **untouched**. Any task that edits them is wrong.
- Public corroboration fields are stamped in `stampDecisions` from `d.Evidence` (post-`Restore`), never projected through `evidence.ToFinding`.
- Import stats consolidate by normalized `ToolID` — the same key `independent()` uses.
- Engine: `gofmt` clean, `go test -race ./...` green. Backend: `ruff check`/`format`, full pytest. Frontend: `vitest` exit 0, `tsc --noEmit`.
- After any serializer/URL/view change: `make schema` → commit `openapi.json` → `npm run codegen` in the frontend → `make schema-check`.
- Engine dev binary: after `go build`, containers need `up -d --force-recreate` (file bind-mount inode changes), and a model/enum change needs `celery-scans` recreated.

---

## File Structure

**Engine**
- `internal/sarifimport/normalize.go` — add stats consolidation by tool.
- `internal/engine/crosstool.go` — return per-tool collapsed counts.
- `internal/engine/orchestrator.go` — fold counts into metadata; stamp public fields.
- `internal/models/finding.go` — two additive public fields.
- `internal/reporters/json.go` — `ImportedTool.Corroborated`.
- `internal/reporters/sarif.go` — emit `corroborating_tools` property.

**Backend**
- `scanning/validators.py` — SARIF version check in the structural gate.
- `scanning/serializers.py` — two-phase upload; `import_files`; new finding fields.
- `scanning/services.py` — `import_files` list in `build_command`; `Scan.imports` coercion + persist.
- `scanning/tasks.py` — cleanup iterates the list.
- `scanning/views.py` — unwind attachments on any create failure.
- `scanning/models.py` — `Scan.imports`, two `ScanFinding` columns, composite index.
- `scanning/filters.py` — `corroborated` filter.
- `scanning/reports.py` — regenerated reports carry `imports`.
- `runners/ingest.py` — the persistence twin.

**Frontend**
- `app/components/CorroborationBadge.tsx` — new.
- `app/components/new-scan/AttachSarifSection.tsx` — new.
- `app/[locale]/scans/[id]/page.tsx`, `app/[locale]/findings/page.tsx`, `app/[locale]/findings/[id]/page.tsx` — badge.
- `app/lib/api.ts`, `app/types/index.ts`, `messages/{en,ar}.json`.

---

## Task 1: Consolidate import stats by tool identity

**Files:**
- Modify: `go/internal/sarifimport/normalize.go`
- Test: `go/internal/sarifimport/normalize_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Normalize` still returns `([]evidence.Evidence, ImportStats, error)`, but `ImportStats.Tools` now holds exactly one `ToolStat` per normalized tool. `ToolStat` gains `Corroborated int \`json:"corroborated,omitempty"\``.

- [ ] **Step 1: Write the failing test**

Add to `normalize_test.go`:

```go
func TestNormalize_ConsolidatesStatsByTool(t *testing.T) {
	// Two runs, same tool, same version → ONE stat block.
	doc := &Document{Version: SupportedVersion, Runs: []Run{
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "a"}, Locations: loc("a.py", 1, 0)}},
		},
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "b"}, Locations: loc("b.py", 2, 0)}},
		},
	}}
	_, stats, err := Normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Tools) != 1 {
		t.Fatalf("two runs of one tool must consolidate to one block, got %d", len(stats.Tools))
	}
	if stats.Tools[0].Tool != "codeql" || stats.Tools[0].Results != 2 {
		t.Fatalf("got %+v, want codeql with 2 results", stats.Tools[0])
	}
	if stats.Tools[0].Version != "2.19.0" {
		t.Fatalf("agreeing versions must be retained, got %q", stats.Tools[0].Version)
	}
}

func TestNormalize_MixedVersionsClearVersion(t *testing.T) {
	doc := &Document{Version: SupportedVersion, Runs: []Run{
		{Tool: Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "a"}, Locations: loc("a.py", 1, 0)}}},
		{Tool: Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.20.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "b"}, Locations: loc("b.py", 2, 0)}}},
	}}
	_, stats, _ := Normalize(doc)
	if len(stats.Tools) != 1 {
		t.Fatalf("still one block per TOOL, got %d", len(stats.Tools))
	}
	if stats.Tools[0].Version != "" {
		t.Fatalf("disagreeing versions must clear the field, got %q", stats.Tools[0].Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/sarifimport/ -run "TestNormalize_Consolidates|TestNormalize_MixedVersions" -v`
Expected: FAIL — `two runs of one tool must consolidate to one block, got 2`.

- [ ] **Step 3: Implement consolidation**

In `normalize.go`, add `Corroborated` to `ToolStat`:

```go
type ToolStat struct {
	Tool       string `json:"tool"`
	Version    string `json:"version,omitempty"`
	Results    int    `json:"results"`
	Suppressed int    `json:"suppressed,omitempty"`
	NoLocation int    `json:"no_location,omitempty"`
	// Corroborated counts imported findings that strong cross-tool
	// correlation collapsed into a native representative. Stamped by the
	// orchestrator AFTER correlation (Normalize runs before it), so it is
	// always 0 here.
	Corroborated int `json:"corroborated,omitempty"`
}
```

Replace the per-run append in `Normalize` with an accumulate-then-consolidate pass:

```go
func Normalize(doc *Document) ([]evidence.Evidence, ImportStats, error) {
	if doc == nil {
		return nil, ImportStats{}, fmt.Errorf("nil SARIF document")
	}
	var out []evidence.Evidence
	// Accumulate by normalized tool identity — the SAME key independence
	// uses in engine.CorrelateCrossTool. One SARIF document may carry many
	// runs of one tool; the correlator treats them as one tool, so the
	// accounting must too, or a per-tool corroborated count would have no
	// unambiguous block to land in.
	byTool := map[string]*ToolStat{}
	var order []string
	for _, run := range doc.Runs {
		toolID := NormalizeToolName(run.Tool.Driver.Name)
		version := driverVersion(run.Tool.Driver)
		st, seen := byTool[toolID]
		if !seen {
			st = &ToolStat{Tool: toolID, Version: version}
			byTool[toolID] = st
			order = append(order, toolID)
		} else if st.Version != version {
			// Mixed versions of one tool are pathological; the tool name is
			// what carries provenance, so drop the ambiguous version rather
			// than assert one of them.
			st.Version = ""
		}
		rules := indexRules(run.Tool.Driver.Rules)
		for _, res := range run.Results {
			if isSuppressed(res) {
				st.Suppressed++
				continue
			}
			ev := normalizeResult(res, rules, run, toolID, version)
			if ev.Endpoint == "unknown" {
				st.NoLocation++
			}
			st.Results++
			out = append(out, ev)
		}
	}
	stats := ImportStats{Tools: make([]ToolStat, 0, len(order))}
	for _, id := range order {
		stats.Tools = append(stats.Tools, *byTool[id])
	}
	return out, stats, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd go && go test ./internal/sarifimport/ -v`
Expected: PASS, including the pre-existing `TestMultiRunDocument` and `TestRealWorldFixtures` (both already assert per-tool totals reconcile).

- [ ] **Step 5: Commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/Fendix
gofmt -w go/internal/sarifimport/normalize.go go/internal/sarifimport/normalize_test.go
git add go/internal/sarifimport/
git commit -m "feat(import): consolidate import stats by normalized tool identity"
```

---

## Task 2: Per-tool collapsed counts into report metadata

**Files:**
- Modify: `go/internal/engine/crosstool.go`, `go/internal/engine/orchestrator.go`, `go/internal/reporters/json.go`
- Test: `go/internal/engine/crosstool_test.go`, `go/internal/engine/orchestrator_import_test.go`

**Interfaces:**
- Consumes: `sarifimport.ToolStat.Corroborated` (Task 1).
- Produces: `CorrelateCrossTool(evs []evidence.Evidence) ([]evidence.Evidence, map[string]int)` — second return is collapsed count keyed by normalized `ToolID`. `reporters.ImportedTool` gains `Corroborated int`.

- [ ] **Step 1: Write the failing test**

Add to `crosstool_test.go`:

```go
func TestCorrelateCrossTool_ReturnsPerToolCollapsedCounts(t *testing.T) {
	// CodeQL collapses 2, Semgrep 1 — a scalar return cannot express this.
	evs := []evidence.Evidence{
		nativeSQLi("app/views.py:100", "100"),
		nativeSQLi("app/db.py:200", "200"),
		nativeSQLi("app/api.py:300", "300"),
		importedSQLi("codeql", "app/views.py:102", "102"),
		importedSQLi("codeql", "app/db.py:201", "201"),
		importedSQLi("semgrep", "app/api.py:301", "301"),
	}
	_, counts := CorrelateCrossTool(evs)
	if counts["codeql"] != 2 {
		t.Fatalf("codeql collapsed count = %d, want 2", counts["codeql"])
	}
	if counts["semgrep"] != 1 {
		t.Fatalf("semgrep collapsed count = %d, want 1", counts["semgrep"])
	}
}

func TestCorrelateCrossTool_NoImportsReturnsNilCounts(t *testing.T) {
	_, counts := CorrelateCrossTool([]evidence.Evidence{nativeSQLi("app/views.py:100", "100")})
	if len(counts) != 0 {
		t.Fatalf("no imports → no counts, got %v", counts)
	}
}
```

Note: `nativeSQLi` and `importedSQLi` already exist in `crosstool_test.go`. Three distinct native findings are used because `Deduplicate` is not involved here but each pair needs its own location.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/engine/ -run TestCorrelateCrossTool_Returns -v`
Expected: FAIL to compile — `assignment mismatch: 2 variables but CorrelateCrossTool returns 1 value`.

- [ ] **Step 3: Change the signature and count collapses**

In `crosstool.go`, change the signature and both early returns, and count in the collapse loop:

```go
func CorrelateCrossTool(evs []evidence.Evidence) ([]evidence.Evidence, map[string]int) {
```

Early returns become `return evs, nil` (two sites: the no-imports guard and the no-corroboration guard).

In the representative-selection loop, count by the imported side's tool:

```go
	drop := make([]bool, len(evs))
	collapsedByTool := map[string]int{}
	for imp, natives := range strongNative {
		drop[imp] = true
		rep := natives[0]
		evs[rep].References = mergeRefs(evs[rep].References, evs[imp].References)
		collapsedByTool[metas[imp].tool]++
	}
```

and the final return becomes `return out, collapsedByTool`.

- [ ] **Step 4: Update the caller in `finalize` and fold into metadata**

In `orchestrator.go`, `finalize` currently begins `evid = CorrelateCrossTool(evid)`. Replace with:

```go
	evid, collapsedByTool := CorrelateCrossTool(evid)
	// Fold the collapsed counts into the per-tool import accounting.
	// meta.Imports is a slice, so mutating its elements is visible to
	// renderReport below even though meta itself is passed by value.
	// Task 1 guarantees exactly one block per tool, so each count has an
	// unambiguous home.
	for i := range meta.Imports {
		if n, ok := collapsedByTool[meta.Imports[i].Tool]; ok {
			meta.Imports[i].Corroborated = n
		}
	}
	findings := evidence.ToFindings(evid)
```

In `reporters/json.go`, add the field to `ImportedTool`:

```go
type ImportedTool struct {
	Tool       string `json:"tool"`
	Version    string `json:"version,omitempty"`
	Results    int    `json:"results"`
	Suppressed int    `json:"suppressed,omitempty"`
	NoLocation int    `json:"no_location,omitempty"`
	// Corroborated: imported findings that strong cross-tool correlation
	// collapsed into a native representative. Lets a report explain why N
	// uploaded findings produced fewer than N rows.
	Corroborated int `json:"corroborated,omitempty"`
}
```

In `orchestrator.go`'s `loadImports`, carry the field through the `ToolStat` → `ImportedTool` copy:

```go
			tools = append(tools, reporters.ImportedTool{
				Tool:         t.Tool,
				Version:      t.Version,
				Results:      t.Results,
				Suppressed:   t.Suppressed,
				NoLocation:   t.NoLocation,
				Corroborated: t.Corroborated,
			})
```

`loadImports` must also consolidate across FILES, since Task 1 only consolidates within one document. Replace its accumulation of `tools` with a fold keyed by tool, mirroring Task 1:

```go
func loadImports(paths []string) ([]evidence.Evidence, []reporters.ImportedTool, error) {
	var evid []evidence.Evidence
	byTool := map[string]*reporters.ImportedTool{}
	var order []string
	for _, p := range paths {
		var data []byte
		var err error
		if p == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(p)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading SARIF import %s: %w", p, err)
		}
		doc, err := sarifimport.Parse(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		evs, stats, err := sarifimport.Normalize(doc)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		evid = append(evid, evs...)
		for _, t := range stats.Tools {
			cur, seen := byTool[t.Tool]
			if !seen {
				cur = &reporters.ImportedTool{Tool: t.Tool, Version: t.Version}
				byTool[t.Tool] = cur
				order = append(order, t.Tool)
			} else if cur.Version != t.Version {
				cur.Version = ""
			}
			cur.Results += t.Results
			cur.Suppressed += t.Suppressed
			cur.NoLocation += t.NoLocation
		}
	}
	tools := make([]reporters.ImportedTool, 0, len(order))
	for _, id := range order {
		tools = append(tools, *byTool[id])
	}
	return evid, tools, nil
}
```

- [ ] **Step 5: Add the two-file consolidation test**

Add to `orchestrator_import_test.go`:

```go
// TestRunImport_ConsolidatesAcrossFiles: the same tool attached twice must
// produce ONE metadata block, or a per-tool corroborated count has no
// unambiguous home.
func TestRunImport_ConsolidatesAcrossFiles(t *testing.T) {
	cfg := importConfig(t, "", codeqlFixture, codeqlFixture)
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 0 {
		t.Fatalf("RunImport = %d, want 0", code)
	}
	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Metadata.Imports) != 1 {
		t.Fatalf("one tool attached twice must consolidate to one block, got %d", len(report.Metadata.Imports))
	}
	if report.Metadata.Imports[0].Results != 4 {
		t.Fatalf("results must sum across files, got %d want 4", report.Metadata.Imports[0].Results)
	}
}
```

- [ ] **Step 6: Run the engine suite**

Run: `cd go && go test ./internal/engine/ ./internal/sarifimport/ ./internal/reporters/ -v -run "CrossTool|RunImport|Import"`
Expected: PASS. The golden test `TestRunImport_GoldenReport` will FAIL because metadata changed — regenerate it in the next step after reviewing the diff.

- [ ] **Step 7: Review and regenerate the golden report**

Run: `cd go && go test ./internal/engine/ -run TestRunImport_GoldenReport` and read the failure.
Then: `cd go && UPDATE_GOLDEN=1 go test ./internal/engine -run TestRunImport_GoldenReport`
Verify with `git diff go/internal/engine/testdata/import_codeql.golden.json` that the ONLY change is additive (no `corroborated` key appears, because the standalone fixture has no native findings to corroborate against — if one appears, correlation fired unexpectedly and must be investigated before proceeding).

- [ ] **Step 8: Commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/Fendix
gofmt -w go/internal/engine/ go/internal/reporters/ go/internal/sarifimport/
go test -race ./... 2>&1 | tail -5
git add go/
git commit -m "feat(import): per-tool collapsed counts in report metadata"
```

---

## Task 3: Publish corroboration on the Finding contract

**Files:**
- Modify: `go/internal/models/finding.go`, `go/internal/engine/orchestrator.go`, `go/internal/reporters/sarif.go`
- Test: `go/internal/engine/crosstool_dedup_test.go`, `go/internal/reporters/sarif_test.go`

**Interfaces:**
- Consumes: `evidence.Evidence.CrossToolCorroborated` / `.CorroboratingTools` (already exist, internal).
- Produces: `models.Finding.CrossToolCorroborated bool` (json `cross_tool_corroborated,omitempty`) and `.CorroboratingTools []string` (json `corroborating_tools,omitempty`).

- [ ] **Step 1: Write the failing test — the load-bearing regression**

Add to `crosstool_dedup_test.go`:

```go
// TestPublicCorroborationSurvivesUncorroboratedDuplicate is the reason the
// public fields are stamped in stampDecisions from the RESTORED evidence
// rather than projected through evidence.ToFinding. Projecting would publish
// whichever duplicate won findingLess in dedup — reintroducing exactly the
// erasure the proof-union fold fixed, but on a public surface this time.
func TestPublicCorroborationSurvivesUncorroboratedDuplicate(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/admin.py:50", "50") // dedup-equivalent, never stamped
	b := importedSQLi("codeql", "app/views.py:102", "102")

	evid, _ := CorrelateCrossTool([]evidence.Evidence{a, aPrime, b})
	prov := evidence.NewProvenanceIndex(evid)
	findings := evidence.ToFindings(evid)
	findings = Deduplicate(findings)
	stampDecisions(findings, prov, "HIGH", decision.Options{EnforceConfidence: true})

	if len(findings) != 1 {
		t.Fatalf("want one representative, got %d", len(findings))
	}
	if !findings[0].CrossToolCorroborated {
		t.Fatal("the PUBLIC field must survive an uncorroborated dedup duplicate")
	}
	if strings.Join(findings[0].CorroboratingTools, ",") != "codeql" {
		t.Fatalf("public tools = %v, want [codeql]", findings[0].CorroboratingTools)
	}
}

// TestUncorroboratedFindingOmitsPublicFields keeps existing reports
// byte-identical: both fields are omitempty and must not appear.
func TestUncorroboratedFindingOmitsPublicFields(t *testing.T) {
	f := nativeSQLi("app/views.py:100", "100").ToFinding()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "cross_tool_corroborated") ||
		strings.Contains(string(raw), "corroborating_tools") {
		t.Fatalf("uncorroborated findings must omit both keys: %s", raw)
	}
}
```

Add `"encoding/json"` and `"github.com/Abdel-RahmanSaied/Fendix/internal/decision"` to that file's imports if absent.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd go && go test ./internal/engine/ -run "TestPublicCorroboration|TestUncorroboratedFindingOmits" -v`
Expected: FAIL to compile — `f.CrossToolCorroborated undefined`.

- [ ] **Step 3: Add the public fields**

In `internal/models/finding.go`, after `ProvenPath`:

```go
	// CrossToolCorroborated / CorroboratingTools publish the verdict of
	// engine.CorrelateCrossTool: an INDEPENDENT tool reported the same
	// normalized weakness at the same normalized location. Both are
	// omitempty, so a report with no corroboration is byte-identical to one
	// produced before these existed.
	//
	// STAMPED, NOT PROJECTED. evidence.ToFinding deliberately does not carry
	// them; engine.stampDecisions writes them from the post-Restore evidence
	// so the value is the PROOF-UNION over the dedup group, not whichever
	// duplicate happened to become the group primary.
	CrossToolCorroborated bool     `json:"cross_tool_corroborated,omitempty"`
	CorroboratingTools    []string `json:"corroborating_tools,omitempty"`
```

- [ ] **Step 4: Stamp them in `stampDecisions`**

In `orchestrator.go`:

```go
	for i := range decisions {
		d := decisions[i]
		findings[i].Status = string(d.Status)
		findings[i].ConfidenceScore = d.Score.Value
		findings[i].ConfidenceBand = string(d.Score.Band)
		findings[i].ConfidenceReasons = d.Score.Reasons
		// d.Evidence is post-Restore, so these carry the proof-union value.
		findings[i].CrossToolCorroborated = d.Evidence.CrossToolCorroborated
		findings[i].CorroboratingTools = d.Evidence.CorroboratingTools
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd go && go test ./internal/engine/ -run "TestPublicCorroboration|TestUncorroboratedFindingOmits" -v`
Expected: PASS.

- [ ] **Step 6: Emit corroboration in the SARIF reporter**

Read `internal/reporters/sarif.go` and find where result properties are built (the same place `Status` / confidence fields are emitted). Add the tools list as a property so re-export into GitHub keeps provenance:

```go
	if len(f.CorroboratingTools) > 0 {
		props["corroborating_tools"] = f.CorroboratingTools
	}
```

Add a test in `sarif_test.go` asserting a corroborated finding's SARIF result carries `corroborating_tools` and an uncorroborated one does not.

- [ ] **Step 7: Full engine suite + commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/Fendix/go
gofmt -l . && go test -race ./... 2>&1 | grep -v "^ok" | head
```
Expected: no gofmt output, no failures. Regenerate the golden file if the standalone fixture output changed (it should NOT — no corroboration in a single-tool standalone import).

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/Fendix
git add go/
git commit -m "feat(import): publish cross-tool corroboration on the finding contract"
```

---

## Task 4: Backend — SARIF version check in the structural gate

**Files:**
- Modify: `backend/scanning/validators.py`
- Test: `backend/scanning/tests/test_sarif_import.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_and_validate_sarif(raw: bytes) -> dict` now raises `ValidationError(code="sarif_unsupported_version")` for any `version != "2.1.0"`.

- [ ] **Step 1: Write the failing test**

In `test_sarif_import.py`, class `TestParseAndValidateSarif`, REPLACE `test_engine_owns_version_validation` with:

```python
    def test_rejects_unsupported_version(self):
        """A 2.0.0 attachment must be refused at the gate. Deferring this to
        the engine is safe for a standalone import (it fails its own cheap
        scan) but not for a merged scan, where it would kill the native
        results too."""
        with pytest.raises(Exception) as exc:  # noqa: PT011
            parse_and_validate_sarif(b'{"version":"2.0.0","runs":[]}')
        assert exc.value.detail[0].code == "sarif_unsupported_version"

    def test_accepts_supported_version(self):
        assert parse_and_validate_sarif(b'{"version":"2.1.0","runs":[]}')["runs"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py -k version -v`
Expected: FAIL — `DID NOT RAISE`.

- [ ] **Step 3: Add the check**

In `validators.py`, add the constant near `MAX_SARIF_UPLOAD_BYTES`:

```python
# The only SARIF version the engine accepts (go/internal/sarifimport:
# SupportedVersion). Checked HERE as well as in the engine: for a merged scan
# a bad attachment would otherwise kill an otherwise-good scan at spawn time,
# after quota was spent. One shared constant is not meaningfully a second
# contract; the engine stays authoritative for everything else.
SUPPORTED_SARIF_VERSION = "2.1.0"
```

and in `parse_and_validate_sarif`, after the `runs` check:

```python
    version = doc.get("version")
    if version != SUPPORTED_SARIF_VERSION:
        raise serializers.ValidationError(
            _("Unsupported SARIF version %(v)s — Fendix supports %(s)s.")
            % {"v": version or "(missing)", "s": SUPPORTED_SARIF_VERSION},
            code="sarif_unsupported_version",
        )
```

- [ ] **Step 4: Run tests**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py -v`
Expected: PASS (33+ tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend
docker compose exec -T django python -m ruff format scanning/
git add backend/scanning/
git commit -m "fix(import): reject unsupported SARIF versions at the upload gate"
```

---

## Task 5: Backend — two-phase upload with unwind

**Files:**
- Modify: `backend/scanning/serializers.py` (`ImportScanSerializer.validate`), `backend/scanning/views.py` (`import_sarif`)
- Test: `backend/scanning/tests/test_sarif_import.py`

**Interfaces:**
- Consumes: `write_import_upload`, `delete_import_upload` (exist).
- Produces: `ImportScanSerializer` validates everything before writing anything. `config["import_files"]` is a LIST (single entry for this endpoint) — replaces `config["import_file"]`.

- [ ] **Step 1: Write the failing tests**

```python
    def test_bad_artifact_path_does_not_orphan_the_upload(self):
        """REGRESSION: the serializer wrote the SARIF before validating the
        artifact paths below it, so a bad baseline orphaned an upload until
        the hourly janitor swept it."""
        user = _pro(UserFactory())
        before = _jail_upload_count(user)
        ser = _serializer(user, {"file": _upload(), "baseline": "../escape.json"})
        assert not ser.is_valid()
        assert _jail_upload_count(user) == before, "a rejected request must leave no file behind"

    def test_config_uses_import_files_list(self):
        user = _pro(UserFactory())
        ser = _serializer(user, {"file": _upload()})
        assert ser.is_valid(), ser.errors
        scan = ser.save()
        assert isinstance(scan.config["import_files"], list)
        assert len(scan.config["import_files"]) == 1
        assert "import_file" not in scan.config
```

Add this module-level helper next to `_upload`:

```python
def _jail_upload_count(user) -> int:
    d = os.path.join(user_jail_root(user), IMPORT_UPLOAD_SUBDIR)
    return len(os.listdir(d)) if os.path.isdir(d) else 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py -k "orphan or import_files" -v`
Expected: FAIL — orphan count is 1, and `KeyError: 'import_files'`.

- [ ] **Step 3: Reorder to validate-then-write**

In `ImportScanSerializer.validate`, move the artifact-path loop ABOVE the write, and store a list:

```python
        upload = attrs.pop("file")
        check_sarif_upload_size(upload.size)
        upload.seek(0)
        raw = upload.read()
        try:
            doc = parse_and_validate_sarif(raw)
        except serializers.ValidationError as exc:
            raise serializers.ValidationError({"file": exc.detail}) from exc
        attrs["_run_count"] = len(doc.get("runs") or [])

        # PHASE ONE — validate everything else BEFORE writing anything. A
        # rejection after the write leaves an orphan in the jail with no Scan
        # row to hang cleanup off; it survives until the hourly janitor sweep.
        for field, must_exist in (("baseline", True), ("ignore", True), ("save_baseline", False)):
            value = attrs.get(field)
            if value:
                attrs[field] = validate_artifact_path(value, user=user, must_exist=must_exist)

        # PHASE TWO — nothing can reject the request now, so write.
        attrs["import_files"] = [write_import_upload(raw, user=user)]
        return attrs
```

Update `create` to drop `_run_count` only (it already does) — `import_files` flows into config unchanged.

- [ ] **Step 4: Unwind on any post-write failure in the view**

In `views.py`, `import_sarif`, wrap the quota/save block so a failure after `validate()` wrote files cleans them up:

```python
        owner = serializer.validated_data.get("organization") or request.user
        written = list(serializer.validated_data.get("import_files") or [])

        def _unwind() -> None:
            for rel in written:
                delete_import_upload(rel, user=request.user)

        try:
            with transaction.atomic():
                enforce_concurrent_limit(owner)
                consume_scan_quota(owner)
                scan = serializer.save()
        except Exception:
            # Quota, concurrency or persist failed AFTER the upload was
            # written. execute_scan (which owns cleanup) never ran, so the
            # files would leak to the janitor.
            _unwind()
            raise
```

and in the existing dispatch-failure branch, replace the single delete with `_unwind()`.

- [ ] **Step 5: Update every remaining `import_file` reference**

Grep and update: `backend/scanning/services.py` (`build_command`), `backend/scanning/tasks.py` (cleanup), `backend/scanning/validators.py` (janitor `protected` set). Each moves from a string to a list:

```python
# services.build_command
    if scan.mode == ScanMode.IMPORT:
        import_files = cfg.get("import_files") or []
        if not isinstance(import_files, list) or not import_files:
            raise ValueError("import scan has no uploaded SARIF document (config['import_files'] is empty)")
        args = [_BINARY, "import"]
        for rel in import_files:
            args.append(absolute_artifact_path(rel, user=scan.user))
        args += ["--format", "json"]
        ...
```

```python
# tasks._cleanup_uploaded_spec
        for rel in config.get("import_files") or []:
            delete_import_upload(rel, user=scan.user)
```

```python
# validators.sweep_orphaned_spec_uploads, protected set
        for rel in (cfg.get("import_files") or []):
            if isinstance(rel, str):
                protected.add((str(user_id), rel))
```

Update the existing tests in `test_sarif_import.py` that reference `import_file` / `config["import_file"]` to the list form.

- [ ] **Step 6: Run the full backend suite**

Run: `docker compose exec -T django python -m pytest -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend
docker compose exec -T django python -m ruff format scanning/ && docker compose exec -T django python -m ruff check scanning/
git add backend/scanning/
git commit -m "fix(import): two-phase upload with unwind; unify on config['import_files']"
```

---

## Task 6: Backend — scan attachments (`import_files` on launch)

**Files:**
- Modify: `backend/scanning/serializers.py` (`LaunchScanSerializer`), `backend/scanning/services.py` (`build_command`), `backend/scanning/views.py` (`create`)
- Test: `backend/scanning/tests/test_sarif_import.py`

**Interfaces:**
- Consumes: Task 5's `import_files` config convention and two-phase rule.
- Produces: `POST /api/scans` accepts up to 5 `import_files`; `build_command` emits one `--import <abs>` per attachment for scanning modes.

- [ ] **Step 1: Write the failing tests**

```python
class TestScanAttachments:
    def test_launch_with_attachments_stores_list(self):
        user = _pro(UserFactory())
        request = APIRequestFactory().post("/api/scans")
        request.user = user
        ser = LaunchScanSerializer(
            data={"mode": ScanMode.WHITEBOX, "code": "src", "import_files": [_upload(), _upload("semgrep.sarif")]},
            context={"request": request},
        )
        assert ser.is_valid(), ser.errors
        scan = ser.save()
        assert len(scan.config["import_files"]) == 2

    def test_build_command_emits_one_import_per_attachment(self):
        user = UserFactory()
        rels = [write_import_upload(SARIF_BYTES, user=user), write_import_upload(SARIF_BYTES, user=user)]
        scan = Scan.objects.create(
            user=user, mode=ScanMode.WHITEBOX, status=ScanStatus.QUEUED,
            config={"code": "/tmp/x", "import_files": rels},
        )
        cmd = build_command(scan)
        assert cmd[1] == "scan"
        assert cmd.count("--import") == 2
        for rel in rels:
            assert os.path.join(user_jail_root(user), rel) in cmd

    def test_too_many_attachments_rejected(self):
        user = _pro(UserFactory())
        request = APIRequestFactory().post("/api/scans")
        request.user = user
        ser = LaunchScanSerializer(
            data={"mode": ScanMode.WHITEBOX, "code": "src", "import_files": [_upload() for _ in range(6)]},
            context={"request": request},
        )
        assert not ser.is_valid()
        assert "import_files" in ser.errors

    def test_attachments_rejected_for_import_mode(self):
        """mode=import uses the dedicated endpoint; two ways to express one
        thing is a bug generator."""
        user = _pro(UserFactory())
        request = APIRequestFactory().post("/api/scans")
        request.user = user
        ser = LaunchScanSerializer(
            data={"mode": ScanMode.IMPORT, "import_files": [_upload()]},
            context={"request": request},
        )
        assert not ser.is_valid()

    def test_free_plan_cannot_attach(self):
        user = UserFactory()
        request = APIRequestFactory().post("/api/scans")
        request.user = user
        ser = LaunchScanSerializer(
            data={"mode": ScanMode.WHITEBOX, "code": "src", "import_files": [_upload()]},
            context={"request": request},
        )
        from rest_framework.exceptions import PermissionDenied

        with pytest.raises(PermissionDenied):
            ser.is_valid(raise_exception=True)
```

- [ ] **Step 2: Run to verify they fail**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py::TestScanAttachments -v`
Expected: FAIL — `import_files` is not a serializer field, so it is ignored and `KeyError`.

- [ ] **Step 3: Add the field and validation**

In `LaunchScanSerializer`, add near `spec_file`:

```python
    # SARIF attachments (cross-tool corroboration). Foreign findings merge
    # into THIS scan before correlation, so a native finding at the same
    # weakness + location becomes independent corroboration.
    import_files = serializers.ListField(
        child=serializers.FileField(),
        required=False,
        allow_empty=True,
        max_length=MAX_SCAN_ATTACHMENTS,
    )
```

with the constant at module scope:

```python
# Bounded so the synchronous parse cost on the web worker stays predictable.
# Five covers a realistic CI fan-in (CodeQL + Semgrep + Trivy + two more).
MAX_SCAN_ATTACHMENTS = 5
```

In `LaunchScanSerializer.validate`, after the org/runner resolution and BEFORE any write, add the two-phase block:

```python
        attachments = attrs.pop("import_files", None) or []
        if attachments:
            if mode == ScanMode.IMPORT:
                raise serializers.ValidationError(
                    {"import_files": [_("Use POST /api/scans/import for a standalone SARIF import.")]}
                )
            from subscriptions.permissions import require_feature

            require_feature(organization or user, "sarif_import")
            # PHASE ONE — read and validate every attachment; write none.
            verified: list[bytes] = []
            for idx, upload in enumerate(attachments):
                check_sarif_upload_size(upload.size)
                upload.seek(0)
                raw = upload.read()
                try:
                    parse_and_validate_sarif(raw)
                except serializers.ValidationError as exc:
                    raise serializers.ValidationError(
                        {"import_files": [_("Attachment %(n)d: %(e)s") % {"n": idx + 1, "e": exc.detail[0]}]}
                    ) from exc
                verified.append(raw)
            attrs["_verified_attachments"] = verified
```

`mode` is already read earlier in `validate`; if not, read it as `attrs.get("mode")` before this block.

At the END of `validate` (after every other check that can raise), phase two:

```python
        verified = attrs.pop("_verified_attachments", None)
        if verified:
            written: list[str] = []
            try:
                for raw in verified:
                    written.append(write_import_upload(raw, user=user))
            except Exception:
                for rel in written:
                    delete_import_upload(rel, user=user)
                raise
            attrs["import_files"] = written
```

Import `delete_import_upload` in `serializers.py`.

- [ ] **Step 4: Emit the flags in `build_command`**

In the non-import branch of `build_command`, after the existing `_flag` calls:

```python
    # SARIF attachments merge into this scan before cross-tool correlation.
    for rel in cfg.get("import_files") or []:
        args.extend(["--import", absolute_artifact_path(rel, user=scan.user)])
```

- [ ] **Step 5: Unwind attachments in `ScanViewSet.create`**

Mirror Task 5's `_unwind` in `create`: capture `serializer.validated_data.get("import_files")`, delete them if quota/concurrency/save raises, and in the existing dispatch-failure branch alongside `delete_spec_upload`.

- [ ] **Step 6: Run the suite**

Run: `docker compose exec -T django python -m pytest -q`
Expected: all pass.

- [ ] **Step 7: Sync the contract and commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend
make schema && make schema-check
docker compose exec -T django python -m ruff format scanning/
git add backend/
git commit -m "feat(scans): attach SARIF reports at launch for cross-tool corroboration"
```

---

## Task 7: Backend — persist and expose the corroboration fields

**Files:**
- Modify: `backend/scanning/models.py`, `backend/scanning/services.py` (`_finding_defaults`), `backend/scanning/serializers.py` (`FindingSerializer`), `backend/scanning/filters.py`
- Test: `backend/scanning/tests/test_sarif_import.py`

**Interfaces:**
- Consumes: engine fields from Task 3.
- Produces: `ScanFinding.cross_tool_corroborated` (bool), `.corroborating_tools` (JSON list); `?corroborated=true` filter.

- [ ] **Step 1: Write the failing test**

```python
    def test_corroboration_persisted_from_report(self):
        user = UserFactory()
        rel = write_import_upload(SARIF_BYTES, user=user)
        scan = self._scan(user, import_files=[rel])
        report = json.dumps({
            "metadata": {"target": "", "mode": "import", "version": "v2.1.0"},
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "sources": {"blackbox": 0, "whitebox": 0, "correlated": 0},
            "total": 1,
            "findings": [{
                "id": "SEC-001", "title": "SQLi", "severity": "HIGH", "source": "whitebox",
                "category": "injection", "endpoint": "app/views.py:100", "confidence": "HIGH",
                "cross_tool_corroborated": True, "corroborating_tools": ["codeql", "semgrep"],
            }],
        })
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=report, stderr="")
        with patch("scanning.services.FendixEngine._spawn", return_value=completed):
            FendixEngine().run(scan.id)
        f = ScanFinding.objects.get(scan=scan)
        assert f.cross_tool_corroborated is True
        assert f.corroborating_tools == ["codeql", "semgrep"]

    def test_corroborating_tools_coerced_defensively(self):
        """Engine output is trusted but bounded, like every other coercion."""
        from scanning.services import _finding_defaults

        d = _finding_defaults({"corroborating_tools": ["ok", 123, "x" * 200], "cross_tool_corroborated": "yes"})
        assert d["corroborating_tools"] == ["ok", "x" * 64]
        assert d["cross_tool_corroborated"] is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py -k corrobor -v`
Expected: FAIL — no such model field.

- [ ] **Step 3: Add the columns and index**

In `models.py`, `ScanFinding`, near `proven_path`:

```python
    # Cross-tool corroboration (SARIF import): an INDEPENDENT tool reported
    # the same normalized weakness at the same normalized location. External
    # agreement — never a native Fendix verification claim.
    cross_tool_corroborated = models.BooleanField(
        default=False,
        help_text=_("True when an independent tool confirmed this finding's weakness and location."),
    )
    corroborating_tools = models.JSONField(default=list, blank=True)
```

In its `Meta.indexes`, alongside `finding_scan_severity_idx`:

```python
            # Composite, not a bare boolean: a two-value column has too little
            # selectivity for Postgres to prefer a standalone index, and
            # findings are always queried within a scan scope.
            models.Index(fields=["scan", "cross_tool_corroborated"], name="finding_scan_corrob_idx"),
```

- [ ] **Step 4: Coerce in `_finding_defaults`**

```python
        "cross_tool_corroborated": payload.get("cross_tool_corroborated") is True,
        "corroborating_tools": [
            str(t)[:64] for t in (payload.get("corroborating_tools") or [])[:16] if isinstance(t, str)
        ],
```

- [ ] **Step 5: Expose and filter**

Add both names to `FindingSerializer.Meta.fields`. In `filters.py`:

```python
class ScanFindingFilter(filters.FilterSet):
    ...
    corroborated = filters.BooleanFilter(field_name="cross_tool_corroborated")
```
and add `"corroborated"` to `Meta.fields`.

- [ ] **Step 6: Migrate, test, commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend
docker compose exec -T django python manage.py makemigrations scanning
docker compose exec -T django python manage.py migrate
docker compose exec -T django python -m pytest -q
make schema && make schema-check
git add backend/
git commit -m "feat(findings): persist and expose cross-tool corroboration"
```

---

## Task 8: Backend — persist the import accounting on Scan

**Files:**
- Modify: `backend/scanning/models.py`, `backend/scanning/services.py`, `backend/runners/ingest.py`, `backend/scanning/serializers.py` (`ScanMetaSerializer`), `backend/scanning/reports.py`
- Test: `backend/scanning/tests/test_sarif_import.py`

**Interfaces:**
- Consumes: `metadata.imports` from Task 2.
- Produces: `Scan.imports` (JSON list of `{tool, version?, results, suppressed?, no_location?, corroborated?}`), exposed as `imports` on the scan serializer and present in regenerated reports.

- [ ] **Step 1: Write the failing test**

```python
    def test_scan_imports_persisted_and_regenerated(self):
        user = UserFactory()
        rel = write_import_upload(SARIF_BYTES, user=user)
        scan = self._scan(user, import_files=[rel])
        report = json.dumps({
            "metadata": {
                "target": "", "mode": "import", "version": "v2.1.0",
                "imports": [{"tool": "codeql", "version": "2.19.0", "results": 5, "corroborated": 2}],
            },
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "sources": {"blackbox": 0, "whitebox": 0, "correlated": 0},
            "total": 0, "findings": [],
        })
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=report, stderr="")
        with patch("scanning.services.FendixEngine._spawn", return_value=completed):
            FendixEngine().run(scan.id)
        scan.refresh_from_db()
        assert scan.imports == [{"tool": "codeql", "version": "2.19.0", "results": 5, "corroborated": 2}]

        # And a regenerated report must carry it — reports.py rebuilds
        # metadata from Scan columns, so a missing column silently drops it.
        from scanning.reports import _serialize_scan_report

        payload = _serialize_scan_report(scan, list(scan.findings.all()))
        assert payload["metadata"]["imports"][0]["corroborated"] == 2
```

`_serialize_scan_report(scan, findings, *, annotate_stale_fixes=False)` is
defined at `scanning/reports.py:264`; its metadata dict (around line 287) is
what Step 5 edits.

- [ ] **Step 2: Run to verify it fails**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_sarif_import.py -k scan_imports -v`
Expected: FAIL — `Scan has no attribute 'imports'`.

- [ ] **Step 3: Add the column**

In `models.py`, `Scan`, beside `scanner_status`:

```python
    # Per-tool SARIF import accounting from the engine's metadata.imports:
    # [{tool, version?, results, suppressed?, no_location?, corroborated?}].
    # Persisted because reports.py rebuilds a regenerated report's metadata
    # from these columns — without it, which tool an import came from is lost
    # the moment the scan finishes, and the scan-detail corroboration summary
    # has no data path.
    imports = models.JSONField(default=list, blank=True)
```

- [ ] **Step 4: Coerce and persist in both ingest paths**

In `services.py`, beside `_coerce_scanner_status`:

```python
def _coerce_imports(value: Any) -> list[dict[str, Any]]:
    """Sanitize metadata.imports: well-formed per-tool blocks only, bounded."""
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value[:16]:
        if not isinstance(item, dict):
            continue
        tool = item.get("tool")
        if not isinstance(tool, str) or not tool:
            continue
        entry: dict[str, Any] = {"tool": tool[:64]}
        version = item.get("version")
        if isinstance(version, str) and version:
            entry["version"] = version[:64]
        for key in ("results", "suppressed", "no_location", "corroborated"):
            n = item.get(key)
            if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
                entry[key] = n
        out.append(entry)
    return out
```

In `_finalize`'s success branch, next to `scan.scanner_status = ...`:

```python
            scan.imports = _coerce_imports(metadata.get("imports"))
```

Add `"imports"` to that method's `save(update_fields=[...])` list if it uses one.

In `runners/ingest.py`, import `_coerce_imports` alongside `_coerce_scanner_status`, set `scan.imports = _coerce_imports(metadata.get("imports"))` next to line 142, and add `"imports"` to the `update_fields` list near line 160.

- [ ] **Step 5: Expose and regenerate**

Add `"imports"` to `ScanMetaSerializer.Meta.fields` (and `read_only_fields` if it mirrors `fields`).

In `reports.py`'s metadata dict, add:

```python
            # Additive: absent for scans with no imports, so pre-existing
            # regenerated reports are unchanged.
            **({"imports": scan.imports} if scan.imports else {}),
```

- [ ] **Step 6: Migrate, test, sync, commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend
docker compose exec -T django python manage.py makemigrations scanning
docker compose exec -T django python manage.py migrate
docker compose exec -T django python -m pytest -q
make schema && make schema-check
docker compose exec -T django python -m ruff format scanning/ runners/
git add backend/
git commit -m "feat(scans): persist per-tool SARIF import accounting"
```

---

## Task 9: Backend — heavy real-engine E2E for merge

**Files:**
- Modify: `backend/scanning/tests/test_e2e_real_engine.py`

**Interfaces:**
- Consumes: everything above.
- Produces: no production code.

- [ ] **Step 1: Write the test**

```python
    def test_attached_sarif_corroborates_a_native_finding(self, settings, tmp_path):
        """The whole point of the cycle: a native whitebox finding and an
        attached CodeQL result at the same CWE + location must produce ONE
        finding carrying corroboration — driven by the real engine, because
        mocks cannot catch a path/CWE normalization mismatch."""
        binary = _engine_binary()
        if not binary:
            pytest.skip("engine binary not available")

        code_dir = tmp_path / "repo"
        code_dir.mkdir()
        # A hardcoded credential the native secrets scanner reliably finds.
        (code_dir / "settings.py").write_text('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.19.0", "rules": [{
                    "id": "py/hardcoded-credentials",
                    "shortDescription": {"text": "Hardcoded credentials"},
                    "properties": {"tags": ["external/cwe/cwe-798"], "precision": "high"},
                    "defaultConfiguration": {"level": "error"},
                }]}},
                "results": [{
                    "ruleId": "py/hardcoded-credentials", "level": "error",
                    "message": {"text": "Hardcoded credential."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "settings.py"},
                        "region": {"startLine": 1},
                    }}],
                }],
            }],
        }
        ...
```

Complete it following the file's existing import test: launch via `POST /api/scans` with `mode=whitebox`, `code=<code_dir>`, and one `import_files` attachment; run eagerly; then assert **either** a single finding with `cross_tool_corroborated is True`, **or** — if the native scanner's exact line/CWE differs — assert explicitly that both findings are present and unlinked, and open a follow-up. Do NOT weaken the assertion silently: if corroboration does not fire, that is the path-normalization risk the spec flagged and it must be surfaced, not hidden.

- [ ] **Step 2: Run it**

Run: `docker compose exec -T django python -m pytest scanning/tests/test_e2e_real_engine.py -v`
Expected: PASS. If corroboration does not fire, STOP and report the actual endpoints/CWEs of both findings — this is the known path-skew risk and it changes the plan.

- [ ] **Step 3: Commit**

```bash
git add backend/scanning/tests/test_e2e_real_engine.py
git commit -m "test(import): real-engine E2E for attached-SARIF corroboration"
```

---

## Task 10: Frontend — corroboration badge

**Files:**
- Create: `app/components/CorroborationBadge.tsx`
- Modify: `app/types/index.ts`, `app/[locale]/scans/[id]/page.tsx`, `app/[locale]/findings/page.tsx`, `app/[locale]/findings/[id]/page.tsx`, `messages/en.json`, `messages/ar.json`
- Test: `tests/components/CorroborationBadge.test.tsx`

**Interfaces:**
- Consumes: `cross_tool_corroborated`, `corroborating_tools` on the finding type.
- Produces: `<CorroborationBadge tools={string[] | undefined} />`.

- [ ] **Step 1: Write the failing test**

```tsx
import { render, screen } from "@testing-library/react";
import CorroborationBadge from "@/app/components/CorroborationBadge";

describe("CorroborationBadge", () => {
  it("names a single confirming tool", () => {
    render(<CorroborationBadge tools={["codeql"]} />);
    expect(screen.getByText(/codeql/i)).toBeInTheDocument();
  });

  it("renders nothing without corroboration", () => {
    const { container } = render(<CorroborationBadge tools={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
```

Wrap in the repo's existing i18n test provider — copy the pattern from `tests/components/` neighbours (check how `ProvenPathBadge` is tested if a test exists).

- [ ] **Step 2: Run to verify it fails**

Run: `npm test -- --run tests/components/CorroborationBadge.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Read `app/components/ProvenPathBadge.tsx` first and mirror its structure, then:

```tsx
"use client";

import { useTranslations } from "next-intl";

/**
 * Independent cross-tool corroboration: another engine reported the same
 * normalized weakness at the same location. Deliberately lower visual weight
 * than ProvenPathBadge — a proven path is Fendix demonstrating an exploitable
 * route itself; this is two tools agreeing.
 */
export default function CorroborationBadge({ tools }: { tools?: string[] }) {
  const t = useTranslations("findings.corroboration");
  if (!tools || tools.length === 0) return null;
  return (
    <span
      className="inline-flex items-center rounded border border-sky-400/20 bg-sky-400/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-300"
      title={t("tooltip", { tools: tools.join(", ") })}
    >
      {t("label", { tools: tools.join(", ") })}
    </span>
  );
}
```

Add to `messages/en.json` under `findings`:

```json
    "corroboration": {
      "label": "Confirmed by {tools}",
      "tooltip": "{tools} reported the same weakness at the same location. Independent agreement — not a Fendix verification."
    }
```

and the Arabic equivalent in `messages/ar.json`.

Add both fields to the finding type in `app/types/index.ts`:

```ts
  cross_tool_corroborated?: boolean;
  corroborating_tools?: string[];
```

- [ ] **Step 4: Render it in all three places**

In each of the three pages, add beside the existing `<ProvenPathBadge … />`:

```tsx
<CorroborationBadge tools={f.corroborating_tools} />
```

(using `finding.corroborating_tools` on the detail page).

- [ ] **Step 5: Test and commit**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/fendix_frontend
npm test -- --run > /tmp/vitest.log 2>&1; echo "EXIT: $?"; tail -5 /tmp/vitest.log
npx tsc --noEmit
git add app/ messages/ tests/
git commit -m "feat(findings): corroboration badge"
```

Note: check the EXIT code, not the summary — vitest reports unhandled rejections separately from failed tests.

---

## Task 11: Frontend — scan-detail summary and findings filter

**Files:**
- Modify: `app/[locale]/scans/[id]/page.tsx`, `app/[locale]/findings/page.tsx`, `app/types/index.ts`, `messages/{en,ar}.json`
- Test: `tests/pages/scan-detail.test.tsx`, `tests/pages/findings.test.tsx` (create the latter if absent; check `tests/pages/` first)

**Interfaces:**
- Consumes: `scan.imports` (Task 8), `?corroborated=true` (Task 7).
- Produces: no new exports.

- [ ] **Step 1: Write the failing test**

Add to `tests/pages/scan-detail.test.tsx` (follow its existing render helper and fixture names):

```tsx
it("explains how many imported findings were confirmed", async () => {
  renderScanDetail({
    ...scanFixture,
    mode: "whitebox",
    imports: [{ tool: "codeql", results: 5, corroborated: 3 }],
  });
  expect(await screen.findByText(/3 imported findings confirmed/i)).toBeInTheDocument();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npm test -- --run tests/pages/scan-detail.test.tsx`
Expected: FAIL — text not found.

- [ ] **Step 3: Implement**

Add `imports?: ImportedTool[]` to the scan type in `app/types/index.ts`:

```ts
export interface ImportedTool {
  tool: string;
  version?: string;
  results: number;
  suppressed?: number;
  no_location?: number;
  corroborated?: number;
}
```

In the scan-detail page, near the By Source block, render when the total is non-zero:

```tsx
{(() => {
  const confirmed = (scan.imports ?? []).reduce((n, b) => n + (b.corroborated ?? 0), 0);
  return confirmed > 0 ? (
    <p className="text-xs text-text-secondary">{t("scan.importsConfirmed", { count: confirmed })}</p>
  ) : null;
})()}
```

with `"importsConfirmed": "{count} imported findings confirmed existing Fendix findings"` in both message files.

On the findings page, add a cross-confirmed toggle that sets `corroborated=true` on the query, following how the existing severity/source filters build their params.

- [ ] **Step 4: Test and commit**

```bash
npm test -- --run > /tmp/vitest.log 2>&1; echo "EXIT: $?"
npx tsc --noEmit
git add app/ messages/ tests/
git commit -m "feat(scans): show corroborated-import count and cross-confirmed filter"
```

---

## Task 12: Frontend — attach SARIF on the new-scan form

**Files:**
- Create: `app/components/new-scan/AttachSarifSection.tsx`
- Modify: `app/components/new-scan/useNewScanForm.ts`, `app/[locale]/new-scan/page.tsx`, `app/lib/api.ts`, `messages/{en,ar}.json`
- Test: `tests/pages/new-scan.test.tsx`

**Interfaces:**
- Consumes: `POST /api/scans` `import_files` (Task 6).
- Produces: `launchScan` accepts `import_files?: File[]` and sends multipart when present.

- [ ] **Step 1: Write the failing test**

```tsx
it("attaches SARIF files to a whitebox scan", async () => {
  const user = userEvent.setup();
  renderNewScan();
  await user.click(screen.getByRole("radio", { name: /white-box/i }));
  await user.click(screen.getByRole("button", { name: /advanced options/i }));
  const input = screen.getByLabelText(/attach findings/i);
  await user.upload(input, new File([JSON.stringify({ version: "2.1.0", runs: [] })], "codeql.sarif"));
  expect(screen.getByText("codeql.sarif")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npm test -- --run tests/pages/new-scan.test.tsx`
Expected: FAIL — no such control.

- [ ] **Step 3: Implement**

Create `AttachSarifSection.tsx` mirroring `ImportSection.tsx` but multi-file (`multiple` on the input, a list of chosen names, per-file remove). Enforce the same client-side caps as the backend: `MAX_SARIF_UPLOAD_BYTES` per file and 5 files total, with inline errors.

In `useNewScanForm.ts`: add `importFiles: File[]` state, validate count and size in `validate()`, and pass them to `launchScan`.

In `app/lib/api.ts`, make `launchScan` send multipart when attachments are present:

```ts
export async function launchScan(body: LaunchScanRequest): Promise<ScanMeta> {
  const files = body.import_files ?? [];
  if (files.length === 0) {
    return apiFetch<ScanMeta>("/scans", { method: "POST", body: JSON.stringify(body) });
  }
  // Multipart only when attachments exist: buildHeaders leaves Content-Type
  // to the browser for FormData so the multipart boundary is set correctly.
  const form = new FormData();
  for (const [key, value] of Object.entries(body)) {
    if (key === "import_files" || value === undefined || value === null || value === "") continue;
    form.append(key, String(value));
  }
  for (const f of files) form.append("import_files", f);
  return apiFetch<ScanMeta>("/scans", { method: "POST", body: form });
}
```

Render the section in the new-scan page under Advanced Options for the three scanning modes.

- [ ] **Step 4: Test and commit**

```bash
npm test -- --run > /tmp/vitest.log 2>&1; echo "EXIT: $?"
npx tsc --noEmit
npm run lint
git add app/ messages/ tests/
git commit -m "feat(new-scan): attach SARIF reports to a scan"
```

---

## Task 13: End-to-end verification in the browser

**Files:** none (verification only).

- [ ] **Step 1: Rebuild the engine and recreate containers**

```bash
cd /Users/asaied/WorkDir/Fendix/fendix-services/Fendix/go
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.Version=v2.2.0-dev" -o ../bin/fendix-linux-arm64 ./cmd/fendix/
cd ../../fendix-backend
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate django celery-scans
docker compose exec -T django /usr/local/bin/fendix version
```

The recreate is mandatory: the binary is a FILE bind-mount tracked by inode, and a model/enum change also needs the worker restarted.

- [ ] **Step 2: Drive the UI**

Log in as a Team-plan user, launch a whitebox scan against a small repo path with a CodeQL SARIF attached whose CWE and location match a finding the native scanner produces. Verify: the scan completes, a corroborated finding shows the badge naming CodeQL, the scan detail shows the confirmed-imports line, and the findings-page filter returns it.

- [ ] **Step 3: Report**

Report actual observed values (finding count, badge text, confirmed count). If corroboration did not fire, report both findings' endpoints and weaknesses — that is the path-skew limitation and it needs a decision, not a silent pass.

---

## Self-Review Notes

Spec coverage checked section by section:

| Spec section | Task |
| --- | --- |
| Merge path (no engine change needed) | 6 (backend emits `--import`) |
| Two additive public fields | 3 |
| Stamped at the end, never projected | 3 (with the named regression test) |
| Collapsed-import accounting, per-tool map | 2 |
| Stats consolidate by tool identity | 1 (within a doc), 2 (across files) |
| SARIF reporter carries the tools | 3 |
| One config key (`import_files`) | 5 |
| Scan attachments, cap 5, gated, exclusive | 6 |
| Two-phase validate/write with unwind | 5, 6 |
| Existing single-file leak fix | 5 |
| Non-corroborating imports still findings | covered by Task 6's stored-list test + Task 9 E2E |
| `ScanFinding` columns + composite index | 7 |
| `Scan.imports` persistence, both paths, reports | 8 |
| Badge / scan-detail / filter / attach form | 10, 11, 12 |
| SARIF version check at the gate | 4 |
| Engine tests (two runs, two tools, union, omitempty) | 1, 2, 3 |
| Backend tests (atomicity, 400s, persistence) | 4–8 |
| Heavy E2E | 9, 13 |
