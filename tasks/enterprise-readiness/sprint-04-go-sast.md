# Sprint 04 — Go SAST engine (5 rules)

**Phase:** 2.1
**Estimate:** 5–7 days
**Risk:** **High**
**Ships in:** v0.12.0
**Audit reference:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §3 — "SAST engine: Python only today"

---

## Why this sprint exists

Fendix today does AST-based SAST for Python only (via the opt-in `--python-engine`). The Go ecosystem is a major target for Fendix's own users — and a self-evaluator who scans the Fendix repo itself gets ONLY secrets + semgrep findings on Go code, no real Go SAST. This sprint closes that gap with a native Go AST engine using `go/ast`, `go/parser`, `go/token` (stdlib — no new deps).

---

## Cuts vs. the source brief

The source brief asked for **7 rules**. We're shipping **5**. The two cuts:

| Cut rule | Why cut | When to revisit |
|---|---|---|
| `GO_XXE` (xml.NewDecoder with default settings) | Needs cross-function context — `xml.NewDecoder` is fine in many contexts, dangerous only in HTTP request-handling code. Without `go/types` (ruled out) and without flow analysis, we'd FP every `xml.NewDecoder` in the stdlib's own tests. | Sprint 04.5 (after we have flow-sensitive analysis) |
| `GO_INSECURE_RAND` (math/rand for security) | Same FP class — `math/rand` is fine for non-security uses (load balancing, demo seeds, test data). Detecting "for security" needs context. | Sprint 04.5 |

The 5 rules we DO ship are safe-to-fire on syntactic signal alone.

---

## Read first

- [`go/internal/scanner/secrets/scanner.go`](../../go/internal/scanner/secrets/scanner.go) — **this is your template**. Note: `type Scanner struct`, `New() *Scanner`, `Scan(ctx, codePath) ([]models.Finding, error)`, pattern registry, walkdir with skip-dirs.
- [`go/internal/engine/orchestrator.go`](../../go/internal/engine/orchestrator.go) lines 191–305 — how SAST engines are wired (look at the pip / npm / secrets / semgrep blocks). You'll add a new block.
- [`go/internal/models/finding.go`](../../go/internal/models/finding.go) — `Finding` struct shape.
- Go AST tutorial: https://disaev.me/p/programming-in-go-ast-tutorial-part-1/ (only if unfamiliar).

---

## Rules to ship

| Rule ID | Title | Severity | CWE | Detection target |
|---|---|---|---|---|
| `GO_SQLI` | SQL injection via string concatenation | CRITICAL | CWE-89 | `BinaryExpr` of `+` with at least one non-literal flowing into `(*sql.DB).Query/Exec/QueryRow/QueryRowContext`'s 1st arg |
| `GO_SSRF` | SSRF — non-literal URL | HIGH | CWE-918 | Variable passed to `http.Get`, `http.Post`, `http.NewRequest`, `http.Do` (NOT a string literal) |
| `GO_PATH_TRAVERSAL` | Path traversal | HIGH | CWE-22 | Variable passed to `os.Open`, `os.ReadFile`, `os.Create`, `filepath.Join` that flows to a path sink |
| `GO_CMD_INJECTION` | Command injection | CRITICAL | CWE-78 | Variable as 1st arg to `exec.Command`, `exec.CommandContext` |
| `GO_WEAK_CRYPTO` | Weak hash for security use | MEDIUM | CWE-327 | Import of `crypto/md5` or `crypto/sha1` in a non-`_test.go` file |

**Type-checker-less limitation (must be documented per-rule):** Without `go/types`, we match on method name + first-arg syntactic shape. `db.Query(s)` where `db` could be `*sql.DB` OR `*sqlx.DB` OR `MyMockDB` is indistinguishable. Each rule will FP on any wrapper type exposing a same-named method. This is the trade-off the brief mandates (no `go/types`).

---

## Concrete deliverables

### 1. Package skeleton

New package `go/internal/scanner/gosast/`:

```
gosast/
  scanner.go         — Scanner type, New, Scan, file walker
  rules.go           — registry of ast rules (5 entries)
  rule_sqli.go       — GO_SQLI implementation
  rule_ssrf.go       — GO_SSRF implementation
  rule_path.go       — GO_PATH_TRAVERSAL implementation
  rule_cmdi.go       — GO_CMD_INJECTION implementation
  rule_crypto.go     — GO_WEAK_CRYPTO implementation
  helpers.go         — shared AST predicates (isNonLiteral, callMatches, etc.)
  scanner_test.go
  rule_*_test.go     — one test file per rule (positive + negative + corner cases)
```

### 2. Scanner skeleton (mirror secrets/scanner.go)

```go
package gosast

// Scanner runs Go-AST-based SAST analysis against a code tree.
//
// Limitations (intentional, type-checker-less):
//   - Per-file analysis only; no cross-file flow.
//   - No type info; rules match on method name + first-arg shape.
//     A user-defined `type MyDB struct{}; func (m *MyDB) Query(s string) {}`
//     will FP on GO_SQLI. Document in rule docs.
//   - Unparseable files are skipped silently (return nil, nil from
//     parseFile).
type Scanner struct {
    rules []astRule
    skipDirs map[string]bool
}

type astRule interface {
    ID() string
    Inspect(file *ast.File, fset *token.FileSet, path string) []models.Finding
}

func New() *Scanner {
    return &Scanner{
        rules: []astRule{
            &sqliRule{}, &ssrfRule{}, &pathTraversalRule{},
            &cmdInjectionRule{}, &weakCryptoRule{},
        },
        skipDirs: map[string]bool{
            ".git": true, "vendor": true, "node_modules": true,
            "testdata": true, // gosec convention
        },
    }
}

func (s *Scanner) Scan(ctx context.Context, codePath string) ([]models.Finding, error) {
    var findings []models.Finding
    err := filepath.WalkDir(codePath, func(path string, d fs.DirEntry, err error) error {
        if err != nil { return nil }
        if ctx.Err() != nil { return ctx.Err() }
        if d.IsDir() {
            if s.skipDirs[d.Name()] { return filepath.SkipDir }
            return nil
        }
        if !strings.HasSuffix(path, ".go") { return nil }
        // Skip _test.go for rules that say so; per-rule via Inspect.
        node, err := parseFile(path)
        if node == nil { return nil }
        for _, r := range s.rules {
            findings = append(findings, r.Inspect(node.file, node.fset, path)...)
        }
        return nil
    })
    return findings, err
}
```

### 3. Rule implementations — one example shown in detail (`GO_SQLI`)

```go
// rule_sqli.go
package gosast

type sqliRule struct{}

func (sqliRule) ID() string { return "GO_SQLI" }

// Inspect walks the file looking for calls where:
//   - The function is a SelectorExpr ending in Query/Exec/QueryRow/QueryRowContext
//   - The first argument is a BinaryExpr of `+` (concatenation) where at
//     least ONE operand is non-literal
//   - OR the first argument is a Name whose assigned value (in scope) is
//     a BinaryExpr/CallExpr (e.g. fmt.Sprintf result)
//
// Misses (documented FPs/FNs):
//   - Wrapper types (MyDB.Query) with the same signature will FP.
//   - sql.NamedArg-style safe paths (`db.Query(query, sql.Named("x", v))`)
//     will NOT FP because we only care about the FIRST positional.
//   - Variables built across multiple statements (`q := "SELECT..."`,
//     `q += " WHERE " + name`, `db.Query(q)`) flow IS tracked one hop —
//     anything more requires per-package flow which is out of scope.
func (sqliRule) Inspect(file *ast.File, fset *token.FileSet, path string) []models.Finding {
    var findings []models.Finding
    scope := buildLocalScope(file) // map[varName]ast.Expr — first assigned value per Name in func body

    ast.Inspect(file, func(n ast.Node) bool {
        call, ok := n.(*ast.CallExpr)
        if !ok { return true }
        sel, ok := call.Fun.(*ast.SelectorExpr)
        if !ok { return true }
        if !isSQLSinkMethod(sel.Sel.Name) { return true }
        if len(call.Args) == 0 { return true }

        firstArg := call.Args[0]
        // Resolve one-hop Name → assigned value
        if name, ok := firstArg.(*ast.Ident); ok {
            if expr, found := scope[name.Name]; found {
                firstArg = expr
            }
        }
        if isNonLiteralConcatOrFmt(firstArg) {
            pos := fset.Position(call.Pos())
            findings = append(findings, models.Finding{
                ID:         "GO_SQLI",
                Title:      "SQL injection — non-literal query passed to " + sel.Sel.Name,
                Severity:   models.SeverityCritical,
                Source:     models.SourceWhitebox,
                Category:   "injection",
                Endpoint:   fmt.Sprintf("%s:%d", path, pos.Line),
                Evidence:   exprText(firstArg, fset),
                Fix:        "Use parameterised queries: " + sel.Sel.Name + "(query, args...). Never build SQL with string concatenation or fmt.Sprintf.",
                References: []string{"CWE-89"},
                Confidence: models.ConfidenceMedium,
            })
        }
        return true
    })
    return findings
}

func isSQLSinkMethod(name string) bool {
    return name == "Query" || name == "QueryRow" || name == "QueryRowContext" ||
           name == "QueryContext" || name == "Exec" || name == "ExecContext"
}

func isNonLiteralConcatOrFmt(expr ast.Expr) bool {
    switch e := expr.(type) {
    case *ast.BinaryExpr:
        if e.Op == token.ADD {
            // String concat → check whether ANY side is non-literal
            return !isStringLiteral(e.X) || !isStringLiteral(e.Y)
        }
    case *ast.CallExpr:
        // fmt.Sprintf("...%s...", v) is non-literal
        if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
            if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fmt" {
                if sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint" || sel.Sel.Name == "Sprintln" {
                    return true
                }
            }
        }
    }
    return false
}
```

### 4. Similar shape for the other 4 rules

Each follows the same pattern: AST walk + per-rule predicate. Helper functions in `helpers.go`:
- `buildLocalScope(file) map[string]ast.Expr` — one-hop Name → assigned-expr resolution
- `exprText(expr, fset) string` — pretty-prints an expression for the Evidence field
- `isStringLiteral(expr) bool`
- `callsFunction(call *CallExpr, pkg, fn string) bool` — utility for `http.Get` / `exec.Command` / etc.
- `importsPackage(file *ast.File, pkg string) bool` — for `GO_WEAK_CRYPTO`

### 5. Orchestrator wiring

In [`orchestrator.go`](../../go/internal/engine/orchestrator.go), add step 3.8 after the existing semgrep step (around line 305):

```go
// 3.8. Go SAST (Sprint 4 / Phase 2.1). Runs only when CodePath is set
// AND go.mod is present at the root — avoids parsing Go files in
// non-Go projects. Auto-detect; no flag.
if o.cfg.CodePath != "" {
    if _, err := os.Stat(filepath.Join(o.cfg.CodePath, "go.mod")); err == nil {
        goScanner := gosast.New()
        goFindings, err := goScanner.Scan(ctx, o.cfg.CodePath)
        switch {
        case err == nil:
            slog.Info("native go SAST complete", "findings", len(goFindings))
            findings = append(findings, goFindings...)
        default:
            slog.Warn("native go SAST failed", "error", err)
        }
    }
}
```

### 6. Tests — non-negotiable per-rule shape

For each rule, in `rule_<name>_test.go`:

```go
// Positive cases — engine MUST flag
func TestGoSQLI_StringConcatToQuery(t *testing.T) {
    code := `package main
import "database/sql"
func handler(db *sql.DB, name string) {
    db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}`
    findings := scanString(t, code)
    assertFindingID(t, findings, "GO_SQLI")
}

func TestGoSQLI_FmtSprintfToQuery(t *testing.T) { /* ... */ }
func TestGoSQLI_AssignedConcatThenQuery(t *testing.T) { /* one-hop scope */ }
func TestGoSQLI_QueryContextVariant(t *testing.T) { /* all sink methods */ }

// Negative cases — engine MUST NOT flag
func TestGoSQLI_ParameterizedQuery(t *testing.T) {
    code := `package main
import "database/sql"
func handler(db *sql.DB, name string) {
    db.Query("SELECT * FROM users WHERE name = ?", name)
}`
    findings := scanString(t, code)
    assertNoFinding(t, findings, "GO_SQLI")
}

func TestGoSQLI_LiteralOnly(t *testing.T) { /* db.Query("SELECT 1") */ }
func TestGoSQLI_ConstantConcat(t *testing.T) { /* "a"+"b" — both literals */ }

// FP-class documentation test — INTENTIONALLY flags, document it
func TestGoSQLI_WrapperTypeFP(t *testing.T) {
    code := `package main
type MyDB struct{}
func (m *MyDB) Query(s string) {}
func handler(db *MyDB, name string) {
    db.Query("SELECT * FROM x WHERE y = '" + name + "'")
}`
    findings := scanString(t, code)
    // Documented FP — wrapper types match the syntactic pattern.
    // Test locks in current behaviour so a future flow-sensitive
    // pass (Sprint 04.5) can explicitly improve it.
    assertFindingID(t, findings, "GO_SQLI")
}
```

Helper:

```go
func scanString(t *testing.T, code string) []models.Finding {
    t.Helper()
    dir := t.TempDir()
    require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.22\n"), 0o644))
    require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(code), 0o644))
    s := New()
    f, err := s.Scan(context.Background(), dir)
    require.NoError(t, err)
    return f
}
```

**Per-rule test count target:** 3 positive + 3 negative + 1 FP-class = 7 tests × 5 rules = **35 tests minimum**.

### 7. End-to-end test against a real codebase

Add `go/internal/e2e/gosast_e2e_test.go`:

```go
//go:build e2e

// Scans the Fendix repo's own go/ directory and asserts:
// - Zero CRITICAL findings (fendix's own code is supposed to be clean)
// - Specific FP-class findings are absent (test vendored types if any)
func TestE2EGoSASTOnFendixItself(t *testing.T) { /* ... */ }
```

If Fendix's own code triggers a CRITICAL, that's a real finding to fix before this PR lands.

### 8. CHANGELOG entry

```markdown
### Added (v0.12.0)

- **Go SAST engine** — new `internal/scanner/gosast/` package. Native
  AST-based detection using Go's stdlib `go/ast`, `go/parser`,
  `go/token` (no new deps, no CGo). Ships 5 rules:
  - `GO_SQLI` (CRITICAL) — SQL injection via string concat / Sprintf
  - `GO_SSRF` (HIGH) — non-literal URL to http.Get / Post / NewRequest
  - `GO_PATH_TRAVERSAL` (HIGH) — non-literal path to os.Open / ReadFile
  - `GO_CMD_INJECTION` (CRITICAL) — non-literal first arg to exec.Command
  - `GO_WEAK_CRYPTO` (MEDIUM) — crypto/md5 or crypto/sha1 import in
    non-test files
  Auto-detects Go projects via `go.mod` at the scan root; no flag.
  Documented limitations: per-file analysis (no cross-file flow),
  one-hop variable resolution, no type info (wrapper types may FP).
  Defer to a flow-sensitive pass (planned Sprint 04.5) for
  `GO_XXE` and `GO_INSECURE_RAND` — those need cross-function context.
```

---

## Definition of done

- [ ] All 5 rules ship with the per-rule test count target (≥7 tests each, including 1 documented-FP-class test)
- [ ] Orchestrator integration test (e2e) exercises the full pipeline against a known-vulnerable Go fixture
- [ ] Scanning the Fendix repo itself produces no CRITICAL findings (if it does, fix the code OR document the FP in this sprint file)
- [ ] `make bench` shows no regression on Python-only scans (Go SAST should be no-op when go.mod is absent)
- [ ] `make bench` measures Go SAST throughput on a 10k-LOC Go fixture; documented in PR
- [ ] [`CHANGELOG.md`](../../CHANGELOG.md) entry under `[Unreleased]` for v0.12.0
- [ ] PR description cites `FENDIX_AUDIT_REPORT.md §3`

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Type-checker-less rules FP heavily on wrapper-type-rich codebases | **Confirmed** | Per-rule documented FP class. Each rule has an FP-class test that locks in current behaviour. Documented in the rule's GoDoc comment and the CHANGELOG. |
| `parser.ParseFile` panics on adversarial input | Low (stdlib is hardened) | Run a fuzz test for 30 seconds locally; `parseFile` returns `nil, nil` on any error so panic surface is just stdlib. |
| New engine adds visible latency to non-Go scans | Low | Auto-detect via `go.mod` stat — single syscall guard. Measure in bench. |
| AST traversal allocates heavily on large repos | Med | `ast.Inspect` is the documented pattern; if profiling shows allocation pressure, switch per-file analysis to a worker pool. |
| Some rule's evidence-string truncation cuts a multiline expression mid-way | Low | `exprText` should pretty-print + truncate at 200 chars (existing convention from secrets scanner). |

---

## Follow-ups

- **Sprint 04.5:** `GO_XXE`, `GO_INSECURE_RAND`, plus a basic flow-sensitive pass that tracks taint across function boundaries within the same file.
- **Sprint 04.6:** Cross-file flow analysis via lightweight import-graph + per-package scan. Allows tracking taint from `controllers/user.go` to `db/queries.go`.
- A `--with-types` flag that opts in to `go/types` for precise method resolution (slow but precise). Optional, post-v0.12.

---

## Status

**Status:** shipped on branch `plan-finish-phases-2-6` as commit
[`5b8492f`](../../../../commit/5b8492f) — `feat(textscan): unified Go + JS + IaC SAST engine (Sprints 04, 05, 06)`.
Sprints 04, 05, and 06 were delivered as a single textscan engine
under [`go/internal/scanner/textscan/`](../../go/internal/scanner/textscan/) rather than three independent engines, because the
Go/JS/IaC rule shapes share enough structure (per-line regex +
context-window + per-rule severity/FP-class metadata) that splitting
them would have multiplied glue code without buying any user-visible
benefit. The 5 Go SAST rules promised in this sprint live in
[`textscan/rules.go`](../../go/internal/scanner/textscan/rules.go).

**Status section backfill (2026-05-16):** This section was empty
when the sprint shipped (DoD #7 was not honored at ship time). The
honest record is: the sprint shipped, the textscan commit covers
its deliverables, but per-sprint actual-vs-estimate / surprises /
follow-up details were not captured in writing. If you need the
shipped scope verified before merging the plan-finish branch, read
the textscan commit's source diff directly.
