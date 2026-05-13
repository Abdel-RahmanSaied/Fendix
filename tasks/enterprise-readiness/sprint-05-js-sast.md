# Sprint 05 — JavaScript / TypeScript regex SAST (6 rules)

**Phase:** 2.2 | **Estimate:** 4 days | **Risk:** Med | **Ships:** v0.12.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §3 (Python-only SAST gap)

---

## Why

JS/TS is the second-most-targeted language by enterprise customers. Fendix today only does *regex secrets* on `.js`/`.ts` files. This sprint adds 6 regex+context-window SAST rules.

**Hard constraint from the brief:** no JS parser binary, no CGo, no tree-sitter. The approach is regex + N=3-line context window. This is a published 20–40% FP-rate technique; the rule documentation must say so honestly.

---

## Cuts vs. source brief

Brief asked for 8 rules; we ship 6. Cuts:

| Cut | Reason | Where |
|---|---|---|
| `JS_PROTO_POLLUTION` | Regex on `Object.assign({}` + `__proto__` FPs every legitimate Proxy-handler use of `__proto__`. Needs AST. | Sprint 05.5 (if/when we add a JS parser) |
| `JS_INSECURE_RAND` (proximity-based) | "Math.random() within 5 lines of token/password/secret" FPs heavily — every PRNG seed in a config file looks like a security context. | Sprint 05.5 |

---

## Read first

- [`go/internal/scanner/secrets/scanner.go`](../../go/internal/scanner/secrets/scanner.go) — your regex+context-window template.
- [Sprint 04](sprint-04-go-sast.md) — the parallel SAST engine for Go. Mirror its package shape; substitute regex for AST.
- [`go/internal/engine/orchestrator.go`](../../go/internal/engine/orchestrator.go) — wire jssast as step 3.9 after gosast.

---

## Rules

| Rule ID | Title | Severity | CWE | Pattern (high-level) |
|---|---|---|---|---|
| `JS_EVAL` | eval() with dynamic input | CRITICAL | CWE-95 | `eval(` not followed by string-literal openning quote |
| `JS_INNERHTML` | innerHTML XSS sink | HIGH | CWE-79 | `\.(inner|outer)HTML\s*=` with non-literal RHS and no sanitiser call within 3 prior lines |
| `JS_DOCWRITE` | document.write XSS | HIGH | CWE-79 | `document\.(write|writeln)\(` with non-literal arg |
| `JS_CHILD_PROCESS` | child_process injection | CRITICAL | CWE-78 | `(exec|execSync|spawn|spawnSync)\(` from `child_process` (or `require('child_process')`) with non-literal arg |
| `JS_PATH_TRAVERSAL` | Path traversal | HIGH | CWE-22 | `(readFile|readFileSync|createReadStream|writeFile|writeFileSync)\(` with non-literal path |
| `JS_HARDCODED_SECRET` | Hardcoded secret | HIGH | CWE-798 | Assignment to variable named `password|secret|api_key|apiKey|token` with literal string value >8 chars that is NOT an `env`/`process\.env` reference |

**Context window:** for each match, fetch ±3 lines around the match. Used to detect sanitiser calls (`DOMPurify.sanitize`, `escape`, `xss`) preceding the sink, or `process.env` on the RHS of an assignment.

---

## Package layout

```
go/internal/scanner/jssast/
  scanner.go        — Scanner type, file walker, ext + skip-dir filters
  rules.go          — registry of jsRule structs
  rule_eval.go
  rule_innerhtml.go
  rule_docwrite.go
  rule_childproc.go
  rule_pathtraversal.go
  rule_hardcodedsecret.go
  context.go        — windowed line reader, sanitiser predicate, env-ref predicate
  scanner_test.go
  rule_*_test.go
```

Scanner `Scan(ctx, codePath)` walks files matching `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`. Skip dirs: `node_modules/`, `dist/`, `build/`, `.next/`, `.nuxt/`, `.git/`, `vendor/`, `coverage/`.

## Rule struct shape

```go
type jsRule interface {
    ID() string
    Inspect(content []byte, path string) []models.Finding
}
```

Each rule receives the full file as `[]byte`. It splits into lines once, then runs its regex against each line, then evaluates the context window for FP-suppressing predicates.

## Sanitiser predicate (shared in `context.go`)

```go
// hasSanitiser returns true if a known XSS sanitiser call appears
// within the 3 lines preceding `lineIdx`. Used by JS_INNERHTML and
// JS_DOCWRITE to suppress FPs on guarded sinks.
//
// Recognised sanitisers (one or more of these names appearing on a
// preceding line — naive but matches the regex-based approach):
//   DOMPurify.sanitize, escape, encodeURIComponent, encodeHTML,
//   xss, sanitize, sanitizeHTML
//
// Conservative — a sanitiser call in an UNRELATED location would
// suppress a real finding. Documented as FN class.
func hasSanitiser(lines [][]byte, lineIdx int) bool { ... }

// isEnvRef returns true if the expression looks like a process.env
// reference (or import.meta.env, or destructured from process.env).
// Used by JS_HARDCODED_SECRET to suppress env-loaded values.
func isEnvRef(expr []byte) bool { ... }
```

## Orchestrator wiring

Step 3.9, after step 3.8 (gosast). Auto-detect: `package.json` at scan root OR any `.js`/`.ts`/`.tsx` file (use `filepath.WalkDir` with early-exit on first match — single-syscall budget).

## Tests

Per rule: 3 positive + 3 negative + 1 documented-FP-class = 7 tests × 6 rules = **42 tests minimum**.

E2E test scanning the Fendix repo (which has no JS code today) should produce 0 findings — verifies the auto-detect skips cleanly.

## CHANGELOG

```markdown
### Added (v0.12.0)

- **JavaScript / TypeScript SAST engine** — new `internal/scanner/jssast/`.
  Regex + 3-line context window approach. **Known FP rate of 20–40%** on
  rules using context windows (JS_INNERHTML, JS_HARDCODED_SECRET). Use the
  rule's documented FP class to suppress via `.fendix-ignore`. A real AST
  pass is planned but requires a JS parser dep (CGo or sub-binary)
  ruled out for v0.12.

  Ships 6 rules: JS_EVAL, JS_INNERHTML, JS_DOCWRITE, JS_CHILD_PROCESS,
  JS_PATH_TRAVERSAL, JS_HARDCODED_SECRET. Defer to Sprint 05.5:
  JS_PROTO_POLLUTION, JS_INSECURE_RAND (need AST for acceptable
  precision).
```

---

## Risks

- **Regex FP rate.** Acknowledge in CHANGELOG + per-rule GoDoc. Provide `.fendix-ignore` snippets in the per-rule docs.
- **Multi-line regex doesn't fit Go's RE2.** Stick to per-line matching + context-window for cross-line context (e.g. import detection).
- **TS-specific syntax** (decorators, generics, `as` casts) doesn't affect any of our 6 rules but worth a smoke test.

## Definition of done — see PLAN.md cross-cutting checklist plus

- 42+ tests across 6 rules
- E2E test asserting auto-detect on a small JS fixture
- Per-rule GoDoc names the FP class explicitly

## Follow-ups

- **Sprint 05.5:** JS_PROTO_POLLUTION + JS_INSECURE_RAND with real flow analysis (requires solving the JS-parser-in-Go problem first)
- **Sprint 05.6:** TypeScript-specific rules (insecure `any` usage in security contexts, `// @ts-ignore` on auth flows)

## Status

**Not started.**
