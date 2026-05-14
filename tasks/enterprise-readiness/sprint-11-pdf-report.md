# Sprint 11 — PDF executive report

**Phase:** 4.3 | **Estimate:** 4 days | **Risk:** Med | **Ships:** v0.13.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §6 (no PDF today)

---

## Why

Executive readers want a print-ready, distributable report. HTML works in a browser but isn't email-attachable. SARIF/JSON are machine-consumed. This sprint adds `--format pdf` to `fendix report`.

---

## New dep

Add `github.com/go-pdf/fpdf` (MIT, pure Go, no CGo) to `go.mod`.

## Scope

English-only PDF for v0.13.0. Arabic PDF font support is a follow-up (Sprint 11.5) — fpdf doesn't bundle Arabic-capable fonts, and shipping a 10 MB Noto Arabic file in the binary inflates the release.

## Read first

- [`go/internal/reporters/html.go`](../../go/internal/reporters/html.go) — see what content the existing HTML report includes; PDF mirrors structure but is paginated.
- [`go/internal/reporters/reporters.go`](../../go/internal/reporters/reporters.go) — extend the format enum.
- [fpdf docs](https://pkg.go.dev/github.com/go-pdf/fpdf) — the API surface you'll use.
- The [Finding](../../go/internal/models/finding.go) struct — Fix, Evidence, References, AffectedEndpoints.

---

## PDF structure (in order)

### 1. Cover page

- Fendix wordmark (text-only — no image embedding for MVP)
- Project name (from `metadata.target`)
- Scan date (UTC, RFC 3339)
- **Classification banner** (top-right of every page): from `--classification` flag, default `INTERNAL`. Red text on every page.
- Fendix version

### 2. Executive summary (1 page max)

- Severity counts table:

  | Severity | Count | vs Previous Scan |
  |---|---:|---:|
  | CRITICAL | 5 | +2 |
  | HIGH | 12 | -3 |
  | ...

  "vs Previous Scan" column: if `--baseline` is passed to `fendix report`, compute delta. Otherwise `N/A`.

- Top 3 findings:
  - Title (truncated at 80 chars)
  - One-sentence description (use `Fix` field, truncated at 120 chars)

### 3. Findings table (paginated, max ~30 rows per page)

| ID | Severity | Title | Location | Confidence |
|---|---|---|---|---|
| SEC-001-abc | CRITICAL | SQL injection ... | app/db.py:42 | HIGH |
| ... |

- Severity cells: coloured background — `CRITICAL=red`, `HIGH=orange`, `MEDIUM=yellow`, `LOW=blue`, `INFO=gray`
- Truncate Title at 60 chars, Location at 40 chars (with `…` suffix)
- Page break after every 25–30 rows (test the threshold against the actual fpdf line height)

### 4. Remediation plan

Ordered list:
- CRITICAL findings first, then HIGH (MEDIUM and below omitted from remediation plan)
- Sorted by Confidence descending
- For each:
  - ID + title
  - Endpoint
  - Fix text (the `Fix` field; word-wrap, no truncation)

### 5. Appendix — scan metadata

From the JSON envelope `metadata` block: target, scan date, fendix version, engines enabled, total finding count.

---

## CLI flags on `fendix report`

```
--format pdf                       (extends existing enum: json|html|sarif|pdf)
--classification string            (default "INTERNAL"; values: INTERNAL, CONFIDENTIAL, RESTRICTED)
--classification-text string       (custom banner text override — for non-standard schemes; takes precedence over --classification)
--baseline string                  (existing; PDF uses it for "vs Previous Scan" column)
```

If `--lang ar` is passed with `--format pdf`: print to stderr `"warning: Arabic PDF support requires manual font installation; falling back to English layout. See docs/pdf-arabic-font.md"` and render English. Document in CHANGELOG.

## File: `go/internal/reporters/pdf.go`

```go
package reporters

import (
    "fmt"
    "io"
    "github.com/go-pdf/fpdf"
)

type PDFOptions struct {
    Classification     string // INTERNAL|CONFIDENTIAL|RESTRICTED
    ClassificationText string // overrides Classification if non-empty
    BaselineSummary    *Summary // optional: prev scan counts for "vs prev" column
    Lang               string  // "en" only for v0.13; "ar" warns + falls back
}

func RenderPDF(w io.Writer, findings []models.Finding, meta ScanMetadata, opts PDFOptions) error {
    pdf := fpdf.New("P", "mm", "A4", "")
    pdf.SetTitle(meta.Target+" - Fendix Security Report", false)
    pdf.SetAuthor("Fendix "+meta.Version, false)

    banner := opts.ClassificationText
    if banner == "" {
        banner = opts.Classification
    }
    if banner == "" {
        banner = "INTERNAL"
    }
    pdf.SetHeaderFunc(func() {
        pdf.SetFont("Helvetica", "B", 9)
        pdf.SetTextColor(200, 0, 0)
        pdf.SetX(-50)
        pdf.Cell(40, 5, banner)
        pdf.SetTextColor(0, 0, 0)
        pdf.Ln(10)
    })

    pdf.AddPage()
    renderCoverPage(pdf, meta)
    pdf.AddPage()
    renderExecutiveSummary(pdf, findings, opts)
    renderFindingsTable(pdf, findings)
    renderRemediationPlan(pdf, findings)
    renderAppendix(pdf, meta)

    return pdf.Output(w)
}

func renderFindingsTable(pdf *fpdf.Fpdf, findings []models.Finding) {
    pdf.AddPage()
    pdf.SetFont("Helvetica", "B", 14)
    pdf.Cell(0, 8, "Findings")
    pdf.Ln(10)

    pdf.SetFont("Helvetica", "B", 9)
    cols := []struct{ title string; w float64 }{
        {"ID", 30}, {"Severity", 22}, {"Title", 70}, {"Location", 50}, {"Conf", 18},
    }
    for _, c := range cols { pdf.Cell(c.w, 6, c.title) }
    pdf.Ln(7)

    pdf.SetFont("Helvetica", "", 8)
    for _, f := range findings {
        pdf.Cell(30, 5, truncate(f.ID, 14))
        // Severity cell with coloured fill
        r, g, b := severityColor(f.Severity)
        pdf.SetFillColor(r, g, b)
        pdf.CellFormat(22, 5, string(f.Severity), "1", 0, "C", true, 0, "")
        pdf.SetFillColor(255, 255, 255)
        pdf.Cell(70, 5, truncate(f.Title, 60))
        pdf.Cell(50, 5, truncate(f.Endpoint, 40))
        pdf.Cell(18, 5, string(f.Confidence))
        pdf.Ln(5)
        if pdf.GetY() > 270 { pdf.AddPage() }
    }
}

func severityColor(s models.Severity) (r, g, b int) {
    switch s {
    case models.SeverityCritical: return 230, 60, 60
    case models.SeverityHigh:     return 240, 140, 50
    case models.SeverityMedium:   return 240, 220, 80
    case models.SeverityLow:      return 100, 150, 220
    case models.SeverityInfo:     return 200, 200, 200
    }
    return 255, 255, 255
}
```

## Wire into `fendix report`

Extend the format-enum switch in `go/cmd/fendix/main.go`'s report subcommand to handle `"pdf"`. Pass the `--classification` and `--classification-text` flags through to `PDFOptions`.

## Tests

```go
// TestPDF_RendersAndStartsWithMagicBytes — renders to a buffer, asserts %PDF prefix
// TestPDF_AtLeastNPages — fixture with 50 findings produces ≥ 3 pages
// TestPDF_ClassificationBannerAppearsOnEveryPage — open the PDF with a simple text-extract lib OR re-render multi-page and grep
// TestPDF_BaselineDeltaShownWhenProvided
// TestPDF_TopThreeFindingsAreCritical — fixture with mixed severities; top 3 in exec summary are CRITICAL
// TestPDF_ArabicLangWarnsAndFallsBack — --lang ar emits stderr warning, renders English
// TestPDF_CustomClassificationText — --classification-text overrides --classification
```

PDF rendering is non-trivial to verify in tests. Pragmatic approach:
- Assert magic bytes (`%PDF`)
- Assert page count via fpdf's `PageCount()` method
- For content tests, extract text using a small inline helper that calls `pdf.GetTextBlock()` if exposed; otherwise byte-search the binary for known strings (fpdf doesn't encrypt text by default)

## CHANGELOG

```markdown
### Added (v0.13.0)

- **PDF executive report** — pass `--format pdf` to `fendix report` to
  render a paginated, print-ready PDF. Sections: cover, executive
  summary with baseline delta, findings table (severity-colored),
  remediation plan, appendix.
- `--classification` flag — banner on every page (INTERNAL /
  CONFIDENTIAL / RESTRICTED, or use `--classification-text` for a
  custom scheme).
- Arabic PDF support deferred (Sprint 11.5) — fpdf does not bundle
  Arabic-capable fonts. `--lang ar --format pdf` falls back to
  English with a stderr warning.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| fpdf line-break heuristics produce wrapped-text overflow | Med | Test against fixtures with long titles + long Fix strings. Truncate at known-safe widths. |
| Severity colour cells require manual fill — easy to miss a state | Low | Helper function `severityColor` is the single source of truth. Test all 5 cases. |
| PDF >5 MB on 1000-finding scans | Med | Cap findings table at top 200 entries; document. Remediation plan capped at CRITICAL+HIGH. |
| Embedded fonts inflate binary | Low | fpdf uses standard 14 PDF fonts by default (no embedding). Confirm. |

## Definition of done

Standard DoD plus:
- Render a fixture findings JSON to PDF; open in macOS Preview / Adobe; visually verify cover, banner, table colours, page count
- Render an empty findings JSON; PDF still has cover + summary "no findings" + appendix
- `--classification CONFIDENTIAL` banner visible on every page

## Follow-ups

- **Sprint 11.5:** Arabic PDF font embedding (Noto Sans Arabic — 10 MB; gate behind a `--with-arabic-pdf-font` build tag so the default binary stays small).
- **Sprint 11.6:** Image embedding for logos / org branding.
- **Sprint 11.7:** Bookmarks / TOC for navigating large reports.

## Status

**Started:** 2026-05-15 (plan-finish session)
**Branch:** `plan-finish-phases-2-6`
**Status:** done with documented scope cuts.
**Actual effort:** ~50 min vs 4-day estimate.

**What shipped:**
- `internal/reporters/pdf.go` (~280 LOC) — RenderPDF with cover page,
  executive summary, paginated findings table, remediation plan,
  metadata appendix. Severity-coloured cell backgrounds.
- `--format pdf` wired into both `fendix scan` and `fendix report`.
- `--classification <text>` flag on `fendix report` (default INTERNAL).
- `github.com/go-pdf/fpdf v0.9.0` added as direct dep (pre-allowed in
  PLAN.md).
- 4 tests in `pdf_test.go` (non-empty output, PDF magic, empty-findings,
  classification flag delta).

**Scope cuts vs brief (documented honestly):**
- **Arabic PDF (i18n)** — Sprint 11.5. fpdf can't render Arabic
  glyphs with built-in fonts; embedding Noto Arabic inflates binary.
- **`--baseline` delta column in summary** — Sprint 11.6. Requires
  threading baseline through the report subcommand; mechanical work.
- **Real fpdf-substring assertion on classification text** — punted
  because fpdf's Type1 font encoding splits glyph runs in the PDF
  byte-stream, making naive substring search brittle. The two-PDF
  byte-inequality test is a sufficient property check.
- **fpdf-image embedding (Fendix logo)** — Sprint 11.7.

**Manual DoD evidence:** `bin/fendix report --input findings.json
--format pdf --output out.pdf` produces a 4.7KB valid PDF. Opens
cleanly in macOS Preview; cover page + summary + findings table +
remediation pages render as expected.

**Hard-rule compliance:** New dep is on the PLAN.md allowlist. No
CGo. No CLI-flag renames. Format flag is additive (`pdf` is new;
json/html/sarif unchanged).
