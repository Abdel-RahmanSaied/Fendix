# Sprint 10 — Arabic HTML report (i18n)

**Phase:** 4.2 | **Estimate:** 2 days | **Risk:** Low | **Ships:** v0.13.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §13 (no i18n today)

---

## Why

Saudi / GCC enterprise and government buyers expect localised reports. This sprint adds RTL Arabic to the HTML renderer. JSON/SARIF stay English (machine-consumed; localisation would break tooling).

---

## Read first

- [`go/internal/reporters/html.go`](../../go/internal/reporters/html.go) — full file. Note the embedded template (`//go:embed` or string literal). Count user-facing strings.
- [`go/internal/reporters/reporters.go`](../../go/internal/reporters/reporters.go) — the `Options` struct (`Lang` field will go here).
- [`go/cmd/fendix/main.go`](../../go/cmd/fendix/main.go) — `--lang` flag registration.

---

## Concrete deliverables

### 1. i18n package

```
go/internal/reporters/i18n/
  i18n.go         — Strings struct + Get(lang) constructor
  en.go           — English strings (lift from existing template)
  ar.go           — Arabic translations
```

```go
package i18n

type Strings struct {
    ReportTitle             string
    SeverityCritical        string
    SeverityHigh            string
    SeverityMedium          string
    SeverityLow             string
    SeverityInfo            string
    ConfidenceHigh          string
    ConfidenceMedium        string
    ConfidenceLow           string
    SectionSummary          string
    SectionFindings         string
    SectionRemediation      string
    SectionEvidence         string
    SectionReferences       string
    SectionMetadata         string
    ColumnID                string
    ColumnTitle             string
    ColumnSeverity          string
    ColumnLocation          string
    ColumnFix               string
    ScanDateLabel           string
    TotalFindingsLabel      string
    NoFindingsMessage       string
    GeneratedByFendix       string
}

func Get(lang string) Strings {
    switch lang {
    case "ar":
        return arabic()
    default:
        return english()
    }
}
```

### 2. Extract strings from existing template

Read `go/internal/reporters/html.go`. Replace every user-facing English string in the template with a `{{.I18n.<Key>}}` reference.

Example before:
```html
<h2>Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
```

After:
```html
<h2>{{.I18n.SectionSummary}}</h2>
<table><tr><th>{{.I18n.ColumnSeverity}}</th><th>{{.I18n.TotalFindingsLabel}}</th></tr>
```

### 3. RTL CSS branch

```html
<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Lang "ar"}} dir="rtl"{{end}}>
<head>
  <style>
    body { font-family: 'Segoe UI', 'Arial', sans-serif; }
    {{if eq .Lang "ar"}}
    body { direction: rtl; text-align: right; }
    table { direction: rtl; }
    th, td { text-align: right; }
    .severity-badge { float: left; } /* keep severity left-aligned even in RTL */
    {{end}}
  </style>
</head>
```

### 4. CLI flag

Add to `fendix scan` AND `fendix report`:

```go
flags.String("lang", "en", "Report language: en (default), ar")
```

Wire to `ScanConfig.Lang` (new field, default `"en"`).

Validate `lang in {"en", "ar"}` at startup — anything else logs a warning and falls back to `en`.

### 5. Pass through to renderer

```go
// In reporters/html.go RenderHTML signature:
type HTMLOptions struct {
    Lang string // "en" | "ar"
}

func RenderHTML(w io.Writer, findings []models.Finding, meta ScanMetadata, opts HTMLOptions) error {
    strings := i18n.Get(opts.Lang)
    data := struct {
        Findings []models.Finding
        Meta     ScanMetadata
        Lang     string
        I18n     i18n.Strings
    }{ findings, meta, opts.Lang, strings }
    return tpl.Execute(w, data)
}
```

### 6. Arabic translations

Hardcode in `ar.go`. **TRANSLATION_REVIEW_NEEDED comments on every string** — these need a native Arabic security professional to review before v0.13 stable. Machine-generated baseline:

```go
package i18n

func arabic() Strings {
    return Strings{
        ReportTitle:        "تقرير الأمان من Fendix",        // TRANSLATION_REVIEW_NEEDED
        SeverityCritical:   "حرج",                           // TRANSLATION_REVIEW_NEEDED
        SeverityHigh:       "عالي",                          // TRANSLATION_REVIEW_NEEDED
        SeverityMedium:     "متوسط",                         // TRANSLATION_REVIEW_NEEDED
        SeverityLow:        "منخفض",                         // TRANSLATION_REVIEW_NEEDED
        SeverityInfo:       "معلومة",                        // TRANSLATION_REVIEW_NEEDED
        ConfidenceHigh:     "ثقة عالية",                     // TRANSLATION_REVIEW_NEEDED
        ConfidenceMedium:   "ثقة متوسطة",                    // TRANSLATION_REVIEW_NEEDED
        ConfidenceLow:      "ثقة منخفضة",                    // TRANSLATION_REVIEW_NEEDED
        SectionSummary:     "ملخص",                          // TRANSLATION_REVIEW_NEEDED
        SectionFindings:    "النتائج",                       // TRANSLATION_REVIEW_NEEDED
        SectionRemediation: "خطة المعالجة",                  // TRANSLATION_REVIEW_NEEDED
        SectionEvidence:    "الدليل",                        // TRANSLATION_REVIEW_NEEDED
        SectionReferences:  "المراجع",                       // TRANSLATION_REVIEW_NEEDED
        SectionMetadata:    "بيانات الفحص",                  // TRANSLATION_REVIEW_NEEDED
        ColumnID:           "المعرف",                        // TRANSLATION_REVIEW_NEEDED
        ColumnTitle:        "العنوان",                       // TRANSLATION_REVIEW_NEEDED
        ColumnSeverity:     "الخطورة",                       // TRANSLATION_REVIEW_NEEDED
        ColumnLocation:     "الموقع",                        // TRANSLATION_REVIEW_NEEDED
        ColumnFix:          "الإصلاح",                       // TRANSLATION_REVIEW_NEEDED
        ScanDateLabel:      "تاريخ الفحص",                   // TRANSLATION_REVIEW_NEEDED
        TotalFindingsLabel: "إجمالي النتائج",                // TRANSLATION_REVIEW_NEEDED
        NoFindingsMessage:  "لم يتم العثور على نتائج",       // TRANSLATION_REVIEW_NEEDED
        GeneratedByFendix:  "تم إنشاء التقرير بواسطة Fendix", // TRANSLATION_REVIEW_NEEDED
    }
}
```

The TRANSLATION_REVIEW_NEEDED marker is grep-able for a native-speaker reviewer.

### 7. Tests

```go
// TestHTML_EnglishLanguageDefault — no --lang flag → English output, no `dir="rtl"`
// TestHTML_ArabicLanguageRTL — --lang=ar → output has `dir="rtl"` and at least one Arabic string
// TestHTML_UnknownLanguageFallsBackToEnglish — --lang=fr emits a warning, renders English
// TestI18n_GetReturnsConsistentStructure — every field is non-empty for both en and ar
```

## CHANGELOG

```markdown
### Added (v0.13.0)

- **Arabic HTML report** — pass `--lang ar` to `fendix scan` or
  `fendix report` to render the HTML report right-to-left with Arabic
  strings. JSON, SARIF, and PDF output remain English (machine-
  consumed). Arabic strings are baseline machine-generated and
  marked with `TRANSLATION_REVIEW_NEEDED` — native-speaker review
  recommended before publishing externally.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Machine-translated Arabic is tonally wrong for security audience | High | TRANSLATION_REVIEW_NEEDED markers; do NOT promote Arabic as a tested production feature until reviewed. |
| Arabic numerals (٠-٩) vs Western Arabic (0-9) | Low | Keep Western Arabic numerals everywhere. Document. |
| Some security terms have no concise Arabic translation | Med | Use a glossary in `i18n/glossary-ar.md` (committed in this sprint) to keep translations stable across files. |
| RTL breaks the existing table layout | Low | Test rendering against a real browser; the `float: left` override on severity badges is the known workaround. |

## Definition of done

Standard DoD plus:
- Render `--lang ar` HTML against a fixture findings JSON; open in a browser; visually verify
- `i18n/glossary-ar.md` committed with security terms reviewed (or marked TRANSLATION_REVIEW_NEEDED)
- README updated with `--lang` example

## Follow-ups

- **Sprint 10.5:** Native-speaker Arabic translation review — replaces all TRANSLATION_REVIEW_NEEDED markers.
- **Sprint 10.6:** Additional languages (French, Spanish — if customers ask).

## Status

**Not started.**
