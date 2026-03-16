package reporters

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/fendix/fendix/internal/models"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fendix Security Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{font-size:1.75rem;margin-bottom:.5rem;color:#f8fafc}
.subtitle{color:#94a3b8;margin-bottom:2rem}
.summary{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
.stat{padding:1rem 1.5rem;border-radius:.75rem;min-width:120px;text-align:center}
.stat .count{font-size:2rem;font-weight:700}
.stat .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;opacity:.8}
.stat.critical{background:#450a0a;border:1px solid #dc2626;color:#fca5a5}
.stat.high{background:#431407;border:1px solid #ea580c;color:#fdba74}
.stat.medium{background:#422006;border:1px solid #d97706;color:#fcd34d}
.stat.low{background:#1e3a5f;border:1px solid #3b82f6;color:#93c5fd}
.stat.info{background:#1e293b;border:1px solid #475569;color:#94a3b8}
.findings{margin-top:1rem}
.finding{background:#1e293b;border:1px solid #334155;border-radius:.75rem;margin-bottom:.75rem;overflow:hidden}
.finding-header{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;cursor:pointer;user-select:none}
.finding-header:hover{background:#253349}
.badge{padding:.25rem .75rem;border-radius:9999px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.badge.CRITICAL{background:#dc2626;color:#fff}
.badge.HIGH{background:#ea580c;color:#fff}
.badge.MEDIUM{background:#d97706;color:#1c1917}
.badge.LOW{background:#3b82f6;color:#fff}
.badge.INFO{background:#475569;color:#e2e8f0}
.finding-title{flex:1;font-weight:500}
.finding-endpoint{color:#94a3b8;font-size:.85rem;font-family:monospace}
.toggle{font-size:1.25rem;color:#64748b;transition:transform .2s}
.finding.open .toggle{transform:rotate(90deg)}
.finding-body{display:none;padding:1rem 1.25rem;border-top:1px solid #334155;font-size:.9rem}
.finding.open .finding-body{display:block}
.field{margin-bottom:.75rem}
.field-label{color:#64748b;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.25rem}
.field-value{color:#cbd5e1}
.evidence{background:#0f172a;padding:.75rem;border-radius:.5rem;font-family:monospace;font-size:.8rem;word-break:break-all;color:#fbbf24}
.meta{margin-top:2rem;padding-top:1.5rem;border-top:1px solid #334155;color:#64748b;font-size:.8rem;display:flex;gap:2rem;flex-wrap:wrap}
@media print{body{background:#fff;color:#1e293b}.container{max-width:100%}.finding{break-inside:avoid}.finding.open .finding-body{display:block}.stat{border-color:#ccc !important}}
</style>
</head>
<body>
<div class="container">
<h1>&#x1f6e1; Fendix Security Report</h1>
<p class="subtitle">{{.Metadata.Target}} &mdash; {{.Metadata.Duration}}</p>
<div class="summary">
<div class="stat critical"><div class="count">{{.Summary.Critical}}</div><div class="label">Critical</div></div>
<div class="stat high"><div class="count">{{.Summary.High}}</div><div class="label">High</div></div>
<div class="stat medium"><div class="count">{{.Summary.Medium}}</div><div class="label">Medium</div></div>
<div class="stat low"><div class="count">{{.Summary.Low}}</div><div class="label">Low</div></div>
<div class="stat info"><div class="count">{{.Summary.Info}}</div><div class="label">Info</div></div>
</div>
<div class="findings">
{{range .Findings}}<div class="finding" onclick="this.classList.toggle('open')">
<div class="finding-header">
<span class="badge {{.Severity}}">{{.Severity}}</span>
<span class="finding-title">{{.Title}}</span>
<span class="finding-endpoint">{{.Endpoint}}</span>
<span class="toggle">&#x25B6;</span>
</div>
<div class="finding-body">
<div class="field"><div class="field-label">Evidence</div><div class="evidence">{{.Evidence}}</div></div>
<div class="field"><div class="field-label">Fix</div><div class="field-value">{{.Fix}}</div></div>
<div class="field"><div class="field-label">Source</div><div class="field-value">{{.Source}} &middot; {{.Confidence}} confidence</div></div>
{{if .References}}<div class="field"><div class="field-label">References</div><div class="field-value">{{joinRefs .References}}</div></div>{{end}}
{{if .Line}}<div class="field"><div class="field-label">Location</div><div class="field-value">{{derefLine .Line}}</div></div>{{end}}
</div>
</div>
{{end}}</div>
<div class="meta">
<span>Scan started: {{formatTime .Metadata.StartedAt}}</span>
<span>Duration: {{.Metadata.Duration}}</span>
<span>Total findings: {{.Total}}</span>
<span>Fendix {{.Metadata.Version}}</span>
</div>
</div>
</body>
</html>`

// RenderHTML writes a self-contained HTML report to the writer.
func RenderHTML(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	funcMap := template.FuncMap{
		"joinRefs": func(refs []string) string {
			return strings.Join(refs, ", ")
		},
		"derefLine": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"formatTime": func(t interface{}) string {
			return fmt.Sprintf("%v", t)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	data := JSONReport{
		Metadata: meta,
		Summary:  CountSeverities(findings),
		Total:    len(findings),
		Findings: findings,
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("executing HTML template: %w", err)
	}
	return nil
}
