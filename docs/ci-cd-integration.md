# CI/CD Integration

Fendix produces SARIF 2.1.0 output that integrates directly with GitHub Advanced Security, enabling PR annotations and the Security tab.

## GitHub Actions — SARIF Upload

This workflow runs Fendix on every pull request, uploads SARIF results to GitHub Code Scanning, and fails the build if any HIGH or CRITICAL findings are detected.

```yaml
name: Fendix Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Install Fendix
        run: |
          curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh
          # Or build from source:
          # go build -o fendix ./go/cmd/fendix/

      - name: Run security scan
        run: |
          fendix scan \
            --spec openapi.yaml \
            --code ./src \
            --format sarif \
            --output results.sarif \
            --fail-on HIGH
        continue-on-error: true  # Upload SARIF even if findings exist

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: fendix

      - name: Fail on findings
        run: |
          fendix scan \
            --spec openapi.yaml \
            --code ./src \
            --format json \
            --fail-on HIGH
```

## GitHub Actions — Baseline Diff

Only report new findings by comparing against a saved baseline. This prevents alert fatigue from pre-existing issues.

```yaml
      - name: Download baseline
        uses: actions/download-artifact@v4
        with:
          name: fendix-baseline
          path: .fendix/
        continue-on-error: true  # First run has no baseline

      - name: Run scan with baseline
        run: |
          fendix scan \
            --spec openapi.yaml \
            --code ./src \
            --format json \
            --output findings.json \
            --baseline .fendix/baseline.json \
            --save-baseline .fendix/baseline.json \
            --fail-on HIGH

      - name: Upload baseline
        if: github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: fendix-baseline
          path: .fendix/baseline.json
```

## GitHub Actions — Live API Scan

For scanning a deployed staging environment before promoting to production:

```yaml
      - name: Scan staging API
        run: |
          fendix scan \
            --url https://staging-api.example.com \
            --auth "Bearer ${{ secrets.STAGING_API_TOKEN }}" \
            --format sarif \
            --output results.sarif \
            --fail-on CRITICAL
```

## GitHub Actions — Active Probing (with consent)

Enable injection detection for pre-production environments:

```yaml
      - name: Active security scan
        run: |
          fendix scan \
            --url https://staging-api.example.com \
            --auth "Bearer ${{ secrets.STAGING_API_TOKEN }}" \
            --enable-active \
            --format sarif \
            --output results.sarif \
            --fail-on HIGH
```

## Re-rendering Reports

Convert a saved JSON findings file to HTML for human review or SARIF for CI upload:

```bash
# JSON -> HTML
fendix report --input findings.json --format html --output report.html

# JSON -> SARIF
fendix report --input findings.json --format sarif --output results.sarif
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no findings at or above `--fail-on` threshold |
| 1 | Scan complete, findings found at or above threshold |
| 2 | Scan error (network failure, invalid config, etc.) |

Use `--fail-on` to control which severity level triggers a non-zero exit:
- `--fail-on CRITICAL` — only fail on critical findings
- `--fail-on HIGH` — fail on high or critical
- `--fail-on MEDIUM` — fail on medium, high, or critical

## Suppressing Known Issues

Create a `.fendix-ignore` file to suppress known or accepted findings:

```yaml
ignore:
  - id: SEC-014
    reason: "Rate limiting handled at API gateway"
    until: 2026-12-01

  - endpoint: GET /health
    reason: "Public health check by design"

  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints intentionally unauthenticated"
```
