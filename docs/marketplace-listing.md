# Fendix — GitHub Marketplace Listing Copy

> This document contains the copy for the GitHub Marketplace listing submission.
> Once the App is registered and deployed, submit this at:
> https://github.com/marketplace/manage

---

## App name

Fendix

## Short description (80 chars max)

DAST + SAST as one PR check. Fails only when both engines confirm the bug.

## Detailed description

Fendix scans every pull request with two engines working together:

**Black-box (DAST):** Probes your running API for real vulnerabilities — SQL injection, auth bypass, CORS misconfiguration, missing security headers.

**White-box (SAST):** Analyzes your source code for hardcoded secrets, unsafe patterns, dependency CVEs, and taint-source-to-sink flows.

**The key insight:** A finding only fails your build when *both engines agree*. This eliminates the false-positive fatigue that makes teams ignore their security tooling.

### What happens on every PR

1. Fendix clones the PR head commit
2. Runs a hybrid scan (SAST over source + DAST if a preview URL is available)
3. Posts a single PR comment summarizing findings by severity
4. Uploads SARIF to the Code Scanning tab (inline annotations on changed lines)
5. Only blocks merge when a finding is confirmed by both engines

### Features

- Zero configuration — install and it works on the next PR
- Correlated findings with severity escalation (DAST + SAST + reachability proof)
- SARIF integration with GitHub Code Scanning
- Plugin system for custom checks (`~/.fendix/plugins/`)
- Supports `.fendix.yaml` policy files for per-repo customization
- MIT licensed, fully open source

### What Fendix does NOT do

- No telemetry, no phone-home, no data collection
- No cloud service dependency — the App runs on YOUR infrastructure
- No vendor lock-in — self-host or use the GitHub Actions workflow instead

## Category

Security

## Pricing

Free

## Support URL

https://github.com/Abdel-RahmanSaied/Fendix/issues

## Documentation URL

https://github.com/Abdel-RahmanSaied/Fendix/blob/main/docs/github-app.md

## Screenshot descriptions

1. **PR comment** — Shows the findings summary comment Fendix posts on a pull request (severity table + source breakdown)
2. **HTML report** — The self-contained HTML report with expandable finding details
3. **Code Scanning** — SARIF annotations inline on the PR's changed files

## Installation instructions (shown post-install)

Fendix is now active on your selected repositories. Every new pull request
will trigger a security scan automatically.

**First scan:** Open a PR (or push to an existing one) and wait ~60 seconds.
You'll see a Fendix comment with the scan results.

**Configuration (optional):** Add a `.fendix.yaml` to your repo root to
customize severity thresholds, ignored rules, or authentication profiles.
Run `fendix init` locally to generate a starter config.

**Troubleshooting:** If no comment appears after 2 minutes, check the
webhook delivery log in your App settings (Settings → Developer settings →
GitHub Apps → Fendix → Advanced → Recent Deliveries).
