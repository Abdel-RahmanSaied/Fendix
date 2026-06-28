# Fendix Privacy & Data Handling

What Fendix reads, what it sends, and what it stores. Fendix is a developer
security tool that runs on your machine / your CI — there is **no Fendix
backend**, no account required for the CLI, and **no telemetry**.

Last reviewed: 2026-06-28 (v0.21).

## TL;DR

- **No telemetry.** Fendix never phones home about your usage, code, or findings.
- The **only** non-target network traffic is dependency-CVE lookups during a
  `--code`/`--spec` scan (`api.osv.dev`, `vuln.go.dev`). `--offline` disables them.
- Findings, reports, and metrics stay **on your disk**. You choose where they go.

## What Fendix reads

| Input | Read when | Leaves your machine? |
|-------|-----------|----------------------|
| Source files under `--code` | white-box scan | No (analyzed locally) |
| The target URL under `--url` | black-box scan | Only requests to that target you specified |
| OpenAPI/Swagger under `--spec` | spec scan | No (parsed locally) |
| Dependency manifests (`requirements.txt`, `package-lock.json`, `go.mod`, …) | dep-CVE scan | Package **names + versions** are sent to the CVE source (see below), unless `--offline` |

## Network egress contract

This mirrors the README "What Fendix sends to the network" section — the
authoritative, code-enforced version.

| Scenario | Outbound traffic |
|----------|------------------|
| `fendix scan --url …` | Requests to the target you named, and nothing else. |
| `fendix scan --code …` (default) | Dependency-CVE lookups to `api.osv.dev` (PyPI/npm) and `vuln.go.dev` (Go, via govulncheck). Everything else (secrets, semgrep, textscan) is local. |
| `fendix scan --code … --offline` | **Zero outbound.** See below. |
| `fendix scan --code … --no-native-deps` | Skips the Go dep scanner's outbound call. |
| `fendix scan` (no target) | Errors out. Zero outbound. |

Dependency-CVE lookups send only package coordinates (ecosystem, name,
version) — never your source code or file contents.

### Air-gapped mode

`--offline` makes dependency scanning **hermetic**:

- pip / npm advisories are read from a local snapshot
  (`--offline-db`, default `~/.fendix/offline-db.json`, built with
  `fendix db update`).
- govulncheck needs `vuln.go.dev`, so in offline mode it is recorded
  **SKIPPED** rather than silently reaching the network.
- The offline code path (`pip.ScanOffline` / `npm.ScanOffline`) takes no HTTP
  client at all — it is *structurally* incapable of a network call.

Verify it: `sudo tcpdump -n host not <target>` while running an `--offline` scan.

## What Fendix stores

| Artifact | Location | Notes |
|----------|----------|-------|
| Scan reports (JSON/HTML/SARIF/PDF) | wherever you point `--output` | You control retention |
| Config-leak findings | in the report | The served-file **body is never captured** — only the HTTP status + path, so a leaked secret isn't re-persisted into your report |
| Debug bundle (`--debug-bundle`) | the path you give | Redacted; opt-in, for bug reports |

### Product metrics

v0.20 added an **opt-in, local-only** metrics log:

- Off by default. Enabled only when `FENDIX_METRICS=true`.
- Written to `metrics/events.jsonl` (override with `FENDIX_METRICS_PATH`); the
  default is `.gitignore`d.
- **Structural data only** — version, scan phase, duration, finding *count*,
  memory. By construction the event record has no field for source code, file
  paths, hostnames, secrets, or finding content.
- **Never transmitted.** `fendix metrics show/export/clear` operate purely on
  the local file. There is no analytics endpoint.

## Hosted / SaaS

The Fendix web application (dashboard, org workspaces) is a separate, optional
product with its own data handling and its own DPA. This document covers the
**CLI / engine**, which needs no account and no backend. If you only run the
CLI, none of the hosted-product data handling applies to you.

## Questions or a discrepancy?

If anything here doesn't match observed behavior, treat it as a security issue
and report it per [SECURITY.md](../SECURITY.md). See the [Trust Center](trust-center.md)
for the full picture.
