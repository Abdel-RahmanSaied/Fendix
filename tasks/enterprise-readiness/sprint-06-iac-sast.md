# Sprint 06 — IaC scanner (Dockerfile + Kubernetes)

**Phase:** 2.3 | **Estimate:** 4 days | **Risk:** Med | **Ships:** v0.12.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §3 (no IaC scanning today)

---

## Why

IaC misconfigurations are the #1 cloud-breach root cause (per Verizon DBIR 2024). Fendix today has zero IaC coverage. This sprint adds two parsers — Dockerfile and Kubernetes YAML — with 8 rules total. **Terraform is deferred** pending decision D2 (see [PLAN.md](PLAN.md)).

---

## Cuts vs. source brief

The brief asked for Terraform + Dockerfile + k8s. We're shipping Dockerfile + k8s only. Terraform's HCL has multi-line blocks, heredocs, and interpolations that defeat regex parsing — a regex-only TF scanner would generate wrong-block-context FPs on every customer codebase.

Decision D2 (in PLAN.md):
- **Option A:** Add `hashicorp/hcl/v2` (MPL-2.0). 6 TF rules in a follow-up Sprint 06.5.
- **Option B:** Stay regex-only on TF, accept high FP rate. Not recommended.
- **Option C:** Hand-rolled HCL subset parser. ~2 weeks. Last resort.

Until D2 is resolved, this sprint ships Dockerfile + k8s.

---

## Read first

- [`go/internal/scanner/secrets/scanner.go`](../../go/internal/scanner/secrets/scanner.go) — your file-walker template.
- `gopkg.in/yaml.v3` is already in go.mod — use it for k8s YAML.
- [Sprint 04 (Go SAST)](sprint-04-go-sast.md) — orchestrator wiring pattern (auto-detect, no flag).

---

## Rules

### Dockerfile (4 rules) — `iac/dockerfile.go`

Parse line-by-line. Track running state: current FROM image, current USER, last instruction kind.

| Rule ID | Severity | Detection |
|---|---|---|
| `DOCKER_ROOT_USER` | HIGH | `USER root` OR no USER directive before `CMD`/`ENTRYPOINT` (final root context) |
| `DOCKER_ADD_URL` | MEDIUM | `ADD http://` or `ADD https://` (use COPY instead, or download in build step with checksum verification) |
| `DOCKER_LATEST_TAG` | MEDIUM | `FROM <image>:latest` OR `FROM <image>` with no tag |
| `DOCKER_SECRET_ENV` | CRITICAL | `ENV` or `ARG` with name matching `(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)` and a non-empty default value |

File extensions: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`.

### Kubernetes YAML (4 rules) — `iac/k8s.go`

Use `gopkg.in/yaml.v3` to decode each YAML document. K8s files often have multiple `---`-separated documents — handle that with `yaml.Decoder.Decode` in a loop.

| Rule ID | Severity | Detection |
|---|---|---|
| `K8S_PRIVILEGED` | CRITICAL | `securityContext.privileged: true` at container OR pod level |
| `K8S_HOST_NETWORK` | HIGH | `spec.hostNetwork: true` OR `spec.hostPID: true` OR `spec.hostIPC: true` at pod-spec level |
| `K8S_NO_RESOURCE_LIMITS` | MEDIUM | Container spec missing `resources.limits` block (no memory/CPU caps → DoS surface) |
| `K8S_SECRET_IN_CONFIGMAP` | HIGH | `kind: ConfigMap` with any `data.<key>` value matching known secret patterns (delegate to `secrets.Scan` on the YAML value, attribute to ConfigMap path) |

Detect k8s files: read first ~1KB, look for `apiVersion:` and `kind: <known-kind>`. Skip `kind: List` containers cleanly.

---

## Package layout

```
go/internal/scanner/iac/
  scanner.go            — top-level Scanner, dispatches by file kind
  detect.go             — kind detection (Dockerfile vs k8s YAML vs unrelated)
  dockerfile.go         — parser + 4 rules
  k8s.go                — yaml.v3-based parser + 4 rules
  rules_dockerfile.go   — rule predicates (DOCKER_ROOT_USER, etc.)
  rules_k8s.go          — rule predicates
  scanner_test.go
  testdata/
    Dockerfile.vuln
    Dockerfile.safe
    deployment-privileged.yaml
    deployment-safe.yaml
    configmap-secret-leak.yaml
```

## Orchestrator wiring

Step 3.10, after jssast. Auto-detect:
- Walk root, early-exit on first `Dockerfile`, `*.dockerfile`, or YAML file with `apiVersion` + `kind` markers.
- If neither found, skip the engine entirely.

## Tests

- Per Docker rule: 2 positive + 2 negative = 4 × 4 = **16 tests**.
- Per k8s rule: 2 positive + 2 negative + 1 multi-doc test = 5 × 4 = **20 tests**.
- 1 end-to-end test using the testdata/ fixtures.

## CHANGELOG

```markdown
### Added (v0.12.0)

- **IaC SAST engine** — new `internal/scanner/iac/`. Two sub-parsers:
  - **Dockerfile** (4 rules): DOCKER_ROOT_USER, DOCKER_ADD_URL,
    DOCKER_LATEST_TAG, DOCKER_SECRET_ENV
  - **Kubernetes YAML** (4 rules): K8S_PRIVILEGED, K8S_HOST_NETWORK,
    K8S_NO_RESOURCE_LIMITS, K8S_SECRET_IN_CONFIGMAP
  Auto-detected; no flag. **Terraform deferred** to Sprint 06.5
  pending decision D2 (HCL parser license acceptance).
```

---

## Risks

- **K8S_SECRET_IN_CONFIGMAP** overlaps with the secrets scanner. Decision: invoke `secrets.Scan` against each ConfigMap `data` value separately; attribute findings to the ConfigMap path. Don't double-emit.
- **Helm templates** (`{{ .Values.foo }}`) in YAML will confuse the YAML decoder. Detect via filename glob `**/templates/*.yaml` and skip with a `note: helm template skipped` log line. Out of scope to render Helm.
- **Multi-doc k8s files**: standard pattern but easy to mishandle. Use `yaml.Decoder.Decode` in a loop, not `yaml.Unmarshal`.

## Definition of done

See [PLAN.md](PLAN.md) cross-cutting checklist. Specifically:
- 36+ tests
- E2E test on testdata/ fixtures
- Auto-detect bypasses non-IaC scans cleanly (verified by bench: no regression on Python-only scans)

## Follow-ups

- **Sprint 06.5:** Terraform support — gated on D2 decision (HCL parser dep).
- **Sprint 06.6:** GitHub Actions workflows (`.github/workflows/*.yml`) for `actions: write` over-permissioned tokens, untrusted `${{ github.event.pull_request.title }}` interpolation in `run:` steps.
- **Sprint 06.7:** Helm template rendering and post-render scan.

## Status

**Status:** shipped as part of the textscan engine, commit
[`5b8492f`](../../../../commit/5b8492f) — `feat(textscan): unified Go + JS + IaC SAST engine (Sprints 04, 05, 06)`. Dockerfile and k8s rules landed; Terraform stayed
deferred (D2 unresolved — see [DECISIONS.md](DECISIONS.md#L80-L85)).
Source: [`go/internal/scanner/textscan/`](../../go/internal/scanner/textscan/).

**Status section backfill (2026-05-16):** Section was empty at ship
time (DoD #7 not honored). See sprint-04 Status for the matching note
on what details are and aren't recorded.
