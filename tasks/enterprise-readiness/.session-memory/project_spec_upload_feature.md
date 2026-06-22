---
name: project-spec-upload-feature
description: "In-progress feature — OpenAPI spec file upload (frontend → backend → engine), plus a discovered pre-existing artifact-path cwd bug being fixed alongside it."
metadata:
  node_type: memory
  type: project
---

Feature: let users **upload an OpenAPI/Swagger file** to start a scan
(instead of only a hosted schema URL). Scoped 2026-06-22.

User decisions:
- Scope = **upload feature + fix the pre-existing cwd gap** (not just the
  minimal workaround).
- Upload limits = **10 MB, accept JSON + YAML**.

Engine (`go/`): `--spec` already reads local files (crawler.go `loadSpec`).
Only change needed was a **size cap on the local-file read** (was uncapped;
URL path capped at 50 MB) — DONE: shared `maxSpecBytes` const, test
`TestLoadSpec_LocalFileSizeCap`. Note: yaml.v3 v3.0.1 *already* guards
billion-laughs via `alias_ratio` (decode.go:458) — the security review's
"no alias defense" claim was wrong.

Backend (`fendix-backend/backend/scanning/`): `spec` is already modeled as
URL-or-jail-relative-path (`LaunchScanSerializer.validate`, validators
`validate_artifact_path`), and URL-form specs get DNS-rebinding re-verified
at task time (`tasks.py` `_URL_FIELDS`). Multipart upload works out of the
box (DRF default parsers include MultiPartParser). Plan: add `spec_file`
FileField → verify-first gate (size→utf8→parse JSON/yaml.safe_load with
aliases disabled→OpenAPI shape with `paths`) → write into per-tenant jail
→ store relative path → delete in task `finally` + janitor sweep for the
crash/quota-deny leak case.

**Pre-existing bug found (being fixed):** the artifact-path jail
(`baseline`/`wordlist`/`ignore`/spec file-form) validates a *relative* path
into the per-tenant jail (`_user_jail_root`, `SCAN_ARTIFACT_ROOT`, default
`/var/lib/fendix-artifacts`) but the engine subprocess is launched with **no
`cwd=`** anywhere in services.py/tasks.py — so those relative paths never
resolve to the jail at runtime. The `validate_artifact_path` docstring
*claims* "engine cwd = jail" but it was never wired. Fix = set
`cwd=_user_jail_root(scan.user)` on the engine `Popen` (services.py
`_spawn`). Real `--code` usage is the absolute git-clone dir
(cwd-independent); `CODE_PATH_ROOT` is unset in settings, so cwd=jail is
safe for `--code`.

**Security-review correction:** do NOT validate the spec's `servers[]`/`host`
for SSRF — the MURI spec lists `http://localhost:8000` as a server, so that
would falsely reject normal specs; and `--url` (always present for
blackbox/hybrid) overrides spec servers in the engine, so they aren't dialed.

See [[project-fendix-overview]].
