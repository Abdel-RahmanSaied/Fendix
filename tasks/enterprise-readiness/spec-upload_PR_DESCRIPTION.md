# Feature: upload an OpenAPI/Swagger spec file to start a scan

Lets users start an API scan from an **uploaded spec file** instead of only a
hosted schema URL — for internal/pre-prod APIs whose `/schema/` isn't publicly
reachable, or specs exported from other tools. Spans engine, backend, and
frontend. Also fixes a pre-existing artifact-path resolution bug found along
the way.

## Engine (`go/`)
- `crawler.go`: cap the **local-file** spec read with the same `maxSpecBytes`
  (50 MB) ceiling the URL path already had — the local branch was uncapped, a
  gap that matters now that the backend writes user-uploaded specs to disk.
  Test: `TestLoadSpec_LocalFileSizeCap`.
- (No other engine change needed — `--spec` already reads local files.)

## Backend (`fendix-backend/`)
- **`LaunchScanSerializer.spec_file`** (new `FileField`): verify-first gate in
  `validate()` → write into the per-tenant jail → store the jail-relative path
  (reuses the existing `validate_artifact_path` containment check) → mark
  ephemeral. Mutually exclusive with the URL-form `spec`; blackbox/hybrid only.
- **`validators.py`**: `parse_and_validate_spec` (size ≤ 10 MB → UTF-8 →
  JSON-or-alias-safe-YAML → OpenAPI/Swagger shape with `paths`),
  `write_spec_upload` (mkstemp in a 0700 jail subdir), `delete_spec_upload`,
  `sweep_orphaned_spec_uploads`. YAML aliases are refused outright
  (`_NoAliasYamlLoader`) to kill billion-laughs.
- **`tasks.py`**: `execute_scan` deletes the uploaded spec on every exit path;
  `purge_expired_scans` sweeps any leaked uploads (>1 h) as a backstop.
- **Pre-existing bug fixed** (`services.py`): the engine subprocess now runs
  with the per-tenant jail as its `cwd`. The artifact-path jail
  (baseline/wordlist/ignore/spec file-form) stored *relative* paths but the
  engine never ran in the jail, so those paths didn't resolve at runtime.
- Tests: `scanning/tests/test_spec_upload.py` (23 cases — parse/shape/bomb,
  jail write/delete/sweep, serializer wiring, cwd, task cleanup).

## Frontend (`fendix_frontend/`)
- `new-scan` page: a **URL / Upload-file toggle** on the spec field + a file
  input (`.json/.yaml/.yml`). `app/lib/api.ts` `launchScan` sends multipart
  when a file is chosen (`buildHeaders` lets the browser set the boundary).
- i18n keys added to `en` + `ar`.

## Security notes
- YAML parsed with a SafeLoader that refuses aliases (billion-laughs);
  size-capped before parse; UTF-8-only; deep-nesting `RecursionError` caught.
- Uploaded specs land in the existing per-tenant 0700 jail via `mkstemp`
  (O_EXCL, unpredictable name); deleted after the scan + janitor backstop.
- **Did NOT** validate the spec's `servers[]` for SSRF: real specs commonly
  list `http://localhost:8000` as a dev server (e.g. the spec that prompted
  this), and the backend always passes `--url` which the engine uses as the
  base (overriding spec servers), so they aren't dialed.

## Decisions
- Limits: 10 MB, JSON **and** YAML accepted.
- Scope included fixing the cwd gap (vs. a minimal absolute-path workaround).
