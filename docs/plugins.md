# Fendix plugin system

The plugin system lets you extend Fendix with custom checks without
modifying the engine source tree. Plugins ship as a directory
containing a `plugin.yaml` manifest plus an executable entrypoint
that speaks the same NDJSON contract Fendix's own engine uses (see
[ADR-002](adr/ADR-002-ndjson-ipc.md)).

> **Compatibility note (TASK-127, v0.9.0):** the v0.7-era plugin wire
> contract is unchanged in v0.9. All three reference plugins
> (`custom-secret-pattern`, `custom-blackbox-check`,
> `custom-semgrep-pack`) were re-audited against the TASK-118 binary
> after the embedded Python distribution was dropped — discovery
> works, NDJSON in/out works, findings flow through correlation +
> dedup unchanged. Plugins do not depend on `embedded.HasEngine()`,
> the extracted `~/.fendix/engine/` tree, or `--python-engine` being
> set. **Known pre-existing limitation:** the discovery walk uses
> `os.ReadDir().IsDir()` which returns `false` for symlinked plugin
> directories — install plugins as real directories (or use
> `cp -R`/`git clone`) rather than `ln -s`.

This document covers:

1. [Discovery and execution model](#discovery-and-execution-model)
2. [The `plugin.yaml` schema](#the-pluginyaml-schema)
3. [The IPC contract](#the-ipc-contract)
4. [Reference plugins](#reference-plugins)
5. [Disabling plugins](#disabling-plugins)
6. [Security model](#security-model)

---

## Discovery and execution model

On every scan that doesn't pass `--no-plugins`, the engine walks
two roots in order:

| Order | Root | Purpose |
|-------|------|---------|
| 1 | `<scan-cwd>/.fendix/plugins/` | Repo-local; takes precedence on collision |
| 2 | `~/.fendix/plugins/`           | User-global; cross-repo defaults |

Each direct child directory is treated as a candidate plugin. A
plugin is loaded when its `plugin.yaml` parses cleanly and validates;
plugins that fail validation are skipped at WARN log level so a
single broken plugin can never block the scan.

After discovery, every plugin whose `mode` matches the current scan
runs in sequence. A plugin's findings flow through the same
correlation, deduplication, severity-consistency, and ID-assignment
pipeline as the embedded engines — so a custom-secret-pattern plugin
that flags a hardcoded token at `src/auth.py:42` correlates against a
blackbox finding at the same auth endpoint exactly like the built-in
secrets analyzer would.

Per-plugin runtime is capped: the manifest's `timeout` (default 30s,
maximum 5m) bounds wall-clock time. A plugin that blows past its
timeout is killed; partial findings emitted before the kill are
preserved. Any non-zero exit also surfaces partial findings, with
the scan continuing through other plugins.

---

## The `plugin.yaml` schema

```yaml
name: my-plugin                    # required; no path separators
version: 0.1.0                     # optional
description: |                     # optional; surfaced in slog
  What this plugin does and why.
entrypoint: ./run.py               # required; relative to plugin dir
mode: blackbox | whitebox | hybrid # required
categories:                        # optional; informational
  - secrets
timeout: 30s                       # optional; default 30s, max 5m
```

Unknown fields are **rejected** with a clear error message — same
posture as `.fendix.yaml` (TASK-109). Typos like `entry_point` or
`Mode` surface at load time rather than silently dropping.

### Mode semantics

| `mode`      | When the plugin runs |
|-------------|----------------------|
| `blackbox`  | `--url` is set |
| `whitebox`  | `--code` or `--spec` is set |
| `hybrid`    | Either condition holds (the plugin can ignore unset fields) |

Plugins that don't match the current scan's mode are silently
skipped at DEBUG level — no error.

---

## The IPC contract

### Input (engine → plugin, on stdin, single JSON line)

```json
{
  "mode": "whitebox",
  "url": "",
  "spec": "./openapi.yaml",
  "code_path": "./src",
  "auth": "Bearer ...",
  "auth_type": "bearer",
  "categories": ["secrets"],
  "verbose": false
}
```

The plugin reads this single line from stdin, parses it as JSON,
and writes findings to stdout.

### Output (plugin → engine, on stdout, NDJSON)

Zero or more `Finding` objects, one per line:

```json
{"id":"","title":"...","severity":"HIGH","category":"secrets","endpoint":"src/x.py:14","evidence":"...","fix":"...","confidence":"HIGH"}
```

Severity values: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`.
Confidence values: `HIGH` | `MEDIUM` | `LOW`.

Then a terminator:

```json
{"done": true, "total": 1}
```

To signal an error and stop:

```json
{"done": true, "total": 0, "error": "could not parse target"}
```

The engine logs `error`, treats the plugin as failed, but continues
running other plugins. Any findings emitted before the error are
preserved.

### Environment variables

| Variable | Value |
|----------|-------|
| `FENDIX_PLUGIN_NAME` | The plugin's `name:` from the manifest |
| `FENDIX_PLUGIN_DIR`  | Absolute path to the plugin directory |

Use `FENDIX_PLUGIN_DIR` to load files (e.g. rule packs, signature
lists) bundled alongside the entrypoint without depending on the
caller's working directory.

### Provenance

Every finding emitted by a plugin gets `fendix-plugin:<name>`
appended to its `references` array. Reports and dedup logic use
this to attribute findings to the originating plugin.

---

## Reference plugins

Three reference plugins live under
[`examples/plugins/`](../examples/plugins/):

| Plugin | Mode | What it demonstrates |
|--------|------|---------------------|
| [`custom-secret-pattern`](../examples/plugins/custom-secret-pattern/) | whitebox | Custom regex-based secret detection over the source tree (Python stdlib only) |
| [`custom-blackbox-check`](../examples/plugins/custom-blackbox-check/) | blackbox | Custom HTTP response assertion (Python stdlib `urllib`) |
| [`custom-semgrep-pack`](../examples/plugins/custom-semgrep-pack/)     | whitebox | Wraps a custom Semgrep rule pack via shell + `jq` |

To try a reference plugin against a real scan:

```bash
# Copy a reference plugin into the user-global root
mkdir -p ~/.fendix/plugins
cp -r examples/plugins/custom-secret-pattern ~/.fendix/plugins/

# Run a normal scan; the plugin runs alongside the embedded engines
fendix scan --code ./your-repo
```

For repo-pinned plugins, copy into `.fendix/plugins/<name>/`
inside the repo and commit the directory.

---

## Disabling plugins

Pass `--no-plugins` on any `fendix scan` invocation to skip plugin
discovery entirely. Useful when:

- Debugging a flaky plugin that's interfering with a scan
- Comparing scan output with vs. without third-party plugins
- Running fendix in a sandboxed CI job that shouldn't execute
  arbitrary plugin code

`--no-plugins` defaults to `false` (plugins enabled) so that
operators who copy plugins into the standard roots get
plug-and-play behavior.

---

## Security model

**Plugins are arbitrary executables.** When you copy a plugin into
`.fendix/plugins/` or `~/.fendix/plugins/`, you are giving it the
same privileges as your `fendix` invocation: filesystem access,
network access, the auth token from `--auth`. Treat plugin
installation the same as installing any other binary.

The engine applies these guardrails:

| Guardrail | Effect |
|-----------|--------|
| Per-plugin timeout (default 30s, max 5m) | Runaway plugins can't pin a CI job |
| Manifest-level path validation | Entrypoint must be relative to plugin dir; no `..` traversal accepted |
| Plugin-mode filter | Whitebox plugins don't run on blackbox-only scans |
| No automatic privilege escalation | Plugins inherit the engine process's UID and capabilities; the engine never `sudo`s into a plugin |
| Stderr captured at DEBUG level | Plugin chatter doesn't pollute stdout/stderr unless `--verbose` is set |
| Crash isolation | A plugin that exits non-zero or emits an error terminator does not abort the scan |

We do **not** sandbox plugins (no seccomp, no chroot, no namespace
isolation). If you need that, run the entire `fendix` invocation in
a container or under your platform's existing job-isolation policy.

### Licensing

Out-of-tree plugins choose their own license. The engine loads any
plugin that implements the IPC contract. Plugins shipped in this
repo (under `examples/plugins/`) are MIT to match the rest of the
tree. See [ADR-007](adr/ADR-007-open-source.md) for the strategic
posture.

---

## Authoring checklist

Before publishing a plugin:

- [ ] `plugin.yaml` has `name`, `entrypoint`, `mode` set
- [ ] Entrypoint is executable (`chmod +x run.py`)
- [ ] Entrypoint reads exactly one line from stdin and tolerates
  malformed input (emit `{"done": true, "error": "..."}`)
- [ ] Every finding has `title` and `severity` (other fields are
  optional — engine discards findings missing required fields)
- [ ] Terminator `{"done": true, "total": N}` is the **last** thing
  written to stdout
- [ ] Stderr only contains diagnostics — never JSON intended as
  output
- [ ] Plugin handles its own timeouts/cancellation — when the
  engine kills a stuck plugin, in-flight findings are lost
- [ ] No secrets in `evidence` — mask them like the embedded engines
  do (`[REDACTED]`)

## References

- [ADR-002 — Newline-delimited JSON IPC](adr/ADR-002-ndjson-ipc.md)
- [ADR-007 — Open-source license + single-repo posture](adr/ADR-007-open-source.md)
- [`docs/schema.md`](schema.md) — full Finding schema
- [`internal/plugin/plugin.go`](../go/internal/plugin/plugin.go) — engine-side discovery + execution
