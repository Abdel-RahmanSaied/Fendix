# `dockerfile-best-practices` — Fendix reference plugin (Ruby)

Walks the source tree under `--code <path>` for `Dockerfile` and
`Dockerfile.*` files, then flags common antipatterns.

## What it detects

Per Dockerfile, the plugin emits up to five distinct findings:

| Finding | Severity | CWE | Detection |
|---------|----------|-----|-----------|
| Image pinned to `:latest` (or no tag) | LOW | CWE-1357 | `FROM` without an explicit tag or digest |
| Pipes remote script to shell (`curl … \| sh`) | MEDIUM | CWE-829 | `RUN` line containing `curl`/`wget` piped to `sh`/`bash`/`zsh` |
| `ADD <url>` instead of `COPY` | LOW | CWE-829 | `ADD https://…` or `ADD http://…` |
| Container runs as root | MEDIUM | CWE-250 | No `USER` directive, OR final `USER` is `root`/`0` |
| No `HEALTHCHECK` directive | INFO | CWE-1059 | No `HEALTHCHECK` anywhere in the file |

Findings are keyed at `<dockerfile>:<lineno>` so the engine's dedup
pass collapses the same antipattern across multiple Dockerfiles
(e.g. `Dockerfile` and `Dockerfile.app` having identical `FROM
alpine:latest` lines collapse into one finding with two
`affected_endpoints`).

## Why it exists

Two reasons:

1. **Real check.** These five antipatterns are the most common
   Dockerfile mistakes that surface during real production incidents
   — root-in-container expanded the blast radius, `:latest` made the
   build non-reproducible, `curl | sh` was the supply-chain hole.
2. **Reference: NDJSON wire contract in Ruby.** This plugin is one of
   two non-Go reference plugins (the other is
   [`license-header-check`](../license-header-check/) in Node).
   Together they prove the NDJSON wire contract is language-agnostic.

## Runtime requirements

Ruby 2.7+ (tested on 3.0+). Pure stdlib (`json`, `find`) — no `gem
install` needed.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `FENDIX_PLUGIN_MAX_FILES` | `5000` | Cap files visited during the walk |

## Install

```bash
mkdir -p ~/.fendix/plugins
cp -R examples/plugins/dockerfile-best-practices ~/.fendix/plugins/
fendix scan --code ./your-repo
```

For repo-pinned use, copy into `<repo>/.fendix/plugins/dockerfile-best-practices/`
and commit the directory.

## Tweaking

Open `run.rb` and modify the `analyze_dockerfile` function. The
detection is one big `case` block — add a new `when "ENV"` /
`when "EXPOSE"` clause to extend coverage. The plugin is ~200 LOC of
pure stdlib Ruby — read it top-to-bottom in a sitting.

## What this plugin doesn't do

- **Doesn't actually pull or scan the image** — purely static, looks
  at the Dockerfile text. Pair with a separate image-vulnerability
  scanner (Trivy, Grype) for per-layer CVE coverage.
- **Doesn't follow `FROM <stage>` multi-stage references** — only
  the FROM image itself is checked for `:latest`. Multi-stage names
  are skipped.
- **Doesn't enforce a base-image allowlist** — that's policy-shaped,
  belongs in a separate plugin keyed off your org's allowed registry
  list.

## License

MIT — see [LICENSE](../../../LICENSE) at the repo root.
