# `license-header-check` — Fendix reference plugin (Node)

Walks the source tree under `--code <path>` and flags any source
file that lacks an `SPDX-License-Identifier:` header in its first
30 lines.

## What it detects

Files matching one of the source extensions
(`.js .jsx .ts .tsx .py .rb .go .rs .java .kt .scala .swift .c .h .cpp .hpp .cc .cs .php`)
that don't contain an `SPDX-License-Identifier: <id>` line near the top.

One LOW finding per offending file.

## Why it exists

Two reasons:

1. **Real check.** Missing license headers cause genuine compliance
   pain — auditors flag them, downstream consumers can't tell which
   license a file ships under, and SPDX-aware tooling silently
   excludes the file from license-bill-of-materials reports.
2. **Reference: NDJSON wire contract in Node.** This plugin is one of
   two non-Go reference plugins (the other is
   [`dockerfile-best-practices`](../dockerfile-best-practices/) in
   Ruby). Together they prove the NDJSON wire contract is
   language-agnostic.

## Runtime requirements

Node.js (any modern version; tested on Node 20+). Pure stdlib
(`node:fs`, `node:path`) — no `npm install` needed.

## Configuration

Two environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FENDIX_LICENSE_HEADER_REGEX` | `SPDX-License-Identifier:\s*\S+` | Override the header detection pattern (e.g. for non-SPDX corporate license templates) |
| `FENDIX_PLUGIN_MAX_FILES` | `5000` | Cap files scanned (large monorepos) |

Example with a custom header pattern:

```bash
FENDIX_LICENSE_HEADER_REGEX="Copyright \(c\) 20\d\d Acme Corp" \
  fendix scan --code ./src
```

## Install

```bash
mkdir -p ~/.fendix/plugins
cp -R examples/plugins/license-header-check ~/.fendix/plugins/
fendix scan --code ./your-repo
```

For repo-pinned use, copy into `<repo>/.fendix/plugins/license-header-check/`
and commit the directory.

## Tweaking

Open `run.js` and modify the `SOURCE_EXTS` set or `HEADER_REGEX`
constant. The plugin is ~150 LOC of pure stdlib JavaScript — read it
top-to-bottom in a sitting.

## License

MIT — see [LICENSE](../../../LICENSE) at the repo root.
