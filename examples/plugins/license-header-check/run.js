#!/usr/bin/env node
// license-header-check reference plugin (Node, stdlib-only).
//
// Walks the configured code path looking for source files that lack
// an SPDX-License-Identifier header. Emits one LOW finding per file
// (deduplicated to one per file even when the same file has multiple
// candidate header positions).
//
// Replace SOURCE_EXTS or HEADER_REGEX to tailor this to your own
// organization's license-header policy. The Fendix engine takes care
// of correlation, dedup, severity-consistency enforcement, and ID
// assignment in the report layer — this plugin just finds matches.
//
// Wire contract: NDJSON over stdin/stdout (ADR-002). Read the
// ScanRequest from stdin, emit Findings to stdout, finish with a
// done terminator. Same contract the engine's Python whitebox path
// uses, and the same contract the other reference plugins use
// (custom-secret-pattern.py, custom-blackbox-check.py,
// custom-semgrep-pack.sh, dockerfile-best-practices.rb).
//
// Limitations (deliberate, for readability):
//   - Walks every matching file; large monorepos may want to cap via
//     FENDIX_PLUGIN_MAX_FILES env var (defaults to 5000).
//   - Skips common build-output / vendor dirs (.git, node_modules,
//     vendor, __pycache__, dist, build, .venv, venv, target, .tox).
//   - Only inspects the first 30 lines of each file — license
//     headers belong at the top.

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const SOURCE_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx",
  ".py", ".rb", ".go", ".rs",
  ".java", ".kt", ".scala", ".swift",
  ".c", ".h", ".cpp", ".hpp", ".cc",
  ".cs", ".php",
]);

const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "__pycache__",
  ".venv", "venv", "dist", "build", "target", ".tox",
]);

const DEFAULT_HEADER_REGEX = /SPDX-License-Identifier:\s*\S+/;
const HEADER_REGEX = process.env.FENDIX_LICENSE_HEADER_REGEX
  ? new RegExp(process.env.FENDIX_LICENSE_HEADER_REGEX)
  : DEFAULT_HEADER_REGEX;

const MAX_FILES = Number.parseInt(
  process.env.FENDIX_PLUGIN_MAX_FILES || "5000",
  10,
);

const HEADER_SCAN_LINES = 30;

function emit(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function readScanRequest() {
  let raw = "";
  try {
    raw = fs.readFileSync(0, "utf-8");
  } catch (_) {
    return {};
  }
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch (err) {
    emit({
      done: true,
      total: 0,
      error: `bad scan request: ${err.message}`,
    });
    process.exit(0);
  }
}

function* walk(root) {
  let seen = 0;
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_) {
      continue;
    }
    for (const entry of entries) {
      if (seen >= MAX_FILES) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name).toLowerCase();
      if (!SOURCE_EXTS.has(ext)) continue;
      seen += 1;
      yield full;
    }
  }
}

function hasLicenseHeader(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
  } catch (_) {
    return true; // unreadable → don't false-positive
  }
  try {
    // Read first ~8 KiB — enough for the first 30 lines of any sane file.
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const head = buf.subarray(0, n).toString("utf-8", 0, n);
    const lines = head.split("\n", HEADER_SCAN_LINES + 1).slice(0, HEADER_SCAN_LINES);
    return lines.some((line) => HEADER_REGEX.test(line));
  } catch (_) {
    return true;
  } finally {
    fs.closeSync(fd);
  }
}

function main() {
  const req = readScanRequest();
  const codePath = req.code_path || ".";

  let root;
  try {
    const stat = fs.statSync(codePath);
    if (!stat.isDirectory()) {
      emit({
        done: true,
        total: 0,
        error: `code_path is not a directory: ${codePath}`,
      });
      return 1;
    }
    root = path.resolve(codePath);
  } catch (err) {
    emit({
      done: true,
      total: 0,
      error: `code_path not accessible: ${err.message}`,
    });
    return 1;
  }

  let total = 0;
  for (const filePath of walk(root)) {
    if (hasLicenseHeader(filePath)) continue;
    const rel = path.relative(root, filePath) || filePath;
    emit({
      title: "Source file missing SPDX-License-Identifier header",
      severity: "LOW",
      category: "compliance",
      endpoint: `${rel}:1`,
      line: `${rel}:1`,
      evidence: `File starts without an SPDX-License-Identifier in the first ${HEADER_SCAN_LINES} lines`,
      fix:
        "Add `// SPDX-License-Identifier: <SPDX-ID>` (or the comment style for the file's language) " +
        "as the first or near-first line of the file. See https://spdx.dev/learn/handling-license-info/",
      references: ["CWE-1104"],
      confidence: "HIGH",
    });
    total += 1;
  }

  emit({ done: true, total });
  return 0;
}

process.exit(main());
