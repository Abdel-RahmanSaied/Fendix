#!/usr/bin/env ruby
# dockerfile-best-practices reference plugin (Ruby, stdlib-only).
#
# Walks the configured code path looking for Dockerfile and
# Dockerfile.* files, then flags common antipatterns:
#
#   - Container runs as root (no USER directive, OR final USER is
#     `root` / `0`)
#   - Image pinned to `:latest` instead of an explicit tag/digest
#   - No HEALTHCHECK directive
#   - `curl ... | sh` (or wget pipe) install — supply chain risk
#   - `ADD https://...` — prefer COPY; ADD's auto-extract semantics
#     surprise people
#
# Each finding is keyed at the Dockerfile + line number so the
# engine's dedup pass collapses duplicates across mirrored Dockerfiles
# (e.g. the same antipattern in Dockerfile and Dockerfile.app).
#
# Wire contract: NDJSON over stdin/stdout (ADR-002). Read the
# ScanRequest from stdin, emit Findings to stdout, finish with a
# done terminator. Same shape the engine's Python whitebox path uses.
#
# Pure Ruby stdlib — `gem install` not required. Tested against
# Ruby 3.0+; should work on 2.7+.

require "json"
require "find"

SOURCE_NAMES = %w[Dockerfile].freeze
SKIP_DIRS = %w[
  .git node_modules vendor __pycache__
  .venv venv dist build target .tox
].freeze
MAX_FILES = (ENV["FENDIX_PLUGIN_MAX_FILES"] || "5000").to_i

def emit(obj)
  $stdout.write("#{JSON.generate(obj)}\n")
  $stdout.flush
end

def read_scan_request
  raw = $stdin.read.to_s.strip
  return {} if raw.empty?

  JSON.parse(raw)
rescue JSON::ParserError => e
  emit(done: true, total: 0, error: "bad scan request: #{e.message}")
  exit(0)
end

def dockerfile?(name)
  return true if SOURCE_NAMES.include?(name)
  return true if name.start_with?("Dockerfile.") || name.end_with?(".dockerfile", ".Dockerfile")

  false
end

def walk_dockerfiles(root)
  seen = 0
  Find.find(root) do |path|
    Find.prune if File.directory?(path) && SKIP_DIRS.include?(File.basename(path))
    next unless File.file?(path)
    next unless dockerfile?(File.basename(path))

    seen += 1
    break if seen > MAX_FILES

    yield path
  end
end

# Returns array of [lineno, line, stripped] for non-blank, non-comment lines.
def directive_lines(file_path)
  out = []
  File.foreach(file_path).with_index(1) do |line, lineno|
    stripped = line.strip
    next if stripped.empty?
    next if stripped.start_with?("#")

    out << [lineno, line, stripped]
  end
  out
rescue Errno::EACCES, Errno::EISDIR
  []
end

# Returns [normalized_directive, rest_of_line] or nil.
def directive_for(line_stripped)
  parts = line_stripped.split(/\s+/, 2)
  return nil if parts.empty?

  [parts[0].upcase, parts[1].to_s]
end

def analyze_dockerfile(rel_path, file_path, &emit_finding)
  directives = directive_lines(file_path)
  return if directives.empty?

  has_healthcheck = false
  has_user = false
  last_user_value = nil

  directives.each do |lineno, raw_line, stripped|
    parsed = directive_for(stripped)
    next if parsed.nil?

    name, args = parsed
    snippet = raw_line.strip[0, 200]

    case name
    when "FROM"
      # Flag :latest tag (explicit or implicit). Skip multi-stage build
      # `--from=<stage>` references which are aliases, not images.
      image_ref = args.split(/\s+/).first.to_s
      tag_or_digest = image_ref.split("@", 2)[1] || image_ref.split(":", 2)[1]
      next if image_ref.include?("--from=")
      if tag_or_digest.nil? || tag_or_digest == "latest"
        emit_finding.call(
          title: "Dockerfile uses :latest tag (or no tag)",
          severity: "LOW",
          category: "compliance",
          endpoint: "#{rel_path}:#{lineno}",
          line: "#{rel_path}:#{lineno}",
          evidence: snippet,
          fix:
            "Pin to an explicit tag or digest (e.g. `FROM alpine:3.20` or `FROM alpine@sha256:...`). " \
            ":latest is mutable and breaks reproducibility.",
          references: ["CWE-1357"],
          confidence: "HIGH",
        )
      end

    when "USER"
      has_user = true
      last_user_value = args.strip

    when "HEALTHCHECK"
      has_healthcheck = true

    when "ADD"
      first_arg = args.split(/\s+/).first.to_s
      if first_arg.start_with?("http://", "https://")
        emit_finding.call(
          title: "Dockerfile uses ADD with a URL (prefer COPY)",
          severity: "LOW",
          category: "compliance",
          endpoint: "#{rel_path}:#{lineno}",
          line: "#{rel_path}:#{lineno}",
          evidence: snippet,
          fix:
            "Prefer `RUN curl ... && ...` or `COPY` over `ADD <url>`. ADD's auto-extract " \
            "semantics surprise readers and the URL fetch isn't checksum-verified.",
          references: ["CWE-829"],
          confidence: "MEDIUM",
        )
      end

    when "RUN"
      # Detect curl/wget piped to a shell (supply-chain risk).
      if args.match?(/\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b/)
        emit_finding.call(
          title: "Dockerfile pipes remote script directly to shell",
          severity: "MEDIUM",
          category: "secrets",
          endpoint: "#{rel_path}:#{lineno}",
          line: "#{rel_path}:#{lineno}",
          evidence: snippet,
          fix:
            "Download to a temp file, verify a checksum, then execute. `curl ... | sh` " \
            "trusts whatever the remote serves at install time; a future compromise of " \
            "the URL silently runs arbitrary code at build.",
          references: ["CWE-829"],
          confidence: "HIGH",
        )
      end
    end
  end

  if !has_user || %w[root 0].include?(last_user_value)
    last_lineno = directives.last[0]
    emit_finding.call(
      title: has_user ? "Dockerfile final USER is root" : "Dockerfile has no USER directive (runs as root)",
      severity: "MEDIUM",
      category: "compliance",
      endpoint: "#{rel_path}:#{last_lineno}",
      line: "#{rel_path}:#{last_lineno}",
      evidence:
        if has_user
          "USER #{last_user_value} (the final USER directive in this Dockerfile)"
        else
          "no USER directive found"
        end,
      fix:
        "Add `USER <non-root-uid>` near the end of the Dockerfile. Containers running as " \
        "root expand the blast radius of any in-container compromise.",
      references: ["CWE-250"],
      confidence: "HIGH",
    )
  end

  unless has_healthcheck
    last_lineno = directives.last[0]
    emit_finding.call(
      title: "Dockerfile has no HEALTHCHECK directive",
      severity: "INFO",
      category: "compliance",
      endpoint: "#{rel_path}:#{last_lineno}",
      line: "#{rel_path}:#{last_lineno}",
      evidence: "no HEALTHCHECK directive found",
      fix:
        "Add `HEALTHCHECK CMD <probe>` so the container runtime can detect a stuck process. " \
        "Even a no-op like `HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1` " \
        "lets orchestrators kill+restart wedged containers.",
      references: ["CWE-1059"],
      confidence: "MEDIUM",
    )
  end
end

def main
  req = read_scan_request
  code_path = req["code_path"].to_s
  code_path = "." if code_path.empty?

  unless File.directory?(code_path)
    emit(done: true, total: 0, error: "code_path is not a directory: #{code_path}")
    return 1
  end

  root = File.absolute_path(code_path)
  total = 0
  walk_dockerfiles(root) do |file_path|
    rel = file_path.start_with?(root + "/") ? file_path[(root.length + 1)..] : file_path
    analyze_dockerfile(rel, file_path) do |finding|
      emit(finding)
      total += 1
    end
  end

  emit(done: true, total: total)
  0
end

exit(main)
