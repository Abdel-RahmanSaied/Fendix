package textscan

import (
	"regexp"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// AllRules returns every shipped rule across Go, JS/TS, and IaC.
// Rules are appended in deterministic order so test snapshots stay
// stable.
func AllRules() []Rule {
	rules := []Rule{}
	rules = append(rules, GoRules()...)
	rules = append(rules, JSRules()...)
	rules = append(rules, IaCRules()...)
	return rules
}

// GoRules — Sprint 04 shipped subset (2 of the brief's 5 rules).
// XXE and INSECURE_RAND need cross-function AST context to avoid
// stdlib false positives; carried to Sprint 04.5.
func GoRules() []Rule {
	return []Rule{
		{
			ID:         "GO_SQL_INJECTION",
			Title:      "SQL injection: query built via string formatting",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-89",
			// Two shapes flagged:
			//   1. Concat/Sprintf directly inside the call: db.Query("…"+x).
			//   2. fmt.Sprintf returning the query argument on the same line.
			// The "query built one line earlier and passed as a bare
			// identifier" case is the dominant real-world shape but
			// needs taint analysis — carried to Sprint 04.5.
			Pattern: regexp.MustCompile(`(?:db|conn|tx)\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\([^)]*(?:\+|%[sv]|fmt\.Sprintf)`),
			Applies: HasGoExtension,
			Fix:     "Use parameterised queries: db.Query(\"SELECT … WHERE x = ?\", value). Never concatenate or fmt.Sprintf user-controlled values into SQL.",
		},
		{
			ID:         "GO_EXEC_COMMAND_INJECTION",
			Title:      "Command injection: exec.Command with shell wrapper or concatenated argv",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-78",
			// Three shapes flagged:
			//   1. exec.Command("sh","-c", …) / bash / cmd / powershell — shell semantics.
			//   2. exec.Command(…) with `+` concat anywhere in the argv list.
			//   3. exec.Command(…) with fmt.Sprintf building an argv element.
			Pattern: regexp.MustCompile(`exec\.(?:Command|CommandContext)\([^)]*(?:"(?:sh|bash|cmd|powershell)"\s*,\s*"-c"|\+|fmt\.Sprintf)`),
			Applies: HasGoExtension,
			Fix:     "Pass argv as a list rather than going through `sh -c`. If shell semantics are required, sanitise inputs with shellescape or use os/exec with explicit env+argv.",
		},
		{
			ID:         "GO_WEAK_HASH_PASSWORD",
			Title:      "Weak hash used for password storage",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "secrets",
			CWE:        "CWE-327",
			// crypto/md5 + crypto/sha1 imports near password-shaped variables.
			// Naive line-level pattern — flags any hash.Sum/New call near a
			// "password"/"pwd"/"passphrase" identifier. The byte-cast is
			// matched as `[]byte(` (closing bracket fixed in v0.13.1).
			Pattern: regexp.MustCompile(`(?:md5|sha1)\.(?:Sum|New)\(\s*(?:\[\s*\]byte\s*\()?\s*(?:[a-zA-Z_]*[Pp]assword|[a-zA-Z_]*[Pp]wd|[a-zA-Z_]*[Pp]assphrase)`),
			Applies: HasGoExtension,
			Fix:     "Use bcrypt, scrypt, argon2, or PBKDF2 for password hashing. Raw MD5/SHA1 is unsuitable — they're fast hashes with no work factor and no per-record salt.",
		},
		{
			ID:         "GO_HARDCODED_AWS_KEY",
			Title:      "AWS access-key ID literal embedded in source",
			Severity:   models.SeverityCritical,
			Confidence: models.ConfidenceHigh,
			Category:   "secrets",
			CWE:        "CWE-798",
			Pattern:    regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			// AWS's own documentation placeholders. Including them here
			// would train users to ignore CRITICAL findings.
			NegPattern: regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE|AKIAI44QH8DHBEXAMPLE`),
			Applies:    HasGoExtension,
			Fix:        "Load AWS credentials from the SDK's default chain (env, ~/.aws/credentials, instance role). If this is a real key, rotate it now.",
		},
	}
}

// JSRules — Sprint 05 shipped subset (4 of the brief's 6 rules).
// Proto-pollution and proximity-based insecure-RNG are cut to
// Sprint 05.5 because the regex+window approach yields too many
// FPs on real codebases.
func JSRules() []Rule {
	return []Rule{
		{
			ID:         "JS_EVAL_LITERAL",
			Title:      "eval() with non-literal argument",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-95",
			// Two acceptable shapes for "non-literal":
			//   eval(identifier...)
			//   eval("..." + something)  — string literal followed by a + concat
			// A bare eval("…literal…") with no concat is the safe case and isn't matched.
			Pattern: regexp.MustCompile(`\beval\s*\(\s*(?:[a-zA-Z_$][\w$]*|['"][^'"]*['"]\s*\+|.*\+\s*[a-zA-Z_$])`),
			Applies: HasJSExtension,
			Fix:     "Replace eval() with explicit parsing (JSON.parse for JSON, Function constructor with allowlist for templated logic). Eval of user-controlled input is direct RCE.",
		},
		{
			ID:         "JS_INNER_HTML_USER_INPUT",
			Title:      "innerHTML assigned from a non-literal expression",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "xss",
			CWE:        "CWE-79",
			Pattern:    regexp.MustCompile(`\.innerHTML\s*=\s*(?:[a-zA-Z_$][\w$]*|.*\+)`),
			NegPattern: regexp.MustCompile(`\.innerHTML\s*=\s*['"]`),
			Applies:    HasJSExtension,
			Fix:        "Use textContent (sanitises automatically) or sanitise input through DOMPurify before assignment.",
		},
		{
			ID:         "JS_CHILD_PROCESS_SHELL",
			Title:      "child_process.exec with shell semantics",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-78",
			Pattern:    regexp.MustCompile(`\bchild_process\.exec\s*\(`),
			Applies:    HasJSExtension,
			Fix:        "Prefer child_process.execFile or spawn with argv as an array. exec passes its first argument to a shell.",
		},
		{
			ID:         "JS_DOCUMENT_WRITE",
			Title:      "document.write — DOM-based XSS surface",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "xss",
			CWE:        "CWE-79",
			Pattern:    regexp.MustCompile(`\bdocument\.write(?:ln)?\s*\(`),
			Applies:    HasJSExtension,
			Fix:        "document.write() is XSS-prone and blocks the parser. Build DOM nodes via createElement/textContent, or use template literals + a sanitiser.",
		},
		{
			ID:         "JS_REQUIRE_INTERPOLATION",
			Title:      "require() called with a non-literal path",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-95",
			// require(somevar) or require(a + b)
			Pattern:    regexp.MustCompile(`\brequire\s*\(\s*(?:[a-zA-Z_$][\w$]*|.*\+|.*\$\{)`),
			NegPattern: regexp.MustCompile(`require\s*\(\s*['"]`),
			Applies:    HasJSExtension,
			Fix:        "Pass a string literal to require(). Dynamic require paths let an attacker load arbitrary modules.",
		},
		{
			ID:         "JS_HARDCODED_AWS_KEY",
			Title:      "AWS access-key ID literal embedded in JavaScript source",
			Severity:   models.SeverityCritical,
			Confidence: models.ConfidenceHigh,
			Category:   "secrets",
			CWE:        "CWE-798",
			Pattern:    regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			NegPattern: regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE|AKIAI44QH8DHBEXAMPLE`),
			Applies:    HasJSExtension,
			Fix:        "Load credentials from process.env or the AWS SDK's default chain. Rotate the exposed key.",
		},
	}
}

// IaCRules — Sprint 06 shipped subset (Dockerfile + k8s; no TF
// per the D2 default).
func IaCRules() []Rule {
	return []Rule{
		// ----- Dockerfile -----
		{
			ID:         "IAC_DOCKER_RUNS_AS_ROOT",
			Title:      "Dockerfile doesn't drop privileges (no USER directive in file)",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceLow,
			Category:   "iac",
			CWE:        "CWE-250",
			// Pattern flags the `FROM` line. scanFile's whole-file
			// pre-pass (dockerfileHasUSER) suppresses the rule when
			// any `USER <name>` directive exists, so a Dockerfile that
			// drops privileges later doesn't get flagged. Confidence:
			// LOW so the orchestrator caps severity at MEDIUM per the
			// consistency rule.
			Pattern: regexp.MustCompile(`^\s*FROM\s+\S+`),
			Applies: IsDockerfile,
			Fix:     "Add `USER <non-root>` after package installs. Containers running as UID 0 escalate easily into the host on misconfigured runtimes.",
		},
		{
			ID:         "IAC_DOCKER_ADD_INSTEAD_OF_COPY",
			Title:      "Dockerfile uses ADD when COPY would suffice",
			Severity:   models.SeverityLow,
			Confidence: models.ConfidenceMedium,
			Category:   "iac",
			CWE:        "CWE-829",
			// ADD with a URL or remote source is the actual hazard; ADD with
			// a tarball auto-extracts (CVE-prone). Match all ADD; reviewer
			// triages.
			Pattern: regexp.MustCompile(`^\s*ADD\s+(?:https?://|\S+\.tar)`),
			Applies: IsDockerfile,
			Fix:     "Use COPY for local files. If you need a URL, prefer curl + verified checksum in a RUN step.",
		},
		{
			ID:         "IAC_DOCKER_LATEST_TAG",
			Title:      "Dockerfile pins to :latest (or no tag at all)",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "iac",
			CWE:        "CWE-829",
			// Flag a FROM line that is either bare (no `:tag`, no
			// `@sha256:…` digest) or explicitly `:latest`. Tolerates
			// the optional `AS <stage>` suffix used in multi-stage
			// builds. Tags starting with `l` (e.g. `lts`, `linux-…`)
			// are correctly NOT flagged because the pattern only
			// matches `:latest` literally.
			Pattern: regexp.MustCompile(`^\s*FROM\s+[^\s:@]+(?::latest)?(?:\s+AS\s+\S+)?\s*$`),
			Applies: IsDockerfile,
			Fix:     "Pin to a specific tag or digest (e.g. `python:3.11.7-slim` or `python@sha256:…`). `:latest` makes builds unreproducible AND ships unreviewed upstream changes.",
		},
		// ----- k8s YAML -----
		{
			ID:         "IAC_K8S_PRIVILEGED_CONTAINER",
			Title:      "Kubernetes pod runs with privileged: true",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\bprivileged\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "Drop `privileged: true`. If a workload genuinely needs host capabilities, use `securityContext.capabilities.add` with the minimum set.",
		},
		{
			ID:         "IAC_K8S_HOST_NETWORK",
			Title:      "Kubernetes pod uses hostNetwork: true",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\bhostNetwork\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "hostNetwork: true binds pod ports to the node's network namespace and shares its interfaces. Justify per-workload; default should be false.",
		},
		{
			ID:         "IAC_K8S_ALLOW_PRIVILEGE_ESCALATION",
			Title:      "Kubernetes container allowPrivilegeEscalation: true",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\ballowPrivilegeEscalation\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "Set `allowPrivilegeEscalation: false`. Required for compliance with most pod-security policies.",
		},
		{
			ID:         "IAC_K8S_RUNS_AS_ROOT",
			Title:      "Kubernetes container runAsUser: 0 (root)",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\brunAsUser\s*:\s*0\b`),
			Applies:    IsYAML,
			Fix:        "Set runAsUser to a non-zero UID, or runAsNonRoot: true to refuse to start if the image's USER is root.",
		},
	}
}
