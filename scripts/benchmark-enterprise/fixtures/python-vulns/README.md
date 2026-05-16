# Python benchmark fixture

This fixture is the apples-to-apples comparison surface for the
`scripts/benchmark-enterprise/run.sh` runner. It contains exactly
five true-positive vulnerabilities and five safe-but-similar
false-positive probes, all in a single ~100 LOC Python file.

## True positives (every tool should flag these)

| ID   | Line | CWE     | Pattern                                              |
|------|-----:|---------|------------------------------------------------------|
| TP-1 |   28 | CWE-89  | SQL injection via string concatenation               |
| TP-2 |   35 | CWE-798 | Hardcoded AWS access key (`AKIA…EXAMPLE`)            |
| TP-3 |   41 | CWE-22  | Path traversal via unfiltered user input             |
| TP-4 |   47 | CWE-918 | SSRF via fully-user-controlled URL                   |
| TP-5 |   53 | CWE-601 | Open redirect via `flask.redirect(<user input>)`     |

## True negatives (no tool should flag these)

| ID   | Line | Shape                                                |
|------|-----:|------------------------------------------------------|
| TN-1 |   65 | Parameterised `cursor.execute(sql, (user,))`         |
| TN-2 |   72 | AWS key from `os.environ`                            |
| TN-3 |   76 | Path traversal mitigated by `os.path.basename`       |
| TN-4 |   84 | SSRF mitigated by host-allowlist                     |
| TN-5 |   95 | Open redirect to `url_for(<constant>)`               |

## Editing rule

If you change line numbers, update `manifest.json` in lockstep.
The benchmark runner reads the manifest and scores tools against
the line numbers. A silent drift would silently change the score.

## What this fixture is NOT

- Not a comprehensive SAST benchmark. 100 LOC is tiny by design — the
  goal is a fast, stable measurement of three tools on identical
  input, not a coverage survey.
- Not a competitive benchmark for tools that don't do Python SAST
  (e.g. gosec). The runner gates Python-only tools (bandit) behind a
  language check; expand the runner before adding non-Python tools.
- Not a measurement of DAST coverage. Only fendix does DAST today.
