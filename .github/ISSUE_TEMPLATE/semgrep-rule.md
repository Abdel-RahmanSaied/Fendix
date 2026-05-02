---
name: New Semgrep Rule
about: Propose or contribute a new Semgrep detection rule
title: 'rule: '
labels: good first issue, semgrep-rule, help wanted
assignees: ''
---

## Rule summary

<!-- What vulnerability or anti-pattern does this rule detect? -->

## Language(s)

<!-- e.g., Python, JavaScript, Go, Java -->

## Example vulnerable code

```
<!-- Paste a minimal snippet that should trigger the rule -->
```

## Example safe code

```
<!-- Paste a minimal snippet that should NOT trigger the rule -->
```

## CWE / OWASP reference

<!-- e.g., CWE-89: SQL Injection, OWASP A03:2021 -->

## Suggested severity

<!-- CRITICAL / HIGH / MEDIUM / LOW / INFO -->

## Implementation notes

<!-- Optional: which YAML file it belongs in, similar existing rules to reference -->

### Contribution checklist

- [ ] Rule YAML added to `python/rules/`
- [ ] At least 1 true-positive test case in `python/tests/fixtures/`
- [ ] At least 1 true-negative test case
- [ ] `python -m pytest python/tests/test_semgrep_runner.py` passes
- [ ] Rule registered in the rule registry (if applicable)
