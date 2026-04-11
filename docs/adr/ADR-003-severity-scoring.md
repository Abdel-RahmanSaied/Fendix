# ADR-003: Severity Scoring Model

## Status

Accepted

## Context

Security findings need consistent, explainable severity levels. Different sources (black-box, white-box, correlated) and different confidence levels should influence the final severity. A finding confirmed by both engines should be rated higher than one flagged by only one.

## Decision

Use a multiplicative scoring model:

```
Score = ImpactBase[category] x ConfidenceMult[confidence] x SourceMult[source]
```

**Thresholds:**
- CRITICAL >= 9.0
- HIGH >= 7.0
- MEDIUM >= 4.0
- LOW >= 1.0
- INFO < 1.0

**Impact base values** reflect the real-world damage potential of each vulnerability category, based on OWASP Top 10 and CWE severity ratings.

**Source multiplier** slightly elevates correlated findings (1.1x) and slightly reduces whitebox-only findings (0.9x), reflecting the confidence difference between runtime-confirmed and static-analysis-only issues.

## Consequences

**Positive:**
- Deterministic: same input always produces same severity
- Explainable: users can understand why a finding has a specific severity
- Correlated findings naturally get higher scores
- Low-confidence findings are appropriately downgraded

**Negative:**
- The multipliers are chosen by judgment, not statistical analysis
- Some edge cases may produce unexpected severity levels at threshold boundaries

**Mitigations:**
- Table-driven tests cover all category/confidence/source combinations
- Scoring model is documented in MEMORY.md for easy reference
