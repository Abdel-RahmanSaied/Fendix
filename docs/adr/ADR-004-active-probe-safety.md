# ADR-004: Active Probe Safety Design

## Status

Accepted

## Context

Active injection probes (SQL injection, command injection, CRLF) send payloads to the target system. Unlike passive checks, these can trigger security alerts, affect system behavior, or cause unintended consequences. We need a design that makes it impossible to accidentally run active probes.

## Decision

1. **Opt-in gate:** Active probes never run without `--enable-active` flag. This is a hard requirement, not a default.

2. **Legal disclaimer:** When `--enable-active` is used, a disclaimer is printed to stderr before any probes are sent.

3. **Safe payloads only:**
   - SQLi: time-based blind (SLEEP/pg_sleep/WAITFOR) — no data extraction or modification
   - CMDi: echo canary (`echo fendix_canary_PROBE`) — no destructive commands
   - CRLF: Set-Cookie injection — no harmful headers

4. **Per-endpoint rate limit:** Maximum 20 probes per endpoint, enforced via audit log count.

5. **Full audit log:** Every probe is recorded with endpoint, payload, timestamp, and result. The audit log is available for post-scan review.

## Consequences

**Positive:**
- Impossible to accidentally run active probes
- All payloads are non-destructive by design
- Audit trail provides accountability and debugging
- Rate limiting prevents excessive load on target

**Negative:**
- Time-based SQLi detection can have false positives from network latency
- Echo canary CMDi only works if output is reflected in response
- Per-endpoint limit may miss vulnerabilities in highly parameterized endpoints

**Mitigations:**
- SQLi uses 3-sample median baseline and confirmation probe for HIGH confidence
- False positive rate is acceptable given the safety tradeoff
