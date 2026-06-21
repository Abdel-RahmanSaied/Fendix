# BUG: Command-injection "confirmed" false-positive on canary reflected in HTML

**Severity:** High (a CRITICAL false positive — erodes trust in the "confirmed" label)
**Component:** active injection probe — command-injection confirmation heuristic
**Found:** 2026-06-20, scanning a TwiScope/Kong gateway via the Fendix SaaS API
**Engine version observed:** v0.18.0

## Summary

The command-injection check reports a **CRITICAL, confidence=HIGH, "Command
Injection confirmed"** finding when its canary string is merely **reflected in an
HTML response body**, not produced by shell command execution.

Observed finding:

```
[CRITICAL] [injection] Command Injection confirmed   @ GET /admin/api
confidence: HIGH   source: blackbox
evidence: Command injection confirmed: canary "fendix_canary_" in response body,
          param="id" (in=query), response snippet:
          <!DOCTYPE html> <html ...> <title> Log in | TwiScope Admin </title> ...
```

## Why it's a false positive

The endpoint does not execute anything. Verified directly:

```bash
curl -s -w "[HTTP %{http_code}]\n" \
  "https://gateway.example.com/admin/api?id=fendix_canary_test"
# -> [HTTP 302]  (redirect to the Django admin login page)
```

`GET /admin/api` 302-redirects to `/admin/login`, whose HTML happens to contain
/ reflects the `id` query value (the canary). The confirmation logic saw the
canary substring in the response body and concluded "command injection
confirmed" — but a canary appearing *in returned HTML* is **reflection**, not
**command output**. No shell ran.

## Root cause (hypothesis)

The command-injection confirmation step appears to assert success on
`strings.Contains(responseBody, canary)` alone. For command injection, the
canary must come back as **command output** (e.g. the literal token produced by
`echo`/`id`/`whoami` on its own, in a non-HTML context), not as a reflected
request parameter inside a rendered HTML page.

## Suggested fixes

1. **Don't confirm command-injection when the response is HTML** (Content-Type
   `text/html` or a `<!DOCTYPE html` / `<html` prefix) and the canary equals the
   injected parameter value verbatim — that's reflection, the XSS check's
   domain, not RCE.
2. **Use a computed canary, not a static reflectable token.** Inject a payload
   whose *output* is a value the input doesn't already contain — e.g.
   `;expr 7919 \* 7919` and confirm on `62710561` in the body, or `;echo
   $((RANDOM_A+RANDOM_B))`. A reflected request param can't reproduce a computed
   result, so reflection stops confirming.
3. **Down-rank to needs-verification** when the only evidence is canary-in-HTML
   on a 3xx/auth-gated endpoint (302→login is a strong "this isn't RCE" signal).

## Test to add

A probe test where the mock endpoint **reflects** the injected `id` param into
an HTML body (and 302s to a login) and asserts the command-injection check does
**not** confirm. Pair with a positive test where the endpoint echoes a *computed*
canary in `text/plain` and the check *does* confirm.

## Impact note

This surfaced as the single CRITICAL on the gateway scan report. A CRITICAL
false-positive is the most damaging kind — it's what a user sees first and
judges the tool by. Worth prioritizing above the h2 spec-fetch bug.
