# BUG: `--spec <url>` fetch fails against HTTP/2-only gateways (Kong) — "malformed HTTP response"

**Severity:** High (silently defeats spec-seeded scanning behind a modern API gateway)
**Component:** `go/internal/scanner/crawler.go` → `Crawler.fetchSpec` (`c.client.Do`)
**Found:** 2026-06-20, via the Fendix SaaS API against a real TwiScope/Kong gateway
**Engine version observed:** v0.18.0 (GHCR image `sha256:d18ee20f`)

## Summary

When `--spec` is an `https://` URL served by a gateway that negotiates **HTTP/2 over
ALPN** (Kong, and most modern reverse proxies), the engine's spec fetch fails with:

```
spec parsing failed, continuing with other strategies
  error="fetching spec from https://<gw>/specs/deepin.json:
  Get \"https://<gw>/specs/deepin.json\":
  net/http: HTTP/1.x transport connection broken:
  malformed HTTP response \"\x00\x00\x12\x04\x00\x00\x00\x00\x00...\""
```

The byte sequence `\x00\x00\x12\x04\x00...` is an **HTTP/2 SETTINGS frame**
(length=0x12, type=0x04=SETTINGS). The crawler's HTTP client sent the request
over HTTP/1.x but the server replied in HTTP/2, and the h1 reader choked on the
h2 frame.

The engine then falls back to sitemap/HTML-crawl/brute-force discovery, finds 0
endpoints (an API gateway has no crawlable root), and the scan **fails**:

```
endpoint discovery complete total=0
no endpoints discovered — nothing to scan
fendix: no endpoints discovered. Provide --url, --spec, or --code.
```

Net effect: a **valid, reachable 460-path OpenAPI spec produces a 0-endpoint
failed scan** purely because of the transport mismatch.

## Reproduction

The spec URL is fine — the engine's client is the problem:

```bash
# Works (curl negotiates h2 via ALPN):
curl -s -o /dev/null -w "%{http_code} HTTP/%{http_version}\n" \
  https://gateway.twiscope.net/specs/deepin.json
# -> 200 HTTP/2

# Also works when h1.1 is forced:
curl -s --http1.1 -o /dev/null -w "%{http_code} HTTP/%{http_version}\n" \
  https://gateway.twiscope.net/specs/deepin.json
# -> 200 HTTP/1.1

# Fails inside the engine:
fendix scan --url https://gateway.twiscope.net/deepin \
  --spec https://gateway.twiscope.net/specs/deepin.json
# -> "malformed HTTP response \x00\x00\x12\x04..." then 0 endpoints
```

## Root cause

`fetchSpec` (crawler.go:~360) issues the request via the crawler's shared
`c.client`. That client's `http.Transport` is evidently configured **without
HTTP/2** (custom Transport with `ForceAttemptHTTP2: false`, or `TLSClientConfig`
set without copying `NextProtos`/leaving ALPN to advertise `h2`). Go's stdlib
only auto-enables HTTP/2 on the *default* transport or when `ForceAttemptHTTP2`
is true and `TLSClientConfig` doesn't suppress ALPN. A hand-rolled Transport
(common, for custom timeouts / TLS / the SSRF `netguard` dialer) silently drops
h2 — so against an h2-preferring server the ALPN handshake still lands on h2 but
the client tries to read h1, producing exactly this "malformed HTTP response"
on an h2 frame.

## Resolution

Fixed in `netguard.Config.Transport` by advertising both protocols via Go 1.25's
`http.Transport.Protocols` (`SetHTTP1(true)` + `SetHTTP2(true)`), so ALPN
negotiates h2 over the custom guarded dialer and falls back to h1 otherwise — with
**no `golang.org/x/net/http2` dependency** (cleaner than the `http2.ConfigureTransport`
route originally sketched in option 1 below). Placing it in `netguard.Config.Transport`
covers every guarded client (the crawler's spec fetch *and* all black-box checks),
not just the one call site. The fix only sets `Protocols` when the caller's template
didn't already pin one, preserving explicit overrides. Regression tests:
`netguard.TestClient_HTTP2Server` and `scanner.TestFromSpec_FetchOverHTTP2`.

The original options considered are kept below for context.

## Suggested fixes (any one resolves it; first is cleanest)

1. **Enable h2 on the crawler transport.** On the `http.Transport`, set
   `ForceAttemptHTTP2 = true` and ensure the custom `TLSClientConfig` does NOT
   clear `NextProtos` (or explicitly set `NextProtos = []string{"h2","http/1.1"}`).
   If a custom `DialContext`/`DialTLSContext` is used (e.g. the netguard SSRF
   dialer), wire it through `golang.org/x/net/http2` via `http2.ConfigureTransport`
   so h2 works over the guarded dialer.

2. **Pin spec fetches to HTTP/1.1** as a targeted fix: give `fetchSpec` its own
   transport with `TLSClientConfig.NextProtos = []string{"http/1.1"}` (ALPN then
   negotiates h1, which the server supports — verified above). Lowest-risk, but
   leaves the same latent h2 gap in any other place `c.client` hits an h2 server.

3. **Detect & retry:** on a `Do` error whose message contains
   `malformed HTTP response` with a leading `\x00\x00..\x04` (h2 SETTINGS frame),
   retry once over a forced-h1.1 transport. Ugly; prefer 1 or 2.

## Test to add

A table test in `crawler_test.go` that serves the spec from an
`httptest.NewUnstartedServer` with `EnableHTTP2 = true` (h2-only) and asserts
`loadSpec`/`fetchSpec` returns the body, not a transport error.

## Workarounds for users until fixed

- Host the spec where the client negotiates HTTP/1.1 (plain origin, S3 static
  URL, raw GitHub), and pass that URL to `--spec`.
- Or download the spec and pass a **local path** (`--spec ./deepin.json`) —
  `loadSpec` reads local files with `os.ReadFile`, bypassing the HTTP client
  entirely. (Not available in SaaS mode, where `--spec` is forwarded as a URL.)
- SaaS note: `scanning/services.py` forwards the `spec` value verbatim as
  `--spec`, so the SaaS inherits this engine bug; a local-path workaround isn't
  reachable through the API.
