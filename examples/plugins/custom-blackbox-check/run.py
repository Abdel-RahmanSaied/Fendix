#!/usr/bin/env python3
"""custom-blackbox-check reference plugin.

Hits the configured target URL and asserts the response includes the
fictional `X-Acme-Compliance-Tier` header. Demonstrates how to write
a blackbox plugin: read the ScanRequest, make HTTP requests against
`url`, emit Findings on stdout in the documented schema.

The plugin uses only the Python stdlib so it works inside the
engine's `Dockerfile.app` runtime image without extra `pip install`.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

REQUIRED_HEADER = "X-Acme-Compliance-Tier"
TIMEOUT_SECONDS = 8


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> int:
    raw = sys.stdin.read().strip()
    try:
        req = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        emit({"done": True, "total": 0, "error": f"bad request: {exc}"})
        return 1

    url = req.get("url")
    if not url:
        emit({"done": True, "total": 0})
        return 0

    headers = {}
    auth = req.get("auth")
    if auth:
        headers["Authorization"] = auth

    request = urllib.request.Request(url, headers=headers)
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as resp:
            present = REQUIRED_HEADER.lower() in {k.lower() for k in resp.headers.keys()}
            if not present:
                emit({
                    "id": "",
                    "title": f"Missing {REQUIRED_HEADER} compliance header",
                    "severity": "MEDIUM",
                    "category": "headers",
                    "endpoint": url,
                    "evidence": f"response from {url} did not include {REQUIRED_HEADER}",
                    "fix": (f"Set {REQUIRED_HEADER} on every response per "
                            "the Acme compliance policy (see internal docs)."),
                    "references": [],
                    "confidence": "HIGH",
                })
                total += 1
    except urllib.error.URLError as exc:
        emit({"done": True, "total": 0, "error": f"request failed: {exc}"})
        return 1

    emit({"done": True, "total": total})
    return 0


if __name__ == "__main__":
    sys.exit(main())
