"""CWE-798: Use of hard-coded credentials.

These are real-shape secrets — fendix's native Go secrets scanner
(TASK-115) should flag every BAD case. GOOD cases use environment
variables, vault references, or are deliberately-broken placeholder
strings.
"""
from __future__ import annotations

import os


# ─── BAD: hard-coded secrets ────────────────────────────────────────

# AWS access key (canonical AKIA + 16 chars)
BAD_01_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # SINK

# AWS secret access key (40 base64-ish chars). Variable name must contain
# "aws...secret...key" prefix — fendix's regex is correctly context-anchored
# to avoid flagging arbitrary base64 strings as AWS secrets.
BAD_02_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # SINK

# GitHub personal access token (ghp_ prefix + 36 chars)
BAD_03_GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # SINK

# Slack bot token
BAD_04_SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmnopqrstuvwx"  # SINK

# Stripe live secret key
BAD_05_STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # SINK

# Generic high-entropy API key (assigned, not env-var)
BAD_06_GENERIC = "api_key = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'"  # SINK

# Private key header (truncated for legibility but fendix matches header)
BAD_07_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxample/notrealkey/abc123==
-----END RSA PRIVATE KEY-----"""  # SINK


# ─── GOOD: not hard-coded ───────────────────────────────────────────

GOOD_01_FROM_ENV = os.environ.get("AWS_ACCESS_KEY_ID")  # SAFE

GOOD_02_FROM_FILE = open("/run/secrets/db-password").read() if False else None  # SAFE — vaulted

GOOD_03_PLACEHOLDER = "<set me>"  # SAFE — obvious placeholder

GOOD_04_TEMPLATE = "AKIA{your_key_here}"  # SAFE — Jinja-style template
