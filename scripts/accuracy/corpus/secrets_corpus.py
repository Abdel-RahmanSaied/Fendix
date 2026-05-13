"""Secrets-detection accuracy corpus.

Each test case is a single line declaring a credential that fendix's
native-Go secrets scanner (TASK-115) should flag with the matching
SEC-<PATTERN_ID>. The safe variants use environment-variable lookups
that should not be flagged.
"""
import os


# EXPECT_TP cases
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY_LINE = "aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
STRIPE_LIVE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
SLACK_BOT_TOKEN = "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"
GOOGLE_API_KEY = "AIzaSyD-ExampleFakeKeyForTestingPurpose"
ANTHROPIC_API_KEY = "sk-ant-api03-ExampleFakeAnthropicKeyForTesting123456"
OPENAI_API_KEY = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"
NPM_TOKEN = "npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DB_CONNECTION = "postgresql://admin:secretpassword@db.example.com:5432/mydb"
HARDCODED_PASSWORD = "password = 'mysupersecretpassword123'"  # noqa: S105
JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
GENERIC_API_KEY = 'api_key = "abc123-super-secret-api-key-value-here"'


# EXPECT_TN cases — env-var lookups, no hardcoded values
SAFE_API_KEY = os.environ.get("API_KEY")  # noqa: S105
SAFE_DB_URL = os.environ["DATABASE_URL"]
SAFE_SECRET = os.getenv("SECRET_KEY", "")  # noqa: S105
