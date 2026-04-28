# Test fixture for provider-specific secret patterns.
# All values are documented test/example tokens or fake-but-shape-valid; never
# use these in real auth flows.

# GitHub personal access token (ghp_ prefix + 36 alphanumerics).
GITHUB_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# GitHub server-to-server token (ghs_ prefix variant).
GITHUB_GHS = "ghs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

# Stripe live secret key (Stripe doc example).
STRIPE_LIVE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# Slack bot token.
SLACK_BOT = "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"

# Slack user token (xoxp- variant).
SLACK_USER = "xoxp-9999999999-8888888888-AAAAAAAAAAAAAAAAAAAAAAAA"

# Google Cloud / Maps / Firebase API key (AIza prefix + exactly 35 chars).
GOOGLE_KEY = "AIzaSyD-ExampleFakeKeyForTestingPurpose"

# Anthropic API key.
ANTHROPIC_KEY = "sk-ant-api03-ExampleFakeAnthropicKeyForTesting123456"

# OpenAI legacy 48-char key.
OPENAI_LEGACY = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"

# OpenAI project key.
OPENAI_PROJ = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn"

# npm registry automation token.
NPM_TOKEN = "npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
