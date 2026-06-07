package plugin

import (
	"strings"
	"testing"
)

// redactPluginEnv is an ALLOWLIST (F-I1): only a fixed set of names
// (PATH, HOME, LANG, TMPDIR), the LC_* / FENDIX_PLUGIN_* prefixes, and
// any per-plugin manifest `env:` extras survive. Everything else —
// including credentials in variables nobody anticipated — is dropped
// because it isn't on the list, not because a denylist entry happened
// to match.
func TestRedactPluginEnv_AllowlistKeepsOnlyExpected(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/me",
		"LANG=en_US.UTF-8",
		"LC_ALL=C",
		"LC_CTYPE=en_US.UTF-8",
		"TMPDIR=/tmp",
		"FENDIX_PLUGIN_NAME=demo",
		"FENDIX_PLUGIN_DIR=/x",
		// Secrets and unanticipated vars — all dropped by the allowlist.
		"AWS_ACCESS_KEY_ID=AKIA1234567890",
		"AWS_SECRET_ACCESS_KEY=dontleakthis",
		"GITHUB_TOKEN=ghp_secrets_here",
		"OPENAI_API_KEY=sk-redactme",
		"ANTHROPIC_API_KEY=sk-ant-redactme",
		"MY_PRIVATE_KEY=-----BEGIN-----",
		"DATABASE_URL=postgres://user:pw@host/db",
		"DB_PASSWORD=hunter2",
		"FENDIX_AUTH_PROFILE_DEFAULT=token-from-disk",
		// Credentials the old substring denylist would have MISSED —
		// the allowlist drops them precisely because they aren't allowed.
		"SNYK_TOKEN=snyk-xxx", // would have matched old TOKEN, but proves intent
		"VAULT_ADDR=https://vault.internal",
		"MY_CREDS=top-secret",
		"TERM=xterm",
		"USER=me",
	}
	out := redactPluginEnv(in, nil)

	must := []string{
		"PATH=", "HOME=", "LANG=", "LC_ALL=", "LC_CTYPE=", "TMPDIR=",
		"FENDIX_PLUGIN_NAME=", "FENDIX_PLUGIN_DIR=",
	}
	for _, m := range must {
		if !containsPrefix(out, m) {
			t.Errorf("expected %q to survive the allowlist; out=%v", m, out)
		}
	}

	mustNot := []string{
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"GITHUB_TOKEN=",
		"OPENAI_API_KEY=",
		"ANTHROPIC_API_KEY=",
		"MY_PRIVATE_KEY=",
		"DATABASE_URL=",
		"DB_PASSWORD=",
		"FENDIX_AUTH_PROFILE_DEFAULT=",
		"SNYK_TOKEN=",
		"VAULT_ADDR=",
		"MY_CREDS=",
		"TERM=",
		"USER=",
	}
	for _, m := range mustNot {
		if containsPrefix(out, m) {
			t.Errorf("expected %q to be dropped by the allowlist; survived in out=%v", m, out)
		}
	}
}

func TestRedactPluginEnv_ManifestExtraAllowlist(t *testing.T) {
	// A plugin can request extra vars via the manifest `env:` field.
	// Those named vars survive; an unrelated secret still does not.
	in := []string{
		"PATH=/bin",
		"HTTPS_PROXY=http://proxy.internal:8080",
		"CUSTOM_NEEDED=ok",
		"AWS_SECRET_ACCESS_KEY=leak",
	}
	out := redactPluginEnv(in, []string{"HTTPS_PROXY", "CUSTOM_NEEDED"})

	for _, m := range []string{"PATH=", "HTTPS_PROXY=", "CUSTOM_NEEDED="} {
		if !containsPrefix(out, m) {
			t.Errorf("expected %q to survive (PATH allowlist / manifest extra); out=%v", m, out)
		}
	}
	if containsPrefix(out, "AWS_SECRET_ACCESS_KEY=") {
		t.Error("a secret not named in the manifest extra must still be dropped")
	}
}

func TestRedactPluginEnv_DropsEntriesWithoutEquals(t *testing.T) {
	// An entry without '=' can't be matched against the allowlist by
	// name, so it's dropped (fail-closed). Go's os.Environ never
	// produces these; this only matters for hand-built inputs.
	in := []string{"PATH=/bin", "weird-line-no-equals", "HOME=/h"}
	out := redactPluginEnv(in, nil)
	if len(out) != 2 {
		t.Errorf("expected 2 entries (PATH, HOME), got %d: %v", len(out), out)
	}
	if !containsPrefix(out, "PATH=") || !containsPrefix(out, "HOME=") {
		t.Errorf("PATH and HOME should survive; got %v", out)
	}
}

func TestRedactPluginEnv_NameNotValueMatching(t *testing.T) {
	// A var whose *value* contains "secret" but whose name is allowed
	// (PATH) passes through. The allowlist is name-based by design.
	in := []string{"PATH=/usr/local/secrets/bin:/usr/bin"}
	out := redactPluginEnv(in, nil)
	if !containsPrefix(out, "PATH=") {
		t.Errorf("PATH should survive even when its value mentions 'secret'; got %v", out)
	}
}

func containsPrefix(env []string, prefix string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}
