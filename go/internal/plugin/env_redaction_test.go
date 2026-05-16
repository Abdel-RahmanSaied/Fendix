package plugin

import (
	"strings"
	"testing"
)

func TestRedactPluginEnv_DropsKnownSecretPrefixes(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/me",
		"AWS_ACCESS_KEY_ID=AKIA1234567890",
		"AWS_SECRET_ACCESS_KEY=dontleakthis",
		"GITHUB_TOKEN=ghp_secrets_here",
		"OPENAI_API_KEY=sk-redactme",
		"ANTHROPIC_API_KEY=sk-ant-redactme",
		"MY_PRIVATE_KEY=-----BEGIN-----",
		"DATABASE_URL=postgres://user:pw@host/db",
		"DB_PASSWORD=hunter2",
		"FENDIX_AUTH_PROFILE_DEFAULT=token-from-disk",
		"LANG=en_US.UTF-8",
		"TERM=xterm",
		"USER=me",
	}
	out := redactPluginEnv(in)

	must := []string{"PATH=", "HOME=", "LANG=", "TERM=", "USER="}
	for _, m := range must {
		if !containsPrefix(out, m) {
			t.Errorf("expected %q to survive redaction; out=%v", m, out)
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
	}
	for _, m := range mustNot {
		if containsPrefix(out, m) {
			t.Errorf("expected %q to be redacted; survived in out=%v", m, out)
		}
	}
}

func TestRedactPluginEnv_PreservesEnvWithoutEquals(t *testing.T) {
	// An entry without '=' is technically malformed but Go's os.Environ
	// won't produce one. If a caller hand-constructs one, don't drop it
	// silently — leaving it through means a test using a non-standard
	// env doesn't fail mysteriously.
	in := []string{"PATH=/bin", "weird-line-no-equals", "HOME=/h"}
	out := redactPluginEnv(in)
	if len(out) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(out), out)
	}
}

func TestRedactPluginEnv_NameNotValueMatching(t *testing.T) {
	// A var whose *value* contains "secret" but whose name does not
	// should pass through. The redaction is name-based by design.
	in := []string{"PATH=/usr/local/secrets/bin:/usr/bin"}
	out := redactPluginEnv(in)
	if !containsPrefix(out, "PATH=") {
		t.Errorf("PATH should survive even when its value mentions 'secret'; got %v", out)
	}
}

func TestRedactPluginEnv_TokenSubstringIsRedacted(t *testing.T) {
	// The list is substring-based on name, so any name containing
	// "TOKEN" or "SECRET" anywhere is dropped. This is intentional
	// over-redaction; the test pins the contract.
	in := []string{"CUSTOM_AUTH_TOKEN=xyz", "BUILD_SECRET_FILE=/tmp/x"}
	out := redactPluginEnv(in)
	if containsPrefix(out, "CUSTOM_AUTH_TOKEN=") {
		t.Error("CUSTOM_AUTH_TOKEN should be redacted (matches TOKEN)")
	}
	if containsPrefix(out, "BUILD_SECRET_FILE=") {
		t.Error("BUILD_SECRET_FILE should be redacted (matches SECRET)")
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
