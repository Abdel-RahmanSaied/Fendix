package plugin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPluginSandbox_EnvRedactionIsEnforced runs a real plugin
// subprocess that tries to read every env var it inherits and writes
// the lot to its stderr. The parent sets a fake secret env var via
// the inherited environment; the test asserts the plugin's stderr
// never contains the secret value.
//
// This is the integration test for the redactPluginEnv unit tests
// in env_redaction_test.go — the unit tests pin redactPluginEnv's
// contract, this test pins that Plugin.Run actually uses it.
func TestPluginSandbox_EnvRedactionIsEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin sandbox tests use POSIX shell")
	}

	const secretValue = "fendix-sandbox-test-this-must-not-leak"

	// Set a fake secret in the parent env that redactPluginEnv
	// should strip before invoking the plugin. Cleanup via t.Setenv.
	t.Setenv("AWS_SECRET_ACCESS_KEY", secretValue)
	t.Setenv("GITHUB_TOKEN", secretValue)
	t.Setenv("OPENAI_API_KEY", secretValue)
	// And a control var that should NOT be redacted — the plugin
	// needs PATH at minimum to find `env` and `printenv`.
	t.Setenv("FENDIX_SANDBOX_TEST_CONTROL", "control-value-ok-to-see")

	manifest := "" +
		"name: env-snoop\n" +
		"version: 0.1.0\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"timeout: 5s\n"

	// Plugin emits done-terminator on stdout and dumps its full
	// environment on stderr. The test reads stderr via the slog
	// debug path Plugin.Run already exposes — but here we want
	// direct access, so the script writes env to a known file
	// inside its plugin dir.
	script := `#!/bin/sh
env > "$FENDIX_PLUGIN_DIR/env.captured"
echo '{"done": true, "total": 0}'
`
	root := writePlugin(t, "env-snoop", manifest, script)

	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	if _, err := plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	captured, err := os.ReadFile(filepath.Join(plugins[0].Dir, "env.captured"))
	if err != nil {
		t.Fatalf("read captured env: %v", err)
	}
	env := string(captured)

	if strings.Contains(env, secretValue) {
		// Print which keys leaked for fast diagnosis (but never
		// the value).
		t.Fatalf("secret value leaked to plugin env. captured env had %d bytes; redaction failed", len(env))
	}
	for _, key := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"} {
		if strings.Contains(env, key+"=") {
			t.Errorf("env var %s should have been redacted; survived in plugin env", key)
		}
	}

	// Sanity: the control var DID make it through, so we're not
	// just shipping an empty env.
	if !strings.Contains(env, "FENDIX_SANDBOX_TEST_CONTROL=control-value-ok-to-see") {
		t.Error("control env var was redacted; redaction is too aggressive")
	}

	// The plugin-injected names must be present.
	if !strings.Contains(env, "FENDIX_PLUGIN_NAME=env-snoop") {
		t.Error("FENDIX_PLUGIN_NAME not set in plugin env")
	}
}

// TestPluginSandbox_DocumentsUnmitigatedRisks is a documentation-as-
// code test that pins the boundary of what tier-1 plugin hardening
// covers. If a future change tightens any of these (e.g. chroot,
// seccomp), the corresponding sub-test should be promoted to an
// actual assertion. Until then, the test exists to make the gap
// visible in `go test -v` output.
//
// Each block describes a known UNMITIGATED attack surface — these
// are NOT bugs in the current implementation; they are scoped-out
// items from tier-1.
func TestPluginSandbox_DocumentsUnmitigatedRisks(t *testing.T) {
	t.Run("plugin can read arbitrary user files (not blocked by tier-1)", func(t *testing.T) {
		// Tier-1 hardening redacts the inherited environment but
		// does NOT chroot the plugin or apply seccomp/AppArmor.
		// A malicious plugin can still os.ReadFile() anywhere the
		// invoking user can read — including ~/.fendix/profiles/
		// scan-time credentials, ~/.ssh/, ~/.aws/, etc.
		//
		// Tier-2 (containerised plugin runtime) is the planned
		// mitigation. Until shipped, treat plugin install as
		// equivalent to `curl … | sh`: only install plugins from
		// authors you'd trust to run arbitrary code on your box.
		t.Log("unmitigated: arbitrary filesystem read at user privilege")
	})

	t.Run("plugin can make arbitrary network requests (not blocked by tier-1)", func(t *testing.T) {
		// Same scoping — outbound network is not firewalled. A
		// malicious plugin can exfil any data it can read over
		// HTTP to its own server.
		t.Log("unmitigated: arbitrary outbound network at user privilege")
	})

	t.Run("plugin can persist beyond its invocation (not blocked by tier-1)", func(t *testing.T) {
		// The timeout cap (DefaultTimeout=30s; MaxTimeout=5m) kills
		// the parent-tracked subprocess, but a plugin that calls
		// `setsid` or otherwise detaches can outlive Fendix's
		// `cmd.Wait`. Tier-2's PID-namespace isolation closes this.
		t.Log("unmitigated: detached child processes survive plugin timeout")
	})
}
