package plugin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPluginSandbox_EnvAllowlistIsEnforced runs a real plugin
// subprocess that dumps its full inherited environment to a file in
// its plugin dir. The parent sets fake secrets in its own environment;
// the test asserts the allowlist (F-I1) drops them while the allowed
// names (PATH/HOME) and the FENDIX_PLUGIN_* injections survive.
//
// This is the integration test for the redactPluginEnv unit tests in
// env_redaction_test.go — the unit tests pin redactPluginEnv's
// contract, this test pins that Plugin.Run actually applies it.
func TestPluginSandbox_EnvAllowlistIsEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin sandbox tests use POSIX shell")
	}

	const secretValue = "fendix-sandbox-test-this-must-not-leak"

	// Set fake secrets — and one unanticipated credential-shaped var —
	// in the parent env. The allowlist must drop every one of them
	// because none is an allowed name (no denylist matching involved).
	t.Setenv("AWS_SECRET_ACCESS_KEY", secretValue)
	t.Setenv("GITHUB_TOKEN", secretValue)
	t.Setenv("OPENAI_API_KEY", secretValue)
	t.Setenv("SNYK_TOKEN", secretValue)
	t.Setenv("MY_BESPOKE_CREDS", secretValue)
	// Ensure PATH/HOME are populated so the allowlist has something to
	// pass through (they're normally set, but pin it for the assertion).
	if os.Getenv("PATH") == "" {
		t.Setenv("PATH", "/usr/bin:/bin")
	}
	if os.Getenv("HOME") == "" {
		t.Setenv("HOME", t.TempDir())
	}

	manifest := "" +
		"name: env-snoop\n" +
		"version: 0.1.0\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"timeout: 5s\n"

	// Plugin emits the done-terminator on stdout and dumps its full
	// environment to a known file inside its plugin dir for inspection.
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
		// Never print the value; report only that a leak occurred.
		t.Fatalf("secret value leaked to plugin env. captured env had %d bytes; allowlist failed", len(env))
	}
	for _, key := range []string{
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY",
		"SNYK_TOKEN", "MY_BESPOKE_CREDS",
	} {
		if strings.Contains(env, key+"=") {
			t.Errorf("env var %s should have been dropped by the allowlist; survived in plugin env", key)
		}
	}

	// Allowed names must make it through so we're not shipping an empty env.
	if !strings.Contains(env, "PATH=") {
		t.Error("PATH was dropped; allowlist is too aggressive (plugin can't find its interpreter)")
	}
	if !strings.Contains(env, "HOME=") {
		t.Error("HOME was dropped; allowlist is too aggressive")
	}

	// The plugin-injected names must be present.
	if !strings.Contains(env, "FENDIX_PLUGIN_NAME=env-snoop") {
		t.Error("FENDIX_PLUGIN_NAME not set in plugin env")
	}
}

// TestPluginSandbox_ManifestEnvAllowlistPassesThrough pins the
// backwards-compatible Spec.Env opt-in: a var named in the manifest's
// `env:` allowlist reaches the plugin, while a sibling secret does not.
func TestPluginSandbox_ManifestEnvAllowlistPassesThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin sandbox tests use POSIX shell")
	}

	t.Setenv("HTTPS_PROXY", "http://proxy.internal:8080")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")

	manifest := "" +
		"name: env-extra\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n" +
		"env:\n" +
		"  - HTTPS_PROXY\n"

	script := `#!/bin/sh
env > "$FENDIX_PLUGIN_DIR/env.captured"
echo '{"done": true, "total": 0}'
`
	root := writePlugin(t, "env-extra", manifest, script)

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

	if !strings.Contains(env, "HTTPS_PROXY=http://proxy.internal:8080") {
		t.Error("manifest-declared env var HTTPS_PROXY should have passed through")
	}
	if strings.Contains(env, "AWS_SECRET_ACCESS_KEY=") {
		t.Error("a secret not named in the manifest env allowlist must still be dropped")
	}
}

// TestPluginSandbox_RejectsWorldWritableEntrypoint pins F-H2: the
// pre-exec check refuses a group/other-writable entrypoint because a
// second party could swap the executable between the check and exec.
func TestPluginSandbox_RejectsWorldWritableEntrypoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("entrypoint permission checks are POSIX-specific")
	}

	manifest := "" +
		"name: ww\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	script := "#!/bin/sh\necho '{\"done\":true,\"total\":0}'\n"
	root := writePlugin(t, "ww", manifest, script)

	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	// Make the entrypoint world- and group-writable after discovery.
	entry := filepath.Join(plugins[0].Dir, "run.sh")
	if err := os.Chmod(entry, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err == nil {
		t.Fatal("expected Run to reject a world/group-writable entrypoint")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writability rejection, got %q", err.Error())
	}
}

// TestPluginSandbox_RejectsWritableParentDir pins that a writable
// in-dir parent of the entrypoint is rejected too (an attacker who can
// write the parent can replace the entrypoint or swap it for a symlink).
func TestPluginSandbox_RejectsWritableParentDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("entrypoint permission checks are POSIX-specific")
	}

	manifest := "" +
		"name: wp\n" +
		"entrypoint: ./bin/run.sh\n" +
		"mode: whitebox\n"
	root := writePlugin(t, "wp", manifest, "")
	pluginDir := filepath.Join(root, "wp")
	binDir := filepath.Join(pluginDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "run.sh"), []byte("#!/bin/sh\necho '{\"done\":true,\"total\":0}'\n"), 0o755); err != nil {
		t.Fatalf("write entrypoint: %v", err)
	}

	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	// Make the intermediate bin/ directory group/other-writable.
	if err := os.Chmod(binDir, 0o777); err != nil {
		t.Fatalf("chmod bin: %v", err)
	}

	_, err = plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err == nil {
		t.Fatal("expected Run to reject an entrypoint under a writable parent dir")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writability rejection, got %q", err.Error())
	}
}

// TestPluginSandbox_RejectsSymlinkEscapingEntrypoint pins that an
// entrypoint which is a symlink pointing OUTSIDE the plugin dir is
// rejected before exec (F-H2). A symlink staying inside the dir is
// tolerated (covered by the happy-path Run tests).
func TestPluginSandbox_RejectsSymlinkEscapingEntrypoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink entrypoint checks are POSIX-specific")
	}

	manifest := "" +
		"name: escape\n" +
		"entrypoint: ./run.sh\n" +
		"mode: whitebox\n"
	// writePlugin with empty script leaves no run.sh; create the symlink
	// ourselves pointing at an executable OUTSIDE the plugin dir.
	root := writePlugin(t, "escape", manifest, "")
	pluginDir := filepath.Join(root, "escape")

	outside := filepath.Join(t.TempDir(), "evil.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\necho '{\"done\":true,\"total\":0}'\n"), 0o755); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(pluginDir, "run.sh")); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	plugins, err := Discover([]string{root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	_, err = plugins[0].Run(context.Background(), ScanRequest{Mode: ModeWhitebox})
	if err == nil {
		t.Fatal("expected Run to reject an entrypoint symlink escaping the plugin dir")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink-escape rejection, got %q", err.Error())
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
