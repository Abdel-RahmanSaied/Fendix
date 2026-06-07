package ghapp

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The best-effort sandbox runs the command with exactly the env it is
// handed (the caller is responsible for stripping the token) and reports
// "none" so the absence of OS isolation is observable.
func TestBestEffortSandbox_PassesEnvAndReportsNone(t *testing.T) {
	var sb Sandbox = bestEffortSandbox{}
	if sb.Isolation() != "none" {
		t.Errorf("best-effort isolation = %q, want none", sb.Isolation())
	}
	env := []string{"FOO=bar", "BAZ=qux"}
	cmd := sb.Command(context.Background(), discardLogger(), "echo", []string{"hi"}, env)
	if cmd == nil {
		t.Fatal("Command returned nil")
	}
	if len(cmd.Env) != len(env) {
		t.Fatalf("env not passed through: got %v want %v", cmd.Env, env)
	}
	for i := range env {
		if cmd.Env[i] != env[i] {
			t.Errorf("env[%d] = %q want %q", i, cmd.Env[i], env[i])
		}
	}
	if cmd.Args[0] != "echo" || cmd.Args[len(cmd.Args)-1] != "hi" {
		t.Errorf("unexpected argv: %v", cmd.Args)
	}
}

// NewSandbox must always return a usable Sandbox (never nil) and a
// non-empty isolation description, so the choice is explicit on every
// platform — strong isolation on Linux when available, best-effort
// otherwise. We don't assert *which* one (it depends on the host
// kernel), only that the contract holds.
func TestNewSandbox_NeverNil(t *testing.T) {
	sb := NewSandbox(discardLogger())
	if sb == nil {
		t.Fatal("NewSandbox returned nil")
	}
	if sb.Isolation() == "" {
		t.Error("Isolation() must be a non-empty, stable description")
	}
	// The command must carry the env we pass and not invent a token.
	cmd := sb.Command(context.Background(), discardLogger(), "true", nil, []string{"A=1"})
	if cmd == nil || len(cmd.Env) != 1 || cmd.Env[0] != "A=1" {
		t.Errorf("NewSandbox command did not pass env through: %+v", cmd)
	}
}
