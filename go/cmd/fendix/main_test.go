package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/cli"
	"github.com/Abdel-RahmanSaied/Fendix/internal/metrics"
	"github.com/spf13/cobra"
)

func TestClassifyResult(t *testing.T) {
	scan := &cobra.Command{Use: "scan"}
	other := &cobra.Command{Use: "version"}
	cases := []struct {
		name        string
		cmd         *cobra.Command
		err         error
		wantCode    int
		wantClass   string
		wantSuccess bool
	}{
		{"clean", scan, nil, 0, "", true},
		{"findings exit 1 is still a usable result", scan, cli.ExitWithCode(1, "findings"), 1, "", true},
		{"scan error", scan, cli.ExitWithCode(2, ""), 2, "scan-error", false},
		{"usage error buckets as usage", other, errors.New("unknown flag: --workrs"), 2, "usage", false},
		{"generic runtime error", other, errors.New("boom"), 2, "runtime", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, class, success := classifyResult(c.cmd, c.err)
			if code != c.wantCode || class != c.wantClass || success != c.wantSuccess {
				t.Errorf("classifyResult = (%d,%q,%v), want (%d,%q,%v)",
					code, class, success, c.wantCode, c.wantClass, c.wantSuccess)
			}
		})
	}
}

func TestIsUsageError(t *testing.T) {
	yes := []string{"unknown flag: --x", "unknown command \"scn\"", "required flag(s) \"url\" not set", "accepts 1 arg(s)"}
	for _, m := range yes {
		if !isUsageError(errors.New(m)) {
			t.Errorf("isUsageError(%q) = false, want true", m)
		}
	}
	if isUsageError(errors.New("scan failed: connection refused")) {
		t.Error("a runtime error was misclassified as usage")
	}
}

// TestRecordCLIMetric_FailureRecordsOneEvent is the B1 invariant: every
// invocation (here a failure) writes exactly one phase="cli" event.
func TestRecordCLIMetric_FailureRecordsOneEvent(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "true")
	t.Setenv(metrics.EnvPathFlag, path)

	recordCLIMetric("scan", 2, "scan-error", false, 1500*time.Millisecond)

	events, err := metrics.LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	cs := metrics.SummarizeCommands(events, 0)
	if cs.Total != 1 || cs.Success != 0 || cs.ByErrorClass["scan-error"] != 1 {
		t.Errorf("summary = %+v, want 1 total / 0 success / scan-error:1", cs)
	}
}

func TestRecordCLIMetric_DisabledWritesNothing(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "false") // opt-in: default off
	t.Setenv(metrics.EnvPathFlag, path)

	recordCLIMetric("version", 0, "", true, time.Millisecond)

	if events, _ := metrics.LoadEvents(path); len(events) != 0 {
		t.Errorf("metrics disabled but %d events written", len(events))
	}
}

// TestMetricsShow_RendersCLISuccessRate verifies the v0.25 rate line appears
// in `metrics show` and reads the env-configured path (ResolvePath).
func TestMetricsShow_RendersCLISuccessRate(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "true")
	t.Setenv(metrics.EnvPathFlag, path)
	// One success, one usage failure.
	recordCLIMetric("version", 0, "", true, time.Millisecond)
	recordCLIMetric("scan", 2, "usage", false, time.Millisecond)

	cmd := newMetricsShowCmd()
	var buf strings.Builder
	cmd.SetOut(&buf)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("show: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CLI success rate:", "50.0%", "below target", "failures (usage): 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics show missing %q:\n%s", want, out)
		}
	}
}

func TestScanEmptyTargetTeachingError(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan"})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error for scan with no target")
	}
	for _, want := range []string{"--code .", "--url", "--spec", "fendix demo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("teaching error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan", "--workrs", "5"})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	err := root.Execute()
	if err == nil || !isUsageError(err) {
		t.Fatalf("bad flag should be a usage error, got %v", err)
	}
}

func TestRootHelpHasQuickstartAndGroups(t *testing.T) {
	root := newRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	help := out.String()
	for _, want := range []string{"Get started:", "fendix demo", "Core commands:", "scan", "init", "demo"} {
		if !strings.Contains(help, want) {
			t.Errorf("root help missing %q", want)
		}
	}
}
