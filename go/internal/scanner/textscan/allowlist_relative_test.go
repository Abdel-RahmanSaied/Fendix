package textscan

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// A privileged Kubernetes container (IAC_K8S_PRIVILEGED_CONTAINER: HIGH,
// high confidence) and a shell-executing child_process call
// (JS_CHILD_PROCESS_SHELL). Only textscan reports either, so a diff scan that
// skips the files loses them outright.
const privilegedPod = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: worker\nspec:\n  containers:\n    - name: worker\n      image: example/worker\n      securityContext:\n        privileged: true\n"
const childProcessJS = "const child_process = require(\"child_process\");\nfunction run(name) { return child_process.exec(\"run \" + name); }\n"

// findingKeys reduces findings to "rule id @ endpoint" so scans can be compared
// on what a report shows, including the user-facing path.
func findingKeys(fs []evidence.Evidence) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID+" @ "+f.Endpoint)
	}
	sort.Strings(out)
	return out
}

// The composite Action's default `code: "."` plus diff mode on a pull request
// must report the same textscan findings, at the same root-relative
// endpoints, as an absolute --code and as the full walk. Through v3.6.1 a
// relative root made TraversesSymlink refuse every changed file, so the diff
// scan reported nothing.
func TestScanWithAllowlist_RelativeRootMatchesAbsoluteRoot(t *testing.T) {
	abs, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, "deploy/k8s/worker.yaml", privilegedPod)
	writeFile(t, abs, "src/jobs.js", childProcessJS)
	t.Chdir(abs)
	changed := []string{"deploy/k8s/worker.yaml", "src/jobs.js"}

	full, err := Scan(".", AllRules())
	if err != nil {
		t.Fatal(err)
	}
	want := findingKeys(full)
	if len(want) < 2 {
		t.Fatalf("seed produced %v; expected the privileged-container and child_process findings", want)
	}
	for _, codePath := range []string{".", "./", abs} {
		got, err := ScanWithAllowlist(codePath, AllRules(), gitdiff.NewAllowlist(codePath, changed))
		if err != nil {
			t.Fatalf("code %q: %v", codePath, err)
		}
		if keys := findingKeys(got); !reflect.DeepEqual(keys, want) {
			t.Errorf("code %q: diff scan reported %v, want the full scan's %v", codePath, keys, want)
		}
	}
}

// Zero changed files still scope textscan to nothing, for every root spelling.
func TestScanWithAllowlist_EmptyAllowlistWithRelativeRoot(t *testing.T) {
	abs, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, "deploy/k8s/worker.yaml", privilegedPod)
	t.Chdir(abs)
	for _, codePath := range []string{".", "./", abs} {
		got, err := ScanWithAllowlist(codePath, AllRules(), gitdiff.NewAllowlist(codePath, nil))
		if err != nil || len(got) != 0 {
			t.Errorf("code %q: empty allowlist returned (%v, %v), want nothing", codePath, findingKeys(got), err)
		}
	}
}
