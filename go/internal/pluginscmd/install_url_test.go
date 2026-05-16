package pluginscmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateInstallURL_AcceptsTrustedTransports(t *testing.T) {
	ok := []string{
		"https://github.com/foo/bar",
		"https://github.com/foo/bar.git",
		"http://example.local/foo/bar.git",
		"git://example.com/foo/bar.git",
		"ssh://git@github.com:2222/foo/bar.git",
		"git@github.com:foo/bar.git",
		"deploy@gitlab.example.com:org/repo",
	}
	for _, u := range ok {
		if err := validateInstallURL(u); err != nil {
			t.Errorf("url %q should be accepted: %v", u, err)
		}
	}
}

func TestValidateInstallURL_RejectsDangerousTransports(t *testing.T) {
	// Each of these is a documented git URL form that can execute
	// arbitrary code or read arbitrary files on the host. Pin the
	// rejection contract so a future refactor doesn't accidentally
	// re-enable them.
	bad := []string{
		"file:///etc/passwd",
		"file:///home/me/.ssh/id_rsa",
		"ext::sh -c whoami",
		"ext::git-remote-evil",
		"ftp://example.com/repo.git",
		"javascript:alert(1)",
		"--upload-pack=evil",
		"",
		"   ",
	}
	for _, u := range bad {
		if err := validateInstallURL(u); err == nil {
			t.Errorf("url %q should be rejected, got nil error", u)
		}
	}
}

func TestRunInstall_RejectsDangerousURLBeforeClone(t *testing.T) {
	// Bind a sentinel gitClone that records whether it ever ran, then
	// invoke runInstall with a file:// URL. The validator must reject
	// before any subprocess.
	cloneCalled := false
	saved := gitClone
	t.Cleanup(func() { gitClone = saved })
	gitClone = func(srcURL, destDir string) ([]byte, error) {
		cloneCalled = true
		return nil, nil
	}

	var out, errOut bytes.Buffer
	err := runInstall(&out, &errOut, "file:///etc/passwd", "")
	if err == nil {
		t.Fatal("expected runInstall to reject file:// URL, got nil error")
	}
	if cloneCalled {
		t.Fatal("gitClone should NOT have been invoked for a rejected URL")
	}
	if !strings.Contains(err.Error(), "unsupported transport") {
		t.Errorf("error should explain the rejection; got %q", err.Error())
	}
}
