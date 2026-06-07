package reporters

import (
	"bytes"
	"strings"
	"testing"
)

// TestResolveLang_Default: empty input resolves to English with no notice.
func TestResolveLang_Default(t *testing.T) {
	var buf bytes.Buffer
	got := ResolveLang("", &buf)
	if got != "en" {
		t.Errorf("ResolveLang(\"\") = %q, want \"en\"", got)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no stderr output for default, got %q", buf.String())
	}
}

// TestResolveLang_EnglishNoNotice: English is the source language and is
// never gated, even though other supported langs may be beta.
func TestResolveLang_EnglishNoNotice(t *testing.T) {
	var buf bytes.Buffer
	got := ResolveLang("en", &buf)
	if got != "en" {
		t.Errorf("ResolveLang(\"en\") = %q, want \"en\"", got)
	}
	if buf.Len() != 0 {
		t.Errorf("English must not emit a notice, got %q", buf.String())
	}
}

// TestResolveLang_UnsupportedFallsBack: an unknown code warns and falls back
// to English (prior CLI behaviour preserved).
func TestResolveLang_UnsupportedFallsBack(t *testing.T) {
	var buf bytes.Buffer
	got := ResolveLang("zz", &buf)
	if got != "en" {
		t.Errorf("ResolveLang(\"zz\") = %q, want \"en\"", got)
	}
	if !strings.Contains(buf.String(), "not a supported translation") {
		t.Errorf("expected fallback warning, got %q", buf.String())
	}
}

// TestResolveLang_BetaEmitsNotice: a beta language (ar) is allowed but emits
// a one-line machine-translated/beta notice when the experimental env var is
// not set to 1 (F-I3). The return value is still the requested language.
func TestResolveLang_BetaEmitsNotice(t *testing.T) {
	t.Setenv(ExperimentalLangEnv, "")

	var buf bytes.Buffer
	got := ResolveLang("ar", &buf)
	if got != "ar" {
		t.Errorf("ResolveLang(\"ar\") = %q, want \"ar\" (beta is allowed, not blocked)", got)
	}
	out := buf.String()
	if !strings.Contains(out, "machine-translated") || !strings.Contains(out, "beta") {
		t.Errorf("expected machine-translated/beta notice for ar, got %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("notice should be a single line, got %q", out)
	}
}

// TestResolveLang_BetaRegionSuffix: region-suffixed beta codes (ar-SA) are
// normalised, so they still trip the beta notice.
func TestResolveLang_BetaRegionSuffix(t *testing.T) {
	t.Setenv(ExperimentalLangEnv, "")

	var buf bytes.Buffer
	got := ResolveLang("ar-SA", &buf)
	if got != "ar-SA" {
		t.Errorf("ResolveLang(\"ar-SA\") = %q, want \"ar-SA\"", got)
	}
	if !strings.Contains(buf.String(), "beta") {
		t.Errorf("expected beta notice for region-suffixed ar, got %q", buf.String())
	}
}

// TestResolveLang_BetaSilencedByEnv: FENDIX_EXPERIMENTAL_LANG=1 opts in and
// suppresses the notice while still selecting the beta language.
func TestResolveLang_BetaSilencedByEnv(t *testing.T) {
	t.Setenv(ExperimentalLangEnv, "1")

	var buf bytes.Buffer
	got := ResolveLang("ar", &buf)
	if got != "ar" {
		t.Errorf("ResolveLang(\"ar\") = %q, want \"ar\"", got)
	}
	if buf.Len() != 0 {
		t.Errorf("FENDIX_EXPERIMENTAL_LANG=1 must silence the beta notice, got %q", buf.String())
	}
}
