package secrets

import (
	"strings"
	"testing"
)

// TestClassifyPlaceholder is the unit gate on the classifier. It is split into
// a FIRES group and a QUIET group, and the QUIET group is the one that matters
// most: this rule costs a finding 20 confidence points, so over-reach
// de-escalates real credentials. Every QUIET row is a shape that appears in
// this repo's own fixtures or in vendor documentation.
func TestClassifyPlaceholder(t *testing.T) {
	// valueStartIn locates value inside line so the table can be written in
	// terms of the real source line rather than hand-counted offsets.
	valueStartIn := func(t *testing.T, line, value string) int {
		t.Helper()
		i := strings.Index(line, value)
		if i < 0 {
			t.Fatalf("value %q is not in line %q — fix the table row", value, line)
		}
		return i
	}

	cases := []struct {
		name  string
		line  string
		value string
		want  placeholderSignals
	}{
		// ---- FIRES ----------------------------------------------------
		{
			name:  "fixture name prefix",
			line:  `FAKE_API_KEY = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
			want:  placeholderSignals{NamePrefix: true},
		},
		{
			name:  "long identical run",
			line:  `GITHUB_TOKEN = "ghp_` + strings.Repeat("A", 36) + `"`,
			value: "ghp_" + strings.Repeat("A", 36),
			want:  placeholderSignals{RepeatedChars: true},
		},
		{
			name:  "aws documented example key",
			line:  `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`,
			value: "AKIAIOSFODNN7EXAMPLE",
			want:  placeholderSignals{ValueWord: true},
		},
		{
			name:  "google fixture key",
			line:  `GOOGLE_KEY = "AIzaSyD-ExampleFakeKeyForTestingPurpose"`,
			value: "AIzaSyD-ExampleFakeKeyForTestingPurpose",
			want:  placeholderSignals{ValueWord: true},
		},
		{
			name:  "subscript target with a too-short value",
			line:  `app.config['JWT_SECRET_KEY'] = 'test'`,
			value: "test",
			want:  placeholderSignals{LowLength: true},
		},
		{
			name:  "camelCase fixture name",
			line:  `fakeApiKey = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
			want:  placeholderSignals{NamePrefix: true},
		},
		{
			name:  "kebab fixture name",
			line:  `MOCK-KEY = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
			want:  placeholderSignals{NamePrefix: true},
		},
		{
			name:  "camelCase fixture name, password",
			line:  `dummyPassword = "hunter2hunter2"`,
			value: "hunter2hunter2",
			want:  placeholderSignals{NamePrefix: true},
		},

		// ---- QUIET (the anti-over-reach gate) -------------------------
		{
			name:  "same value under a plain key",
			line:  `API_KEY = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
		},
		{
			name:  "stripe documentation key",
			line:  `STRIPE_LIVE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`,
			value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		},
		{
			name:  "48-char openai key",
			line:  `OPENAI_LEGACY = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"`,
			value: "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt",
		},
		{
			name:  "short but real-looking placeholder-free value",
			line:  `app.config["JWT_SECRET_KEY"] = "rotate-me"`,
			value: "rotate-me",
		},
		{
			name:  "db password (the key resolves to the url user, not the var)",
			line:  `DB_URL = "postgresql://admin:secretpassword@db.example.com:5432/mydb"`,
			value: "secretpassword",
		},
		// The S1 boundary cases. Each of these WOULD fire under a naive
		// "starts with test/…" prefix test.
		{
			name:  "latest_token is not a fixture",
			line:  `latest_token = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
		},
		{
			name:  "testament is not a fixture",
			line:  `testament = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
		},
		{
			name:  "testing_key is not a fixture",
			line:  `testing_key = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
		},
		{
			name:  "ALL-CAPS TESTING_KEY must not trip the camelCase arm",
			line:  `TESTING_KEY = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"`,
			value: "08bf2e526a1f4c8db3b91e7d0f2a5c6e",
		},
		{
			name:  "empty value classifies as not-a-placeholder",
			line:  `{"type": "service_account"}`,
			value: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := 0
			if c.value != "" {
				start = valueStartIn(t, c.line, c.value)
			}
			got := classifyPlaceholder(c.line, start, c.value)
			if got != c.want {
				t.Errorf("classifyPlaceholder(%q, %q) = %+v; want %+v", c.line, c.value, got, c.want)
			}
			if got.isPlaceholder() != (c.want != placeholderSignals{}) {
				t.Errorf("isPlaceholder() = %v; want %v", got.isPlaceholder(), c.want != placeholderSignals{})
			}
		})
	}
}

func TestHasRepeatedChars(t *testing.T) {
	cases := map[string]bool{
		"":                                 false,
		"abc":                              false,
		strings.Repeat("A", 8):             true,  // exactly the run floor
		strings.Repeat("A", 7):             false, // below the 8-byte length gate
		"ghp_" + strings.Repeat("A", 36):   true,  // the canonical fixture token
		"aaaXaaaXaa":                       true,  // no run of 8, but 'a' is 8/10 = 80%
		"aXaXaXaXaXaXaXaXaX":               false, // 9+9 of 18 = 50% each, under the 60% floor
		"08bf2e526a1f4c8db3b91e7d0f2a5c6e": false, // real-looking 32-hex
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc": false,
	}
	for in, want := range cases {
		if got := hasRepeatedChars(in); got != want {
			t.Errorf("hasRepeatedChars(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestLastAssignmentKey(t *testing.T) {
	cases := map[string]string{
		`FAKE_API_KEY = "`:                      "FAKE_API_KEY",
		`app.config['JWT_SECRET_KEY'] = '`:      "JWT_SECRET_KEY",
		`DB_URL = "postgresql://admin:`:         "admin", // last binding wins
		`no assignment here`:                    "",
		`GITHUB_TOKEN = "`:                      "GITHUB_TOKEN",
		`  "api_key": "`:                        "api_key",
		`app.config["SECRET_KEY_HMAC"]   =   '`: "SECRET_KEY_HMAC",
	}
	for prefix, want := range cases {
		if got := lastAssignmentKey(prefix); got != want {
			t.Errorf("lastAssignmentKey(%q) = %q; want %q", prefix, got, want)
		}
	}
}
