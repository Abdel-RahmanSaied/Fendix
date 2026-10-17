package catalog

import (
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// unresolvedPlaceholder matches interpolation tokens that only make sense
// before a value is filled in: Semgrep metavariables ($FUNC, $...ARGS),
// ${NAME}, {{...}}, {name} and printf verbs (%s, %d, %v, %q).
var unresolvedPlaceholder = regexp.MustCompile(`\$\{[^}]*\}|\$(?:\.\.\.)?[A-Z_][A-Z0-9_]*\b|\{\{[^}]*\}\}|\{[a-z_][a-z0-9_]*\}|%[-+# 0-9.]*[sdvq]\b`)

// allowedPlaceholderLike lists reviewed tokens that look like placeholders but
// are literal example syntax in a check's published copy, by check and field.
var allowedPlaceholderLike = map[string]map[string][]string{
	// DB-API parameter syntax in the parameterised-query example.
	"python-sql-injection-string-format": {"remediation": {"%s"}},
}

// nonProseCheckFields are Check's string fields that hold identifiers or enum
// values, not human-readable copy. Every other string field is published
// prose and is scanned below; a new field must be classified here or there.
var nonProseCheckFields = map[string]bool{
	"ID": true, "FindingID": true, "Analyzer": true, "Category": true, "DefaultSeverity": true,
	"Confidence": true, "ExecutionMode": true, "AuthRequirement": true, "Availability": true,
}

// publishedProse returns the check's human-readable fields by JSON name.
func publishedProse(t *testing.T, check Check) map[string]string {
	t.Helper()
	out := map[string]string{}
	value, typ := reflect.ValueOf(check), reflect.TypeOf(check)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() != reflect.String || nonProseCheckFields[field.Name] {
			continue
		}
		out[field.Name] = value.Field(i).String()
	}
	return out
}

// TestPublishedProseHasNoUnresolvedPlaceholders fails when a check's static
// published copy carries a raw interpolation token. Semgrep rules whose
// runtime message holds metavariables publish metadata.fendix_title and
// fendix_remediation instead (v3.6.3: eleven checks printed '$VAR', '$FUNC'
// and similar on the public catalog).
func TestPublishedProseHasNoUnresolvedPlaceholders(t *testing.T) {
	contract, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(contract.Checks) == 0 {
		t.Fatal("catalog has no checks")
	}
	for _, check := range contract.Checks {
		prose := publishedProse(t, check)
		fields := make([]string, 0, len(prose))
		for name := range prose {
			fields = append(fields, name)
		}
		sort.Strings(fields)
		for _, name := range fields {
			allowed := map[string]bool{}
			for _, token := range allowedPlaceholderLike[check.ID][fieldJSONName(name)] {
				allowed[token] = true
			}
			for _, token := range unresolvedPlaceholder.FindAllString(prose[name], -1) {
				if !allowed[token] {
					t.Errorf("%s %s publishes unresolved placeholder %q: %q", check.ID, fieldJSONName(name), token, prose[name])
				}
			}
		}
	}
}

// TestPublishedProseFieldsAreClassified keeps the scan above complete: the
// prose fields it finds must be exactly the ones the contract publishes as
// copy today, so a new string field cannot skip the placeholder check.
func TestPublishedProseFieldsAreClassified(t *testing.T) {
	prose := publishedProse(t, Check{})
	got := make([]string, 0, len(prose))
	for name := range prose {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"Remediation", "Title"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Check prose fields = %v, want %v: classify the new field in nonProseCheckFields or extend this list", got, want)
	}
}

// TestPlaceholderDetectorScope pins what the detector treats as a leak and
// what it leaves alone, so legitimate copy is not flagged.
func TestPlaceholderDetectorScope(t *testing.T) {
	leaks := []string{"found in '$VAR'", "route '$FUNC'", "$...ARGS", "${TOKEN}", "{{ secret }}", "for {user_id}", "query %s", "value %d"}
	for _, text := range leaks {
		if !unresolvedPlaceholder.MatchString(text) {
			t.Errorf("detector missed %q", text)
		}
	}
	clean := []string{"costs $5", "100% coverage", "Depends(get_current_user)", "dependencies=[...]", "{\"type\": \"service_account\"}", "Use os.environ[\"API_KEY\"]"}
	for _, text := range clean {
		if unresolvedPlaceholder.MatchString(text) {
			t.Errorf("detector flagged legitimate copy %q: %q", text, unresolvedPlaceholder.FindString(text))
		}
	}
}

func fieldJSONName(goName string) string {
	field, ok := reflect.TypeOf(Check{}).FieldByName(goName)
	if !ok {
		return goName
	}
	tag := field.Tag.Get("json")
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i]
		}
	}
	return tag
}
