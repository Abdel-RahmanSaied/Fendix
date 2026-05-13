// Tiny Go module that imports two known-vulnerable deps so the
// heavy-eval harness can exercise fendix's govulncheck-based dep
// scanner (TASK-119). The CVEs are:
//
//   - github.com/dgrijalva/jwt-go v3.2.0+incompatible — CVE-2020-26160
//   - gopkg.in/yaml.v2 v2.2.2 — CVE-2019-11254
//
// We call into both packages so the call-graph reachability check
// in govulncheck flags them as reachable, not just present.
package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
)

func main() {
	// CVE-2020-26160 vulnerable surface: jwt.Parse with un-validated
	// signing method allows "alg: none" bypass.
	tok, _ := jwt.Parse("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.x", func(t *jwt.Token) (any, error) {
		return []byte("k"), nil
	})
	if tok != nil {
		fmt.Println("token:", tok.Header)
	}

	var m map[string]any
	if err := yaml.Unmarshal([]byte("a: 1\n"), &m); err == nil {
		fmt.Println("parsed:", m)
	}
}
