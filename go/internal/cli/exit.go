// Package cli holds tiny shared CLI utilities. Today it has one type:
// ExitError, which carries a custom exit code that the top-level
// main() catches to call os.Exit explicitly.
//
// Why this exists: Cobra's RunE returning an error always exits 1 (or
// whatever cobra picks). The verify subcommand needs CI-script-friendly
// distinction between "finding still present" (exit 1, the build
// should fail) and "verify couldn't tell" (exit 2, the build should
// not fail on ambiguous results — the operator needs to investigate).
// Sprint 03 introduced the convention.
package cli

import "fmt"

// ExitError carries an explicit exit code from a Cobra RunE up to
// main(). It satisfies the error interface so RunE can return it
// without changing signatures, but main() inspects the type and
// honours Code via os.Exit.
type ExitError struct {
	Code    int
	Message string
}

// Error returns the user-facing message, or a generic "exit N" if no
// message was supplied.
func (e *ExitError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Message
}

// ExitWithCode returns an *ExitError suitable for returning from a
// Cobra RunE closure. Pair with main()'s `errors.As(err, *cli.ExitError)`
// catch to translate to a specific os.Exit code.
func ExitWithCode(code int, msg string) error {
	return &ExitError{Code: code, Message: msg}
}
