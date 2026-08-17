package models

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// profileFile represents the YAML structure of a profile config file.
//
// The canonical shape nests the credential under `auth:`. The three top-level
// fields exist ONLY to detect the flat shape that docs/fendix-yaml.md
// incorrectly showed for a while:
//
//	type: bearer          # WRONG — parses to nothing
//	value: <token>
//
// Without the detection that file unmarshalled cleanly into a zero-valued
// struct, LoadProfileFrom returned (nil, nil), and the scan ran completely
// UNAUTHENTICATED with no diagnostic — a silent failure of a security control,
// which is the one outcome the profile system must never produce.
type profileFile struct {
	Auth profileAuth `yaml:"auth"`

	FlatType   string `yaml:"type"`
	FlatValue  string `yaml:"value"`
	FlatHeader string `yaml:"header"`
}

type profileAuth struct {
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	Header string `yaml:"header"`
}

// DefaultProfileName is the profile loaded when no --profile is specified.
const DefaultProfileName = "default"

// ProfilesDir returns the path to ~/.fendix/profiles/.
func ProfilesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".fendix", "profiles"), nil
}

// LoadProfile reads a named profile from ~/.fendix/profiles/<name>.yaml.
// Returns nil (not an error) if the profile file does not exist.
func LoadProfile(name string) (*AuthContext, error) {
	dir, err := ProfilesDir()
	if err != nil {
		return nil, err
	}
	return LoadProfileFrom(filepath.Join(dir, name+".yaml"))
}

// LoadProfileFrom reads a profile from an explicit file path.
// Returns nil (not an error) if the file does not exist.
func LoadProfileFrom(path string) (*AuthContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading profile %s: %w", path, err)
	}

	var pf profileFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing profile %s: %w", path, err)
	}

	if pf.Auth.Value == "" {
		// Flat shape: the credential is there, just at the wrong nesting depth.
		// Fail loudly with the exact correction rather than scanning
		// unauthenticated and reporting a wall of 401s as "findings".
		if pf.FlatValue != "" {
			return nil, fmt.Errorf(
				"profile %s: credential found at the top level, but it must be nested under `auth:`.\n"+
					"Change:\n  type: %s\n  value: <token>\nto:\n  auth:\n    type: %s\n    value: <token>",
				path, orPlaceholder(pf.FlatType), orPlaceholder(pf.FlatType))
		}
		return nil, nil
	}

	return &AuthContext{
		Type:   pf.Auth.Type,
		Value:  pf.Auth.Value,
		Header: pf.Auth.Header,
	}, nil
}

// orPlaceholder renders an empty auth type as a placeholder so the correction
// message stays readable when only `value:` was supplied.
func orPlaceholder(s string) string {
	if s == "" {
		return "bearer"
	}
	return s
}

// ProfileLoader returns a function suitable for passing to ResolveAuth
// that loads the named profile. If name is empty, uses "default".
//
// A load failure yields nil (the scan continues unauthenticated) but is now
// LOGGED rather than discarded: swallowing it meant a malformed or
// wrongly-nested profile silently degraded every authenticated check, and the
// operator's only clue was an implausible pile of 401-shaped findings.
func ProfileLoader(name string) func() *AuthContext {
	if name == "" {
		name = DefaultProfileName
	}
	return func() *AuthContext {
		auth, err := LoadProfile(name)
		if err != nil {
			slog.Error("auth profile could not be loaded — scanning unauthenticated",
				"profile", name, "error", err)
			return nil
		}
		return auth
	}
}
