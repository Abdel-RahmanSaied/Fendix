package models

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// profileFile represents the YAML structure of a profile config file.
type profileFile struct {
	Auth profileAuth `yaml:"auth"`
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
		return nil, nil
	}

	return &AuthContext{
		Type:   pf.Auth.Type,
		Value:  pf.Auth.Value,
		Header: pf.Auth.Header,
	}, nil
}

// ProfileLoader returns a function suitable for passing to ResolveAuth
// that loads the named profile. If name is empty, uses "default".
func ProfileLoader(name string) func() *AuthContext {
	if name == "" {
		name = DefaultProfileName
	}
	return func() *AuthContext {
		auth, err := LoadProfile(name)
		if err != nil {
			return nil
		}
		return auth
	}
}
