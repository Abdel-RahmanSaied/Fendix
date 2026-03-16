package models

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfileFrom_ValidProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `auth:
  type: bearer
  value: "Bearer profile-token-123"
  header: Authorization
`
	os.WriteFile(path, []byte(content), 0644)

	auth, err := LoadProfileFrom(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth")
	}
	if auth.Value != "Bearer profile-token-123" {
		t.Errorf("Value = %q, want Bearer profile-token-123", auth.Value)
	}
	if auth.Type != "bearer" {
		t.Errorf("Type = %q, want bearer", auth.Type)
	}
	if auth.Header != "Authorization" {
		t.Errorf("Header = %q, want Authorization", auth.Header)
	}
}

func TestLoadProfileFrom_APIKeyProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apikey.yaml")
	content := `auth:
  type: apikey
  value: "sk-live-abc123"
  header: X-API-Key
`
	os.WriteFile(path, []byte(content), 0644)

	auth, err := LoadProfileFrom(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.Type != "apikey" {
		t.Errorf("Type = %q, want apikey", auth.Type)
	}
	if auth.Header != "X-API-Key" {
		t.Errorf("Header = %q, want X-API-Key", auth.Header)
	}
}

func TestLoadProfileFrom_FileNotFound(t *testing.T) {
	auth, err := LoadProfileFrom("/nonexistent/path/profile.yaml")
	if err != nil {
		t.Fatalf("missing file should return nil, not error: %v", err)
	}
	if auth != nil {
		t.Error("missing file should return nil auth")
	}
}

func TestLoadProfileFrom_EmptyValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	content := `auth:
  type: bearer
  value: ""
`
	os.WriteFile(path, []byte(content), 0644)

	auth, err := LoadProfileFrom(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth != nil {
		t.Error("empty value should return nil auth")
	}
}

func TestLoadProfileFrom_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{{invalid yaml"), 0644)

	_, err := LoadProfileFrom(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadProfileFrom_MinimalProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.yaml")
	content := `auth:
  value: "Bearer minimal-tok"
`
	os.WriteFile(path, []byte(content), 0644)

	auth, err := LoadProfileFrom(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth")
	}
	if auth.Value != "Bearer minimal-tok" {
		t.Errorf("Value = %q, want Bearer minimal-tok", auth.Value)
	}
	if auth.Type != "" {
		t.Errorf("Type should be empty for auto-detection, got %q", auth.Type)
	}
}

func TestProfileLoader_Integration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "default.yaml")
	content := `auth:
  value: "Bearer loader-token"
`
	os.WriteFile(path, []byte(content), 0644)

	loader := func() *AuthContext {
		auth, _ := LoadProfileFrom(path)
		return auth
	}

	auth := ResolveAuth(nil, loader)
	if auth == nil {
		t.Fatal("expected auth from profile loader")
	}
	if auth.Value != "Bearer loader-token" {
		t.Errorf("Value = %q, want Bearer loader-token", auth.Value)
	}
	if auth.Type != AuthTypeBearer {
		t.Errorf("Type = %q, want auto-detected bearer", auth.Type)
	}
}

func TestProfileLoader_FlagOverridesProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "default.yaml")
	content := `auth:
  value: "Bearer profile-token"
`
	os.WriteFile(path, []byte(content), 0644)

	loader := func() *AuthContext {
		auth, _ := LoadProfileFrom(path)
		return auth
	}

	flagAuth := &AuthContext{Value: "Bearer flag-token"}
	auth := ResolveAuth(flagAuth, loader)

	if auth.Value != "Bearer flag-token" {
		t.Errorf("flag should override profile, got %q", auth.Value)
	}
}
