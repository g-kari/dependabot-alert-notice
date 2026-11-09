package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
	"gopkg.in/yaml.v3"
)

func TestGitHubAuthConfigContainsOnlyReferenceMetadata(t *testing.T) {
	cfg := Defaults()
	cfg.GitHubAuth = ghcommand.Settings{Mode: "token_env", Host: "github.com", TokenEnv: "FIXTURE_GITHUB_TOKEN", ExpectedLogin: "alice"}
	runner, err := ghcommand.NewWithEnvironment(filepath.Join(t.TempDir(), "fixture-gh"), cfg.GitHubAuth, []string{"FIXTURE_GITHUB_TOKEN=synthetic-secret-never-persist"})
	if err != nil {
		t.Fatal(err)
	}
	copy, err := Clone(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	if copy.GitHubAuth != cfg.GitHubAuth {
		t.Fatal("clone lost authentication metadata")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	jsonConfig, _ := json.Marshal(cfg)
	yamlConfig, _ := yaml.Marshal(cfg)
	for _, data := range []string{string(saved), string(jsonConfig), string(yamlConfig), fmt.Sprintf("%+v %#v", runner, runner)} {
		if strings.Contains(data, "synthetic-secret-never-persist") {
			t.Fatal("secret escaped runtime context")
		}
	}
	if !strings.Contains(string(saved), "token_env: FIXTURE_GITHUB_TOKEN") {
		t.Fatal("non-secret reference was not saved")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GitHubAuth != cfg.GitHubAuth {
		t.Fatal("load lost authentication metadata")
	}
}

func TestGitHubAuthValidationDoesNotAllowImplicitFallback(t *testing.T) {
	for _, s := range []ghcommand.Settings{{Mode: "token_env"}, {Mode: "inherited", ExpectedLogin: "alice"}, {Mode: "token_env", TokenEnv: "TOKEN", Host: "other.invalid"}} {
		cfg := Defaults()
		cfg.GitHubAuth = s
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid selection %+v", s)
		}
	}
}
