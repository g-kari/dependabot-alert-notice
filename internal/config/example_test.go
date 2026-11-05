package config

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExampleSandboxFieldsAreNestedAndPodmanRequiresIsolation(t *testing.T) {
	for _, path := range []string{"../../config.yaml.example", "../../packaging/macos/config.yaml.example"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg := Defaults()
		decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
		decoder.KnownFields(true)
		if err := decoder.Decode(cfg); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !cfg.Evaluator.Sandbox.Enabled || cfg.Evaluator.Sandbox.Runtime != "auto" {
			t.Fatalf("sandbox=%+v", cfg.Evaluator.Sandbox)
		}
	}
	cfg := Defaults()
	cfg.Evaluator.Sandbox.Runtime = "podman"
	cfg.Evaluator.Sandbox.Enabled = false
	if cfg.Validate() == nil {
		t.Fatal("Podman without isolation accepted")
	}
}
