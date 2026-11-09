package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
)

func TestManualUpdateLoadsAuthSelectionWithoutImplicitFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := loadUpdateConfig(path, false); err == nil {
		t.Fatal("explicit missing config fell back")
	}
	legacy, err := loadUpdateConfig(path, true)
	if err != nil || legacy.GitHubAuth.Mode != "" {
		t.Fatal("missing-default compatibility failed")
	}
	if err := os.WriteFile(path, []byte("gh_path: fixture-gh\ngithub_auth:\n  mode: token_env\n  token_env: MISSING_SYNTHETIC_SOURCE\n  expected_login: alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUpdateConfig(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHubAuth.ExpectedLogin != "alice" || cfg.GhPath != "fixture-gh" {
		t.Fatal("update selection not loaded")
	}
	if _, err := releaseSource("org/repo", "", *cfg); err == nil {
		t.Fatal("manual update missing source fell back")
	}
}

func TestReleaseSourceUsesSnapshotPathAndFrozenRunner(t *testing.T) {
	cfg := config.Config{GhPath: "snapshot-gh", GitHubAuth: ghcommand.Settings{Mode: "inherited"}}
	source, err := releaseSource("org/repo", "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.GhPath = "changed"
	if source.Path != "snapshot-gh" || source.Runner == nil {
		t.Fatal("release source not frozen")
	}
	if !strings.Contains(source.Runner.(*ghcommand.Context).Description(), "inherited") {
		t.Fatal("legacy mode unlabeled")
	}
	override, err := releaseSource("org/repo", "override-gh", cfg)
	if err != nil || override.Path != "override-gh" {
		t.Fatal("explicit executable override lost")
	}
}
