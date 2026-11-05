package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestPolicyExcludeIsMonitored(t *testing.T) {
	m, err := config.NewManager(filepath.Join(t.TempDir(), "c.yaml"), &config.Config{Targets: []config.Target{{Owner: "Org"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := New(m)
	if !p.IsMonitored(m.Snapshot(), "org", "repo") {
		t.Fatal("org-wide target should monitor repo")
	}
	if err := p.UpdateExclusion(context.Background(), 0, "org", "repo", true); err != nil {
		t.Fatal(err)
	}
	if p.IsMonitored(m.Snapshot(), "org", "repo") {
		t.Fatal("excluded repo is monitored")
	}
	if err := p.UpdateExclusion(context.Background(), 1, "org", "repo", false); err != nil {
		t.Fatal(err)
	}
	if !p.IsMonitored(m.Snapshot(), "org", "repo") {
		t.Fatal("included repo is not monitored")
	}
}

func TestMonitoringPrecedenceAndUnconfiguredRepos(t *testing.T) {
	for _, targets := range [][]config.Target{
		{{Owner: "ORG", Repo: "API"}, {Owner: "org", Excludes: []string{"api"}}},
		{{Owner: "org", Excludes: []string{"api"}}, {Owner: "ORG", Repo: "API"}},
	} {
		if (&Policy{}).IsMonitored(config.Snapshot{Config: config.Config{Targets: targets}}, "org", "api") {
			t.Fatalf("exclusion overridden by target order: %+v", targets)
		}
	}
	if (&Policy{}).IsMonitored(config.Snapshot{}, "org", "api") {
		t.Fatal("no targets should not enable monitoring")
	}
}
