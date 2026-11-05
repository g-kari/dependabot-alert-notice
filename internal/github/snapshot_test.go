package github

import (
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"testing"
)

func TestWithConfigFreezesOperationWithoutChangingClient(t *testing.T) {
	original := &config.Config{GhPath: "original", FetchMinSeverity: "high"}
	client := New(original).(*ghClient)
	next := config.Config{GhPath: "fixture", FetchMinSeverity: "low", Targets: []config.Target{{Owner: "org", Excludes: []string{"api"}}}}
	bound, err := client.WithConfig(next)
	if err != nil {
		t.Fatal(err)
	}
	next.Targets[0].Excludes[0] = "mutated"
	original.GhPath = "changed"
	c := bound.(*ghClient)
	if c.cfg.GhPath != "fixture" || c.cfg.FetchMinSeverity != "low" || c.cfg.Targets[0].Excludes[0] != "api" {
		t.Fatalf("binding not frozen: %+v", c.cfg)
	}
	if client.cfg.FetchMinSeverity != "high" {
		t.Fatal("binding mutated original client")
	}
}
