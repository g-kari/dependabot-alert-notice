package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerSnapshotAndRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	m, err := NewManager(path, &Config{Targets: []Target{{Owner: "org"}}, Slack: SlackConfig{BotToken: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	snap := m.Snapshot()
	snap.Config.Targets[0].Owner = "mutated"
	if m.Snapshot().Config.Targets[0].Owner != "org" {
		t.Fatal("snapshot was not deep copied")
	}
	if err := m.Update(99, func(*Config) error { return nil }); err == nil {
		t.Fatal("expected revision conflict")
	}
	if err := m.Update(0, func(c *Config) error { c.Targets[0].Repo = "repo"; return nil }); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("runtime token was persisted")
	}
	if m.Snapshot().Revision != 1 {
		t.Fatalf("revision=%d", m.Snapshot().Revision)
	}
}
