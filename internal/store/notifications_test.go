package store

import (
	"path/filepath"
	"testing"
)

func TestNotificationGroupsPersistAndSeparateDestinationRepository(t *testing.T) {
	path := filepath.Join(t.TempDir(), "groups.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	key := NotificationGroupKey("slack", "workspace/channel", "Org", "Repo")
	if err := s.SaveNotificationGroup(key, "parent-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.NotificationGroup(NotificationGroupKey("slack", "workspace/channel", "org", "repo"))
	if err != nil || got != "parent-1" {
		t.Fatalf("group = %q, %v", got, err)
	}
	for _, other := range []string{NotificationGroupKey("slack", "other", "org", "repo"), NotificationGroupKey("discord", "workspace/channel", "org", "repo"), NotificationGroupKey("slack", "workspace/channel", "org", "other")} {
		if got, err := s.NotificationGroup(other); err != nil || got != "" {
			t.Fatalf("crossed group boundary: %q, %v", got, err)
		}
	}
	if len(key) != 64 {
		t.Fatalf("destination must be hashed: %q", key)
	}
}
