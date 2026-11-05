package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNotificationBatchPersistsDeduplicatesAndKeepsOriginalDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if err := s.ScheduleNotification("scope", "key", "org", "repo", "first", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleNotification("scope", "key", "org", "repo", "second", now.Add(2*time.Hour)); err != nil {
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
	if rows, err := s.DueNotifications("scope", now.Add(59*time.Minute)); err != nil || len(rows) != 0 {
		t.Fatalf("early=%+v %v", rows, err)
	}
	rows, err := s.DueNotifications("scope", now.Add(time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Fingerprint != "second" {
		t.Fatalf("due=%+v %v", rows, err)
	}
	if err := s.ScheduleNotification("scope", "key", "org", "repo", "third", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteNotification("key", "second", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if early, err := s.DueNotifications("scope", now.Add(time.Hour)); err != nil || len(early) != 0 {
		t.Fatalf("sent twice in one interval: %+v %v", early, err)
	}
	rows, err = s.DueNotifications("scope", now.Add(2*time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Fingerprint != "third" {
		t.Fatalf("concurrent event lost=%+v %v", rows, err)
	}
	if err := s.CompleteNotification("key", "third", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleNotification("scope", "key", "org", "repo", "third", now.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.DueNotifications("scope", now.Add(5*time.Hour)); err != nil || len(rows) != 0 {
		t.Fatalf("unchanged resent=%+v %v", rows, err)
	}
	if rows, err := s.DueNotifications("other", now.Add(5*time.Hour)); err != nil || len(rows) != 0 {
		t.Fatalf("scope crossed=%+v %v", rows, err)
	}
}
