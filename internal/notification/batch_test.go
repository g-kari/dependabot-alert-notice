package notification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestHourlyBatchCoalescesRetriesAndUsesCurrentPolicy(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org"}}
	if cfg.NotificationInterval != time.Hour {
		t.Fatal("default must be hourly")
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	b := NewBatcher(s, "scope", func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil }, func(owner, repo string) string { return store.NotificationGroupKey("test", "fixture", owner, repo) })
	b.now = func() time.Time { return now }
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, NotifiedAt: now}
	s.SaveObserved(r)
	for i := 0; i < 3; i++ {
		if deferred, err := b.Defer("org", "repo"); !deferred || err != nil {
			t.Fatalf("defer=%v %v", deferred, err)
		}
	}
	calls := 0
	fail := true
	send := func(owner, repo string) (string, error) {
		calls++
		if owner != "org" || repo != "repo" {
			t.Fatal("wrong repository")
		}
		if fail {
			return "", errors.New("fixture")
		}
		return currentBatchFingerprint(t, s, cfg)
	}
	if err := b.Flush(context.Background(), now.Add(59*time.Minute), send); err != nil || calls != 0 {
		t.Fatalf("early calls=%d %v", calls, err)
	}
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err == nil || calls != 1 {
		t.Fatalf("failure calls=%d %v", calls, err)
	}
	cfg.Targets = nil
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil || calls != 1 {
		t.Fatalf("excluded sent=%d %v", calls, err)
	}
	cfg.Targets = []config.Target{{Owner: "org"}}
	fail = false
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil || calls != 2 {
		t.Fatalf("retry calls=%d %v", calls, err)
	}
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(context.Background(), now.Add(2*time.Hour), send); err != nil || calls != 2 {
		t.Fatalf("unchanged calls=%d %v", calls, err)
	}
	cfg.NotificationInterval = 0
	if deferred, err := b.Defer("org", "repo"); deferred || err != nil {
		t.Fatalf("immediate=%v %v", deferred, err)
	}
}

func TestResolvedBeforeFirstDeliveryDoesNotSuppressReopenedAlert(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org"}}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	b := NewBatcher(s, "scope", func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil }, func(owner, repo string) string { return store.NotificationGroupKey("test", "fixture", owner, repo) })
	b.now = func() time.Time { return now }
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, EvalStatus: model.EvalStatusPending, NotifiedAt: now}
	s.SaveObserved(r)
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "repo", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	sends := 0
	send := func(string, string) (string, error) { sends++; return currentBatchFingerprint(t, s, cfg) }
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil {
		t.Fatal(err)
	}
	s.SaveObserved(r)
	now = now.Add(2 * time.Hour)
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil {
		t.Fatal(err)
	}
	if sends != 2 {
		t.Fatalf("reopened alert was suppressed: sends=%d", sends)
	}
}

func currentBatchFingerprint(t *testing.T, s *store.Store, cfg *config.Config) (string, error) {
	t.Helper()
	records, err := s.NotificationRecords("org", "repo")
	if err != nil {
		return "", err
	}
	return Fingerprint(Build(records, *cfg, "org", "repo"))
}

func TestBatchAcknowledgesActualDeliveredStateInsteadOfOldQueueSnapshot(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org"}}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	b := NewBatcher(s, "scope", func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil }, func(owner, repo string) string { return store.NotificationGroupKey("test", "fixture", owner, repo) })
	b.now = func() time.Time { return now }
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, NotifiedAt: now}
	s.SaveObserved(r)
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	sends := 0
	send := func(string, string) (string, error) {
		sends++
		if sends == 1 {
			r.Evaluation = &model.Evaluation{AWSRisk: "updated before delivery"}
			s.Save(r)
			if _, err := b.Defer("org", "repo"); err != nil {
				return "", err
			}
		}
		return currentBatchFingerprint(t, s, cfg)
	}
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.DueNotifications("scope", now.Add(10*time.Hour)); err != nil || len(pending) != 0 {
		t.Fatalf("delivered state still pending: %+v %v", pending, err)
	}
	r.Evaluation = nil
	s.Save(r)
	now = now.Add(2 * time.Hour)
	if _, err := b.Defer("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(context.Background(), now.Add(time.Hour), send); err != nil {
		t.Fatal(err)
	}
	if sends != 2 {
		t.Fatalf("reverted state was lost: sends=%d", sends)
	}
}
