package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestRiskTimelineIsScopedBoundedAndContextAware(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, entry := range []struct{ profile, repo, key, hash string }{
		{"api", "ORG/API", "cve:CVE-2026-1234", "A"},
		{"api", "ORG/API", "cve:CVE-2026-1234", "B"},
		{"api", "ORG/API", "cve:CVE-2026-1234", "C"},
		{"other", "org/other", "cve:CVE-2026-1234", "other"},
		{"api", "ORG/API", "cve:CVE-2026-9999", "another"},
	} {
		if _, err := s.SaveRiskEvaluation(ctx, entry.profile, entry.repo, entry.key, entry.hash, model.ScoreInput{At: at}, model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}, at.Add(8*time.Hour), false); err != nil {
			t.Fatal(err)
		}
	}
	timeline, err := s.LoadRiskTimeline(ctx, "org/api", "cve:CVE-2026-1234", 2)
	if err != nil || len(timeline.History) != 2 || !timeline.More || len(timeline.Deadlines) != 1 || timeline.Deadlines[0].ProfileID != "api" {
		t.Fatalf("scoped timeline=%+v err=%v", timeline, err)
	}
	if timeline.History[0].ID <= timeline.History[1].ID {
		t.Fatal("history order isn't newest-first")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.LoadRiskTimeline(canceled, "org/api", "cve:CVE-2026-1234", 20); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	if _, err := s.db.Exec(`UPDATE score_history SET result_json='broken' WHERE id=?`, timeline.History[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadRiskTimeline(ctx, "org/api", "cve:CVE-2026-1234", 20); err == nil {
		t.Fatal("corrupt history was treated as empty or current data")
	}
}
