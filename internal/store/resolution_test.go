package store

import (
	"context"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestResolutionPreservesDetailAndClosesResponseEpisode(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	record := saveTestAlert(s, "org", "repo", 1)
	record.Alert.CVEID = "CVE-2026-1234"
	record.Evaluation = &model.Evaluation{Reasoning: "previous evidence"}
	s.Save(record)
	at := time.Now().UTC()
	if _, err := s.SaveRiskEvaluation(context.Background(), "api", "org/repo", "cve:CVE-2026-1234", "initial", model.ScoreInput{At: at}, model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}, at.Add(8*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	closed := s.RemoveResolvedAlerts("org", "repo", nil)
	if len(closed) != 1 {
		t.Fatalf("closed=%d", len(closed))
	}
	saved, err := s.Get(record.Alert.ID)
	if err != nil {
		t.Fatalf("resolved detail was deleted: %v", err)
	}
	if saved.Evaluation == nil || saved.Evaluation.Reasoning != "previous evidence" {
		t.Fatalf("evaluation erased: %+v", saved)
	}
	if len(s.List()) != 0 || s.HasByKey("org", "repo", 1) {
		t.Fatal("resolved record remains in active collection")
	}
	if len(s.RemoveResolvedAlerts("org", "repo", nil)) != 0 {
		t.Fatal("same resolution was emitted twice")
	}
	var closedAt *string
	if err := s.db.QueryRow(`SELECT closed_at FROM risk_deadlines`).Scan(&closedAt); err != nil {
		t.Fatal(err)
	}
	if closedAt == nil {
		t.Fatal("response episode still open after confirmed resolution")
	}
	if alerts, err := s.ListReportAlerts(context.Background(), []string{"CVE-2026-1234"}); err != nil || len(alerts) != 0 {
		t.Fatalf("resolved report association=%d err=%v", len(alerts), err)
	}
	if s.Save(record) || s.HasByKey("org", "repo", 1) {
		t.Fatal("delayed evaluation reopened resolved alert")
	}
}

func TestResolutionDoesNotCloseCVEWithAnotherOpenAlert(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	for _, number := range []int{1, 2} {
		rec := saveTestAlert(s, "org", "repo", number)
		rec.Alert.CVEID = "CVE-2026-1234"
		s.Save(rec)
	}
	at := time.Now().UTC()
	if _, err := s.SaveRiskEvaluation(context.Background(), "api", "org/repo", "cve:CVE-2026-1234", "initial", model.ScoreInput{At: at}, model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}, at.Add(8*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if closed := s.RemoveResolvedAlerts("org", "repo", []int{2}); len(closed) != 1 {
		t.Fatalf("closed=%d", len(closed))
	}
	var closedAt *string
	if err := s.db.QueryRow(`SELECT closed_at FROM risk_deadlines`).Scan(&closedAt); err != nil {
		t.Fatal(err)
	}
	if closedAt != nil {
		t.Fatal("one closed package resolved another open package's CVE")
	}
}

func TestResolutionRollsBackWhenEpisodeCloseFails(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	rec := saveTestAlert(s, "org", "repo", 1)
	rec.Alert.CVEID = "CVE-2026-1234"
	s.Save(rec)
	at := time.Now().UTC()
	if _, err := s.SaveRiskEvaluation(context.Background(), "api", "org/repo", "cve:CVE-2026-1234", "initial", model.ScoreInput{At: at}, model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}, at.Add(8*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_close BEFORE UPDATE ON risk_deadlines BEGIN SELECT RAISE(ABORT,'fixture close failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "repo", nil, at); err == nil {
		t.Fatal("want episode write failure")
	}
	got, err := s.Get(rec.Alert.ID)
	if err != nil || got.ResolvedAt != nil || !s.HasByKey("org", "repo", 1) {
		t.Fatalf("partial resolution persisted: %+v err=%v", got, err)
	}
}

func TestSaveUpsertUsesStableIDAndDoesNotClaimNew(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	first := saveTestAlert(s, "org", "repo", 1)
	id := first.Alert.ID
	other := saveTestAlert(s, "org", "repo", 2)
	if s.Save(first) {
		t.Fatal("existing alert incorrectly reported as new")
	}
	if first.Alert.ID != id || first.Alert.ID == other.Alert.ID {
		t.Fatalf("upsert used another row's LastInsertId: %d want %d", first.Alert.ID, id)
	}
}

func TestResolutionReopenKeepsIDAndStartsNewResponseEpisode(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	first := saveTestAlert(s, "org", "repo", 1)
	id := first.Alert.ID
	first.Alert.CVEID = "CVE-2026-1234"
	s.Save(first)
	at := time.Now().UTC()
	input := model.ScoreInput{At: at}
	result := model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}
	if _, err := s.SaveRiskEvaluation(context.Background(), "api", "org/repo", "cve:CVE-2026-1234", "initial", input, result, at.Add(8*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	s.RemoveResolvedAlerts("org", "repo", nil)
	saveTestAlert(s, "org", "repo", 2)
	if !s.SaveObserved(first) {
		t.Fatal("confirmed reopened alert should be available for notification/evaluation")
	}
	if first.Alert.ID != id {
		t.Fatalf("reopen replaced original ID: %d want %d", first.Alert.ID, id)
	}
	input.At = at.Add(time.Hour)
	deadline, err := s.SaveRiskEvaluation(context.Background(), "api", "org/repo", "cve:CVE-2026-1234", "reopened", input, result, input.At.Add(8*time.Hour), false)
	if err != nil || deadline == nil || deadline.Episode != 2 {
		t.Fatalf("reopened deadline=%+v err=%v", deadline, err)
	}
}
