package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestRiskInputsAreLightweightPagedAndScoped(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	for i := 1; i <= 3; i++ {
		rec := saveTestAlert(s, "ORG", "api", i)
		rec.Alert.CVEID = "CVE-2026-1234"
		rec.Alert.GHSAID = "GHSA-fixture"
		rec.Alert.Description = "large fixture"
		rec.Alert.CVSSKnown = true
		rec.Alert.CVSSScore = 9.8
		s.Save(rec)
	}
	saveTestAlert(s, "other", "api", 4)
	s.RemoveResolvedAlerts("ORG", "api", []int{1, 2})
	rows, err := s.ListRiskInputs(context.Background(), RiskScope{Repos: []string{"org/api"}}, 0, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("page=%+v err=%v", rows, err)
	}
	if rows[0].Alert.Description != "" || rows[0].Evaluation != nil || rows[0].Alert.GHSAID != "GHSA-fixture" || !rows[0].Alert.CVSSKnown {
		t.Fatalf("incorrect projection: %+v", rows[0])
	}
	second, err := s.ListRiskInputs(context.Background(), RiskScope{Advisories: []string{"cve:CVE-2026-1234"}}, rows[0].Alert.ID, 100)
	if err != nil || len(second) != 1 || second[0].Alert.Number != 2 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestRiskSaveRejectsChangedInputsBeforeAnyHistoryWrite(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	revision := s.RiskRevision()
	saveTestAlert(s, "org", "api", 1)
	at := time.Now().UTC()
	_, err := s.SaveRiskEvaluationAtRevision(context.Background(), revision, "api", "org/api", "cve:CVE-2026-1234", "old", model.ScoreInput{At: at}, model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today"}, at.Add(8*time.Hour), false)
	if !errors.Is(err, ErrRiskInputsChanged) {
		t.Fatalf("stale save error=%v", err)
	}
	timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 0 || len(timeline.Deadlines) != 0 {
		t.Fatalf("stale data persisted: %+v err=%v", timeline, err)
	}
}

func TestRiskSubscriptionOverflowRequestsFullSweepAndUnsubscribes(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	changes, unsubscribe := s.SubscribeRiskChanges()
	saveTestAlert(s, "org", "api", 1)
	saveTestAlert(s, "org", "sdk", 2)
	select {
	case change := <-changes:
		if !change.All {
			t.Fatalf("overflow lost a repository: %+v", change)
		}
	default:
		t.Fatal("change missing")
	}
	unsubscribe()
	unsubscribe()
	saveTestAlert(s, "org", "api", 3)
	if _, ok := <-changes; ok {
		t.Fatal("subscription wasn't closed")
	}
}

func TestThreatChangeScopesSmallBatchToChangedAdvisories(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	changes, unsubscribe := s.SubscribeRiskChanges()
	defer unsubscribe()
	key := "cve:CVE-2026-1234"
	if err := s.UpsertThreat(context.Background(), "kev", []model.ThreatSnapshot{{AdvisoryKey: key, KEV: true, FetchedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	change := <-changes
	if change.All || len(change.Advisories) != 1 || change.Advisories[0] != key {
		t.Fatalf("small threat update forced full sweep: %+v", change)
	}
}
