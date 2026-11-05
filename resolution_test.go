package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type resolutionEvaluator struct {
	calls  int
	during func()
}

func (e *resolutionEvaluator) Evaluate(context.Context, model.Alert) (*model.Evaluation, error) {
	e.calls++
	if e.during != nil {
		e.during()
	}
	return &model.Evaluation{Recommendation: "approve"}, nil
}

func TestEvaluationSkipsResolvedQueuedJob(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityCritical}, State: model.AlertStatePending, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
	s.SaveObserved(rec)
	s.RemoveResolvedAlerts("org", "repo", nil)
	e := &resolutionEvaluator{}
	handler := makeEvaluateHandler(&config.Config{}, e, s, nil, nil)
	if err := handler(context.Background(), queue.Job{Payload: rec.Alert.ID}); err != nil {
		t.Fatal(err)
	}
	if e.calls != 0 {
		t.Fatalf("resolved job invoked evaluator %d times", e.calls)
	}
}

func TestLateEvaluationDoesNotPublishAfterResolution(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityCritical}, State: model.AlertStatePending, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
	s.SaveObserved(rec)
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"fixture-message"}`)
	}))
	t.Cleanup(endpoint.Close)
	e := &resolutionEvaluator{during: func() { s.RemoveResolvedAlerts("org", "repo", nil) }}
	handler := makeEvaluateHandler(&config.Config{NotifyMinSeverity: "low", Targets: []config.Target{{Owner: "org"}}}, e, s, nil, discord.New(endpoint.URL))
	if err := handler(context.Background(), queue.Job{Payload: rec.Alert.ID}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("late evaluation sent %d fixture notifications", requests.Load())
	}
	saved, err := s.Get(rec.Alert.ID)
	if err != nil || saved.ResolvedAt == nil || saved.Evaluation != nil {
		t.Fatalf("late evaluation changed history: %+v err=%v", saved, err)
	}
}
