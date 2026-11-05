package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestFailedGroupedNotificationRetriesOnNextFetchWithoutAutoEvaluation(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	target := config.Target{Owner: "org", Repo: "api"}
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.Targets = []config.Target{target}
	cfg.Evaluator.AutoEval = false
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"parent"}`)
	}))
	defer endpoint.Close()
	c := discord.New(endpoint.URL)
	c.ConfigureGrouping(s, func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
	client := &policyFetchClient{result: github.FetchResult{Alerts: []model.Alert{{Owner: "org", Repo: "api", Number: 1, Severity: model.SeverityHigh}}}}
	handler := makeFetchHandler(cfg, client, s, queue.New(10, 1), nil, c)
	for i := 0; i < 2; i++ {
		if err := handler(context.Background(), queue.Job{Payload: target}); err != nil {
			t.Fatal(err)
		}
	}
	record := s.List()[0]
	if record.DiscordMessageID != "parent" || requests.Load() < 2 {
		t.Fatalf("retry failed: id=%q requests=%d", record.DiscordMessageID, requests.Load())
	}
}
