package discord

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/ratelimit"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestHourlyDiscordCoalescesNewEvaluationAndResolvedEvents(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org"}}
	requests := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload webhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		if len(payload.Embeds) != 1 || len(payload.Embeds[0].Fields) != 0 || !strings.Contains(payload.Embeds[0].Description, "Web UI / TUI") || strings.Contains(payload.Embeds[0].Description, "秘密のパッケージ") {
			t.Errorf("短い件数サマリーではありません: %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"summary"}`)
	}))
	defer endpoint.Close()
	c := New(endpoint.URL)
	c.limiter = ratelimit.NewLimiter(0)
	source := func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil }
	c.ConfigureGrouping(s, source)
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh, PackageName: "秘密のパッケージ"}, EvalStatus: model.EvalStatusDone, Evaluation: &model.Evaluation{Impact: "詳細本文", AWSRisk: "詳細本文"}, NotifiedAt: time.Now()}
	s.SaveObserved(r)
	if _, err := c.Notify(r); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateEvalMessage(r); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("sent immediately")
	}
	restarted := New(endpoint.URL)
	restarted.limiter = ratelimit.NewLimiter(0)
	restarted.ConfigureGrouping(s, source)
	if err := restarted.FlushNotifications(context.Background(), time.Now().Add(time.Hour+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("batch requests=%d", requests)
	}
	resolved, err := s.ResolveMissingAlerts(context.Background(), "org", "repo", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.NotifyResolved(resolved[0]); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatal("resolved sent immediately")
	}
	if err := restarted.FlushNotifications(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("resolved requests=%d", requests)
	}
}
