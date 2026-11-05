package discord

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/ratelimit"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestRepositorySummaryReusedAndUpdatedWithAWSDetails(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.Targets = []config.Target{{Owner: "org"}}
	posts, patches := 0, 0
	var last webhookPayload
	var mu sync.Mutex
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			posts++
		} else {
			patches++
			if !strings.Contains(r.URL.Path, "/messages/parent") {
				t.Error(r.URL.Path)
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&last); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"parent"}`)
	}))
	defer endpoint.Close()
	makeClient := func() *Client {
		c := New(endpoint.URL)
		c.limiter = ratelimit.NewLimiter(0)
		c.ConfigureGrouping(s, func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
		return c
	}
	c := makeClient()
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh, PackageName: "pkg"}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
	s.SaveObserved(r)
	id, err := c.Notify(r)
	if err != nil || id != "parent" {
		t.Fatalf("notify=%s %v", id, err)
	}
	r.DiscordMessageID = id
	r.Evaluation = &model.Evaluation{Impact: strings.Repeat("影響", 1000), Reasoning: "利用条件", AWSRisk: strings.Repeat("AWS条件😀", 1000)}
	r.EvalStatus = model.EvalStatusDone
	s.Save(r)
	restarted := makeClient()
	if err := restarted.UpdateEvalMessage(r); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(last)
	if !strings.Contains(string(raw), "AWS条件") {
		t.Fatal("AWS field missing")
	}
	for _, e := range last.Embeds {
		if len(e.Fields) > 25 {
			t.Fatal("too many fields")
		}
		for _, f := range e.Fields {
			if len([]rune(f.Value)) > 1024 {
				t.Fatal("field too long")
			}
		}
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "repo", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.NotifyResolved(r); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(last)
	if !strings.Contains(string(raw), "未解決: 0件") {
		t.Fatal(string(raw))
	}
	if posts != 1 || patches != 2 {
		t.Fatalf("posts=%d patches=%d", posts, patches)
	}
}

func TestSummaryCreatedForExistingLegacyAlerts(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.Targets = []config.Target{{Owner: "org"}}
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, DiscordMessageID: "legacy", NotifiedAt: time.Now()})
	posts := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.Method != "POST" {
			t.Error("legacy detail overwritten")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"parent"}`)
	}))
	defer endpoint.Close()
	c := New(endpoint.URL)
	c.limiter = ratelimit.NewLimiter(0)
	c.ConfigureGrouping(s, func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
	if err := c.RefreshSummary("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("legacy migration posts=%d", posts)
	}
}
