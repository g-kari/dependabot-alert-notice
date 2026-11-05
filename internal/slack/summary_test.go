package slack

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
	slackgo "github.com/slack-go/slack"
)

func TestRepositoryThreadsConcurrentRestartEvaluationAndResolution(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.Targets = []config.Target{{Owner: "org"}}
	cfg.DisableApproval = true
	cfg.Slack.ChannelID = "channel"
	var mu sync.Mutex
	roots, details, updates := 0, 0, 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if strings.HasSuffix(r.URL.Path, "chat.postMessage") {
			if r.FormValue("thread_ts") == "" {
				roots++
			} else {
				details++
				if r.FormValue("thread_ts") != "parent" {
					t.Errorf("thread=%s", r.FormValue("thread_ts"))
				}
			}
		} else {
			updates++
		}
		if strings.Contains(r.FormValue("blocks"), `"action_id":"approve"`) {
			t.Error("approval resurrected")
		}
		w.Header().Set("Content-Type", "application/json")
		ts := "parent"
		if r.FormValue("thread_ts") != "" {
			ts = fmt.Sprintf("detail-%d", details)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": ts, "channel": "channel"})
	}))
	defer endpoint.Close()
	makeClient := func() *SlackClient {
		c := New(cfg, s, nil)
		c.api = slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/"))
		c.limiter = ratelimit.NewLimiter(0)
		c.SetConfigSource(func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
		return c
	}
	c := makeClient()
	records := []*model.AlertRecord{}
	for i := 1; i <= 2; i++ {
		r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: i, PackageName: "pkg", Severity: model.SeverityHigh}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
		s.SaveObserved(r)
		records = append(records, r)
	}
	var wg sync.WaitGroup
	for _, r := range records {
		wg.Add(1)
		go func(r *model.AlertRecord) {
			defer wg.Done()
			ts, err := c.Notify(r)
			if err != nil {
				t.Error(err)
				return
			}
			r.SlackMessageTS = ts
			if err := s.UpdateSlackMessageTS(r.Alert.ID, ts); err != nil {
				t.Error(err)
			}
		}(r)
	}
	wg.Wait()
	restarted := makeClient()
	records[0].Evaluation = &model.Evaluation{AWSRisk: "AWS条件"}
	records[0].EvalStatus = model.EvalStatusDone
	s.Save(records[0])
	if err := restarted.UpdateEvalMessage(records[0]); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveMissingAlerts(context.Background(), "org", "repo", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range resolved {
		if err := restarted.NotifyResolved(r); err != nil {
			t.Fatal(err)
		}
	}
	if roots != 1 || details != 4 || updates < 5 {
		t.Fatalf("roots=%d details=%d updates=%d", roots, details, updates)
	}
}

func TestSummaryAPIFailuresDoNotDuplicateParents(t *testing.T) {
	for _, failure := range []string{"message_not_found", "internal_error", "ratelimited"} {
		t.Run(failure, func(t *testing.T) {
			s := store.New()
			t.Cleanup(func() { _ = s.Close() })
			cfg := config.Defaults()
			cfg.NotificationInterval = 0
			cfg.Targets = []config.Target{{Owner: "org"}}
			cfg.Slack.ChannelID = "channel"
			r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, NotifiedAt: time.Now()}
			s.SaveObserved(r)
			roots := 0
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "chat.update") {
					_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": failure})
					return
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.FormValue("thread_ts") == "" {
					roots++
				}
				_, _ = fmt.Fprint(w, `{"ok":true,"ts":"new-parent"}`)
			}))
			defer endpoint.Close()
			c := New(cfg, s, nil)
			c.api = slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/"))
			c.limiter = ratelimit.NewLimiter(0)
			c.SetConfigSource(func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
			key := c.groupKey("org", "repo")
			if err := s.SaveNotificationGroup(key, "old-parent"); err != nil {
				t.Fatal(err)
			}
			_, err := c.Notify(r)
			if failure == "message_not_found" {
				if err != nil || roots != 1 {
					t.Fatalf("recreate roots=%d err=%v", roots, err)
				}
			} else if err == nil || roots != 0 {
				t.Fatalf("failure created duplicate: roots=%d err=%v", roots, err)
			}
		})
	}
}

func TestApprovalCleanupFailureKeepsOldActionsDisabled(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.DisableApproval = true
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, SlackMessageTS: "old", NotifiedAt: time.Now()}
	s.SaveObserved(r)
	updates := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "chat.update") {
			updates++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if strings.Contains(r.FormValue("blocks"), `"action_id":"approve"`) {
				t.Error("buttons remain")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":false,"error":"fixture_failure"}`)
	}))
	defer endpoint.Close()
	m := &mockMerger{}
	c := New(cfg, s, m)
	c.api = slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/"))
	c.limiter = ratelimit.NewLimiter(0)
	c.RefreshApprovalButtons()
	c.handleInteraction(context.Background(), makeCallback("approve", "1", "user"))
	c.handleInteraction(context.Background(), makeCallback("reject", "1", "user"))
	if updates != 1 || len(m.approved)+len(m.rejected) != 0 {
		t.Fatalf("cleanup updates=%d merger=%+v", updates, m)
	}
}

func TestSummaryCreatedForExistingLegacyAlertsWithoutRepostingDetails(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.NotificationInterval = 0
	cfg.Targets = []config.Target{{Owner: "org"}}
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, Severity: model.SeverityHigh}, SlackMessageTS: "legacy", NotifiedAt: time.Now()})
	posts := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.FormValue("thread_ts") != "" {
			t.Error("legacy detail reposted")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":true,"ts":"parent"}`)
	}))
	defer endpoint.Close()
	c := New(cfg, s, nil)
	c.api = slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/"))
	c.limiter = ratelimit.NewLimiter(0)
	c.SetConfigSource(func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
	if err := c.RefreshSummary("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("legacy migration posts=%d", posts)
	}
}
