package slack

import (
	"context"
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
	slackgo "github.com/slack-go/slack"
)

func TestHourlySlackSendsOnlyOneSummaryWithoutIndividualMessages(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org"}}
	requests := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.FormValue("thread_ts") != "" {
			t.Error("individual detail posted")
		}
		body := r.FormValue("blocks")
		if !strings.Contains(body, "Web UI / TUI") || !strings.Contains(body, "未解決: 3件") || strings.Contains(body, "詳細本文") || strings.Contains(body, "秘密のパッケージ") {
			t.Errorf("件数と画面への案内だけを表示する必要があります: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":true,"ts":"summary"}`)
	}))
	defer endpoint.Close()
	c := New(cfg, s, nil)
	c.api = slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/"))
	c.limiter = ratelimit.NewLimiter(0)
	c.SetConfigSource(func() (config.Snapshot, error) { return config.Snapshot{Config: *cfg}, nil })
	for i := 1; i <= 3; i++ {
		r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: i, Severity: model.SeverityHigh, PackageName: "秘密のパッケージ"}, EvalStatus: model.EvalStatusDone, Evaluation: &model.Evaluation{Impact: "詳細本文", AWSRisk: "詳細本文"}, NotifiedAt: time.Now()}
		s.SaveObserved(r)
		if _, err := c.Notify(r); err != nil {
			t.Fatal(err)
		}
		if err := c.UpdateEvalMessage(r); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 0 {
		t.Fatalf("immediate requests=%d", requests)
	}
	if err := c.FlushNotifications(context.Background(), time.Now().Add(time.Hour+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("batch requests=%d", requests)
	}
	if err := c.RefreshSummary("org", "repo"); err != nil {
		t.Fatal(err)
	}
	if err := c.FlushNotifications(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("unchanged requests=%d", requests)
	}
}
