package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	slackgo "github.com/slack-go/slack"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

type toolResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type targetResult struct {
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	OK      bool   `json:"ok"`
	Count   int    `json:"count"`
	Message string `json:"message"`
}

type connectivityResult struct {
	GH      toolResult     `json:"gh"`
	Claude  toolResult     `json:"claude"`
	Slack   toolResult     `json:"slack"`
	Targets []targetResult `json:"targets"`
}

func (s *Server) handleConnectivity(w http.ResponseWriter, r *http.Request) {
	s.render(w, "connectivity.html", nil)
}

func (s *Server) handleConnectivityTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	var (
		res connectivityResult
		mu  sync.Mutex
		wg  sync.WaitGroup
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		r := testGH(ctx, cfg.GhPath)
		mu.Lock()
		res.GH = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := testClaude(ctx, cfg.ClaudePath)
		mu.Lock()
		res.Claude = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := testSlack(ctx, cfg.Slack)
		mu.Lock()
		res.Slack = r
		mu.Unlock()
	}()

	wg.Wait()
	res.Targets = testTargets(ctx, cfg.GhPath, cfg.Targets)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func testGH(ctx context.Context, ghPath string) toolResult {
	out, err := exec.CommandContext(ctx, ghPath, "auth", "status").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return toolResult{OK: false, Message: msg}
	}
	return toolResult{OK: true, Message: strings.TrimSpace(string(out))}
}

func testClaude(ctx context.Context, claudePath string) toolResult {
	out, err := exec.CommandContext(ctx, claudePath, "--version").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return toolResult{OK: false, Message: msg}
	}
	return toolResult{OK: true, Message: strings.TrimSpace(string(out))}
}

func testSlack(ctx context.Context, slackCfg config.SlackConfig) toolResult {
	botToken := os.Getenv("SLACK_BOT_TOKEN")
	if botToken == "" {
		return toolResult{OK: false, Message: "SLACK_BOT_TOKEN が未設定"}
	}
	api := slackgo.New(botToken)
	resp, err := api.AuthTestContext(ctx)
	if err != nil {
		return toolResult{OK: false, Message: "auth.test 失敗: " + err.Error()}
	}
	return toolResult{OK: true, Message: fmt.Sprintf("接続OK: @%s (%s)", resp.User, resp.Team)}
}

func testTargets(ctx context.Context, ghPath string, targets []config.Target) []targetResult {
	results := make([]targetResult, 0, len(targets))
	for _, t := range targets {
		var endpoint string
		if t.Repo != "" {
			endpoint = fmt.Sprintf("/repos/%s/%s/dependabot/alerts", t.Owner, t.Repo)
		} else {
			endpoint = fmt.Sprintf("/orgs/%s/dependabot/alerts", t.Owner)
		}
		out, err := exec.CommandContext(ctx, ghPath, "api", endpoint, "--jq", "length").CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			results = append(results, targetResult{
				Owner:   t.Owner,
				Repo:    t.Repo,
				OK:      false,
				Message: msg,
			})
			continue
		}
		count := 0
		_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
		results = append(results, targetResult{
			Owner:   t.Owner,
			Repo:    t.Repo,
			OK:      true,
			Count:   count,
			Message: fmt.Sprintf("%d 件のアラートを取得", count),
		})
	}
	return results
}
