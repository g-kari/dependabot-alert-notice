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

type streamEvent struct {
	Type    string `json:"type"` // "gh" | "claude" | "slack" | "target" | "done"
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Owner   string `json:"owner,omitempty"`
	Repo    string `json:"repo,omitempty"`
	Count   int    `json:"count"`
}

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

func (s *Server) handleConnectivityStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	var sendMu sync.Mutex
	send := func(ev streamEvent) {
		b, _ := json.Marshal(ev)
		sendMu.Lock()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
		sendMu.Unlock()
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testGH(ctx, cfg.GhPath)
		send(streamEvent{Type: "gh", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testClaude(ctx, cfg.ClaudePath)
		send(streamEvent{Type: "claude", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testSlack(ctx, cfg.Slack)
		send(streamEvent{Type: "slack", OK: res.OK, Message: res.Message})
	}()

	for _, t := range cfg.Targets {
		wg.Add(1)
		go func(t config.Target) {
			defer wg.Done()
			var res targetResult
			if t.Repo != "" {
				res = testRepoTarget(ctx, cfg.GhPath, t.Owner, t.Repo)
			} else {
				res = testOrgTarget(ctx, cfg.GhPath, t.Owner)
				if !res.OK {
					res = testUserRepoTarget(ctx, cfg.GhPath, t.Owner)
				}
			}
			send(streamEvent{Type: "target", OK: res.OK, Message: res.Message, Owner: res.Owner, Repo: res.Repo, Count: res.Count})
		}(t)
	}

	wg.Wait()
	send(streamEvent{Type: "done"})
}

func (s *Server) handleConnectivityTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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
	results := make([]targetResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t config.Target) {
			defer wg.Done()
			if t.Repo != "" {
				results[i] = testRepoTarget(ctx, ghPath, t.Owner, t.Repo)
				return
			}
			// repo未指定 → org APIを試してダメなら全リポジトリにフォールバック
			r := testOrgTarget(ctx, ghPath, t.Owner)
			if !r.OK {
				r = testUserRepoTarget(ctx, ghPath, t.Owner)
			}
			results[i] = r
		}(i, t)
	}
	wg.Wait()
	return results
}

func testRepoTarget(ctx context.Context, ghPath, owner, repo string) targetResult {
	endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open", owner, repo)
	out, err := exec.CommandContext(ctx, ghPath, "api", endpoint, "--jq", "length").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return targetResult{Owner: owner, Repo: repo, OK: false, Message: msg}
	}
	count := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
	return targetResult{Owner: owner, Repo: repo, OK: true, Count: count, Message: fmt.Sprintf("%d 件のアラートを取得", count)}
}

func testOrgTarget(ctx context.Context, ghPath, owner string) targetResult {
	endpoint := fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open", owner)
	out, err := exec.CommandContext(ctx, ghPath, "api", endpoint, "--jq", "length").CombinedOutput()
	if err != nil {
		return targetResult{Owner: owner, OK: false, Message: strings.TrimSpace(string(out))}
	}
	count := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
	return targetResult{Owner: owner, OK: true, Count: count, Message: fmt.Sprintf("org: %d 件のアラートを取得", count)}
}

func testUserRepoTarget(ctx context.Context, ghPath, owner string) targetResult {
	// ユーザーリポジトリ一覧を取得して総アラート数をカウント
	reposOut, err := exec.CommandContext(ctx, ghPath, "repo", "list", owner,
		"--json", "name", "--jq", ".[].name", "--limit", "1000",
	).Output()
	if err != nil {
		return targetResult{Owner: owner, OK: false, Message: "リポジトリ一覧取得失敗: " + err.Error()}
	}

	var repos []string
	for _, line := range strings.Split(strings.TrimSpace(string(reposOut)), "\n") {
		if line != "" {
			repos = append(repos, line)
		}
	}

	total := 0
	for _, repo := range repos {
		endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open", owner, repo)
		out, err := exec.CommandContext(ctx, ghPath, "api", endpoint, "--jq", "length").Output()
		if err != nil {
			continue
		}
		count := 0
		_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
		total += count
	}
	return targetResult{
		Owner:   owner,
		OK:      true,
		Count:   total,
		Message: fmt.Sprintf("全リポジトリ(%d件)合計: %d 件のアラート", len(repos), total),
	}
}
